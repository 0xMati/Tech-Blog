<#
.SYNOPSIS
    Audits the Windows Firewall state on all DCs of a domain.
.DESCRIPTION
    Compares the WFAS view (PowerShell/wf.msc), the legacy registry view and
    the WSC view (firewall.cpl) to detect configuration discrepancies across
    all firewall profiles (Domain / Private / Public).
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,                       # If empty: all DCs of the current domain
    [PSCredential]$Credential,
    [string]$ExportCsv                             # Optional CSV export path
)

# ---------------------------------------------------------------------------
# Column legend (used both in console output and in the CSV companion file)
# ---------------------------------------------------------------------------
$ColumnLegend = @"
COLUMN LEGEND
=============

ComputerName            DC hostname.

OSCaption               Operating system caption (Win Server version + edition).

ActiveProfile           Active network profile per NIC, as seen by
                        Get-NetConnectionProfile. On a DC, every NIC should be
                        'DomainAuthenticated'. Anything else means the NIC failed
                        domain detection at boot and the WRONG profile's rules
                        are being applied.

WFAS_Domain             Enabled state of each WFAS profile (Domain / Private /
WFAS_Private            Public) as reported by Get-NetFirewallProfile (same
WFAS_Public             source as wf.msc). True = firewall enabled, False =
                        firewall disabled. This is the AUTHORITATIVE state that
                        actually drives traffic filtering.

InAction_Domain         DefaultInboundAction per profile (Block / Allow /
InAction_Private        NotConfigured). 'Enabled=True' is meaningless if the
InAction_Public         default action is Allow: the firewall is technically
                        on but does not filter inbound traffic. Block is the
                        secure default.

OutAction_Domain        DefaultOutboundAction per profile. Allow is the
OutAction_Private       expected default on a DC (DCs need outbound
OutAction_Public        connectivity). Block would break replication.

Reg_Domain              Legacy registry value of 'EnableFirewall' under
Reg_Private             HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\
Reg_Public              Parameters\FirewallPolicy\<Profile>\.
                        Values: 1 = enabled, 0 = disabled, NotSet = no value
                        (normal). Note: in the registry, StandardProfile maps
                        to the Private profile.
                        Old GPOs / scripts sometimes write here directly,
                        bypassing WFAS -> typical source of desync.

WSC_Available           True only on workstation SKUs (Windows Security Center
                        is absent on Server SKUs). On DCs this is normally
                        False.

WSC_FirewallProducts    Firewall products registered with WSC (consumed by
                        firewall.cpl). 'N/A' on DCs is normal.

Svc_MpsSvc              State of the Windows Defender Firewall service in the
                        form <Status>/<StartType>. Must be 'Running/Automatic'
                        for the firewall to actually filter traffic.

Svc_BFE                 State of the Base Filtering Engine service. Required
                        dependency of MpsSvc; must be running.

Svc_Wscsvc              State of the Security Center service. Absent on Server
                        SKUs (NotInstalled is expected on DCs).

Status                  Overall verdict:
                          OK         -> no issue detected
                          DIVERGENCE -> at least one issue (see Notes column):
                            * MpsSvc or BFE not running
                            * WFAS state != Registry state on a profile
                            * WFAS enabled but DefaultInboundAction = Allow
                              (firewall is on but does not filter inbound)
                            * Any profile disabled in WFAS
                            * WSC reports non-Defender or multiple FW products

Notes                   Free-text details of the issues that triggered
                        DIVERGENCE.
"@

# ---------------------------------------------------------------------------
# Resolve DC list if none provided
# ---------------------------------------------------------------------------
if (-not $ComputerName) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ComputerName = (Get-ADDomainController -Filter *).HostName
}

# ---------------------------------------------------------------------------
# Remote payload
# ---------------------------------------------------------------------------
$scriptBlock = {
    $result = [ordered]@{
        ComputerName         = $env:COMPUTERNAME
        OSCaption            = (Get-CimInstance Win32_OperatingSystem).Caption
        ActiveProfile        = $null
        WFAS_Domain          = $null
        WFAS_Private         = $null
        WFAS_Public          = $null
        InAction_Domain      = $null
        InAction_Private     = $null
        InAction_Public      = $null
        OutAction_Domain     = $null
        OutAction_Private    = $null
        OutAction_Public     = $null
        Reg_Domain           = $null
        Reg_Private          = $null
        Reg_Public           = $null
        WSC_Available        = $false
        WSC_FirewallProducts = $null
        Svc_MpsSvc           = $null
        Svc_BFE              = $null
        Svc_Wscsvc           = $null
        Status               = 'OK'
        Notes                = New-Object System.Collections.Generic.List[string]
    }

    # Active profile - all NICs
    try {
        $nics = Get-NetConnectionProfile -ErrorAction Stop
        if ($nics) {
            $result.ActiveProfile = ($nics | ForEach-Object {
                "{0}={1}" -f $_.InterfaceAlias, $_.NetworkCategory
            }) -join '; '
        } else {
            $result.ActiveProfile = 'None'
        }
    } catch { $result.Notes.Add("ActiveProfile: $($_.Exception.Message)") }

    # WFAS - all 3 profiles (Enabled + Default actions). Kept as native types
    # ([bool] for Enabled, string for actions) instead of stringified booleans.
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($pName in 'Domain','Private','Public') {
            $p = $profiles | Where-Object Name -eq $pName | Select-Object -First 1
            if ($p) {
                $result."WFAS_$pName"      = [bool]$p.Enabled
                $result."InAction_$pName"  = [string]$p.DefaultInboundAction
                $result."OutAction_$pName" = [string]$p.DefaultOutboundAction
            }
        }
    } catch { $result.Notes.Add("WFAS: $($_.Exception.Message)") }

    # Legacy registry - all 3 profiles
    $regBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    foreach ($p in 'DomainProfile','StandardProfile','PublicProfile') {
        try {
            $val = (Get-ItemProperty "$regBase\$p" -Name EnableFirewall -ErrorAction Stop).EnableFirewall
            switch ($p) {
                'DomainProfile'   { $result.Reg_Domain  = $val }
                'StandardProfile' { $result.Reg_Private = $val }
                'PublicProfile'   { $result.Reg_Public  = $val }
            }
        } catch {
            switch ($p) {
                'DomainProfile'   { $result.Reg_Domain  = 'NotSet' }
                'StandardProfile' { $result.Reg_Private = 'NotSet' }
                'PublicProfile'   { $result.Reg_Public  = 'NotSet' }
            }
        }
    }

    # WSC (absent on Server SKUs). Detect the namespace explicitly so that a
    # query failure on a workstation (broken WMI / permissions) is not
    # mis-reported as "absent - normal on Server".
    $wscNs = Get-CimInstance -Namespace root -ClassName __NAMESPACE `
                -Filter "Name='SecurityCenter2'" -ErrorAction SilentlyContinue
    if ($wscNs) {
        try {
            $fwProducts = Get-CimInstance -Namespace root\SecurityCenter2 `
                            -ClassName FirewallProduct -ErrorAction Stop
            $result.WSC_Available = $true
            $result.WSC_FirewallProducts = ($fwProducts | ForEach-Object {
                "{0} (state=0x{1:X})" -f $_.displayName, $_.productState
            }) -join ' | '
        } catch {
            $result.WSC_Available = $true
            $result.WSC_FirewallProducts = "WSC present but query failed: $($_.Exception.Message)"
            $result.Notes.Add("WSC query failed: $($_.Exception.Message)")
        }
    } else {
        $result.WSC_Available = $false
        $result.WSC_FirewallProducts = 'N/A (WSC namespace absent - normal on Server SKU)'
    }

    # Services
    foreach ($svc in 'MpsSvc','BFE','wscsvc') {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            $value = "{0}/{1}" -f $s.Status, $s.StartType
        } catch { $value = 'NotInstalled' }
        switch ($svc) {
            'MpsSvc' { $result.Svc_MpsSvc = $value }
            'BFE'    { $result.Svc_BFE    = $value }
            'wscsvc' { $result.Svc_Wscsvc = $value }
        }
    }

    # Discrepancy analysis - covers all 3 profiles
    $issues = New-Object System.Collections.Generic.List[string]

    if ($result.Svc_MpsSvc -and $result.Svc_MpsSvc -notmatch '^Running') {
        $issues.Add('MpsSvc not running')
    }
    if ($result.Svc_BFE -and $result.Svc_BFE -notmatch '^Running') {
        $issues.Add('BFE not running')
    }

    $checks = @(
        @{ N='Domain';  W=$result.WFAS_Domain;  R=$result.Reg_Domain;  In=$result.InAction_Domain  },
        @{ N='Private'; W=$result.WFAS_Private; R=$result.Reg_Private; In=$result.InAction_Private },
        @{ N='Public';  W=$result.WFAS_Public;  R=$result.Reg_Public;  In=$result.InAction_Public  }
    )
    foreach ($c in $checks) {
        # Registry vs WFAS divergence (bool-bool comparison, no string)
        if ($c.R -in 0,1 -and $c.W -is [bool]) {
            if ([bool]$c.R -ne $c.W) {
                $issues.Add("$($c.N): WFAS=$($c.W) but Registry=$($c.R)")
            }
        }
        # Profile disabled
        if ($c.W -eq $false) {
            $issues.Add("$($c.N) profile is DISABLED in WFAS")
        }
        # Enabled but inbound default is Allow = filtering off in practice
        if ($c.W -eq $true -and $c.In -eq 'Allow') {
            $issues.Add("$($c.N): Enabled=True but DefaultInboundAction=Allow (no filtering)")
        }
    }

    if ($result.WSC_Available -and $result.WSC_FirewallProducts) {
        if ($result.WSC_FirewallProducts -notmatch 'Windows Defender Firewall') {
            $issues.Add('WSC: no Windows Defender Firewall registered')
        }
        if (($result.WSC_FirewallProducts -split '\|').Count -gt 1) {
            $issues.Add('WSC: multiple FirewallProduct entries registered')
        }
    }

    if ($issues.Count -gt 0) {
        $result.Status = 'DIVERGENCE'
        foreach ($i in $issues) { $result.Notes.Add($i) }
    }

    $result.Notes = ($result.Notes -join ' ; ')
    [PSCustomObject]$result
}

# ---------------------------------------------------------------------------
# Remote execution
# ---------------------------------------------------------------------------
$invokeParams = @{
    ComputerName = $ComputerName
    ScriptBlock  = $scriptBlock
    ErrorAction  = 'Continue'
}
if ($Credential) { $invokeParams.Credential = $Credential }

$results = Invoke-Command @invokeParams |
           Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName

# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------
Write-Host "`n=== FIREWALL AUDIT - SUMMARY TABLE ===" -ForegroundColor Cyan
$results | Format-Table ComputerName, ActiveProfile,
    WFAS_Domain, WFAS_Private, WFAS_Public,
    InAction_Domain, InAction_Private, InAction_Public,
    Reg_Domain, Reg_Private, Reg_Public,
    Svc_MpsSvc, Status -AutoSize

Write-Host "=== DIVERGENCE DETAILS ===" -ForegroundColor Yellow
$divergent = $results | Where-Object Status -ne 'OK'
if ($divergent) {
    foreach ($r in $divergent) {
        Write-Host ""
        Write-Host ("[{0}] -> {1}" -f $r.ComputerName, $r.Status) -ForegroundColor Red
        Write-Host ("  Notes               : {0}" -f $r.Notes)
        Write-Host ("  WSC_FirewallProducts: {0}" -f $r.WSC_FirewallProducts)
        Write-Host ("  Svc_BFE / Wscsvc    : {0} / {1}" -f $r.Svc_BFE, $r.Svc_Wscsvc)
    }
} else {
    Write-Host "No divergence detected on any DC." -ForegroundColor Green
}

$ok    = ($results | Where-Object Status -eq 'OK').Count
$bad   = ($results | Where-Object Status -ne 'OK').Count
Write-Host ""
Write-Host ("=== TOTALS: {0} OK / {1} DIVERGENCE ===" -f $ok, $bad) -ForegroundColor Cyan

Write-Host ""
Write-Host $ColumnLegend -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# CSV export + companion legend file
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8

    $legendPath = [System.IO.Path]::ChangeExtension($ExportCsv, $null).TrimEnd('.') + '_legend.txt'
    $ColumnLegend | Out-File -FilePath $legendPath -Encoding UTF8

    Write-Host ""
    Write-Host ("CSV exported to    : {0}" -f $ExportCsv)    -ForegroundColor Green
    Write-Host ("Legend exported to : {0}" -f $legendPath)   -ForegroundColor Green
}
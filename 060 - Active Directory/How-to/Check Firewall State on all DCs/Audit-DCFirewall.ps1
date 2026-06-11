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
    [string]$ExportCsv,                            # Optional CSV export path
    [switch]$ShowRules,                            # Print individual rule names per group
    [switch]$ShowLegend,                           # Print the symbol/column legends in the console
    [switch]$Transcript,                           # Start-Transcript in the current directory

    # Built-in firewall rule groups (DisplayGroup) that must have at least one
    # enabled inbound rule on the Domain profile for a DC to function. Override
    # to add/remove groups (e.g. add 'Remote Desktop' for Tier 0 RDP access,
    # 'Netlogon Service' or 'Remote Event Log Management' if your baseline
    # requires them - both are DISABLED by default on Windows Server and the
    # Netlogon RPC traffic actually rides on the 'Active Directory Domain
    # Services' group rules).
    [string[]]$RequiredRuleGroups = @(
        'Active Directory Domain Services',
        'Kerberos Key Distribution Center',
        'DNS Service',
        'File and Printer Sharing',
        'DFS Replication',
        'Windows Management Instrumentation (WMI)',
        'Core Networking'
    )
)

# Force UTF-8 on the console so the symbols below render correctly even on
# powershell.exe 5.1 with a legacy code page.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# ---------------------------------------------------------------------------
# Optional transcript - written to the current working directory.
# ---------------------------------------------------------------------------
$transcriptStarted = $false
if ($Transcript) {
    $transcriptPath = Join-Path -Path (Get-Location).Path `
        -ChildPath ('Audit-DCFirewall_{0}_{1}.log' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        $transcriptStarted = $true
        Write-Host ("Transcript started: {0}" -f $transcriptPath) -ForegroundColor DarkGray
    } catch {
        Write-Warning ("Could not start transcript: {0}" -f $_.Exception.Message)
    }
}

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
                        firewall disabled. This is the EFFECTIVE state
                        (ActiveStore: local + GPO + MDM merged) - the value
                        that actually drives traffic filtering.

WFAS_Local_Domain       Enabled state of each WFAS profile from the
WFAS_Local_Private      PersistentStore (the DC's LOCAL config only - what
WFAS_Local_Public       wf.msc shows when not viewing GPO data). When this
                        differs from WFAS_<Profile>, a GPO or MDM policy is
                        overriding the local config. Classic source of
                        confusion: admin sees Enabled in wf.msc while the
                        firewall is actually OFF at runtime (or vice versa).

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

Rules_Status            Verdict on the built-in firewall rule groups required
                        for the DC role on the Domain profile:
                          OK       -> every required group has at least one
                                      enabled inbound rule on Domain profile
                          MISSING  -> at least one required group has no rule
                                      at all on the host
                          DISABLED -> at least one required group exists but
                                      has no enabled inbound rule on Domain
                                      (its rules exist but are all disabled
                                      or scoped to Private/Public only)

Rules_Missing           Required groups for which Get-NetFirewallRule returns
                        zero rules (the group is absent from the host).

Rules_Disabled          Required groups present on the host but with no
                        enabled inbound rule scoped to the Domain profile.

RuleGroups_Detail       Compact per-group verdict, in the form
                        '<group1>=<status1> | <group2>=<status2> | ...'.
                        CSV-friendly mirror of the per-group breakdown
                        printed in the 'RULE GROUPS DETAIL' console block.

Status                  Overall verdict:
                          OK         -> no issue detected
                          DIVERGENCE -> at least one issue (see Notes column):
                            * MpsSvc or BFE not running
                            * WFAS state != Registry state on a profile
                            * WFAS Effective != WFAS Local on a profile
                              (a GPO or MDM is overriding the local config)
                            * WFAS enabled but DefaultInboundAction = Allow
                              (firewall is on but does not filter inbound)
                            * Any profile disabled in WFAS
                            * WSC reports non-Defender or multiple FW products
                            * A required rule group is missing or disabled
                              on the Domain profile (Rules_Status != OK)

Notes                   Free-text details of the issues that triggered
                        DIVERGENCE.
"@

# ---------------------------------------------------------------------------
# Colored console legend (structured by section). The plain text version
# above is kept for the CSV companion file.
# ---------------------------------------------------------------------------
function Write-ColumnLegend {
    $sections = @(
        @{
            Title = 'IDENTITY'
            Items = @(
                @{ Cols=@('ComputerName');  Desc=@('DC hostname.') },
                @{ Cols=@('OSCaption');     Desc=@('Operating system caption (Win Server version + edition).') },
                @{ Cols=@('ActiveProfile'); Desc=@(
                    "Active network profile per NIC (Get-NetConnectionProfile).",
                    "On a DC, every NIC should be 'DomainAuthenticated'. Anything else means the NIC",
                    "failed domain detection at boot and the WRONG profile's rules are being applied.") }
            )
        },
        @{
            Title = 'WFAS - AUTHORITATIVE STATE (what wf.msc and Get-NetFirewallProfile show)'
            Items = @(
                @{ Cols=@('WFAS_Domain','WFAS_Private','WFAS_Public'); Desc=@(
                    "Enabled state per profile (EFFECTIVE = ActiveStore: local + GPO + MDM merged).",
                    "True = firewall enabled, False = disabled.",
                    "This is the value that actually drives traffic filtering.") },
                @{ Cols=@('WFAS_Local_Domain','WFAS_Local_Private','WFAS_Local_Public'); Desc=@(
                    "Enabled state per profile from the LOCAL config only (PersistentStore).",
                    "When this differs from WFAS_<Profile>, a GPO or MDM policy is overriding",
                    "the local config -> classic source of confusion when wf.msc shows Enabled",
                    "but the firewall is actually OFF at runtime (or vice versa).") },
                @{ Cols=@('InAction_Domain','InAction_Private','InAction_Public'); Desc=@(
                    "DefaultInboundAction per profile (Block / Allow / NotConfigured).",
                    "'Enabled=True' is meaningless if the default is Allow: the firewall is on but",
                    "does not filter inbound traffic. Block is the secure default.") },
                @{ Cols=@('OutAction_Domain','OutAction_Private','OutAction_Public'); Desc=@(
                    "DefaultOutboundAction per profile. Allow is the expected default on a DC",
                    "(DCs need outbound connectivity). Block would break replication.") }
            )
        },
        @{
            Title = 'LEGACY REGISTRY (HKLM\...\SharedAccess\Parameters\FirewallPolicy)'
            Items = @(
                @{ Cols=@('Reg_Domain','Reg_Private','Reg_Public'); Desc=@(
                    "Value of 'EnableFirewall' under DomainProfile / StandardProfile / PublicProfile.",
                    "Values: 1 = enabled, 0 = disabled, NotSet = no value (normal).",
                    "Note: in the registry, StandardProfile maps to the Private profile.",
                    "Old GPOs / scripts sometimes write here directly, bypassing WFAS",
                    "-> typical source of desync.") }
            )
        },
        @{
            Title = 'WINDOWS SECURITY CENTER (workstations only - absent on Server SKUs)'
            Items = @(
                @{ Cols=@('WSC_Available'); Desc=@(
                    "True only on workstation SKUs. On DCs this is normally False.") },
                @{ Cols=@('WSC_FirewallProducts'); Desc=@(
                    "Firewall products registered with WSC (consumed by firewall.cpl).",
                    "'N/A' on DCs is normal.") }
            )
        },
        @{
            Title = 'SERVICES'
            Items = @(
                @{ Cols=@('Svc_MpsSvc'); Desc=@(
                    "Windows Defender Firewall service: <Status>/<StartType>.",
                    "Must be 'Running/Automatic' for the firewall to actually filter traffic.") },
                @{ Cols=@('Svc_BFE');    Desc=@('Base Filtering Engine. Required dependency of MpsSvc; must be running.') },
                @{ Cols=@('Svc_Wscsvc'); Desc=@('Security Center service. Absent on Server SKUs (NotInstalled is expected on DCs).') }
            )
        },
        @{
            Title = 'REQUIRED RULE GROUPS (Domain profile, Inbound)'
            Items = @(
                @{ Cols=@('Rules_Status'); Desc=@(
                    "Verdict on the built-in firewall rule groups required for the DC role:",
                    "  OK       -> every required group has at least one enabled inbound rule",
                    "  MISSING  -> at least one required group has no rule at all on the host",
                    "  DISABLED -> at least one required group exists but has no enabled inbound",
                    "              rule on Domain (rules disabled or scoped to Private/Public only)") },
                @{ Cols=@('Rules_Missing');     Desc=@('Required groups for which Get-NetFirewallRule returns zero rules.') },
                @{ Cols=@('Rules_Disabled');    Desc=@('Required groups present on the host but with no enabled inbound rule on Domain.') },
                @{ Cols=@('RuleGroups_Detail'); Desc=@(
                    "Compact per-group verdict: '<group1>=<status1> | <group2>=<status2> | ...'.",
                    "CSV-friendly mirror of the per-group breakdown printed in the",
                    "'RULE GROUPS DETAIL' console block.") }
            )
        },
        @{
            Title = 'OVERALL VERDICT'
            Items = @(
                @{ Cols=@('Status'); Desc=@(
                    "OK         -> no issue detected",
                    "DIVERGENCE -> at least one issue (see Notes column):",
                    "  * MpsSvc or BFE not running",
                    "  * WFAS state != Registry state on a profile",
                    "  * WFAS Effective != WFAS Local on a profile (GPO/MDM override)",
                    "  * WFAS enabled but DefaultInboundAction = Allow (no filtering)",
                    "  * Any profile disabled in WFAS",
                    "  * WSC reports non-Defender or multiple FW products",
                    "  * A required rule group is missing or disabled on the Domain profile") },
                @{ Cols=@('Notes'); Desc=@('Free-text details of the issues that triggered DIVERGENCE.') }
            )
        }
    )

    Write-Host ''
    Write-Host '+-------------------------------------------------------------+' -ForegroundColor Cyan
    Write-Host '|                       COLUMN LEGEND                         |' -ForegroundColor Cyan
    Write-Host '+-------------------------------------------------------------+' -ForegroundColor Cyan

    foreach ($section in $sections) {
        Write-Host ''
        Write-Host (' [' + $section.Title + ']') -ForegroundColor Yellow
        Write-Host (' ' + ('-' * ($section.Title.Length + 2))) -ForegroundColor DarkYellow
        foreach ($item in $section.Items) {
            foreach ($col in $item.Cols) {
                Write-Host ('   ' + $col) -ForegroundColor White
            }
            foreach ($line in $item.Desc) {
                Write-Host ('       ' + $line) -ForegroundColor Gray
            }
            Write-Host ''
        }
    }
}

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
    param([string[]]$RequiredRuleGroups)

    $result = [ordered]@{
        ComputerName         = $env:COMPUTERNAME
        OSCaption            = (Get-CimInstance Win32_OperatingSystem).Caption
        ActiveProfile        = $null
        WFAS_Domain          = $null
        WFAS_Private         = $null
        WFAS_Public          = $null
        WFAS_Local_Domain    = $null
        WFAS_Local_Private   = $null
        WFAS_Local_Public    = $null
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
        Rules_Status         = $null
        Rules_Missing        = $null
        Rules_Disabled       = $null
        RuleGroups           = $null
        RuleGroups_Detail    = $null
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

    # WFAS - all 3 profiles (Enabled + Default actions). Read TWO stores:
    #   ActiveStore     = effective state (local + GPO + MDM merged) -> what
    #                     Get-NetFirewallProfile returns by default and what
    #                     actually drives traffic filtering.
    #   PersistentStore = local-only config -> what wf.msc shows in its tree
    #                     when not viewing GPO data.
    # If the two differ on a profile, a GPO (or MDM) is overriding the local
    # config -> classic source of confusion when an admin sees 'Enabled' in
    # wf.msc but the firewall is actually disabled at runtime.
    try {
        $profilesActive = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
        foreach ($pName in 'Domain','Private','Public') {
            $p = $profilesActive | Where-Object Name -eq $pName | Select-Object -First 1
            if ($p) {
                $result."WFAS_$pName"      = [bool]$p.Enabled
                $result."InAction_$pName"  = [string]$p.DefaultInboundAction
                $result."OutAction_$pName" = [string]$p.DefaultOutboundAction
            }
        }
    } catch { $result.Notes.Add("WFAS (ActiveStore): $($_.Exception.Message)") }

    try {
        $profilesLocal = Get-NetFirewallProfile -PolicyStore PersistentStore -ErrorAction Stop
        foreach ($pName in 'Domain','Private','Public') {
            $p = $profilesLocal | Where-Object Name -eq $pName | Select-Object -First 1
            if ($p) {
                $result."WFAS_Local_$pName" = [bool]$p.Enabled
            }
        }
    } catch { $result.Notes.Add("WFAS (PersistentStore): $($_.Exception.Message)") }

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

    # Required firewall rule groups (Domain profile, Inbound) needed for the
    # DC role. We classify per group as:
    #   MISSING  -> Get-NetFirewallRule returns nothing for the DisplayGroup
    #   DISABLED -> rules exist but none is Enabled+Inbound on Domain profile
    #   OK       -> at least one matching rule exists
    $missing      = New-Object System.Collections.Generic.List[string]
    $disabled     = New-Object System.Collections.Generic.List[string]
    $groupsDetail = New-Object System.Collections.Generic.List[psobject]
    try {
        foreach ($group in $RequiredRuleGroups) {
            $rules = Get-NetFirewallRule -DisplayGroup $group `
                        -ErrorAction SilentlyContinue
            $detail = [pscustomobject]@{
                Group       = $group
                Status      = $null
                ActiveRules = ''
            }
            if (-not $rules) {
                $missing.Add($group)
                $detail.Status = 'MISSING'
                $groupsDetail.Add($detail)
                continue
            }

            # Keep only Inbound + Enabled rules whose Profile includes Domain
            # (or Any). Profile is a flag enum: Domain=1, Private=2, Public=4,
            # Any=2147483647. We test by string for portability across SKUs.
            $active = $rules | Where-Object {
                $_.Direction -eq 'Inbound' -and
                $_.Enabled   -eq 'True'    -and
                ($_.Profile -match 'Domain' -or $_.Profile -match 'Any')
            }
            if (-not $active) {
                $disabled.Add($group)
                $detail.Status = 'DISABLED'
            } else {
                $detail.Status = 'OK'
                $detail.ActiveRules = ($active | Select-Object -ExpandProperty DisplayName -Unique) -join ' | '
            }
            $groupsDetail.Add($detail)
        }
        if ($missing.Count -eq 0 -and $disabled.Count -eq 0) {
            $result.Rules_Status = 'OK'
        } elseif ($missing.Count -gt 0) {
            $result.Rules_Status = 'MISSING'
        } else {
            $result.Rules_Status = 'DISABLED'
        }
        $result.Rules_Missing  = ($missing  -join ' | ')
        $result.Rules_Disabled = ($disabled -join ' | ')
        $result.RuleGroups     = $groupsDetail.ToArray()
        $result.RuleGroups_Detail = ($groupsDetail | ForEach-Object { "$($_.Group)=$($_.Status)" }) -join ' | '
    } catch {
        $result.Rules_Status = 'ERROR'
        $result.Notes.Add("Rules check failed: $($_.Exception.Message)")
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

    # Effective (ActiveStore) vs Local (PersistentStore) divergence -> a GPO
    # or MDM policy is overriding the DC's local firewall config. This is the
    # typical reason an admin sees 'Enabled' in wf.msc while the firewall is
    # actually OFF at runtime (or vice versa).
    $localChecks = @(
        @{ N='Domain';  E=$result.WFAS_Domain;  L=$result.WFAS_Local_Domain  },
        @{ N='Private'; E=$result.WFAS_Private; L=$result.WFAS_Local_Private },
        @{ N='Public';  E=$result.WFAS_Public;  L=$result.WFAS_Local_Public  }
    )
    foreach ($c in $localChecks) {
        if ($c.E -is [bool] -and $c.L -is [bool] -and $c.E -ne $c.L) {
            $issues.Add("$($c.N): Effective=$($c.E) but Local=$($c.L) (overridden by GPO/MDM)")
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

    if ($missing.Count -gt 0) {
        $issues.Add("Required rule groups MISSING: $($missing -join ', ')")
    }
    if ($disabled.Count -gt 0) {
        $issues.Add("Required rule groups DISABLED on Domain: $($disabled -join ', ')")
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
    ArgumentList = (,$RequiredRuleGroups)
    ErrorAction  = 'Continue'
}
if ($Credential) { $invokeParams.Credential = $Credential }

$results = Invoke-Command @invokeParams |
           Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName

# ---------------------------------------------------------------------------
# Helpers for the compact symbolic table
# ---------------------------------------------------------------------------
function ConvertTo-BoolSymbol {
    param($Value)
    if ($Value -eq $true)  { return [pscustomobject]@{ Text='✓'; Color='Green' } }
    if ($Value -eq $false) { return [pscustomobject]@{ Text='✗'; Color='Red'   } }
    return [pscustomobject]@{ Text='?'; Color='DarkGray' }
}
function ConvertTo-ActionSymbol {
    param([string]$Value)
    switch ($Value) {
        'Block'         { 'B'  }
        'Allow'         { 'A'  }
        'NotConfigured' { '―' }
        default         { '?'  }
    }
}
function ConvertTo-RegSymbol {
    param($Value)
    if ($Value -eq 1)        { '1' }
    elseif ($Value -eq 0)    { '0' }
    elseif ($Value -eq 'NotSet') { '―' }
    else                     { '?' }
}

# ---------------------------------------------------------------------------
# Console output - compact symbolic summary table
# ---------------------------------------------------------------------------
Write-Host "`n=== FIREWALL AUDIT - SUMMARY TABLE ===" -ForegroundColor Cyan
if ($ShowLegend) {
    Write-Host "  Each (D/P/Pu) triplet is the value for the Domain / Private / Public profile" -ForegroundColor DarkGray
    Write-Host "  Firewall : ✓=enabled ✗=disabled                                              " -ForegroundColor DarkGray
    Write-Host "  Inbound / Outbound default action : B=Block A=Allow ―=NotConfigured           " -ForegroundColor DarkGray
    Write-Host "  Registry EnableFirewall : 1=enabled 0=disabled ―=NotSet                       " -ForegroundColor DarkGray
}
Write-Host ""

# Use a wide rendering width so the summary table never wraps mid-column,
# even when the host is narrow (the user can scroll right). Out-String's
# default of ~80 chars produces hard line-breaks that hide entire columns.
$tableWidth = try {
    [Math]::Max([Console]::WindowWidth, 200)
} catch { 500 }

$summaryRows = $results | ForEach-Object {
    [pscustomobject]@{
        ComputerName        = $_.ComputerName
        ActiveProfile       = $_.ActiveProfile
        'Firewall(D/P/Pu)'  = '{0} / {1} / {2}' -f (ConvertTo-BoolSymbol $_.WFAS_Domain).Text,
                                                    (ConvertTo-BoolSymbol $_.WFAS_Private).Text,
                                                    (ConvertTo-BoolSymbol $_.WFAS_Public).Text
        'Inbound(D/P/Pu)'   = '{0} / {1} / {2}' -f (ConvertTo-ActionSymbol $_.InAction_Domain),
                                                    (ConvertTo-ActionSymbol $_.InAction_Private),
                                                    (ConvertTo-ActionSymbol $_.InAction_Public)
        'Outbound(D/P/Pu)'  = '{0} / {1} / {2}' -f (ConvertTo-ActionSymbol $_.OutAction_Domain),
                                                    (ConvertTo-ActionSymbol $_.OutAction_Private),
                                                    (ConvertTo-ActionSymbol $_.OutAction_Public)
        'Registry(D/P/Pu)'  = '{0} / {1} / {2}' -f (ConvertTo-RegSymbol $_.Reg_Domain),
                                                    (ConvertTo-RegSymbol $_.Reg_Private),
                                                    (ConvertTo-RegSymbol $_.Reg_Public)
        MpsSvc              = if ($_.Svc_MpsSvc -match '^Running') { '✓' } else { '✗' }
        Rules               = $_.Rules_Status
        Status              = $_.Status
    }
}
$summaryRows | Format-Table -AutoSize | Out-String -Width $tableWidth | Write-Host

# ---------------------------------------------------------------------------
# Console output - rule groups detail (per DC, per group)
# ---------------------------------------------------------------------------
Write-Host "=== RULE GROUPS DETAIL ===" -ForegroundColor Cyan
foreach ($r in $results) {
    Write-Host ""
    Write-Host ("[{0}]" -f $r.ComputerName) -ForegroundColor White
    if (-not $r.RuleGroups) {
        Write-Host "  (no rule group data - check Notes)" -ForegroundColor DarkGray
        continue
    }
    $maxLen = ($r.RuleGroups | ForEach-Object { $_.Group.Length } | Measure-Object -Maximum).Maximum
    foreach ($g in $r.RuleGroups) {
        switch ($g.Status) {
            'OK'       { $sym='✓'; $color='Green'  }
            'DISABLED' { $sym='✗'; $color='Yellow' }
            'MISSING'  { $sym='✗'; $color='Red'    }
            default    { $sym='?'; $color='DarkGray' }
        }
        $line = '  {0} {1}  {2}' -f $sym, $g.Group.PadRight($maxLen), $g.Status
        Write-Host $line -ForegroundColor $color
        if ($ShowRules -and $g.ActiveRules) {
            foreach ($ruleName in ($g.ActiveRules -split ' \| ')) {
                Write-Host ("      → {0}" -f $ruleName) -ForegroundColor DarkGray
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Console output - divergence details (free text)
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== DIVERGENCE DETAILS ===" -ForegroundColor Yellow
$divergent = $results | Where-Object Status -ne 'OK'
if ($divergent) {
    foreach ($r in $divergent) {
        Write-Host ""
        Write-Host ("[{0}] -> {1}" -f $r.ComputerName, $r.Status) -ForegroundColor Red
        Write-Host ("  ActiveProfile       : {0}" -f $r.ActiveProfile)
        Write-Host ("  Notes               : {0}" -f $r.Notes)

        # Show Effective vs Local triplet only when they differ on at least
        # one profile - signals a GPO/MDM override.
        $effTriplet  = '{0} / {1} / {2}' -f (ConvertTo-BoolSymbol $r.WFAS_Domain).Text,
                                              (ConvertTo-BoolSymbol $r.WFAS_Private).Text,
                                              (ConvertTo-BoolSymbol $r.WFAS_Public).Text
        $locTriplet  = '{0} / {1} / {2}' -f (ConvertTo-BoolSymbol $r.WFAS_Local_Domain).Text,
                                              (ConvertTo-BoolSymbol $r.WFAS_Local_Private).Text,
                                              (ConvertTo-BoolSymbol $r.WFAS_Local_Public).Text
        $hasOverride = ($r.WFAS_Domain  -is [bool] -and $r.WFAS_Local_Domain  -is [bool] -and $r.WFAS_Domain  -ne $r.WFAS_Local_Domain) -or `
                       ($r.WFAS_Private -is [bool] -and $r.WFAS_Local_Private -is [bool] -and $r.WFAS_Private -ne $r.WFAS_Local_Private) -or `
                       ($r.WFAS_Public  -is [bool] -and $r.WFAS_Local_Public  -is [bool] -and $r.WFAS_Public  -ne $r.WFAS_Local_Public)
        if ($hasOverride) {
            Write-Host ("  Firewall Effective  : {0}  (ActiveStore - what actually applies)" -f $effTriplet) -ForegroundColor Yellow
            Write-Host ("  Firewall Local      : {0}  (PersistentStore - what wf.msc shows)" -f $locTriplet) -ForegroundColor Yellow
        }
        Write-Host ("  WSC_FirewallProducts: {0}" -f $r.WSC_FirewallProducts)
        Write-Host ("  Svc_BFE / Wscsvc    : {0} / {1}" -f $r.Svc_BFE, $r.Svc_Wscsvc)
        if ($r.Rules_Missing)  { Write-Host ("  Rules_Missing       : {0}" -f $r.Rules_Missing) }
        if ($r.Rules_Disabled) { Write-Host ("  Rules_Disabled      : {0}" -f $r.Rules_Disabled) }

        # Contextual hint: if all NICs are DomainAuthenticated, only the Domain
        # profile state matters at runtime - Private/Public being off is
        # cosmetic (but still flagged because Microsoft Security Baseline
        # recommends all three on).
        $allDomainAuth = $true
        if ($r.ActiveProfile) {
            foreach ($entry in ($r.ActiveProfile -split ';\s*')) {
                $cat = ($entry -split '=')[1]
                if ($cat -and $cat -ne 'DomainAuthenticated') {
                    $allDomainAuth = $false
                    break
                }
            }
        }
        $domOn  = [bool]$r.WFAS_Domain
        $privOn = [bool]$r.WFAS_Private
        $pubOn  = [bool]$r.WFAS_Public
        if ($domOn -and $allDomainAuth -and (-not $privOn -or -not $pubOn)) {
            Write-Host "  Hint                : Domain profile is ON and all NICs are DomainAuthenticated -> runtime is fine. Private/Public being off is a baseline finding, not an outage." -ForegroundColor DarkGray
        }
        if (-not $domOn) {
            Write-Host "  Hint                : Domain profile is OFF -> the firewall is NOT filtering traffic on this DC. Critical." -ForegroundColor DarkGray
        }
        if ($hasOverride) {
            Write-Host "  Hint                : Local config differs from effective state -> a GPO or MDM policy is overriding this DC's firewall settings (run 'gpresult /h gpresult.html' to find which GPO)." -ForegroundColor DarkGray
        }
    }
} else {
    Write-Host "No divergence detected on any DC." -ForegroundColor Green
}

$ok    = ($results | Where-Object Status -eq 'OK').Count
$bad   = ($results | Where-Object Status -ne 'OK').Count
Write-Host ""
Write-Host ("=== TOTALS: {0} OK / {1} DIVERGENCE ===" -f $ok, $bad) -ForegroundColor Cyan

if ($ShowLegend) {
    Write-ColumnLegend
} else {
    Write-Host ""
    Write-Host "(Tip: re-run with -ShowLegend to print the symbol legend and the full column reference)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# CSV export + companion legend file
# ---------------------------------------------------------------------------
if ($ExportCsv) {
    # Drop the nested RuleGroups array (kept the flat RuleGroups_Detail string)
    $results |
        Select-Object * -ExcludeProperty RuleGroups |
        Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8

    $legendPath = [System.IO.Path]::ChangeExtension($ExportCsv, $null).TrimEnd('.') + '_legend.txt'
    $ColumnLegend | Out-File -FilePath $legendPath -Encoding UTF8

    Write-Host ""
    Write-Host ("CSV exported to    : {0}" -f $ExportCsv)    -ForegroundColor Green
    Write-Host ("Legend exported to : {0}" -f $legendPath)   -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Stop transcript (if it was started)
# ---------------------------------------------------------------------------
if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}
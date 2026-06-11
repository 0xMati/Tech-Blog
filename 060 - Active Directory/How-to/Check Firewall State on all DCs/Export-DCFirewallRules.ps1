<#
.SYNOPSIS
    Exports the EFFECTIVE Windows Firewall rules and profile settings of every
    DC of a domain, in CSV + JSON. Optionally compares with a previous export
    to highlight what changed (typical use case: snapshot before / after a
    GPO push).
.DESCRIPTION
    For each Domain Controller, the script reads the ActiveStore (effective
    state = local + GPO + MDM merged) via Get-NetFirewallRule and
    Get-NetFirewallProfile, joins the associated PortFilter / AddressFilter /
    ApplicationFilter / ServiceFilter values, and writes:

        <OutputFolder>\<Label>\<DC>_rules.csv
        <OutputFolder>\<Label>\<DC>_rules.json
        <OutputFolder>\<Label>\<DC>_profiles.csv
        <OutputFolder>\<Label>\<DC>_profiles.json

    With -CompareWith <previousFolder>, the script also produces, per DC:

        <OutputFolder>\<Label>\<DC>_diff.md

    listing rules added / removed / modified between the previous snapshot and
    the current one, plus profile setting deltas.

    The PolicyStoreSourceType field on each rule tells you where the rule came
    from (Local vs GroupPolicy) - very useful right after a GPO push.

.EXAMPLE
    # Snapshot before a GPO change
    .\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW -Label 'before-gpo'

    # ... push GPO + gpupdate /force on the DCs ...

    # Snapshot after + immediate diff
    .\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW -Label 'after-gpo' `
        -CompareWith C:\Temp\FW\before-gpo
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName,                       # If empty: all DCs of the current domain
    [PSCredential]$Credential,

    [Parameter(Mandatory)]
    [string]$OutputFolder,                         # Root folder for the snapshots

    [Parameter(Mandatory)]
    [string]$Label,                                # Sub-folder name (e.g. 'before-gpo', '2026-06-11')

    [string]$CompareWith,                          # Path to a previous snapshot folder (the <OutputFolder>\<Label> of a previous run)

    [switch]$Transcript                            # Start-Transcript in the current directory
)

# Force UTF-8 on the console so symbols below render correctly even on
# powershell.exe 5.1 with a legacy code page.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

# ---------------------------------------------------------------------------
# Optional transcript - written to the current working directory.
# ---------------------------------------------------------------------------
$transcriptStarted = $false
if ($Transcript) {
    $transcriptPath = Join-Path -Path (Get-Location).Path `
        -ChildPath ('Export-DCFirewallRules_{0}_{1}.log' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
    try {
        Start-Transcript -Path $transcriptPath -Force | Out-Null
        $transcriptStarted = $true
        Write-Host ("Transcript started: {0}" -f $transcriptPath) -ForegroundColor DarkGray
    } catch {
        Write-Warning ("Could not start transcript: {0}" -f $_.Exception.Message)
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
# Resolve output folder layout
# ---------------------------------------------------------------------------
$snapshotFolder = Join-Path -Path $OutputFolder -ChildPath $Label
if (-not (Test-Path -LiteralPath $snapshotFolder)) {
    New-Item -ItemType Directory -Path $snapshotFolder -Force | Out-Null
}
Write-Host ("Snapshot folder    : {0}" -f $snapshotFolder) -ForegroundColor Cyan
if ($CompareWith) {
    if (-not (Test-Path -LiteralPath $CompareWith)) {
        throw "CompareWith folder not found: $CompareWith"
    }
    Write-Host ("Compare against    : {0}" -f $CompareWith) -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Remote payload
# ---------------------------------------------------------------------------
$scriptBlock = {
    # Always read the ActiveStore - that's the effective state that filters
    # traffic (local + GPO + MDM merged).

    # 1) Profile settings ------------------------------------------------
    $profiles = @()
    try {
        $profiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    ComputerName            = $env:COMPUTERNAME
                    Name                    = $_.Name
                    Enabled                 = [bool]$_.Enabled
                    DefaultInboundAction    = [string]$_.DefaultInboundAction
                    DefaultOutboundAction   = [string]$_.DefaultOutboundAction
                    AllowInboundRules       = [string]$_.AllowInboundRules
                    AllowLocalFirewallRules = [string]$_.AllowLocalFirewallRules
                    AllowLocalIPsecRules    = [string]$_.AllowLocalIPsecRules
                    NotifyOnListen          = [string]$_.NotifyOnListen
                    LogFileName             = [string]$_.LogFileName
                    LogMaxSizeKilobytes     = [int]$_.LogMaxSizeKilobytes
                    LogAllowed              = [string]$_.LogAllowed
                    LogBlocked              = [string]$_.LogBlocked
                }
            }
    } catch {
        Write-Warning "[$env:COMPUTERNAME] Get-NetFirewallProfile: $($_.Exception.Message)"
    }

    # 2) Rules + filters --------------------------------------------------
    # We use the per-rule pipeline (slower but documented and reliable on
    # both PS 5.1 and PS 7+). On a DC with ~600 rules this typically
    # takes 30-60s.
    $rules = @()
    try {
        $allRules = Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop
        $count = 0
        $total = ($allRules | Measure-Object).Count
        foreach ($r in $allRules) {
            $count++
            if ($count % 50 -eq 0) {
                Write-Progress -Activity "Reading firewall rules on $env:COMPUTERNAME" `
                    -Status ("{0} / {1}" -f $count, $total) -PercentComplete (($count / $total) * 100)
            }
            $port = $null; $addr = $null; $app = $null; $svc = $null
            try { $port = $r | Get-NetFirewallPortFilter        -ErrorAction SilentlyContinue } catch {}
            try { $addr = $r | Get-NetFirewallAddressFilter     -ErrorAction SilentlyContinue } catch {}
            try { $app  = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue } catch {}
            try { $svc  = $r | Get-NetFirewallServiceFilter     -ErrorAction SilentlyContinue } catch {}

            $rules += [pscustomobject]@{
                ComputerName          = $env:COMPUTERNAME
                Name                  = $r.Name                              # Stable unique ID
                DisplayName           = $r.DisplayName
                DisplayGroup          = $r.DisplayGroup
                Group                 = $r.Group
                Enabled               = [string]$r.Enabled
                Direction             = [string]$r.Direction
                Action                = [string]$r.Action
                Profile               = [string]$r.Profile
                EdgeTraversalPolicy   = [string]$r.EdgeTraversalPolicy
                PolicyStoreSourceType = [string]$r.PolicyStoreSourceType    # Local / GroupPolicy / ...
                PolicyStoreSource     = [string]$r.PolicyStoreSource         # GPO GUID/path if applicable
                Protocol              = if ($port) { [string]$port.Protocol     } else { '' }
                LocalPort             = if ($port) { ($port.LocalPort  -join ';') } else { '' }
                RemotePort            = if ($port) { ($port.RemotePort -join ';') } else { '' }
                IcmpType              = if ($port) { ($port.IcmpType   -join ';') } else { '' }
                LocalAddress          = if ($addr) { ($addr.LocalAddress  -join ';') } else { '' }
                RemoteAddress         = if ($addr) { ($addr.RemoteAddress -join ';') } else { '' }
                Program               = if ($app)  { [string]$app.Program } else { '' }
                Package               = if ($app)  { [string]$app.Package } else { '' }
                Service               = if ($svc)  { [string]$svc.Service } else { '' }
            }
        }
        Write-Progress -Activity "Reading firewall rules on $env:COMPUTERNAME" -Completed
    } catch {
        Write-Warning "[$env:COMPUTERNAME] Get-NetFirewallRule: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Profiles     = $profiles
        Rules        = $rules
    }
}

# ---------------------------------------------------------------------------
# Remote execution
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ("Querying {0} DC(s) in parallel..." -f $ComputerName.Count) -ForegroundColor Cyan

$invokeParams = @{
    ComputerName = $ComputerName
    ScriptBlock  = $scriptBlock
    ErrorAction  = 'Continue'
}
if ($Credential) { $invokeParams.Credential = $Credential }

$results = Invoke-Command @invokeParams |
           Select-Object * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName

# ---------------------------------------------------------------------------
# Write per-DC files
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== EXPORT ===" -ForegroundColor Cyan
foreach ($r in $results) {
    $dc = $r.ComputerName
    $rulesCsv     = Join-Path $snapshotFolder ("{0}_rules.csv"     -f $dc)
    $rulesJson    = Join-Path $snapshotFolder ("{0}_rules.json"    -f $dc)
    $profilesCsv  = Join-Path $snapshotFolder ("{0}_profiles.csv"  -f $dc)
    $profilesJson = Join-Path $snapshotFolder ("{0}_profiles.json" -f $dc)

    if ($r.Rules)    {
        # Sort by Name so subsequent diffs / git diffs stay stable.
        $r.Rules    | Sort-Object Name | Export-Csv -Path $rulesCsv  -NoTypeInformation -Encoding UTF8
        $r.Rules    | Sort-Object Name | ConvertTo-Json -Depth 5 | Set-Content -Path $rulesJson -Encoding UTF8
    }
    if ($r.Profiles) {
        $r.Profiles | Sort-Object Name | Export-Csv -Path $profilesCsv -NoTypeInformation -Encoding UTF8
        $r.Profiles | Sort-Object Name | ConvertTo-Json -Depth 5 | Set-Content -Path $profilesJson -Encoding UTF8
    }

    Write-Host ("[{0}] {1} rules, {2} profiles -> {3}" -f $dc, ($r.Rules | Measure-Object).Count,
        ($r.Profiles | Measure-Object).Count, $snapshotFolder) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Optional: diff against a previous snapshot
# ---------------------------------------------------------------------------
if ($CompareWith) {
    Write-Host ""
    Write-Host "=== DIFF vs $CompareWith ===" -ForegroundColor Yellow

    # Fields used to detect a "modified" rule (Name is the key, excluded).
    $compareFields = @(
        'DisplayName','DisplayGroup','Group','Enabled','Direction','Action','Profile',
        'EdgeTraversalPolicy','PolicyStoreSourceType','PolicyStoreSource',
        'Protocol','LocalPort','RemotePort','IcmpType',
        'LocalAddress','RemoteAddress',
        'Program','Package','Service'
    )

    foreach ($r in $results) {
        $dc = $r.ComputerName
        $prevRulesPath    = Join-Path $CompareWith    ("{0}_rules.csv"    -f $dc)
        $prevProfilesPath = Join-Path $CompareWith    ("{0}_profiles.csv" -f $dc)
        $diffPath         = Join-Path $snapshotFolder ("{0}_diff.md"      -f $dc)

        if (-not (Test-Path -LiteralPath $prevRulesPath)) {
            Write-Host ("[{0}] no previous snapshot ({1}), skipping diff" -f $dc, $prevRulesPath) -ForegroundColor DarkGray
            continue
        }

        $prevRules = Import-Csv -Path $prevRulesPath -Encoding UTF8
        $currRules = $r.Rules

        $prevByName = @{}
        foreach ($p in $prevRules) { $prevByName[$p.Name] = $p }
        $currByName = @{}
        foreach ($c in $currRules) { $currByName[$c.Name] = $c }

        $added    = New-Object System.Collections.Generic.List[psobject]
        $removed  = New-Object System.Collections.Generic.List[psobject]
        $modified = New-Object System.Collections.Generic.List[psobject]

        foreach ($name in $currByName.Keys) {
            if (-not $prevByName.ContainsKey($name)) {
                $added.Add($currByName[$name])
                continue
            }
            $changes = New-Object System.Collections.Generic.List[string]
            foreach ($f in $compareFields) {
                $oldVal = [string]$prevByName[$name].$f
                $newVal = [string]$currByName[$name].$f
                if ($oldVal -ne $newVal) {
                    $changes.Add(("{0}: '{1}' -> '{2}'" -f $f, $oldVal, $newVal))
                }
            }
            if ($changes.Count -gt 0) {
                $modified.Add([pscustomobject]@{
                    Name        = $name
                    DisplayName = $currByName[$name].DisplayName
                    Changes     = ($changes -join ' ; ')
                })
            }
        }
        foreach ($name in $prevByName.Keys) {
            if (-not $currByName.ContainsKey($name)) {
                $removed.Add($prevByName[$name])
            }
        }

        # Profiles diff
        $profileChanges = New-Object System.Collections.Generic.List[string]
        if (Test-Path -LiteralPath $prevProfilesPath) {
            $prevProfiles = Import-Csv -Path $prevProfilesPath -Encoding UTF8
            $prevProfByName = @{}
            foreach ($p in $prevProfiles) { $prevProfByName[$p.Name] = $p }
            foreach ($curr in $r.Profiles) {
                if (-not $prevProfByName.ContainsKey($curr.Name)) { continue }
                $prev = $prevProfByName[$curr.Name]
                foreach ($f in 'Enabled','DefaultInboundAction','DefaultOutboundAction',
                                'AllowInboundRules','AllowLocalFirewallRules','AllowLocalIPsecRules',
                                'NotifyOnListen','LogAllowed','LogBlocked','LogFileName','LogMaxSizeKilobytes') {
                    $oldVal = [string]$prev.$f
                    $newVal = [string]$curr.$f
                    if ($oldVal -ne $newVal) {
                        $profileChanges.Add(("{0}.{1}: '{2}' -> '{3}'" -f $curr.Name, $f, $oldVal, $newVal))
                    }
                }
            }
        }

        # Console summary
        Write-Host ""
        Write-Host ("[{0}] Compared against {1}:" -f $dc, $CompareWith) -ForegroundColor White
        if ($added.Count    -gt 0) { Write-Host ("  + {0} rule(s) added"    -f $added.Count)    -ForegroundColor Green }
        if ($removed.Count  -gt 0) { Write-Host ("  - {0} rule(s) removed"  -f $removed.Count)  -ForegroundColor Red }
        if ($modified.Count -gt 0) { Write-Host ("  ~ {0} rule(s) modified" -f $modified.Count) -ForegroundColor Yellow }
        if ($profileChanges.Count -gt 0) {
            Write-Host ("  ! {0} profile setting(s) changed" -f $profileChanges.Count) -ForegroundColor Magenta
        }
        if ($added.Count    -eq 0 -and
            $removed.Count  -eq 0 -and
            $modified.Count -eq 0 -and
            $profileChanges.Count -eq 0) {
            Write-Host "  No changes detected." -ForegroundColor DarkGreen
        }

        # Markdown report
        $md = New-Object System.Collections.Generic.List[string]
        $md.Add("# Firewall diff for $dc")
        $md.Add("")
        $md.Add(("- Previous snapshot: ``{0}``" -f $prevRulesPath))
        $md.Add(("- Current snapshot : ``{0}``" -f $rulesCsv))
        $md.Add(("- Generated        : {0}"   -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
        $md.Add("")
        $md.Add("## Profile setting changes")
        $md.Add("")
        if ($profileChanges.Count -eq 0) {
            $md.Add("_No profile setting changed._")
        } else {
            foreach ($c in $profileChanges) { $md.Add("- $c") }
        }
        $md.Add("")
        $md.Add(("## Rules added ({0})"    -f $added.Count))
        $md.Add("")
        if ($added.Count -eq 0) {
            $md.Add("_None._")
        } else {
            $md.Add("| Name | DisplayName | DisplayGroup | Enabled | Direction | Action | Profile | Source |")
            $md.Add("|---|---|---|---|---|---|---|---|")
            foreach ($a in ($added | Sort-Object Name)) {
                $md.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                    $a.Name, $a.DisplayName, $a.DisplayGroup, $a.Enabled, $a.Direction, $a.Action, $a.Profile, $a.PolicyStoreSourceType))
            }
        }
        $md.Add("")
        $md.Add(("## Rules removed ({0})"  -f $removed.Count))
        $md.Add("")
        if ($removed.Count -eq 0) {
            $md.Add("_None._")
        } else {
            $md.Add("| Name | DisplayName | DisplayGroup | Enabled | Direction | Action | Profile | Source |")
            $md.Add("|---|---|---|---|---|---|---|---|")
            foreach ($a in ($removed | Sort-Object Name)) {
                $md.Add(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} |" -f `
                    $a.Name, $a.DisplayName, $a.DisplayGroup, $a.Enabled, $a.Direction, $a.Action, $a.Profile, $a.PolicyStoreSourceType))
            }
        }
        $md.Add("")
        $md.Add(("## Rules modified ({0})" -f $modified.Count))
        $md.Add("")
        if ($modified.Count -eq 0) {
            $md.Add("_None._")
        } else {
            foreach ($m in ($modified | Sort-Object Name)) {
                $md.Add(("### {0} - {1}" -f $m.Name, $m.DisplayName))
                foreach ($change in ($m.Changes -split ' ; ')) {
                    $md.Add("- $change")
                }
                $md.Add("")
            }
        }

        $md -join [Environment]::NewLine | Set-Content -Path $diffPath -Encoding UTF8
        Write-Host ("    diff report -> {0}" -f $diffPath) -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# Stop transcript (if it was started)
# ---------------------------------------------------------------------------
if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}

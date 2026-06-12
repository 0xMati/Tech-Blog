<#
.SYNOPSIS
    Exports the EFFECTIVE Windows Firewall rules and profile settings of every
    DC of a domain (Snapshot mode), or compares two existing snapshots and
    produces per-DC Markdown diff reports (Compare mode).

.DESCRIPTION
    The script has TWO mutually-exclusive modes selected by parameter set:

    Snapshot mode (default):
        For each Domain Controller, reads the ActiveStore (effective state =
        local + GPO + MDM merged) via Get-NetFirewallRule and
        Get-NetFirewallProfile, joins the associated PortFilter /
        AddressFilter / ApplicationFilter / ServiceFilter values, and writes
        directly into <OutputFolder> (no sub-folder is created):

            <OutputFolder>\<DC>_rules.csv
            <OutputFolder>\<DC>_rules.json
            <OutputFolder>\<DC>_profiles.csv
            <OutputFolder>\<DC>_profiles.json

        Files are sorted by rule Name so successive snapshots / git diffs
        stay stable. The PolicyStoreSourceType field on each rule tells you
        where the rule came from (Local vs GroupPolicy) - very useful right
        after a GPO push.

    Compare mode:
        No DC is queried. The script reads the CSV exports of two existing
        snapshot folders (typically a "before" and an "after") and writes,
        per DC found in the second folder:

            <OutputCompareFolder>\<DC>_diff.csv

        Each diff CSV has one row per change with columns:
            ChangeType (Added / Removed / Modified / ProfileChanged)
            Name, DisplayName
            Direction, Action, Profile, Source   (filled for Added/Removed only)
            Field, OldValue, NewValue            (filled for Modified/ProfileChanged only)

        plus a console summary "+N added / ~N modified / -N removed /
        !N profile changed" per DC.

.PARAMETER OutputFolder
    Snapshot mode only. Folder where the per-DC CSV/JSON snapshot files are
    written. Created if it does not exist. Existing files for the same DC
    are overwritten.

.PARAMETER ComputerName
    Snapshot mode only. List of DCs to query. If omitted, the script uses
    Get-ADDomainController -Filter * to target every DC of the current
    domain.

.PARAMETER Credential
    Snapshot mode only. Alternate credentials for the WinRM session.

.PARAMETER Compare
    Compare mode only. Exactly two folders: the "before" snapshot first,
    the "after" snapshot second. Both folders must contain the
    <DC>_rules.csv / <DC>_profiles.csv files produced by a previous
    Snapshot run.

.PARAMETER OutputCompareFolder
    Compare mode only. Folder where the per-DC <DC>_diff.md files are
    written. Created if it does not exist.

.PARAMETER Transcript
    Both modes. Starts Start-Transcript in the current working directory.

.EXAMPLE
    # Snapshot before a GPO change
    .\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\before-gpo

    # ... push GPO + gpupdate /force on the DCs ...

    # Snapshot after the change
    .\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\after-gpo

    # Compare the two snapshots
    .\Export-DCFirewallRules.ps1 `
        -Compare C:\Temp\FW\before-gpo, C:\Temp\FW\after-gpo `
        -OutputCompareFolder C:\Temp\FW\diff-gpo

.EXAMPLE
    # Snapshot only one DC
    .\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\dc01-baseline -ComputerName DC01
#>

[CmdletBinding(DefaultParameterSetName = 'Snapshot')]
param(
    # --- Snapshot mode ----------------------------------------------------
    [Parameter(ParameterSetName = 'Snapshot', Mandatory)]
    [string]$OutputFolder,

    [Parameter(ParameterSetName = 'Snapshot')]
    [string[]]$ComputerName,                       # If empty: all DCs of the current domain

    [Parameter(ParameterSetName = 'Snapshot')]
    [PSCredential]$Credential,

    # --- Compare mode -----------------------------------------------------
    [Parameter(ParameterSetName = 'Compare', Mandatory)]
    [ValidateCount(2, 2)]
    [string[]]$Compare,                            # 2 folders: before, after

    [Parameter(ParameterSetName = 'Compare', Mandatory)]
    [string]$OutputCompareFolder,                  # Where the *_diff.md files go

    # --- Both modes -------------------------------------------------------
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
# COMPARE MODE - read 2 existing snapshots, write diffs, then exit.
# ---------------------------------------------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Compare') {
    $beforeFolder = $Compare[0]
    $afterFolder  = $Compare[1]

    foreach ($folder in @($beforeFolder, $afterFolder)) {
        if (-not (Test-Path -LiteralPath $folder)) {
            throw "Compare folder not found: $folder"
        }
    }
    if (-not (Test-Path -LiteralPath $OutputCompareFolder)) {
        New-Item -ItemType Directory -Path $OutputCompareFolder -Force | Out-Null
    }

    Write-Host ("Before snapshot   : {0}" -f $beforeFolder) -ForegroundColor Cyan
    Write-Host ("After snapshot    : {0}" -f $afterFolder) -ForegroundColor Cyan
    Write-Host ("Diff output folder: {0}" -f $OutputCompareFolder) -ForegroundColor Cyan

    # DC list = every <DC>_rules.csv found in the "after" folder.
    $afterRulesFiles = Get-ChildItem -LiteralPath $afterFolder -Filter '*_rules.csv' -File -ErrorAction Stop
    if (-not $afterRulesFiles) {
        throw "No *_rules.csv files found in $afterFolder. Did you run Snapshot mode against this folder first?"
    }

    # Fields used to detect a "modified" rule (Name is the key, excluded).
    $compareFields = @(
        'DisplayName','DisplayGroup','Group','Enabled','Direction','Action','Profile',
        'EdgeTraversalPolicy','PolicyStoreSourceType','PolicyStoreSource',
        'Protocol','LocalPort','RemotePort','IcmpType',
        'LocalAddress','RemoteAddress',
        'Program','Package','Service'
    )

    Write-Host ""
    Write-Host "=== DIFF ===" -ForegroundColor Yellow

    foreach ($currFile in $afterRulesFiles) {
        $dc                = $currFile.BaseName -replace '_rules$', ''
        $prevRulesPath     = Join-Path $beforeFolder ("{0}_rules.csv"    -f $dc)
        $prevProfilesPath  = Join-Path $beforeFolder ("{0}_profiles.csv" -f $dc)
        $currRulesPath     = $currFile.FullName
        $currProfilesPath  = Join-Path $afterFolder  ("{0}_profiles.csv" -f $dc)
        $diffPath          = Join-Path $OutputCompareFolder ("{0}_diff.csv" -f $dc)

        if (-not (Test-Path -LiteralPath $prevRulesPath)) {
            Write-Host ("[{0}] no matching snapshot in {1}, skipping" -f $dc, $beforeFolder) -ForegroundColor DarkGray
            continue
        }

        $prevRules = Import-Csv -Path $prevRulesPath -Encoding UTF8 -Delimiter ';'
        $currRules = Import-Csv -Path $currRulesPath -Encoding UTF8 -Delimiter ';'

        $prevByName = @{}
        foreach ($p in $prevRules) { $prevByName[$p.Name] = $p }
        $currByName = @{}
        foreach ($c in $currRules) { $currByName[$c.Name] = $c }

        # One row per change goes into this list and is exported as CSV.
        $diffRows = New-Object System.Collections.Generic.List[psobject]

        $addedCount = 0
        $removedCount = 0
        $modifiedCount = 0
        $profileChangedCount = 0

        # ---- Rules added / modified ----------------------------------
        foreach ($name in $currByName.Keys) {
            $curr = $currByName[$name]
            if (-not $prevByName.ContainsKey($name)) {
                $addedCount++
                $diffRows.Add([pscustomobject]@{
                    ChangeType  = 'Added'
                    Name        = $name
                    DisplayName = $curr.DisplayName
                    Direction   = $curr.Direction
                    Action      = $curr.Action
                    Profile     = $curr.Profile
                    Source      = $curr.PolicyStoreSourceType
                    Field       = ''
                    OldValue    = ''
                    NewValue    = ''
                })
                continue
            }
            $prev = $prevByName[$name]
            $ruleChanged = $false
            foreach ($f in $compareFields) {
                $oldVal = [string]$prev.$f
                $newVal = [string]$curr.$f
                if ($oldVal -ne $newVal) {
                    $diffRows.Add([pscustomobject]@{
                        ChangeType  = 'Modified'
                        Name        = $name
                        DisplayName = $curr.DisplayName
                        Direction   = ''
                        Action      = ''
                        Profile     = ''
                        Source      = ''
                        Field       = $f
                        OldValue    = $oldVal
                        NewValue    = $newVal
                    })
                    $ruleChanged = $true
                }
            }
            if ($ruleChanged) { $modifiedCount++ }
        }

        # ---- Rules removed -------------------------------------------
        foreach ($name in $prevByName.Keys) {
            if (-not $currByName.ContainsKey($name)) {
                $removedCount++
                $prev = $prevByName[$name]
                $diffRows.Add([pscustomobject]@{
                    ChangeType  = 'Removed'
                    Name        = $name
                    DisplayName = $prev.DisplayName
                    Direction   = $prev.Direction
                    Action      = $prev.Action
                    Profile     = $prev.Profile
                    Source      = $prev.PolicyStoreSourceType
                    Field       = ''
                    OldValue    = ''
                    NewValue    = ''
                })
            }
        }

        # ---- Profile setting changes ---------------------------------
        if ((Test-Path -LiteralPath $prevProfilesPath) -and (Test-Path -LiteralPath $currProfilesPath)) {
            $prevProfiles  = Import-Csv -Path $prevProfilesPath -Encoding UTF8 -Delimiter ';'
            $currProfiles  = Import-Csv -Path $currProfilesPath -Encoding UTF8 -Delimiter ';'
            $prevProfByName = @{}
            foreach ($p in $prevProfiles) { $prevProfByName[$p.Name] = $p }
            foreach ($curr in $currProfiles) {
                if (-not $prevProfByName.ContainsKey($curr.Name)) { continue }
                $prev = $prevProfByName[$curr.Name]
                foreach ($f in 'Enabled','DefaultInboundAction','DefaultOutboundAction',
                                'AllowInboundRules','AllowLocalFirewallRules','AllowLocalIPsecRules',
                                'NotifyOnListen','LogAllowed','LogBlocked','LogFileName','LogMaxSizeKilobytes') {
                    $oldVal = [string]$prev.$f
                    $newVal = [string]$curr.$f
                    if ($oldVal -ne $newVal) {
                        $profileChangedCount++
                        $diffRows.Add([pscustomobject]@{
                            ChangeType  = 'ProfileChanged'
                            Name        = ''
                            DisplayName = $curr.Name           # profile name (Domain/Private/Public)
                            Direction   = ''
                            Action      = ''
                            Profile     = ''
                            Source      = ''
                            Field       = $f
                            OldValue    = $oldVal
                            NewValue    = $newVal
                        })
                    }
                }
            }
        }

        # ---- Console summary -----------------------------------------
        Write-Host ""
        Write-Host ("[{0}] {1}  vs  {2}" -f $dc, $prevRulesPath, $currRulesPath) -ForegroundColor White
        if ($addedCount          -gt 0) { Write-Host ("  + {0} rule(s) added"           -f $addedCount)          -ForegroundColor Green }
        if ($removedCount        -gt 0) { Write-Host ("  - {0} rule(s) removed"         -f $removedCount)        -ForegroundColor Red }
        if ($modifiedCount       -gt 0) { Write-Host ("  ~ {0} rule(s) modified"        -f $modifiedCount)       -ForegroundColor Yellow }
        if ($profileChangedCount -gt 0) { Write-Host ("  ! {0} profile setting(s) changed" -f $profileChangedCount) -ForegroundColor Magenta }
        if ($addedCount    -eq 0 -and
            $removedCount  -eq 0 -and
            $modifiedCount -eq 0 -and
            $profileChangedCount -eq 0) {
            Write-Host "  No changes detected." -ForegroundColor DarkGreen
        }

        # ---- CSV report ----------------------------------------------
        # Always write the file so its absence means "the comparison was
        # not run for that DC" and not "no changes". An empty diff has
        # only the header row.
        $diffRows |
            Sort-Object ChangeType, Name, DisplayName, Field |
            Export-Csv -Path $diffPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host ("    diff report -> {0}" -f $diffPath) -ForegroundColor DarkGray
    }

    if ($transcriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
    return
}

# ---------------------------------------------------------------------------
# SNAPSHOT MODE - resolve DC list and prepare the output folder.
# ---------------------------------------------------------------------------
if (-not $ComputerName) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $ComputerName = (Get-ADDomainController -Filter *).HostName
}

if (-not (Test-Path -LiteralPath $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}
Write-Host ("Output folder : {0}" -f $OutputFolder) -ForegroundColor Cyan

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
    $rulesCsv     = Join-Path $OutputFolder ("{0}_rules.csv"     -f $dc)
    $rulesJson    = Join-Path $OutputFolder ("{0}_rules.json"    -f $dc)
    $profilesCsv  = Join-Path $OutputFolder ("{0}_profiles.csv"  -f $dc)
    $profilesJson = Join-Path $OutputFolder ("{0}_profiles.json" -f $dc)

    if ($r.Rules)    {
        # Sort by Name so subsequent diffs / git diffs stay stable.
        $r.Rules    | Sort-Object Name | Export-Csv -Path $rulesCsv  -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        $r.Rules    | Sort-Object Name | ConvertTo-Json -Depth 5 | Set-Content -Path $rulesJson -Encoding UTF8
    }
    if ($r.Profiles) {
        $r.Profiles | Sort-Object Name | Export-Csv -Path $profilesCsv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        $r.Profiles | Sort-Object Name | ConvertTo-Json -Depth 5 | Set-Content -Path $profilesJson -Encoding UTF8
    }

    Write-Host ("[{0}] {1} rules, {2} profiles -> {3}" -f $dc, ($r.Rules | Measure-Object).Count,
        ($r.Profiles | Measure-Object).Count, $OutputFolder) -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# Stop transcript (if it was started)
# ---------------------------------------------------------------------------
if ($transcriptStarted) {
    try { Stop-Transcript | Out-Null } catch { }
}

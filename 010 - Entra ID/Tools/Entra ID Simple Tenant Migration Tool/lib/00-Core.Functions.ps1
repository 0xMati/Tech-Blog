#Requires -Version 5.1

Set-StrictMode -Version Latest
$script:ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Console UI helpers (visual wizard)
# ------------------------------------------------------------

function Write-EIDMHeader {
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host ("  " + $Text) -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-EIDMSection {
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ""
    Write-Host ("--- " + $Text + " ---") -ForegroundColor Yellow
    Write-Host ""
}

function Write-EIDMTag {
    param(
        [Parameter(Mandatory)][string]$Tag,
        [Parameter(Mandatory)][string]$Text,
        [ValidateSet('Gray','Green','Yellow','Red','Cyan','Magenta','White','DarkCyan','DarkYellow','DarkGray')]
        [string]$Color = 'Gray'
    )

    Write-Host ("[" + $Tag + "] ") -NoNewline -ForegroundColor $Color
    Write-Host $Text -ForegroundColor White
}

function Read-EIDMYesNo {
    param(
        [Parameter(Mandatory)][string]$Question,
        [Parameter(Mandatory)][string[]]$Details,
        [bool]$DefaultYes = $true,
        [string]$Tag = "INFO",
        [ValidateSet('Gray','Green','Yellow','Red','Cyan','Magenta','White','DarkCyan','DarkYellow','DarkGray')]
        [string]$TagColor = "Gray"
    )

    Write-Host ""
    Write-EIDMTag -Tag $Tag -Text $Question -Color $TagColor

    foreach ($line in $Details) {
        Write-Host ("  - " + $line) -ForegroundColor DarkGray
    }

    $suffix = if ($DefaultYes) { "[Y/n]" } else { "[y/N]" }
    $ans = Read-Host ("Answer " + $suffix)

    if ([string]::IsNullOrWhiteSpace($ans)) { return $DefaultYes }

    $v = $ans.Trim().ToLower()
    return ($v -in @('y','yes'))
}

function Read-EIDMSimpleYesNo {
    <#
    .SYNOPSIS  Lightweight Y/N prompt (no tag/detail overhead).
    .DESCRIPTION  Returns $true for Y, $false for N. No implicit default:
                  the prompt loops until the user types Y or N. The square
                  brackets in "[y/n]" are a visual cue, NOT a default value.
    #>
    param([Parameter(Mandatory)][string]$Question)
    do {
        $r = Read-Host ("{0} [y/n]" -f $Question)
        if (-not $r) { continue }
        $r = $r.Trim()
    } while ($r -notmatch '^[YyNn]$')
    return ($r -match '^[Yy]$')
}

function Read-EIDMNonEmpty {
    <#
    .SYNOPSIS  Prompt that refuses blank input.
    #>
    param([Parameter(Mandatory)][string]$Question)
    while ($true) {
        $value = Read-Host $Question
        if (-not [string]::IsNullOrWhiteSpace($value)) { return $value.Trim() }
        Write-Host "Value cannot be empty." -ForegroundColor Yellow
    }
}

function Test-EIDMGuidFormat {
    <#
    .SYNOPSIS  Returns $true if the string is a valid GUID.
    #>
    param([Parameter(Mandatory)][string]$Candidate)
    $out = [guid]::Empty
    return [guid]::TryParse($Candidate, [ref]$out)
}

function Read-EIDMWorkloadChoices {
    param(
        [hashtable]$Defaults = @{
            Discovery           = $true
            IdentityPreparation = $true
            ExchangeMigration   = $true
            OneDriveMigration   = $true
            SharePointMigration = $false
        }
    )

    $workloadDefs = [ordered]@{
        Discovery           = @{ Question = 'Run Discovery [READ-ONLY]?';           Tag = 'READ-ONLY'; TagColor = 'Green'
                                  Details  = @('Exports tenant inventory as CSV files','Does NOT modify anything',"Output folder: output\runs\<RunId>\01-Discovery\") }
        IdentityPreparation = @{ Question = 'Run Identity Preparation [WRITE]?';    Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares identity objects and mappings','May create or update objects',"Output folder: output\runs\<RunId>\02-IdentityPreparation\") }
        ExchangeMigration   = @{ Question = 'Run Exchange Migration [WRITE]?';      Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares and/or executes Exchange mailbox migration steps','May create batches or modify migration settings',"Output folder: output\runs\<RunId>\03-ExchangeMigrationPlan\ and 04-ExchangeMigrationExecution\") }
        OneDriveMigration   = @{ Question = 'Run OneDrive Migration [WRITE]?';      Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares and/or executes OneDrive migration steps','May create migration tasks/endpoints depending on implementation',"Output folder: output\runs\<RunId>\05-OneDriveMigrationPlan\ and 06-OneDriveMigrationExecution\") }
        SharePointMigration = @{ Question = 'Run SharePoint Migration [WRITE]?';    Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares and/or executes SharePoint migration steps','May create migration tasks/endpoints depending on implementation',"Output folder: output\runs\<RunId>\07-SharePointMigrationPlan\ and 08-SharePointMigrationExecution\") }
    }

    $results = @{}
    foreach ($name in $workloadDefs.Keys) {
        $wl = $workloadDefs[$name]
        $default = if ($Defaults.ContainsKey($name)) { [bool]$Defaults[$name] } else { $true }
        $results[$name] = Read-EIDMYesNo `
            -Question $wl.Question `
            -Details $wl.Details `
            -DefaultYes $default `
            -Tag $wl.Tag `
            -TagColor $wl.TagColor
    }

    return $results
}

# ------------------------------------------------------------
# Logging + filesystem helpers
# ------------------------------------------------------------

function Write-EIDMLog {
    param(
        [Parameter(Mandatory)] [string]$LogPath,
        [Parameter(Mandatory)] [ValidateSet('INFO','WARN','ERROR','DEBUG')] [string]$Level,
        [Parameter(Mandatory)] [string]$Message
    )

    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
}

function Assert-EIDMDirectory {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function New-EIDMRunId {
    return (Get-Date -Format 'yyyy-MM-dd_HHmmss')
}

# ------------------------------------------------------------
# Config wizard (interactive) + config persistence (.psd1)
# ------------------------------------------------------------

function New-EIDMConfigWizard {
    param([Parameter(Mandatory)][string]$RepoRoot)

    Write-EIDMHeader "Entra ID Simple Tenant Migration Tool - Configuration Wizard"

    Write-EIDMTag -Tag "NOTE"   -Text "This wizard creates a local config file: config\config.psd1" -Color Cyan
    Write-EIDMTag -Tag "NOTE"   -Text "No secrets are stored in the config file." -Color Cyan
    Write-EIDMTag -Tag "OUTPUT" -Text "All generated files will be stored under: output\runs\<RunId>\" -Color Cyan
    Write-Host ""

    Write-EIDMSection "Tenants"

    Write-EIDMTag -Tag "INFO" -Text "Enter tenant identifiers (domain or tenantId)." -Color Gray
    Write-Host "Press Enter to accept the default value shown in brackets." -ForegroundColor DarkGray
    Write-Host ""

    $src = Read-Host "SOURCE tenant (domain or tenantId) [e.g. source.onmicrosoft.com]"
    if ([string]::IsNullOrWhiteSpace($src)) { $src = "source.onmicrosoft.com" }

    $tgt = Read-Host "TARGET tenant (domain or tenantId) [e.g. target.onmicrosoft.com]"
    if ([string]::IsNullOrWhiteSpace($tgt)) { $tgt = "target.onmicrosoft.com" }

    # Simplified: fixed output location
    $out = ".\output\runs"

    $workloads = Read-EIDMWorkloadChoices

    Write-EIDMSection "Summary"

    Write-EIDMTag -Tag "SOURCE" -Text $src -Color Cyan
    Write-EIDMTag -Tag "TARGET" -Text $tgt -Color Cyan
    Write-Host ""
    Write-EIDMTag -Tag "WORKLOADS" -Text ("Discovery={0}, IdentityPreparation={1}, ExchangeMigration={2}, OneDriveMigration={3}, SharePointMigration={4}" -f `
        $workloads.Discovery, $workloads.IdentityPreparation, $workloads.ExchangeMigration, $workloads.OneDriveMigration, $workloads.SharePointMigration) -Color Magenta
    Write-Host ""

    $confirm = Read-EIDMYesNo `
        -Question "Save this configuration to config\config.psd1?" `
        -Details @("You can delete config\config.psd1 to re-run the wizard anytime.") `
        -DefaultYes $true `
        -Tag "CONFIRM" `
        -TagColor "Cyan"

    if (-not $confirm) {
        throw "Configuration wizard cancelled by user."
    }

    return @{
        Run = @{ OutputRoot = $out }
        Tenants = @{
            Source = @{ TenantIdOrDomain = $src }
            Target = @{ TenantIdOrDomain = $tgt }
        }
        Workloads = $workloads
    }
}

function Save-EIDMConfigPsd1 {
    param(
        [Parameter(Mandatory)][hashtable]$Config,
        [Parameter(Mandatory)][string]$Path
    )

    Assert-EIDMDirectory -Path (Split-Path -Parent $Path)

    # Helper: PSD1 boolean formatting
    function ConvertTo-PsdBool([bool]$Value) { if ($Value) { '$true' } else { '$false' } }

    # Escape single quotes for PSD1 strings
    $src = [string]$Config.Tenants.Source.TenantIdOrDomain
    $tgt = [string]$Config.Tenants.Target.TenantIdOrDomain
    $out = [string]$Config.Run.OutputRoot

    $src = $src.Replace("'", "''")
    $tgt = $tgt.Replace("'", "''")
    $out = $out.Replace("'", "''")

    $w = $Config.Workloads

    # Optional persisted values (non-secrets)
    $lastOU = ""
    if ($Config.ContainsKey("OnPremIdentity")) {
        if ($Config.OnPremIdentity -and $Config.OnPremIdentity.ContainsKey("LastUsedTargetOU")) {
            $lastOU = [string]$Config.OnPremIdentity.LastUsedTargetOU
        }
    }
    $lastOU = $lastOU.Replace("'", "''")

    $psd1 = @"
@{
  Run = @{
    OutputRoot = '$out'
  }

  Tenants = @{
    Source = @{ TenantIdOrDomain = '$src' }
    Target = @{ TenantIdOrDomain = '$tgt' }
  }

  Workloads = @{
    Discovery           = $(ConvertTo-PsdBool ([bool]$w.Discovery))
    IdentityPreparation = $(ConvertTo-PsdBool ([bool]$w.IdentityPreparation))
    ExchangeMigration   = $(ConvertTo-PsdBool ([bool]$w.ExchangeMigration))
    OneDriveMigration   = $(ConvertTo-PsdBool ([bool]$w.OneDriveMigration))
    SharePointMigration = $(ConvertTo-PsdBool ([bool]$w.SharePointMigration))
  }

  OnPremIdentity = @{
    LastUsedTargetOU = '$lastOU'
  }
}
"@

    Set-Content -LiteralPath $Path -Value $psd1 -Encoding UTF8
}

# ------------------------------------------------------------
# Run initialization (creates output/run folders + log)
# ------------------------------------------------------------

function Initialize-EIDMRun {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $runId = New-EIDMRunId

    # Simplified: fixed output root expected in config (defaults to .\output\runs)
    $outputRootRel = $Config.Run.OutputRoot
    if ([string]::IsNullOrWhiteSpace($outputRootRel)) { $outputRootRel = ".\output\runs" }

    $outputRoot = Join-Path $RepoRoot $outputRootRel
    $runRoot = Join-Path $outputRoot $runId

    Assert-EIDMDirectory -Path $runRoot
    Assert-EIDMDirectory -Path (Join-Path $runRoot "logs")

    # Workload folders (match phases naming)
    @('01-Discovery','02-IdentityPreparation','03-ExchangeMigrationPlan','04-ExchangeMigrationExecution','05-OneDriveMigrationPlan','06-OneDriveMigrationExecution','07-SharePointMigrationPlan','08-SharePointMigrationExecution') | ForEach-Object {
        Assert-EIDMDirectory -Path (Join-Path $runRoot $_)
    }

    $logPath = Join-Path $runRoot "logs\run.log"
    if (-not (Test-Path -LiteralPath $logPath)) {
        New-Item -ItemType File -Path $logPath -Force | Out-Null
    }

    return [pscustomobject]@{
        RepoRoot   = $RepoRoot
        RunId      = $runId
        OutputRoot = $outputRoot
        RunRoot    = $runRoot
        LogPath    = $logPath
    }
}

function Edit-EIDMConfigWizard {
    param(
        [Parameter(Mandatory)][hashtable]$CurrentConfig
    )

    Write-EIDMHeader "Edit Existing Configuration"

    $currentSrc = $CurrentConfig.Tenants.Source.TenantIdOrDomain
    $currentTgt = $CurrentConfig.Tenants.Target.TenantIdOrDomain

    Write-EIDMSection "Tenants"
    Write-EIDMTag -Tag "INFO" -Text "Press Enter to keep the current value." -Color Gray
    Write-Host ""

    $src = Read-Host ("SOURCE tenant (domain or tenantId) [{0}]" -f $currentSrc)
    if ([string]::IsNullOrWhiteSpace($src)) { $src = $currentSrc }

    $tgt = Read-Host ("TARGET tenant (domain or tenantId) [{0}]" -f $currentTgt)
    if ([string]::IsNullOrWhiteSpace($tgt)) { $tgt = $currentTgt }

    # Simplified: fixed output location (keep it, do not ask)
    $out = ".\output\runs"

    $workloads = Read-EIDMWorkloadChoices -Defaults $CurrentConfig.Workloads

    Write-EIDMSection "Summary"
    Write-EIDMTag -Tag "SOURCE" -Text $src -Color Cyan
    Write-EIDMTag -Tag "TARGET" -Text $tgt -Color Cyan
    Write-Host ""
    Write-EIDMTag -Tag "WORKLOADS" -Text ("Discovery={0}, IdentityPreparation={1}, ExchangeMigration={2}, OneDriveMigration={3}, SharePointMigration={4}" -f `
        $workloads.Discovery, $workloads.IdentityPreparation, $workloads.ExchangeMigration, $workloads.OneDriveMigration, $workloads.SharePointMigration) -Color Magenta
    Write-Host ""

    $confirm = Read-EIDMYesNo `
        -Question "Save updated configuration to config\config.psd1?" `
        -Details @("This will overwrite the existing config file.") `
        -DefaultYes $true `
        -Tag "CONFIRM" `
        -TagColor "Cyan"

    if (-not $confirm) {
        throw "Edit wizard cancelled by user."
    }

    return @{
        Run = @{ OutputRoot = $out }
        Tenants = @{
            Source = @{ TenantIdOrDomain = $src }
            Target = @{ TenantIdOrDomain = $tgt }
        }
        Workloads = $workloads
    }
}
function Select-EIDMConfigAction {
    param([Parameter(Mandatory)][string]$ConfigPath)

    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Configuration                                           |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  A configuration file was found:" -ForegroundColor Gray
    Write-Host "  $ConfigPath" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  The configuration file stores the settings for this tool:" -ForegroundColor DarkGray
    Write-Host "    - SOURCE tenant: the Microsoft 365 tenant you migrate FROM" -ForegroundColor DarkGray
    Write-Host "      (e.g. source.contoso.com or source.onmicrosoft.com)" -ForegroundColor DarkGray
    Write-Host "    - TARGET tenant: the Microsoft 365 tenant you migrate TO" -ForegroundColor DarkGray
    Write-Host "      (e.g. target.contoso.com or target.onmicrosoft.com)" -ForegroundColor DarkGray
    Write-Host "    - Workloads: which migration tasks are enabled" -ForegroundColor DarkGray
    Write-Host "      (Discovery, Identity, Exchange, OneDrive, SharePoint)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  If this is your first time, choose option 2 to review the" -ForegroundColor DarkGray
    Write-Host "  current settings, or option 4 to start fresh." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " Use existing config" -ForegroundColor Green
    Write-Host "      Keep the current settings and proceed to the run menu." -ForegroundColor DarkGray
    Write-Host "      Choose this if nothing has changed since last time." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " View config (read-only)" -ForegroundColor Cyan
    Write-Host "      Display the current tenants and workload settings." -ForegroundColor DarkGray
    Write-Host "      No changes will be made. You will return to this menu." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Edit config" -ForegroundColor Yellow
    Write-Host "      Modify tenant domains, enable/disable workloads, etc." -ForegroundColor DarkGray
    Write-Host "      The updated config will be saved to disk." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 4 " -NoNewline -ForegroundColor White -BackgroundColor DarkRed; Write-Host " Re-run wizard (overwrite)" -ForegroundColor Red
    Write-Host "      Start the configuration wizard from scratch." -ForegroundColor DarkGray
    Write-Host "      The existing config file will be overwritten." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 5 " -NoNewline -ForegroundColor Gray -BackgroundColor DarkGray; Write-Host " Exit" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {
        $choice = Read-Host "Enter choice [1-5]"
        switch ($choice) {
            '1' { return 'USE' }
            '2' { return 'VIEW' }
            '3' { return 'EDIT' }
            '4' { return 'RECREATE' }
            '5' { return 'CANCEL' }
            default {
                Write-EIDMTag -Tag "ERROR" -Text "Invalid choice. Please enter 1, 2, 3, 4, or 5." -Color Red
            }
        }
    }
}

function Show-EIDMCurrentConfig {
    param([Parameter(Mandatory)][hashtable]$Config)

    Write-EIDMSection "Current Configuration (Read-Only View)"

    $src = $Config.Tenants.Source.TenantIdOrDomain
    $tgt = $Config.Tenants.Target.TenantIdOrDomain
    $w   = $Config.Workloads

    Write-EIDMTag -Tag "SOURCE" -Text $src -Color Cyan
    Write-EIDMTag -Tag "TARGET" -Text $tgt -Color Cyan
    Write-Host ""

    Write-EIDMTag -Tag "WORKLOADS" -Text ("Discovery={0}" -f $w.Discovery) -Color Magenta
    Write-EIDMTag -Tag "WORKLOADS" -Text ("IdentityPreparation={0}" -f $w.IdentityPreparation) -Color Magenta
    Write-EIDMTag -Tag "WORKLOADS" -Text ("ExchangeMigration={0}" -f $w.ExchangeMigration) -Color Magenta
    Write-EIDMTag -Tag "WORKLOADS" -Text ("OneDriveMigration={0}" -f $w.OneDriveMigration) -Color Magenta
    Write-EIDMTag -Tag "WORKLOADS" -Text ("SharePointMigration={0}" -f $w.SharePointMigration) -Color Magenta

    Write-Host ""
}
function Get-EIDMOutputRunsRoot {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $rel = $Config.Run.OutputRoot
    if ([string]::IsNullOrWhiteSpace($rel)) { $rel = ".\output\runs" }
    return (Join-Path $RepoRoot $rel)
}

function Ensure-EIDMRunStateFile {
    param([Parameter(Mandatory)]$Ctx)

    $path = Join-Path $Ctx.RunRoot "run_state.csv"
    if (-not (Test-Path -LiteralPath $path)) {
        "Timestamp,Phase,Step,Status,Message" | Set-Content -LiteralPath $path -Encoding UTF8
    }
}

function Add-EIDMRunStateEntry {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string]$Phase,
        [Parameter(Mandatory)][string]$Step,
        [Parameter(Mandatory)][string]$Status,
        [Parameter(Mandatory)][string]$Message
    )

    $path = Join-Path $Ctx.RunRoot "run_state.csv"

    [PSCustomObject]@{
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Phase     = $Phase
        Step      = $Step
        Status    = $Status
        Message   = $Message
    } | Export-Csv -LiteralPath $path -Append -NoTypeInformation -Encoding UTF8
}

function Show-EIDMRunState {
    param([Parameter(Mandatory)]$Ctx)

    $path = Join-Path $Ctx.RunRoot "run_state.csv"

    Write-EIDMSection "Run State"
    Write-EIDMTag -Tag "RUN" -Text ("RunId: {0}" -f $Ctx.RunId) -Color Cyan
    Write-EIDMTag -Tag "FILE" -Text ("State file: {0}" -f $path) -Color Cyan
    Write-Host ""

    if (-not (Test-Path -LiteralPath $path)) {
        Write-EIDMTag -Tag "WARN" -Text "run_state.csv not found." -Color Yellow
        return
    }

    $rows = @(Import-Csv -LiteralPath $path)

    if ($rows.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No entries yet." -Color DarkGray
        return
    }

    $tail = $rows | Select-Object -Last 20
    $tail | Format-Table -AutoSize

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text "Showing last 20 entries." -Color DarkGray
}


function Select-EIDMExistingRun {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][hashtable]$Config
    )

    $runsRoot = Get-EIDMOutputRunsRoot -RepoRoot $RepoRoot -Config $Config

    if (-not (Test-Path -LiteralPath $runsRoot)) {
        Write-EIDMTag -Tag "WARN" -Text ("No runs folder found: {0}" -f $runsRoot) -Color Yellow
        return $null
    }

    $dirs = @(Get-ChildItem -LiteralPath $runsRoot -Directory | Sort-Object Name -Descending)

    if ($dirs.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No existing runs found." -Color Yellow
        return $null
    }

    Write-EIDMSection "Select a Run"

    for ($i = 0; $i -lt $dirs.Count; $i++) {
        Write-Host ("  {0}) {1}" -f ($i + 1), $dirs[$i].Name) -ForegroundColor White
    }

    Write-Host "  X) Cancel" -ForegroundColor DarkGray
    Write-Host ""

    while ($true) {

        $ans = Read-Host "Select run number"

        if ($ans.Trim().ToUpper() -eq 'X') {
            return $null
        }

        $n = 0
        if ([int]::TryParse($ans, [ref]$n)) {

            if ($n -ge 1 -and $n -le $dirs.Count) {

                $selected = $dirs[$n - 1]

                $logPath = Join-Path $selected.FullName "logs\run.log"

                if (-not (Test-Path -LiteralPath $logPath)) {
                    Assert-EIDMDirectory -Path (Join-Path $selected.FullName "logs")
                    New-Item -ItemType File -Path $logPath -Force | Out-Null
                }

                return [pscustomobject]@{
                    RepoRoot   = $RepoRoot
                    RunId      = $selected.Name
                    OutputRoot = $runsRoot
                    RunRoot    = $selected.FullName
                    LogPath    = $logPath
                }
            }
        }

        Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
    }
}


function Select-EIDMPhaseFromUser {

    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Select a Phase to Execute                               |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Phases should be executed in order. Each contains multiple steps." -ForegroundColor DarkGray
    Write-Host ""

    # --- Section: Inventory ---
    Write-Host "  " -NoNewline; Write-Host " INVENTORY & PREPARATION " -ForegroundColor White -BackgroundColor DarkGreen
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " 01-Discovery" -ForegroundColor Green
    Write-Host "      Inventory SOURCE tenant: users, groups, licenses, mailboxes, OneDrive." -ForegroundColor DarkGray
    Write-Host "      Read-only -- exports CSV reports, no changes are made." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " 02-IdentityPreparation" -ForegroundColor Green
    Write-Host "      Create user accounts on TARGET (AD synced + cloud-only)." -ForegroundColor DarkGray
    Write-Host "      Builds provisioning plans, creates accounts, sets passwords." -ForegroundColor DarkGray
    Write-Host ""

    # --- Section: Exchange ---
    Write-Host "  " -NoNewline; Write-Host " EXCHANGE ONLINE MIGRATION " -ForegroundColor Black -BackgroundColor DarkYellow
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " 03-ExchangeMigrationPlan" -ForegroundColor Yellow
    Write-Host "      Prepare cross-tenant mailbox migration: prerequisites check," -ForegroundColor DarkGray
    Write-Host "      org relationship, migration endpoint, scope group, MailUser stamps." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 4 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " 04-ExchangeMigrationExecution" -ForegroundColor Yellow
    Write-Host "      Execute mailbox migration: create batches, monitor progress," -ForegroundColor DarkGray
    Write-Host "      complete/stop batches, assign licenses to migrated users." -ForegroundColor DarkGray
    Write-Host ""

    # --- Section: OneDrive ---
    Write-Host "  " -NoNewline; Write-Host " ONEDRIVE MIGRATION " -ForegroundColor White -BackgroundColor DarkCyan
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 5 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " 05-OneDriveMigrationPlan" -ForegroundColor Cyan
    Write-Host "      Prepare OneDrive migration: user mapping, cross-tenant trust," -ForegroundColor DarkGray
    Write-Host "      CTIM identity map, license assignment, OneDrive pre-provisioning." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 6 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " 06-OneDriveMigrationExecution" -ForegroundColor Cyan
    Write-Host "      Upload identity map, start moves, monitor status, reset trust." -ForegroundColor DarkGray
    Write-Host ""

    # --- Section: SharePoint ---
    Write-Host "  " -NoNewline; Write-Host " SHAREPOINT MIGRATION " -ForegroundColor White -BackgroundColor DarkMagenta
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 7 " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta; Write-Host " 07-SharePointMigrationPlan" -ForegroundColor Magenta
    Write-Host "      Discover SharePoint sites, build mapping, verify trust," -ForegroundColor DarkGray
    Write-Host "      upload identity map, check compatibility." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 8 " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta; Write-Host " 08-SharePointMigrationExecution" -ForegroundColor Magenta
    Write-Host "      Start site moves, monitor status, cancel/stop, cleanup." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " X " -NoNewline -ForegroundColor White -BackgroundColor DarkRed; Write-Host " Cancel - return to main menu" -ForegroundColor Red
    Write-Host ""

    $ans = Read-Host "Select phase [1-8 or X]"
    if ($ans.Trim().ToUpper() -eq 'X') { return $null }

    switch ($ans) {
        '1' { return "01-Discovery" }
        '2' { return "02-IdentityPreparation" }
        '3' { return "03-ExchangeMigrationPlan" }
        '4' { return "04-ExchangeMigrationExecution" }
        '5' { return "05-OneDriveMigrationPlan" }
        '6' { return "06-OneDriveMigrationExecution" }
        '7' { return "07-SharePointMigrationPlan" }
        '8' { return "08-SharePointMigrationExecution" }
        default {
            Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
            return $null
        }
    }
}
# ------------------------------------------------------------
# Step Framework - Status Constants
# ------------------------------------------------------------

$script:EIDMStatus_InProgress  = 'InProgress'
$script:EIDMStatus_Completed   = 'Completed'
$script:EIDMStatus_Failed      = 'Failed'
$script:EIDMStatus_WaitingUser = 'WaitingUser'

function Get-EIDMStepLastStatus {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string]$StepId
    )

    $path = Join-Path $Ctx.RunRoot "run_state.csv"

    if (-not (Test-Path -LiteralPath $path)) {
        return $null
    }

    $rows = @(Import-Csv -LiteralPath $path | Where-Object { $_.Step -eq $StepId })

    if ($rows.Count -eq 0) {
        return $null
    }

    return $rows[-1].Status
}

function Ensure-EIDMDependencies {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string[]]$Requires
    )

    foreach ($dependency in $Requires) {

        switch ($dependency) {

            # -------------------------
            # Microsoft Graph
            # -------------------------
            'GraphSource' {
                Ensure-EIDMGraphSourceConnection -Ctx $Ctx
                continue
            }
            'GraphTarget' {
                Ensure-EIDMGraphTargetConnection -Ctx $Ctx
                continue
            }

            # -------------------------
            # Exchange Online
            # -------------------------
            'ExchangeSource' {
                Ensure-EIDMExchangeSourceConnection -Ctx $Ctx
                continue
            }
            'ExchangeTarget' {
                Ensure-EIDMExchangeTargetConnection -Ctx $Ctx
                continue
            }

            # -------------------------
            # SharePoint Online
            # -------------------------
            'SharePointSource' {
                Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
                continue
            }
            'SharePointTarget' {
                Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
                continue
            }

            # -------------------------
            # Unknown dependency
            # -------------------------
            default {
                throw "Unknown dependency: $dependency"
            }
        }
    }
}

function Invoke-EIDMStep {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][hashtable]$Step
    )

    $stepId   = $Step.Id
    $phase    = $Step.Phase
    $handler  = $Step.Handler
    $requires = $Step.Requires

    Write-EIDMTag -Tag 'STEP' -Text $stepId -Color Cyan

    $lastStatus = Get-EIDMStepLastStatus -Ctx $Ctx -StepId $stepId

    $allowRerun = $false
    if ($Step.ContainsKey('AllowRerun') -and $Step.AllowRerun -eq $true) {
        $allowRerun = $true
    }

    if ($lastStatus -eq $script:EIDMStatus_Completed -and -not $allowRerun) {
        Write-EIDMTag -Tag 'INFO' -Text 'Step already completed. Skipping.' -Color DarkGray
        return
    }

    try {

        Add-EIDMRunStateEntry -Ctx $Ctx `
            -Phase $phase `
            -Step $stepId `
            -Status $script:EIDMStatus_InProgress `
            -Message 'Step started'

        if ($requires -and $requires.Count -gt 0) {
            if ($null -ne $requires -and $requires.Count -gt 0) {
            Ensure-EIDMDependencies -Ctx $Ctx -Requires $requires
            }

        }

        if (-not (Get-Command $handler -ErrorAction SilentlyContinue)) {
            throw "Handler function '$handler' not found."
        }

        $result = & $handler -Ctx $Ctx

        if ($result -eq $script:EIDMStatus_WaitingUser) {

            Add-EIDMRunStateEntry -Ctx $Ctx `
                -Phase $phase `
                -Step $stepId `
                -Status $script:EIDMStatus_WaitingUser `
                -Message 'Operator validation required'

            Write-EIDMTag -Tag 'INFO' -Text 'Operator validation required.' -Color Yellow
            Read-Host 'Press Enter to return to menu'

            return $script:EIDMStatus_WaitingUser
        }

        Add-EIDMRunStateEntry -Ctx $Ctx `
            -Phase $phase `
            -Step $stepId `
            -Status $script:EIDMStatus_Completed `
            -Message 'Step completed successfully'

        Write-EIDMTag -Tag 'OK' -Text 'Step completed.' -Color Green
    }
    catch {

        $errorMessage = $_.Exception.Message

        Add-EIDMRunStateEntry -Ctx $Ctx `
            -Phase $phase `
            -Step $stepId `
            -Status $script:EIDMStatus_Failed `
            -Message $errorMessage

        Write-EIDMTag -Tag 'ERROR' -Text $errorMessage -Color Red
        Write-Host ""
        Write-Host "The phase has been stopped."
        Write-Host "You can resume this run later."
        Read-Host "Press Enter to return to menu"

        return $script:EIDMStatus_Failed
    }
}
function Invoke-EIDMPhase {
    param(
        [Parameter(Mandatory)]$Ctx,
        [Parameter(Mandatory)][string]$PhaseName,
        [Parameter(Mandatory)][hashtable[]]$Steps
    )

    Write-EIDMHeader ("Starting Phase: " + $PhaseName)

    foreach ($step in $Steps) {

        $result = Invoke-EIDMStep -Ctx $Ctx -Step $step

        if ($result -eq $script:EIDMStatus_Failed) {
            return
        }

        if ($result -eq $script:EIDMStatus_WaitingUser) {
            return
        }
    }

    Write-EIDMTag -Tag 'OK' -Text 'Phase completed successfully.' -Color Green
}
function Assert-EIDADPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Purpose = "IdentityPreparation"
    )

    # 1) RSAT / ActiveDirectory module available
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1
    if (-not $adModule) {
        throw "[AD PREREQ] ActiveDirectory PowerShell module not found. Install RSAT AD tools before running $Purpose."
    }

    # 2) Import module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        throw "[AD PREREQ] Failed to import ActiveDirectory module: $($_.Exception.Message)"
    }

    # 3) Forest connectivity / permissions
    $forest = $null
    try {
        $forest = Get-ADForest -ErrorAction Stop
    }
    catch {
        throw "[AD PREREQ] Cannot access Active Directory forest (Get-ADForest failed): $($_.Exception.Message)"
    }

    # 4) Optional: show some context that reassures the operator
    $suffixes = @()
    try {
        # Some environments have UPN suffix list in forest object; keep defensive
        $suffixes = @($forest.UPNSuffixes) | Where-Object { $_ -and $_.Trim() -ne "" }
    } catch { }

    [pscustomobject]@{
        ModulePath   = $adModule.Path
        ForestName   = $forest.Name
        RootDomain   = $forest.RootDomain
        Domains      = ($forest.Domains -join ";")
        UPNSuffixes  = ($suffixes -join ";")
    }
}

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
                                  Details  = @('Prepares and/or executes Exchange mailbox migration steps','May create batches or modify migration settings',"Output folder: output\runs\<RunId>\03-ExchangeMigration\") }
        OneDriveMigration   = @{ Question = 'Run OneDrive Migration [WRITE]?';      Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares and/or executes OneDrive migration steps','May create migration tasks/endpoints depending on implementation',"Output folder: output\runs\<RunId>\04-OneDriveMigration\") }
        SharePointMigration = @{ Question = 'Run SharePoint Migration [WRITE]?';    Tag = 'WRITE';     TagColor = 'Yellow'
                                  Details  = @('Prepares and/or executes SharePoint migration steps','May create migration tasks/endpoints depending on implementation',"Output folder: output\runs\<RunId>\05-SharePointMigration\") }
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
    @('01-Discovery','02-IdentityPreparation','03-ExchangeMigration','04-OneDriveMigration','05-SharePointMigration') | ForEach-Object {
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

    Write-EIDMSection "Configuration File Detected"
    Write-EIDMTag -Tag "CONFIG" -Text ("Existing config found: {0}" -f $ConfigPath) -Color Cyan
    Write-Host ""

    Write-Host "Choose an action:" -ForegroundColor White
    Write-Host "  1) Use existing config (continue)" -ForegroundColor Green
    Write-Host "  2) View config (read-only)" -ForegroundColor Cyan
    Write-Host "  3) Edit existing config (tenants + workloads)" -ForegroundColor Yellow
    Write-Host "  4) Re-run wizard and overwrite config" -ForegroundColor Red
    Write-Host "  5) Cancel and exit" -ForegroundColor DarkGray
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

    Write-EIDMSection "Select a Phase (Stub)"
    Write-Host "  1) 01-Discovery" -ForegroundColor Green
    Write-Host "  2) 02-IdentityPreparation" -ForegroundColor Yellow
    Write-Host "  3) 03-ExchangeMigration" -ForegroundColor Magenta
    Write-Host "  4) 04-OneDriveMigration" -ForegroundColor Cyan
    Write-Host "  5) 05-SharePointMigration" -ForegroundColor DarkCyan
    Write-Host "  X) Cancel" -ForegroundColor DarkGray
    Write-Host ""

    $ans = Read-Host "Select phase [1-5 or X]"
    if ($ans.Trim().ToUpper() -eq 'X') { return $null }

    switch ($ans) {
        '1' { return "01-Discovery" }
        '2' { return "02-IdentityPreparation" }
        '3' { return "03-ExchangeMigration" }
        '4' { return "04-OneDriveMigration" }
        '5' { return "05-SharePointMigration" }
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

    if ($lastStatus -eq $script:EIDMStatus_Completed) {
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

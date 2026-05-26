#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Clear-Host

$RepoRoot   = $PSScriptRoot
$ConfigPath = Join-Path $RepoRoot "config\config.psd1"

# Load libraries
. (Join-Path $RepoRoot "lib\00-Core.Functions.ps1")
. (Join-Path $RepoRoot "lib\00-Auth.Functions.ps1")
. (Join-Path $RepoRoot "lib\01-Discovery.Functions.ps1")
. (Join-Path $RepoRoot "lib\02-IdentityPreparation.Functions.ps1")
. (Join-Path $RepoRoot "lib\03-ExchangeMigrationPlan.Functions.ps1")
. (Join-Path $RepoRoot "lib\04-ExchangeMigrationExecution.Functions.ps1")
. (Join-Path $RepoRoot "lib\05-OneDriveMigrationPlan.Functions.ps1")
. (Join-Path $RepoRoot "lib\06-OneDriveMigrationExecution.Functions.ps1")
. (Join-Path $RepoRoot "lib\07-SharePointMigrationPlan.Functions.ps1")
. (Join-Path $RepoRoot "lib\08-SharePointMigrationExecution.Functions.ps1")

# Welcome banner
Write-Host ""
Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host "  |                                                            |" -ForegroundColor DarkCyan
Write-Host "  |" -NoNewline -ForegroundColor DarkCyan; Write-Host "    Entra ID Simple Tenant Migration Tool              " -NoNewline -ForegroundColor Cyan; Write-Host "|" -ForegroundColor DarkCyan
Write-Host "  |" -NoNewline -ForegroundColor DarkCyan; Write-Host "    Cross-Tenant Migration Orchestrator                " -NoNewline -ForegroundColor DarkGray; Write-Host "|" -ForegroundColor DarkCyan
Write-Host "  |                                                            |" -ForegroundColor DarkCyan
Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "  Supported workloads:" -ForegroundColor White
Write-Host "    [" -NoNewline -ForegroundColor DarkGray; Write-Host "*" -NoNewline -ForegroundColor Green; Write-Host "]" -NoNewline -ForegroundColor DarkGray; Write-Host " User identity provisioning (AD synced + cloud-only)" -ForegroundColor Gray
Write-Host "    [" -NoNewline -ForegroundColor DarkGray; Write-Host "*" -NoNewline -ForegroundColor Green; Write-Host "]" -NoNewline -ForegroundColor DarkGray; Write-Host " Exchange Online mailbox migration" -ForegroundColor Gray
Write-Host "    [" -NoNewline -ForegroundColor DarkGray; Write-Host "*" -NoNewline -ForegroundColor Green; Write-Host "]" -NoNewline -ForegroundColor DarkGray; Write-Host " OneDrive for Business content migration" -ForegroundColor Gray
Write-Host "    [" -NoNewline -ForegroundColor DarkGray; Write-Host "*" -NoNewline -ForegroundColor Green; Write-Host "]" -NoNewline -ForegroundColor DarkGray; Write-Host " SharePoint Online site migration" -ForegroundColor Gray
Write-Host ""
Write-Host "  NOTE: This tool must be run from a domain-joined machine" -ForegroundColor Yellow
Write-Host "        on the TARGET Active Directory (not the source)." -ForegroundColor Yellow
Write-Host "        The account running this tool needs AD permissions to:" -ForegroundColor Yellow
Write-Host "          - Create users and groups (New-ADUser, New-ADGroup)" -ForegroundColor Yellow
Write-Host "          - Edit user attributes (Set-ADUser, Set-ADForest)" -ForegroundColor Yellow
Write-Host "          - Manage group membership (Add-ADGroupMember)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Initializing..." -ForegroundColor Gray
Write-Host ""
$config = Import-PowerShellDataFile -Path $ConfigPath

# Check Graph/EXO/SPO modules (your existing function)
Ensure-EIDMPrerequisites

# If IdentityPreparation is enabled, AD (RSAT) must be available -> STOP if not
if ($config.Workloads.IdentityPreparation -eq $true) {

    # 1) RSAT AD module presence (cannot be installed from PSGallery)
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory | Select-Object -First 1)) {
        throw "ActiveDirectory module not found (RSAT). Install RSAT 'Active Directory Domain Services and LDAP Tools' and re-run the tool."
    }

    # 2) AD connectivity / permissions check (Get-ADForest, etc.)
    try {
        $adInfo = Assert-EIDADPrerequisites -Purpose "IdentityPreparation"

        Write-Host ""
        Write-Host "AD prerequisites: OK" -ForegroundColor Green
        Write-Host ("Forest      : {0}" -f $adInfo.ForestName)
        Write-Host ("RootDomain  : {0}" -f $adInfo.RootDomain)

        if ($adInfo.UPNSuffixes) {
            Write-Host ("UPN Suffixes: {0}" -f $adInfo.UPNSuffixes)
        }

        Write-Host ""
    }
    catch {
        Write-Host ""
        Write-Host "AD prerequisites: FAILED" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""
        throw  # hard stop
    }
}



# ------------------------------------------------------------
# CONFIGURATION LIFECYCLE
# ------------------------------------------------------------

$cfg = $null

if (-not (Test-Path -LiteralPath $ConfigPath)) {

    $cfg = New-EIDMConfigWizard -RepoRoot $RepoRoot
    Save-EIDMConfigPsd1 -Config $cfg -Path $ConfigPath

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Config created: {0}" -f $ConfigPath) -Color Green

} else {

    while ($true) {

        $action = Select-EIDMConfigAction -ConfigPath $ConfigPath

        if ($action -eq 'USE') {

            $cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath
            Write-EIDMTag -Tag "OK" -Text "Using existing config." -Color Green
            break

        }
        elseif ($action -eq 'VIEW') {

            $current = Import-PowerShellDataFile -LiteralPath $ConfigPath
            Show-EIDMCurrentConfig -Config $current
            Read-Host "Press Enter to return to menu" | Out-Null
            continue

        }
        elseif ($action -eq 'EDIT') {

            $current = Import-PowerShellDataFile -LiteralPath $ConfigPath
            Show-EIDMCurrentConfig -Config $current

            $cfg = Edit-EIDMConfigWizard -CurrentConfig $current
            Save-EIDMConfigPsd1 -Config $cfg -Path $ConfigPath

            Write-EIDMTag -Tag "OK" -Text "Config updated." -Color Green
            break

        }
        elseif ($action -eq 'RECREATE') {

            $cfg = New-EIDMConfigWizard -RepoRoot $RepoRoot
            Save-EIDMConfigPsd1 -Config $cfg -Path $ConfigPath

            Write-EIDMTag -Tag "OK" -Text "Config overwritten." -Color Green
            break

        }
        elseif ($action -eq 'CANCEL') {

            Write-EIDMTag -Tag "EXIT" -Text "Operation cancelled." -Color DarkGray
            return

        }
    }
}

# ------------------------------------------------------------
# INTERACTIVE RUN MENU
# ------------------------------------------------------------

$currentRun = $null

while ($true) {

    Clear-Host

    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "  |" -NoNewline -ForegroundColor DarkCyan; Write-Host "    Entra ID Simple Tenant Migration Tool              " -NoNewline -ForegroundColor Cyan; Write-Host "|" -ForegroundColor DarkCyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    if ($null -ne $currentRun) {
        Write-Host "  " -NoNewline; Write-Host " ACTIVE RUN " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host (" {0}" -f $currentRun.RunId) -ForegroundColor Green
        Write-Host ("               {0}" -f $currentRun.RunRoot) -ForegroundColor DarkGray
    }
    else {
        Write-Host "  " -NoNewline; Write-Host " NO ACTIVE RUN " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Start or resume a run first (option 1 or 2)" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |  Main Menu                                               |" -ForegroundColor White
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " Start a new run" -ForegroundColor Green
    Write-Host "      Create a fresh run folder with a unique timestamp." -ForegroundColor DarkGray
    Write-Host "      All phase outputs (CSVs, logs) will be stored there." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Resume an existing run" -ForegroundColor Yellow
    Write-Host "      Pick a previous run folder to continue where you left off." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " View run status" -ForegroundColor Cyan
    Write-Host "      Show which steps have been completed, failed, or are pending." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 4 " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta; Write-Host " Execute a phase" -ForegroundColor Magenta
    Write-Host "      Run a migration phase (Discovery, Identity, Exchange, OneDrive...)." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "  " -NoNewline; Write-Host " 5 " -NoNewline -ForegroundColor Gray -BackgroundColor DarkGray; Write-Host " Exit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "Enter choice [1-5]"

    switch ($choice) {

        # ---------------------------------------------
        # START NEW RUN
        # ---------------------------------------------
        '1' {

            $currentRun = Initialize-EIDMRun -RepoRoot $RepoRoot -Config $cfg
            Ensure-EIDMRunStateFile -Ctx $currentRun
            # Attach config to run context (required by Auth/Steps)
            $currentRun | Add-Member -NotePropertyName Config -NotePropertyValue $cfg -Force
            $currentRun | Add-Member -NotePropertyName ConfigPath -NotePropertyValue $ConfigPath -Force

            Write-EIDMSection "New Run Created"

            Write-EIDMTag -Tag "RUN ID" -Text $currentRun.RunId -Color Green
            Write-EIDMTag -Tag "FOLDER" -Text $currentRun.RunRoot -Color Cyan
            Write-EIDMTag -Tag "LOG" -Text $currentRun.LogPath -Color Cyan
            Write-EIDMTag -Tag "INFO" -Text "This run is now active in this session." -Color Yellow

            Read-Host "Press Enter to continue" | Out-Null
        }

        # ---------------------------------------------
        # RESUME RUN
        # ---------------------------------------------
        '2' {

            $selected = Select-EIDMExistingRun -RepoRoot $RepoRoot -Config $cfg

            if ($null -ne $selected) {

                Ensure-EIDMRunStateFile -Ctx $selected
                $currentRun = $selected
                # Attach config to run context (required by Auth/Steps)
                $currentRun | Add-Member -NotePropertyName Config -NotePropertyValue $cfg -Force
                $currentRun | Add-Member -NotePropertyName ConfigPath -NotePropertyValue $ConfigPath -Force

                Write-EIDMSection "Run Resumed"

                Write-EIDMTag -Tag "RUN ID" -Text $currentRun.RunId -Color Green
                Write-EIDMTag -Tag "FOLDER" -Text $currentRun.RunRoot -Color Cyan
                Write-EIDMTag -Tag "INFO" -Text "This run is now active." -Color Yellow

                Read-Host "Press Enter to continue" | Out-Null
            }
        }

        # ---------------------------------------------
        # VIEW RUN STATE
        # ---------------------------------------------
        '3' {

            if ($null -eq $currentRun) {
                Write-EIDMTag -Tag "WARN" -Text "No active run selected." -Color Yellow
                Read-Host "Press Enter to continue" | Out-Null
                continue
            }

            Show-EIDMRunState -Ctx $currentRun
            Read-Host "Press Enter to continue" | Out-Null
        }

        # ---------------------------------------------
        # EXECUTE PHASE (STUB)
        # ---------------------------------------------
        '4' {

            if ($null -eq $currentRun) {
                Write-EIDMTag -Tag "WARN" -Text "No active run selected." -Color Yellow
                Read-Host "Press Enter to continue" | Out-Null
                continue
            }

            Ensure-EIDMRunStateFile -Ctx $currentRun

            $phase = Select-EIDMPhaseFromUser
            if ([string]::IsNullOrWhiteSpace($phase)) { continue }

            switch ($phase) {

                '01-Discovery' {

                    # Safety check: Step engine must exist in Core
                    if (-not (Get-Command -Name Invoke-EIDMPhase -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMPhase not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $steps = Get-EIDMDiscoverySteps -Ctx $currentRun
                    Invoke-EIDMPhase -Ctx $currentRun -PhaseName '01-Discovery' -Steps $steps

                    Write-EIDMTag -Tag "OK" -Text "Phase completed: 01-Discovery" -Color Green
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                 '02-IdentityPreparation' {

                    if (-not (Get-Command -Name Invoke-EIDMPhase -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMPhase not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $steps = Get-EIDMIdentityPreparationSteps -Ctx $currentRun
                    Invoke-EIDMPhase -Ctx $currentRun -PhaseName '02-IdentityPreparation' -Steps $steps

                    Write-EIDMTag -Tag "OK" -Text "Phase completed: 02-IdentityPreparation" -Color Green
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                '03-ExchangeMigrationPlan' {

                    if (-not (Get-Command -Name Invoke-EIDMPhase -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMPhase not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $steps = Get-EIDMExchangeMigrationPlanSteps -Ctx $currentRun
                    Invoke-EIDMPhase -Ctx $currentRun -PhaseName '03-ExchangeMigrationPlan' -Steps $steps

                    Write-EIDMTag -Tag "OK" -Text "Phase completed: 03-ExchangeMigrationPlan" -Color Green
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                '04-ExchangeMigrationExecution' {

                    if (-not (Get-Command -Name Invoke-EIDMStep -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMStep not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $allSteps = Get-EIDMExchangeMigrationExecutionSteps -Ctx $currentRun

                    Write-Host ""
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host "  |  04 - Exchange Migration Execution                       |" -ForegroundColor Magenta
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "  Tip: Typical order: Start -> Check -> Complete -> Assign licenses" -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " Start Migration Batch" -ForegroundColor Green
                    Write-Host "      Adds source mailboxes to the scope security group (SOURCE EXO)," -ForegroundColor DarkGray
                    Write-Host "      then creates a New-MigrationBatch on the TARGET tenant." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " Check Migration Batches" -ForegroundColor Cyan
                    Write-Host "      Lists all migration batches on TARGET with per-user status." -ForegroundColor DarkGray
                    Write-Host "      Exports status CSVs. Run this repeatedly to track progress." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Stop / Remove Batches" -ForegroundColor Yellow
                    Write-Host "      Complete (finalize), Stop, or Remove migration batches." -ForegroundColor DarkGray
                    Write-Host "      Use 'Complete' once all users are synced and ready to cut over." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 4 " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta; Write-Host " Assign Licenses" -ForegroundColor Magenta
                    Write-Host "      Assign Exchange Online licenses to migrated users on TARGET." -ForegroundColor DarkGray
                    Write-Host "      Required after migration completes so users can access mail." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 5 " -NoNewline -ForegroundColor White -BackgroundColor DarkRed; Write-Host " Cleanup Migration Config" -ForegroundColor Red
                    Write-Host "      Remove migration endpoint, org relationships, scope group," -ForegroundColor DarkGray
                    Write-Host "      and app registration. Use to start fresh or after completion." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " X " -NoNewline -ForegroundColor Gray -BackgroundColor DarkGray; Write-Host " Cancel" -ForegroundColor DarkGray
                    Write-Host ""

                    $stepChoice = Read-Host "Select step [1-5 or X]"

                    if ($stepChoice.Trim().ToUpper() -eq 'X') {
                        break
                    }

                    $stepIndex = -1
                    switch ($stepChoice.Trim()) {
                        '1' { $stepIndex = 0 }
                        '2' { $stepIndex = 1 }
                        '3' { $stepIndex = 2 }
                        '4' { $stepIndex = 3 }
                        '5' { $stepIndex = 4 }
                        default {
                            Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
                        }
                    }

                    if ($stepIndex -ge 0 -and $stepIndex -lt $allSteps.Count) {
                        $selectedStep = $allSteps[$stepIndex]
                        Invoke-EIDMStep -Ctx $currentRun -Step $selectedStep
                    }

                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }


                '05-OneDriveMigrationPlan' {

                    if (-not (Get-Command -Name Invoke-EIDMPhase -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMPhase not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $steps = Get-EIDMOneDriveMigrationPlanSteps -Ctx $currentRun
                    Invoke-EIDMPhase -Ctx $currentRun -PhaseName '05-OneDriveMigrationPlan' -Steps $steps

                    Write-EIDMTag -Tag "OK" -Text "Phase completed: 05-OneDriveMigrationPlan" -Color Green
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                '06-OneDriveMigrationExecution' {

                    if (-not (Get-Command -Name Invoke-EIDMStep -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMStep not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $allSteps = Get-EIDMOneDriveMigrationExecutionSteps -Ctx $currentRun

                    Write-Host ""
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host "  |  06 - OneDrive Migration Execution                       |" -ForegroundColor Cyan
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "  Tip: Typical order: Start migrations -> Check status -> Reset trust" -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " Start OneDrive Migrations" -ForegroundColor Green
                    Write-Host "      Uploads the CTIM identity map to TARGET SPO, then starts" -ForegroundColor DarkGray
                    Write-Host "      cross-tenant user content moves on SOURCE for each user." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " Check Migration Status" -ForegroundColor Cyan
                    Write-Host "      Queries Get-SPOCrossTenantUserContentMoveState on both tenants." -ForegroundColor DarkGray
                    Write-Host "      Exports status CSVs. Run repeatedly until all moves complete." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Reset Cross-Tenant Trust" -ForegroundColor Yellow
                    Write-Host "      Removes the MnA cross-tenant relationship on both sides." -ForegroundColor DarkGray
                    Write-Host "      Only run this AFTER all OneDrive migrations are finished." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " X " -NoNewline -ForegroundColor Gray -BackgroundColor DarkGray; Write-Host " Cancel" -ForegroundColor DarkGray
                    Write-Host ""

                    $stepChoice = Read-Host "Select step [1-3 or X]"

                    if ($stepChoice.Trim().ToUpper() -eq 'X') {
                        break
                    }

                    $stepIndex = -1
                    switch ($stepChoice.Trim()) {
                        '1' { $stepIndex = 0 }
                        '2' { $stepIndex = 1 }
                        '3' { $stepIndex = 2 }
                        default {
                            Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
                        }
                    }

                    if ($stepIndex -ge 0 -and $stepIndex -lt $allSteps.Count) {
                        $selectedStep = $allSteps[$stepIndex]
                        Invoke-EIDMStep -Ctx $currentRun -Step $selectedStep
                    }

                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                '07-SharePointMigrationPlan' {

                    if (-not (Get-Command -Name Invoke-EIDMPhase -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMPhase not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $steps = Get-EIDMSharePointMigrationPlanSteps -Ctx $currentRun
                    Invoke-EIDMPhase -Ctx $currentRun -PhaseName '07-SharePointMigrationPlan' -Steps $steps

                    Write-EIDMTag -Tag "OK" -Text "Phase completed: 07-SharePointMigrationPlan" -Color Green
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                '08-SharePointMigrationExecution' {

                    if (-not (Get-Command -Name Invoke-EIDMStep -ErrorAction SilentlyContinue)) {
                        throw "Invoke-EIDMStep not found in 00-Core.Functions.ps1. Step engine is missing."
                    }

                    $allSteps = Get-EIDMSharePointMigrationExecutionSteps -Ctx $currentRun

                    Write-Host ""
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host "  |  08 - SharePoint Migration Execution                     |" -ForegroundColor Magenta
                    Write-Host "  +----------------------------------------------------------+" -ForegroundColor DarkGray
                    Write-Host ""
                    Write-Host "  Tip: Typical order: Start -> Check status -> Cleanup" -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 1 " -NoNewline -ForegroundColor White -BackgroundColor DarkGreen; Write-Host " Start SharePoint Site Migrations" -ForegroundColor Green
                    Write-Host "      Loads the sites mapping CSV and starts cross-tenant moves" -ForegroundColor DarkGray
                    Write-Host "      from SOURCE for each site marked Migrate=YES." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 2 " -NoNewline -ForegroundColor White -BackgroundColor DarkCyan; Write-Host " Check Migration Status" -ForegroundColor Cyan
                    Write-Host "      Queries move state on both tenants. Exports status CSVs." -ForegroundColor DarkGray
                    Write-Host "      Run repeatedly until all moves show Success." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 3 " -NoNewline -ForegroundColor Black -BackgroundColor DarkYellow; Write-Host " Stop/Cancel Migrations" -ForegroundColor Yellow
                    Write-Host "      Cancel pending or queued site migrations." -ForegroundColor DarkGray
                    Write-Host "      Migrations InProgress or Success cannot be cancelled." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 4 " -NoNewline -ForegroundColor White -BackgroundColor DarkRed; Write-Host " Cleanup (Remove trust + redirect sites)" -ForegroundColor Red
                    Write-Host "      Remove cross-tenant trust on both tenants and clean up" -ForegroundColor DarkGray
                    Write-Host "      redirect sites left on SOURCE. Run after ALL migrations." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " 5 " -NoNewline -ForegroundColor White -BackgroundColor DarkMagenta; Write-Host " Post-Migration: Fix Site Admins" -ForegroundColor Magenta
                    Write-Host "      Add a TARGET admin as Site Collection Admin on migrated" -ForegroundColor DarkGray
                    Write-Host "      sites. Run after migrations complete (Success state)." -ForegroundColor DarkGray
                    Write-Host ""

                    Write-Host "  " -NoNewline; Write-Host " X " -NoNewline -ForegroundColor Gray -BackgroundColor DarkGray; Write-Host " Cancel" -ForegroundColor DarkGray
                    Write-Host ""

                    $stepChoice = Read-Host "Select step [1-5 or X]"

                    if ($stepChoice.Trim().ToUpper() -eq 'X') {
                        break
                    }

                    $stepIndex = -1
                    switch ($stepChoice.Trim()) {
                        '1' { $stepIndex = 0 }
                        '2' { $stepIndex = 1 }
                        '3' { $stepIndex = 2 }
                        '4' { $stepIndex = 3 }
                        '5' { $stepIndex = 4 }
                        default {
                            Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
                        }
                    }

                    if ($stepIndex -ge 0 -and $stepIndex -lt $allSteps.Count) {
                        $selectedStep = $allSteps[$stepIndex]
                        Invoke-EIDMStep -Ctx $currentRun -Step $selectedStep
                    }

                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }

                default {
                    Write-EIDMTag -Tag "WARN" -Text ("Phase '{0}' not implemented yet." -f $phase) -Color Yellow
                    Read-Host "Press Enter to continue" | Out-Null
                    break
                }
            }
        }


        # ---------------------------------------------
        # EXIT
        # ---------------------------------------------
        '5' {
            Write-EIDMTag -Tag "EXIT" -Text "Goodbye." -Color DarkGray
            return
        }

        default {
            Write-EIDMTag -Tag "ERROR" -Text "Invalid choice." -Color Red
            Read-Host "Press Enter to continue" | Out-Null
        }
    }
}

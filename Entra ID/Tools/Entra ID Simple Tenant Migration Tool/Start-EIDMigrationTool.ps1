#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot   = $PSScriptRoot
$ConfigPath = Join-Path $RepoRoot "config\config.psd1"

# Load libraries
. (Join-Path $RepoRoot "lib\00-Core.Functions.ps1")
. (Join-Path $RepoRoot "lib\00-Auth.Functions.ps1")
. (Join-Path $RepoRoot "lib\01-Discovery.Functions.ps1")
. (Join-Path $RepoRoot "lib\02-IdentityPreparation.Functions.ps1")


# Load config FIRST (so we know which workloads are enabled)
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
    Write-EIDMHeader "Run Orchestrator"

    if ($null -ne $currentRun) {
        Write-EIDMTag -Tag "ACTIVE RUN" -Text $currentRun.RunId -Color Green
    }
    else {
        Write-EIDMTag -Tag "ACTIVE RUN" -Text "None selected" -Color Yellow
    }

    Write-Host ""
    Write-Host "Select an action:" -ForegroundColor White
    Write-Host "  1) Start a new run" -ForegroundColor Green
    Write-Host "  2) Resume an existing run" -ForegroundColor Yellow
    Write-Host "  3) View run status" -ForegroundColor Cyan
    Write-Host "  4) Execute a phase (stub)" -ForegroundColor Magenta
    Write-Host "  5) Exit" -ForegroundColor DarkGray
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

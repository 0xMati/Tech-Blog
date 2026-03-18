# Tiering\Invoke-MATITieringMenu.ps1
# Orchestrates the Tiering Model implementation phases.

function Invoke-MATITieringMenu {
    <#
    .SYNOPSIS
        Displays the Tiering Model implementation sub-menu and routes to the selected phase.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [hashtable]$Config
    )

    # Load tiering config
    $tieringConfigPath = Join-Path $RootPath 'Config\Tiering.config.psd1'
    if (-not (Test-Path $tieringConfigPath)) {
        Write-Host "  [ERROR] Tiering configuration not found: $tieringConfigPath" -ForegroundColor Red
        return
    }
    $tieringConfig = Import-PowerShellDataFile $tieringConfigPath

    # Load tiering modules
    $tieringModules = @(
        'Tiering\Invoke-MATITieringDiscovery.ps1'
        'Tiering\Export-TieringDiscoveryHtml.ps1'
        'Tiering\Invoke-MATITieringPhase1.ps1'
        'Tiering\Export-TieringPhase1Html.ps1'
        'Tiering\Invoke-MATITieringPhase2.ps1'
        'Tiering\Export-TieringPhase2Html.ps1'
        'Tiering\Invoke-MATITieringPhase3.ps1'
        'Tiering\Export-TieringPhase3Html.ps1'
        'Tiering\Invoke-MATITieringPhase4.ps1'
        'Tiering\Export-TieringPhase4Html.ps1'
        'Tiering\Invoke-MATITieringPhase5.ps1'
        'Tiering\Export-TieringPhase5Html.ps1'
        'Tiering\Invoke-MATITieringPhase6.ps1'
        'Tiering\Export-TieringPhase6Html.ps1'
        'Tiering\Invoke-MATITieringPhase7.ps1'
        'Tiering\Export-TieringPhase7Html.ps1'
        'Tiering\Invoke-MATITieringPhase8.ps1'
        'Tiering\Export-TieringPhase8Html.ps1'
        'Tiering\Invoke-MATITieringPhase9.ps1'
        'Tiering\Export-TieringPhase9Html.ps1'
    )
    foreach ($mod in $tieringModules) {
        $modPath = Join-Path $RootPath $mod
        if (Test-Path $modPath) {
            . $modPath
        } else {
            Write-Warning "Tiering module not found: $modPath"
        }
    }

    # Output directory
    $outputBase = Join-Path $RootPath 'Outputs\Tiering'
    $outputDir  = Join-Path $outputBase (Get-Date -Format 'yyyy-MM-dd_HHmmss')

    # Sub-menu loop
    $continue = $true
    while ($continue) {
        Write-Host ""
        Write-Host "    ┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "    │              IMPLEMENT TIERING MODEL                        │" -ForegroundColor Cyan
        Write-Host "    ├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
        Write-Host "    │  [0]  Phase 0 — Discovery & Tier Classification            │" -ForegroundColor Green
        Write-Host "    │  [1]  Phase 1 — OU Structure & Group Model                │" -ForegroundColor Green
        Write-Host "    │  [2]  Phase 2 — Tiered Admin Accounts                     │" -ForegroundColor Green
        Write-Host "    │  [3]  Phase 3 — Deny Logon GPOs                           │" -ForegroundColor Green
        Write-Host "    │  [4]  Phase 4 — Auth Policies & Silos                     │" -ForegroundColor Green
        Write-Host "    │  [5]  Phase 5 — PAW Hardening GPOs                        │" -ForegroundColor Green
        Write-Host "    │  [6]  Phase 6 — GPO Hardening Per Tier                    │" -ForegroundColor Green
        Write-Host "    │  [7]  Phase 7 — Tier 0 Object Protection                  │" -ForegroundColor Green
        Write-Host "    │  [8]  Phase 8 — Monitoring & Detection                    │" -ForegroundColor Green
        Write-Host "    │  [9]  Phase 9 — Health Check & Ongoing Ops                │" -ForegroundColor Green
        Write-Host "    │  [R]  Review current tiering deployment status              │" -ForegroundColor DarkGray
        Write-Host "    │  [B]  Back to main menu                                    │" -ForegroundColor Red
        Write-Host "    └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""

        $choice = Read-Host "    Select a phase [0-9/R/B]"

        switch ($choice.Trim().ToUpper()) {
            '0' {
                Invoke-MATITieringDiscovery -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '1' {
                Invoke-MATITieringPhase1 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '2' {
                Invoke-MATITieringPhase2 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '3' {
                Invoke-MATITieringPhase3 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '4' {
                Invoke-MATITieringPhase4 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '5' {
                Invoke-MATITieringPhase5 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '6' {
                Invoke-MATITieringPhase6 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '7' {
                Invoke-MATITieringPhase7 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '8' {
                Invoke-MATITieringPhase8 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '9' {
                Invoke-MATITieringPhase9 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            'R' {
                Write-Host ""
                Write-Host "    [!] Tiering status review is not yet available." -ForegroundColor Yellow
                Write-Host ""
            }
            'B' {
                $continue = $false
            }
            default {
                Write-Host "    [!] Invalid option." -ForegroundColor Yellow
            }
        }
    }
}

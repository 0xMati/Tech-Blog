# Tiering\Invoke-ADTTMenu.ps1
# Orchestrates the Tiering Model implementation phases.

function Invoke-ADTTMenu {
    <#
    .SYNOPSIS
        Displays the Tiering Model implementation sub-menu and routes to the selected phase.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [string]$ConfigPath
    )

    # Load tiering config
    $tieringConfigPath = if ($ConfigPath) { $ConfigPath } else { Join-Path $RootPath 'Config\Tiering.config.psd1' }
    if (-not (Test-Path $tieringConfigPath)) {
        throw "Tiering configuration not found: $tieringConfigPath"
    }
    $tieringConfig = Import-PowerShellDataFile $tieringConfigPath

    # Load tiering modules
    $tieringModules = @(
        'Engine\Get-ADTTSummarySnapshot.ps1'
        'Tiering\Invoke-ADTTDiscovery.ps1'
        'Tiering\Export-TieringDiscoveryHtml.ps1'
        'Tiering\Invoke-ADTTPhase1.ps1'
        'Tiering\Export-TieringPhase1Html.ps1'
        'Tiering\Invoke-ADTTPhase2.ps1'
        'Tiering\Export-TieringPhase2Html.ps1'
        'Tiering\Invoke-ADTTPhase3.ps1'
        'Tiering\Export-TieringPhase3Html.ps1'
        'Tiering\Invoke-ADTTPhase4.ps1'
        'Tiering\Export-TieringPhase4Html.ps1'
        'Tiering\Invoke-ADTTPhase5.ps1'
        'Tiering\Export-TieringPhase5Html.ps1'
        'Tiering\Invoke-ADTTPhase6.ps1'
        'Tiering\Export-TieringPhase6Html.ps1'
        'Tiering\Invoke-ADTTPhase7.ps1'
        'Tiering\Export-TieringPhase7Html.ps1'
        'Tiering\Invoke-ADTTPhase8.ps1'
        'Tiering\Export-TieringPhase8Html.ps1'
        'Tiering\Invoke-ADTTPhase9.ps1'
        'Tiering\Export-TieringPhase9Html.ps1'
    )
    foreach ($mod in $tieringModules) {
        $modPath = Join-Path $RootPath $mod
        if (Test-Path $modPath) {
            . $modPath
        } else {
            throw "Tiering module not found: $modPath"
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
        Write-Host "    │              AD TIERING TOOLKIT                             │" -ForegroundColor Cyan
        Write-Host "    ├─────────────────────────────────────────────────────────────┤" -ForegroundColor Cyan
        Write-Host "    │  [0]  Phase 0 — Discovery & Tier Classification            │" -ForegroundColor Green
        Write-Host "    │  [1]  Phase 1 — Create Recommended OU Structure & Group Model │" -ForegroundColor Green
        Write-Host "    │  [2]  Phase 2 — Create Recommended Tiered Admin Accounts │" -ForegroundColor Green
        Write-Host "    │  [3]  Phase 3 — Create Deny Logon GPOs for each Tiers    │" -ForegroundColor Green
        Write-Host "    │  [4]  Phase 4 — Create Auth Policies & Silos              │" -ForegroundColor Green
        Write-Host "    │  [5]  Phase 5 — Create PAW Hardening GPOs                 │" -ForegroundColor Green
        Write-Host "    │  [6]  Phase 6 — Create GPO Hardening Per Tier             │" -ForegroundColor Green
        Write-Host "    │  [7]  Phase 7 — Implement Tier 0 Object Protection        │" -ForegroundColor Green
        Write-Host "    │  [8]  Phase 8 — Monitoring & Detection                    │" -ForegroundColor Green
        Write-Host "    │  [9]  Phase 9 — Health Check & Ongoing Ops                │" -ForegroundColor Green
        Write-Host "    │  [R]  Review current tiering deployment status              │" -ForegroundColor DarkGray
        Write-Host "    │  [Q]  Quit                                                 │" -ForegroundColor Red
        Write-Host "    └─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host ""

        $choice = Read-Host "    Select a phase [0-9/R/Q]"

        switch ($choice.Trim().ToUpper()) {
            '0' {
                Invoke-ADTTDiscovery -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '1' {
                Invoke-ADTTPhase1 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '2' {
                Invoke-ADTTPhase2 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '3' {
                Invoke-ADTTPhase3 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '4' {
                Invoke-ADTTPhase4 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '5' {
                Invoke-ADTTPhase5 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '6' {
                Invoke-ADTTPhase6 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '7' {
                Invoke-ADTTPhase7 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '8' {
                Invoke-ADTTPhase8 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            '9' {
                Invoke-ADTTPhase9 -RootPath $RootPath -TieringConfig $tieringConfig -OutputDir $outputDir
            }
            'R' {
                Write-Host ""
                Write-Host "    [!] Tiering status review is not yet available." -ForegroundColor Yellow
                Write-Host ""
            }
            'Q' {
                $continue = $false
            }
            default {
                Write-Host "    [!] Invalid option." -ForegroundColor Yellow
            }
        }
    }
}

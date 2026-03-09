# Invoke-MATI.ps1
# MATIv2 - Microsoft Active Directory Threat Inspector v2
# Main entry point - orchestrates the full assessment pipeline.
#
# Usage:
#   .\Invoke-MATI.ps1
#   .\Invoke-MATI.ps1 -ConfigPath .\Config\custom.config.psd1
#   .\Invoke-MATI.ps1 -CategoriesOnly Config,Kerberos
#   .\Invoke-MATI.ps1 -RulesOnly MATI-CONFIG-001,MATI-KERB-005

#requires -Version 7.0

[CmdletBinding()]
param(
    # Path to an alternative configuration file
    [string]$ConfigPath,

    # Run only specific categories (comma-separated)
    [string[]]$CategoriesOnly,

    # Run only specific rule IDs (comma-separated)
    [string[]]$RulesOnly,

    # Skip report generation (useful for quick checks)
    [switch]$NoReport,

    # Skip score history save
    [switch]$NoHistory
)

$ErrorActionPreference = 'Stop'

# Resolve root path
$RootPath = $PSScriptRoot

# ==================================================================
# 0. Banner
# ==================================================================
Clear-Host
$banner = @"

    ███╗   ███╗ █████╗ ████████╗██╗
    ████╗ ████║██╔══██╗╚══██╔══╝██║
    ██╔████╔██║███████║   ██║   ██║
    ██║╚██╔╝██║██╔══██║   ██║   ██║
    ██║ ╚═╝ ██║██║  ██║   ██║   ██║
    ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝
    Microsoft Active Directory Threat Inspector

"@
# Read version from config
$configFile = if ($ConfigPath -and (Test-Path $ConfigPath)) { $ConfigPath } else { Join-Path $RootPath 'Config\MATI.config.psd1' }
$matiVersion = if (Test-Path $configFile) { (Import-PowerShellDataFile $configFile).Metadata.Version } else { '?.?.?' }

Write-Host $banner -ForegroundColor Cyan
Write-Host "    v$matiVersion | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "    $('-' * 50)" -ForegroundColor DarkGray

# ==================================================================
# 0.1 PowerShell version check
# ==================================================================
if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "    [OK] PowerShell $($PSVersionTable.PSVersion) detected" -ForegroundColor Green
} else {
    Write-Host "    [ERROR] PowerShell 7+ is required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    Write-Host "    Download PowerShell 7: https://aka.ms/powershell-release?tag=stable" -ForegroundColor Yellow
    Write-Host ""
    throw "MATI requires PowerShell 7 or later. Please re-run this script using pwsh.exe."
}
Write-Host ""

# ==================================================================
# 1. Load engine components
# ==================================================================
$engineFiles = @(
    'Models\Finding.ps1'
    'Engine\Initialize-MATIEngine.ps1'
    'Engine\Invoke-MATICollectors.ps1'
    'Engine\Invoke-MATIRules.ps1'
    'Engine\ConvertTo-MATIReport.ps1'
    'Scoring\Get-MATIScore.ps1'
)

foreach ($file in $engineFiles) {
    $filePath = Join-Path $RootPath $file
    if (Test-Path $filePath) {
        . $filePath
    } else {
        throw "Engine component not found: $filePath"
    }
}

# ==================================================================
# 2. Initialize engine (loads config, discovers rules/collectors)
# ==================================================================
$sw = [System.Diagnostics.Stopwatch]::StartNew()

$ctx = Initialize-MATIEngine -RootPath $RootPath -ConfigPath $ConfigPath

# Apply runtime filters if specified
if ($CategoriesOnly) {
    $ctx.Rules = [System.Collections.Generic.List[hashtable]]@(
        $ctx.Rules | Where-Object { $_['_Category'] -in $CategoriesOnly }
    )
    Write-Host "  [~] Filtered to categories: $($CategoriesOnly -join ', ')" -ForegroundColor Yellow
}

if ($RulesOnly) {
    $ctx.Rules = [System.Collections.Generic.List[hashtable]]@(
        $ctx.Rules | Where-Object { $_.Id -in $RulesOnly }
    )
    Write-Host "  [~] Filtered to rules: $($RulesOnly -join ', ')" -ForegroundColor Yellow
}

# ==================================================================
# 3. Run collectors (lazy, based on rule dependencies)
# ==================================================================
Invoke-MATICollectors -EngineContext $ctx

# ==================================================================
# 4. Execute rules
# ==================================================================
Invoke-MATIRules -EngineContext $ctx

# ==================================================================
# 5. Calculate score
# ==================================================================
$score = Get-MATIScore -EngineContext $ctx

# ==================================================================
# 6. Generate reports
# ==================================================================
if (-not $NoReport) {
    ConvertTo-MATIReport -EngineContext $ctx
}

# ==================================================================
# 7. Save score history
# ==================================================================
if (-not $NoHistory) {
    Save-MATIScoreHistory -EngineContext $ctx
    Write-Host "  [+] Score history updated.`n" -ForegroundColor Green
}

# ==================================================================
# 8. Final summary
# ==================================================================
$sw.Stop()

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  MATI Assessment Complete" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Score     : $($score.Score) / $($score.BaseScore)  (Grade: $($score.Grade))" -ForegroundColor White
Write-Host "  Findings  : $($score.TotalFindings)" -ForegroundColor White
Write-Host "  Duration  : $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor White
Write-Host "  Output    : $($ctx.OutputRoot)" -ForegroundColor White
Write-Host "================================================================`n" -ForegroundColor Cyan

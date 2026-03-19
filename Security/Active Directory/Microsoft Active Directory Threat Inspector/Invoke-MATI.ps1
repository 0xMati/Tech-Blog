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
$matiVersion = if (Test-Path $configFile) { (Import-PowerShellDataFile $configFile).General.Version } else { '?.?.?' }

Write-Host $banner -ForegroundColor Cyan
Write-Host "    v$matiVersion | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host "    $('-' * 50)" -ForegroundColor DarkGray

# ==================================================================
# 0.01 PowerShell version check
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
# 0.02 Permission prerequisite check
# ==================================================================
Write-Host "  [~] Checking permissions..." -ForegroundColor Yellow
try {
    $currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)
    $tokenGroupSids = $currentIdentity.Groups | ForEach-Object { $_.Value }
    $isLocalAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $isDomainAdmin     = $tokenGroupSids | Where-Object { $_ -match '-512$' }
    $isEnterpriseAdmin = $tokenGroupSids | Where-Object { $_ -match '-519$' }
    $forest        = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $isMultiDomain = $forest.Domains.Count -gt 1
    $permOk = $true

    if ($isMultiDomain) {
        if ($isEnterpriseAdmin) {
            Write-Host "    [OK] Enterprise Admins membership detected (multi-domain forest - $($forest.Domains.Count) domains)" -ForegroundColor Green
        } elseif ($isDomainAdmin) {
            Write-Host "    [!!] Domain Admins detected - but NOT Enterprise Admins" -ForegroundColor Yellow
            Write-Host "         Multi-domain forest with $($forest.Domains.Count) domains detected." -ForegroundColor Yellow
            Write-Host "         Cross-domain analysis may be incomplete. Enterprise Admins is recommended." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host "    Minimum required  : Domain Admins" -ForegroundColor Yellow
            Write-Host "    Recommended       : Enterprise Admins (multi-domain forest detected)" -ForegroundColor Yellow
            $permOk = $false
        }
    } else {
        if ($isDomainAdmin) {
            Write-Host "    [OK] Domain Admins membership detected" -ForegroundColor Green
        } elseif ($isLocalAdmin) {
            Write-Host "    [!!] Builtin\Administrators detected - but NOT Domain Admins" -ForegroundColor Yellow
            Write-Host "         Some AD collectors may return partial results." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host "    Minimum required : Domain Admins" -ForegroundColor Yellow
            $permOk = $false
        }
    }

    if (-not $permOk) {
        $continueChoice = Read-Host "    Continue anyway with potentially incomplete results? [Y/N]"
        if ($continueChoice.Trim().ToUpper() -ne 'Y') {
            Write-Host "    Exiting MATI. Please re-run with appropriate permissions." -ForegroundColor Cyan
            return
        }
        Write-Host "    [!] Continuing with current permissions - results may be incomplete." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not verify AD permissions: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    [!] Continuing - some collectors may fail if permissions are insufficient." -ForegroundColor Yellow
}
Write-Host ""

# ==================================================================
# 0.03 Define Threat Detection function
# ==================================================================
function Invoke-MATIThreatDetection {
    $global:MATIMode = 'ThreatDetection'
    Write-Host ""
    Write-Host "    [>] Launching Threat Detection & Security Analysis..." -ForegroundColor Green
    Write-Host ""

    # Load engine components
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

    # Initialize engine
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ctx = Initialize-MATIEngine -RootPath $RootPath -ConfigPath $ConfigPath

    # Apply runtime filters
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

    # Run collectors
    Invoke-MATICollectors -EngineContext $ctx

    # Execute rules
    Invoke-MATIRules -EngineContext $ctx

    # Calculate score
    $score = Get-MATIScore -EngineContext $ctx

    # Generate reports
    if (-not $NoReport) {
        ConvertTo-MATIReport -EngineContext $ctx
    }

    # Save score history
    if (-not $NoHistory) {
        Save-MATIScoreHistory -EngineContext $ctx
        Write-Host "  [+] Score history updated.`n" -ForegroundColor Green
    }

    # Final summary
    $sw.Stop()
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  MATI Assessment Complete" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "  Score     : $($score.Score) / $($score.BaseScore)  (Grade: $($score.Grade))" -ForegroundColor White
    Write-Host "  Findings  : $($score.TotalFindings)" -ForegroundColor White
    Write-Host "  Duration  : $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor White
    Write-Host "  Output    : $($ctx.OutputRoot)" -ForegroundColor White
    Write-Host "================================================================`n" -ForegroundColor Cyan
}

# ==================================================================
# 0.05 Main Menu
# ==================================================================
$mainLoop = $true
while ($mainLoop) {
Write-Host ""
Write-Host "    ┌─────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "    │                  MAIN MENU                      │" -ForegroundColor Cyan
Write-Host "    ├─────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "    │  [1]  Threat Detection & Security Analysis      │" -ForegroundColor Green
Write-Host "    │  [2]  Implement Tiering Model                    │" -ForegroundColor Green
Write-Host "    │  [Q]  Quit                                      │" -ForegroundColor Red
Write-Host "    └─────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$menuChoice = Read-Host "    Select an option [1/2/Q]"
switch ($menuChoice.Trim().ToUpper()) {
    '2' {
        # Load and launch Tiering Menu
        $tieringMenuPath = Join-Path $RootPath 'Tiering\Invoke-MATITieringMenu.ps1'
        if (Test-Path $tieringMenuPath) {
            . $tieringMenuPath
            Invoke-MATITieringMenu -RootPath $RootPath -Config @{ ConfigFile = $configFile }
        } else {
            Write-Host "    [ERROR] Tiering module not found: $tieringMenuPath" -ForegroundColor Red
        }
        # Loop back to main menu
    }
    'Q' {
        Write-Host "    Exiting MATI. Goodbye!" -ForegroundColor Cyan
        $mainLoop = $false
        return
    }
    '1' {
        Invoke-MATIThreatDetection
        # Loop back to main menu
    }
    default {
        Write-Host "    [!] Invalid option. Please select 1, 2, or Q." -ForegroundColor Yellow
    }
}
} # end main menu loop

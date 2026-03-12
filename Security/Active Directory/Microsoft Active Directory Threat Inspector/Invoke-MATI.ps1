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
# 0.05 Main Menu
# ==================================================================
Write-Host ""
Write-Host "    ┌─────────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "    │                  MAIN MENU                      │" -ForegroundColor Cyan
Write-Host "    ├─────────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "    │  [1]  Threat Detection & Security Analysis      │" -ForegroundColor Green
Write-Host "    │  [2]  Implement Tiering Model  (Coming Soon)    │" -ForegroundColor DarkGray
Write-Host "    │  [Q]  Quit                                      │" -ForegroundColor Red
Write-Host "    └─────────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""

$menuChoice = Read-Host "    Select an option [1/2/Q]"
switch ($menuChoice.Trim().ToUpper()) {
    '2' {
        Write-Host ""
        Write-Host "    [!] Tiering Model implementation is not yet available." -ForegroundColor Yellow
        Write-Host "    [!] This feature will allow you to automatically deploy an AD tiering model." -ForegroundColor Yellow
        Write-Host "    [!] Stay tuned for a future release!" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    'Q' {
        Write-Host "    Exiting MATI. Goodbye!" -ForegroundColor Cyan
        return
    }
    '1' {
        # Continue with Threat Detection
    }
    default {
        Write-Host "    [!] Invalid option. Defaulting to Threat Detection & Security Analysis." -ForegroundColor Yellow
    }
}
$global:MATIMode = 'ThreatDetection'
Write-Host ""
Write-Host "    [>] Launching Threat Detection & Security Analysis..." -ForegroundColor Green
Write-Host ""

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
# 0.2 Permission prerequisite check
# ==================================================================
Write-Host "  [~] Checking permissions..." -ForegroundColor Yellow
try {
    $currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = [System.Security.Principal.WindowsPrincipal]::new($currentIdentity)

    # Get group SIDs from the current user's token (includes nested membership)
    $tokenGroupSids = $currentIdentity.Groups | ForEach-Object { $_.Value }

    # Builtin\Administrators (S-1-5-32-544) — local admin on the machine
    $isLocalAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    # Domain Admins (RID -512) / Enterprise Admins (RID -519)
    $isDomainAdmin     = $tokenGroupSids | Where-Object { $_ -match '-512$' }
    $isEnterpriseAdmin = $tokenGroupSids | Where-Object { $_ -match '-519$' }

    # Detect forest topology
    $forest        = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $isMultiDomain = $forest.Domains.Count -gt 1

    $permOk = $true

    if ($isMultiDomain) {
        # ----- Multi-domain forest: Enterprise Admins recommended -----
        if ($isEnterpriseAdmin) {
            Write-Host "    [OK] Enterprise Admins membership detected (multi-domain forest — $($forest.Domains.Count) domains)" -ForegroundColor Green
        } elseif ($isDomainAdmin) {
            Write-Host "    [!!] Domain Admins detected — but NOT Enterprise Admins" -ForegroundColor Yellow
            Write-Host "         Multi-domain forest with $($forest.Domains.Count) domains detected." -ForegroundColor Yellow
            Write-Host "         Cross-domain analysis may be incomplete. Enterprise Admins is recommended." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host ""
            Write-Host "    MATI requires elevated Active Directory permissions to perform" -ForegroundColor Red
            Write-Host "    a comprehensive security assessment." -ForegroundColor Red
            Write-Host ""
            Write-Host "    Minimum required  : Domain Admins" -ForegroundColor Yellow
            Write-Host "    Recommended       : Enterprise Admins (multi-domain forest detected)" -ForegroundColor Yellow
            Write-Host "    Domains in forest : $($forest.Domains.Count)" -ForegroundColor Yellow
            Write-Host ""
            $permOk = $false
        }
    } else {
        # ----- Single-domain forest: Domain Admins is sufficient -----
        if ($isDomainAdmin) {
            Write-Host "    [OK] Domain Admins membership detected" -ForegroundColor Green
        } elseif ($isLocalAdmin) {
            Write-Host "    [!!] Builtin\Administrators detected — but NOT Domain Admins" -ForegroundColor Yellow
            Write-Host "         Some AD collectors may return partial results." -ForegroundColor Yellow
            Write-Host "         Domain Admins membership is recommended for full coverage." -ForegroundColor Yellow
        } else {
            Write-Host "    [ERROR] Insufficient permissions detected!" -ForegroundColor Red
            Write-Host ""
            Write-Host "    MATI requires elevated Active Directory permissions to perform" -ForegroundColor Red
            Write-Host "    a comprehensive security assessment." -ForegroundColor Red
            Write-Host ""
            Write-Host "    Minimum required : Domain Admins" -ForegroundColor Yellow
            Write-Host ""
            $permOk = $false
        }
    }

    if (-not $permOk) {
        Write-Host "    Prerequisites:" -ForegroundColor Cyan
        Write-Host "    ┌────────────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
        Write-Host "    │  Scenario                │  Required Group                     │" -ForegroundColor DarkGray
        Write-Host "    ├────────────────────────────────────────────────────────────────┤" -ForegroundColor DarkGray
        Write-Host "    │  Single-domain forest     │  Domain Admins                     │" -ForegroundColor DarkGray
        Write-Host "    │  Multi-domain forest      │  Enterprise Admins (recommended)   │" -ForegroundColor DarkGray
        Write-Host "    └────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "    Why these permissions?" -ForegroundColor Cyan
        Write-Host "    - WinRM / Invoke-Command on all Domain Controllers (registry, audit policy)" -ForegroundColor DarkGray
        Write-Host "    - Read Security event logs on DCs (NTLM/Kerberos legacy protocol audit)" -ForegroundColor DarkGray
        Write-Host "    - Read ACLs on protected AD objects (AdminSDHolder, Schema, DPAPI keys)" -ForegroundColor DarkGray
        Write-Host "    - Read sensitive attributes (LAPS passwords, dSHeuristics, msDS-RevealedUsers)" -ForegroundColor DarkGray
        Write-Host "    - Query AD across all domains in the forest" -ForegroundColor DarkGray
        Write-Host ""

        $continueChoice = Read-Host "    Continue anyway with potentially incomplete results? [Y/N]"
        if ($continueChoice.Trim().ToUpper() -ne 'Y') {
            Write-Host "    Exiting MATI. Please re-run with appropriate permissions." -ForegroundColor Cyan
            return
        }
        Write-Host ""
        Write-Host "    [!] Continuing with current permissions — results may be incomplete." -ForegroundColor Yellow
    }
} catch {
    Write-Host "    [!] Could not verify AD permissions: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "    [!] Continuing — some collectors may fail if permissions are insufficient." -ForegroundColor Yellow
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

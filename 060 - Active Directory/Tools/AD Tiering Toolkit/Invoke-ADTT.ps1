#requires -Version 7.0

[CmdletBinding()]
param(
    [string]$ConfigPath
)

$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'AD Tiering Toolkit requires Windows with the ActiveDirectory RSAT module.'
}

$configFile = if ($ConfigPath) {
    (Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop).ProviderPath
} else {
    Join-Path $PSScriptRoot 'Config\Tiering.config.psd1'
}
if (-not (Test-Path -LiteralPath $configFile -PathType Leaf)) {
    throw "Tiering configuration not found: $configFile"
}

$menuPath = Join-Path $PSScriptRoot 'Tiering\Invoke-ADTTMenu.ps1'
if (-not (Test-Path -LiteralPath $menuPath -PathType Leaf)) {
    throw "Tiering menu not found: $menuPath"
}

try {
    Import-Module ActiveDirectory -SkipEditionCheck -ErrorAction Stop
} catch {
    throw "Cannot load the ActiveDirectory module. Install the AD DS and LDS RSAT tools. Error: $($_.Exception.Message)"
}

$domain = Get-ADDomain -ErrorAction Stop
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$outputRoot = Join-Path $PSScriptRoot 'Outputs\Tiering'
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
$transcriptPath = Join-Path $outputRoot ("ADTT.transcript.{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$transcriptStarted = $false

try {
    try {
        Start-Transcript -Path $transcriptPath -Force -IncludeInvocationHeader -ErrorAction Stop | Out-Null
        $transcriptStarted = $true
    } catch {
        Write-Warning "Could not start ADTT transcript: $($_.Exception.Message)"
    }

    Write-Host "`n  ADTT - AD Tiering Toolkit" -ForegroundColor Cyan
    Write-Host "  Operator : $($identity.Name)" -ForegroundColor White
    Write-Host "  Host     : $env:COMPUTERNAME" -ForegroundColor White
    Write-Host "  Domain   : $($domain.DNSRoot)" -ForegroundColor White
    Write-Host "  Config   : $configFile" -ForegroundColor DarkGray
    Write-Warning 'Deployment phases can modify Active Directory, GPOs and administrative access. Validate backups and test in a lab first.'
    Write-Host '  Start with discovery and review the configuration before deployment.' -ForegroundColor Yellow

    . $menuPath
    Invoke-ADTTMenu -RootPath $PSScriptRoot -ConfigPath $configFile
}
finally {
    if ($transcriptStarted) {
        try {
            Stop-Transcript -ErrorAction Stop | Out-Null
        } catch {
            Write-Warning "Could not stop ADTT transcript cleanly: $($_.Exception.Message)"
        }
    }
}

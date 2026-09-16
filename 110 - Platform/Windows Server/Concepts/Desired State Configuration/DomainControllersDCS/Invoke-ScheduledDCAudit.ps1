#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainName,
    [string]$InventoryPath = (Join-Path $PSScriptRoot 'inventory.json'),
    [string]$SettingsPath = (Join-Path $PSScriptRoot 'compliance.settings.json'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'Reports')
)

$ErrorActionPreference = 'Stop'
$exitCode = 2
$transcriptStarted = $false
try {
    $logDirectory = Join-Path $OutputDirectory 'Runs'
    $null = New-Item -Path $logDirectory -ItemType Directory -Force
    $logName = '{0}-{1}.log' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), [guid]::NewGuid().ToString('N').Substring(0, 8)
    $null = Start-Transcript -Path (Join-Path $logDirectory $logName) -ErrorAction Stop
    $transcriptStarted = $true
    & (Join-Path $PSScriptRoot 'Get-DCInventory.ps1') -DomainName $DomainName -OutputPath $InventoryPath | Out-Null
    & (Join-Path $PSScriptRoot 'Invoke-DCCompliance.ps1') -InventoryPath $InventoryPath -SettingsPath $SettingsPath -OutputDirectory $OutputDirectory -Operation Audit
    $exitCode = $LASTEXITCODE
}
catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    $exitCode = 2
}
finally {
    if ($transcriptStarted) { $null = Stop-Transcript -ErrorAction Continue }
}
exit $exitCode
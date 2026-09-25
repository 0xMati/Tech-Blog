#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Resource,
    [Parameter(Mandatory)][ValidateSet('Get', 'Set')][string]$Operation
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    Import-Module (Join-Path $PSScriptRoot 'NativeResources.psm1') -Force -ErrorAction Stop
    $properties = [Console]::In.ReadToEnd() | ConvertFrom-Json -ErrorAction Stop
    if ($properties -isnot [pscustomobject]) { throw 'Resource input must be a JSON object.' }
    $state = Invoke-DCNativeResource -Resource $Resource -Operation $Operation -Properties $properties
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $state -Depth 8 -Compress))
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
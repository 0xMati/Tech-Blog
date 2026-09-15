#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainName,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Join-Path -Path $PSScriptRoot -ChildPath 'inventory.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($DomainName -ne $DomainName.Trim() -or $DomainName.EndsWith('.') -or
    -not $DomainName.Contains('.') -or
    [Uri]::CheckHostName($DomainName) -ne [UriHostNameType]::Dns) {
    throw 'DomainName must be an AD DNS domain name without whitespace, wildcards, or a trailing dot.'
}

$resolvedOutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
if ([System.IO.Path]::GetExtension($resolvedOutputPath) -ine '.json') {
    throw 'OutputPath must name a JSON file.'
}

Import-Module ActiveDirectory -ErrorAction Stop

$domainControllers = @(Get-ADDomainController -Filter * -Server $DomainName -ErrorAction Stop)
if ($domainControllers.Count -eq 0) {
    throw "No domain controllers were returned for '$DomainName'. The inventory file was not updated."
}

$inventory = @(
    foreach ($domainController in $domainControllers) {
        if ([string]::IsNullOrWhiteSpace($domainController.HostName)) {
            throw "A domain controller in '$DomainName' has no DNS host name. The inventory file was not updated."
        }

        if ($domainController.Domain -ine $DomainName) {
            throw "Domain mismatch for '$($domainController.HostName)': expected '$DomainName', received '$($domainController.Domain)'."
        }

        if ($domainController.IsReadOnly -isnot [bool]) {
            throw "Cannot determine whether '$($domainController.HostName)' is read-only. The inventory file was not updated."
        }

        [pscustomobject][ordered]@{
            HostName = $domainController.HostName
            Domain = $domainController.Domain
            Site = $domainController.Site
            OperatingSystem = $domainController.OperatingSystem
            IsReadOnly = $domainController.IsReadOnly
        }
    }
)

$duplicateHosts = @($inventory | Group-Object -Property HostName | Where-Object Count -gt 1)
if ($duplicateHosts.Count -gt 0) {
    throw 'Duplicate DC host names were returned. The inventory file was not updated.'
}

$inventory = @($inventory | Sort-Object -Property HostName)
$inventoryDocument = [pscustomobject][ordered]@{
    Domain = $DomainName
    DiscoveredAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    SourceComputer = $env:COMPUTERNAME
    DomainControllers = $inventory
}

$json = ConvertTo-Json -InputObject $inventoryDocument -Depth 5
$outputDirectory = Split-Path -Path $resolvedOutputPath -Parent
$null = New-Item -Path $outputDirectory -ItemType Directory -Force -ErrorAction Stop
$temporaryPath = Join-Path -Path $outputDirectory -ChildPath ([System.IO.Path]::GetRandomFileName())

try {
    [System.IO.File]::WriteAllText($temporaryPath, $json, [System.Text.UTF8Encoding]::new($false))

    if ([System.IO.File]::Exists($resolvedOutputPath)) {
        [System.IO.File]::Replace($temporaryPath, $resolvedOutputPath, [NullString]::Value)
    }
    else {
        [System.IO.File]::Move($temporaryPath, $resolvedOutputPath)
    }
}
finally {
    if ([System.IO.File]::Exists($temporaryPath)) {
        [System.IO.File]::Delete($temporaryPath)
    }
}

Write-Information -MessageData "Inventory saved to: $resolvedOutputPath" -InformationAction Continue
$inventory
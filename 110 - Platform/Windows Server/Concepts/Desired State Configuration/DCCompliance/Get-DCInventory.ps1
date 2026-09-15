#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SettingsPath = (Join-Path -Path $PSScriptRoot -ChildPath 'inventory.settings.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$settings = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 -ErrorAction Stop |
    ConvertFrom-Json -ErrorAction Stop

if ($null -eq $settings -or $settings -isnot [pscustomobject]) {
    throw 'The settings document must be a JSON object.'
}

$propertyNames = @($settings.PSObject.Properties.Name)
$expectedProperties = @('Domains', 'IncludeReadOnlyDCs', 'ExcludedDCs', 'RemediationAllowedDCs')

foreach ($propertyName in $propertyNames) {
    if ($expectedProperties -notcontains $propertyName) {
        throw "Unknown settings property: $propertyName."
    }
}

foreach ($propertyName in $expectedProperties) {
    if ($propertyNames -notcontains $propertyName) {
        throw "Missing settings property: $propertyName."
    }
}

foreach ($propertyName in @('Domains', 'ExcludedDCs', 'RemediationAllowedDCs')) {
    if ($settings.$propertyName -isnot [array]) {
        throw "$propertyName must be a JSON array."
    }

    foreach ($entry in $settings.$propertyName) {
        if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace($entry)) {
            throw "$propertyName must contain non-empty DNS names."
        }

        if ($entry -ne $entry.Trim() -or $entry.EndsWith('.') -or
            -not $entry.Contains('.') -or
            [Uri]::CheckHostName($entry) -ne [UriHostNameType]::Dns) {
            throw "Invalid DNS name in ${propertyName}: '$entry'. Use an exact FQDN without whitespace, wildcards, or a trailing dot."
        }
    }
}

if ($settings.Domains.Count -eq 0) {
    throw 'Domains must contain at least one approved domain.'
}

if ($settings.IncludeReadOnlyDCs -isnot [bool]) {
    throw 'IncludeReadOnlyDCs must be a JSON Boolean, not a string.'
}

Import-Module ActiveDirectory -ErrorAction Stop

$inventory = @(
    foreach ($domainName in ($settings.Domains | Sort-Object -Unique)) {
        $domainControllers = @(Get-ADDomainController -Filter * -Server $domainName -ErrorAction Stop)

        if ($domainControllers.Count -eq 0) {
            throw "No domain controllers were returned for '$domainName'. Inventory is incomplete."
        }

        foreach ($domainController in $domainControllers) {
            if ([string]::IsNullOrWhiteSpace($domainController.HostName)) {
                throw "A domain controller in '$domainName' has no DNS host name. Inventory is incomplete."
            }

            if ($domainController.Domain -ine $domainName) {
                throw "Domain mismatch for '$($domainController.HostName)': expected '$domainName', received '$($domainController.Domain)'."
            }

            if ($domainController.IsReadOnly -isnot [bool]) {
                throw "Cannot determine whether '$($domainController.HostName)' is read-only. Inventory is incomplete."
            }

            $auditScope = 'Included'
            $scopeReason = 'Discovered in an approved domain'

            if ($settings.ExcludedDCs -contains $domainController.HostName) {
                $auditScope = 'Excluded'
                $scopeReason = 'Explicitly excluded by inventory settings'
            }
            elseif ($domainController.IsReadOnly -and -not $settings.IncludeReadOnlyDCs) {
                $auditScope = 'Excluded'
                $scopeReason = 'Read-only domain controllers are outside this audit scope'
            }

            [pscustomobject][ordered]@{
                HostName = $domainController.HostName
                Domain = $domainController.Domain
                Forest = $domainController.Forest
                Site = $domainController.Site
                OperatingSystem = $domainController.OperatingSystem
                IsReadOnly = $domainController.IsReadOnly
                OperationMasterRoles = @($domainController.OperationMasterRoles | ForEach-Object { [string]$_ })
                AuditScope = $auditScope
                ScopeReason = $scopeReason
                RemediationAllowlisted = (
                    $auditScope -eq 'Included' -and
                    $settings.RemediationAllowedDCs -contains $domainController.HostName
                )
                ComplianceStatus = 'NotEvaluated'
            }
        }
    }
)

$duplicateHosts = @($inventory | Group-Object -Property HostName | Where-Object Count -gt 1)
if ($duplicateHosts.Count -gt 0) {
    throw 'Duplicate DC host names were returned. Review the domain scope and directory metadata.'
}

foreach ($propertyName in @('ExcludedDCs', 'RemediationAllowedDCs')) {
    foreach ($configuredHost in $settings.$propertyName) {
        if ($inventory.HostName -notcontains $configuredHost) {
            Write-Warning "'$configuredHost' in $propertyName was not discovered. Check for a typo, a retired DC, or an incorrect domain scope."
        }
    }
}

if (@($inventory | Where-Object AuditScope -eq 'Included').Count -eq 0) {
    Write-Warning 'No DCs are included in the audit scope. This inventory is not evidence of compliance.'
}

$inventory | Sort-Object -Property Domain, HostName
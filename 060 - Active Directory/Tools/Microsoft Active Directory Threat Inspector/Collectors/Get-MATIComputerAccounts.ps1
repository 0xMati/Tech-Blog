# Collectors\Get-MATIComputerAccounts.ps1
# MATIv2 - Collects all computer accounts.

function Get-MATIComputerAccounts {
    <#
    .SYNOPSIS
        Collects all computer accounts across the forest.
    .OUTPUTS
        [array] of computer objects.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest    = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $compProps = $Config.Collectors.ComputerProperties

    $computers = foreach ($domainDns in $forest.Domains) {
        try {
            $domainControllerDNs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            try {
                $domainDCs = @(Get-ADDomainController -Filter * -Server $domainDns -ErrorAction Stop)
                foreach ($dc in $domainDCs) {
                    if ($dc.ComputerObjectDN) {
                        $null = $domainControllerDNs.Add($dc.ComputerObjectDN)
                    }
                }
            } catch {
                Write-Verbose "    Could not pre-load Domain Controller DNs for ${domainDns}: $($_.Exception.Message)"
            }

            $domainComputers = Get-ADComputer -Filter * -Server $domainDns -Properties $compProps -ErrorAction Stop
            foreach ($comp in $domainComputers) {
                [PSCustomObject]@{
                    SamAccountName        = $comp.SamAccountName
                    DistinguishedName     = $comp.DistinguishedName
                    Domain                = $domainDns
                    Enabled               = $comp.Enabled
                    OperatingSystem       = $comp.OperatingSystem
                    OperatingSystemVersion = $comp.OperatingSystemVersion
                    DNSHostName           = $comp.DNSHostName
                    IPv4Address           = $comp.IPv4Address
                    LastLogonTimestamp     = if ($comp.LastLogonTimestamp) {
                        [DateTime]::FromFileTime($comp.LastLogonTimestamp)
                    } else { $null }
                    PasswordLastSet       = $comp.PasswordLastSet
                    WhenCreated           = $comp.WhenCreated
                    Description           = $comp.Description
                    SID                   = [string]$comp.SID
                    PrimaryGroupID        = $comp.PrimaryGroupID
                    UserAccountControl    = $comp.UserAccountControl
                    IsDomainController    = $domainControllerDNs.Contains($comp.DistinguishedName)
                    # RBCD: Resource-Based Constrained Delegation
                    AllowedToActOnBehalf  = $comp.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                    # Shadow Credentials
                    KeyCredentialLink     = $comp.'msDS-KeyCredentialLink'
                }
            }
        }
        catch {
            Write-Warning "    Cannot query computers for ${domainDns} : $($_.Exception.Message)"
        }
    }

    return @($computers)
}

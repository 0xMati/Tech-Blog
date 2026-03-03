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

    $forest    = Get-ADForest -ErrorAction Stop
    $compProps = $Config.Collectors.ComputerProperties

    $computers = foreach ($domainDns in $forest.Domains) {
        try {
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
                    SID                   = $comp.SID.Value
                    IsDomainController    = $comp.DistinguishedName -match 'OU=Domain Controllers'
                }
            }
        }
        catch {
            Write-Warning "    Cannot query computers for $domainDns : $($_.Exception.Message)"
        }
    }

    return @($computers)
}

# Collectors\Get-MATIDNSConfig.ps1
# MATIv2 - Collects DNS zone configuration from Active Directory.

function Get-MATIDNSConfig {
    <#
    .SYNOPSIS
        Reads DNS zone properties from AD-integrated zones: secure/insecure updates,
        zone transfer settings, and DnsAdmins group membership.
    .OUTPUTS
        [hashtable] with keys: Zones, DnsAdmins
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest  = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $zoneList   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $dnsAdmins  = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($domainDns in $forest.Domains) {
        try {
            $domainDN = ($Config['_DomainCache'][$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DistinguishedName

            # --- DnsAdmins group members ---
            try {
                $members = @(Get-ADGroupMember -Identity 'DnsAdmins' -Server $domainDns -ErrorAction Stop)
                foreach ($m in $members) {
                    $dnsAdmins.Add([PSCustomObject]@{
                        Domain     = $domainDns
                        MemberName = $m.Name
                        MemberSAM  = $m.SamAccountName
                        MemberDN   = $m.DistinguishedName
                        ObjectClass = $m.objectClass
                    })
                }
            } catch { }

            # --- AD-integrated DNS zones ---
            # Read zones from CN=MicrosoftDNS,DC=DomainDnsZones,<DomainDN>
            # and CN=MicrosoftDNS,DC=ForestDnsZones,<ForestDN>
            $partitions = @(
                "DC=DomainDnsZones,$domainDN"
            )
            if ($domainDns -eq $forest.RootDomain) {
                $forestDN = ($Config['_DomainCache'][$forest.RootDomain] ?? (Get-ADDomain -Server $forest.RootDomain -ErrorAction Stop)).DistinguishedName
                $partitions += "DC=ForestDnsZones,$forestDN"
            }

            foreach ($partition in $partitions) {
                $dnsContainer = "CN=MicrosoftDNS,$partition"
                try {
                    $zones = Get-ADObject -SearchBase $dnsContainer -Filter { objectClass -eq 'dnsZone' } `
                        -Server $domainDns -Properties dnsProperty, name -ErrorAction Stop
                    foreach ($zone in $zones) {
                        # Skip metadata zones
                        if ($zone.Name -in @('RootDNSServers', 'Cache', '..TrustAnchors')) { continue }

                        # Read zone properties for secure dynamic update setting
                        $zoneList.Add([PSCustomObject]@{
                            Name       = $zone.Name
                            DN         = $zone.DistinguishedName
                            Partition  = $partition
                            Domain     = $domainDns
                        })
                    }
                } catch { }
            }

            # If DnsServer module is available, read zone properties directly
            if (Get-Module -ListAvailable -Name DnsServer -ErrorAction SilentlyContinue) {
                try {
                    $dc = (Get-ADDomainController -DomainName $domainDns -Discover -ErrorAction Stop).HostName[0]
                    $serverZones = Get-DnsServerZone -ComputerName $dc -ErrorAction Stop |
                        Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneType -in @('Primary','Stub') }

                    foreach ($sz in $serverZones) {
                        # Update or add zone info with dynamic update and zone transfer settings
                        $existing = $zoneList | Where-Object { $_.Name -eq $sz.ZoneName -and $_.Domain -eq $domainDns }

                        # Read aging properties
                        $agingEnabled      = $null
                        $noRefreshInterval = $null
                        $refreshInterval   = $null
                        $scavengingServers = @()
                        try {
                            $agingInfo = Get-DnsServerZoneAging -Name $sz.ZoneName -ComputerName $dc -ErrorAction Stop
                            $agingEnabled      = $agingInfo.AgingEnabled
                            $noRefreshInterval = $agingInfo.NoRefreshInterval.TotalHours
                            $refreshInterval   = $agingInfo.RefreshInterval.TotalHours
                            $scavengingServers = @($agingInfo.ScavengingServers)
                        } catch { }

                        $info = [PSCustomObject]@{
                            Name            = $sz.ZoneName
                            Domain          = $domainDns
                            DynamicUpdate   = [string]$sz.DynamicUpdate      # None, Secure, NonsecureAndSecure
                            SecureOnly      = ($sz.DynamicUpdate -eq 'Secure')
                            IsReverseLookup = $sz.IsReverseLookupZone
                            ZoneType        = [string]$sz.ZoneType
                            IsADIntegrated  = $sz.IsAutoCreated -eq $false
                            SecondaryServers = @($sz.SecondaryServers)
                            ZoneTransferPolicy = if ($sz.SecondaryServers.Count -eq 0 -and
                                $sz.ZoneName -notlike '_msdcs*') { 'NoTransfer' }
                                elseif ($sz.SecondaryServers.Count -gt 0) { 'SpecificServers' }
                                else { 'Unknown' }
                            AgingEnabled       = $agingEnabled
                            NoRefreshInterval  = $noRefreshInterval
                            RefreshInterval    = $refreshInterval
                            ScavengingServers  = $scavengingServers
                        }
                        if ($existing) {
                            $idx = $zoneList.IndexOf($existing)
                            if ($idx -ge 0) { $zoneList[$idx] = $info }
                        } else {
                            $zoneList.Add($info)
                        }
                    }
                } catch { }
            }

        } catch {
            Write-Warning "    Cannot query DNS config for $domainDns : $($_.Exception.Message)"
        }
    }

    return @{
        Zones      = @($zoneList)
        DnsAdmins  = @($dnsAdmins)
    }
}

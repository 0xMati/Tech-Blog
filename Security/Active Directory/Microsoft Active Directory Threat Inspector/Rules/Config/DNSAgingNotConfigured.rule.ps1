# Rules\Config\DNSAgingNotConfigured.rule.ps1
# Flags DNS zones where aging/scavenging is not enabled.

@{
    Id          = 'MATI-CONFIG-019'
    Title       = 'DNS zone aging/scavenging not enabled'
    Severity    = 'Medium'
    Description = "This AD-integrated DNS zone does not have aging and scavenging enabled. Without aging, stale DNS records accumulate, potentially pointing to decommissioned hosts. Attackers can re-register stale names to intercept traffic."
    Remediation = "Enable aging on the zone (Set-DnsServerZoneAging -Name <Zone> -Aging $true -ScavengingServer <DC>) and configure appropriate NoRefreshInterval and RefreshInterval (default 7 days each). Enable scavenging on at least one DC."
    Collectors  = @('DNSConfig')
    References  = @('Blog: DNS Aging and Scavenging Configuration', 'PingCastle: S-DNSZoneAging')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($zone in @($Data.DNSConfig.Zones)) {
            # Only check zones that have aging info (DnsServer module was available)
            if ($null -eq $zone.AgingEnabled) { continue }
            if ($zone.AgingEnabled -ne $true) {
                $findings += @{
                    ObjectDN = $zone.Name
                    Domain   = $zone.Domain
                    Details  = @{
                        ZoneName       = $zone.Name
                        AgingEnabled   = [string]$zone.AgingEnabled
                        ScavengingServer = if ($zone.ScavengingServers) { ($zone.ScavengingServers -join ', ') } else { 'None' }
                    }
                }
            }
        }
        return $findings
    }
}

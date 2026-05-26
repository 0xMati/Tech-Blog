# Rules\Config\InsufficientDCs.rule.ps1
# Flags domains with fewer than 2 Domain Controllers. [PingCastle: A-NotEnoughDC]

@{
    Id          = 'MATI-CONFIG-028'
    Title       = 'Insufficient Domain Controllers for redundancy'
    Severity    = 'High'
    Description = "A domain has fewer than two Domain Controllers. Without redundancy, a single DC failure means complete loss of authentication services and directory access for the domain."
    Remediation = "Deploy at least two Domain Controllers per domain in separate physical or logical locations to ensure high availability and disaster recovery."
    Collectors  = @('DCInfo', 'DomainInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/determining-the-number-of-domains-required')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $dcsByDomain = @{}
        foreach ($dc in $Data.DCInfo) {
            if (-not $dcsByDomain.ContainsKey($dc.Domain)) { $dcsByDomain[$dc.Domain] = 0 }
            $dcsByDomain[$dc.Domain]++
        }
        foreach ($domain in $dcsByDomain.Keys) {
            if ($dcsByDomain[$domain] -lt 2) {
                $findings += @{
                    ObjectDN = $domain
                    Domain   = $domain
                    Details  = @{
                        DCCount = $dcsByDomain[$domain]
                        Issue   = "Only $($dcsByDomain[$domain]) DC(s) — minimum 2 recommended"
                    }
                }
            }
        }
        return $findings
    }
}

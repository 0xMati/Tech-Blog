# Rules\Config\DomainFunctionalLevel.rule.ps1
# Checks if any domain has a functional level below the configured minimum.

@{
    Id          = 'MATI-CONFIG-001'
    Title       = 'Outdated domain functional level'
    Severity    = 'Medium'
    Description = "One or more domains have a functional level below the recommended minimum. A low functional level prevents the use of modern security features (Protected Users, Authentication Policies, etc.)."
    Remediation = "Raise each domain functional level to at least Windows Server 2016 after verifying domain controller compatibility."
    Collectors  = @('DomainInfo')
    Condition   = {
        param($Data, $Config)
        $minLevel = $Config.Thresholds.MinDomainFunctionalLevel
        $findings = @()
        foreach ($domain in $Data.DomainInfo.Domains) {
            if ([int]$domain.DomainModeNumeric -lt $minLevel) {
                $findings += @{
                    ObjectDN = $domain.DistinguishedName
                    Domain   = $domain.DNSRoot
                    Details  = @{
                        CurrentLevel = "$($domain.DomainMode)"
                        MinRequired  = "$minLevel"
                    }
                }
            }
        }
        return $findings
    }
}

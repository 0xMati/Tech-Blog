# Rules\Config\DCSubnetMissing.rule.ps1
# Flags DCs in AD sites without any subnet defined.

@{
    Id          = 'MATI-CONFIG-016'
    Title       = 'Domain Controller in site without AD subnet'
    Severity    = 'Medium'
    Description = "A Domain Controller is located in an AD site that has no subnet defined. This causes incorrect site-aware KDC and DC locator behavior, potentially routing authentication to wrong DCs or causing slow logons."
    Remediation = "Create appropriate AD subnets in Active Directory Sites and Services and link them to the correct site for each DC."
    Collectors  = @('DCInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/networking/core-network-guide/cncg/server-certs/configure-the-server-certificate-template')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.DCInfo) {
            if (-not $dc.SiteHasSubnets) {
                $findings += @{
                    ObjectDN = $dc.DistinguishedName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName       = $dc.Name
                        Site         = $dc.Site
                        SubnetCount  = 0
                    }
                }
            }
        }
        return $findings
    }
}

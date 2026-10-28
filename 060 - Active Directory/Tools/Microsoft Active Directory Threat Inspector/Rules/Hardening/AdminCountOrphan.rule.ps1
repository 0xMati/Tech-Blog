# Rules\Hardening\AdminCountOrphan.rule.ps1
# Flags enabled accounts with AdminCount=1 that are no longer in any privileged group.

@{
    Id          = 'MATI-HARD-024'
    Title       = 'AdminCount=1 without an in-forest privileged membership'
    Severity    = 'Medium'
    Description = "An enabled account has AdminCount=1 but no privileged membership path was found inside the assessed forest. Review whether its protected status is still needed. Membership paths through external forests are outside this assessment."
    Remediation = "Verify all intended privileged memberships, including any external paths, before clearing AdminCount or restoring ACL inheritance. Do not remove protection solely on the basis of this finding."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($acct in $Data.SecurityConfig.AdminCountOrphans) {
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    AccountName = $acct.SamAccountName
                    AdminCount  = 1
                    InPrivGroup = 'No in-forest path found'
                    MembershipScope = 'TargetForest'
                }
            }
        }
        return $findings
    }
}

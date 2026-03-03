# Rules\Hardening\AdminCountOrphan.rule.ps1
# Flags enabled accounts with AdminCount=1 that are no longer in any privileged group.

@{
    Id          = 'MATI-HARD-024'
    Title       = 'AdminCount orphan — account with stale elevated flag'
    Severity    = 'Medium'
    Description = "An enabled account has AdminCount=1 set but is no longer a member of any privileged group. This means the account still has SDProp-hardened ACLs (preventing inheritance) but no longer needs them, creating a security blind spot."
    Remediation = "For each orphan: clear the AdminCount attribute (set to 0 or null), then re-enable ACL inheritance on the account. Investigate why the account was previously privileged."
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
                    InPrivGroup = 'No'
                }
            }
        }
        return $findings
    }
}

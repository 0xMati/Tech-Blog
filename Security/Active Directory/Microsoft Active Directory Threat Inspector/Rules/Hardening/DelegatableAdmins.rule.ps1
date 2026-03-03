# Rules\Hardening\DelegatableAdmins.rule.ps1
# Flags privileged accounts without the 'Account is sensitive and cannot be delegated' flag.

@{
    Id          = 'MATI-HARD-009'
    Title       = 'Privileged account can be delegated'
    Severity    = 'Medium'
    Description = "A privileged account (Domain Admins or Enterprise Admins member) does not have the 'Account is sensitive and cannot be delegated' flag set. Without this flag, attackers who compromise a server with delegation can impersonate the admin. Note: accounts in the Protected Users group are already protected."
    Remediation = "Set the AccountNotDelegated flag: Set-ADUser <user> -AccountNotDelegated `$true. Alternatively, add the account to the Protected Users group."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.DelegatableAdmins) {
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    SamAccountName      = $acct.SamAccountName
                    AccountNotDelegated = 'False'
                    Recommendation      = "Set 'Account is sensitive and cannot be delegated'"
                }
            }
        }
        return $findings
    }
}

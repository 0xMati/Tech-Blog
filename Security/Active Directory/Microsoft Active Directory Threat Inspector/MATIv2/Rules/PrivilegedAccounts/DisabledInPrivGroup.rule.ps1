# Rules\PrivilegedAccounts\DisabledInPrivGroup.rule.ps1
# Flags disabled accounts still members of privileged groups.

@{
    Id          = 'MATI-ADMIN-003'
    Title       = 'Disabled account still in a privileged group'
    Severity    = 'Low'
    Description = "A disabled account is still a member of a privileged group. Although disabled, the account could be re-enabled by an attacker with modify permissions on the object."
    Remediation = "Remove the disabled account from privileged groups. If the account is no longer needed, move it to a dedicated OU for disabled accounts."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName = $account.SamAccountName
                        Enabled        = 'False'
                    }
                }
            }
        }
        return $findings
    }
}

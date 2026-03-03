# Rules\PrivilegedAccounts\PasswordNeverExpires.rule.ps1
# Flags privileged accounts with non-expiring passwords.

@{
    Id          = 'MATI-ADMIN-001'
    Title       = 'Privileged account with non-expiring password'
    Severity    = 'High'
    Description = "An account that is a member of a privileged group has the 'PasswordNeverExpires' flag set. This means the password will never be forced to change, increasing the long-term risk of compromise."
    Remediation = "Disable the 'Password never expires' option and implement regular password rotation for privileged accounts."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if ($account.Enabled -and $account.PasswordNeverExpires) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName       = $account.SamAccountName
                        PasswordNeverExpires = 'True'
                        PasswordLastSet      = "$($account.PasswordLastSet)"
                    }
                }
            }
        }
        return $findings
    }
}

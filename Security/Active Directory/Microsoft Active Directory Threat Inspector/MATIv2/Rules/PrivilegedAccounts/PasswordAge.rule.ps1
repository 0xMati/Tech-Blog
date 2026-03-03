# Rules\PrivilegedAccounts\PasswordAge.rule.ps1
# Flags privileged accounts with old passwords.

@{
    Id          = 'MATI-ADMIN-007'
    Title       = 'Privileged account with old password'
    Severity    = 'Medium'
    Description = "A privileged account has not changed its password for longer than the configured threshold. Old passwords are more likely to have been compromised through leaks, brute-force, or offline attacks."
    Remediation = "Force a password change for privileged accounts according to the defined rotation policy."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $maxAge = $Config.Thresholds.PrivilegedPasswordMaxAge
        $now = Get-Date
        $findings = @()

        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }

            $pwdAge = if ($account.PasswordLastSet) {
                ($now - $account.PasswordLastSet).Days
            } else { 9999 }

            if ($pwdAge -gt $maxAge) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName  = $account.SamAccountName
                        PasswordAgeDays = "$pwdAge"
                        PasswordLastSet = "$($account.PasswordLastSet)"
                        MaxAge          = "$maxAge days"
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\PrivilegedAccounts\BuiltinAdminEnabled.rule.ps1
# Flags the built-in Administrator (RID-500) account if enabled.

@{
    Id          = 'MATI-ADMIN-009'
    Title       = 'Built-in Administrator account (RID-500) enabled'
    Severity    = 'High'
    Description = "The built-in Administrator account (RID-500) is enabled. This account is a primary target because its SID is predictable and it cannot be locked out by default in many environments. Password spraying attacks specifically target this account. It should not be used for routine administration. If it is intentionally retained as a break-glass account, it should be treated as a tightly controlled exception with strong compensating controls."
    Remediation = "Prefer disabling the built-in Administrator account (RID-500) and using dedicated named administrative or emergency accounts instead. If the RID-500 account is intentionally retained for break-glass use, ensure it is renamed, protected by a very strong password, excluded from daily administration, tightly monitored, and reserved for emergency access only."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            # RID-500 detection
            if ($account.SID -and $account.SID -match '-500$' -and $account.Enabled) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName = $account.SamAccountName
                        SID            = $account.SID
                        Enabled        = 'True'
                    }
                }
            }
        }
        return $findings
    }
}

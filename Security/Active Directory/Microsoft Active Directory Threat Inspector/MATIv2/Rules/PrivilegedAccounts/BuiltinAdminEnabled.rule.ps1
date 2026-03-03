# Rules\PrivilegedAccounts\BuiltinAdminEnabled.rule.ps1
# Flags the built-in Administrator (RID-500) account if enabled.

@{
    Id          = 'MATI-ADMIN-009'
    Title       = 'Built-in Administrator account (RID-500) enabled'
    Severity    = 'High'
    Description = "The built-in Administrator account (RID-500) is enabled. This account is a primary target because its SID is predictable and it cannot be locked out by default. Password spraying attacks specifically target this account."
    Remediation = "Disable the built-in Administrator account (RID-500) and use named accounts for administration. Rename the account and set a highly complex password as an additional safeguard."
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

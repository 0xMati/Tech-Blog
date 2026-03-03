# Rules\PrivilegedAccounts\InactivePrivileged.rule.ps1
# Flags privileged accounts that are inactive (no logon for X days).

@{
    Id          = 'MATI-ADMIN-002'
    Title       = 'Inactive privileged account'
    Severity    = 'Medium'
    Description = "A privileged account has had no recent logon activity. Inactive accounts in high-privilege groups represent an attack vector as they are often forgotten and can be reused by an attacker."
    Remediation = "Disable or remove inactive accounts from privileged groups after validation with business teams."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $inactiveDays = $Config.Thresholds.PrivilegedInactiveDays
        $now = Get-Date
        $findings = @()

        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }

            $lastLogon = $account.LastLogonTimestamp
            if (-not $lastLogon) {
                $daysSinceLogon = 9999
            } else {
                $daysSinceLogon = ($now - $lastLogon).Days
            }

            if ($daysSinceLogon -ge $inactiveDays) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName   = $account.SamAccountName
                        DaysSinceLogon   = "$daysSinceLogon"
                        LastLogon        = "$lastLogon"
                        Threshold        = "$inactiveDays days"
                    }
                }
            }
        }
        return $findings
    }
}

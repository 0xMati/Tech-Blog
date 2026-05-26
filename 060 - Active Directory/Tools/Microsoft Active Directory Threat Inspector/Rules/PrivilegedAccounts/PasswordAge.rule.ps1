# Rules\PrivilegedAccounts\PasswordAge.rule.ps1
# Flags privileged accounts with old passwords.

@{
    Id          = 'MATI-ADMIN-007'
    Title       = 'Privileged account with old password'
    Severity    = 'Medium'
    Description = "A privileged account has not changed its password for longer than the configured threshold. Accounts whose password age cannot be determined are reported separately as verification items instead of being treated as confirmed overdue passwords."
    Remediation = "Force a password change for privileged accounts according to the defined rotation policy."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $maxAge = $Config.Thresholds.PrivilegedPasswordMaxAge
        $now = Get-Date
        $findings = @()
        $unknownBuckets = @{}

        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }

            if (-not $account.PasswordLastSet) {
                $key = $account.Domain
                if (-not $unknownBuckets.ContainsKey($key)) {
                    $unknownBuckets[$key] = @{
                        Domain   = $account.Domain
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $unknownBuckets[$key].Count++
                if ($unknownBuckets[$key].Examples.Count -lt 5) {
                    $unknownBuckets[$key].Examples.Add($account.SamAccountName)
                }
                continue
            }

            $pwdAge = ($now - $account.PasswordLastSet).Days

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

        foreach ($bucket in $unknownBuckets.Values) {
            $findings += @{
                Severity = 'Informational'
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    EvaluationStatus      = 'Could not determine privileged password age'
                    UnknownPasswordAgeCount = "$($bucket.Count)"
                    ExampleAccounts       = ($bucket.Examples -join '; ')
                    Reason                = 'PasswordLastSet is empty or unavailable'
                }
            }
        }

        return $findings
    }
}

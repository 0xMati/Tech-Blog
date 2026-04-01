# Rules\PrivilegedAccounts\InactivePrivileged.rule.ps1
# Flags privileged accounts that are inactive (no logon for X days).

@{
    Id          = 'MATI-ADMIN-002'
    Title       = 'Inactive privileged account'
    Severity    = 'Medium'
    Description = "A privileged account has had no recent logon activity based on available logon metadata. Accounts with no usable logon timestamp are reported separately as verification items instead of being treated as confirmed inactive accounts."
    Remediation = "Disable or remove inactive accounts from privileged groups after validation with business teams."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $inactiveDays = $Config.Thresholds.PrivilegedInactiveDays
        $now = Get-Date
        $findings = @()
        $unknownBuckets = @{}

        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }

            $lastLogon = $account.LastLogonTimestamp
            if (-not $lastLogon) {
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

            $daysSinceLogon = ($now - $lastLogon).Days

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

        foreach ($bucket in $unknownBuckets.Values) {
            $findings += @{
                Severity = 'Informational'
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    EvaluationStatus           = 'Could not determine privileged account inactivity'
                    UnknownLastLogonCount      = "$($bucket.Count)"
                    ExampleAccounts            = ($bucket.Examples -join '; ')
                    Reason                     = 'LastLogonTimestamp is empty or unavailable'
                }
            }
        }

        return $findings
    }
}

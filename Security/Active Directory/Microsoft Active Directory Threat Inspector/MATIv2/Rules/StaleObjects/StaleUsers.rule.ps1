# Rules\StaleObjects\StaleUsers.rule.ps1
# Flags stale (inactive) user accounts with severity based on inactivity duration.

@{
    Id          = 'MATI-STALE-001'
    Title       = 'Stale (inactive) user accounts'
    Severity    = 'Medium'
    Description = "User accounts have not been used for an extended period. Stale accounts increase the attack surface as they can be compromised without being detected. Severity increases with inactivity duration."
    Remediation = "Disable accounts inactive for more than 90 days. Delete accounts inactive for more than 365 days after validation. Implement an automated account lifecycle management process."
    Collectors  = @('UserAccounts')
    Condition   = {
        param($Data, $Config)
        $thresholds = $Config.Thresholds.StaleAccountDays
        $now = Get-Date
        $findings = @()

        # Group by domain and severity for aggregated findings
        $domainBuckets = @{}

        foreach ($user in $Data.UserAccounts) {
            if (-not $user.Enabled) { continue }

            $lastLogon = $user.LastLogonTimestamp
            if (-not $lastLogon) {
                $daysSinceLogon = 9999
            } else {
                $daysSinceLogon = ($now - $lastLogon).Days
            }

            $severity = $null
            if ($daysSinceLogon -ge $thresholds.Critical) {
                $severity = 'Critical'
            } elseif ($daysSinceLogon -ge $thresholds.High) {
                $severity = 'High'
            } elseif ($daysSinceLogon -ge $thresholds.Medium) {
                $severity = 'Medium'
            }

            if ($severity) {
                $key = "$($user.Domain)|$severity"
                if (-not $domainBuckets.ContainsKey($key)) {
                    $domainBuckets[$key] = @{
                        Domain   = $user.Domain
                        Severity = $severity
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $domainBuckets[$key].Count++
                if ($domainBuckets[$key].Examples.Count -lt 5) {
                    $domainBuckets[$key].Examples.Add("$($user.SamAccountName) ($daysSinceLogon days)")
                }
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $findings += @{
                Severity = $bucket.Severity
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    StaleUserCount = "$($bucket.Count)"
                    Severity       = $bucket.Severity
                    Examples       = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}

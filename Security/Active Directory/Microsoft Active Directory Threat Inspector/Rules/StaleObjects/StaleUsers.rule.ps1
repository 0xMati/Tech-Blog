# Rules\StaleObjects\StaleUsers.rule.ps1
# Flags stale (inactive) user accounts with severity based on inactivity duration.

@{
    Id          = 'MATI-STALE-001'
    Title       = 'Stale (inactive) user accounts'
    Severity    = 'Medium'
    Description = "User accounts appear inactive based on the latest available account activity evidence. The rule uses the most recent known date among logon timestamp, password set, and object creation to avoid treating missing logon metadata as a confirmed stale account."
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

            $activityCandidates = @($user.LastLogonTimestamp, $user.PasswordLastSet, $user.WhenCreated) | Where-Object { $_ }
            if (@($activityCandidates).Count -eq 0) { continue }

            $lastActivity = @($activityCandidates | Sort-Object -Descending)[0]
            $daysSinceActivity = ($now - $lastActivity).Days

            $activitySource = if ($user.LastLogonTimestamp -and $lastActivity -eq $user.LastLogonTimestamp) {
                'LastLogonTimestamp'
            } elseif ($user.PasswordLastSet -and $lastActivity -eq $user.PasswordLastSet) {
                'PasswordLastSet'
            } else {
                'WhenCreated'
            }

            $severity = $null
            if ($daysSinceActivity -ge $thresholds.Critical) {
                $severity = 'Critical'
            } elseif ($daysSinceActivity -ge $thresholds.High) {
                $severity = 'High'
            } elseif ($daysSinceActivity -ge $thresholds.Medium) {
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
                    $domainBuckets[$key].Examples.Add("$($user.SamAccountName) ($daysSinceActivity days via $activitySource)")
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

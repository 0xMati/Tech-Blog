# Rules\StaleObjects\StaleComputers.rule.ps1
# Flags stale (inactive) computer accounts.

@{
    Id          = 'MATI-STALE-002'
    Title       = 'Stale (inactive) computer accounts'
    Severity    = 'Medium'
    Description = "Computer accounts appear inactive based on the latest available account activity evidence. The rule uses the most recent known date among logon timestamp, password set, and object creation to avoid treating missing logon metadata as a confirmed stale computer."
    Remediation = "Disable computer accounts inactive for more than 90 days. Delete accounts inactive for more than 365 days. Implement an automated cleanup process."
    Collectors  = @('ComputerAccounts')
    Condition   = {
        param($Data, $Config)
        $thresholds = $Config.Thresholds.StaleAccountDays
        $now = Get-Date
        $findings = @()

        $domainBuckets = @{}

        foreach ($comp in $Data.ComputerAccounts) {
            if (-not $comp.Enabled) { continue }
            if ($comp.IsDomainController) { continue }  # Skip DCs

            $activityCandidates = @($comp.LastLogonTimestamp, $comp.PasswordLastSet, $comp.WhenCreated) | Where-Object { $_ }
            if (@($activityCandidates).Count -eq 0) { continue }

            $lastActivity = @($activityCandidates | Sort-Object -Descending)[0]
            $daysSinceActivity = ($now - $lastActivity).Days

            $activitySource = if ($comp.LastLogonTimestamp -and $lastActivity -eq $comp.LastLogonTimestamp) {
                'LastLogonTimestamp'
            } elseif ($comp.PasswordLastSet -and $lastActivity -eq $comp.PasswordLastSet) {
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
                $key = "$($comp.Domain)|$severity"
                if (-not $domainBuckets.ContainsKey($key)) {
                    $domainBuckets[$key] = @{
                        Domain   = $comp.Domain
                        Severity = $severity
                        Count    = 0
                        Examples = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $domainBuckets[$key].Count++
                if ($domainBuckets[$key].Examples.Count -lt 5) {
                    $domainBuckets[$key].Examples.Add("$($comp.SamAccountName) ($daysSinceActivity days via $activitySource)")
                }
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $findings += @{
                Severity = $bucket.Severity
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    StaleComputerCount = "$($bucket.Count)"
                    Severity           = $bucket.Severity
                    Examples           = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}

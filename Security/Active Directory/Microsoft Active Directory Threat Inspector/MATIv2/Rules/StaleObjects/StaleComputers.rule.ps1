# Rules\StaleObjects\StaleComputers.rule.ps1
# Flags stale (inactive) computer accounts.

@{
    Id          = 'MATI-STALE-002'
    Title       = 'Stale (inactive) computer accounts'
    Severity    = 'Medium'
    Description = "Computer accounts have not been used for an extended period. Stale machine accounts can be reused by an attacker to join the domain with a rogue computer and gain legitimate network access."
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

            $lastLogon = $comp.LastLogonTimestamp
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
                    $domainBuckets[$key].Examples.Add("$($comp.SamAccountName) ($daysSinceLogon days)")
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

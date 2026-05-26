# Rules\Hardening\SIDHistoryAnyAccount.rule.ps1
# ORADAD: vuln_sidhistory_present
# Flags any account (not just privileged) with SIDHistory populated.

@{
    Id          = 'MATI-HARD-038'
    Title       = 'Account with SIDHistory attribute populated'
    Severity    = 'Medium'
    Description = "One or more accounts still have values in the SIDHistory attribute. SIDHistory is used during domain migrations to preserve access to resources in the source domain. After migration is complete, SIDHistory should be removed because it can be exploited for privilege escalation (SIDHistory injection) — an attacker who controls an account with SIDHistory containing a privileged SID from another domain gains those privileges."
    Remediation = "Remove SIDHistory from all accounts where the migration is complete. Use: Set-ADUser -Identity <user> -Remove @{SIDHistory=<SID>}. If migrations are ongoing, document which accounts legitimately need SIDHistory and review regularly. Enable SID Filtering on trusts to block SIDHistory from being used across trust boundaries."
    Collectors  = @('UserAccounts', 'ComputerAccounts')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $domainBuckets = @{}

        foreach ($user in $Data.UserAccounts) {
            if (-not $user.SIDHistory -or $user.SIDHistory.Count -eq 0) { continue }
            $key = $user.Domain
            if (-not $domainBuckets.ContainsKey($key)) {
                $domainBuckets[$key] = @{
                    Domain   = $user.Domain
                    Count    = 0
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }
            $domainBuckets[$key].Count++
            if ($domainBuckets[$key].Examples.Count -lt 10) {
                $domainBuckets[$key].Examples.Add("$($user.SamAccountName) ($($user.SIDHistory.Count) SIDs)")
            }
        }
        foreach ($comp in $Data.ComputerAccounts) {
            # ComputerAccounts don't have SIDHistory in current collector (only users do)
            # But if present, check it
            if (-not $comp.PSObject.Properties['SIDHistory']) { continue }
            if (-not $comp.SIDHistory -or $comp.SIDHistory.Count -eq 0) { continue }
            $key = $comp.Domain
            if (-not $domainBuckets.ContainsKey($key)) {
                $domainBuckets[$key] = @{
                    Domain   = $comp.Domain
                    Count    = 0
                    Examples = [System.Collections.Generic.List[string]]::new()
                }
            }
            $domainBuckets[$key].Count++
            if ($domainBuckets[$key].Examples.Count -lt 10) {
                $domainBuckets[$key].Examples.Add("$($comp.SamAccountName) [Computer] ($($comp.SIDHistory.Count) SIDs)")
            }
        }

        foreach ($bucket in $domainBuckets.Values) {
            $sev = if ($bucket.Count -gt 50) { 'High' }
                   elseif ($bucket.Count -gt 10) { 'Medium' }
                   else { 'Low' }
            $findings += @{
                Severity = $sev
                ObjectDN = "Domain: $($bucket.Domain)"
                Domain   = $bucket.Domain
                Details  = @{
                    SIDHistoryAccountCount = "$($bucket.Count)"
                    Examples               = ($bucket.Examples -join '; ')
                }
            }
        }
        return $findings
    }
}

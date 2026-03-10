# Rules\StaleObjects\DuplicateSamAccountName.rule.ps1
# Flags duplicate sAMAccountName entries across forest domains. [PingCastle: S-Duplicate]

@{
    Id          = 'MATI-STALE-007'
    Title       = 'Duplicate sAMAccountName across forest domains'
    Severity    = 'Medium'
    Description = "Accounts with the same sAMAccountName exist in multiple domains within the forest. This can occur due to replication conflicts or incomplete migrations. Duplicate names can cause confusion during authentication and may be exploited by an attacker for lateral movement."
    Remediation = "Identify and rename or remove the duplicate accounts. Investigate whether they were created by replication conflicts (CNF: objects) or intentional provisioning."
    Collectors  = @('UserAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        # Build per-sAMAccountName map with domain
        $samMap = @{}
        foreach ($user in $Data.UserAccounts) {
            $sam = $user.SamAccountName.ToLower()
            if (-not $samMap.ContainsKey($sam)) { $samMap[$sam] = @() }
            $domain = $user.DistinguishedName -replace '^.*?,DC=','DC=' -replace ',DC=','.' -replace '^DC=',''
            $samMap[$sam] += @{ DN = $user.DistinguishedName; Domain = $domain }
        }
        foreach ($sam in $samMap.Keys) {
            $entries = $samMap[$sam]
            $domains = @($entries | ForEach-Object { $_.Domain } | Sort-Object -Unique)
            if ($domains.Count -gt 1) {
                $findings += @{
                    ObjectDN = $entries[0].DN
                    Domain   = $entries[0].Domain
                    Details  = @{
                        SamAccountName = $sam
                        FoundInDomains = $domains -join '; '
                        Count          = $entries.Count
                    }
                }
            }
        }
        return $findings
    }
}

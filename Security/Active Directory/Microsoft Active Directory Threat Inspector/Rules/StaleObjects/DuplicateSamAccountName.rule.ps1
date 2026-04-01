# Rules\StaleObjects\DuplicateSamAccountName.rule.ps1
# Flags duplicate sAMAccountName entries across forest domains. [PingCastle: S-Duplicate]

@{
    Id          = 'MATI-STALE-007'
    Title       = 'Duplicate sAMAccountName across forest domains'
    Severity    = 'Informational'
    Description = "Accounts with the same sAMAccountName exist in multiple domains within the forest. This is often a naming or governance issue rather than a direct security problem, but it becomes more important when privileged accounts or sensitive account names are involved."
    Remediation = "Review duplicate names and confirm they are intentional. Prioritize renaming or consolidating duplicates for privileged accounts, service accounts, or other sensitive naming patterns."
    Collectors  = @('UserAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $excludedWellKnownRidSuffixes = @('-500', '-501', '-502')
        $sensitiveSamPatterns = @(
            '(^|[-_.])(adm|admin)([-_.]|$)',
            '(^|[-_.])(svc|service)([-_.]|$)',
            '(^|[-_.])(sql|mssql)([-_.]|$)',
            '(^|[-_.])(backup|bkp)([-_.]|$)',
            '(^|[-_.])(tier0|tier1|t0|t1)([-_.]|$)',
            '(^|[-_.])(sec|security)([-_.]|$)'
        )

        # Build per-sAMAccountName map with domain
        $samMap = @{}
        foreach ($user in $Data.UserAccounts) {
            if ([string]::IsNullOrWhiteSpace($user.SamAccountName)) { continue }

            $userSid = "$($user.SID)"
            if ($excludedWellKnownRidSuffixes | Where-Object { $userSid.EndsWith($_, [System.StringComparison]::OrdinalIgnoreCase) }) {
                continue
            }

            $sam = $user.SamAccountName.ToLower()
            if (-not $samMap.ContainsKey($sam)) { $samMap[$sam] = @() }
            $domain = if ($user.Domain) { "$($user.Domain)" } else { $user.DistinguishedName -replace '^.*?,DC=','DC=' -replace ',DC=','.' -replace '^DC=','' }
            $isSensitiveName = $false
            foreach ($pattern in $sensitiveSamPatterns) {
                if ($sam -match $pattern) {
                    $isSensitiveName = $true
                    break
                }
            }

            $samMap[$sam] += @{
                DN              = $user.DistinguishedName
                Domain          = $domain
                AdminCount      = $user.AdminCount
                SensitiveName   = $isSensitiveName
                SamAccountName  = $user.SamAccountName
            }
        }
        foreach ($sam in $samMap.Keys) {
            $entries = $samMap[$sam]
            $domains = @($entries | ForEach-Object { $_.Domain } | Sort-Object -Unique)
            if ($domains.Count -gt 1) {
                $hasPrivilegedDuplicate = @($entries | Where-Object { $_.AdminCount -eq 1 }).Count -gt 0
                $hasSensitiveNameDuplicate = @($entries | Where-Object { $_.SensitiveName }).Count -gt 0
                $severity = if ($hasPrivilegedDuplicate -or $hasSensitiveNameDuplicate) { 'Medium' } else { 'Informational' }
                $classification = if ($hasPrivilegedDuplicate) {
                    'Privileged account duplicate'
                }
                elseif ($hasSensitiveNameDuplicate) {
                    'Sensitive account name duplicate'
                }
                else {
                    'General duplicate naming'
                }

                $findings += @{
                    Severity = $severity
                    ObjectDN = $entries[0].DN
                    Domain   = $entries[0].Domain
                    Details  = @{
                        SamAccountName       = $entries[0].SamAccountName
                        FoundInDomains       = $domains -join '; '
                        Count                = $entries.Count
                        Classification       = $classification
                        PrivilegedDuplicate  = $hasPrivilegedDuplicate
                        SensitiveName        = $hasSensitiveNameDuplicate
                    }
                }
            }
        }
        return $findings
    }
}

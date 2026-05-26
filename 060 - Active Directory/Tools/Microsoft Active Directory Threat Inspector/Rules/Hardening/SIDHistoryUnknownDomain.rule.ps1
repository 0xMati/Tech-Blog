# Rules\Hardening\SIDHistoryUnknownDomain.rule.ps1
# Flags accounts with SIDHistory from unknown/non-existing domains. [PingCastle: T-SIDHistoryUnknownDomain]

@{
    Id          = 'MATI-HARD-043'
    Title       = 'SIDHistory referencing unknown or non-existing domain'
    Severity    = 'High'
    Description = "One or more accounts have SIDHistory entries whose domain SID does not match any current domain or trust in the forest. This may indicate a completed migration where cleanup was not performed, or a potential backdoor using a fabricated SID."
    Remediation = "Remove SIDHistory entries that reference domains no longer trusted or no longer existing. Use 'Get-ADUser -Properties SIDHistory' and 'Set-ADUser -Remove @{SIDHistory=...}' for cleanup."
    Collectors  = @('UserAccounts', 'TrustInfo', 'DomainInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/sid-filtering-and-sid-history')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        # Build set of known domain SIDs (own domains + trusts)
        $knownDomainSIDs = @{}
        foreach ($dom in $Data.DomainInfo.Domains) {
            try {
                $domSID = (Get-ADDomain -Server $dom.DNSRoot -ErrorAction SilentlyContinue).DomainSID.Value
                if ($domSID) { $knownDomainSIDs[$domSID] = $dom.DNSRoot }
            } catch { }
        }
        # Resolve trust target domain SIDs
        foreach ($trust in $Data.TrustInfo) {
            try {
                $trustObj = Get-ADTrust -Identity $trust.DistinguishedName -Properties securityIdentifier `
                    -Server $trust.SourceDomain -ErrorAction SilentlyContinue
                if ($trustObj.securityIdentifier) {
                    $knownDomainSIDs[$trustObj.securityIdentifier.Value] = $trust.TargetDomain
                }
            } catch { }
        }

        foreach ($user in $Data.UserAccounts) {
            $sidHistory = @($user.SIDHistory | Where-Object { $null -ne $_ })
            if ($sidHistory.Count -eq 0) { continue }
            foreach ($sid in $sidHistory) {
                $sidStr = if ($sid -is [System.Security.Principal.SecurityIdentifier]) { $sid.Value } else { "$sid" }
                # Extract domain SID (remove the RID at the end)
                $parts = $sidStr -split '-'
                if ($parts.Count -lt 5) { continue }
                $domSID = ($parts[0..($parts.Count - 2)]) -join '-'
                if (-not $knownDomainSIDs.ContainsKey($domSID)) {
                    $findings += @{
                        ObjectDN = $user.DistinguishedName
                        Domain   = ($user.DistinguishedName -replace '^.*?,DC=','DC=' -replace ',DC=','.' -replace '^DC=','')
                        Details  = @{
                            AccountName     = $user.SamAccountName
                            SIDHistoryEntry = $sidStr
                            DomainSID       = $domSID
                            Issue           = 'SID from unknown domain (no matching trust or forest domain)'
                        }
                    }
                }
            }
        }
        return $findings
    }
}

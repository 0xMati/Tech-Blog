# Rules\GPO\NullSessionRestriction.rule.ps1
# Flags domains where anonymous/null session access is not restricted via GPO.

@{
    Id          = 'MATI-GPO-009'
    Title       = 'Anonymous/null session access not restricted via GPO'
    Severity    = 'Medium'
    Description = "Anonymous access restrictions are not properly configured via GPO on Domain Controllers. Null sessions allow unauthenticated users to enumerate domain users, groups, shares, and other sensitive information that aids reconnaissance."
    Remediation = "Configure GPO security options: 'Network access: Restrict anonymous access to Named Pipes and Shares' = Enabled, 'Network access: Do not allow anonymous enumeration of SAM accounts' = Enabled, 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' = Enabled. Set RestrictAnonymous=1, RestrictAnonymousSAM=1, EveryoneIncludesAnonymous=0."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $issues = @()
            $restrictAnonymous = $null
            $restrictAnonymousSAM = $null

            if ($domainData.SecurityOptions) {
                foreach ($key in $domainData.SecurityOptions.Keys) {
                    if ($key -like '*Lsa\RestrictAnonymous' -and $key -notlike '*RestrictAnonymousSAM*') {
                        $value = $domainData.SecurityOptions[$key]
                        if ($value -match ',(\d+)') {
                            $restrictAnonymous = [int]$Matches[1]
                        }
                    }
                    if ($key -like '*Lsa\RestrictAnonymousSAM*') {
                        $value = $domainData.SecurityOptions[$key]
                        if ($value -match ',(\d+)') {
                            $restrictAnonymousSAM = [int]$Matches[1]
                        }
                    }
                }
            }

            if ($null -eq $restrictAnonymous -or $restrictAnonymous -lt 1) {
                $issues += "RestrictAnonymous=$(if ($null -ne $restrictAnonymous) { $restrictAnonymous } else { 'Not configured' }) (expected >=1)"
            }
            if ($null -eq $restrictAnonymousSAM -or $restrictAnonymousSAM -lt 1) {
                $issues += "RestrictAnonymousSAM=$(if ($null -ne $restrictAnonymousSAM) { $restrictAnonymousSAM } else { 'Not configured' }) (expected >=1)"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        RestrictAnonymous    = "$(if ($null -ne $restrictAnonymous) { $restrictAnonymous } else { 'Not configured' })"
                        RestrictAnonymousSAM = "$(if ($null -ne $restrictAnonymousSAM) { $restrictAnonymousSAM } else { 'Not configured' })"
                        Issues               = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}

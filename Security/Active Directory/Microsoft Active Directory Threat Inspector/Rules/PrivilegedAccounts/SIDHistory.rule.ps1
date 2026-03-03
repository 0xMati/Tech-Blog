# Rules\PrivilegedAccounts\SIDHistory.rule.ps1
# Flags privileged accounts with SIDHistory attribute populated.

@{
    Id          = 'MATI-ADMIN-011'
    Title       = 'Privileged account with SIDHistory'
    Severity    = 'High'
    Description = "A privileged account has SIDs in the SIDHistory attribute. This attribute is normally used during migrations but can be exploited to impersonate identities in other domains (SIDHistory injection attack)."
    Remediation = "Remove the SIDHistory attribute from privileged accounts once the migration is complete. Use the command: Set-ADUser -Identity <user> -Remove @{SIDHistory=<SID>}"
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if ($account.SIDHistory -and $account.SIDHistory.Count -gt 0) {
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        SamAccountName = $account.SamAccountName
                        SIDHistoryCount = "$($account.SIDHistory.Count)"
                        SIDHistory      = ($account.SIDHistory -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}

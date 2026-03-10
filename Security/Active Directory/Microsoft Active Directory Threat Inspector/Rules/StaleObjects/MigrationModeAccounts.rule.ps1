# Rules\StaleObjects\MigrationModeAccounts.rule.ps1
# Flags migration-mode accounts (YOURDOMAINNAME$). [PingCastle: S-Domain$$$]

@{
    Id          = 'MATI-STALE-006'
    Title       = 'Migration-mode accounts detected'
    Severity    = 'Medium'
    Description = "Accounts with names ending in '$$' were detected. These are typically created during inter-domain migration operations and indicate that a migration process is or was in progress. If the migration is complete, these accounts should be cleaned up as they can contain SIDHistory and other attributes that weaken security boundaries."
    Remediation = "If migration is complete, remove the migration-mode accounts. If migration is ongoing, ensure these accounts are properly secured and monitored."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/sid-filtering-and-sid-history')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.MigrationAccounts) {
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    AccountName     = $acct.SamAccountName
                    Enabled         = "$($acct.Enabled)"
                    PasswordLastSet = "$($acct.PasswordLastSet)"
                    WhenCreated     = "$($acct.WhenCreated)"
                }
            }
        }
        return $findings
    }
}

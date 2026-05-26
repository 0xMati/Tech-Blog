# Rules\PrivilegedAccounts\PrivilegedAccountEmailEnabled.rule.ps1
# Flags privileged accounts with email enabled. [PingCastle: P-AdminEmailOn]

@{
    Id          = 'MATI-ADMIN-015'
    Title       = 'Privileged account with email enabled'
    Severity    = 'Medium'
    Description = "One or more privileged accounts have the 'mail' attribute populated, indicating an associated mailbox. Email-enabled privileged accounts are exposed to phishing, credential harvesting, and Exchange-based attacks. Administrators should use non-privileged accounts for email."
    Remediation = "Remove the mailbox from privileged accounts or clear the mail attribute. Create dedicated non-privileged accounts for email and daily activities."
    Collectors  = @('PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-accounts')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = @{}
        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }
            if ($seen.ContainsKey($account.DistinguishedName)) { continue }
            $mail = $account.mail
            if (-not [string]::IsNullOrWhiteSpace($mail)) {
                $seen[$account.DistinguishedName] = $true
                $findings += @{
                    ObjectDN = $account.DistinguishedName
                    Domain   = $account.Domain
                    Details  = @{
                        AccountName = $account.SamAccountName
                        Mail        = $mail
                    }
                }
            }
        }
        return $findings
    }
}

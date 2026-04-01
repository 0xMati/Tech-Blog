# Rules\PrivilegedAccounts\PrivilegedAccountLogonScript.rule.ps1
# Flags privileged accounts with a configured logon script.

@{
    Id          = 'MATI-ADMIN-016'
    Title       = 'Privileged account with logon script configured'
    Severity    = 'High'
    Description = "A privileged account has the AD logon script attribute configured. Logon scripts execute code in the privileged user's context and create an additional persistence and hijacking surface on SYSVOL or other script paths."
    Remediation = "Remove interactive logon scripts from privileged accounts. If a script is still required for an administrative workflow, replace it with a controlled management mechanism and secure the referenced path."
    Collectors  = @('PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($account in $Data.PrivilegedAccounts.Accounts) {
            if (-not $account.Enabled) { continue }
            if ([string]::IsNullOrWhiteSpace($account.ScriptPath)) { continue }
            if (-not $seen.Add($account.DistinguishedName)) { continue }

            $findings += @{
                ObjectDN = $account.DistinguishedName
                Domain   = $account.Domain
                Details  = @{
                    AccountName = $account.SamAccountName
                    ScriptPath  = $account.ScriptPath
                }
            }
        }

        return $findings
    }
}
# Rules\Hardening\GuestEnabled.rule.ps1
# Flags domains where the Guest account is enabled.

@{
    Id          = 'MATI-HARD-002'
    Title       = 'Guest account is enabled'
    Severity    = 'High'
    Description = "The built-in Guest account is enabled. This account provides unauthenticated access to the domain and can be exploited by attackers to enumerate domain resources and move laterally."
    Remediation = "Disable the Guest account: Disable-ADAccount -Identity Guest"
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/accounts-guest-account-status')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($guest in $Data.SecurityConfig.GuestAccounts) {
            if ($guest.Enabled) {
                $findings += @{
                    ObjectDN = $guest.SID
                    Domain   = $guest.Domain
                    Details  = @{
                        SamAccountName  = $guest.SamAccountName
                        Enabled         = 'True'
                        PasswordLastSet = "$($guest.PasswordLastSet)"
                    }
                }
            }
        }
        return $findings
    }
}

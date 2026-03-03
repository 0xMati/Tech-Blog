# Rules\Hardening\PasswordNotRequired.rule.ps1
# Flags enabled accounts with the PASSWD_NOTREQD flag.

@{
    Id          = 'MATI-HARD-007'
    Title       = 'Account with PASSWORD_NOT_REQUIRED flag'
    Severity    = 'High'
    Description = "An enabled account has the PASSWD_NOTREQD flag set in UserAccountControl. This means the account can have an empty password regardless of the domain password policy, allowing an attacker to authenticate without any password."
    Remediation = "Clear the PASSWD_NOTREQD flag: Set-ADAccountControl -Identity <samAccountName> -PasswordNotRequired `$false. Then force a password reset."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.PwdNotRequired) {
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    SamAccountName    = $acct.SamAccountName
                    Enabled           = "$($acct.Enabled)"
                    PasswordNotRequired = 'True'
                }
            }
        }
        return $findings
    }
}

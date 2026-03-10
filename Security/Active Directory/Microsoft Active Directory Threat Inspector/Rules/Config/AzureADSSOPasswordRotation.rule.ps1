# Rules\Config\AzureADSSOPasswordRotation.rule.ps1
# Flags AZUREADSSOACC$ account with old password. [PingCastle: T-AzureADSSO]

@{
    Id          = 'MATI-CONFIG-029'
    Title       = 'Azure AD Seamless SSO account password not rotated'
    Severity    = 'Critical'
    Description = "The AZUREADSSOACC$ computer account is used for Azure AD Seamless Single Sign-On. Its Kerberos decryption key is shared with Azure AD. If the password is not rotated regularly (at least every 30 days), an attacker who compromises this key can forge Kerberos tickets as any Azure AD user, enabling Silver Ticket attacks against cloud resources."
    Remediation = "Rotate the AZUREADSSOACC$ account password using the Azure AD Connect wizard or PowerShell cmdlet 'Update-AzureADSSOForest'. Microsoft recommends rotation at least every 30 days."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-faq'
        'https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-sso'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.AzureADSSOAccounts) {
            if ($acct.PasswordAgeDays -gt 30) {
                $severity = if ($acct.PasswordAgeDays -gt 180) { 'Critical' }
                            elseif ($acct.PasswordAgeDays -gt 90) { 'High' }
                            else { 'Medium' }
                $findings += @{
                    ObjectDN = $acct.DistinguishedName
                    Domain   = $acct.Domain
                    Details  = @{
                        AccountName     = $acct.SamAccountName
                        PasswordLastSet = "$($acct.PasswordLastSet)"
                        PasswordAgeDays = $acct.PasswordAgeDays
                        Enabled         = "$($acct.Enabled)"
                        Severity        = $severity
                    }
                }
            }
        }
        return $findings
    }
}

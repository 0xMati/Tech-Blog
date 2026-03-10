# Rules\Hardening\UnixPasswordAttributes.rule.ps1
# Flags accounts with userPassword or unixUserPassword set. [PingCastle: A-UnixPwd]

@{
    Id          = 'MATI-HARD-044'
    Title       = 'Unix or LDAP password attributes set on accounts'
    Severity    = 'High'
    Description = "One or more accounts have the userPassword or unixUserPassword attribute populated. These attributes may store passwords in clear text or weakly hashed formats (e.g. crypt, MD5, SHA). An attacker with read access to these attributes can retrieve credentials."
    Remediation = "Clear the userPassword and unixUserPassword attributes. Migrate applications to use Kerberos or Active Directory password authentication instead of LDAP simple binds against these attributes."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26571a284f2')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.UnixPwdAccounts) {
            $attrs = @()
            if ($acct.HasUserPassword) { $attrs += 'userPassword' }
            if ($acct.HasUnixPassword) { $attrs += 'unixUserPassword' }
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    AccountName       = $acct.SamAccountName
                    Enabled           = "$($acct.Enabled)"
                    AttributesPresent = $attrs -join ', '
                }
            }
        }
        return $findings
    }
}

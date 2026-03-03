# Rules\Hardening\DESEncryption.rule.ps1
# Flags accounts with DES encryption enabled.

@{
    Id          = 'MATI-HARD-006'
    Title       = 'Account with DES encryption enabled'
    Severity    = 'High'
    Description = "An account has the USE_DES_KEY_ONLY flag set in UserAccountControl. DES is a weak, deprecated encryption algorithm. Accounts with DES forced are vulnerable to offline brute-force attacks on Kerberos tickets."
    Remediation = "Disable the USE_DES_KEY_ONLY flag: Set-ADUser <user> -KerberosEncryptionType AES128,AES256 and clear the DES flag."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: S-DesEnabled', 'ANSSI: vuln_des_encryption')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($acct in $Data.SecurityConfig.DESAccounts) {
            $findings += @{
                ObjectDN = $acct.DistinguishedName
                Domain   = $acct.Domain
                Details  = @{
                    SamAccountName = $acct.SamAccountName
                    Enabled        = "$($acct.Enabled)"
                    ObjectClass    = $acct.ObjectClass
                }
            }
        }
        return $findings
    }
}

# Rules\Kerberos\KrbtgtWeakEncryption.rule.ps1
# Flags KRBTGT accounts without AES encryption support.

@{
    Id          = 'MATI-KERB-008'
    Title       = 'KRBTGT account does not support AES encryption'
    Severity    = 'High'
    Description = "The KRBTGT account does not have AES encryption types (AES128/AES256) enabled in msDS-SupportedEncryptionTypes. This forces the KDC to use RC4-HMAC for ticket encryption, which is weaker and susceptible to offline attacks."
    Remediation = "Ensure the domain functional level is 2008 or higher (AES is automatically available). Rotate the KRBTGT password twice to update encryption keys. Verify msDS-SupportedEncryptionTypes includes AES (bits 0x8 and 0x10)."
    Collectors  = @('KerberosConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-supported-encryption-types')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($krbtgt in $Data.KerberosConfig.KrbtgtAccounts) {
            $encTypes = $krbtgt.SupportedEncryptionTypes
            # AES128 = 0x8, AES256 = 0x10
            $hasAES = ($null -ne $encTypes) -and (($encTypes -band 0x18) -ne 0)

            if (-not $hasAES) {
                $findings += @{
                    ObjectDN = $krbtgt.DistinguishedName
                    Domain   = $krbtgt.Domain
                    Details  = @{
                        Account                  = $krbtgt.SamAccountName
                        SupportedEncryptionTypes = if ($null -eq $encTypes) { 'Not set (RC4 only)' } else { "0x$($encTypes.ToString('X'))" }
                        PasswordAgeDays          = $krbtgt.PasswordAgeDays
                    }
                }
            }
        }
        return $findings
    }
}

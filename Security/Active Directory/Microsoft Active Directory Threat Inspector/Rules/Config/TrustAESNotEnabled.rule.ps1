# Rules\Config\TrustAESNotEnabled.rule.ps1
# Flags trust relationships without AES encryption support.

@{
    Id          = 'MATI-CONFIG-012'
    Title       = 'Trust without AES encryption'
    Severity    = 'Medium'
    Description = "A trust relationship does not have AES encryption enabled. Without AES, Kerberos tickets for cross-domain authentication use RC4 encryption, which is vulnerable to offline cracking attacks. Even intra-forest trusts benefit from AES enforcement."
    Remediation = "Enable AES for the trust: ksetup /setenctypeattr <TrustedDomain> AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96. Or use: netdom trust <TrustingDomain> /domain:<TrustedDomain> /SetAes256"
    Collectors  = @('TrustInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trust/configure-encryption-types')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # Check msDS-SupportedEncryptionTypes for AES bits:
            #   AES128_CTS_HMAC_SHA1 = 0x08
            #   AES256_CTS_HMAC_SHA1 = 0x10
            $hasAES = $trust.AES128Enabled -or $trust.AES256Enabled

            if (-not $hasAES) {
                $encTypes = $trust.SupportedEncryptionTypes
                $severity = if ($trust.IntraForest) { 'Medium' } else { 'High' }

                $findings += @{
                    Severity = $severity
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain             = $trust.TargetDomain
                        TrustType                = "$($trust.TrustType)"
                        Direction                = "$($trust.TrustDirection)"
                        IntraForest              = "$($trust.IntraForest)"
                        AES128Enabled            = "$($trust.AES128Enabled)"
                        AES256Enabled            = "$($trust.AES256Enabled)"
                        RC4Enabled               = "$($trust.RC4Enabled)"
                        SupportedEncryptionTypes = "$encTypes"
                    }
                }
            }
        }
        return $findings
    }
}

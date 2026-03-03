# Rules\Config\TrustAESNotEnabled.rule.ps1
# Flags trust relationships without AES encryption support.

@{
    Id          = 'MATI-CONFIG-012'
    Title       = 'Trust without AES encryption'
    Severity    = 'Medium'
    Description = "A trust relationship does not have AES encryption enabled. Without AES, Kerberos tickets for cross-domain authentication use RC4 encryption, which is vulnerable to offline cracking attacks. Even intra-forest trusts benefit from AES enforcement."
    Remediation = "Enable AES for the trust: ksetup /setenctypeattr <TrustedDomain> AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96. Or use: netdom trust <TrustingDomain> /domain:<TrustedDomain> /SetAes256"
    Collectors  = @('TrustInfo')
    References  = @('PingCastle: T-AlgsAES', 'ANSSI: vuln_trusts_aes')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # TRUST_ATTRIBUTE_USES_AES_KEYS = 0x00000100
            $aesEnabled = ($trust.TrustAttributes -band 0x00000100) -ne 0
            if (-not $aesEnabled) {
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain    = $trust.TargetDomain
                        TrustType       = "$($trust.TrustType)"
                        Direction       = "$($trust.TrustDirection)"
                        AESEnabled      = 'False'
                        TrustAttributes = "$($trust.TrustAttributes)"
                    }
                }
            }
        }
        return $findings
    }
}

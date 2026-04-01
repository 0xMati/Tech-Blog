# Rules\Config\TrustAESNotEnabled.rule.ps1
# Flags trust relationships without AES encryption support.

@{
    Id          = 'MATI-CONFIG-012'
    Title       = 'Trust without AES encryption'
    Severity    = 'Medium'
    Description = "A trust relationship does not advertise AES support, or cannot be evaluated locally because the AES capability is only exposed from the opposite side of a one-way outbound trust. In those outbound cases, this rule reports an informational verification item instead of a true misconfiguration."
    Remediation = "If the trust is inbound or bidirectional and AES is absent, enable AES on the trust with ksetup /setenctypeattr <TrustedDomain> AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 or netdom trust <TrustingDomain> /domain:<TrustedDomain> /SetAes256 as appropriate. If the trust is one-way outbound, verify the setting from the opposite side where the trust exposes the 'other domain supports Kerberos AES encryption' option."
    Collectors  = @('TrustInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trust/configure-encryption-types')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # In a one-way outbound trust, the local TDO does not expose the effective
            # 'other domain supports Kerberos AES encryption' state. The relevant flag is
            # visible from the opposite side (incoming), so keep the item as informational only.
            if ($trust.TrustDirection -eq 'Outbound') {
                $findings += @{
                    Severity = 'Informational'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain             = $trust.TargetDomain
                        TrustType                = "$($trust.TrustType)"
                        Direction                = "$($trust.TrustDirection)"
                        IntraForest              = "$($trust.IntraForest)"
                        EvaluationStatus         = 'Not locally evaluable from outbound side'
                        VerificationRequired     = 'Check the opposite side of the trust'
                        AES128Enabled            = "$($trust.AES128Enabled)"
                        AES256Enabled            = "$($trust.AES256Enabled)"
                        RC4Enabled               = "$($trust.RC4Enabled)"
                        SupportedEncryptionTypes = "$($trust.SupportedEncryptionTypes)"
                    }
                }
                continue
            }

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

# Rules\Config\TrustAESNotEnabled.rule.ps1
# Flags trust relationships without AES encryption support.

@{
    Id          = 'MATI-CONFIG-012'
    Title       = 'Trust not AES-only (RC4, DES, or unset)'
    Severity    = 'Medium'
    Description = "A trust relationship is not in an AES-only state. It either advertises no AES (RC4-only or unset, which behaves like RC4 for cross-realm referrals), still allows RC4 alongside AES (Mixed), or carries a legacy DES bit. RC4/DES cross-realm tickets are crackable offline and block AES-only enforcement. One-way outbound trusts cannot be evaluated locally and are reported as an informational verification item."
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

            # Decode msDS-SupportedEncryptionTypes (MS-KILE):
            #   DES-CBC-CRC = 0x01, DES-CBC-MD5 = 0x02
            #   RC4-HMAC    = 0x04
            #   AES128      = 0x08, AES256 = 0x10
            $encTypes = $trust.SupportedEncryptionTypes
            $encInt   = if ($null -ne $encTypes) { [int]$encTypes } else { 0 }

            $hasAES = $trust.AES128Enabled -or $trust.AES256Enabled
            $hasRC4 = [bool]$trust.RC4Enabled
            $hasDES = ($encInt -band 0x03) -ne 0

            # Classify the trust posture (mirrors the RC4 Hardening trust audit classes).
            $classification = if ($encInt -eq 0)        { 'Unset' }
                              elseif ($hasDES)          { 'Legacy-DES' }
                              elseif ($hasRC4 -and $hasAES) { 'Mixed' }
                              elseif ($hasRC4)          { 'RC4-only' }
                              elseif ($hasAES)          { 'AES-only' }
                              else                      { 'Unknown' }

            $baseDetails = @{
                TargetDomain             = $trust.TargetDomain
                TrustType                = "$($trust.TrustType)"
                Direction                = "$($trust.TrustDirection)"
                IntraForest              = "$($trust.IntraForest)"
                Classification           = $classification
                AES128Enabled            = "$($trust.AES128Enabled)"
                AES256Enabled            = "$($trust.AES256Enabled)"
                RC4Enabled               = "$($trust.RC4Enabled)"
                SupportedEncryptionTypes = "$encTypes"
                LastChanged              = "$($trust.WhenCreated)"
            }

            if ($hasDES) {
                # DES on a trust should not exist on a modern forest — always a priority finding.
                $findings += @{
                    Severity = 'High'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = $baseDetails + @{
                        Issue = 'Trust still advertises DES encryption. Set msDS-SupportedEncryptionTypes to 0x18 (AES128+AES256) and rotate the trust password.'
                    }
                }
            }
            elseif (-not $hasAES) {
                # RC4-only or Unset (0/absent): behaves like RC4 for cross-realm referrals.
                $severity = if ($trust.IntraForest) { 'Medium' } else { 'High' }

                $findings += @{
                    Severity = $severity
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = $baseDetails + @{
                        Issue = if ($classification -eq 'Unset') {
                            'Trust encryption is unset (0/absent), which behaves like RC4-only for cross-realm referrals. Set msDS-SupportedEncryptionTypes to 0x18 and rotate the trust password.'
                        } else {
                            'Trust advertises RC4 only. Set msDS-SupportedEncryptionTypes to 0x18 (AES128+AES256) and rotate the trust password.'
                        }
                    }
                }
            }
            elseif ($hasRC4) {
                # Mixed: AES present but RC4 still allowed. RC4 referrals can still be negotiated.
                $findings += @{
                    Severity = 'Medium'
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = $baseDetails + @{
                        Issue = 'Trust allows RC4 alongside AES (Mixed). Remove the RC4 bit (set msDS-SupportedEncryptionTypes to 0x18) and rotate the trust password to force AES-only referrals.'
                    }
                }
            }
        }
        return $findings
    }
}

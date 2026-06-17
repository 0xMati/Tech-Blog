# Rules\Hardening\KdcRc4ByOmission.rule.ps1
# Flags domain controllers whose KDC fallback (DefaultDomainSupportedEncTypes)
# is not pinned to AES-only, allowing RC4 "by omission" for accounts whose
# msDS-SupportedEncryptionTypes is unset. Per-DC registry value, not replicated.

@{
    Id          = 'MATI-HARD-047'
    Title       = 'KDC default allows RC4 by omission (DefaultDomainSupportedEncTypes not AES-only)'
    Severity    = 'Medium'
    Description = "DefaultDomainSupportedEncTypes (HKLM\SYSTEM\CurrentControlSet\Services\Kdc) is the per-DC fallback the KDC applies when an account's msDS-SupportedEncryptionTypes is 0 or absent. When this value is not explicitly pinned to AES-only (0x18), the DC can hand out RC4 tickets for any account that does not declare its encryption types. This value is NOT replicated, so it must be aligned on every DC. Severity scales with what the value permits: unset (implicit AES on patched DCs, but not enforced), Mixed (AES+RC4), or DES/RC4-only."
    Remediation = "On every domain controller, set DefaultDomainSupportedEncTypes = 0x18 (AES128 + AES256) under HKLM\SYSTEM\CurrentControlSet\Services\Kdc once the account inventory confirms no identity depends on RC4. This is the only posture that survives the KB5073381 July 2026 enforcement, where the RC4DefaultDisablementPhase knob is removed and the explicit registry value becomes the sole declarative lever. Do not pin it before AES keys are materialized on all service accounts."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d'
        'https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $dcs = @($Data.ProtocolConfig.DCProtocolSettings | Where-Object { $_.WinRMAccessible })
        if ($dcs.Count -eq 0) { return $findings }

        foreach ($dc in $dcs) {
            $raw = $dc.KdcDefaultEncTypes

            # Mirror Get-KdcDefaultStatus from the source audit script.
            if ($null -eq $raw) {
                # Registry value absent: patched DCs prefer AES, but AES-only is not pinned.
                $findings += @{
                    Severity = 'Low'
                    Domain   = $dc.Domain
                    Details  = @{
                        DomainController = $dc.HostName
                        Domain           = $dc.Domain
                        RegistryValue    = '(absent)'
                        Classification   = 'Unset (implicit AES on patched DCs, not enforced)'
                        Issue            = 'DefaultDomainSupportedEncTypes is not explicitly pinned to AES-only (0x18); unset accounts fall back to implicit KDC behavior.'
                        RegistryPath     = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
                    }
                }
                continue
            }

            $val    = [int]$raw
            $hasAes = (($val -band 0x18) -eq 0x18)
            $hasRc4 = (($val -band 0x04) -ne 0)
            $hasDes = (($val -band 0x03) -ne 0)

            # Compliant: AES-only, no RC4, no DES.
            if ($hasAes -and -not $hasRc4 -and -not $hasDes) { continue }

            $classification = if ($hasDes) { 'Legacy-DES allowed' }
                              elseif (-not $hasAes -and $hasRc4) { 'RC4-only' }
                              elseif (-not $hasAes) { 'No AES exposed' }
                              elseif ($hasRc4) { 'Mixed (AES + RC4)' }
                              else { 'Unknown' }

            $severity = if ($hasDes -or (-not $hasAes)) { 'High' } else { 'Medium' }

            $findings += @{
                Severity = $severity
                Domain   = $dc.Domain
                Details  = @{
                    DomainController = $dc.HostName
                    Domain           = $dc.Domain
                    RegistryValue    = ('0x{0:X}' -f $val)
                    Classification   = $classification
                    Issue            = 'KDC fallback allows non-AES encryption for accounts whose msDS-SupportedEncryptionTypes is unset.'
                    RegistryPath     = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
                }
            }
        }

        return $findings
    }
}

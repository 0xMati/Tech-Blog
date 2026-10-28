# Rules\Hardening\KdcRc4ByOmission.rule.ps1
# Flags domain controllers whose KDC fallback (DefaultDomainSupportedEncTypes)
# is not pinned to AES-only, allowing RC4 "by omission" for accounts whose
# msDS-SupportedEncryptionTypes is unset. Per-DC registry value, not replicated.

@{
    Id          = 'MATI-HARD-047'
    Title       = 'KDC default allows RC4 by omission (DefaultDomainSupportedEncTypes not AES-only)'
    Severity    = 'Medium'
    Description = "The effective KDC fallback permits legacy encryption for accounts whose msDS-SupportedEncryptionTypes is zero or absent. MATI evaluates explicit configuration and Windows build/revision against the KB5073381 rollout. An absent registry value is AES-only on enforced builds and is not itself a misconfiguration."
    Remediation = "Update DCs and verify AES keys and clients before enforcing AES-only. An explicit DefaultDomainSupportedEncTypes = 0x18 is optional when the patched KDC already defaults to AES-only. Review explicit legacy overrides, which remain effective even after July 2026; RC4DefaultDisablementPhase is ignored after final enforcement."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d'
        'https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys'
        'https://support.microsoft.com/help/5073381'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $dcs = @($Data.ProtocolConfig.DCProtocolSettings | Where-Object { $_.WinRMAccessible })
        if ($dcs.Count -eq 0) { return $findings }

        foreach ($dc in $dcs) {
            $raw = $dc.EffectiveKdcEncTypes
            if ($null -eq $raw) { throw "Effective KDC encryption settings are unknown on $($dc.HostName)." }

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
                    ConfigurationSource = if ($null -eq $dc.KdcDefaultEncTypes) { 'Build-dependent default' } else { 'Explicit registry setting' }
                    Evidence         = $dc.KdcSettingsEvidence
                    Classification   = $classification
                    Issue            = 'KDC fallback allows non-AES encryption for accounts whose msDS-SupportedEncryptionTypes is unset.'
                    RegistryPath     = 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes'
                }
            }
        }

        return $findings
    }
}

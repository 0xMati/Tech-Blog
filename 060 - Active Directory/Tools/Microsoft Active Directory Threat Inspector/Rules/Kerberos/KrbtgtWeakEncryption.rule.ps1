# Rules\Kerberos\KrbtgtWeakEncryption.rule.ps1
# Evaluates KRBTGT strong-key posture using runtime evidence first.

@{
    Id          = 'MATI-KERB-008'
    Title       = 'KRBTGT strong key posture requires review'
    Severity    = 'Informational'
    Description = "This control validates KRBTGT encryption posture using KDC runtime evidence when available. Attribute-only checks on msDS-SupportedEncryptionTypes are treated as a verification signal, not as proof that KRBTGT is RC4-only. In particular, a blank or 0x0 msDS-SupportedEncryptionTypes value on krbtgt should not be treated as a confirmed weakness if recent TGT issuance shows AES and no direct KDC strong-key warnings are present."
    Remediation = "If KDC runtime evidence shows weak KRBTGT keys or RC4-issued TGTs, rotate KRBTGT twice with the required replication interval and confirm AES TGT issuance on domain controllers. If only the attribute is suspicious, verify recent 4768 events and KDC strong-key warnings before treating it as a true issue. Prioritize observed TGT encryption types, KDC warnings, and KRBTGT rotation history over the raw krbtgt attribute alone; manual changes to msDS-SupportedEncryptionTypes on krbtgt are not the primary remediation path."
    Collectors  = @('KerberosConfig', 'LegacyProtocolAudit', 'DomainInfo')
    References  = @(
        'https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d'
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $domainModes = @{}
        foreach ($domainInfo in @($Data.DomainInfo.Domains)) {
            if ($domainInfo.DNSRoot) { $domainModes[$domainInfo.DNSRoot] = $domainInfo.DomainMode }
        }

        $kerberosAuditByDomain = @{}
        foreach ($domainAudit in @($Data.LegacyProtocolAudit.Kerberos.ByDomain)) {
            if ($domainAudit.Domain) { $kerberosAuditByDomain[$domainAudit.Domain] = $domainAudit }
        }

        foreach ($krbtgt in $Data.KerberosConfig.KrbtgtAccounts) {
            $encTypes = $krbtgt.SupportedEncryptionTypes
            $hasExplicitAES = ($null -ne $encTypes) -and (($encTypes -band 0x18) -ne 0)
            $domainAudit = $kerberosAuditByDomain[$krbtgt.Domain]
            $domainMode = $domainModes[$krbtgt.Domain]
            $maxKrbtgtAge = if ($Config.Thresholds.KrbtgtPasswordMaxAge) { [int]$Config.Thresholds.KrbtgtPasswordMaxAge } else { 180 }

            $kdcWarnings = @()
            if ($domainAudit -and $domainAudit.KdcStrongKeyWarnings) {
                $kdcWarnings = @($domainAudit.KdcStrongKeyWarnings | Where-Object {
                    $_.Account -and $_.Account -match '^krbtgt($|/)'
                })
            }

            $tgtRc4Count = if ($domainAudit) { [int]$domainAudit.TGT_RC4 } else { 0 }
            $tgtAesCount = if ($domainAudit) { [int]$domainAudit.TGT_AES128 + [int]$domainAudit.TGT_AES256 } else { 0 }
            $supportedEncLabel = if ($null -eq $encTypes) { 'Not set' } else { "0x$($encTypes.ToString('X'))" }
            $baseDetails = @{
                Account                  = $krbtgt.SamAccountName
                SupportedEncryptionTypes = $supportedEncLabel
                ExplicitAESSupported     = "$hasExplicitAES"
                PasswordAgeDays          = $krbtgt.PasswordAgeDays
                PasswordLastSet          = "$($krbtgt.PasswordLastSet)"
                DomainMode               = if ($domainMode) { "$domainMode" } else { '(unknown)' }
                AuditWindowHours         = if ($Data.LegacyProtocolAudit.AuditHours) { $Data.LegacyProtocolAudit.AuditHours } else { '(unknown)' }
                TgtAesCountObserved      = $tgtAesCount
                TgtRc4CountObserved      = $tgtRc4Count
                KdcStrongKeyWarnings     = $kdcWarnings.Count
            }

            if ($kdcWarnings.Count -gt 0) {
                $findings += @{
                    Severity = 'High'
                    Description = "KDC event 42 reported that KRBTGT lacks strong keys in domain '$($krbtgt.Domain)'. This is direct runtime evidence that the KDC does not have the expected AES-capable key material for KRBTGT."
                    Remediation = "Rotate KRBTGT twice with the required replication interval, then confirm KDC event 42 no longer appears and recent 4768 TGTs are issued with AES."
                    ObjectDN = $krbtgt.DistinguishedName
                    Domain   = $krbtgt.Domain
                    Details  = $baseDetails + @{
                        EvaluationStatus = 'Direct runtime evidence'
                        KdcWarningSample = $kdcWarnings[0].Message
                    }
                }
                continue
            }

            if ($tgtRc4Count -gt 0) {
                $findings += @{
                    Severity = 'High'
                    Description = "Recent 4768 events show RC4-encrypted TGT issuance in domain '$($krbtgt.Domain)'. This is strong evidence that KRBTGT strong-key posture is not where it should be, regardless of the raw AD attribute alone."
                    Remediation = "Investigate why the domain is still issuing RC4 TGTs, rotate KRBTGT twice if needed, and verify that updated domain controllers issue AES TGTs only."
                    ObjectDN = $krbtgt.DistinguishedName
                    Domain   = $krbtgt.Domain
                    Details  = $baseDetails + @{
                        EvaluationStatus = 'RC4 TGTs observed'
                    }
                }
                continue
            }

            if ((-not $hasExplicitAES) -and ([int]$krbtgt.PasswordAgeDays -gt $maxKrbtgtAge)) {
                $findings += @{
                    Severity = 'Informational'
                    Description = "KRBTGT does not explicitly advertise AES in msDS-SupportedEncryptionTypes for domain '$($krbtgt.Domain)', and the KRBTGT password age is older than the expected review threshold, but no direct runtime evidence of weak KRBTGT keys was observed in the current audit window. This should be reviewed rather than treated as a confirmed RC4-only state. If AES-encrypted TGTs are being issued and no KDC strong-key warnings are present, the attribute alone may simply be non-explicit or stale rather than indicating an actual weak-key condition."
                    Remediation = "Review recent 4768 events, KDC warnings, and KRBTGT rotation history for the domain. If KRBTGT was rotated and TGTs are issued with AES, this may only reflect an attribute/configuration discrepancy and does not by itself justify emergency remediation or manual edits to msDS-SupportedEncryptionTypes on krbtgt. If the password age is genuinely old, plan a controlled KRBTGT double rotation with the appropriate replication interval."
                    ObjectDN = $krbtgt.DistinguishedName
                    Domain   = $krbtgt.Domain
                    Details  = $baseDetails + @{
                        EvaluationStatus = 'Attribute-only verification required'
                        ReviewThresholdDays = $maxKrbtgtAge
                    }
                }
            }
        }
        return $findings
    }
}

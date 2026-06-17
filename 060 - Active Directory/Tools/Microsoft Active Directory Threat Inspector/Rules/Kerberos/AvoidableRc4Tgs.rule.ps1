# Rules\Kerberos\AvoidableRc4Tgs.rule.ps1
# Flags RC4 service tickets (4769) that were AVOIDABLE: the client advertised AES,
# the target service had AES keys, and the DC supported AES — yet RC4 was issued.
# Highest-signal RC4 evidence because every party in the exchange could already do AES.

@{
    Id          = 'MATI-KERB-011'
    Title       = 'Avoidable RC4 service tickets (AES was available end-to-end)'
    Severity    = 'High'
    Description = "Service tickets encrypted with RC4-HMAC were observed (event 4769) where the event capability fields indicate the client advertised AES, the target service exposed AES keys, and the issuing DC supported AES. Unlike generic RC4 usage, these are avoidable: every party in the exchange could already negotiate AES, yet RC4 was selected. This points to a misconfiguration (e.g. the service account's msDS-SupportedEncryptionTypes still pins RC4) rather than a missing AES key, and is the highest-signal RC4 evidence for remediation."
    Remediation = "For each listed service, set msDS-SupportedEncryptionTypes = 0x18 (AES128 + AES256) on the account behind the SPN and rotate its secret so AES keys are materialized. Confirm the RC4 TGS activity disappears in the next audit window. Because the client and DC already advertise AES, fixing the service account alone should eliminate these events without breaking authentication."
    Collectors  = @('LegacyProtocolAudit')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769'
        'https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $avoidable = @($Data.LegacyProtocolAudit.Kerberos.RC4ServiceDetails | Where-Object { $_.Name -and [int]$_.Count -gt 0 })
        if ($avoidable.Count -eq 0) { return $findings }

        $auditHours = if ($Data.LegacyProtocolAudit.AuditHours) { $Data.LegacyProtocolAudit.AuditHours } else { '(unknown)' }

        foreach ($svc in $avoidable) {
            $findings += @{
                Severity = 'High'
                ObjectDN = "$($svc.Name)"
                Details  = @{
                    Service               = "$($svc.Name)"
                    AvoidableRC4TgsCount  = "$($svc.Count)"
                    Condition             = 'Client advertised AES, service had AES keys, DC supported AES — RC4 issued anyway'
                    AuditWindowHours      = "$auditHours"
                }
            }
        }

        return $findings
    }
}

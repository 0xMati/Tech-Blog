# Rules\Kerberos\Kb5073381Rc4Disablement.rule.ps1
# Surfaces Kdcsvc 201-209 events (KB5073381 / CVE-2026-20833) that signal which
# accounts will break when implicit RC4 is removed. Pattern B = client RC4-only,
# Pattern D = service has no AES key (stale-key trap), 205 = insecure DC registry.

@{
    Id          = 'MATI-KERB-012'
    Title       = 'KB5073381 RC4 disablement readiness (Kdcsvc 201-209)'
    Severity    = 'Medium'
    Description = "KB5073381 (January 2026, permanent July 2026) introduces Kdcsvc events 201-209 in the System log that fire when the KDC would have used implicit RC4. Pattern B (201/203/206/208) means a client requested RC4-only; Pattern D (202/204/207/209) means the target service has no AES key (the stale-key trap); event 205 means a DC has an explicit insecure DefaultDomainSupportedEncTypes. Audit-phase events (201/202/206/207) are warnings; enforce-phase events (203/204/208/209) are blocking errors — those accounts are already failing or will fail once enforcement lands. These events are the definitive readiness signal before flipping to AES-only enforcement."
    Remediation = "For Pattern D (service no AES key), set msDS-SupportedEncryptionTypes = 0x18 on the named service account and rotate its secret so an AES key is materialized — this is the highest priority because the account breaks at enforcement. For Pattern B (client RC4-only), update the client/account to advertise AES. For event 205, fix DefaultDomainSupportedEncTypes on the named DC (see MATI-HARD-047). Re-run after each fix until the audit-phase events stop firing, then enforcement is safe."
    Collectors  = @('LegacyProtocolAudit')
    References  = @(
        'https://support.microsoft.com/en-us/topic/kb5073381'
        'https://learn.microsoft.com/en-us/windows-server/security/kerberos/preventing-kerberos-change-password-that-uses-rc4-secret-keys'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $kdcsvc = $Data.LegacyProtocolAudit.Kerberos.KdcsvcRc4Disablement
        if (-not $kdcsvc -or [int]$kdcsvc.TotalEvents -le 0) { return $findings }

        $auditHours = if ($Data.LegacyProtocolAudit.AuditHours) { $Data.LegacyProtocolAudit.AuditHours } else { '(unknown)' }
        $samples    = @($kdcsvc.Samples)

        foreach ($evt in @($kdcsvc.ByEventId)) {
            if ([int]$evt.Count -le 0) { continue }

            $severity = switch ($evt.Phase) {
                'Enforce' { 'High' }    # blocking errors — account already failing
                'Audit'   { 'Medium' }  # warnings — will fail at enforcement
                'Hygiene' { 'Low' }     # DC registry misconfig (also MATI-HARD-047)
                default   { 'Informational' }
            }

            $examples = @($samples |
                Where-Object { [int]$_.EventId -eq [int]$evt.EventId -and ($_.Account -or $_.Service) } |
                Select-Object -First 8 |
                ForEach-Object {
                    $who = if ($_.Service) { $_.Service } else { $_.Account }
                    "$who@$($_.DC)"
                }) -join '; '

            $findings += @{
                Severity = $severity
                Details  = @{
                    EventId          = "$($evt.EventId)"
                    Pattern          = "$($evt.Pattern)"
                    Cause            = "$($evt.Cause)"
                    PolicyMode       = "$($evt.Policy)"
                    PhaseSignal      = "$($evt.Phase)"
                    EventCount       = "$($evt.Count)"
                    Examples         = if ($examples) { $examples } else { '(no account/service parsed)' }
                    AuditWindowHours = "$auditHours"
                }
            }
        }

        return $findings
    }
}

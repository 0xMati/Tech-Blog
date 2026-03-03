# Rules\Hardening\NTLMv1Usage.rule.ps1
# Fires when NTLMv1 logon events are detected in DC Security logs.

@{
    Id          = 'MATI-HARD-030'
    Title       = 'NTLMv1 Authentication Detected'
    Severity    = 'Critical'
    Description = 'NTLMv1 logon events were observed in the Security event logs of the domain controllers. ' +
                  'NTLMv1 is cryptographically broken (DES-based challenge/response) and can be cracked in seconds. ' +
                  'It should be disabled immediately via LmCompatibilityLevel >= 3.'
    Remediation = 'Set LmCompatibilityLevel = 5 (Send NTLMv2 response only, refuse LM & NTLM) on all machines via GPO: ' +
                  'Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > ' +
                  '"Network security: LAN Manager authentication level". Identify NTLMv1 sources from the top accounts/IPs ' +
                  'and remediate before enforcement.'
    Collectors  = @('LegacyProtocolAudit','DomainInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level'
    )

    Condition = {
        param($Data, $Config)
        $domainDns = $Data['DomainInfo'].Forest.RootDomain
        $audit = $Data['LegacyProtocolAudit']
        if (-not $audit -or -not $audit.NTLM) { return $null }

        $ntlm = $audit.NTLM

        $findings = [System.Collections.Generic.List[hashtable]]::new()

        # NTLMv1 finding (Critical)
        if ($ntlm.NTLMv1Count -gt 0) {
            $findings.Add(@{
                Severity    = 'Critical'
                Description = "Over the last $($audit.AuditHours) hours, $($ntlm.NTLMv1Count) NTLMv1 logon events were detected " +
                              "($($ntlm.NTLMv1Percent)% of all NTLM). NTLMv1 is trivially crackable and must be eliminated."
                Domain      = $domainDns
                Details     = @{
                    'NTLMv1 events'        = $ntlm.NTLMv1Count
                    'NTLMv2 events'        = $ntlm.NTLMv2Count
                    'Total NTLM events'    = $ntlm.TotalEvents
                    'NTLMv1 %'             = "$($ntlm.NTLMv1Percent)%"
                    'Audit window (hours)' = $audit.AuditHours
                }
            })

            # Per top NTLMv1 source account
            foreach ($acct in $ntlm.TopAccounts | Select-Object -First 10) {
                $findings.Add(@{
                    Severity    = 'High'
                    Description = "Account '$($acct.Name)' generated $($acct.Count) NTLM logon event(s). " +
                                  "Investigate the source workstation and application to eliminate NTLM dependency."
                    ObjectDN    = $acct.Name
                    Domain      = $domainDns
                    Details     = @{ 'Account' = $acct.Name; 'NTLM events' = $acct.Count }
                })
            }
        }

        # NTLMv2-only (informational awareness if volume is high)
        if ($ntlm.NTLMv1Count -eq 0 -and $ntlm.NTLMv2Count -gt 0) {
            $findings.Add(@{
                Severity    = 'Medium'
                Description = "Over the last $($audit.AuditHours) hours, $($ntlm.NTLMv2Count) NTLMv2 logon events were detected. " +
                              "No NTLMv1, but NTLM remains a legacy protocol. Consider migrating to Kerberos where possible."
                Domain      = $domainDns
                Details     = @{
                    'NTLMv2 events'        = $ntlm.NTLMv2Count
                    'Total NTLM events'    = $ntlm.TotalEvents
                    'Audit window (hours)' = $audit.AuditHours
                }
            })
        }

        if ($findings.Count -gt 0) { return $findings }
        return $null
    }
}

# Rules\Hardening\NTLMv1Allowed.rule.ps1
# Flags DCs where NTLMv1 is allowed (LmCompatibilityLevel < 5).

@{
    Id          = 'MATI-HARD-021'
    Title       = 'NTLMv1 authentication allowed on Domain Controller'
    Severity    = 'Critical'
    Description = "One or more Domain Controllers allow NTLMv1 authentication (LmCompatibilityLevel < 5). NTLMv1 responses can be cracked offline in seconds, enabling credential theft."
    Remediation = "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only. Refuse LM & NTLM) on all DCs via GPO: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options > Network security: LAN Manager authentication level."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: A-NTLMv1', 'ANSSI: vuln_ntlmv1')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # LmCompatibilityLevel: 0-5. Best practice = 5 (NTLMv2 only, refuse LM/NTLM)
            # Anything < 3 allows NTLMv1 responses
            if ($null -eq $dc.NTLMLevel -or $dc.NTLMLevel -lt 3) {
                $sev = if ($null -eq $dc.NTLMLevel -or $dc.NTLMLevel -lt 2) { 'Critical' } else { 'High' }
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Severity = $sev
                    Details  = @{
                        DCName              = $dc.DCName
                        LmCompatibilityLevel = switch ($dc.NTLMLevel) {
                            0 { '0 - Send LM & NTLM responses' }
                            1 { '1 - Send LM & NTLM, use NTLMv2 session if negotiated' }
                            2 { '2 - Send NTLM response only' }
                            $null { 'Not configured (default: 3 on DCs)' }
                            default { "$($dc.NTLMLevel)" }
                        }
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\Hardening\CredentialGuardNotEnabled.rule.ps1
# Flags DCs where Credential Guard is enabled — Microsoft explicitly recommends AGAINST it on DCs.
# Credential Guard should be deployed on PAWs and member servers, NOT on Domain Controllers.

@{
    Id          = 'MATI-HARD-032'
    Title       = 'Credential Guard enabled on Domain Controller (not recommended)'
    Severity    = 'Medium'
    Description = "Credential Guard is enabled on a Domain Controller. Microsoft explicitly states: 'Enabling Credential Guard on domain controllers is not recommended. Credential Guard does not provide any added security to domain controllers, and can cause application compatibility issues on domain controllers.' Credential Guard should be deployed on PAWs, member servers, and workstations instead."
    Remediation = "Disable Credential Guard on Domain Controllers. Deploy it instead on PAWs (Tier 0/1/2) and member servers where it provides actual value. On DCs, rely on LSASS Protected Mode (RunAsPPL) and Protected Users group to mitigate credential theft."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/'
        'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-known-issues'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # LsaCfgFlags: 0 or $null = not enabled, 1 = enabled with UEFI lock, 2 = enabled without lock
            if ($dc.CredentialGuard -and $dc.CredentialGuard -ne 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.DCName
                        CredentialGuard = switch ($dc.CredentialGuard) {
                            1       { 'Enabled with UEFI lock' }
                            2       { 'Enabled without UEFI lock' }
                            default { "Enabled (value: $($dc.CredentialGuard))" }
                        }
                        Warning         = 'Microsoft recommends NOT enabling Credential Guard on DCs'
                    }
                }
            }
        }
        return $findings
    }
}

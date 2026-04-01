# Rules\Hardening\CredentialGuardEnabledOnDC.rule.ps1
# Flags DCs where Credential Guard is enabled.
# Microsoft explicitly states that enabling Credential Guard on domain controllers is not recommended.

@{
    Id          = 'MATI-HARD-032'
    Title       = 'Credential Guard enabled on Domain Controller'
    Severity    = 'Medium'
    Description = "Credential Guard is enabled on a Domain Controller. Microsoft explicitly states that enabling Credential Guard on domain controllers is not recommended because it doesn't provide added security on DCs and can cause application compatibility issues."
    Remediation = "Disable Credential Guard on Domain Controllers. Keep Credential Guard for PAWs, workstations, and member servers where it provides value. On DCs, rely instead on controls such as LSASS protection (RunAsPPL), Protected Users, hardened delegation, and strong audit coverage."
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
                        DCName               = $dc.DCName
                        VbsEnabled           = switch ($dc.VbsEnabled) {
                            1       { 'Yes' }
                            0       { 'No' }
                            $null   { 'Unknown' }
                            default { "$($dc.VbsEnabled)" }
                        }
                        CredentialGuard      = switch ($dc.CredentialGuard) {
                            1       { 'Enabled with UEFI lock' }
                            2       { 'Enabled without UEFI lock' }
                            default { "Enabled (value: $($dc.CredentialGuard))" }
                        }
                        Recommendation       = 'Microsoft recommends not enabling Credential Guard on Domain Controllers'
                    }
                }
            }
        }
        return $findings
    }
}
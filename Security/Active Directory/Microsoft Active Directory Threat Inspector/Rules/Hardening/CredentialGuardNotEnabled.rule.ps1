# Rules\Hardening\CredentialGuardNotEnabled.rule.ps1
# Flags DCs where Credential Guard (VBS-based credential isolation) is not enabled.

@{
    Id          = 'MATI-HARD-032'
    Title       = 'Credential Guard not enabled on Domain Controller'
    Severity    = 'High'
    Description = "Credential Guard is not enabled on a Domain Controller. Credential Guard uses Virtualization-Based Security (VBS) to isolate NTLM hashes, Kerberos TGTs, and other credentials in a protected container inaccessible to LSASS. Without it, credential theft tools like Mimikatz can extract secrets from LSASS memory."
    Remediation = "Enable Credential Guard via GPO: Computer Configuration > Policies > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security > Credential Guard Configuration = Enabled with UEFI lock. Prerequisites: UEFI firmware, Secure Boot, TPM 2.0, and VBS-compatible CPU."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure'
        'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # LsaCfgFlags: 0 or $null = not enabled, 1 = enabled with UEFI lock, 2 = enabled without lock
            if ($null -eq $dc.CredentialGuard -or $dc.CredentialGuard -eq 0) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName          = $dc.DCName
                        CredentialGuard = switch ($dc.CredentialGuard) {
                            0       { 'Disabled' }
                            $null   { 'Not configured (disabled)' }
                            default { $dc.CredentialGuard }
                        }
                    }
                }
            }
        }
        return $findings
    }
}

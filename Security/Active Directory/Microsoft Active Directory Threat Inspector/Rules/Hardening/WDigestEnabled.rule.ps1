# Rules\Hardening\WDigestEnabled.rule.ps1
# Flags DCs where WDigest authentication stores plaintext credentials in memory.

@{
    Id          = 'MATI-HARD-031'
    Title       = 'WDigest authentication enabled on Domain Controller'
    Severity    = 'Critical'
    Description = "WDigest authentication is enabled on a Domain Controller (UseLogonCredential = 1). When WDigest is enabled, LSASS stores plaintext copies of user passwords in memory, making them trivially extractable with tools like Mimikatz. On Windows Server 2012 R2+ WDigest is disabled by default, but it can be re-enabled via registry."
    Remediation = "Set the registry value UseLogonCredential to 0 via GPO: HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0 (DWORD). This is the default on Server 2012 R2+ but should be explicitly enforced."
    Collectors  = @('ProtocolConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn785165(v=ws.11)'
        'https://blog.stealthbits.com/wdigest-clear-text-passwords-stealing-more-than-a-hash/'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # UseLogonCredential: 1 = WDigest storing plaintext in LSASS
            if ($dc.WDigestEnabled -eq 1) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName            = $dc.DCName
                        UseLogonCredential = '1 (Enabled - plaintext passwords in LSASS)'
                    }
                }
            }
        }
        return $findings
    }
}

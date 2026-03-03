# Rules\Hardening\TLSHardening.rule.ps1
# Flags DCs where legacy TLS (1.0/1.1) is not disabled or TLS 1.2 not explicitly enabled.

@{
    Id          = 'MATI-HARD-028'
    Title       = 'Legacy TLS protocols not disabled on Domain Controller'
    Severity    = 'Medium'
    Description = "This Domain Controller has not explicitly disabled legacy TLS protocols (TLS 1.0/1.1) or has not enabled TLS 1.2 in the Schannel registry. Legacy TLS protocols are vulnerable to BEAST, POODLE, and other attacks."
    Remediation = "Disable TLS 1.0 and TLS 1.1 in HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server (Enabled=0, DisabledByDefault=1) and similarly for TLS 1.1. Ensure TLS 1.2 Server has Enabled=1 and DisabledByDefault=0. Also set .NET Strong Crypto: HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 SchUseStrongCrypto=1 and SystemDefaultTlsVersions=1."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: A-TLSLegacy', 'Blog: TLS/SSL Schannel and .NET Strong Crypto Hardening')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in @($Data.ProtocolConfig.DCProtocolSettings)) {
            if (-not $dc.WinRMAccessible) { continue }
            if (-not $dc.TLS) { continue }

            $issues = @()
            $tls = $dc.TLS

            # Check TLS 1.0 Server: Enabled should be 0 or DisabledByDefault should be 1
            if ($tls.TLS10_Enabled -ne 0) {
                $issues += "TLS 1.0 not disabled (Enabled=$($tls.TLS10_Enabled))"
            }
            # Check TLS 1.1 Server
            if ($tls.TLS11_Enabled -ne 0) {
                $issues += "TLS 1.1 not disabled (Enabled=$($tls.TLS11_Enabled))"
            }
            # Check TLS 1.2 Server: Enabled should be 1 (or null=OS default usually OK on modern OS)
            if ($null -ne $tls.TLS12_Enabled -and $tls.TLS12_Enabled -eq 0) {
                $issues += "TLS 1.2 explicitly disabled!"
            }
            # .NET Strong Crypto
            if ($tls.DotNetStrongCrypto -ne 1) {
                $issues += "SchUseStrongCrypto not set (.NET may fall back to TLS 1.0)"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $dc.DCName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName = $dc.DCName
                        FQDN   = $dc.HostName
                        Issues = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}

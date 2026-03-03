# Rules\Hardening\NetSessionEnum.rule.ps1
# Flags DCs where SrvsvcSessionInfo is not hardened (NetCease-style).

@{
    Id          = 'MATI-HARD-027'
    Title       = 'Net session enumeration not restricted on Domain Controller'
    Severity    = 'Medium'
    Description = "The SrvsvcSessionInfo security descriptor on this Domain Controller has not been hardened. Any authenticated user can enumerate active SMB sessions via NetSessionEnum, enabling reconnaissance of privileged logon sessions for lateral movement."
    Remediation = "Apply NetCease-style hardening by replacing the SrvsvcSessionInfo security descriptor in HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity to remove Authenticated Users access. Restart the LanmanServer service after the change."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: S-NetSessionEnum', 'Blog: Hardening Net Session Enumeration on Domain Controllers')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($dc in @($Data.ProtocolConfig.DCProtocolSettings)) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($dc.NetSessionHardened -ne $true) {
                $findings += @{
                    ObjectDN = $dc.DCName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName = $dc.DCName
                        FQDN   = $dc.HostName
                        NetSessionHardened = if ($null -eq $dc.NetSessionHardened) { 'Unknown (could not read)' } else { 'No' }
                    }
                }
            }
        }
        return $findings
    }
}

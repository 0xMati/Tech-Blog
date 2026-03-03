# Rules\Hardening\LDAPChannelBindingNotRequired.rule.ps1
# Flags DCs where LDAP channel binding is not enforced.

@{
    Id          = 'MATI-HARD-019'
    Title       = 'LDAP channel binding not enforced on Domain Controller'
    Severity    = 'High'
    Description = "LDAP channel binding (EPA) is not enforced on one or more Domain Controllers. This allows NTLM relay attacks against LDAP/LDAPS endpoints."
    Remediation = "Set LdapEnforceChannelBinding to 2 (Always) on all DCs via GPO or registry: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 2."
    Collectors  = @('ProtocolConfig')
    References  = @('PingCastle: A-LDAPChannelBinding', 'ANSSI: vuln_ldap_channel_binding')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            if ($null -eq $dc.LDAPChannelBinding -or $dc.LDAPChannelBinding -lt 2) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName              = $dc.DCName
                        LDAPChannelBinding  = switch ($dc.LDAPChannelBinding) {
                            0 { 'Never' }
                            1 { 'When Supported' }
                            $null { 'Not configured (default: Never)' }
                            default { $dc.LDAPChannelBinding }
                        }
                    }
                }
            }
        }
        return $findings
    }
}

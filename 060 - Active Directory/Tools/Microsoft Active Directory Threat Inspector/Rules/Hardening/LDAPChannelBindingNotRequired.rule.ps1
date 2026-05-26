# Rules\Hardening\LDAPChannelBindingNotRequired.rule.ps1
# Flags DCs where LDAP channel binding is not enforced.

@{
    Id          = 'MATI-HARD-019'
    Title       = 'LDAP channel binding not enforced on Domain Controller'
    Severity    = 'High'
    Description = "LDAP channel binding is validated from the effective registry value on each Domain Controller. A DC where the registry value cannot be read is treated as an important verification gap, and a missing value is treated as not enforced unless proven otherwise because the effective default is not 'Always'."
    Remediation = "Set LdapEnforceChannelBinding to 2 (Always) on all DCs via GPO or registry: HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 2."
    Collectors  = @('ProtocolConfig')
    References  = @('https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) {
                $findings += @{
                    Severity = 'High'
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName            = $dc.DCName
                        RegistryPath      = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
                        EvaluationStatus  = 'Could not evaluate via WinRM'
                    }
                }
                continue
            }

            if ($null -eq $dc.LDAPChannelBinding) {
                $findings += @{
                    Severity = 'High'
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName             = $dc.DCName
                        RegistryPath       = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding'
                        LDAPChannelBinding = 'Not configured in local registry'
                        EvaluationStatus   = 'Treat as not enforced until verified otherwise'
                    }
                }
                continue
            }

            if ($dc.LDAPChannelBinding -lt 2) {
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

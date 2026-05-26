# Rules\Hardening\LDAPSigningNotRequired.rule.ps1
# Flags DCs where LDAP signing is not required.

@{
    Id          = 'MATI-HARD-018'
    Title       = 'LDAP signing not required on Domain Controller'
    Severity    = 'High'
    Description = "LDAP signing is validated from the effective registry value on each Domain Controller. A DC where the registry value cannot be read is treated as an important verification gap, and a missing value is treated as not enforced unless proven otherwise because the effective default is not 'Require signing'."
    Remediation = "Set the registry value LDAPServerIntegrity to 2 (Require signing) on all DCs via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements = Require signing."
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
                        RegistryPath      = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
                        EvaluationStatus  = 'Could not evaluate via WinRM'
                    }
                }
                continue
            }

            # LDAPServerIntegrity: 0=None, 1=Negotiated (default), 2=Required
            if ($null -eq $dc.LDAPServerSigning) {
                $findings += @{
                    Severity = 'High'
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName            = $dc.DCName
                        RegistryPath      = 'HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
                        LDAPServerSigning = 'Not configured in local registry'
                        EvaluationStatus  = 'Treat as not enforced until verified otherwise'
                    }
                }
                continue
            }

            if ($dc.LDAPServerSigning -lt 2) {
                $findings += @{
                    ObjectDN = $dc.HostName
                    Domain   = $dc.Domain
                    Details  = @{
                        DCName           = $dc.DCName
                        LDAPServerSigning = switch ($dc.LDAPServerSigning) {
                            0 { 'None' }
                            1 { 'Negotiated (not enforced)' }
                            $null { 'Not configured (default: Negotiated)' }
                            default { $dc.LDAPServerSigning }
                        }
                    }
                }
            }
        }
        return $findings
    }
}

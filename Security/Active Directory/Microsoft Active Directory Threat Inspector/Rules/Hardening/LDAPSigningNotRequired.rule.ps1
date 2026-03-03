# Rules\Hardening\LDAPSigningNotRequired.rule.ps1
# Flags DCs where LDAP signing is not required.

@{
    Id          = 'MATI-HARD-018'
    Title       = 'LDAP signing not required on Domain Controller'
    Severity    = 'High'
    Description = "LDAP signing is not enforced on one or more Domain Controllers. Without LDAP signing, an attacker can perform man-in-the-middle attacks on LDAP connections and relay NTLM authentication."
    Remediation = "Set the registry value LDAPServerIntegrity to 2 (Require signing) on all DCs via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Domain controller: LDAP server signing requirements = Require signing."
    Collectors  = @('ProtocolConfig')
    References  = @('https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($dc in $Data.ProtocolConfig.DCProtocolSettings) {
            if (-not $dc.WinRMAccessible) { continue }
            # LDAPServerIntegrity: 0=None, 1=Negotiated (default), 2=Required
            if ($null -eq $dc.LDAPServerSigning -or $dc.LDAPServerSigning -lt 2) {
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

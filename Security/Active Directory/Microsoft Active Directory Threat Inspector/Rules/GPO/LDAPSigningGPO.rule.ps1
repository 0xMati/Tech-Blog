# Rules\GPO\LDAPSigningGPO.rule.ps1
# Flags domains where LDAP signing is not required via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-006'
    Title       = 'LDAP signing not required via GPO on Domain Controllers'
    Severity    = 'High'
    Description = "LDAP server signing is not set to 'Require signing' via GPO on Domain Controllers. Without requiring LDAP signing, attackers can intercept and modify LDAP traffic via man-in-the-middle attacks, potentially modifying directory data or relaying credentials."
    Remediation = "Configure GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > 'Domain controller: LDAP server signing requirements' = 'Require signing'. This sets the registry value HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity to 2."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $found = $false
            $currentValue = $null

            # Check SecurityOptions for LDAPServerIntegrity
            if ($domainData.SecurityOptions) {
                foreach ($key in $domainData.SecurityOptions.Keys) {
                    if ($key -like '*NTDS\Parameters\LDAPServerIntegrity*') {
                        $value = $domainData.SecurityOptions[$key]
                        if ($value -match ',(\d+)') {
                            $currentValue = [int]$Matches[1]
                            if ($currentValue -eq 2) { $found = $true }
                        }
                        break
                    }
                }
            }

            # Also check RegistryPolicies
            if (-not $found) {
                $regMatch = $domainData.RegistryPolicies | Where-Object {
                    $_.Key -like '*NTDS\Parameters' -and $_.ValueName -eq 'LDAPServerIntegrity' -and $_.Data -eq 2
                }
                if ($regMatch) { $found = $true }
            }

            if (-not $found) {
                $details = @{
                    Issue       = "LDAP server signing not set to 'Require signing' (2)"
                    ExpectedKey = 'MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity'
                    ExpectedValue = '2 (Require signing)'
                }
                if ($null -ne $currentValue) {
                    $details['CurrentValue'] = "$currentValue"
                }
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = $details
                }
            }
        }
        return $findings
    }
}

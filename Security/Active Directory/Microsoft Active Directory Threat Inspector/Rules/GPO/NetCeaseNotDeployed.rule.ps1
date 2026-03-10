# Rules\GPO\NetCeaseNotDeployed.rule.ps1
# Flags domains where NetCease (NetSession hardening) is not deployed via GPO.

@{
    Id          = 'MATI-GPO-015'
    Title       = 'NetCease (NetSession hardening) not deployed via GPO'
    Severity    = 'Medium'
    Description = "The NetCease hardening (SrvsvcSessionInfo permission restriction) is not deployed via GPO on Domain Controllers. By default, any authenticated user can enumerate active sessions on DCs via NetSessionEnum, exposing which privileged users are logged on where, enabling targeted attacks."
    Remediation = "Deploy NetCease by configuring the SrvsvcSessionInfo registry value under HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity via GPO. This restricts NetSessionEnum to admins only. See Sa-Int NetCease tool for the exact binary value."
    Collectors  = @('GPOSettings')
    References  = @('https://github.com/p0w3rsh3ll/NetCease')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $netCease = $registryPolicies | Where-Object {
                $_.Key -like '*LanmanServer\DefaultSecurity*' -and
                $_.ValueName -eq 'SrvsvcSessionInfo'
            }

            if (-not $netCease) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = "SrvsvcSessionInfo not configured via GPO (NetCease not deployed)"
                        ExpectedKey   = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\SrvsvcSessionInfo'
                        ExpectedValue = 'Custom SDDL restricting NetSessionEnum to admins'
                    }
                }
            }
        }
        return $findings
    }
}

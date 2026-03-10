# Rules\GPO\HardenedUNCPaths.rule.ps1
# Flags domains where hardened UNC paths are not configured via GPO for SYSVOL and NETLOGON.

@{
    Id          = 'MATI-GPO-012'
    Title       = 'Hardened UNC paths not configured via GPO'
    Severity    = 'High'
    Description = "Hardened UNC paths are not configured via GPO for SYSVOL and NETLOGON shares. Without hardened UNC paths, attackers can perform man-in-the-middle attacks to modify Group Policy files or logon scripts in transit, achieving remote code execution on domain-joined machines."
    Remediation = "Deploy a GPO setting hardened UNC paths under HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths. Set \\*\SYSVOL = RequireMutualAuthentication=1,RequireIntegrity=1 and \\*\NETLOGON = RequireMutualAuthentication=1,RequireIntegrity=1."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/security-updates/SecurityAdvisories/2015/3004375')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $hardenedPaths = $registryPolicies | Where-Object {
                $_.Key -like '*NetworkProvider\HardenedPaths*'
            }

            $issues = @()

            # Check SYSVOL
            $sysvol = $hardenedPaths | Where-Object {
                $_.ValueName -like '*SYSVOL*' -and
                $_.Data -like '*RequireMutualAuthentication=1*' -and
                $_.Data -like '*RequireIntegrity=1*'
            }
            if (-not $sysvol) {
                $issues += "SYSVOL hardened UNC path not configured or incomplete"
            }

            # Check NETLOGON
            $netlogon = $hardenedPaths | Where-Object {
                $_.ValueName -like '*NETLOGON*' -and
                $_.Data -like '*RequireMutualAuthentication=1*' -and
                $_.Data -like '*RequireIntegrity=1*'
            }
            if (-not $netlogon) {
                $issues += "NETLOGON hardened UNC path not configured or incomplete"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = ($issues -join '; ')
                        ExpectedKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
                        ExpectedValue = '\\*\SYSVOL and \\*\NETLOGON = RequireMutualAuthentication=1,RequireIntegrity=1'
                    }
                }
            }
        }
        return $findings
    }
}

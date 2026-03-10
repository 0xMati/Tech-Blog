# Rules\GPO\SpoolerOnDC.rule.ps1
# Flags domains where the Print Spooler service is not disabled via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-005'
    Title       = 'Print Spooler not disabled via GPO on Domain Controllers'
    Severity    = 'High'
    Description = "The Print Spooler service is not disabled via GPO on Domain Controllers. The Spooler service has been the target of multiple critical vulnerabilities (PrintNightmare CVE-2021-34527, CVE-2021-1675) enabling remote code execution and privilege escalation. It also enables the printer bug relay attack for coercing DC authentication."
    Remediation = "Disable the Print Spooler service on all DCs via GPO (Service startup type = Disabled) or via the ServiceSettings section. DCs should never serve as print servers."
    Collectors  = @('GPOSettings')
    References  = @('https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]

            # Check ServiceSettings for Spooler disabled (value contains '4' = disabled)
            $spoolerDisabledViaService = $false
            if ($domainData.ServiceSettings) {
                foreach ($key in $domainData.ServiceSettings.Keys) {
                    if ($key -like 'Spooler*' -and $domainData.ServiceSettings[$key] -match '4') {
                        $spoolerDisabledViaService = $true
                        break
                    }
                }
            }

            # Check RegistryPolicies for Spooler Start=4
            $spoolerDisabledViaRegistry = $domainData.RegistryPolicies | Where-Object {
                $_.Key -eq 'SYSTEM\CurrentControlSet\Services\Spooler' -and
                $_.ValueName -eq 'Start' -and
                $_.Data -eq 4
            }

            if (-not $spoolerDisabledViaService -and -not $spoolerDisabledViaRegistry) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue = "Print Spooler service not disabled via GPO on Domain Controllers"
                        ServiceSettings = "Spooler not set to Disabled (4)"
                        RegistryPolicy  = "SYSTEM\CurrentControlSet\Services\Spooler\Start not set to 4"
                    }
                }
            }
        }
        return $findings
    }
}

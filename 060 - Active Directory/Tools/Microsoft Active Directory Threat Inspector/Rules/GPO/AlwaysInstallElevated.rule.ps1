# Rules\GPO\AlwaysInstallElevated.rule.ps1
# Flags domains where AlwaysInstallElevated is enabled via GPO (privilege escalation risk).

@{
    Id          = 'MATI-GPO-014'
    Title       = 'AlwaysInstallElevated is enabled via GPO'
    Severity    = 'Critical'
    Description = "The machine-side AlwaysInstallElevated policy is enabled in linked GPO configuration. Privilege escalation requires both machine and user policy to be enabled. Verify user policy, filtering and client RSoP before concluding exploitability."
    Remediation = "Immediately disable AlwaysInstallElevated by removing or setting to 0 the registry value HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated in all GPOs. Also check the HKCU path."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $alwaysInstallElevated = $registryPolicies | Where-Object {
                $_.Key -like '*Windows\Installer*' -and
                $_.ValueName -eq 'AlwaysInstallElevated' -and
                $_.Data -eq 1
            }

            if ($alwaysInstallElevated) {
                foreach ($match in $alwaysInstallElevated) {
                    $findings += @{
                        ObjectDN = $domainDns
                        Domain   = $domainDns
                        Details  = @{
                            Issue    = "AlwaysInstallElevated is enabled (set to 1)"
                            GPO      = $match.GPO
                            LinkedTo = $match.LinkedTo
                            Key      = $match.Key
                            AssessmentBasis = $domainData.AssessmentBasis
                            UserPolicyVerified = 'False'
                        }
                    }
                }
            }
        }
        return $findings
    }
}

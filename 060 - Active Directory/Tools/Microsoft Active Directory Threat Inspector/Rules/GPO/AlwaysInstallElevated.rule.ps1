# Rules\GPO\AlwaysInstallElevated.rule.ps1
# Flags domains where AlwaysInstallElevated is enabled via GPO (privilege escalation risk).

@{
    Id          = 'MATI-GPO-014'
    Title       = 'AlwaysInstallElevated is enabled via GPO'
    Severity    = 'Critical'
    Description = "The AlwaysInstallElevated policy is enabled via GPO, which allows any user to install MSI packages with SYSTEM-level privileges. This is a well-known privilege escalation vector that enables any low-privileged user to gain full system control by crafting a malicious MSI."
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
                        }
                    }
                }
            }
        }
        return $findings
    }
}

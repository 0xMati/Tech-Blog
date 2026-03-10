# Rules\GPO\CredentialGuardGPO.rule.ps1
# Flags domains where Credential Guard is not enabled via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-003'
    Title       = 'Credential Guard not enabled via GPO on Domain Controllers'
    Severity    = 'Medium'
    Description = "Windows Credential Guard is not enabled via GPO on Domain Controllers. Credential Guard uses virtualization-based security to isolate LSASS secrets, preventing pass-the-hash and pass-the-ticket attacks even if LSASS memory is compromised."
    Remediation = "Deploy a GPO enabling Virtualization Based Security (EnableVirtualizationBasedSecurity=1) and configuring LsaCfgFlags=1 or 2 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa. Note: not supported on all server versions - verify compatibility."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $vbs = $registryPolicies | Where-Object {
                $_.Key -eq 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -and
                $_.ValueName -eq 'EnableVirtualizationBasedSecurity' -and
                $_.Data -eq 1
            }

            if (-not $vbs) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue       = "Credential Guard (VBS) not enabled via GPO"
                        ExpectedKey = 'SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
                        ExpectedValue = '1'
                    }
                }
            }
        }
        return $findings
    }
}

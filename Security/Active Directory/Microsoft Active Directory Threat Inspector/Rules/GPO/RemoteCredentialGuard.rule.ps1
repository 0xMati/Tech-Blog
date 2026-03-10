# Rules\GPO\RemoteCredentialGuard.rule.ps1
# Flags domains where Remote Credential Guard is not enforced via GPO for RDP connections.

@{
    Id          = 'MATI-GPO-018'
    Title       = 'Restricted Admin / Remote Credential Guard not enforced via GPO'
    Severity    = 'Medium'
    Description = "Remote Credential Guard or Restricted Admin mode is not enforced via GPO for RDP connections to Domain Controllers. Without these protections, RDP credentials are exposed on the remote server's LSASS process, enabling credential theft when a DC is compromised."
    Remediation = "Deploy a GPO enabling Remote Credential Guard: HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\RestrictedRemoteAdministration = 1 (DWORD) and RestrictedRemoteAdministrationType = 2 (Remote Credential Guard)."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $remoteCredGuard = $registryPolicies | Where-Object {
                $_.Key -like '*CredentialsDelegation*' -and
                $_.ValueName -eq 'RestrictedRemoteAdministration' -and
                [int]$_.Data -ge 1
            }

            if (-not $remoteCredGuard) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = "Remote Credential Guard not enforced via GPO"
                        ExpectedKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\RestrictedRemoteAdministration'
                        ExpectedValue = '1 or higher'
                    }
                }
            }
        }
        return $findings
    }
}

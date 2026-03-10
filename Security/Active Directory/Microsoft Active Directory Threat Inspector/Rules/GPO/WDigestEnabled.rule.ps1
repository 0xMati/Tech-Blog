# Rules\GPO\WDigestEnabled.rule.ps1
# Flags domains where WDigest authentication is not explicitly disabled via GPO.

@{
    Id          = 'MATI-GPO-004'
    Title       = 'WDigest authentication not disabled via GPO'
    Severity    = 'High'
    Description = "WDigest authentication is not explicitly disabled via GPO on Domain Controllers. When WDigest is enabled, plaintext passwords are stored in LSASS memory and can be extracted by credential-dumping tools. While disabled by default on Windows Server 2012 R2+, an attacker with admin access can re-enable it without a GPO enforcing the setting."
    Remediation = "Deploy a GPO to Domain Controllers setting HKLM\SYSTEM\CurrentControlSet\SecurityProviders\WDigest\UseLogonCredential = 0 (DWORD)."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn283389(v=ws.11)')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $wdigest = $registryPolicies | Where-Object {
                $_.Key -like '*SecurityProviders\WDigest' -and
                $_.ValueName -eq 'UseLogonCredential' -and
                $_.Data -eq 0
            }

            if (-not $wdigest) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue       = "WDigest UseLogonCredential not set to 0 via GPO"
                        ExpectedKey = 'HKLM\SYSTEM\CurrentControlSet\SecurityProviders\WDigest\UseLogonCredential'
                        ExpectedValue = '0'
                    }
                }
            }
        }
        return $findings
    }
}

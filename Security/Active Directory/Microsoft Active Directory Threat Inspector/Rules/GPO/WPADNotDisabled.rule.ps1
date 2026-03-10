# Rules\GPO\WPADNotDisabled.rule.ps1
# Flags domains where WPAD is not disabled via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-011'
    Title       = 'WPAD not disabled via GPO on Domain Controllers'
    Severity    = 'Medium'
    Description = "Web Proxy Auto-Discovery (WPAD) is not disabled via GPO on Domain Controllers. WPAD allows attackers to perform man-in-the-middle attacks by setting up a rogue WPAD server, intercepting HTTP traffic, and capturing NTLM authentication credentials via automatic proxy detection."
    Remediation = "Disable WPAD by deploying a GPO setting HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\WpadOverride = 1 (DWORD) and disabling the WinHTTP Auto-Proxy Service (WinHttpAutoProxySvc startup type = 4 disabled)."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $wpadOverride = $registryPolicies | Where-Object {
                $_.Key -like '*Internet Settings\Wpad*' -and
                $_.ValueName -eq 'WpadOverride' -and
                $_.Data -eq 1
            }

            if (-not $wpadOverride) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = "WPAD WpadOverride not set to 1 via GPO"
                        ExpectedKey   = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\WpadOverride'
                        ExpectedValue = '1'
                    }
                }
            }
        }
        return $findings
    }
}

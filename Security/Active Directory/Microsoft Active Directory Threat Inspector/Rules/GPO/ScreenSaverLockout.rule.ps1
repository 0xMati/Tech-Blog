# Rules\GPO\ScreenSaverLockout.rule.ps1
# Flags domains where screen saver lockout policy is not configured via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-013'
    Title       = 'Screen saver lockout policy not configured via GPO'
    Severity    = 'Low'
    Description = "No screen saver lockout policy is configured via GPO for Domain Controllers. Without an automatic screen lock, unattended DC consoles remain accessible, allowing physical attackers or insiders to execute commands with elevated privileges."
    Remediation = "Deploy a GPO to enforce screen saver with password protection. Set ScreenSaveActive=1, ScreenSaverIsSecure=1, and ScreenSaveTimeOut to a reasonable value (e.g., 600 seconds) under User or Machine configuration."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies
            $issues = @()

            # Check ScreenSaveActive
            $screenSaveActive = $registryPolicies | Where-Object {
                $_.Key -like '*Control Panel\Desktop*' -and
                $_.ValueName -eq 'ScreenSaveActive'
            }
            if (-not $screenSaveActive -or $screenSaveActive.Data -ne '1') {
                $issues += "ScreenSaveActive=$(if ($screenSaveActive) { $screenSaveActive.Data } else { 'Not configured' }) (expected 1)"
            }

            # Check ScreenSaverIsSecure
            $screenSaverIsSecure = $registryPolicies | Where-Object {
                $_.Key -like '*Control Panel\Desktop*' -and
                $_.ValueName -eq 'ScreenSaverIsSecure'
            }
            if (-not $screenSaverIsSecure -or $screenSaverIsSecure.Data -ne '1') {
                $issues += "ScreenSaverIsSecure=$(if ($screenSaverIsSecure) { $screenSaverIsSecure.Data } else { 'Not configured' }) (expected 1)"
            }

            if ($issues.Count -gt 0) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        ScreenSaveActive   = "$(if ($screenSaveActive) { $screenSaveActive.Data } else { 'Not configured' })"
                        ScreenSaverIsSecure = "$(if ($screenSaverIsSecure) { $screenSaverIsSecure.Data } else { 'Not configured' })"
                        Issues             = ($issues -join '; ')
                    }
                }
            }
        }
        return $findings
    }
}

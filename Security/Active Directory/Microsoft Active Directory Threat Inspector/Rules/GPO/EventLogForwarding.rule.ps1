# Rules\GPO\EventLogForwarding.rule.ps1
# Flags domains where Windows Event Forwarding is not configured via GPO.

@{
    Id          = 'MATI-GPO-019'
    Title       = 'Windows Event Forwarding not configured via GPO'
    Severity    = 'Low'
    Description = "Windows Event Forwarding (WEF) is not configured via GPO to centralize security logs from Domain Controllers. Without centralized logging, security events remain isolated on individual DCs, making correlation, alerting, and incident response significantly more difficult."
    Remediation = "Configure Windows Event Forwarding via GPO: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager should contain one or more WEF collector URLs. Also ensure the Windows Event Collector service is enabled."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-event-forwarding/')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $wefConfig = $registryPolicies | Where-Object {
                $_.Key -like '*EventLog\EventForwarding*' -and
                $_.ValueName -eq 'SubscriptionManager'
            }

            if (-not $wefConfig) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = "Windows Event Forwarding SubscriptionManager not configured via GPO"
                        ExpectedKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
                        ExpectedValue = 'WEF collector URL(s)'
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\GPO\PowerShellLogging.rule.ps1
# Flags domains where PowerShell script block logging is not enabled via GPO.

@{
    Id          = 'MATI-GPO-017'
    Title       = 'PowerShell script block logging not enabled via GPO'
    Severity    = 'Medium'
    Description = "PowerShell script block logging is not enabled via GPO on Domain Controllers. Without script block logging, malicious PowerShell commands (obfuscated or not) executed during attacks leave no trace in event logs, severely limiting incident response and forensic capabilities."
    Remediation = "Deploy a GPO enabling PowerShell script block logging: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1 (DWORD). Also consider enabling module logging and transcription."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $registryPolicies = $domainData.RegistryPolicies

            $scriptBlockLogging = $registryPolicies | Where-Object {
                $_.Key -like '*PowerShell\ScriptBlockLogging*' -and
                $_.ValueName -eq 'EnableScriptBlockLogging' -and
                $_.Data -eq 1
            }

            if (-not $scriptBlockLogging) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue         = "PowerShell script block logging not enabled via GPO"
                        ExpectedKey   = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
                        ExpectedValue = '1'
                    }
                }
            }
        }
        return $findings
    }
}

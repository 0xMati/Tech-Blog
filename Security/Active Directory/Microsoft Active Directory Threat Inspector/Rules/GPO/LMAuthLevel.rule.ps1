# Rules\GPO\LMAuthLevel.rule.ps1
# Flags domains where the LAN Manager authentication level is insufficient via GPO.

@{
    Id          = 'MATI-GPO-008'
    Title       = 'LAN Manager authentication level insufficient via GPO'
    Severity    = 'High'
    Description = "The LAN Manager authentication level configured via GPO on Domain Controllers is insufficient. A level below 5 (Send NTLMv2 response only. Refuse LM & NTLM) allows legacy LM or NTLM authentication protocols which are vulnerable to relay and cracking attacks."
    Remediation = "Configure GPO: 'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM' (level 5). This sets HKLM\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel = 5."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $found = $false
            $currentLevel = $null

            # Check SecurityOptions for LmCompatibilityLevel
            if ($domainData.SecurityOptions) {
                foreach ($key in $domainData.SecurityOptions.Keys) {
                    if ($key -like '*Lsa\LmCompatibilityLevel*') {
                        $value = $domainData.SecurityOptions[$key]
                        if ($value -match ',(\d+)') {
                            $currentLevel = [int]$Matches[1]
                            if ($currentLevel -ge 5) { $found = $true }
                        }
                        break
                    }
                }
            }

            # Also check RegistryPolicies
            if (-not $found -and $null -eq $currentLevel) {
                $regMatch = $domainData.RegistryPolicies | Where-Object {
                    $_.Key -like '*Control\Lsa' -and $_.ValueName -eq 'LmCompatibilityLevel'
                }
                if ($regMatch) {
                    $currentLevel = [int]$regMatch.Data
                    if ($currentLevel -ge 5) { $found = $true }
                }
            }

            if (-not $found) {
                $details = @{
                    Issue         = "LAN Manager authentication level is below 5"
                    ExpectedKey   = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'
                    ExpectedValue = '5 (Send NTLMv2 response only. Refuse LM & NTLM)'
                }
                if ($null -ne $currentLevel) {
                    $details['CurrentLevel'] = "$currentLevel"
                } else {
                    $details['CurrentLevel'] = 'Not configured via GPO'
                }
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = $details
                }
            }
        }
        return $findings
    }
}

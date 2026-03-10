# Rules\GPO\LMHashStorageGPO.rule.ps1
# Flags domains where LM hash storage is not explicitly disabled via GPO.

@{
    Id          = 'MATI-GPO-016'
    Title       = 'LM hash storage not disabled via GPO'
    Severity    = 'High'
    Description = "LM hash storage is not explicitly disabled via GPO on Domain Controllers. LM hashes are an extremely weak password representation that can be cracked in seconds. While disabled by default on modern Windows, explicitly enforcing NoLMHash=1 via GPO prevents re-enabling."
    Remediation = "Configure GPO: 'Network security: Do not store LAN Manager hash value on next password change' = Enabled. This sets HKLM\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1 via the security options in GptTmpl.inf."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $found = $false
            $currentValue = $null

            # Check SecurityOptions for NoLMHash
            if ($domainData.SecurityOptions) {
                foreach ($key in $domainData.SecurityOptions.Keys) {
                    if ($key -like '*Lsa\NoLMHash*') {
                        $value = $domainData.SecurityOptions[$key]
                        if ($value -match ',(\d+)') {
                            $currentValue = [int]$Matches[1]
                            if ($currentValue -eq 1) { $found = $true }
                        }
                        break
                    }
                }
            }

            # Also check RegistryPolicies
            if (-not $found -and $null -eq $currentValue) {
                $regMatch = $domainData.RegistryPolicies | Where-Object {
                    $_.Key -like '*Control\Lsa' -and $_.ValueName -eq 'NoLMHash'
                }
                if ($regMatch) {
                    $currentValue = [int]$regMatch.Data
                    if ($currentValue -eq 1) { $found = $true }
                }
            }

            if (-not $found) {
                $details = @{
                    Issue         = "LM hash storage not disabled via GPO"
                    ExpectedKey   = 'MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash'
                    ExpectedValue = '4,1'
                }
                if ($null -ne $currentValue) {
                    $details['CurrentValue'] = "$currentValue"
                } else {
                    $details['CurrentValue'] = 'Not configured via GPO'
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

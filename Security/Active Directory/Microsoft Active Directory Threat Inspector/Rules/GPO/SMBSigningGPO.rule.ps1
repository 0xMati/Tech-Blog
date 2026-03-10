# Rules\GPO\SMBSigningGPO.rule.ps1
# Flags domains where SMB signing is not required via GPO on Domain Controllers.

@{
    Id          = 'MATI-GPO-007'
    Title       = 'SMB signing not required via GPO on Domain Controllers'
    Severity    = 'High'
    Description = "SMB server signing is not enforced via GPO on Domain Controllers. Without required SMB signing, attackers can perform relay attacks (NTLM relay) to authenticate to SMB services on DCs, potentially gaining administrative access."
    Remediation = "Configure GPO: 'Microsoft network server: Digitally sign communications (always)' = Enabled. This sets HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature = 1."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $found = $false
            $currentValue = $null

            # Check SecurityOptions for RequireSecuritySignature
            if ($domainData.SecurityOptions) {
                foreach ($key in $domainData.SecurityOptions.Keys) {
                    if ($key -like '*LanManServer\Parameters\RequireSecuritySignature*') {
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
            if (-not $found) {
                $regMatch = $domainData.RegistryPolicies | Where-Object {
                    $_.Key -like '*LanManServer\Parameters' -and
                    $_.ValueName -eq 'RequireSecuritySignature' -and
                    $_.Data -eq 1
                }
                if ($regMatch) { $found = $true }
            }

            if (-not $found) {
                $details = @{
                    Issue       = "SMB server signing not required via GPO"
                    ExpectedKey = 'MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature'
                    ExpectedValue = '1 (Enabled)'
                }
                if ($null -ne $currentValue) {
                    $details['CurrentValue'] = "$currentValue"
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

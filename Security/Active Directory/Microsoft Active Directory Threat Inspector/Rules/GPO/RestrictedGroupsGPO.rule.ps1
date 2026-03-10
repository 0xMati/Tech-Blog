# Rules\GPO\RestrictedGroupsGPO.rule.ps1
# Flags domains where Restricted Groups policy is not configured for privileged groups.

@{
    Id          = 'MATI-GPO-020'
    Title       = 'Restricted Groups policy not configured for privileged groups'
    Severity    = 'Medium'
    Description = "The Restricted Groups policy or Preferences-based group management is not configured via GPO for the built-in Administrators group on Domain Controllers. Without Restricted Groups, unauthorized accounts added to privileged local groups persist indefinitely without detection or automatic removal."
    Remediation = "Configure Restricted Groups via GPO to control membership of the built-in Administrators group on DCs. Define the allowed members explicitly using either Security Settings > Restricted Groups or Group Policy Preferences > Local Users and Groups."
    Collectors  = @('GPOSettings')
    References  = @('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restricted-groups')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($domainDns in $Data.GPOSettings.PerDomain.Keys) {
            $domainData = $Data.GPOSettings.PerDomain[$domainDns]
            $hasRestrictedGroups = $false

            # Check RestrictedGroups from GptTmpl.inf [Group Membership] section
            if ($domainData.RestrictedGroups -and $domainData.RestrictedGroups.Count -gt 0) {
                $hasRestrictedGroups = $true
            }

            # Also check RegistryPolicies for Group Policy Preferences local group management
            if (-not $hasRestrictedGroups) {
                $gppLocalGroups = $domainData.RegistryPolicies | Where-Object {
                    $_.Key -like '*Group Policy\Local Group*'
                }
                if ($gppLocalGroups) {
                    $hasRestrictedGroups = $true
                }
            }

            if (-not $hasRestrictedGroups) {
                $findings += @{
                    ObjectDN = $domainDns
                    Domain   = $domainDns
                    Details  = @{
                        Issue       = "No Restricted Groups or GPP local group policy configured"
                        Expected    = 'At least one Restricted Groups entry or GPP local group configuration for privileged groups'
                        RestrictedGroupEntries = '0'
                    }
                }
            }
        }
        return $findings
    }
}

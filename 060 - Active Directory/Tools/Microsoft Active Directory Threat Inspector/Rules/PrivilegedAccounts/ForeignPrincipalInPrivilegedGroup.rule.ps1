# Rules\PrivilegedAccounts\ForeignPrincipalInPrivilegedGroup.rule.ps1
# Flags foreign security principals directly added to privileged groups.

@{
    Id          = 'MATI-ADMIN-018'
    Title       = 'Foreign security principal directly in privileged group'
    Severity    = 'High'
    Description = "A privileged group contains a direct foreignSecurityPrincipal member. This usually indicates a cross-forest or external-trust principal has been granted privileged access inside the domain. Such placements deserve explicit review because they create trust-path exposure in Tier 0 groups."
    Remediation = "Review each foreign principal in privileged groups. Remove unnecessary external memberships and replace them with narrowly scoped delegated access where possible."
    Collectors  = @('PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            foreach ($member in @($group.DirectMemberDetails)) {
                if (-not $member.IsForeignSecurityPrincipal) { continue }

                $key = "$($group.DistinguishedName)|$($member.DistinguishedName)"
                if (-not $seen.Add($key)) { continue }

                $findings += @{
                    ObjectDN = $member.DistinguishedName
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName       = $group.GroupName
                        GroupDomain     = $group.Domain
                        ForeignPrincipal = ($member.Name ?? $member.SID)
                    }
                }
            }
        }

        return $findings
    }
}
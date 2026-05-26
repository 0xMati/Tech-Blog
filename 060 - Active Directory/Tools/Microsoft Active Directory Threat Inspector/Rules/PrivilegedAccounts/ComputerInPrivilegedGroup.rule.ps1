# Rules\PrivilegedAccounts\ComputerInPrivilegedGroup.rule.ps1
# Flags computer objects that are members of privileged groups.

@{
    Id          = 'MATI-ADMIN-017'
    Title       = 'Computer object in privileged group'
    Severity    = 'Critical'
    Description = "A computer object is a direct or nested member of a privileged administrative group. Machine accounts are frequently exposed through host compromise, delegation abuse, ticket theft, or certificate misuse. Placing them in privileged groups creates a direct path to Tier 0 compromise."
    Remediation = "Remove computer objects from privileged groups. Grant required rights through scoped delegation, gMSA design, or resource ACLs instead of broad admin group membership."
    Collectors  = @('PrivilegedAccounts')
    References  = @('https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            foreach ($member in @($group.MemberDetails)) {
                if ($member.ObjectClass -ne 'computer') { continue }

                $key = "$($group.DistinguishedName)|$($member.DistinguishedName)"
                if (-not $seen.Add($key)) { continue }

                $findings += @{
                    ObjectDN = $member.DistinguishedName
                    Domain   = $member.Domain
                    Details  = @{
                        ComputerName     = ($member.SamAccountName ?? $member.Name)
                        GroupName        = $group.GroupName
                        GroupDomain      = $group.Domain
                        MembershipScope  = 'Recursive'
                    }
                }
            }
        }

        return $findings
    }
}
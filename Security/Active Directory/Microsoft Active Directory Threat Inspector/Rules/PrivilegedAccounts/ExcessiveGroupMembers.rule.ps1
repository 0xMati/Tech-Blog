# Rules\PrivilegedAccounts\ExcessiveGroupMembers.rule.ps1
# Flags privileged groups with too many members.

@{
    Id          = 'MATI-ADMIN-004'
    Title       = 'Privileged group with too many members'
    Severity    = 'High'
    Description = "A privileged group contains more members than the recommended threshold. Too many privileged accounts significantly increase the attack surface and make access tracking difficult."
    Remediation = "Reduce the number of members in privileged groups to the strict minimum required. Implement a least-privilege model with JIT (Just-In-Time) access if possible."
    Collectors  = @('PrivilegedAccounts')
    Condition   = {
        param($Data, $Config)
        $maxMembers = $Config.Thresholds.PrivilegedGroupMaxMembers
        $findings = @()

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            $threshold = $maxMembers[$group.GroupName]
            if (-not $threshold) { continue }

            if ($group.MemberCount -gt $threshold) {
                $findings += @{
                    ObjectDN = $group.DistinguishedName
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName    = $group.GroupName
                        MemberCount  = "$($group.MemberCount)"
                        MaxAllowed   = "$threshold"
                    }
                }
            }
        }
        return $findings
    }
}

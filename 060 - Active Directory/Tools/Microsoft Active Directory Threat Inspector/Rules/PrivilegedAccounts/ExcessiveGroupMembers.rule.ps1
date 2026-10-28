# Rules\PrivilegedAccounts\ExcessiveGroupMembers.rule.ps1
# Flags privileged groups with too many members.

@{
    Id          = 'MATI-ADMIN-004'
    Category    = 'Governance'
    Title       = 'Privileged group with too many members'
    Severity    = 'High'
    Description = "A privileged group contains more members than the recommended threshold. Too many privileged accounts significantly increase the attack surface and make access tracking difficult."
    Remediation = "Reduce the number of members in privileged groups to the strict minimum required. Implement a least-privilege model with JIT (Just-In-Time) access if possible."
    Collectors  = @('PrivilegedAccounts')
    CollectorDatasets = @{ PrivilegedAccounts = {
        param($Config)
        @($Config.Thresholds.PrivilegedGroupMaxMembers.Keys | ForEach-Object { "Groups/Recursive/$_" })
    } }
    Condition   = {
        param($Data, $Config)
        $maxMembers = $Config.Thresholds.PrivilegedGroupMaxMembers
        $findings = @()

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            $groupKey = Get-MATIPrivilegedGroupKey -Group $group
            if (-not $maxMembers.ContainsKey($groupKey)) { continue }
            $threshold = $maxMembers[$groupKey]
            $memberCount = if ($null -ne $group.MemberCount) { $group.MemberCount } else { $group.KnownMemberCount }

            if ($memberCount -gt $threshold) {
                $findings += @{
                    ObjectDN = $group.DistinguishedName
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName    = $group.GroupName
                        MemberCount  = if ($null -ne $group.MemberCount) { "$memberCount" }
                            elseif ($group.ExternalPrincipalCount -and $group.MembershipComplete) { "At least $memberCount in-forest principals; external expansion outside audit scope" }
                            else { "At least $memberCount (partial membership)" }
                        MaxAllowed   = "$threshold"
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\Hardening\OperatorGroups.rule.ps1
# Flags Operator groups (Account, Server, Print, Backup) that are not empty.

@{
    Id          = 'MATI-HARD-011'
    Title       = 'Operator group is not empty'
    Severity    = 'Medium'
    Description = "A built-in Operator group (Account Operators, Server Operators, Print Operators, or Backup Operators) has members. These groups have dangerous implicit permissions. Account Operators can create/modify non-protected accounts, Server Operators can log on to DCs and modify services, Backup Operators can backup/restore the ntds.dit database."
    Remediation = "Empty all Operator groups and delegate specific permissions using custom security groups with least-privilege access."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($group in $Data.SecurityConfig.OperatorGroups) {
            if ($group.MemberCount -gt 0) {
                $findings += @{
                    ObjectDN = "$($group.GroupSID) ($($group.GroupName))"
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName   = $group.GroupName
                        MemberCount = "$($group.MemberCount)"
                        Members     = ($group.Members -join ', ')
                    }
                }
            }
        }
        return $findings
    }
}

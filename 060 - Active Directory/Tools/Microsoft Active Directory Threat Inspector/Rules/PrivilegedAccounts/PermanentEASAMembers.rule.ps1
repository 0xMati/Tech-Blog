# Rules\PrivilegedAccounts\PermanentEASAMembers.rule.ps1
# Flags Enterprise Admins and Schema Admins groups that have permanent members.

@{
    Id          = 'MATI-ADMIN-013'
    Category    = 'Governance'
    Title       = 'Enterprise Admins or Schema Admins group has permanent members'
    Severity    = 'High'
    Description = "The Enterprise Admins or Schema Admins group has permanent members. These groups grant forest-wide privileges and should be empty by default. Membership should only be granted temporarily (Just-In-Time) when performing specific tasks that require it (e.g., schema extensions, cross-domain operations). Permanent membership significantly increases the attack surface for Golden Ticket and credential theft attacks."
    Remediation = "Remove all permanent members from Enterprise Admins and Schema Admins. Use temporary group membership (MemberTimeToLive with Forest Functional Level 2016+) or a JIT workflow to grant access only when needed. Maintain a break-glass procedure for emergency access."
    Collectors  = @('PrivilegedAccounts')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-resetting-the-krbtgt-password'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $targetGroups = @('Enterprise Admins', 'Schema Admins')

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            if ($group.GroupName -in $targetGroups -and $group.MemberCount -gt 0) {
                $findings += @{
                    ObjectDN = $group.DistinguishedName
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName   = $group.GroupName
                        MemberCount = "$($group.MemberCount)"
                        Members     = ($group.DirectMembers | ForEach-Object {
                            ($_ -split ',')[0] -replace '^CN=',''
                        }) -join ', '
                    }
                }
            }
        }
        return $findings
    }
}

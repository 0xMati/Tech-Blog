# Rules\PrivilegedAccounts\PermanentPrivilegedMembers.rule.ps1
# ORADAD: vuln_privileged_members_perm
# Flags all privileged groups (DA, EA, SA, Administrators, operator groups)
# that have permanent direct members — recommends JIT/PAM.

@{
    Id          = 'MATI-ADMIN-014'
    Category    = 'Governance'
    Title       = 'Privileged group has permanent direct members'
    Severity    = 'Medium'
    Description = "A privileged group (Domain Admins, Administrators, Account Operators, Server Operators, Backup Operators, or Print Operators) has permanent direct members. Best practice recommends that privileged group memberships be time-limited (Just-In-Time access) using PAM features (Forest FFL 2016+, MemberTimeToLive), PIM/PAM solutions, or strict operational procedures. Permanent membership in these groups increases the attack surface and the window of opportunity for credential theft, lateral movement, and privilege escalation. A limited number of dedicated break-glass accounts can be a valid exception when they are tightly controlled, monitored, excluded from daily administration, and protected with strong compensating controls."
    Remediation = "Reduce the number of permanent members in privileged groups to the strict minimum. For Domain Admins, a very small number of dedicated break-glass accounts can be acceptable when they are offline-documented, highly protected, monitored, and reserved for emergency use only. For operator groups (Account Operators, Server Operators, Backup Operators, Print Operators), aim for zero members and use RBAC or JIT instead. Deploy a Privileged Access Management (PAM) solution or leverage native AD time-limited group memberships (requires FFL 2016+)."
    Collectors  = @('PrivilegedAccounts')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        # EA and SA are already covered by ADMIN-013; this rule covers the remaining privileged groups
        $targetGroups = @(
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Server Operators',
            'Backup Operators',
            'Print Operators'
        )

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            if ($group.GroupName -in $targetGroups -and $group.MemberCount -gt 0) {
                # For Domain Admins, severity escalates with count
                $sev = switch ($group.GroupName) {
                    'Domain Admins'     { if ($group.MemberCount -gt 5) { 'High' } else { 'Medium' } }
                    'Administrators'    { if ($group.MemberCount -gt 5) { 'High' } else { 'Medium' } }
                    default             { 'High' }  # Operator groups should ideally be empty
                }

                $findings += @{
                    ObjectDN = $group.DistinguishedName
                    Domain   = $group.Domain
                    Severity = $sev
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

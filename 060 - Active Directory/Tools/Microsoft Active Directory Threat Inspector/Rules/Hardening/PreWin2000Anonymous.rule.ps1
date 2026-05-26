# Rules\Hardening\PreWin2000Anonymous.rule.ps1
# Flags Pre-Windows 2000 Compatible Access group containing dangerous members.

@{
    Id          = 'MATI-HARD-005'
    Title       = 'Pre-Windows 2000 group contains Anonymous or Everyone'
    Severity    = 'High'
    Description = "The 'Pre-Windows 2000 Compatible Access' group contains Anonymous Logon (S-1-5-7), Everyone (S-1-1-0), or Authenticated Users (S-1-5-11). This grants broad read access to Active Directory objects, including user attributes, group membership, and potentially sensitive information."
    Remediation = "Remove Anonymous Logon and Everyone from the Pre-Windows 2000 Compatible Access group. Run: Remove-ADGroupMember -Identity 'Pre-Windows 2000 Compatible Access' -Members 'S-1-5-7' -Confirm:`$false"
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($member in $Data.SecurityConfig.PreWin2000Members) {
            if ($member.IsDangerous) {
                $findings += @{
                    ObjectDN = $member.DistinguishedName
                    Domain   = $member.Domain
                    Details  = @{
                        MemberName = $member.MemberName
                        MemberSID  = $member.MemberSID
                        GroupName  = 'Pre-Windows 2000 Compatible Access'
                    }
                }
            }
        }
        return $findings
    }
}

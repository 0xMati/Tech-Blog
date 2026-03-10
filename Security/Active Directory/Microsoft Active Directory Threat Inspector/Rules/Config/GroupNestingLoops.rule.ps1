# Rules\Config\GroupNestingLoops.rule.ps1
# ORADAD: vuln_group_loop
# Flags circular group nesting (group membership loops).

@{
    Id          = 'MATI-CONFIG-026'
    Title       = 'Circular group nesting detected'
    Severity    = 'Medium'
    Description = "A circular nesting loop has been detected among AD groups (Group A member of Group B member of Group A, or longer chains). Circular group nesting can cause unpredictable behavior in permission evaluation, token bloat, and may indicate an administrative error or intentional misconfiguration."
    Remediation = "Break the circular nesting by removing one of the MemberOf relationships in the loop. Review group membership governance processes to prevent future occurrences."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($loop in $Data.SecurityConfig.GroupLoops) {
            $findings += @{
                ObjectDN = $loop.Groups[0]
                Domain   = $loop.Domain
                Details  = @{
                    CycleLength = "$($loop.CycleLength)"
                    GroupNames  = ($loop.GroupNames -join ' -> ')
                    GroupDNs    = ($loop.Groups -join '; ')
                }
            }
        }
        return $findings
    }
}

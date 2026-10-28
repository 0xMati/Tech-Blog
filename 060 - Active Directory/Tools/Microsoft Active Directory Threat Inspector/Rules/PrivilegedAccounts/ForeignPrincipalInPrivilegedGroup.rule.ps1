# Rules\PrivilegedAccounts\ForeignPrincipalInPrivilegedGroup.rule.ps1
# Flags foreign security principals directly added to privileged groups.

@{
    Id          = 'MATI-ADMIN-018'
    Title       = 'Foreign security principal directly in privileged group'
    Severity    = 'High'
    Description = "A privileged group contains a direct foreignSecurityPrincipal member. This usually indicates a cross-forest or external-trust principal has been granted privileged access inside the domain. Such placements deserve explicit review because they create trust-path exposure in Tier 0 groups."
    Remediation = "Review each foreign principal in privileged groups. Remove unnecessary external memberships and replace them with narrowly scoped delegated access where possible."
    Collectors  = @('PrivilegedAccounts')
    CollectorDatasets = @{ PrivilegedAccounts = @('Groups/DirectDetails') }
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models'
        'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/get-adgroupmember-error-remote-forest-members'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            foreach ($member in @($group.DirectMemberDetails)) {
                if (-not $member.IsForeignSecurityPrincipal) { continue }

                $key = "$($group.DistinguishedName)|$($member.DistinguishedName)"
                if (-not $seen.Add($key)) { continue }
                $status = if ($member.ExternalResolutionStatus) { $member.ExternalResolutionStatus } else { 'NotAttempted' }
                $outsideScope = [bool]$member.OutsideAssessmentScope
                $unresolved = $status -notin @('Resolved', 'ReturnedByADWS')

                $findings += @{
                    Title = if ($outsideScope) { 'External principal in privileged group' }
                        elseif ($member.ResolvedName -and $unresolved) { 'Foreign privileged identity: directory attributes unavailable' }
                        elseif ($unresolved) { 'Unresolved foreign identity in privileged group' }
                        else { 'Foreign security principal directly in privileged group' }
                    Description = if ($outsideScope) {
                        'A principal outside the assessed forest is a direct member of this privileged group. Its local membership is collected. Remote account attributes and external group expansion are outside the assessment scope, not a failure of local collection. Review whether this external privileged access is intended.'
                    } elseif ($unresolved) {
                        "A direct foreign principal in this privileged group could not be verified during collection (status: $status). Its SID and membership are retained. This may indicate an inaccessible identity or a deleted source account, but does not establish that the SID is orphaned or the trust is broken."
                    } else { $null }
                    ObjectDN = $member.DistinguishedName
                    Domain   = $group.Domain
                    Details  = @{
                        GroupName       = $group.GroupName
                        GroupDomain     = $group.Domain
                        ForeignPrincipal = ($member.Name ?? $member.SID)
                        SID = $member.SID
                        ResolutionStatus = $status
                        ResolvedName = $member.ResolvedName
                        ResolvedObjectClass = $member.ResolvedObjectClass
                        ResolvedDistinguishedName = $member.ResolvedDistinguishedName
                        ResolutionError = $member.ResolutionError
                        ResolutionAttempts = @($member.ResolutionAttempts)
                        OrphanStatus = 'NotDetermined'
                        MembershipScope = 'Direct'
                        OutsideAssessmentScope = $outsideScope
                        ExternalAudit = if ($outsideScope) { 'Not performed: outside the target forest' } else { 'Target forest' }
                        Note = 'Windows can resolve a SID name without permitting remote directory reads. Get-ADGroupMember can fail across one-way trusts (Microsoft KB 3171600); MATI reads local member links instead. This does not establish a deleted account or a broken trust.'
                    }
                }
            }
        }

        return $findings
    }
}
# Rules\PrivilegedAccounts\ManagedServiceInPrivilegedGroup.rule.ps1
# Flags managed service accounts that are members of privileged groups.

@{
    Id          = 'MATI-ADMIN-019'
    Title       = 'Managed service account in privileged group'
    Severity    = 'Critical'
    Description = "A managed service account (gMSA or sMSA) is a direct or nested member of a privileged administrative group. Managed service accounts are designed for service identity, not interactive or broad administrative membership. If a service host is compromised, this membership can create a direct escalation path into Tier 0 or other high-privilege scopes."
    Remediation = "Remove managed service accounts from privileged groups. Grant required rights through scoped delegation, service-specific ACLs, or host groups allowed to retrieve the managed password instead of broad administrative group membership."
    Collectors  = @('PrivilegedAccounts')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview',
        'https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

        foreach ($group in $Data.PrivilegedAccounts.Groups) {
            foreach ($member in @($group.MemberDetails)) {
                if ($member.ObjectClass -notin @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) { continue }

                $key = "$($group.DistinguishedName)|$($member.DistinguishedName)"
                if (-not $seen.Add($key)) { continue }

                $managedType = if ($member.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
                $findings += @{
                    ObjectDN = $member.DistinguishedName
                    Domain   = $member.Domain
                    Details  = @{
                        AccountName     = ($member.SamAccountName ?? $member.Name)
                        ManagedType     = $managedType
                        GroupName       = $group.GroupName
                        GroupDomain     = $group.Domain
                        MembershipScope = 'Recursive'
                    }
                }
            }
        }

        return $findings
    }
}
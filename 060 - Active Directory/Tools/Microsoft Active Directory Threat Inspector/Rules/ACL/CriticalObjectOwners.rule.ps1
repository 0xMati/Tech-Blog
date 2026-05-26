# Rules\ACL\CriticalObjectOwners.rule.ps1
# Flags critical AD objects owned by non-privileged principals.

@{
    Id          = 'MATI-ACL-006'
    Title       = 'Critical AD object with non-privileged owner'
    Severity    = 'High'
    Description = "A critical Active Directory object (domain controller, AdminSDHolder) is owned by a non-privileged principal. The owner of an object has implicit full control, which can be exploited for privilege escalation."
    Remediation = "Change ownership of the critical objects to Domain Admins or SYSTEM. Use: Set-ACL or the Active Directory delegation wizard."
    Collectors  = @('ACLInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.ACLInfo.Owners) {
            $findings += @{
                ObjectDN = $entry.ObjectDN
                Domain   = $entry.Domain
                Details  = @{
                    ObjectType = $entry.ObjectType
                    Owner      = $entry.Owner
                    OwnerSID   = $entry.OwnerSID
                }
            }
        }
        return $findings
    }
}

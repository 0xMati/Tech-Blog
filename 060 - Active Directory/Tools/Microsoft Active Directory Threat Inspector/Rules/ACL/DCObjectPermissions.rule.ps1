# Rules\ACL\DCObjectPermissions.rule.ps1
# ORADAD: vuln_permissions_dc
# Flags dangerous ACEs on Domain Controller computer objects.

@{
    Id          = 'MATI-ACL-008'
    Title       = 'Dangerous permissions on Domain Controller computer object'
    Severity    = 'Critical'
    Description = "A non-privileged principal has dangerous permissions (GenericAll, WriteDACL, WriteOwner, GenericWrite, WriteAllProperties, or AllExtendedRights) on a Domain Controller computer object. This allows an attacker to modify the DC object's attributes, set Resource-Based Constrained Delegation (RBCD), modify the msDS-KeyCredentialLink (Shadow Credentials), or take ownership — all of which lead to full domain compromise."
    Remediation = "Remove the dangerous ACE from the DC computer object. Review who has been delegated permissions on the Domain Controllers OU and its children. Ensure only Domain Admins, Enterprise Admins, and SYSTEM have write access to DC objects. Investigate whether this was set intentionally or is a result of compromise."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($ace in $Data.ACLInfo.DCObjects) {
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    DCName            = $ace.DCName
                    IdentityReference = $ace.IdentityRef
                    IdentitySID       = $ace.IdentitySID
                    Right             = $ace.Right
                    ADRights          = $ace.ADRights
                    IsInherited       = "$($ace.IsInherited)"
                }
            }
        }
        return $findings
    }
}

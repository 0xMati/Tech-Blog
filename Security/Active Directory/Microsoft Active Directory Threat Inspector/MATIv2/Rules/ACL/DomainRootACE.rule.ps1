# Rules\ACL\DomainRootACE.rule.ps1
# Flags dangerous ACEs on domain root objects (excluding DCSync, handled by ACL-002).

@{
    Id          = 'MATI-ACL-003'
    Title       = 'Dangerous permissions on domain root object'
    Severity    = 'High'
    Description = "A non-privileged principal has dangerous permissions (GenericAll, WriteDACL, WriteOwner, GenericWrite, or WriteAllProperties) on a domain root object. This can lead to complete domain compromise."
    Remediation = "Remove the dangerous ACEs from the domain root object. Review and remediate permissions using dsacls or AD Security tools."
    Collectors  = @('ACLInfo')
    References  = @('PingCastle: P-DomainRootACL', 'ANSSI: vuln_permissions_naming_context')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.DomainRoots) {
            # Skip replication rights (handled by ACL-002)
            if ($ace.Right -match 'DS-Replication') { continue }
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    IdentityReference = $ace.IdentityRef
                    IdentitySID       = $ace.IdentitySID
                    Right             = $ace.Right
                    ADRights          = $ace.ADRights
                }
            }
        }
        return $findings
    }
}

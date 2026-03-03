# Rules\ACL\SchemaACE.rule.ps1
# Flags dangerous ACEs on the Schema container.

@{
    Id          = 'MATI-ACL-004'
    Title       = 'Dangerous permissions on Schema container'
    Severity    = 'Critical'
    Description = "A non-privileged principal has dangerous permissions on the Schema container. Modifying the schema is irreversible and can compromise the entire forest."
    Remediation = "Remove the dangerous ACEs from the Schema container. Only Schema Admins should have write access to schema objects."
    Collectors  = @('ACLInfo')
    References  = @('PingCastle: P-SchemaACL', 'ANSSI: vuln_permissions_schema')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.SchemaObjects) {
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

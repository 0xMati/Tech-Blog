# Rules\ACL\ConfigContainerACE.rule.ps1
# Flags dangerous ACEs on the Configuration container.

@{
    Id          = 'MATI-ACL-005'
    Title       = 'Dangerous permissions on Configuration container'
    Severity    = 'High'
    Description = "A non-privileged principal has dangerous permissions on the Configuration naming context. This container holds forest-wide settings including sites, services, and certificate authorities."
    Remediation = "Remove the dangerous ACEs from the Configuration container. Only Enterprise Admins and Domain Admins of the forest root should have write access."
    Collectors  = @('ACLInfo')
    References  = @('PingCastle: P-ConfigACL', 'ANSSI: vuln_permissions_configuration')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.ConfigObjects) {
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

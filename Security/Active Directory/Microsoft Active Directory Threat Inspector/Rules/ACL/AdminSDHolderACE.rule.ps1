# Rules\ACL\AdminSDHolderACE.rule.ps1
# Flags dangerous ACEs on AdminSDHolder objects.

@{
    Id          = 'MATI-ACL-001'
    Title       = 'Dangerous permissions on AdminSDHolder'
    Severity    = 'Critical'
    Description = "The AdminSDHolder object has dangerous access control entries (ACEs) granted to non-privileged principals. These ACEs are propagated every 60 minutes by SDProp to all protected accounts (Domain Admins, Enterprise Admins, etc.), enabling privilege escalation."
    Remediation = "Remove the dangerous ACEs from the AdminSDHolder object. Run: dsacls 'CN=AdminSDHolder,CN=System,<DomainDN>' to review and clean permissions."
    Collectors  = @('ACLInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.AdminSDHolder) {
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
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

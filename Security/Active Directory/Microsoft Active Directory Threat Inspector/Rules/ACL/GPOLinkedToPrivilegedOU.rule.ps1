# Rules\ACL\GPOLinkedToPrivilegedOU.rule.ps1
# ORADAD: vuln_permissions_gpo_container_priv
# Flags dangerous ACEs on GPOs linked to the Domain Controllers OU.

@{
    Id          = 'MATI-ACL-012'
    Title       = 'Dangerous permissions on GPO linked to Domain Controllers OU'
    Severity    = 'Critical'
    Description = "A non-privileged principal has dangerous permissions (GenericAll, WriteDACL, WriteOwner, GenericWrite, etc.) on a Group Policy Object that is linked to the Domain Controllers OU. An attacker who can modify such a GPO can push arbitrary settings, scripts, or scheduled tasks to all Domain Controllers, leading to immediate and complete domain compromise. This is one of the most impactful AD attack paths."
    Remediation = "Remove the dangerous ACE from the affected GPO(s). Only Domain Admins and Enterprise Admins should have write access to GPOs linked to the Domain Controllers OU. Review GPO delegation using 'Get-GPPermission' and ensure the principle of least privilege is enforced. Consider using Group Policy Modeling to audit the effective permissions."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-group-policy'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($ace in $Data.ACLInfo.GPOPrivilegedOUs) {
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    GPOName           = "$($ace.GPOName)"
                    LinkedTo          = "$($ace.LinkedTo)"
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

# Rules\ACL\DFSRSysvolPermissions.rule.ps1
# ORADAD: vuln_permissions_dfsr_sysvol
# Flags dangerous ACEs on DFSR SYSVOL replication objects.

@{
    Id          = 'MATI-ACL-009'
    Title       = 'Dangerous permissions on DFSR/SYSVOL replication objects'
    Severity    = 'High'
    Description = "A non-privileged principal has dangerous permissions on DFSR SYSVOL replication configuration objects (Domain System Volume, SYSVOL Subscription, or DFSR-LocalSettings). An attacker with write access to these objects can manipulate SYSVOL replication, potentially injecting malicious scripts or Group Policy files that execute on all domain-joined machines."
    Remediation = "Remove the dangerous ACE from DFSR SYSVOL objects. These objects should only be writable by SYSTEM, Domain Admins, and Enterprise Admins. Review delegation on CN=DFSR-GlobalSettings,CN=System and on DC computer objects' DFSR-LocalSettings containers."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($ace in $Data.ACLInfo.DFSRSysvolObjects) {
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

# Rules\ACL\GPODangerousPermissions.rule.ps1
# Flags GPOs with dangerous permissions granted to non-privileged principals.

@{
    Id          = 'MATI-ACL-007'
    Title       = 'GPO with dangerous permissions for non-privileged principal'
    Severity    = 'High'
    Description = "A Group Policy Object has write, modify, or full control permissions granted to a non-privileged principal. An attacker who compromises this account can modify the GPO to deploy malware, change security settings, or create backdoor accounts on all computers where the GPO is applied."
    Remediation = "Review and restrict GPO permissions. Remove write/modify access for non-privileged accounts. Use delegation of GPO management only to trusted admin groups."
    Collectors  = @('GPOInfo')
    References  = @('PingCastle: P-GPOPermissions', 'ANSSI: vuln_permissions_gpo')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($perm in $Data.GPOInfo.DangerousGPOPerms) {
            # Only flag linked GPOs (orphan GPOs are less impactful)
            if (-not $perm.GPOLinked) { continue }
            $findings += @{
                ObjectDN = $perm.DistinguishedName
                Domain   = $perm.Domain
                Details  = @{
                    GPOName     = $perm.GPOName
                    Identity    = $perm.IdentityRef
                    Right       = $perm.Right
                    GPOLinked   = 'Yes'
                }
            }
        }
        return $findings
    }
}

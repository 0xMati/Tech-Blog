# Rules\ACL\KeyAdminDangerousPermissions.rule.ps1
# Flags Key Admins group with dangerous ACL permissions. [PingCastle: P-DelegationKeyAdmin]

@{
    Id          = 'MATI-ACL-015'
    Title       = 'Key Admins / Enterprise Key Admins with dangerous permissions'
    Severity    = 'Critical'
    Description = "The Key Admins or Enterprise Key Admins group (introduced with Windows Server 2016 AD prep) has write permissions on the domain root or key objects. A bug in the Windows Server 2016 AD preparation (before KB 3205642) granted these groups GenericAll or GenericWrite on the domain root, allowing full domain compromise. Any member of Key Admins could modify msDS-KeyCredentialLink on any object and perform Shadow Credential attacks."
    Remediation = "Apply KB 3205642 or later cumulative update to the schema master, then re-run 'adprep /domainprep'. Remove Key Admins and Enterprise Key Admins permissions from the domain root. Keep these groups empty unless actively using Windows Hello for Business or FIDO2 key credential provisioning."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://support.microsoft.com/en-us/topic/ad-replication-error-8453-replication-access-was-denied-87a67107-1f46-51c3-fd6a-fa6c00138903'
        'https://www.yourkit.com/docs/security/key-admins-exploit'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.KeyAdminACEs) {
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    GroupName = $ace.IdentityRef
                    GroupSID  = $ace.IdentitySID
                    Right     = $ace.Right
                    Issue     = 'Key Admin group has dangerous write permissions — potential Shadow Credential attack vector'
                }
            }
        }
        return $findings
    }
}

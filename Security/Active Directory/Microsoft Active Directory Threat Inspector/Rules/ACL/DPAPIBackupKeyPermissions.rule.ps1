# Rules\ACL\DPAPIBackupKeyPermissions.rule.ps1
# ORADAD: vuln_permissions_dpapi
# Flags dangerous ACEs on DPAPI domain backup key objects.

@{
    Id          = 'MATI-ACL-010'
    Title       = 'Dangerous permissions on DPAPI domain backup key objects'
    Severity    = 'Critical'
    Description = "A non-privileged principal has dangerous permissions on DPAPI domain backup key objects (BCKUPKEY_* in CN=System). These objects contain the domain's DPAPI master key used to protect user secrets (credentials, certificates, encryption keys). An attacker with read access can extract the DPAPI backup key and decrypt all DPAPI-protected secrets across the entire domain, including saved passwords, private keys, and browser credentials."
    Remediation = "Remove the dangerous ACE from the DPAPI backup key objects immediately. Only SYSTEM and Domain Admins should have access. These objects reside in CN=System under the domain root and should not have delegated permissions. Investigate whether the DPAPI backup key was already exfiltrated."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/win32/seccrypto/cng-dpapi'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($ace in $Data.ACLInfo.DPAPIObjects) {
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

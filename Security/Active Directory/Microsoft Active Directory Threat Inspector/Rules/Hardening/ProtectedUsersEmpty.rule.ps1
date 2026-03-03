# Rules\Hardening\ProtectedUsersEmpty.rule.ps1
# Flags domains where the Protected Users group is empty or has too few members.

@{
    Id          = 'MATI-HARD-001'
    Title       = 'Protected Users group is empty or incomplete'
    Severity    = 'High'
    Description = "The Protected Users security group is empty or contains very few members. Privileged accounts should be members of this group to receive additional protection: no NTLM authentication, no DES/RC4 encryption, no delegation, no long-lived TGT caching."
    Remediation = "Add all Domain Admins, Enterprise Admins, and other privileged accounts to the Protected Users group. Ensure the domain functional level is at least Windows Server 2012 R2."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: P-ProtectedUsers', 'ANSSI: vuln_protected_users')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($pu in $Data.SecurityConfig.ProtectedUsers) {
            if ($pu.MemberCount -eq 0) {
                $findings += @{
                    ObjectDN = $pu.Domain
                    Domain   = $pu.Domain
                    Details  = @{
                        MemberCount    = '0'
                        Recommendation = 'Add all privileged accounts to Protected Users'
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\ACL\ExchangeAdminSDHolder.rule.ps1
# Flags Exchange modification of AdminSDHolder. [PingCastle: P-ExchangeAdminSDHolder]

@{
    Id          = 'MATI-ACL-014'
    Title       = 'Exchange modified AdminSDHolder object'
    Severity    = 'Critical'
    Description = "An Exchange-related security group has dangerous permissions on the AdminSDHolder object. The AdminSDHolder ACL is propagated to all protected accounts (Domain Admins, Enterprise Admins, etc.) by the SDProp process every 60 minutes. Exchange groups with such rights can effectively control all privileged accounts."
    Remediation = "Remove Exchange group permissions from AdminSDHolder. Run the Exchange /PrepareAD with a patched version that removes these excessive rights. Review and revert any SDProp propagation."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory'
        'https://adsecurity.org/?p=4119'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.ExchangeACEs) {
            if ($ace.TargetType -ne 'AdminSDHolder') { continue }
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    ExchangeGroup = $ace.IdentityRef
                    GroupSID      = $ace.IdentitySID
                    Right         = $ace.Right
                    Issue         = "Exchange group has $($ace.Right) on AdminSDHolder — propagated to all protected accounts"
                }
            }
        }
        return $findings
    }
}

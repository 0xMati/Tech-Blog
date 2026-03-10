# Rules\ACL\ExchangePrivEscDomainRoot.rule.ps1
# Flags Exchange privilege escalation on domain root. [PingCastle: P-ExchangePrivEsc]

@{
    Id          = 'MATI-ACL-013'
    Title       = 'Exchange privilege escalation vulnerability on domain root'
    Severity    = 'Critical'
    Description = "An Exchange-related security group (Exchange Windows Permissions, Exchange Trusted Subsystem, etc.) has dangerous write permissions (WriteDACL, GenericAll, GenericWrite) on the domain root object. An attacker who compromises an Exchange server can leverage these permissions to grant themselves DCSync rights and extract all domain credentials."
    Remediation = "Remove the dangerous permissions. Apply the Exchange security fix by running 'Setup /PrepareAD /IAcceptExchangeServerLicenseTerms' from a patched Exchange version that removes the WriteDACL. For Exchange 2019 CU1+, the fix is included in Shared Permissions mode."
    Collectors  = @('ACLInfo')
    References  = @(
        'https://learn.microsoft.com/en-us/exchange/permissions/permissions'
        'https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($ace in $Data.ACLInfo.ExchangeACEs) {
            if ($ace.TargetType -ne 'DomainRoot') { continue }
            $findings += @{
                ObjectDN = $ace.TargetDN
                Domain   = $ace.Domain
                Details  = @{
                    ExchangeGroup = $ace.IdentityRef
                    GroupSID      = $ace.IdentitySID
                    Right         = $ace.Right
                    Issue         = "Exchange group has $($ace.Right) on domain root — potential PrivExchange attack vector"
                }
            }
        }
        return $findings
    }
}

# Rules\Config\TrustTGTDelegation.rule.ps1
# Flags trusts where TGT delegation is enabled.

@{
    Id          = 'MATI-CONFIG-015'
    Title       = 'TGT delegation enabled on trust'
    Severity    = 'High'
    Description = "A trust relationship has the TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION flag set. This allows TGTs to be forwarded across the trust, enabling protocol transition and potentially allowing accounts from the trusted domain to impersonate users in this domain."
    Remediation = "Disable TGT delegation on the trust: netdom trust <TrustingDomain> /domain:<TrustedDomain> /EnableTGTDelegation:no"
    Collectors  = @('TrustInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # TRUST_ATTRIBUTE_ENABLE_TGT_DELEGATION = 0x00000200 (512)
            $tgtDelegation = ($trust.TrustAttributes -band 0x00000200) -ne 0
            if ($tgtDelegation) {
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain     = $trust.TargetDomain
                        TrustType        = "$($trust.TrustType)"
                        Direction        = "$($trust.TrustDirection)"
                        TGTDelegation    = 'Enabled'
                        TrustAttributes  = "$($trust.TrustAttributes)"
                    }
                }
            }
        }
        return $findings
    }
}

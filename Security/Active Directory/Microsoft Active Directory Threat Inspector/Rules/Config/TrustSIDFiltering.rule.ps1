# Rules\Config\TrustSIDFiltering.rule.ps1
# Flags inter-forest trusts without SID filtering.

@{
    Id          = 'MATI-CONFIG-010'
    Title       = 'Trust relationship without SID Filtering'
    Severity    = 'High'
    Description = "An inter-forest trust does not have SID Filtering enabled. Without SID Filtering, an attacker who has compromised the trusted forest can inject arbitrary SIDs (including Enterprise Admins) into Kerberos tickets."
    Remediation = "Enable SID Filtering on inter-forest trusts via: netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes"
    Collectors  = @('TrustInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            # Only check non-intra-forest trusts
            if ($trust.IntraForest) { continue }
            if (-not $trust.SIDFilteringEnabled) {
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain  = $trust.TargetDomain
                        TrustType     = "$($trust.TrustType)"
                        Direction     = "$($trust.TrustDirection)"
                        SIDFiltering  = 'Disabled'
                    }
                }
            }
        }
        return $findings
    }
}

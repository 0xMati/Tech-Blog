# Rules\Config\TrustSIDFiltering.rule.ps1
# Flags inter-forest trusts without SID filtering.

@{
    Id          = 'MATI-CONFIG-010'
    Title       = 'Trust relationship without SID Filtering'
    Severity    = 'High'
    Description = "This control is only a confirmed local exposure when the local domain accepts identities from the trusted side, that is, on outbound or bidirectional external/forest trusts. One-way inbound trusts are reported as verification items because the effective exposure is on the opposite side."
    Remediation = "If the local domain accepts authentication from the trusted side, enable SID Filtering on the trust via: netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes. For one-way inbound trusts, verify the setting from the opposite side where the exposure actually exists."
    Collectors  = @('TrustInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            if ($trust.IntraForest) { continue }
            $isForestOrExternal = ($trust.TrustType -eq 'Forest') -or ($trust.TrustType -eq 'External') -or $trust.ForestTransitive
            if (-not $isForestOrExternal) { continue }
            if (-not $trust.SIDFilteringEnabled) {
                $isLocallyExposed = ($trust.TrustDirection -eq 'Outbound') -or ($trust.TrustDirection -eq 'Bidirectional')
                $findings += @{
                    Severity = if ($isLocallyExposed) { 'High' } else { 'Informational' }
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain         = $trust.TargetDomain
                        TrustType            = "$($trust.TrustType)"
                        Direction            = "$($trust.TrustDirection)"
                        SIDFiltering         = 'Disabled'
                        EvaluationStatus     = if ($isLocallyExposed) { 'Confirmed local exposure' } else { 'Verify from the opposite side of the trust' }
                    }
                }
            }
        }
        return $findings
    }
}

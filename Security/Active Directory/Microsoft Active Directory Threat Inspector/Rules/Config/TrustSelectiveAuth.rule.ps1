# Rules\Config\TrustSelectiveAuth.rule.ps1
# Flags inter-forest trusts without selective authentication.

@{
    Id          = 'MATI-CONFIG-011'
    Title       = 'Trust relationship without selective authentication'
    Severity    = 'Medium'
    Description = "Selective authentication is a hardening control for forest trusts where the local domain accepts identities from the remote forest. This rule only treats outbound or bidirectional forest trusts as a confirmed local exposure; one-way inbound trusts are verification items because the effective restriction lives on the opposite side."
    Remediation = "For forest trusts where the local domain accepts remote identities, enable selective authentication on the trust and configure 'Allowed-To-Authenticate' permissions on the required resources. For one-way inbound trusts, verify the opposite side instead of treating the local object as a confirmed issue."
    Collectors  = @('TrustInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            if ($trust.IntraForest) { continue }
            $isForestTrust = ($trust.TrustType -eq 'Forest') -or $trust.ForestTransitive
            if (-not $isForestTrust) { continue }
            if (-not $trust.SelectiveAuth) {
                $isLocallyExposed = ($trust.TrustDirection -eq 'Outbound') -or ($trust.TrustDirection -eq 'Bidirectional')
                $findings += @{
                    Severity = if ($isLocallyExposed) { 'Medium' } else { 'Informational' }
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain     = $trust.TargetDomain
                        TrustType        = "$($trust.TrustType)"
                        Direction        = "$($trust.TrustDirection)"
                        SelectiveAuth    = 'Disabled'
                        EvaluationStatus = if ($isLocallyExposed) { 'Confirmed local exposure' } else { 'Verify from the opposite side of the trust' }
                    }
                }
            }
        }
        return $findings
    }
}

# Rules\Config\TrustSelectiveAuth.rule.ps1
# Flags inter-forest trusts without selective authentication.

@{
    Id          = 'MATI-CONFIG-011'
    Title       = 'Trust relationship without selective authentication'
    Severity    = 'Medium'
    Description = "An inter-forest trust does not use selective authentication. Without it, all users from the trusted forest can authenticate to all resources, widening the attack surface."
    Remediation = "Enable selective authentication on the trust and configure 'Allowed-To-Authenticate' permissions on the required resources."
    Collectors  = @('TrustInfo')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($trust in $Data.TrustInfo) {
            if ($trust.IntraForest) { continue }
            if (-not $trust.SelectiveAuth) {
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain    = $trust.TargetDomain
                        TrustType       = "$($trust.TrustType)"
                        SelectiveAuth   = 'Disabled'
                    }
                }
            }
        }
        return $findings
    }
}

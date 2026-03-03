# Rules\Config\TrustInactive.rule.ps1
# Flags trust relationships that appear inactive.

@{
    Id          = 'MATI-CONFIG-014'
    Title       = 'Inactive trust relationship'
    Severity    = 'Medium'
    Description = "A trust relationship appears to be inactive based on its age and type. Old trusts that are no longer needed expand the attack surface and may provide unmonitored paths into the domain."
    Remediation = "Verify whether the trust is still needed. If not, remove it: Remove-ADTrust or netdom trust <domain> /domain:<target> /remove."
    Collectors  = @('TrustInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-trust/')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        $inactiveDays = $Config.Thresholds.TrustInactiveDays
        if (-not $inactiveDays) { $inactiveDays = 365 }
        $cutoff = (Get-Date).AddDays(-$inactiveDays)

        foreach ($trust in $Data.TrustInfo) {
            # Skip intra-forest trusts (always active)
            if ($trust.IntraForest) { continue }

            if ($trust.WhenCreated -and $trust.WhenCreated -lt $cutoff) {
                $ageDays = ((Get-Date) - $trust.WhenCreated).Days
                $findings += @{
                    ObjectDN = $trust.DistinguishedName
                    Domain   = $trust.SourceDomain
                    Details  = @{
                        TargetDomain = $trust.TargetDomain
                        TrustType    = "$($trust.TrustType)"
                        CreatedDate  = "$($trust.WhenCreated)"
                        AgeDays      = "$ageDays"
                    }
                }
            }
        }
        return $findings
    }
}

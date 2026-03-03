# Collectors\Get-MATITrustInfo.ps1
# MATIv2 - Collects AD trust relationships.

function Get-MATITrustInfo {
    <#
    .SYNOPSIS
        Collects all trust relationships across the forest.
    .OUTPUTS
        [array] of trust objects.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = Get-ADForest -ErrorAction Stop
    $trusts = foreach ($domainDns in $forest.Domains) {
        try {
            $domainTrusts = Get-ADTrust -Filter * -Server $domainDns -Properties * -ErrorAction Stop
            foreach ($trust in $domainTrusts) {
                [PSCustomObject]@{
                    SourceDomain          = $domainDns
                    TargetDomain          = $trust.Target
                    TrustDirection        = $trust.Direction          # Inbound, Outbound, Bidirectional
                    TrustType             = $trust.TrustType          # External, Forest, ParentChild...
                    TrustAttributes       = $trust.TrustAttributes
                    IsTransitive          = ($trust.TrustAttributes -band 0x00000001) -ne 0
                    SIDFilteringEnabled   = -not (($trust.TrustAttributes -band 0x00000004) -ne 0)  # TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                    SelectiveAuth         = ($trust.TrustAttributes -band 0x00000010) -ne 0          # TRUST_ATTRIBUTE_CROSS_ORGANIZATION
                    ForestTransitive      = ($trust.TrustAttributes -band 0x00000008) -ne 0          # TRUST_ATTRIBUTE_FOREST_TRANSITIVE
                    IntraForest           = $trust.IntraForest
                    DistinguishedName     = $trust.DistinguishedName
                    WhenCreated           = $trust.WhenCreated
                }
            }
        }
        catch {
            Write-Warning "    Cannot query trusts for $domainDns : $($_.Exception.Message)"
        }
    }

    return @($trusts)
}

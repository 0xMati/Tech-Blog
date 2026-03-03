# Collectors\Get-MATIDomainInfo.ps1
# MATIv2 - Collects domain and forest information.

function Get-MATIDomainInfo {
    <#
    .SYNOPSIS
        Collects domain and forest metadata across the AD forest.
    .OUTPUTS
        [hashtable] with keys: Domains, Forest
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $domains = foreach ($domainDns in $forest.Domains) {
        try {
            $dom = Get-ADDomain -Identity $domainDns -ErrorAction Stop
            [PSCustomObject]@{
                Name                  = $dom.Name
                DNSRoot               = $dom.DNSRoot
                NetBIOSName           = $dom.NetBIOSName
                DistinguishedName     = $dom.DistinguishedName
                DomainMode            = $dom.DomainMode
                DomainModeNumeric     = [int]$dom.DomainMode
                InfrastructureMaster  = $dom.InfrastructureMaster
                PDCEmulator           = $dom.PDCEmulator
                RIDMaster             = $dom.RIDMaster
                ParentDomain          = $dom.ParentDomain
                ChildDomains          = $dom.ChildDomains
            }
        }
        catch {
            Write-Warning "    Cannot query domain $domainDns : $($_.Exception.Message)"
        }
    }

    $forestInfo = [PSCustomObject]@{
        Name                = $forest.Name
        ForestMode          = $forest.ForestMode
        ForestModeNumeric   = [int]$forest.ForestMode
        RootDomain          = $forest.RootDomain
        SchemaMaster        = $forest.SchemaMaster
        DomainNamingMaster  = $forest.DomainNamingMaster
        Domains             = $forest.Domains
        GlobalCatalogs      = $forest.GlobalCatalogs
        Sites               = $forest.Sites
        # Check if AD Recycle Bin is enabled
        RecycleBinEnabled   = (
            Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"' -ErrorAction SilentlyContinue
        ).EnabledScopes.Count -gt 0
        # Tombstone lifetime
        TombstoneLifetime   = (
            Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$(
                (Get-ADRootDSE).configurationNamingContext
            )" -Properties tombstoneLifetime -ErrorAction SilentlyContinue
        ).tombstoneLifetime
    }

    return @{
        Domains = @($domains)
        Forest  = $forestInfo
    }
}

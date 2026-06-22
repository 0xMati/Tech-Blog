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
    $rootDSE = $Config['_RootDSECache'] ?? (Get-ADRootDSE -Server ($Config['_DirectoryServer'] ?? $forest.RootDomain) -ErrorAction Stop)
    $directoryServer = $Config['_DirectoryServer'] ?? $forest.RootDomain
    $domains = foreach ($domainDns in $forest.Domains) {
        try {
            $dom = Get-ADDomain -Identity $domainDns -Server $domainDns -ErrorAction Stop
            $ouCount = 0
            try {
                $ouCount = @(Get-ADOrganizationalUnit -Filter * -Server $domainDns -ResultSetSize $null -ErrorAction Stop).Count
            } catch {
                Write-Verbose "    Cannot count organizational units for $domainDns : $($_.Exception.Message)"
            }
            [PSCustomObject]@{
                Name                  = $dom.Name
                DNSRoot               = $dom.DNSRoot
                NetBIOSName           = $dom.NetBIOSName
                DistinguishedName     = $dom.DistinguishedName
                DomainMode            = $dom.DomainMode
                OrganizationalUnitCount = $ouCount
                DomainModeNumeric     = Get-MATIFunctionalLevelNumeric $dom.DomainMode
                InfrastructureMaster  = $dom.InfrastructureMaster
                PDCEmulator           = $dom.PDCEmulator
                RIDMaster             = $dom.RIDMaster
                ParentDomain          = $dom.ParentDomain
                ChildDomains          = $dom.ChildDomains
                ComputersContainer    = $dom.ComputersContainer
                UsersContainer        = $dom.UsersContainer
            }
        }
        catch {
            Write-Warning "    Cannot query domain $domainDns : $($_.Exception.Message)"
        }
    }

    $forestInfo = [PSCustomObject]@{
        Name                = $forest.Name
        ForestMode          = $forest.ForestMode
        ForestModeNumeric   = Get-MATIFunctionalLevelNumeric $forest.ForestMode
        RootDomain          = $forest.RootDomain
        SchemaMaster        = $forest.SchemaMaster
        DomainNamingMaster  = $forest.DomainNamingMaster
        Domains             = $forest.Domains
        GlobalCatalogs      = $forest.GlobalCatalogs
        Sites               = $forest.Sites
        # Check if AD Recycle Bin is enabled
        RecycleBinEnabled   = (
            Get-ADOptionalFeature -Filter 'Name -eq "Recycle Bin Feature"' -Server $directoryServer -ErrorAction SilentlyContinue
        ).EnabledScopes.Count -gt 0
        # Tombstone lifetime
        TombstoneLifetime   = (
            Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$(
                $rootDSE.configurationNamingContext
            )" -Server $directoryServer -Properties tombstoneLifetime -ErrorAction SilentlyContinue
        ).tombstoneLifetime
        # AD Schema version (objectVersion on Schema container)
        SchemaVersion       = (
            Get-ADObject $rootDSE.schemaNamingContext -Server $directoryServer -Properties objectVersion -ErrorAction SilentlyContinue
        ).objectVersion
    }

    return @{
        Domains = @($domains)
        Forest  = $forestInfo
    }
}

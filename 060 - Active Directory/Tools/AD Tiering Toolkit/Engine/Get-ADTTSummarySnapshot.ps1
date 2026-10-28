function Get-ADTTSummarySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Discovery
    )

    function Get-ADTTDotClass {
        param(
            [int]$Count,
            [int]$YellowThreshold,
            [int]$RedThreshold = -1
        )

        if ($RedThreshold -ge 0 -and $Count -gt $RedThreshold) {
            return 'red'
        }
        if ($Count -gt $YellowThreshold) {
            return 'yellow'
        }
        return 'green'
    }

    function Get-ADTTUniqueSamCount {
        param([object[]]$Entries)

        return @(
            @($Entries) |
                Where-Object { $_.SamAccountName } |
                ForEach-Object { $_.SamAccountName } |
                Select-Object -Unique
        ).Count
    }

    function Get-ADTTSnapshotValue {
        param(
            [int]$Count,
            [string]$Dot
        )

        return [ordered]@{ Count = $Count; Dot = $Dot }
    }

    $daEntries = foreach ($key in $Discovery.PrivilegedAccounts.Keys) {
        if ($key -like '*\Domain Admins') {
            $Discovery.PrivilegedAccounts[$key]
        }
    }
    $eaEntries = foreach ($key in $Discovery.PrivilegedAccounts.Keys) {
        if ($key -like '*\Enterprise Admins') {
            $Discovery.PrivilegedAccounts[$key]
        }
    }

    $domainCount = if ($Discovery.Forest -and $Discovery.Forest.DomainCount) { [int]$Discovery.Forest.DomainCount } else { @($Discovery.Domains).Count }
    $computerCount = @($Discovery.ComputersByTier.Tier0 | Where-Object { $_ }).Count + @($Discovery.ComputersByTier.Tier1 | Where-Object { $_ }).Count + @($Discovery.ComputersByTier.Tier2 | Where-Object { $_ }).Count + @($Discovery.ComputersByTier.Unclassified | Where-Object { $_ }).Count
    $daCount = Get-ADTTUniqueSamCount -Entries @($daEntries)
    $eaCount = Get-ADTTUniqueSamCount -Entries @($eaEntries)
    $svcInDaCount = @($Discovery.ServiceAccountsInDA).Count
    $gmsaCount = @($Discovery.ManagedServiceAccounts.GMSA).Count
    $msaCount = @($Discovery.ManagedServiceAccounts.MSA).Count
    $orphansCount = @($Discovery.AdminCountOrphans).Count
    $trustCount = @($Discovery.Trusts).Count
    $unsafeTrustCount = @($Discovery.Trusts | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest }).Count
    $siteCount = if ($Discovery.Forest -and $Discovery.Forest.SiteCount) { [int]$Discovery.Forest.SiteCount } else { 0 }
    $dcCount = @($Discovery.DomainControllers).Count
    $ouCount = @($Discovery.OUStructure).Count
    $gpoCount = @($Discovery.GPOs).Count

    $daDot = Get-ADTTDotClass -Count $daCount -YellowThreshold 2 -RedThreshold 5
    $eaDot = Get-ADTTDotClass -Count $eaCount -YellowThreshold 1 -RedThreshold 3
    $svcDaDot = if ($svcInDaCount -gt 0) { 'red' } else { 'green' }
    $gmsaDot = if ($gmsaCount -gt 0) { 'green' } else { 'yellow' }
    $msaDot = if ($msaCount -gt 0) { 'yellow' } else { 'green' }
    $orphansDot = if ($orphansCount -gt 0) { 'yellow' } else { 'green' }
    $trustDot = if ($unsafeTrustCount -gt 0) { 'red' } elseif ($trustCount -gt 0) { 'yellow' } else { 'green' }
    $unsafeTrustDot = if ($unsafeTrustCount -gt 0) { 'red' } else { 'green' }

    return [ordered]@{
        Environment = [ordered]@{
            Domains          = $domainCount
            Computers        = $computerCount
            Users            = [int]$Discovery.DirectoryCounts.Users
            Groups           = [int]$Discovery.DirectoryCounts.Groups
            DomainAdmins     = Get-ADTTSnapshotValue -Count $daCount -Dot $daDot
            EnterpriseAdmins = Get-ADTTSnapshotValue -Count $eaCount -Dot $eaDot
            Trusts           = Get-ADTTSnapshotValue -Count $trustCount -Dot $trustDot
        }
        IdentityAccess = [ordered]@{
            DomainAdmins        = Get-ADTTSnapshotValue -Count $daCount -Dot $daDot
            EnterpriseAdmins    = Get-ADTTSnapshotValue -Count $eaCount -Dot $eaDot
            ServiceAccountsInDA = Get-ADTTSnapshotValue -Count $svcInDaCount -Dot $svcDaDot
            GMSA                = Get-ADTTSnapshotValue -Count $gmsaCount -Dot $gmsaDot
            MSA                 = Get-ADTTSnapshotValue -Count $msaCount -Dot $msaDot
            AdminCountOrphans   = Get-ADTTSnapshotValue -Count $orphansCount -Dot $orphansDot
        }
        Infrastructure = [ordered]@{
            Sites               = $siteCount
            DomainControllers   = $dcCount
            OrganizationalUnits = [int]$ouCount
            GroupPolicies       = [int]$gpoCount
        }
        Trusts = [ordered]@{
            TrustRelationships = Get-ADTTSnapshotValue -Count $trustCount -Dot $trustDot
            UnsafeTrusts       = Get-ADTTSnapshotValue -Count $unsafeTrustCount -Dot $unsafeTrustDot
        }
    }
}

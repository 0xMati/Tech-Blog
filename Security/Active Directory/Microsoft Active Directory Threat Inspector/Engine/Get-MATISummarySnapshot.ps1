# Engine\Get-MATISummarySnapshot.ps1
# Shared summary snapshot builder for Threat Detection and Tiering reports.

function Test-MATILikelyServiceAccount {
    param(
        [string]$SamAccountName,
        [string]$Description,
        [bool]$HasSPN
    )

    $signals = [System.Collections.Generic.List[string]]::new()
    if ($HasSPN) {
        $signals.Add('SPN present')
    }
    if ($SamAccountName -match '(^|[-_.])(svc|service|sql|app|batch|task|scan|backup|agent)([-_.]|$)') {
        $signals.Add('Sensitive naming pattern')
    }
    if ($Description -and $Description -match '(?i)service|scheduled|batch|application|sql|backup|agent') {
        $signals.Add('Description suggests service usage')
    }

    return [ordered]@{
        IsServiceAccount = ($signals.Count -gt 0)
        Signals          = @($signals)
    }
}

function Get-MATISummarySnapshot {
    [CmdletBinding(DefaultParameterSetName = 'EngineContext')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'EngineContext')]
        [hashtable]$EngineContext,

        [Parameter(Mandatory, ParameterSetName = 'Discovery')]
        [hashtable]$Discovery
    )

    function Get-MATIDotClass {
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

    function Get-MATIUniqueSamCount {
        param(
            [object[]]$Entries
        )

        return @(
            @($Entries) |
                Where-Object { $_.SamAccountName } |
                ForEach-Object { $_.SamAccountName } |
                Select-Object -Unique
        ).Count
    }

    function Get-MATISnapshotValue {
        param(
            [int]$Count,
            [string]$Dot
        )

        return [ordered]@{
            Count = $Count
            Dot   = $Dot
        }
    }

    if ($PSCmdlet.ParameterSetName -eq 'Discovery') {
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
        $computerCount = @($Discovery.ComputersByTier.Tier0).Count + @($Discovery.ComputersByTier.Tier1).Count + @($Discovery.ComputersByTier.Tier2).Count + @($Discovery.ComputersByTier.Unclassified).Count
        $daCount = Get-MATIUniqueSamCount -Entries @($daEntries)
        $eaCount = Get-MATIUniqueSamCount -Entries @($eaEntries)
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
    }
    else {
        $dataCache = $EngineContext.DataCache
        $domainInfo = $dataCache['DomainInfo']
        $computerAccounts = @($dataCache['ComputerAccounts'])
        $userAccounts = @($dataCache['UserAccounts'])
        $trustInfo = @($dataCache['TrustInfo'])
        $privilegedData = $dataCache['PrivilegedAccounts']
        $dcData = @($dataCache['DCInfo'])
        $securityConfig = $dataCache['SecurityConfig']
        $gpoInfo = $dataCache['GPOInfo']

        $domainCount = if ($domainInfo -and $domainInfo.Domains) { @($domainInfo.Domains).Count } else { 0 }
        $computerCount = $computerAccounts.Count
        $siteCount = if ($domainInfo -and $domainInfo.Forest -and $domainInfo.Forest.Sites) { @($domainInfo.Forest.Sites).Count } else { 0 }
        $dcCount = $dcData.Count
        $gmsaCount = if ($securityConfig -and $securityConfig.GMSAAccounts) { @($securityConfig.GMSAAccounts).Count } else { 0 }
        $msaCount = if ($securityConfig -and $securityConfig.MSAAccounts) { @($securityConfig.MSAAccounts).Count } else { 0 }
        $orphansCount = if ($securityConfig -and $securityConfig.AdminCountOrphans) { @($securityConfig.AdminCountOrphans).Count } else { 0 }
        $groupCount = if ($securityConfig -and $securityConfig.GroupCounts) { (@($securityConfig.GroupCounts) | Measure-Object -Property Count -Sum).Sum } else { 0 }
        $ouCount = if ($domainInfo -and $domainInfo.Domains) { (@($domainInfo.Domains) | Measure-Object -Property OrganizationalUnitCount -Sum).Sum } else { 0 }
        $gpoCount = if ($gpoInfo -and $gpoInfo.GPOs) { @($gpoInfo.GPOs).Count } else { 0 }
        $trustCount = $trustInfo.Count
        $unsafeTrustCount = @($trustInfo | Where-Object { -not $_.SIDFilteringEnabled -and -not $_.IntraForest }).Count

        $daGroups = if ($privilegedData -and $privilegedData.Groups) { @($privilegedData.Groups | Where-Object GroupName -eq 'Domain Admins') } else { @() }
        $eaGroups = if ($privilegedData -and $privilegedData.Groups) { @($privilegedData.Groups | Where-Object GroupName -eq 'Enterprise Admins') } else { @() }
        $daEntries = foreach ($group in $daGroups) { @($group.MemberDetails) }
        $eaEntries = foreach ($group in $eaGroups) { @($group.MemberDetails) }
        $daCount = Get-MATIUniqueSamCount -Entries @($daEntries)
        $eaCount = Get-MATIUniqueSamCount -Entries @($eaEntries)

        $userLookup = @{}
        foreach ($account in @($privilegedData.Accounts)) {
            if ($account.DistinguishedName) {
                $userLookup[$account.DistinguishedName] = $account
            }
        }
        foreach ($account in @($userAccounts)) {
            if ($account.DistinguishedName -and -not $userLookup.ContainsKey($account.DistinguishedName)) {
                $userLookup[$account.DistinguishedName] = $account
            }
        }

        $serviceAccountDns = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($svc in @($securityConfig.GMSAAccounts)) {
            if ($svc.DistinguishedName) {
                $null = $serviceAccountDns.Add($svc.DistinguishedName)
            }
        }
        foreach ($svc in @($securityConfig.MSAAccounts)) {
            if ($svc.DistinguishedName) {
                $null = $serviceAccountDns.Add($svc.DistinguishedName)
            }
        }

        $serviceAccountSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($member in @($daEntries)) {
            if (-not $member.SamAccountName) {
                continue
            }

            $isServiceAccount = $false
            if ($member.ObjectClass -in @('msDS-GroupManagedServiceAccount', 'msDS-ManagedServiceAccount')) {
                $isServiceAccount = $true
            }
            elseif ($member.DistinguishedName -and $serviceAccountDns.Contains($member.DistinguishedName)) {
                $isServiceAccount = $true
            }
            else {
                $lookup = if ($member.DistinguishedName -and $userLookup.ContainsKey($member.DistinguishedName)) { $userLookup[$member.DistinguishedName] } else { $null }
                $hasSPN = $false
                $description = $null
                if ($lookup) {
                    $hasSPN = @($lookup.ServicePrincipalName).Count -gt 0
                    $description = $lookup.Description
                }

                $assessment = Test-MATILikelyServiceAccount -SamAccountName $member.SamAccountName -Description $description -HasSPN $hasSPN
                $isServiceAccount = $assessment.IsServiceAccount
            }

            if ($isServiceAccount) {
                $null = $serviceAccountSet.Add($member.SamAccountName)
            }
        }

        $svcInDaCount = $serviceAccountSet.Count
    }

    $daDot = Get-MATIDotClass -Count $daCount -YellowThreshold 2 -RedThreshold 5
    $eaDot = Get-MATIDotClass -Count $eaCount -YellowThreshold 1 -RedThreshold 3
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
            Users            = if ($PSCmdlet.ParameterSetName -eq 'Discovery') { [int]$Discovery.DirectoryCounts.Users } else { @($userAccounts).Count }
            Groups           = if ($PSCmdlet.ParameterSetName -eq 'Discovery') { [int]$Discovery.DirectoryCounts.Groups } else { [int]$groupCount }
            DomainAdmins     = Get-MATISnapshotValue -Count $daCount -Dot $daDot
            EnterpriseAdmins = Get-MATISnapshotValue -Count $eaCount -Dot $eaDot
            Trusts           = Get-MATISnapshotValue -Count $trustCount -Dot $trustDot
        }
        IdentityAccess = [ordered]@{
            DomainAdmins       = Get-MATISnapshotValue -Count $daCount -Dot $daDot
            EnterpriseAdmins   = Get-MATISnapshotValue -Count $eaCount -Dot $eaDot
            ServiceAccountsInDA = Get-MATISnapshotValue -Count $svcInDaCount -Dot $svcDaDot
            GMSA               = Get-MATISnapshotValue -Count $gmsaCount -Dot $gmsaDot
            MSA                = Get-MATISnapshotValue -Count $msaCount -Dot $msaDot
            AdminCountOrphans  = Get-MATISnapshotValue -Count $orphansCount -Dot $orphansDot
        }
        Infrastructure = [ordered]@{
            Sites               = $siteCount
            DomainControllers   = $dcCount
            OrganizationalUnits = [int]$ouCount
            GroupPolicies       = [int]$gpoCount
        }
        Trusts = [ordered]@{
            TrustRelationships = Get-MATISnapshotValue -Count $trustCount -Dot $trustDot
            UnsafeTrusts       = Get-MATISnapshotValue -Count $unsafeTrustCount -Dot $unsafeTrustDot
        }
    }
}
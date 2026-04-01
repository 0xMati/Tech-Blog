# Tiering\Invoke-MATITieringDiscovery.ps1
# Phase 0 — Discovery & Tier Classification
# Read-only assessment of the current environment to prepare for tiering deployment.

function Invoke-MATITieringDiscovery {
    <#
    .SYNOPSIS
        Phase 0 — Discovers and classifies all AD assets by tier.
    .DESCRIPTION
        Performs a read-only inventory of the forest:
        - Computer objects classified as T0 / T1 / T2
        - Privileged accounts enumerated across all built-in groups
        - Current OU structure mapped
        - GPOs and links inventoried
        - Trusts assessed
        - Existing Authentication Policies and Silos inventoried
        - Generates an HTML discovery report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootPath,

        [Parameter(Mandatory)]
        [hashtable]$TieringConfig,

        [Parameter(Mandatory)]
        [string]$OutputDir
    )

    $ErrorActionPreference = 'Continue'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Ensure output directory exists
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    function Add-ClassificationSignal {
        param(
            [hashtable]$ScoreBoard,
            [string]$Tier,
            [int]$Weight,
            [string]$Evidence
        )

        $ScoreBoard[$Tier].Score += $Weight
        $ScoreBoard[$Tier].Evidence += @($Evidence)
    }

    function Resolve-ComputerTierProposal {
        param(
            [hashtable]$ScoreBoard,
            [string]$ComputerName
        )

        $ranking = foreach ($tierKey in $ScoreBoard.Keys) {
            [PSCustomObject]@{
                Tier     = $tierKey
                Score    = $ScoreBoard[$tierKey].Score
                Evidence = @($ScoreBoard[$tierKey].Evidence)
            }
        }

        $sorted = @($ranking | Sort-Object Score -Descending)
        $top = $sorted[0]
        $runnerUpScore = if ($sorted.Count -gt 1) { $sorted[1].Score } else { 0 }
        $scoreGap = $top.Score - $runnerUpScore

        if ($top.Score -le 0) {
            return [ordered]@{
                Tier          = 'Unclassified'
                Confidence    = 'Low'
                Evidence      = @('No tiering evidence matched')
                ReviewRequired = $true
                ReviewReason  = 'No tiering evidence matched'
                Scores        = [ordered]@{
                    Tier0 = $ScoreBoard.Tier0.Score
                    Tier1 = $ScoreBoard.Tier1.Score
                    Tier2 = $ScoreBoard.Tier2.Score
                }
            }
        }

        $confidence = if ($top.Score -ge 100 -and $scoreGap -ge 50) {
            'High'
        }
        elseif ($top.Score -ge 50 -and $scoreGap -ge 20) {
            'Medium'
        }
        else {
            'Low'
        }

        $reviewReasons = [System.Collections.Generic.List[string]]::new()
        $onlyWeakSignals = $top.Evidence.Count -gt 0 -and @($top.Evidence | Where-Object { $_ -notmatch '^OS heuristic:' }).Count -eq 0
        $competingSignals = @($sorted | Where-Object { $_.Tier -ne $top.Tier -and $_.Score -ge 40 }).Count -gt 0

        if ($onlyWeakSignals) {
            $reviewReasons.Add('Classification relies only on OS heuristics')
        }
        if ($competingSignals) {
            $reviewReasons.Add('Competing evidence exists for another tier')
        }
        if ($confidence -eq 'Low') {
            $reviewReasons.Add('Classification confidence is low')
        }

        return [ordered]@{
            Tier           = $top.Tier
            Confidence     = $confidence
            Evidence       = @($top.Evidence)
            ReviewRequired = ($reviewReasons.Count -gt 0)
            ReviewReason   = ($reviewReasons -join '; ')
            Scores         = [ordered]@{
                Tier0 = $ScoreBoard.Tier0.Score
                Tier1 = $ScoreBoard.Tier1.Score
                Tier2 = $ScoreBoard.Tier2.Score
            }
        }
    }

    function Test-LikelyServiceAccount {
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

    function Test-LikelyEntraConnectComputer {
        param(
            [string]$ComputerName,
            [string]$Description,
            [hashtable]$ClassificationConfig
        )

        $signals = [System.Collections.Generic.List[string]]::new()

        foreach ($pattern in @($ClassificationConfig.Tier0.NamePatterns)) {
            if ($pattern -and $ComputerName -like $pattern -and $pattern -match 'AADConnect|EntraConnect|ADSync|AzureADConnect') {
                $signals.Add("Name indicates Entra Connect: $pattern")
            }
        }

        foreach ($pattern in @($ClassificationConfig.Tier0.DescriptionPatterns)) {
            if (-not $pattern -or -not $Description) { continue }
            if ($Description -match [regex]::Escape($pattern)) {
                $signals.Add("Description indicates Entra Connect: $pattern")
            }
        }

        return [ordered]@{
            IsMatch = ($signals.Count -gt 0)
            Signals = @($signals)
        }
    }

    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 0 — Discovery & Tier Classification" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Mode: Read-Only (no changes will be made)`n" -ForegroundColor DarkGray

    # Result container
    $discovery = [ordered]@{
        Timestamp           = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Forest              = $null
        Domains             = [System.Collections.Generic.List[object]]::new()
        DomainControllers   = [System.Collections.Generic.List[object]]::new()
        DCConnectivity      = [System.Collections.Generic.List[object]]::new()
        DirectoryCounts     = [ordered]@{ Users = 0; Groups = 0 }
        ComputersByTier     = [ordered]@{ Tier0 = @(); Tier1 = @(); Tier2 = @(); Unclassified = @() }
        ReviewQueue         = [System.Collections.Generic.List[object]]::new()
        PriorityActions     = [System.Collections.Generic.List[object]]::new()
        ClassificationSummary = [ordered]@{}
        PrivilegedAccounts  = [ordered]@{}
        ManagedServiceAccounts = [ordered]@{ GMSA = @(); MSA = @() }
        AuthenticationControls = [ordered]@{ Policies = @(); Silos = @(); Summary = [ordered]@{} }
        AdminCountOrphans   = @()
        ServiceAccountsInDA = @()
        OUStructure         = @()
        GPOs                = @()
        GPOLinks            = @()
        Trusts              = @()
        ExistingTiering     = [ordered]@{}
        Readiness           = [ordered]@{}
        Observations        = [ordered]@{}
    }

    # ================================================================
    # Step 1 — Forest & Domain info
    # ================================================================
    Write-Host "  [1/8] Collecting forest & domain information..." -ForegroundColor Yellow
    try {
        $forest = Get-ADForest
        $discovery.Forest = [ordered]@{
            Name                = $forest.Name
            ForestMode          = $forest.ForestMode.ToString()
            RootDomain          = $forest.RootDomain
            DomainCount         = $forest.Domains.Count
            Domains             = @($forest.Domains)
            SiteCount           = $forest.Sites.Count
            Sites               = @($forest.Sites)
            GlobalCatalogCount  = $forest.GlobalCatalogs.Count
        }

        foreach ($domainName in $forest.Domains) {
            try {
                $dom = Get-ADDomain -Server $domainName
                $domPwdPolicy = Get-ADDefaultDomainPasswordPolicy -Server $domainName

                $discovery.Domains.Add([ordered]@{
                    Name                = $dom.DNSRoot
                    NetBIOSName         = $dom.NetBIOSName
                    DomainMode          = $dom.DomainMode.ToString()
                    DistinguishedName   = $dom.DistinguishedName
                    PDCEmulator         = $dom.PDCEmulator
                    InfrastructureMaster = $dom.InfrastructureMaster
                    RIDMaster           = $dom.RIDMaster
                    ChildDomains        = @($dom.ChildDomains)
                    MinPwdLength        = $domPwdPolicy.MinPasswordLength
                    MaxPwdAge           = $domPwdPolicy.MaxPasswordAge.Days
                    LockoutThreshold    = $domPwdPolicy.LockoutThreshold
                    MachineAccountQuota = (Get-ADObject $dom.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $domainName).'ms-DS-MachineAccountQuota'
                })

                $domainUserCount = @(Get-ADUser -Filter * -Server $domainName -ResultSetSize $null -ErrorAction SilentlyContinue).Count
                $domainGroupCount = @(Get-ADGroup -Filter * -Server $domainName -ResultSetSize $null -ErrorAction SilentlyContinue).Count
                $discovery.DirectoryCounts.Users += $domainUserCount
                $discovery.DirectoryCounts.Groups += $domainGroupCount
            } catch {
                Write-Warning "  Could not query domain $domainName : $($_.Exception.Message)"
            }
        }
        Write-Host "    Forest: $($forest.Name) | Domains: $($forest.Domains.Count) | Sites: $($forest.Sites.Count) | Users: $($discovery.DirectoryCounts.Users) | Groups: $($discovery.DirectoryCounts.Groups)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to collect forest info: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 2 — Domain Controllers
    # ================================================================
    Write-Host "  [2/8] Enumerating Domain Controllers..." -ForegroundColor Yellow
    try {
        foreach ($domainName in $forest.Domains) {
            try {
                $dcs = Get-ADDomainController -Filter * -Server $domainName
                foreach ($dc in $dcs) {
                    $discovery.DomainControllers.Add([ordered]@{
                        Name              = $dc.Name
                        HostName          = $dc.HostName
                        Domain            = $domainName
                        IPv4Address       = $dc.IPv4Address
                        Site              = $dc.Site
                        OperatingSystem   = $dc.OperatingSystem
                        IsGlobalCatalog   = $dc.IsGlobalCatalog
                        IsReadOnly        = $dc.IsReadOnly
                        OperationMasterRoles = @($dc.OperationMasterRoles)
                    })
                }
            } catch {
                Write-Warning "  Could not enumerate DCs for $domainName : $($_.Exception.Message)"
            }
        }
        $dcCount = $discovery.DomainControllers.Count
        $rodcCount = ($discovery.DomainControllers | Where-Object { $_.IsReadOnly }).Count
        Write-Host "    DCs: $dcCount (including $rodcCount RODC)" -ForegroundColor Green

        if ($dcCount -gt 0) {
            Write-Host "    Probing DC connectivity..." -ForegroundColor DarkGray
            foreach ($dc in $discovery.DomainControllers) {
                $targetHost = if ($dc.HostName) { $dc.HostName } elseif ($dc.Domain) { "$($dc.Name).$($dc.Domain)" } else { $dc.Name }
                $status = 'Unreachable'
                $latency = $null
                $errorMsg = $null

                try {
                    $ping = Test-Connection -TargetName $targetHost -Count 1 -TimeoutSeconds 2 -ErrorAction Stop
                    if ($ping.Status -eq 'Success') {
                        $status = 'Reachable'
                        $latency = [math]::Round($ping.Latency, 1)
                    }
                } catch {
                    $errorMsg = $_.Exception.Message
                }

                $ldapOk = $false
                try {
                    $tcp = [System.Net.Sockets.TcpClient]::new()
                    $result = $tcp.BeginConnect($targetHost, 389, $null, $null)
                    $connected = $result.AsyncWaitHandle.WaitOne(2000, $false)
                    if ($connected -and $tcp.Connected) {
                        $ldapOk = $true
                    }
                    $tcp.Close()
                } catch {
                }

                $connectivity = if ($status -eq 'Reachable' -and $ldapOk) {
                    'OK'
                }
                elseif ($status -eq 'Reachable' -and -not $ldapOk) {
                    'ICMP only (LDAP unreachable)'
                }
                else {
                    'Unreachable'
                }

                $discovery.DCConnectivity.Add([ordered]@{
                    Name            = $dc.Name
                    HostName        = $targetHost
                    Domain          = $dc.Domain
                    IPv4Address     = $dc.IPv4Address
                    Site            = $dc.Site
                    OperatingSystem = $dc.OperatingSystem
                    IsGlobalCatalog = $dc.IsGlobalCatalog
                    IsReadOnly      = $dc.IsReadOnly
                    Status          = $connectivity
                    LatencyMs       = $latency
                    Error           = $errorMsg
                })
            }

            $okCount = @($discovery.DCConnectivity | Where-Object { $_.Status -eq 'OK' }).Count
            Write-Host "    Connectivity: $okCount/$dcCount DCs reachable on ICMP+LDAP" -ForegroundColor Green
        }
    } catch {
        Write-Warning "  Failed to enumerate DCs: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 3 — Computer classification (T0/T1/T2)
    # ================================================================
    Write-Host "  [3/8] Classifying computer objects by tier..." -ForegroundColor Yellow
    try {
        $classif = $TieringConfig.Classification
        $dcNames = @($discovery.DomainControllers | ForEach-Object { $_.Name })

        foreach ($domainName in $forest.Domains) {
            try {
                $computers = Get-ADComputer -Filter * -Properties Name, DistinguishedName, OperatingSystem, Enabled,
                    LastLogonTimestamp, ServicePrincipalName, Description, WhenCreated, IPv4Address -Server $domainName

                foreach ($comp in $computers) {
                    $dn = $comp.DistinguishedName
                    $spns = @($comp.ServicePrincipalName)
                    $name = $comp.Name
                    $os = $comp.OperatingSystem
                    $description = $comp.Description
                    $scoreBoard = @{
                        Tier0 = @{ Score = 0; Evidence = @() }
                        Tier1 = @{ Score = 0; Evidence = @() }
                        Tier2 = @{ Score = 0; Evidence = @() }
                    }

                    if ($name -in $dcNames) {
                        Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 100 -Evidence 'Domain Controller'
                    }

                    if ($classif.Tier0.SPNPatterns) {
                        foreach ($pattern in $classif.Tier0.SPNPatterns) {
                            if ($spns | Where-Object { $_ -like $pattern }) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 80 -Evidence "SPN match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier0.OUPatterns) {
                        foreach ($pattern in $classif.Tier0.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 60 -Evidence "OU match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier0.NamePatterns) {
                        foreach ($pattern in $classif.Tier0.NamePatterns) {
                            if ($name -like $pattern) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 40 -Evidence "Name match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier0.DescriptionPatterns) {
                        foreach ($pattern in $classif.Tier0.DescriptionPatterns) {
                            if ($description -and $description -match [regex]::Escape($pattern)) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 65 -Evidence "Description match: $pattern"
                            }
                        }
                    }

                    $entraConnectAssessment = Test-LikelyEntraConnectComputer -ComputerName $name -Description $description -ClassificationConfig $classif
                    if ($entraConnectAssessment.IsMatch) {
                        foreach ($signal in @($entraConnectAssessment.Signals)) {
                            Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier0' -Weight 30 -Evidence $signal
                        }
                    }

                    if ($os -and $os -match 'Server') {
                        Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier1' -Weight 20 -Evidence 'OS heuristic: Server OS detected'
                    }

                    if ($classif.Tier1.SPNPatterns) {
                        foreach ($pattern in $classif.Tier1.SPNPatterns) {
                            if ($spns | Where-Object { $_ -like $pattern }) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier1' -Weight 70 -Evidence "SPN match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier1.OUPatterns) {
                        foreach ($pattern in $classif.Tier1.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier1' -Weight 50 -Evidence "OU match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier1.NamePatterns) {
                        foreach ($pattern in $classif.Tier1.NamePatterns) {
                            if ($name -like $pattern) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier1' -Weight 35 -Evidence "Name match: $pattern"
                            }
                        }
                    }

                    if ($classif.Tier2.OUPatterns) {
                        foreach ($pattern in $classif.Tier2.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier2' -Weight 40 -Evidence "OU match: $pattern"
                            }
                        }
                    }

                    if ($os -and $os -notmatch 'Server') {
                        Add-ClassificationSignal -ScoreBoard $scoreBoard -Tier 'Tier2' -Weight 20 -Evidence 'OS heuristic: Workstation OS detected'
                    }

                    $classification = Resolve-ComputerTierProposal -ScoreBoard $scoreBoard -ComputerName $name
                    $tier = $classification.Tier
                    $reason = if ($classification.Evidence.Count -gt 0) {
                        ($classification.Evidence | Select-Object -First 3) -join '; '
                    }
                    else {
                        ''
                    }

                    $obj = [ordered]@{
                        Name            = $name
                        Domain          = $domainName
                        OperatingSystem = $os
                        Description     = $description
                        Enabled         = $comp.Enabled
                        Tier            = $tier
                        ProposedTier    = $tier
                        Confidence      = $classification.Confidence
                        Reason          = $reason
                        Evidence        = @($classification.Evidence)
                        ReviewRequired  = $classification.ReviewRequired
                        ReviewReason    = $classification.ReviewReason
                        Scores          = $classification.Scores
                        OU              = ($dn -replace '^CN=[^,]+,', '')
                        LastLogon       = if ($comp.LastLogonTimestamp) { [DateTime]::FromFileTime($comp.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
                        WhenCreated     = if ($comp.WhenCreated) { $comp.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                    }

                    $discovery.ComputersByTier[$tier] += @($obj)
                    if ($classification.ReviewRequired -or $tier -eq 'Unclassified') {
                        $discovery.ReviewQueue.Add([ordered]@{
                            Name            = $name
                            Domain          = $domainName
                            ProposedTier    = $tier
                            Confidence      = $classification.Confidence
                            ReviewReason    = $classification.ReviewReason
                            Evidence        = @($classification.Evidence)
                            OperatingSystem = $os
                            OU              = ($dn -replace '^CN=[^,]+,', '')
                        })
                    }
                }
            } catch {
                Write-Warning "  Could not classify computers in $domainName : $($_.Exception.Message)"
            }
        }

        $t0 = $discovery.ComputersByTier.Tier0.Count
        $t1 = $discovery.ComputersByTier.Tier1.Count
        $t2 = $discovery.ComputersByTier.Tier2.Count
        $un = $discovery.ComputersByTier.Unclassified.Count
        $reviewCount = $discovery.ReviewQueue.Count
        $discovery.ClassificationSummary = [ordered]@{
            Tier0       = $t0
            Tier1       = $t1
            Tier2       = $t2
            Unclassified = $un
            ReviewQueue = $reviewCount
        }
        Write-Host "    T0: $t0 | T1: $t1 | T2: $t2 | Unclassified: $un | Review: $reviewCount" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to classify computers: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 4 — Privileged accounts
    # ================================================================
    Write-Host "  [4/8] Enumerating privileged accounts..." -ForegroundColor Yellow
    try {
        $privilegedGroups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Server Operators'
            'Backup Operators'
            'Print Operators'
            'DnsAdmins'
            'Group Policy Creator Owners'
            'Cert Publishers'
        )

        foreach ($domainName in $forest.Domains) {
            try {
                foreach ($groupName in $privilegedGroups) {
                    try {
                        $members = @(Get-ADGroupMember -Identity $groupName -Server $domainName -Recursive -ErrorAction SilentlyContinue)

                        if ($members) {
                            $enriched = foreach ($m in $members) {
                                try {
                                    switch -Regex ($m.objectClass) {
                                        '^user$' {
                                            $user = Get-ADUser -Identity $m.SID -Server $domainName -Properties Enabled, PasswordLastSet,
                                                LastLogonTimestamp, AdminCount, PasswordNeverExpires, ServicePrincipalName,
                                                WhenCreated, Description, MemberOf -ErrorAction SilentlyContinue
                                            if (-not $user) { break }

                                            $hasSPN = (@($user.ServicePrincipalName).Count -gt 0)
                                            $serviceAccountAssessment = Test-LikelyServiceAccount -SamAccountName $user.SamAccountName -Description $user.Description -HasSPN $hasSPN

                                            [ordered]@{
                                                SamAccountName        = $user.SamAccountName
                                                Domain                = $domainName
                                                Group                 = $groupName
                                                ObjectClass           = 'user'
                                                ManagedServiceType    = $null
                                                Enabled               = $user.Enabled
                                                IsServiceAccount      = $serviceAccountAssessment.IsServiceAccount
                                                ServiceAccountSignals = @($serviceAccountAssessment.Signals)
                                                HasSPN                = $hasSPN
                                                PasswordNeverExpires  = $user.PasswordNeverExpires
                                                PasswordLastSet       = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
                                                LastLogon             = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
                                                AdminCount            = $user.AdminCount
                                                Description           = $user.Description
                                            }
                                            break
                                        }
                                        '^msDS-GroupManagedServiceAccount$|^msDS-ManagedServiceAccount$' {
                                            $svc = Get-ADServiceAccount -Identity $m.DistinguishedName -Server $domainName -Properties Enabled, PasswordLastSet,
                                                ServicePrincipalName, WhenCreated, Description, ObjectClass -ErrorAction SilentlyContinue
                                            if (-not $svc) { break }

                                            $svcType = if ($svc.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
                                            $hasSPN = (@($svc.ServicePrincipalName).Count -gt 0)

                                            [ordered]@{
                                                SamAccountName        = $svc.SamAccountName
                                                Domain                = $domainName
                                                Group                 = $groupName
                                                ObjectClass           = $svc.ObjectClass
                                                ManagedServiceType    = $svcType
                                                Enabled               = $svc.Enabled
                                                IsServiceAccount      = $true
                                                ServiceAccountSignals = @('Managed service account', $svcType)
                                                HasSPN                = $hasSPN
                                                PasswordNeverExpires  = $true
                                                PasswordLastSet       = if ($svc.PasswordLastSet) { $svc.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Managed' }
                                                LastLogon             = 'N/A'
                                                AdminCount            = $null
                                                Description           = $svc.Description
                                            }
                                            break
                                        }
                                    }
                                } catch { $null }
                            }

                            $key = "$domainName\$groupName"
                            $discovery.PrivilegedAccounts[$key] = @($enriched | Where-Object { $_ })
                        }
                    } catch { }
                }
            } catch {
                Write-Warning "  Could not enumerate privileged groups in $domainName : $($_.Exception.Message)"
            }
        }

        $totalPriv  = ($discovery.PrivilegedAccounts.Values | ForEach-Object { $_ } | ForEach-Object { $_.SamAccountName } | Select-Object -Unique).Count
        $daCount    = ($discovery.PrivilegedAccounts.Keys | Where-Object { $_ -like '*\Domain Admins' } |
            ForEach-Object { $discovery.PrivilegedAccounts[$_] } | ForEach-Object { $_ } |
            ForEach-Object { $_.SamAccountName } | Select-Object -Unique).Count
        Write-Host "    Unique privileged accounts: $totalPriv | Domain Admins: $daCount" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to enumerate privileged accounts: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 5 — Managed service accounts, auth policies/silos, service accounts in Domain Admins & AdminCount orphans
    # ================================================================
    Write-Host "  [5/8] Detecting managed service accounts, auth policies/silos, service accounts in DA & adminCount orphans..." -ForegroundColor Yellow
    try {
        $gmsaAccounts = @()
        $msaAccounts = @()

        foreach ($domainName in $forest.Domains) {
            try {
                $allServiceAccounts = @(Get-ADServiceAccount -Filter * -Server $domainName -Properties Enabled, Description,
                    ServicePrincipalName, PasswordLastSet, WhenCreated, PrincipalsAllowedToRetrieveManagedPassword,
                    'msDS-ManagedPasswordInterval', ObjectClass -ErrorAction SilentlyContinue)

                foreach ($svc in @($allServiceAccounts | Where-Object { $_.ObjectClass -eq 'msDS-GroupManagedServiceAccount' })) {
                    $principals = @($svc.PrincipalsAllowedToRetrieveManagedPassword | Where-Object { $_ })
                    $gmsaAccounts += [ordered]@{
                        SamAccountName    = $svc.SamAccountName
                        DistinguishedName = $svc.DistinguishedName
                        Domain            = $domainName
                        Enabled           = $svc.Enabled
                        PasswordLastSet   = if ($svc.PasswordLastSet) { $svc.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Managed' }
                        PasswordInterval  = $svc.'msDS-ManagedPasswordInterval'
                        PrincipalsAllowed = @($principals)
                        PrincipalsCount   = $principals.Count
                        Description       = $svc.Description
                        HasSPN            = (@($svc.ServicePrincipalName).Count -gt 0)
                        WhenCreated       = if ($svc.WhenCreated) { $svc.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                        Type              = 'gMSA'
                    }
                }

                $domainDN = (Get-ADDomain -Server $domainName -ErrorAction SilentlyContinue).DistinguishedName
                if ($domainDN) {
                    $standaloneMsas = @(Get-ADServiceAccount -Filter * -SearchBase "CN=Managed Service Accounts,$domainDN" -Server $domainName `
                        -Properties PasswordLastSet, WhenCreated, Description, ObjectClass, Enabled, ServicePrincipalName `
                        -ErrorAction SilentlyContinue | Where-Object { $_.ObjectClass -eq 'msDS-ManagedServiceAccount' })

                    foreach ($svc in $standaloneMsas) {
                        $msaAccounts += [ordered]@{
                            SamAccountName    = $svc.SamAccountName
                            DistinguishedName = $svc.DistinguishedName
                            Domain            = $domainName
                            Enabled           = $svc.Enabled
                            PasswordLastSet   = if ($svc.PasswordLastSet) { $svc.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
                            Description       = $svc.Description
                            HasSPN            = (@($svc.ServicePrincipalName).Count -gt 0)
                            WhenCreated       = if ($svc.WhenCreated) { $svc.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                            Type              = 'sMSA'
                        }
                    }
                }
            } catch { }
        }

        $discovery.ManagedServiceAccounts = [ordered]@{
            GMSA = @($gmsaAccounts)
            MSA  = @($msaAccounts)
        }

        $authPolicies = @()
        $authSilos = @()
        try {
            $rootDomain = $forest.RootDomain
            $policies = @(Get-ADAuthenticationPolicy -Filter * -Server $rootDomain -ErrorAction SilentlyContinue)
            foreach ($policy in $policies) {
                $authPolicies += [ordered]@{
                    Name              = $policy.Name
                    DistinguishedName = $policy.DistinguishedName
                    Enforce           = [bool]$policy.Enforce
                    Description       = $policy.Description
                }
            }

            $silos = @(Get-ADAuthenticationPolicySilo -Filter * -Server $rootDomain -ErrorAction SilentlyContinue)
            foreach ($silo in $silos) {
                $members = @()
                try {
                    $members = @(Get-ADAuthenticationPolicySilo -Identity $silo.Name -Server $rootDomain -Properties Members -ErrorAction SilentlyContinue).Members
                } catch { }

                $authSilos += [ordered]@{
                    Name              = $silo.Name
                    DistinguishedName = $silo.DistinguishedName
                    Enforce           = [bool]$silo.Enforce
                    MemberCount       = @($members).Count
                    Members           = @($members)
                    UserPolicy        = $silo.UserAuthenticationPolicy
                    ComputerPolicy    = $silo.ComputerAuthenticationPolicy
                    ServicePolicy     = $silo.ServiceAuthenticationPolicy
                    Description       = $silo.Description
                }
            }
        } catch {
            Write-Verbose "    Cannot enumerate Authentication Policies/Silos: $($_.Exception.Message)"
        }

        $assignedMembers = @($authSilos | Measure-Object -Property MemberCount -Sum).Sum
        if ($null -eq $assignedMembers) { $assignedMembers = 0 }
        $discovery.AuthenticationControls = [ordered]@{
            Policies = @($authPolicies)
            Silos    = @($authSilos)
            Summary  = [ordered]@{
                PolicyCount      = @($authPolicies).Count
                EnforcedPolicies = @($authPolicies | Where-Object { $_.Enforce }).Count
                SiloCount        = @($authSilos).Count
                EnforcedSilos    = @($authSilos | Where-Object { $_.Enforce }).Count
                AuditOnlySilos   = @($authSilos | Where-Object { -not $_.Enforce }).Count
                AssignedMembers  = $assignedMembers
            }
        }

        # Service accounts in Domain Admins
        $daKeys = $discovery.PrivilegedAccounts.Keys | Where-Object { $_ -like '*\Domain Admins' }
        $svcInDA = foreach ($key in $daKeys) {
            $discovery.PrivilegedAccounts[$key] | Where-Object { $_.IsServiceAccount -or $_.HasSPN }
        }
        $discovery.ServiceAccountsInDA = @($svcInDA | Where-Object { $_ })

        # AdminCount orphans — accounts with adminCount=1 but NOT in any privileged group
        $allPrivSams = $discovery.PrivilegedAccounts.Values | ForEach-Object { $_ } |
            ForEach-Object { $_.SamAccountName } | Select-Object -Unique

        foreach ($domainName in $forest.Domains) {
            try {
                $adminCountUsers = Get-ADUser -Filter 'AdminCount -eq 1' -Properties SamAccountName, AdminCount -Server $domainName
                $orphans = $adminCountUsers | Where-Object { $_.SamAccountName -notin $allPrivSams }
                $discovery.AdminCountOrphans += @($orphans | ForEach-Object {
                    [ordered]@{
                        SamAccountName = $_.SamAccountName
                        Domain         = $domainName
                    }
                })
            } catch { }
        }

        $svcInDACount = $discovery.ServiceAccountsInDA.Count
        $gmsaCount = $discovery.ManagedServiceAccounts.GMSA.Count
        $msaCount = $discovery.ManagedServiceAccounts.MSA.Count
        $authPolicyCount = $discovery.AuthenticationControls.Summary.PolicyCount
        $authSiloCount = $discovery.AuthenticationControls.Summary.SiloCount
        $orphanCount  = $discovery.AdminCountOrphans.Count
        Write-Host "    gMSA: $gmsaCount | sMSA: $msaCount | Auth Policies: $authPolicyCount | Silos: $authSiloCount | Service accounts in DA: $svcInDACount | AdminCount orphans: $orphanCount" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed service account detection: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 6 — Current OU structure
    # ================================================================
    Write-Host "  [6/8] Mapping current OU structure..." -ForegroundColor Yellow
    try {
        foreach ($domainName in $forest.Domains) {
            try {
                $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName, Description, gPLink -Server $domainName
                foreach ($ou in $ous) {
                    $depth = ($ou.DistinguishedName -split ',' | Where-Object { $_ -match '^OU=' }).Count
                    $hasGPO = [bool]$ou.gPLink
                    $discovery.OUStructure += @([ordered]@{
                        Name              = $ou.Name
                        DistinguishedName = $ou.DistinguishedName
                        Domain            = $domainName
                        Depth             = $depth
                        HasGPOLinked      = $hasGPO
                        Description       = $ou.Description
                    })
                }
            } catch { }
        }

        $expectedTieringNames = @(
            $TieringConfig.OUStructure.ContainerOU
            $TieringConfig.OUStructure.Tier0
            $TieringConfig.OUStructure.Tier1
            $TieringConfig.OUStructure.Tier2
            $TieringConfig.OUStructure.Quarantine
            $TieringConfig.OUStructure.Disabled
            $TieringConfig.OUStructure.StandardUsers
        ) + @($TieringConfig.OUStructure.SubOUs.Tier0) + @($TieringConfig.OUStructure.SubOUs.Tier1) + @($TieringConfig.OUStructure.SubOUs.Tier2) + @($TieringConfig.OUStructure.QuarantineSubOUs) + @($TieringConfig.OUStructure.DisabledSubOUs)

        $tieringOUs = $discovery.OUStructure | Where-Object {
            $_.Name -in $expectedTieringNames
        }
        $discovery.ExistingTiering = [ordered]@{
            DetectedOUCount = @($tieringOUs).Count
            DetectedOUs     = @($tieringOUs | ForEach-Object { $_.DistinguishedName })
        }

        $ouCount = $discovery.OUStructure.Count
        $tierOUCount = $tieringOUs.Count
        Write-Host "    Total OUs: $ouCount | Tiering OUs already present: $tierOUCount" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to map OUs: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 7 — GPO inventory
    # ================================================================
    Write-Host "  [7/8] Inventorying GPOs and links..." -ForegroundColor Yellow
    try {
        foreach ($domainName in $forest.Domains) {
            try {
                $gpos = Get-ADObject -Filter { objectClass -eq 'groupPolicyContainer' } `
                    -Properties DisplayName, gPCFileSysPath, WhenCreated, WhenChanged -Server $domainName

                foreach ($gpo in $gpos) {
                    $discovery.GPOs += @([ordered]@{
                        DisplayName = $gpo.DisplayName
                        DN          = $gpo.DistinguishedName
                        Domain      = $domainName
                        WhenCreated = if ($gpo.WhenCreated) { $gpo.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                        WhenChanged = if ($gpo.WhenChanged) { $gpo.WhenChanged.ToString('yyyy-MM-dd') } else { '' }
                    })
                }

                # GPO links on OUs
                $linked = Get-ADObject -Filter { gPLink -like "*" } `
                    -Properties DistinguishedName, gPLink -Server $domainName -SearchScope Subtree |
                    Where-Object { $_.gPLink }

                foreach ($obj in $linked) {
                    $links = [regex]::Matches($obj.gPLink, '\[LDAP://([^\]]+);(\d)\]')
                    foreach ($link in $links) {
                        $gpoDN = $link.Groups[1].Value
                        $flags = [int]$link.Groups[2].Value
                        $enforced = ($flags -band 2) -ne 0
                        $disabled = ($flags -band 1) -ne 0
                        $gpoDisplay = ($discovery.GPOs | Where-Object { $_.DN -eq $gpoDN } | Select-Object -First 1).DisplayName

                        $discovery.GPOLinks += @([ordered]@{
                            GPOName    = $gpoDisplay
                            GPODN     = $gpoDN
                            LinkedTo   = $obj.DistinguishedName
                            Domain     = $domainName
                            Enforced   = $enforced
                            Disabled   = $disabled
                        })
                    }
                }
            } catch { }
        }

        $gpoCount  = $discovery.GPOs.Count
        $linkCount = $discovery.GPOLinks.Count
        # Check for existing tiering GPOs
        $tierGPOs = $discovery.GPOs | Where-Object { $_.DisplayName -match 'Tier|Tiering|Deny.*Logon|PAW|Hardening' }
        Write-Host "    GPOs: $gpoCount | Links: $linkCount | Tiering-related GPOs: $($tierGPOs.Count)" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to inventory GPOs: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 8 — Trusts
    # ================================================================
    Write-Host "  [8/8] Assessing trust relationships..." -ForegroundColor Yellow
    try {
        $trustKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($domainName in $forest.Domains) {
            try {
                $trusts = Get-ADTrust -Filter * -Server $domainName -Properties *
                foreach ($trust in $trusts) {
                    $trustKey = "$domainName|$($trust.Target)|$($trust.Direction)|$($trust.TrustType)|$($trust.IntraForest)"
                    if (-not $trustKeys.Add($trustKey)) { continue }

                    $discovery.Trusts += @([ordered]@{
                        Source              = $domainName
                        Target              = $trust.Target
                        TrustType           = $trust.TrustType.ToString()
                        Direction           = $trust.Direction.ToString()
                        ForestTransitive    = $trust.ForestTransitive
                        SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
                        SIDFilteringForestAware = $trust.SIDFilteringForestAware
                        SelectiveAuth       = $trust.SelectiveAuthentication
                        IntraForest         = $trust.IntraForest
                        WhenCreated         = if ($trust.WhenCreated) { $trust.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                    })
                }
            } catch { }
        }

        $trustCount = $discovery.Trusts.Count
        $noSIDFilter = ($discovery.Trusts | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest }).Count
        Write-Host "    Trusts: $trustCount | External without SID filtering: $noSIDFilter" -ForegroundColor Green
    } catch {
        Write-Warning "  Failed to assess trusts: $($_.Exception.Message)"
    }

    # ================================================================
    # Current State Summary
    # ================================================================
    Write-Host "`n  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "   Current State Summary" -ForegroundColor Cyan
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray

    $observations = [ordered]@{}

    # Observation 1 — Functional level
    $flDetail = ($discovery.Domains | ForEach-Object { "$($_.Name): $($_.DomainMode)" }) -join ' | '
    $observations['Domain Functional Level'] = $flDetail

    # Observation 2 — Domain Admins count
    $allDA = $discovery.PrivilegedAccounts.Keys | Where-Object { $_ -like '*\Domain Admins' } |
        ForEach-Object { $discovery.PrivilegedAccounts[$_] } | ForEach-Object { $_ }
    $daUniqueCount = ($allDA | ForEach-Object { $_.SamAccountName } | Select-Object -Unique).Count
    $observations['Domain Admins members'] = "$daUniqueCount account(s)"

    # Observation 2b — Directory counts
    $observations['Directory objects'] = "Users: $($discovery.DirectoryCounts.Users) | Groups: $($discovery.DirectoryCounts.Groups)"

    # Observation 3 — Enterprise Admins
    $allEA = $discovery.PrivilegedAccounts.Keys | Where-Object { $_ -like '*\Enterprise Admins' } |
        ForEach-Object { $discovery.PrivilegedAccounts[$_] } | ForEach-Object { $_ }
    $eaCount = ($allEA | ForEach-Object { $_.SamAccountName } | Select-Object -Unique).Count
    $observations['Enterprise Admins members'] = "$eaCount account(s)"

    # Observation 4 — Service accounts in DA
    $observations['Service accounts in Domain Admins'] = "$($discovery.ServiceAccountsInDA.Count) found"

    # Observation 4b — Managed service accounts
    $observations['Managed service accounts'] = "gMSA: $($discovery.ManagedServiceAccounts.GMSA.Count) | sMSA: $($discovery.ManagedServiceAccounts.MSA.Count)"

    # Observation 4c — Managed service accounts in privileged groups
    $managedServiceInPriv = @($discovery.ServiceAccountsInDA | Where-Object { $_.ManagedServiceType })
    $observations['Managed service accounts in privileged groups'] = if ($managedServiceInPriv.Count -gt 0) {
        "$(($managedServiceInPriv | Where-Object ManagedServiceType -eq 'gMSA').Count) gMSA | $(($managedServiceInPriv | Where-Object ManagedServiceType -eq 'sMSA').Count) sMSA"
    }
    else {
        'None detected'
    }

    # Observation 5 — AdminCount orphans
    $observations['AdminCount orphans'] = "$($discovery.AdminCountOrphans.Count) account(s)"

    # Observation 5b — Authentication policies and silos
    $authSummary = $discovery.AuthenticationControls.Summary
    $observations['Authentication policies & silos'] = "Policies: $($authSummary.PolicyCount) ($($authSummary.EnforcedPolicies) enforced) | Silos: $($authSummary.SiloCount) ($($authSummary.EnforcedSilos) enforced, $($authSummary.AuditOnlySilos) audit-only) | Assigned members: $($authSummary.AssignedMembers)"

    # Observation 6 — Password policy
    $observations['Password policy'] = ($discovery.Domains | ForEach-Object { "$($_.Name): min $($_.MinPwdLength) chars, lockout $($_.LockoutThreshold)" }) -join ' | '

    # Observation 7 — MachineAccountQuota
    $observations['MachineAccountQuota'] = ($discovery.Domains | ForEach-Object { "$($_.Name): $($_.MachineAccountQuota)" }) -join ' | '

    # Observation 8 — Trusts
    $unsafeTrusts = $discovery.Trusts | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest }
    $observations['Trust relationships'] = "$($discovery.Trusts.Count) total, $($unsafeTrusts.Count) external without SID filtering"

    # Observation 9 — Computer classification
    $observations['Computers classified'] = "T0: $($discovery.ComputersByTier.Tier0.Count) | T1: $($discovery.ComputersByTier.Tier1.Count) | T2: $($discovery.ComputersByTier.Tier2.Count) | Unclassified: $($discovery.ComputersByTier.Unclassified.Count)"
    $observations['Review queue'] = "$($discovery.ReviewQueue.Count) computer(s) require validation"

    # Observation 10 — Existing tiering footprint
    $observations['Existing tiering footprint'] = "$($discovery.ExistingTiering.DetectedOUCount) expected tiering OU(s) detected"

    $blockers = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $recommendations = [System.Collections.Generic.List[string]]::new()

    if (-not $discovery.Forest -or $discovery.Domains.Count -eq 0) {
        $blockers.Add('Forest or domain discovery failed; tiering preparation data is incomplete')
    }
    if ($discovery.DomainControllers.Count -eq 0) {
        $blockers.Add('No domain controllers were discovered; stop before any tiering deployment')
    }
    if ($discovery.ServiceAccountsInDA.Count -gt 0) {
        $warnings.Add('Service accounts remain in Domain Admins and should be remediated before tiering')
        $recommendations.Add('Remove service accounts from Domain Admins and replace with least-privilege delegation')
    }
    if ($managedServiceInPriv.Count -gt 0) {
        $warnings.Add('Managed service accounts were found in privileged groups and should be reviewed before tiering')
        $recommendations.Add('Remove gMSA and sMSA objects from privileged groups and use scoped delegation or resource ACLs instead')
    }
    if ($authSummary.PolicyCount -eq 0 -and $authSummary.SiloCount -eq 0) {
        $recommendations.Add('No Authentication Policies or Silos are currently deployed. Capture this in the Phase 0 baseline and plan the target design in Phase 4 once tiers are validated')
    }
    elseif ($authSummary.SiloCount -gt 0 -and $authSummary.AuditOnlySilos -gt 0) {
        $warnings.Add('One or more Authentication Policy Silos are present but still in audit mode')
        $recommendations.Add('Review the silos discovered in Phase 0 and decide whether they should remain in audit mode or move to enforcement during Phase 4')
    }
    elseif ($authSummary.PolicyCount -gt 0 -and $authSummary.SiloCount -eq 0) {
        $warnings.Add('Authentication Policies exist without any Authentication Policy Silo assignments')
        $recommendations.Add('Review whether the discovered Authentication Policies are still used or should be tied to silos in the target tiering design')
    }
    $unsafeTrusts = @($discovery.Trusts | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest })
    if ($unsafeTrusts.Count -gt 0) {
        $warnings.Add('One or more external trusts do not enforce SID filtering')
        $recommendations.Add('Review external trusts and enable SID filtering where appropriate before tiering rollout')
    }
    if ($discovery.AdminCountOrphans.Count -gt 0) {
        $warnings.Add('AdminCount orphaned accounts were detected and may indicate stale privileged protections')
        $recommendations.Add('Review AdminCount orphaned accounts and clean up privileged remnants before migrating identities')
    }
    if ($discovery.ReviewQueue.Count -gt 0) {
        $warnings.Add('Some computer classifications require manual validation')
        $recommendations.Add('Review the classification queue before using discovery output to drive tier placement decisions')
    }

    $readinessStatus = if ($blockers.Count -gt 0) {
        'Blocked'
    }
    elseif ($warnings.Count -gt 0) {
        'ReadyWithWarnings'
    }
    else {
        'Ready'
    }

    $discovery.Readiness = [ordered]@{
        Status          = $readinessStatus
        Blockers        = @($blockers)
        Warnings        = @($warnings)
        Recommendations = @($recommendations | Select-Object -Unique)
    }

    $priorityActions = [System.Collections.Generic.List[object]]::new()
    $priorityRank = 1

    if ($discovery.ServiceAccountsInDA.Count -gt 0) {
        $priorityActions.Add([ordered]@{
            Priority = $priorityRank++
            Title    = 'Remove service accounts from Domain Admins'
            Severity = 'High'
            Detail   = "$($discovery.ServiceAccountsInDA.Count) service, gMSA, sMSA or SPN-bearing account(s) remain in Domain Admins"
        })
    }
    if ($discovery.AdminCountOrphans.Count -gt 0) {
        $priorityActions.Add([ordered]@{
            Priority = $priorityRank++
            Title    = 'Clean AdminCount orphaned accounts'
            Severity = 'Medium'
            Detail   = "$($discovery.AdminCountOrphans.Count) account(s) still have adminCount=1 without matching privileged group membership"
        })
    }
    if ($discovery.ReviewQueue.Count -gt 0) {
        $priorityActions.Add([ordered]@{
            Priority = $priorityRank++
            Title    = 'Validate manual classification queue'
            Severity = 'Medium'
            Detail   = "$($discovery.ReviewQueue.Count) computer(s) need human validation before they are used for tier placement"
        })
    }
    if ($authSummary.SiloCount -gt 0 -and $authSummary.AuditOnlySilos -gt 0) {
        $priorityActions.Add([ordered]@{
            Priority = $priorityRank++
            Title    = 'Review existing Authentication Policy Silos'
            Severity = 'Medium'
            Detail   = "$($authSummary.AuditOnlySilos) discovered silo(s) are still in audit mode and should be validated before enforcement planning"
        })
    }
    if ($unsafeTrusts.Count -gt 0) {
        $priorityActions.Add([ordered]@{
            Priority = $priorityRank++
            Title    = 'Review external trusts without SID filtering'
            Severity = 'High'
            Detail   = "$($unsafeTrusts.Count) external trust(s) do not enforce SID filtering"
        })
    }
    if ($priorityActions.Count -eq 0) {
        $priorityActions.Add([ordered]@{
            Priority = 1
            Title    = 'Proceed to Phase 1 design review'
            Severity = 'Info'
            Detail   = 'No urgent blockers were identified by the current Phase 0 review. Validate the proposed tiers and prepare the OU and group model.'
        })
    }
    $discovery.PriorityActions = $priorityActions
    $observations['Tiering readiness'] = $readinessStatus

    $discovery.Observations = $observations

    foreach ($name in $observations.Keys) {
        Write-Host "    $name : $($observations[$name])" -ForegroundColor White
    }

    # ================================================================
    # Generate HTML Report
    # ================================================================
    Write-Host "`n  [>] Generating discovery report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Discovery-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringDiscoveryHtml -Discovery $discovery -OutputPath $htmlPath

    # ================================================================
    # Export JSON data
    # ================================================================
    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Discovery-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $discovery | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 0 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   Report: $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    # Offer to open the report in the default browser
    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') {
        Start-Process $htmlPath
    }

    return $discovery
}

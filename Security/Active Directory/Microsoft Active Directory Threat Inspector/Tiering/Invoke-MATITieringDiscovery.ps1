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
        ComputersByTier     = [ordered]@{ Tier0 = @(); Tier1 = @(); Tier2 = @(); Unclassified = @() }
        PrivilegedAccounts  = [ordered]@{}
        AdminCountOrphans   = @()
        ServiceAccountsInDA = @()
        OUStructure         = @()
        GPOs                = @()
        GPOLinks            = @()
        Trusts              = @()
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
            } catch {
                Write-Warning "  Could not query domain $domainName : $($_.Exception.Message)"
            }
        }
        Write-Host "    Forest: $($forest.Name) | Domains: $($forest.Domains.Count) | Sites: $($forest.Sites.Count)" -ForegroundColor Green
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
    } catch {
        Write-Warning "  Failed to enumerate DCs: $($_.Exception.Message)"
    }

    # ================================================================
    # Step 3 — Computer classification (T0/T1/T2)
    # ================================================================
    Write-Host "  [3/8] Classifying computer objects by tier..." -ForegroundColor Yellow
    try {
        $classif = $TieringConfig.Classification
        $dcDNs   = $discovery.DomainControllers | ForEach-Object { $_.Name }

        foreach ($domainName in $forest.Domains) {
            try {
                $computers = Get-ADComputer -Filter * -Properties Name, DistinguishedName, OperatingSystem, Enabled,
                    LastLogonTimestamp, ServicePrincipalName, Description, WhenCreated, IPv4Address -Server $domainName

                foreach ($comp in $computers) {
                    $tier = 'Unclassified'
                    $reason = ''
                    $dn = $comp.DistinguishedName
                    $spns = @($comp.ServicePrincipalName)
                    $name = $comp.Name
                    $os = $comp.OperatingSystem

                    # --- Tier 0 checks ---
                    # DCs are always T0
                    if ($name -in $dcDNs) {
                        $tier = 'Tier0'; $reason = 'Domain Controller'
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier0.SPNPatterns) {
                        foreach ($pattern in $classif.Tier0.SPNPatterns) {
                            if ($spns | Where-Object { $_ -like $pattern }) {
                                $tier = 'Tier0'; $reason = "SPN match: $pattern"; break
                            }
                        }
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier0.OUPatterns) {
                        foreach ($pattern in $classif.Tier0.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                $tier = 'Tier0'; $reason = "OU match: $pattern"; break
                            }
                        }
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier0.NamePatterns) {
                        foreach ($pattern in $classif.Tier0.NamePatterns) {
                            if ($name -like $pattern) {
                                $tier = 'Tier0'; $reason = "Name match: $pattern"; break
                            }
                        }
                    }

                    # --- Tier 1 checks ---
                    if ($tier -eq 'Unclassified' -and $os -and $os -match 'Server') {
                        $tier = 'Tier1'; $reason = 'Server OS detected'
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier1.SPNPatterns) {
                        foreach ($pattern in $classif.Tier1.SPNPatterns) {
                            if ($spns | Where-Object { $_ -like $pattern }) {
                                $tier = 'Tier1'; $reason = "SPN match: $pattern"; break
                            }
                        }
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier1.OUPatterns) {
                        foreach ($pattern in $classif.Tier1.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                $tier = 'Tier1'; $reason = "OU match: $pattern"; break
                            }
                        }
                    }

                    if ($tier -eq 'Unclassified' -and $classif.Tier1.NamePatterns) {
                        foreach ($pattern in $classif.Tier1.NamePatterns) {
                            if ($name -like $pattern) {
                                $tier = 'Tier1'; $reason = "Name match: $pattern"; break
                            }
                        }
                    }

                    # --- Tier 2 checks ---
                    if ($tier -eq 'Unclassified' -and $classif.Tier2.OUPatterns) {
                        foreach ($pattern in $classif.Tier2.OUPatterns) {
                            if ($dn -match [regex]::Escape($pattern)) {
                                $tier = 'Tier2'; $reason = "OU match: $pattern"; break
                            }
                        }
                    }

                    # Default: non-server OS → Tier 2
                    if ($tier -eq 'Unclassified' -and $os -and $os -notmatch 'Server') {
                        $tier = 'Tier2'; $reason = 'Workstation OS (default)'
                    }

                    $obj = [ordered]@{
                        Name            = $name
                        Domain          = $domainName
                        OperatingSystem = $os
                        Enabled         = $comp.Enabled
                        Tier            = $tier
                        Reason          = $reason
                        OU              = ($dn -replace '^CN=[^,]+,', '')
                        LastLogon       = if ($comp.LastLogonTimestamp) { [DateTime]::FromFileTime($comp.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
                        WhenCreated     = if ($comp.WhenCreated) { $comp.WhenCreated.ToString('yyyy-MM-dd') } else { '' }
                    }

                    $discovery.ComputersByTier[$tier] += @($obj)
                }
            } catch {
                Write-Warning "  Could not classify computers in $domainName : $($_.Exception.Message)"
            }
        }

        $t0 = $discovery.ComputersByTier.Tier0.Count
        $t1 = $discovery.ComputersByTier.Tier1.Count
        $t2 = $discovery.ComputersByTier.Tier2.Count
        $un = $discovery.ComputersByTier.Unclassified.Count
        Write-Host "    T0: $t0 | T1: $t1 | T2: $t2 | Unclassified: $un" -ForegroundColor Green
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
                        $members = Get-ADGroupMember -Identity $groupName -Server $domainName -Recursive -ErrorAction SilentlyContinue |
                            Where-Object { $_.objectClass -eq 'user' }

                        if ($members) {
                            $enriched = foreach ($m in $members) {
                                try {
                                    $user = Get-ADUser -Identity $m.SID -Server $domainName -Properties Enabled, PasswordLastSet,
                                        LastLogonTimestamp, AdminCount, PasswordNeverExpires, ServicePrincipalName,
                                        WhenCreated, Description, MemberOf -ErrorAction SilentlyContinue

                                    $isSvc = $user.SamAccountName -match 'svc|service|sql|app|batch|task|scan|backup|agent'
                                    $hasSPN = ($user.ServicePrincipalName.Count -gt 0)

                                    [ordered]@{
                                        SamAccountName      = $user.SamAccountName
                                        Domain              = $domainName
                                        Group               = $groupName
                                        Enabled             = $user.Enabled
                                        IsServiceAccount    = $isSvc
                                        HasSPN              = $hasSPN
                                        PasswordNeverExpires = $user.PasswordNeverExpires
                                        PasswordLastSet     = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Never' }
                                        LastLogon           = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
                                        AdminCount          = $user.AdminCount
                                        Description         = $user.Description
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
    # Step 5 — Service accounts in Domain Admins & AdminCount orphans
    # ================================================================
    Write-Host "  [5/8] Detecting service accounts in DA & adminCount orphans..." -ForegroundColor Yellow
    try {
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
        $orphanCount  = $discovery.AdminCountOrphans.Count
        Write-Host "    Service accounts in DA: $svcInDACount | AdminCount orphans: $orphanCount" -ForegroundColor Green
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

        # Check if tiering OUs already exist
        $tieringOUs = $discovery.OUStructure | Where-Object {
            $_.Name -match '^Tier\s*[012]$|^Quarantine$|^Disabled$'
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
        foreach ($domainName in $forest.Domains) {
            try {
                $trusts = Get-ADTrust -Filter * -Server $domainName -Properties *
                foreach ($trust in $trusts) {
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

    # Observation 3 — Enterprise Admins
    $allEA = $discovery.PrivilegedAccounts.Keys | Where-Object { $_ -like '*\Enterprise Admins' } |
        ForEach-Object { $discovery.PrivilegedAccounts[$_] } | ForEach-Object { $_ }
    $eaCount = ($allEA | ForEach-Object { $_.SamAccountName } | Select-Object -Unique).Count
    $observations['Enterprise Admins members'] = "$eaCount account(s)"

    # Observation 4 — Service accounts in DA
    $observations['Service accounts in Domain Admins'] = "$($discovery.ServiceAccountsInDA.Count) found"

    # Observation 5 — AdminCount orphans
    $observations['AdminCount orphans'] = "$($discovery.AdminCountOrphans.Count) account(s)"

    # Observation 6 — Password policy
    $observations['Password policy'] = ($discovery.Domains | ForEach-Object { "$($_.Name): min $($_.MinPwdLength) chars, lockout $($_.LockoutThreshold)" }) -join ' | '

    # Observation 7 — MachineAccountQuota
    $observations['MachineAccountQuota'] = ($discovery.Domains | ForEach-Object { "$($_.Name): $($_.MachineAccountQuota)" }) -join ' | '

    # Observation 8 — Trusts
    $unsafeTrusts = $discovery.Trusts | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest }
    $observations['Trust relationships'] = "$($discovery.Trusts.Count) total, $($unsafeTrusts.Count) external without SID filtering"

    # Observation 9 — Computer classification
    $observations['Computers classified'] = "T0: $($discovery.ComputersByTier.Tier0.Count) | T1: $($discovery.ComputersByTier.Tier1.Count) | T2: $($discovery.ComputersByTier.Tier2.Count) | Unclassified: $($discovery.ComputersByTier.Unclassified.Count)"

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

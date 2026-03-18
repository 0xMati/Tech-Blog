# Tiering\Invoke-MATITieringPhase2.ps1
# Phase 2 — Tiered Admin Accounts
# Creates dedicated admin accounts per tier from auto-discovery or CSV import,
# applies T0 hardening (Protected Users + AccountNotDelegated), and generates an HTML report.

function Invoke-MATITieringPhase2 {
    <#
    .SYNOPSIS
        Phase 2 — Interactive creation of tiered admin accounts.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Choose account source: auto-discover from Phase 0 output, CSV import, or both
        2. Review and edit the mapping table (add, remove, change tier, skip entries)
        3. Confirm the account list before creation
        4. Create accounts in the correct tiered OUs with secure passwords
        5. Harden Tier 0 accounts (Protected Users + AccountNotDelegated)
        6. Generate an HTML deployment report
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
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    # Shorthand references
    $naming  = $TieringConfig.Naming
    $ouCfg   = $TieringConfig.OUStructure
    $domain  = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $dnsRoot  = $domain.DNSRoot

    # Determine base DN (container OU or domain root — matches Phase 1 deployment)
    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) {
            $baseDN = $candidateDN
        } else {
            $baseDN = $domainDN
        }
    } else {
        $baseDN = $domainDN
    }

    # Pre-check: verify Phase 1 OU structure exists
    $missingOUs = @()
    foreach ($tierKey in @('Tier0', 'Tier1', 'Tier2')) {
        $tierName = $ouCfg.$tierKey
        $accountsOU = "OU=Accounts,OU=$tierName,$baseDN"
        if (-not ([adsi]::Exists("LDAP://$accountsOU"))) {
            $missingOUs += $accountsOU
        }
    }
    if ($missingOUs.Count -gt 0) {
        Write-Host "`n  [ERROR] Phase 1 OU structure not found. Run Phase 1 first." -ForegroundColor Red
        foreach ($m in $missingOUs) {
            Write-Host "    Missing: $m" -ForegroundColor DarkGray
        }
        Write-Host ""
        return
    }

    # Results tracker
    $results = @{
        Source                = ''
        BaseDN                = $baseDN
        ContainerOU           = $containerOU
        AccountsMapped        = [System.Collections.Generic.List[object]]::new()
        AccountsCreated       = [System.Collections.Generic.List[object]]::new()
        AccountsExisted       = [System.Collections.Generic.List[object]]::new()
        AccountsSkipped       = [System.Collections.Generic.List[object]]::new()
        HardeningApplied      = [System.Collections.Generic.List[object]]::new()
        GroupMembershipsAdded = [System.Collections.Generic.List[string]]::new()
        Errors                = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Banner
    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 2 — Tiered Admin Accounts" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates dedicated admin accounts per tier with hardening." -ForegroundColor DarkGray
    Write-Host "   Naming convention: $($naming.AccountPrefix.Tier0)-firstname.lastname`n" -ForegroundColor DarkGray

    # ================================================================
    # Helper: build SamAccountName from naming convention
    # ================================================================
    function Build-TieredSam {
        param([string]$Tier, [string]$FirstName, [string]$LastName)
        $tierNum = $Tier -replace 'T',''
        $prefix  = $naming.AccountPrefix."Tier$tierNum"
        if ($LastName) {
            return "$prefix-$FirstName.$LastName".ToLower()
        } else {
            return "$prefix-$FirstName".ToLower()
        }
    }

    # ================================================================
    # Helper: generate cryptographically secure random password
    # ================================================================
    function New-RandomPassword {
        param([int]$Length = 24)
        $chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*-_=+'
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $bytes = [byte[]]::new($Length)
        $rng.GetBytes($bytes)
        $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
        $rng.Dispose()
        return $password
    }

    # ================================================================
    # Helper: display the mapping table
    # ================================================================
    function Show-MappingTable {
        param([System.Collections.Generic.List[object]]$Accounts)
        Write-Host ""
        Write-Host "    ┌─────┬────────────┬──────────────────┬────────────────────────────┬──────┬────────┐" -ForegroundColor DarkGray
        Write-Host "    │  #  │ Source     │ Current Account  │ New Account Name           │ Tier │ Action │" -ForegroundColor DarkGray
        Write-Host "    ├─────┼────────────┼──────────────────┼────────────────────────────┼──────┼────────┤" -ForegroundColor DarkGray

        $i = 0
        foreach ($a in $Accounts) {
            $i++
            $a.Index = $i
            $actionColor = switch ($a.Action) {
                'Skip'   { 'DarkGray' }
                'Create' { 'Green' }
                default  { 'White' }
            }
            $current = if ($a.CurrentAccount.Length -gt 16) { $a.CurrentAccount.Substring(0,15) + '~' } else { $a.CurrentAccount }
            $newSam  = if ($a.NewSamAccountName.Length -gt 26) { $a.NewSamAccountName.Substring(0,25) + '~' } else { $a.NewSamAccountName }
            $line = "    │ {0,-3} │ {1,-10} │ {2,-16} │ {3,-26} │ {4,-4} │ " -f $i, $a.Source, $current, $newSam, $a.Tier
            Write-Host $line -NoNewline
            Write-Host ("{0,-6}" -f $a.Action) -ForegroundColor $actionColor -NoNewline
            Write-Host " │"
        }
        Write-Host "    └─────┴────────────┴──────────────────┴────────────────────────────┴──────┴────────┘" -ForegroundColor DarkGray

        $createCount = ($Accounts | Where-Object Action -eq 'Create').Count
        $skipCount   = ($Accounts | Where-Object Action -eq 'Skip').Count
        Write-Host "    Total: $($Accounts.Count) │ Create: $createCount │ Skip: $skipCount" -ForegroundColor DarkGray
    }

    # ================================================================
    # Step 1 — Source Selection
    # ================================================================
    Write-Host "  ─── Step 1/6: Account Source ───────────────────────────" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [A]  Auto-discover from Phase 0 output" -ForegroundColor Cyan
    Write-Host "         Reads the latest discovery JSON and extracts privileged accounts." -ForegroundColor DarkGray
    Write-Host "    [C]  Import from CSV file" -ForegroundColor Cyan
    Write-Host "         CSV format: FirstName,LastName,Tier (e.g. John,Doe,T0)" -ForegroundColor DarkGray
    Write-Host "    [M]  Merge both sources (auto-discover + CSV)" -ForegroundColor Cyan
    Write-Host "    [X]  Cancel and return to menu" -ForegroundColor Red
    Write-Host ""

    $sourceChoice = Read-Host "    Select source [A/C/M/X]"
    if ($sourceChoice -match '^[Xx]') {
        Write-Host "    Cancelled.`n" -ForegroundColor Yellow
        return
    }

    $accounts = [System.Collections.Generic.List[object]]::new()

    # ----------------------------------------------------------------
    # Auto-discovery
    # ----------------------------------------------------------------
    if ($sourceChoice -match '^[AaMm]') {
        Write-Host ""
        Write-Host "    Searching for Phase 0 discovery output..." -ForegroundColor DarkGray
        $outputBase = Join-Path $RootPath 'Outputs\Tiering'
        $jsonFiles = Get-ChildItem -Path $outputBase -Filter 'MATI-Tiering-Discovery*.json' -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending

        if (-not $jsonFiles) {
            Write-Host "    [!] No Phase 0 discovery output found in Outputs\Tiering\." -ForegroundColor Red
            Write-Host "    [!] Run Phase 0 (Discovery) first, then come back." -ForegroundColor Red
            if ($sourceChoice -match '^[Aa]') { return }
            Write-Host "    [!] Continuing with CSV source only..." -ForegroundColor Yellow
        } else {
            # Show available discovery files if more than one
            if ($jsonFiles.Count -gt 1) {
                Write-Host "    Found $($jsonFiles.Count) discovery file(s):" -ForegroundColor White
                for ($j = 0; $j -lt [math]::Min($jsonFiles.Count, 5); $j++) {
                    $jf = $jsonFiles[$j]
                    Write-Host "      [$($j+1)] $($jf.Name)  ($($jf.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor DarkGray
                }
                $jsonChoice = Read-Host "    Select file [1-$([math]::Min($jsonFiles.Count, 5))] (default: 1)"
                if (-not $jsonChoice) { $jsonChoice = '1' }
                $selectedJson = $jsonFiles[[int]$jsonChoice - 1]
            } else {
                $selectedJson = $jsonFiles[0]
            }

            Write-Host "    Loading: $($selectedJson.Name)" -ForegroundColor DarkGray
            $discovery = Get-Content $selectedJson.FullName -Raw | ConvertFrom-Json

            # Extract privileged accounts — all built-in privileged groups map to T0
            $seen = @{}
            foreach ($prop in $discovery.PrivilegedAccounts.PSObject.Properties) {
                $groupKey  = $prop.Name
                $groupName = ($groupKey -split '\\')[-1]
                $members   = $prop.Value

                foreach ($m in $members) {
                    $sam = $m.SamAccountName
                    if ($seen.ContainsKey($sam)) { continue }
                    if ($m.IsServiceAccount -or $m.HasSPN) {
                        $seen[$sam] = $true
                        continue  # Skip service accounts — they need a different process
                    }

                    # Query AD for proper names
                    $firstName = ''
                    $lastName  = ''
                    try {
                        $adUser = Get-ADUser -Identity $sam -Properties GivenName, Surname -ErrorAction Stop
                        $firstName = $adUser.GivenName
                        $lastName  = $adUser.Surname
                    } catch { }

                    # Fallback: parse from SamAccountName
                    if (-not $firstName) {
                        if ($sam -match '\.') {
                            $parts = $sam -split '\.'
                            $firstName = $parts[0]
                            $lastName  = $parts[-1]
                        } else {
                            $firstName = $sam
                            $lastName  = ''
                        }
                    }

                    $tier = 'T0'  # All built-in privileged groups are T0-level
                    $newSam = Build-TieredSam -Tier $tier -FirstName $firstName -LastName $lastName

                    # Skip if the discovered account already IS a tiered account
                    $prefixes = @($naming.AccountPrefix.Tier0, $naming.AccountPrefix.Tier1, $naming.AccountPrefix.Tier2)
                    $alreadyTiered = $false
                    foreach ($px in $prefixes) {
                        if ($sam -like "$px-*") { $alreadyTiered = $true; break }
                    }
                    if ($alreadyTiered) { $seen[$sam] = $true; continue }

                    $accounts.Add([PSCustomObject]@{
                        Index             = $accounts.Count + 1
                        Source            = 'Discovery'
                        CurrentAccount    = $sam
                        FirstName         = $firstName
                        LastName          = $lastName
                        Tier              = $tier
                        NewSamAccountName = $newSam
                        Action            = 'Create'
                    })
                    $seen[$sam] = $true
                }
            }

            Write-Host "    Auto-discovered: $($accounts.Count) account(s) (service accounts excluded)" -ForegroundColor Green
            $results.Source = if ($sourceChoice -match '^[Mm]') { 'Both' } else { 'Auto-Discovery' }
        }
    }

    # ----------------------------------------------------------------
    # CSV import
    # ----------------------------------------------------------------
    if ($sourceChoice -match '^[CcMm]') {
        Write-Host ""
        Write-Host "    CSV format (header required):" -ForegroundColor DarkGray
        Write-Host "      FirstName,LastName,Tier" -ForegroundColor DarkGray
        Write-Host "      John,Doe,T0" -ForegroundColor DarkGray
        Write-Host "      Jane,Smith,T1" -ForegroundColor DarkGray
        Write-Host ""
        $csvPath = Read-Host "    Enter CSV file path"

        if (-not (Test-Path $csvPath)) {
            Write-Host "    [!] File not found: $csvPath" -ForegroundColor Red
            if ($accounts.Count -eq 0) {
                Write-Host "    [!] No accounts to process.`n" -ForegroundColor Red
                return
            }
            Write-Host "    [!] Continuing with auto-discovered accounts only..." -ForegroundColor Yellow
        } else {
            $csvData = Import-Csv $csvPath
            $csvCount = 0
            foreach ($row in $csvData) {
                $tier = $row.Tier.ToUpper().Trim()
                if ($tier -notin @('T0','T1','T2')) {
                    Write-Host "    [!] Skipping invalid tier '$($row.Tier)' for $($row.FirstName) $($row.LastName)" -ForegroundColor Yellow
                    continue
                }
                $fn = $row.FirstName.Trim()
                $ln = $row.LastName.Trim()
                $newSam = Build-TieredSam -Tier $tier -FirstName $fn -LastName $ln

                # Check for duplication with already-loaded accounts
                $isDupe = $accounts | Where-Object { $_.NewSamAccountName -eq $newSam }
                if ($isDupe) {
                    Write-Host "    [!] Duplicate: $newSam (already from discovery) — merged" -ForegroundColor Yellow
                    continue
                }

                $accounts.Add([PSCustomObject]@{
                    Index             = $accounts.Count + 1
                    Source            = 'CSV'
                    CurrentAccount    = '—'
                    FirstName         = $fn
                    LastName          = $ln
                    Tier              = $tier
                    NewSamAccountName = $newSam
                    Action            = 'Create'
                })
                $csvCount++
            }
            Write-Host "    CSV imported: $csvCount account(s)" -ForegroundColor Green
            if ($results.Source -eq '') { $results.Source = 'CSV' }
        }
    }

    if ($accounts.Count -eq 0) {
        Write-Host "`n    [!] No accounts to process.`n" -ForegroundColor Yellow
        return
    }

    # ================================================================
    # Step 2 — Review & Edit Mapping Table
    # ================================================================
    Write-Host "`n  ─── Step 2/6: Review Mapping Table ─────────────────────" -ForegroundColor Yellow

    $editing = $true
    while ($editing) {
        Show-MappingTable -Accounts $accounts

        Write-Host ""
        Write-Host "    [E #]       Edit entry       [D #]       Delete entry" -ForegroundColor Cyan
        Write-Host "    [S #]       Toggle skip      [T # tier]  Change tier (e.g. T 3 T1)" -ForegroundColor Cyan
        Write-Host "    [A]         Add new entry     [C]         Confirm & proceed" -ForegroundColor Cyan
        Write-Host ""

        $editCmd = (Read-Host "    Command").Trim()

        if ($editCmd -match '^[Cc]$') {
            $editing = $false
        }
        elseif ($editCmd -match '^[Ee]\s+(\d+)$') {
            $idx = [int]$Matches[1] - 1
            if ($idx -ge 0 -and $idx -lt $accounts.Count) {
                $entry = $accounts[$idx]
                Write-Host "      Editing entry #$($idx+1): $($entry.NewSamAccountName)" -ForegroundColor White
                $newFirst = Read-Host "      FirstName [$($entry.FirstName)]"
                if ($newFirst) { $entry.FirstName = $newFirst.Trim() }
                $newLast = Read-Host "      LastName [$($entry.LastName)]"
                if ($newLast -ne $null -and $newLast -ne '') { $entry.LastName = $newLast.Trim() }
                $newTier = Read-Host "      Tier [$($entry.Tier)]"
                if ($newTier -and $newTier.ToUpper().Trim() -in @('T0','T1','T2')) {
                    $entry.Tier = $newTier.ToUpper().Trim()
                }
                $entry.NewSamAccountName = Build-TieredSam -Tier $entry.Tier -FirstName $entry.FirstName -LastName $entry.LastName
                Write-Host "      Updated: $($entry.NewSamAccountName)" -ForegroundColor Green
            } else {
                Write-Host "      [!] Invalid index." -ForegroundColor Yellow
            }
        }
        elseif ($editCmd -match '^[Dd]\s+(\d+)$') {
            $idx = [int]$Matches[1] - 1
            if ($idx -ge 0 -and $idx -lt $accounts.Count) {
                $removed = $accounts[$idx].NewSamAccountName
                $accounts.RemoveAt($idx)
                Write-Host "      Removed: $removed" -ForegroundColor Yellow
            }
        }
        elseif ($editCmd -match '^[Ss]\s+(\d+)$') {
            $idx = [int]$Matches[1] - 1
            if ($idx -ge 0 -and $idx -lt $accounts.Count) {
                $accounts[$idx].Action = if ($accounts[$idx].Action -eq 'Skip') { 'Create' } else { 'Skip' }
                Write-Host "      $($accounts[$idx].NewSamAccountName): $($accounts[$idx].Action)" -ForegroundColor Cyan
            }
        }
        elseif ($editCmd -match '^[Tt]\s+(\d+)\s+(T[012])$') {
            $idx     = [int]$Matches[1] - 1
            $newTier = $Matches[2].ToUpper()
            if ($idx -ge 0 -and $idx -lt $accounts.Count) {
                $accounts[$idx].Tier = $newTier
                $accounts[$idx].NewSamAccountName = Build-TieredSam -Tier $newTier -FirstName $accounts[$idx].FirstName -LastName $accounts[$idx].LastName
                Write-Host "      Updated: $($accounts[$idx].NewSamAccountName) ($newTier)" -ForegroundColor Cyan
            }
        }
        elseif ($editCmd -match '^[Aa]$') {
            $fn = Read-Host "      FirstName"
            $ln = Read-Host "      LastName"
            $tr = (Read-Host "      Tier [T0/T1/T2]").ToUpper().Trim()
            if ($fn -and $tr -in @('T0','T1','T2')) {
                $newSam = Build-TieredSam -Tier $tr -FirstName $fn.Trim() -LastName $ln.Trim()
                $accounts.Add([PSCustomObject]@{
                    Index             = $accounts.Count + 1
                    Source            = 'Manual'
                    CurrentAccount    = '—'
                    FirstName         = $fn.Trim()
                    LastName          = $ln.Trim()
                    Tier              = $tr
                    NewSamAccountName = $newSam
                    Action            = 'Create'
                })
                Write-Host "      Added: $newSam ($tr)" -ForegroundColor Green
            } else {
                Write-Host "      [!] Invalid input." -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "      [!] Unknown command. Use E/D/S/T/A/C." -ForegroundColor Yellow
        }
    }

    # Store all mapped accounts (including skipped)
    foreach ($a in $accounts) { $results.AccountsMapped.Add($a) }

    # Filter to actionable accounts
    $toCreate = @($accounts | Where-Object Action -eq 'Create')
    $toSkip   = @($accounts | Where-Object Action -eq 'Skip')
    foreach ($s in $toSkip) {
        $results.AccountsSkipped.Add([PSCustomObject]@{
            SamAccountName = $s.NewSamAccountName
            Tier           = $s.Tier
            Reason         = 'Skipped by user'
        })
    }

    if ($toCreate.Count -eq 0) {
        Write-Host "`n    [!] No accounts selected for creation.`n" -ForegroundColor Yellow
        return
    }

    # ================================================================
    # Step 3 — Final Confirmation
    # ================================================================
    Write-Host "`n  ─── Step 3/6: Final Confirmation ───────────────────────" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    You are about to create $($toCreate.Count) admin account(s):" -ForegroundColor White
    $t0Count = @($toCreate | Where-Object Tier -eq 'T0').Count
    $t1Count = @($toCreate | Where-Object Tier -eq 'T1').Count
    $t2Count = @($toCreate | Where-Object Tier -eq 'T2').Count
    if ($t0Count) { Write-Host "      Tier 0 : $t0Count account(s)  ← Protected Users + AccountNotDelegated" -ForegroundColor Red }
    if ($t1Count) { Write-Host "      Tier 1 : $t1Count account(s)" -ForegroundColor Yellow }
    if ($t2Count) { Write-Host "      Tier 2 : $t2Count account(s)" -ForegroundColor Cyan }
    Write-Host ""
    Write-Host "    All accounts will be created with:" -ForegroundColor DarkGray
    Write-Host "      - Random 24-char password (exported to CSV)" -ForegroundColor DarkGray
    Write-Host "      - ChangePasswordAtLogon = True" -ForegroundColor DarkGray
    Write-Host "      - PasswordNeverExpires = False" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "    Proceed with account creation? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "    Cancelled.`n" -ForegroundColor Yellow
        return
    }

    # ================================================================
    # Step 4 — Create Accounts
    # ================================================================
    Write-Host "`n  ─── Step 4/6: Creating Accounts ────────────────────────" -ForegroundColor Yellow

    # Password export list (temporarily held in memory, exported to CSV after)
    $passwordExport = [System.Collections.Generic.List[object]]::new()

    foreach ($acct in $toCreate) {
        $tierNum    = $acct.Tier -replace 'T',''
        $tierOUName = $ouCfg."Tier$tierNum"
        $targetOU   = "OU=Accounts,OU=$tierOUName,$baseDN"
        $groupName  = "$($naming.GroupPrefix)$tierNum-Admins"

        $sam         = $acct.NewSamAccountName
        $upn         = "$sam@$dnsRoot"
        $displayName = "$($acct.FirstName) $($acct.LastName) ($($acct.Tier) Admin)".Trim()
        $description = "$($acct.Tier) administrative account for $($acct.FirstName) $($acct.LastName)".Trim()

        # Check if account already exists
        try {
            $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue
            if ($existing) {
                Write-Host "    [=] $sam — already exists (skipped creation)" -ForegroundColor DarkGray
                $results.AccountsExisted.Add([PSCustomObject]@{
                    SamAccountName = $sam
                    Tier           = $acct.Tier
                    FirstName      = $acct.FirstName
                    LastName       = $acct.LastName
                    TargetOU       = $targetOU
                    Source         = $acct.Source
                })
                # Still try to add to group
                try {
                    Add-ADGroupMember -Identity $groupName -Members $sam -ErrorAction Stop
                    Write-Host "    [+] $sam → $groupName" -ForegroundColor Green
                    $results.GroupMembershipsAdded.Add("$sam -> $groupName")
                } catch {
                    if ($_.Exception.Message -notmatch 'already a member') {
                        $results.Errors.Add("Failed to add $sam to ${groupName}: $($_.Exception.Message)")
                    }
                }
                continue
            }
        } catch { }

        # Generate secure random password
        $pwPlain = New-RandomPassword -Length 24
        $pw = ConvertTo-SecureString $pwPlain -AsPlainText -Force

        try {
            $userParams = @{
                Name                  = $sam
                SamAccountName        = $sam
                UserPrincipalName     = $upn
                GivenName             = $acct.FirstName
                Surname               = $acct.LastName
                DisplayName           = $displayName
                Description           = $description
                Path                  = $targetOU
                AccountPassword       = $pw
                Enabled               = $true
                ChangePasswordAtLogon = $true
                PasswordNeverExpires  = $false
            }
            New-ADUser @userParams
            Write-Host "    [+] Created: $sam → $targetOU" -ForegroundColor Green

            $results.AccountsCreated.Add([PSCustomObject]@{
                SamAccountName = $sam
                Tier           = $acct.Tier
                FirstName      = $acct.FirstName
                LastName       = $acct.LastName
                TargetOU       = $targetOU
                Source         = $acct.Source
            })

            $passwordExport.Add([PSCustomObject]@{
                SamAccountName    = $sam
                Tier              = $acct.Tier
                TemporaryPassword = $pwPlain
                MustChangeAtLogon = 'Yes'
            })

            # Add to tier admins group
            try {
                Add-ADGroupMember -Identity $groupName -Members $sam
                Write-Host "    [+] $sam → $groupName" -ForegroundColor Green
                $results.GroupMembershipsAdded.Add("$sam -> $groupName")
            } catch {
                $errMsg = "Failed to add $sam to ${groupName}: $($_.Exception.Message)"
                Write-Host "    [!] $errMsg" -ForegroundColor Red
                $results.Errors.Add($errMsg)
            }
        } catch {
            $errMsg = "Failed to create ${sam}: $($_.Exception.Message)"
            Write-Host "    [!] $errMsg" -ForegroundColor Red
            $results.Errors.Add($errMsg)
            $results.AccountsSkipped.Add([PSCustomObject]@{
                SamAccountName = $sam
                Tier           = $acct.Tier
                Reason         = $_.Exception.Message
            })
        }
    }

    # Export temporary passwords to CSV
    if ($passwordExport.Count -gt 0) {
        $pwCsvPath = Join-Path $OutputDir "MATI-Phase2-Passwords-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $passwordExport | Export-Csv -Path $pwCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "    ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "    │  TEMPORARY PASSWORDS EXPORTED                           │" -ForegroundColor Yellow
        Write-Host "    │  $pwCsvPath" -ForegroundColor Yellow
        Write-Host "    │                                                         │" -ForegroundColor Yellow
        Write-Host "    │  ⚠ Distribute securely and DELETE this file after use.  │" -ForegroundColor Red
        Write-Host "    │  All accounts must change password at first logon.      │" -ForegroundColor Yellow
        Write-Host "    └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
    }

    # ================================================================
    # Step 5 — Harden Tier 0 Accounts
    # ================================================================
    Write-Host "`n  ─── Step 5/6: Hardening Tier 0 Accounts ────────────────" -ForegroundColor Yellow

    # Gather all T0 accounts (newly created + already existed)
    $t0Accounts = @()
    $t0Accounts += @($results.AccountsCreated | Where-Object Tier -eq 'T0')
    $t0Accounts += @($results.AccountsExisted | Where-Object Tier -eq 'T0')

    if ($t0Accounts.Count -eq 0) {
        Write-Host "    No Tier 0 accounts to harden." -ForegroundColor DarkGray
    } else {
        Write-Host "    Hardening $($t0Accounts.Count) Tier 0 account(s)..." -ForegroundColor White

        foreach ($t0 in $t0Accounts) {
            $sam = $t0.SamAccountName

            # Add to Protected Users
            try {
                Add-ADGroupMember -Identity 'Protected Users' -Members $sam -ErrorAction Stop
                Write-Host "    [+] $sam → Protected Users" -ForegroundColor Green
                $results.HardeningApplied.Add([PSCustomObject]@{
                    SamAccountName = $sam
                    Setting        = 'Protected Users'
                    Status         = 'Applied'
                })
            } catch {
                if ($_.Exception.Message -match 'already a member') {
                    Write-Host "    [=] $sam — already in Protected Users" -ForegroundColor DarkGray
                    $results.HardeningApplied.Add([PSCustomObject]@{
                        SamAccountName = $sam
                        Setting        = 'Protected Users'
                        Status         = 'Already Applied'
                    })
                } else {
                    $errMsg = "Failed to add $sam to Protected Users: $($_.Exception.Message)"
                    Write-Host "    [!] $errMsg" -ForegroundColor Red
                    $results.Errors.Add($errMsg)
                    $results.HardeningApplied.Add([PSCustomObject]@{
                        SamAccountName = $sam
                        Setting        = 'Protected Users'
                        Status         = 'Failed'
                    })
                }
            }

            # Set AccountNotDelegated
            try {
                Set-ADUser -Identity $sam -AccountNotDelegated $true -ErrorAction Stop
                Write-Host "    [+] $sam → AccountNotDelegated = True" -ForegroundColor Green
                $results.HardeningApplied.Add([PSCustomObject]@{
                    SamAccountName = $sam
                    Setting        = 'AccountNotDelegated'
                    Status         = 'Applied'
                })
            } catch {
                $errMsg = "Failed to set AccountNotDelegated on ${sam}: $($_.Exception.Message)"
                Write-Host "    [!] $errMsg" -ForegroundColor Red
                $results.Errors.Add($errMsg)
                $results.HardeningApplied.Add([PSCustomObject]@{
                    SamAccountName = $sam
                    Setting        = 'AccountNotDelegated'
                    Status         = 'Failed'
                })
            }
        }
    }

    # ================================================================
    # Step 6 — Generate Report
    # ================================================================
    Write-Host "`n  ─── Step 6/6: Generating Report ────────────────────────" -ForegroundColor Yellow

    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase2-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase2Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    # Export JSON
    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase2-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 2 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   Created  : $($results.AccountsCreated.Count) account(s)" -ForegroundColor White
    Write-Host "   Existed  : $($results.AccountsExisted.Count) account(s)" -ForegroundColor White
    Write-Host "   Skipped  : $($results.AccountsSkipped.Count) account(s)" -ForegroundColor White
    Write-Host "   Hardened : $(($results.HardeningApplied | Where-Object Status -eq 'Applied').Count) setting(s)" -ForegroundColor White
    if ($results.Errors.Count -gt 0) {
        Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red
    }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    # Offer to open the report
    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') {
        Start-Process $htmlPath
    }

    return $results
}

# Tiering\Invoke-MATITieringPhase8.ps1
# Phase 8 — Monitoring & Detection
# Configures tiering violation detection, event forwarding, and generates monitoring KPIs.

function Invoke-MATITieringPhase8 {
    <#
    .SYNOPSIS
        Phase 8 — Tiering monitoring and detection setup.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Enumerate T0 accounts and T0 computers for watchlists
        2. Check tiering violations (T0 accounts on non-T0 machines)
        3. Audit privileged group membership (DA, EA, SA counts)
        4. Verify security event log settings on DCs
        5. Generate KPI dashboard and HTML report
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RootPath,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputDir
    )

    $ErrorActionPreference = 'Continue'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

    $naming  = $TieringConfig.Naming
    $ouCfg   = $TieringConfig.OUStructure
    $domain  = Get-ADDomain
    $domainDN = $domain.DistinguishedName

    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    $prefix = $naming.GroupPrefix

    $results = @{
        BaseDN               = $baseDN
        T0Accounts           = [System.Collections.Generic.List[object]]::new()
        T0Computers          = [System.Collections.Generic.List[object]]::new()
        TieringViolations    = [System.Collections.Generic.List[object]]::new()
        PrivGroupAudit       = [System.Collections.Generic.List[object]]::new()
        EventLogAudit        = [System.Collections.Generic.List[object]]::new()
        KPIs                 = [System.Collections.Generic.List[object]]::new()
        WatchlistExported    = $false
        Errors               = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 8 — Monitoring & Detection" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Builds watchlists, detects violations, audits privileged groups.`n" -ForegroundColor DarkGray

    # ================================================================
    # Step 1 — Build T0 Watchlists
    # ================================================================
    Write-Host "  Step 1/5 — Building T0 Watchlists" -ForegroundColor Yellow
    Write-Host ""

    # T0 accounts
    $t0Group = "${prefix}0-Admins"
    try {
        $t0Members = Get-ADGroupMember -Identity $t0Group -Recursive -ErrorAction Stop |
            Where-Object { $_.objectClass -eq 'user' }
        foreach ($m in $t0Members) {
            $results.T0Accounts.Add([PSCustomObject]@{
                SamAccountName    = $m.SamAccountName
                DistinguishedName = $m.DistinguishedName
            })
        }
        Write-Host "    T0 accounts: $($results.T0Accounts.Count) (from $t0Group)" -ForegroundColor Green
    } catch {
        Write-Host "    [!] Cannot enumerate $t0Group — $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("Cannot enumerate $t0Group — $($_.Exception.Message)")
    }

    # T0 computers (DC + T0 Servers OU)
    try {
        $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
        foreach ($dc in $dcs) {
            $results.T0Computers.Add([PSCustomObject]@{
                Name = $dc.HostName
                Type = 'Domain Controller'
            })
        }
        $t0srvOU = "OU=Servers,OU=$($ouCfg.Tier0),$baseDN"
        if ([adsi]::Exists("LDAP://$t0srvOU")) {
            $t0Servers = Get-ADComputer -Filter * -SearchBase $t0srvOU -ErrorAction SilentlyContinue
            foreach ($srv in $t0Servers) {
                $results.T0Computers.Add([PSCustomObject]@{
                    Name = $srv.DNSHostName
                    Type = 'T0 Server'
                })
            }
        }
        Write-Host "    T0 computers: $($results.T0Computers.Count) (DCs + T0 servers)" -ForegroundColor Green
    } catch {
        $results.Errors.Add("T0 computer enumeration failed: $($_.Exception.Message)")
    }

    # Export watchlists
    $t0AcctPath = Join-Path $OutputDir 'T0-Accounts-Watchlist.csv'
    $t0CompPath = Join-Path $OutputDir 'T0-Computers-Watchlist.csv'
    $results.T0Accounts | Export-Csv -Path $t0AcctPath -NoTypeInformation -Encoding UTF8
    $results.T0Computers | Export-Csv -Path $t0CompPath -NoTypeInformation -Encoding UTF8
    $results.WatchlistExported = $true
    Write-Host "    Exported: $t0AcctPath" -ForegroundColor DarkGray
    Write-Host "    Exported: $t0CompPath" -ForegroundColor DarkGray

    # ================================================================
    # Step 2 — Tiering Violation Scan
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/5 — Tiering Violation Scan (recent 4624 events)" -ForegroundColor Yellow
    Write-Host "    Checking for T0 account logons on non-T0 machines..." -ForegroundColor DarkGray
    Write-Host ""

    $t0SamList = $results.T0Accounts.SamAccountName
    $t0CompNames = $results.T0Computers.Name | ForEach-Object { ($_ -split '\.')[0].ToUpper() }

    try {
        $dcs = (Get-ADDomainController -Filter *).HostName
        $scanDC = $dcs | Select-Object -First 1

        if ($scanDC -and $t0SamList.Count -gt 0) {
            $recentLogons = Get-WinEvent -ComputerName $scanDC -FilterHashtable @{
                LogName = 'Security'; Id = 4624; StartTime = (Get-Date).AddDays(-7)
            } -MaxEvents 5000 -ErrorAction SilentlyContinue

            foreach ($evt in $recentLogons) {
                $targetUser = $evt.Properties[5].Value  # TargetUserName
                $targetComp = ($evt.Properties[11].Value -split '\.')[0].ToUpper()  # WorkstationName
                $logonType  = $evt.Properties[8].Value

                if ($targetUser -in $t0SamList -and $targetComp -notin $t0CompNames -and $targetComp -ne '-') {
                    $results.TieringViolations.Add([PSCustomObject]@{
                        Timestamp = $evt.TimeCreated
                        Account   = $targetUser
                        Computer  = $targetComp
                        LogonType = $logonType
                        Severity  = 'Critical'
                    })
                }
            }
            Write-Host "    Violations found: $($results.TieringViolations.Count)" -ForegroundColor $(if($results.TieringViolations.Count -gt 0){'Red'}else{'Green'})
        } else {
            Write-Host "    [!] Skipped — no DCs reachable or no T0 accounts" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [!] Event scan failed (may require admin on DC): $($_.Exception.Message)" -ForegroundColor Yellow
        $results.Errors.Add("Event scan failed: $($_.Exception.Message)")
    }

    # ================================================================
    # Step 3 — Privileged Group Audit
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/5 — Privileged Group Membership Audit" -ForegroundColor Yellow
    Write-Host ""

    $privGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Backup Operators', 'Account Operators')
    foreach ($grpName in $privGroups) {
        try {
            $members = Get-ADGroupMember -Identity $grpName -Recursive -ErrorAction Stop
            $count = ($members | Measure-Object).Count
            $target = switch ($grpName) {
                'Enterprise Admins' { 0 }
                'Schema Admins'     { 0 }
                'Domain Admins'     { 5 }
                default             { 10 }
            }
            $status = if ($count -le $target) { 'OK' } elseif ($count -le ($target * 2)) { 'Warning' } else { 'Critical' }

            $results.PrivGroupAudit.Add([PSCustomObject]@{
                Group   = $grpName
                Count   = $count
                Target  = $target
                Members = ($members.Name -join ', ')
                Status  = $status
            })

            $color = switch ($status) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Critical' { 'Red' } }
            Write-Host "    $grpName : $count members (target: <= $target) [$status]" -ForegroundColor $color
        } catch {
            $results.PrivGroupAudit.Add([PSCustomObject]@{ Group = $grpName; Count = 'N/A'; Target = ''; Members = ''; Status = 'Error' })
        }
    }

    # ================================================================
    # Step 4 — Event Log Audit on DCs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/5 — Security Event Log Settings on DCs" -ForegroundColor Yellow
    Write-Host ""

    try {
        $dcList = (Get-ADDomainController -Filter *).HostName
        foreach ($dc in $dcList) {
            try {
                $log = Get-WinEvent -ComputerName $dc -ListLog 'Security' -ErrorAction Stop
                $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 0)
                $status = if ($sizeMB -ge 1024) { 'OK' } elseif ($sizeMB -ge 256) { 'Warning' } else { 'Critical' }
                Write-Host "    $dc : Security log max = ${sizeMB} MB [$status]" -ForegroundColor $(switch($status){'OK'{'Green'}'Warning'{'Yellow'}'Critical'{'Red'}})
                $results.EventLogAudit.Add([PSCustomObject]@{
                    DC       = $dc
                    LogSizeMB = $sizeMB
                    Status    = $status
                })
            } catch {
                $results.EventLogAudit.Add([PSCustomObject]@{ DC = $dc; LogSizeMB = 'N/A'; Status = 'Error' })
            }
        }
    } catch {
        $results.Errors.Add("DC enumeration for event log audit failed: $($_.Exception.Message)")
    }

    # ================================================================
    # Step 5 — Build KPIs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 5/5 — Computing KPIs" -ForegroundColor Yellow

    # krbtgt age
    try {
        $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -ErrorAction Stop
        $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
        $results.KPIs.Add([PSCustomObject]@{ KPI = 'krbtgt password age'; Value = "$krbtgtAge days"; Target = '<= 180 days'; Status = if($krbtgtAge -le 180){'OK'}elseif($krbtgtAge -le 365){'Warning'}else{'Critical'} })
    } catch { $results.KPIs.Add([PSCustomObject]@{ KPI = 'krbtgt password age'; Value = 'N/A'; Target = '<= 180 days'; Status = 'Error' }) }

    # T0 in Protected Users
    try {
        $pu = Get-ADGroupMember -Identity 'Protected Users' -Recursive -ErrorAction Stop
        $puSIDs = @($pu | ForEach-Object { [string]$_.SID })
        $t0NotProtected = $results.T0Accounts | Where-Object {
            $u = Get-ADUser $_.SamAccountName -Properties SID -ErrorAction SilentlyContinue
            $u -and [string]$u.SID -notin $puSIDs
        }
        $notProtCount = ($t0NotProtected | Measure-Object).Count
        $results.KPIs.Add([PSCustomObject]@{ KPI = 'T0 accounts NOT in Protected Users'; Value = $notProtCount; Target = '0'; Status = if($notProtCount -eq 0){'OK'}else{'Critical'} })
    } catch { $results.KPIs.Add([PSCustomObject]@{ KPI = 'T0 accounts NOT in Protected Users'; Value = 'N/A'; Target = '0'; Status = 'Error' }) }

    # Tiering violations
    $results.KPIs.Add([PSCustomObject]@{ KPI = 'Tiering violations (7 days)'; Value = $results.TieringViolations.Count; Target = '0'; Status = if($results.TieringViolations.Count -eq 0){'OK'}else{'Critical'} })

    # EA/SA membership
    $eaEntry = $results.PrivGroupAudit | Where-Object Group -eq 'Enterprise Admins'
    $saEntry = $results.PrivGroupAudit | Where-Object Group -eq 'Schema Admins'
    if ($eaEntry) { $results.KPIs.Add([PSCustomObject]@{ KPI = 'Enterprise Admins members'; Value = $eaEntry.Count; Target = '0'; Status = $eaEntry.Status }) }
    if ($saEntry) { $results.KPIs.Add([PSCustomObject]@{ KPI = 'Schema Admins members'; Value = $saEntry.Count; Target = '0'; Status = $saEntry.Status }) }

    foreach ($kpi in $results.KPIs) {
        $color = switch ($kpi.Status) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Critical' { 'Red' } default { 'DarkGray' } }
        Write-Host "    $($kpi.KPI): $($kpi.Value) (target: $($kpi.Target)) [$($kpi.Status)]" -ForegroundColor $color
    }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 8 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase8-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase8Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase8-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 8 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   T0 watchlist      : $($results.T0Accounts.Count) accounts, $($results.T0Computers.Count) computers" -ForegroundColor White
    Write-Host "   Violations (7d)   : $($results.TieringViolations.Count)" -ForegroundColor $(if($results.TieringViolations.Count -gt 0){'Red'}else{'White'})
    Write-Host "   KPIs              : $(($results.KPIs | Where-Object Status -eq 'OK').Count)/$(($results.KPIs).Count) OK" -ForegroundColor White
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors            : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report            : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

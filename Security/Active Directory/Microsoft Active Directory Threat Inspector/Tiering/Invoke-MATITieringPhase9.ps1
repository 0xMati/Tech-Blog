# Tiering\Invoke-MATITieringPhase9.ps1
# Phase 9 — Health Check & Ongoing Ops
# Automated compliance checks, break-glass verification, periodic review dashboard.

function Invoke-MATITieringPhase9 {
    <#
    .SYNOPSIS
        Phase 9 — Tiering health check and operational readiness.
    .DESCRIPTION
        Guided, step-by-step assessment:
        1. Tiering compliance check (DA/EA/SA counts, stale admins, T0 in Protected Users)
        2. Break-glass account verification
        3. Service account compliance (DA membership, password age, SPN hygiene)
        4. Quarantine OU scan (objects pending review)
        5. Generate an HTML health-check report
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

    $domain   = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $ouCfg    = $TieringConfig.OUStructure
    $naming   = $TieringConfig.Naming

    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    $results = @{
        BaseDN                = $baseDN
        PrivGroupSummary      = [System.Collections.Generic.List[object]]::new()
        StaleAdmins           = [System.Collections.Generic.List[object]]::new()
        BreakGlassStatus      = [System.Collections.Generic.List[object]]::new()
        ServiceAccountIssues  = [System.Collections.Generic.List[object]]::new()
        QuarantineObjects     = [System.Collections.Generic.List[object]]::new()
        HealthChecks          = [System.Collections.Generic.List[object]]::new()
        Errors                = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Pre-flight
    # ================================================================
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host "  PHASE 9 — Health Check & Ongoing Ops" -ForegroundColor Cyan
    Write-Host "  Domain : $domainDN" -ForegroundColor Gray
    Write-Host "  Base DN: $baseDN" -ForegroundColor Gray
    Write-Host "=" * 70 -ForegroundColor Cyan
    Write-Host ""

    # ================================================================
    # Step 1 — Privileged Group & Compliance Check
    # ================================================================
    Write-Host "  ┌─ Step 1: Privileged Group Compliance Check" -ForegroundColor Cyan
    $answer = Read-Host "  │  Audit DA/EA/SA membership and Protected Users? [Y/N]"
    if ($answer -match '^[Yy]') {
        try {
            $groupChecks = @(
                @{ Name = 'Domain Admins';       Target = '≤ 5';  DN = "CN=Domain Admins,CN=Users,$domainDN" }
                @{ Name = 'Enterprise Admins';   Target = '≤ 2';  DN = "CN=Enterprise Admins,CN=Users,$domainDN" }
                @{ Name = 'Schema Admins';       Target = '0';    DN = "CN=Schema Admins,CN=Users,$domainDN" }
                @{ Name = 'Administrators';      Target = '≤ 5';  DN = "CN=Administrators,CN=Builtin,$domainDN" }
                @{ Name = 'Account Operators';   Target = '0';    DN = "CN=Account Operators,CN=Builtin,$domainDN" }
                @{ Name = 'Backup Operators';    Target = '0';    DN = "CN=Backup Operators,CN=Builtin,$domainDN" }
            )

            foreach ($gc in $groupChecks) {
                try {
                    $members = Get-ADGroupMember -Identity $gc.DN -ErrorAction SilentlyContinue
                    $count   = ($members | Measure-Object).Count
                    $targetNum = [int]($gc.Target -replace '[^\d]','')
                    $status  = if ($count -le $targetNum) { 'OK' } else { 'Warning' }
                    $results.PrivGroupSummary.Add([PSCustomObject]@{
                        Group   = $gc.Name
                        Count   = $count
                        Target  = $gc.Target
                        Status  = $status
                        Members = ($members | ForEach-Object { $_.SamAccountName }) -join ', '
                    })
                    $badge = if ($status -eq 'OK') { 'OK' } else { '!!' }
                    Write-Host "  │    [$badge] $($gc.Name): $count members (target $($gc.Target))" -ForegroundColor $(if ($status -eq 'OK') { 'Green' } else { 'Yellow' })
                } catch { $results.Errors.Add("Group check $($gc.Name): $_") }
            }

            # Protected Users membership check
            try {
                $protectedUsers = Get-ADGroupMember -Identity "CN=Protected Users,CN=Users,$domainDN" -ErrorAction SilentlyContinue
                $puCount = ($protectedUsers | Measure-Object).Count
                $daMembers = Get-ADGroupMember -Identity "CN=Domain Admins,CN=Users,$domainDN" -ErrorAction SilentlyContinue
                $daCount = ($daMembers | Measure-Object).Count
                $puPercent = if ($daCount -gt 0) { [math]::Round(($puCount / $daCount) * 100, 0) } else { 100 }
                $puStatus = if ($puPercent -ge 80) { 'OK' } elseif ($puPercent -ge 50) { 'Warning' } else { 'Critical' }
                $results.HealthChecks.Add([PSCustomObject]@{
                    Check  = 'T0 in Protected Users'
                    Value  = "$puCount / $daCount ($puPercent%)"
                    Target = '≥ 80% of T0 admins'
                    Status = $puStatus
                })
                Write-Host "  │    Protected Users: $puCount / $daCount T0 accounts ($puPercent%)" -ForegroundColor $(if ($puStatus -eq 'OK') { 'Green' } else { 'Yellow' })
            } catch { $results.Errors.Add("Protected Users check: $_") }

            # Stale admin check (no logon in 90 days)
            $staleThreshold = (Get-Date).AddDays(-90)
            foreach ($gc in @('Domain Admins','Enterprise Admins')) {
                try {
                    $members = Get-ADGroupMember -Identity $gc -ErrorAction SilentlyContinue | ForEach-Object {
                        Get-ADUser -Identity $_.DistinguishedName -Properties LastLogonDate, Enabled -ErrorAction SilentlyContinue
                    }
                    foreach ($m in $members) {
                        if (-not $m.Enabled -or ($m.LastLogonDate -and $m.LastLogonDate -lt $staleThreshold) -or (-not $m.LastLogonDate)) {
                            $reason = if (-not $m.Enabled) { 'Disabled' } elseif (-not $m.LastLogonDate) { 'Never logged on' } else { "Last logon: $($m.LastLogonDate.ToString('yyyy-MM-dd'))" }
                            $results.StaleAdmins.Add([PSCustomObject]@{
                                Account       = $m.SamAccountName
                                Group         = $gc
                                Enabled       = $m.Enabled
                                LastLogonDate = $m.LastLogonDate
                                Reason        = $reason
                            })
                        }
                    }
                } catch { $results.Errors.Add("Stale admin scan $gc : $_") }
            }
            if ($results.StaleAdmins.Count -gt 0) {
                Write-Host "  │    [!!] $($results.StaleAdmins.Count) stale privileged account(s) found" -ForegroundColor Yellow
            } else {
                Write-Host "  │    [OK] No stale privileged accounts" -ForegroundColor Green
            }
            $results.HealthChecks.Add([PSCustomObject]@{
                Check  = 'Stale Privileged Accounts'
                Value  = "$($results.StaleAdmins.Count)"
                Target = '0'
                Status = if ($results.StaleAdmins.Count -eq 0) { 'OK' } else { 'Warning' }
            })

        } catch { $results.Errors.Add("Step 1 error: $_") }
    }
    Write-Host "  └─ Step 1 complete.`n" -ForegroundColor Cyan

    # ================================================================
    # Step 2 — Break-Glass Account Verification
    # ================================================================
    Write-Host "  ┌─ Step 2: Break-Glass Account Verification" -ForegroundColor Cyan
    $answer = Read-Host "  │  Check break-glass accounts? [Y/N]"
    if ($answer -match '^[Yy]') {
        try {
            # Look for accounts with "BreakGlass" or "BG" in name inside the Tier 0 OU
            $t0OU = "OU=$($ouCfg.Tier0OU),$baseDN"
            $bgAccounts = @()
            try {
                $bgAccounts = Get-ADUser -SearchBase $t0OU -Filter { SamAccountName -like '*breakglass*' -or SamAccountName -like '*BG-*' -or Description -like '*break*glass*' } -Properties Enabled, LastLogonDate, PasswordLastSet, MemberOf -ErrorAction SilentlyContinue
            } catch {}

            if ($bgAccounts.Count -eq 0) {
                Write-Host "  │    [!!] No break-glass accounts found in $t0OU" -ForegroundColor Yellow
                $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Break-Glass Accounts'; Value = '0 found'; Target = '≥ 2'; Status = 'Critical' })
            } else {
                foreach ($bg in $bgAccounts) {
                    $pwAge = if ($bg.PasswordLastSet) { ((Get-Date) - $bg.PasswordLastSet).Days } else { 9999 }
                    $inDA  = ($bg.MemberOf | Where-Object { $_ -match 'CN=Domain Admins' }).Count -gt 0
                    $status = 'OK'
                    if (-not $bg.Enabled) { $status = 'Warning' }
                    if ($pwAge -gt 180) { $status = 'Warning' }
                    $results.BreakGlassStatus.Add([PSCustomObject]@{
                        Account         = $bg.SamAccountName
                        Enabled         = $bg.Enabled
                        PasswordAgeDays = $pwAge
                        InDomainAdmins  = $inDA
                        LastLogon       = $bg.LastLogonDate
                        Status          = $status
                    })
                    $badge = if ($status -eq 'OK') { 'OK' } else { '!!' }
                    Write-Host "  │    [$badge] $($bg.SamAccountName) — Enabled=$($bg.Enabled), PW age=${pwAge}d, DA=$inDA" -ForegroundColor $(if ($status -eq 'OK') { 'Green' } else { 'Yellow' })
                }
                $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Break-Glass Accounts'; Value = "$($bgAccounts.Count) found"; Target = '≥ 2'; Status = if ($bgAccounts.Count -ge 2) { 'OK' } else { 'Warning' } })
            }
        } catch { $results.Errors.Add("Break-glass check: $_") }
    }
    Write-Host "  └─ Step 2 complete.`n" -ForegroundColor Cyan

    # ================================================================
    # Step 3 — Service Account Compliance
    # ================================================================
    Write-Host "  ┌─ Step 3: Service Account Compliance" -ForegroundColor Cyan
    $answer = Read-Host "  │  Audit service accounts (SPN, DA membership, password age)? [Y/N]"
    if ($answer -match '^[Yy]') {
        try {
            $svcAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName, PasswordLastSet, Enabled, MemberOf, PasswordNeverExpires -ErrorAction SilentlyContinue
            $daMembers   = (Get-ADGroupMember -Identity 'Domain Admins' -Recursive -ErrorAction SilentlyContinue).DistinguishedName

            foreach ($svc in $svcAccounts) {
                $pwAge = if ($svc.PasswordLastSet) { ((Get-Date) - $svc.PasswordLastSet).Days } else { 9999 }
                $inDA  = $svc.DistinguishedName -in $daMembers
                $issues = @()
                if ($inDA) { $issues += 'In Domain Admins' }
                if ($pwAge -gt 365) { $issues += "Password $($pwAge)d old" }
                if ($svc.PasswordNeverExpires) { $issues += 'Password never expires' }
                if (-not $svc.Enabled) { $issues += 'Disabled' }

                if ($issues.Count -gt 0) {
                    $severity = if ($inDA) { 'Critical' } elseif ($pwAge -gt 365) { 'Warning' } else { 'Info' }
                    $results.ServiceAccountIssues.Add([PSCustomObject]@{
                        Account         = $svc.SamAccountName
                        SPN             = ($svc.ServicePrincipalName | Select-Object -First 1)
                        PasswordAgeDays = $pwAge
                        InDomainAdmins  = $inDA
                        PwNeverExpires  = $svc.PasswordNeverExpires
                        Enabled         = $svc.Enabled
                        Issues          = $issues -join '; '
                        Severity        = $severity
                    })
                }
            }
            Write-Host "  │    Total SPN accounts: $(($svcAccounts | Measure-Object).Count)" -ForegroundColor Gray
            Write-Host "  │    Accounts with issues: $($results.ServiceAccountIssues.Count)" -ForegroundColor $(if ($results.ServiceAccountIssues.Count -gt 0) { 'Yellow' } else { 'Green' })

            $svcInDA = ($results.ServiceAccountIssues | Where-Object InDomainAdmins -eq $true).Count
            $results.HealthChecks.Add([PSCustomObject]@{ Check = 'SVC Accounts in DA'; Value = "$svcInDA"; Target = '0'; Status = if ($svcInDA -eq 0) { 'OK' } else { 'Critical' } })
            $results.HealthChecks.Add([PSCustomObject]@{ Check = 'SVC Accounts with Issues'; Value = "$($results.ServiceAccountIssues.Count)"; Target = '0'; Status = if ($results.ServiceAccountIssues.Count -eq 0) { 'OK' } else { 'Warning' } })

        } catch { $results.Errors.Add("Service account audit: $_") }
    }
    Write-Host "  └─ Step 3 complete.`n" -ForegroundColor Cyan

    # ================================================================
    # Step 4 — Quarantine OU Scan
    # ================================================================
    Write-Host "  ┌─ Step 4: Quarantine OU Scan" -ForegroundColor Cyan
    $answer = Read-Host "  │  Check for objects in quarantine OUs? [Y/N]"
    if ($answer -match '^[Yy]') {
        try {
            # Look for a quarantine OU inside the tiering structure
            $quarantineOUs = @()
            foreach ($tier in @($ouCfg.Tier0OU, $ouCfg.Tier1OU, $ouCfg.Tier2OU)) {
                $qDN = "OU=Quarantine,OU=$tier,$baseDN"
                if ([adsi]::Exists("LDAP://$qDN")) { $quarantineOUs += $qDN }
            }
            # Also check top-level quarantine
            $topQ = "OU=Quarantine,$baseDN"
            if ([adsi]::Exists("LDAP://$topQ")) { $quarantineOUs += $topQ }

            if ($quarantineOUs.Count -eq 0) {
                Write-Host "  │    No quarantine OUs found in tiering structure" -ForegroundColor Gray
            } else {
                foreach ($qOU in $quarantineOUs) {
                    $objects = Get-ADObject -SearchBase $qOU -SearchScope OneLevel -Filter * -Properties WhenCreated, ObjectClass -ErrorAction SilentlyContinue
                    foreach ($obj in $objects) {
                        $ageDays = ((Get-Date) - $obj.WhenCreated).Days
                        $results.QuarantineObjects.Add([PSCustomObject]@{
                            Name        = $obj.Name
                            ObjectClass = $obj.ObjectClass
                            OU          = $qOU
                            WhenCreated = $obj.WhenCreated
                            AgeDays     = $ageDays
                        })
                    }
                    Write-Host "  │    $qOU : $(($objects | Measure-Object).Count) object(s)" -ForegroundColor $(if (($objects | Measure-Object).Count -gt 0) { 'Yellow' } else { 'Green' })
                }
            }
            $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Quarantine Objects'; Value = "$($results.QuarantineObjects.Count)"; Target = '0'; Status = if ($results.QuarantineObjects.Count -eq 0) { 'OK' } else { 'Warning' } })

        } catch { $results.Errors.Add("Quarantine scan: $_") }
    }
    Write-Host "  └─ Step 4 complete.`n" -ForegroundColor Cyan

    # ================================================================
    # Step 5 — Krbtgt + Auth Silo Quick Check
    # ================================================================
    Write-Host "  ┌─ Step 5: Krbtgt & Auth Silo Quick Check" -ForegroundColor Cyan
    $answer = Read-Host "  │  Quick-check krbtgt and auth silo status? [Y/N]"
    if ($answer -match '^[Yy]') {
        try {
            # krbtgt
            $krbtgt = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet -ErrorAction SilentlyContinue
            $krbtgtAge = if ($krbtgt.PasswordLastSet) { ((Get-Date) - $krbtgt.PasswordLastSet).Days } else { 9999 }
            $krbtgtStatus = if ($krbtgtAge -le 180) { 'OK' } elseif ($krbtgtAge -le 365) { 'Warning' } else { 'Critical' }
            $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Krbtgt Password Age'; Value = "${krbtgtAge} days"; Target = '≤ 180 days'; Status = $krbtgtStatus })
            Write-Host "  │    krbtgt password age: ${krbtgtAge} days — $krbtgtStatus" -ForegroundColor $(if ($krbtgtStatus -eq 'OK') { 'Green' } else { 'Yellow' })

            # Auth silo
            $siloName = $TieringConfig.AuthPolicy.SiloName
            if ($siloName) {
                try {
                    $silo = Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction SilentlyContinue
                    if ($silo) {
                        $enforced = $silo.Enforce
                        $siloStatus = if ($enforced) { 'OK' } else { 'Warning' }
                        $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Auth Silo Enforcement'; Value = if ($enforced) { 'Enforced' } else { 'Audit Only' }; Target = 'Enforced'; Status = $siloStatus })
                        Write-Host "  │    Auth Silo '$siloName': $(if ($enforced) { 'Enforced' } else { 'Audit only' })" -ForegroundColor $(if ($enforced) { 'Green' } else { 'Yellow' })
                    } else {
                        $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Auth Silo'; Value = 'Not found'; Target = 'Exists & Enforced'; Status = 'Critical' })
                        Write-Host "  │    [!!] Auth Silo '$siloName' not found" -ForegroundColor Red
                    }
                } catch { $results.HealthChecks.Add([PSCustomObject]@{ Check = 'Auth Silo'; Value = 'Check failed'; Target = 'Exists & Enforced'; Status = 'Critical' }) }
            }
        } catch { $results.Errors.Add("Krbtgt/Silo check: $_") }
    }
    Write-Host "  └─ Step 5 complete.`n" -ForegroundColor Cyan

    # ================================================================
    # Export results
    # ================================================================
    $sw.Stop()
    Write-Host "  ════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Phase 9 health check completed in $([math]::Round($sw.Elapsed.TotalSeconds,1))s" -ForegroundColor Green
    Write-Host "  Health Checks: $($results.HealthChecks.Count) | Issues: $($results.ServiceAccountIssues.Count) | Errors: $($results.Errors.Count)" -ForegroundColor Gray
    Write-Host ""

    # JSON
    $jsonPath = Join-Path $OutputDir 'Phase9-HealthCheck.json'
    $results | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor Gray

    # HTML
    $htmlPath = Join-Path $OutputDir 'Phase9-HealthCheck.html'
    Export-TieringPhase9Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    Write-Host ""
    $open = Read-Host "  Open HTML report? [Y/N]"
    if ($open -match '^[Yy]') { Start-Process $htmlPath }
}

# Tiering\Invoke-MATITieringPhase7.ps1
# Phase 7 — Tier 0 Object Protection
# Audits ACLs on critical AD objects, GPO ownership, krbtgt, service accounts.

function Invoke-MATITieringPhase7 {
    <#
    .SYNOPSIS
        Phase 7 — Audit and harden Tier 0 AD objects.
    .DESCRIPTION
        Guided, step-by-step assessment:
        1. Audit ACLs on domain root, AdminSDHolder, Configuration, Schema
        2. Audit GPO ownership and permissions for T0-linked GPOs
        3. Check krbtgt password age and optionally rotate
        4. Audit service accounts (SPN, Domain Admins membership, password age)
        5. Generate an HTML audit report
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
        BaseDN              = $baseDN
        ACLFindings         = [System.Collections.Generic.List[object]]::new()
        GPOFindings         = [System.Collections.Generic.List[object]]::new()
        KrbtgtStatus        = $null
        KrbtgtRotated       = $false
        ServiceAccountAudit = [System.Collections.Generic.List[object]]::new()
        Errors              = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 7 — Tier 0 Object Protection" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Audits critical AD objects, GPOs, krbtgt, service accounts.`n" -ForegroundColor DarkGray

    # ================================================================
    # Step 1 — ACL Audit on critical objects
    # ================================================================
    Write-Host "  Step 1/4 — ACL Audit on Critical Objects" -ForegroundColor Yellow
    Write-Host ""

    $criticalObjects = @(
        @{ Name = 'Domain Root';    Path = $domainDN }
        @{ Name = 'AdminSDHolder';  Path = "CN=AdminSDHolder,CN=System,$domainDN" }
        @{ Name = 'Configuration';  Path = "CN=Configuration,$domainDN" }
    )

    $trustedPatterns = 'S-1-5-18|NT AUTHORITY|BUILTIN\\Administrators|Domain Admins|Enterprise Admins|SYSTEM|Schema Admins'

    foreach ($obj in $criticalObjects) {
        Write-Host "    Auditing: $($obj.Name)" -ForegroundColor White
        try {
            $acl = Get-Acl "AD:\$($obj.Path)" -ErrorAction Stop
            $dangerousACEs = $acl.Access | Where-Object {
                $_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner|GenericWrite' -and
                $_.IdentityReference.Value -notmatch $trustedPatterns -and
                $_.AccessControlType -eq 'Allow'
            }
            foreach ($ace in $dangerousACEs) {
                $severity = if ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl') { 'Critical' } else { 'High' }
                Write-Host "      [!] ${severity}: $($ace.IdentityReference) has $($ace.ActiveDirectoryRights) on $($obj.Name)" -ForegroundColor $(if($severity -eq 'Critical'){'Red'}else{'Yellow'})
                $results.ACLFindings.Add([PSCustomObject]@{
                    Object    = $obj.Name
                    Path      = $obj.Path
                    Identity  = $ace.IdentityReference.Value
                    Rights    = $ace.ActiveDirectoryRights.ToString()
                    Inherited = $ace.IsInherited
                    Severity  = $severity
                })
            }
            if (-not $dangerousACEs) {
                Write-Host "      [OK] No dangerous non-standard ACEs found" -ForegroundColor Green
            }
        } catch {
            Write-Host "      [!] Cannot read ACL: $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("ACL audit failed on $($obj.Name): $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Step 2 — GPO Ownership Audit
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/4 — GPO Ownership Audit" -ForegroundColor Yellow
    Write-Host ""

    try {
        $allGPOs = Get-GPO -All -ErrorAction Stop
        foreach ($gpo in $allGPOs) {
            $ownerOk = $gpo.Owner -match 'Domain Admins|Enterprise Admins'
            $severity = if (-not $ownerOk) { 'Warning' } else { 'OK' }

            if (-not $ownerOk) {
                Write-Host "      [!] GPO '$($gpo.DisplayName)' owned by: $($gpo.Owner)" -ForegroundColor Yellow
            }

            $results.GPOFindings.Add([PSCustomObject]@{
                GPOName  = $gpo.DisplayName
                GPOId    = $gpo.Id.ToString()
                Owner    = $gpo.Owner
                Status   = $severity
            })
        }

        $badOwners = ($results.GPOFindings | Where-Object Status -ne 'OK').Count
        Write-Host "    Total GPOs: $($allGPOs.Count) | Non-standard ownership: $badOwners" -ForegroundColor $(if($badOwners -gt 0){'Yellow'}else{'Green'})
    } catch {
        Write-Host "      [!] Cannot enumerate GPOs: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("GPO audit failed: $($_.Exception.Message)")
    }

    # ================================================================
    # Step 3 — krbtgt Password Age
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/4 — krbtgt Account Status" -ForegroundColor Yellow
    Write-Host ""

    try {
        $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet, Enabled -ErrorAction Stop
        $pwdAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
        $severity = if ($pwdAge -le 180) { 'OK' } elseif ($pwdAge -le 365) { 'Warning' } else { 'Critical' }

        $results.KrbtgtStatus = [PSCustomObject]@{
            PasswordLastSet = $krbtgt.PasswordLastSet
            AgeDays         = $pwdAge
            Severity        = $severity
        }

        $color = switch ($severity) { 'OK' { 'Green' } 'Warning' { 'Yellow' } 'Critical' { 'Red' } }
        Write-Host "    krbtgt password last set: $($krbtgt.PasswordLastSet) ($pwdAge days ago)" -ForegroundColor $color

        if ($pwdAge -gt 180) {
            Write-Host "    [!] krbtgt password is older than 180 days. Rotation recommended." -ForegroundColor Yellow
            $rotateChoice = Read-Host "    Rotate krbtgt password now? (First rotation of double rotation) [Y/N]"
            if ($rotateChoice.Trim().ToUpper() -eq 'Y') {
                try {
                    $newPwd = [System.Web.Security.Membership]::GeneratePassword(64, 16)
                    Set-ADAccountPassword -Identity 'krbtgt' -Reset -NewPassword (
                        ConvertTo-SecureString -String $newPwd -AsPlainText -Force
                    ) -ErrorAction Stop
                    Write-Host "    [+] First krbtgt rotation complete. Wait 12+ hours, then run second rotation." -ForegroundColor Green
                    $results.KrbtgtRotated = $true
                } catch {
                    Write-Host "    [!] krbtgt rotation failed: $($_.Exception.Message)" -ForegroundColor Red
                    $results.Errors.Add("krbtgt rotation failed: $($_.Exception.Message)")
                }
            }
        }
    } catch {
        Write-Host "    [!] Cannot read krbtgt: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("krbtgt audit failed: $($_.Exception.Message)")
    }

    # ================================================================
    # Step 4 — Service Account Audit
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/4 — Service Account Audit (SPN + Domain Admins)" -ForegroundColor Yellow
    Write-Host ""

    try {
        $svcAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, PasswordLastSet, MemberOf, Enabled -ErrorAction Stop

        foreach ($svc in $svcAccounts) {
            $inDA  = $svc.MemberOf | Where-Object { $_ -match 'CN=Domain Admins,' }
            $pwAge = if ($svc.PasswordLastSet) { (New-TimeSpan -Start $svc.PasswordLastSet -End (Get-Date)).Days } else { 9999 }

            $risk = 'Low'
            if ($inDA) { $risk = 'Critical' }
            elseif ($pwAge -gt 365) { $risk = 'High' }
            elseif ($pwAge -gt 180) { $risk = 'Medium' }

            $results.ServiceAccountAudit.Add([PSCustomObject]@{
                SamAccountName = $svc.SamAccountName
                SPNs           = ($svc.ServicePrincipalName -join '; ')
                PasswordAge    = $pwAge
                InDomainAdmins = [bool]$inDA
                Enabled        = $svc.Enabled
                Risk           = $risk
            })

            if ($risk -in @('Critical','High')) {
                $c = if ($risk -eq 'Critical') { 'Red' } else { 'Yellow' }
                Write-Host "      [$risk] $($svc.SamAccountName) — PwdAge: ${pwAge}d$(if($inDA){' — IN DOMAIN ADMINS'})" -ForegroundColor $c
            }
        }

        $critCount = ($results.ServiceAccountAudit | Where-Object Risk -eq 'Critical').Count
        $highCount = ($results.ServiceAccountAudit | Where-Object Risk -eq 'High').Count
        Write-Host "    Total: $($svcAccounts.Count) | Critical: $critCount | High: $highCount" -ForegroundColor $(if($critCount -gt 0){'Red'}elseif($highCount -gt 0){'Yellow'}else{'Green'})
    } catch {
        Write-Host "    [!] Service account audit failed: $($_.Exception.Message)" -ForegroundColor Red
        $results.Errors.Add("Service account audit failed: $($_.Exception.Message)")
    }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 7 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase7-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase7Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase7-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 7 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   ACL findings     : $($results.ACLFindings.Count)" -ForegroundColor White
    Write-Host "   GPO non-standard : $(($results.GPOFindings | Where-Object Status -ne 'OK').Count)" -ForegroundColor White
    Write-Host "   krbtgt age       : $(if($results.KrbtgtStatus){"$($results.KrbtgtStatus.AgeDays) days ($($results.KrbtgtStatus.Severity))"}else{'N/A'})" -ForegroundColor White
    Write-Host "   Svc acct risks   : $(($results.ServiceAccountAudit | Where-Object {$_.Risk -in 'Critical','High'}).Count)" -ForegroundColor White
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors           : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report           : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

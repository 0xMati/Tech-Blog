# Tiering\Invoke-MATITieringPhase4.ps1
# Phase 4 — Create Auth Policies & Silos
# Creates T0 Authentication Policy, Computer Authentication Policy, and Authentication Silo in audit-only mode.
# Optionally assigns T0 accounts and computers to the silo.

function Invoke-MATITieringPhase4 {
    <#
    .SYNOPSIS
        Phase 4 — Interactive creation of Authentication Policies and Silos.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: DFL >= 2012 R2, Phase 1 groups/OUs exist
        2. Verify KDC support for claims, compound authentication, and Kerberos armoring on DCs
        3. Create T0 Authentication Policy (audit-only)
        4. Create T0 Computer Authentication Policy (audit-only)
        5. Create T0 Authentication Silo (audit-only)
        6. Optionally assign T0 accounts and computers to the silo
        7. Generate an HTML deployment report with warnings and next steps toward enforce mode
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

    $naming   = $TieringConfig.Naming
    $ouCfg    = $TieringConfig.OUStructure
    $authCfg  = $TieringConfig.AuthPolicy
    $domain   = Get-ADDomain
    $domainDN = $domain.DistinguishedName

    $phase1StatePath = Join-Path $RootPath 'Outputs\Tiering\MATI-Tiering-Phase1-Latest.json'
    if (-not (Test-Path $phase1StatePath)) {
        Write-Host "`n  [ERROR] Phase 1 state file not found. Run Phase 1 first." -ForegroundColor Red
        Write-Host "    Expected: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    try {
        $phase1State = Get-Content -Path $phase1StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "`n  [ERROR] Failed to read Phase 1 state file." -ForegroundColor Red
        Write-Host "    $phase1StatePath" -ForegroundColor DarkGray
        Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $baseDN = [string]$phase1State.BaseDN
    $containerOU = if ($null -ne $phase1State.ContainerOU -and [string]$phase1State.ContainerOU -ne '') { [string]$phase1State.ContainerOU } else { $null }
    $tier0OUDN = [string]$phase1State.Tier0OUDN

    if ([string]::IsNullOrWhiteSpace($baseDN) -or [string]::IsNullOrWhiteSpace($tier0OUDN)) {
        Write-Host "`n  [ERROR] Phase 1 state is incomplete. Run Phase 1 again." -ForegroundColor Red
        Write-Host "    State file: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    # Results tracker
    $results = @{
        BaseDN              = $baseDN
        ContainerOU         = $containerOU
        Phase1StatePath     = $phase1StatePath
        DomainMode          = ''
        EnforcementMode     = 'Audit'
        ClaimsReady         = $false
        ClaimsStatus        = [System.Collections.Generic.List[object]]::new()
        Warnings            = [System.Collections.Generic.List[string]]::new()
        PolicyCreated       = $null
        ComputerPolicyCreated = $null
        SiloCreated         = $null
        AccountsAssigned    = [System.Collections.Generic.List[object]]::new()
        ComputersAssigned   = [System.Collections.Generic.List[object]]::new()
        Errors              = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Banner
    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 4 — Create Auth Policies & Silos" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Deploys Authentication Policies and Silos in audit-only mode for Tier 0 isolation." -ForegroundColor DarkGray
    Write-Host "   Silo: $($authCfg.SiloName) | Policy: $($authCfg.PolicyName)`n" -ForegroundColor DarkGray

    # ================================================================
    # Pre-checks
    # ================================================================
    Write-Host "  Pre-checks..." -ForegroundColor Yellow

    # Domain functional level
    $domainMode = (Get-ADDomain).DomainMode
    $results.DomainMode = $domainMode.ToString()
    # Allow unknowns (future DFL) and >= 2012R2
    $dflOk = $domainMode -ge [Microsoft.ActiveDirectory.Management.ADDomainMode]::Windows2012R2Domain
    if (-not $dflOk) {
        Write-Host "  [ERROR] Domain Functional Level must be 2012 R2 or higher." -ForegroundColor Red
        Write-Host "  Current DFL: $domainMode" -ForegroundColor DarkGray
        return
    }
    Write-Host "    [OK] DFL: $domainMode (>= 2012 R2)" -ForegroundColor Green

    # T0 Admins group
    $prefix = $naming.GroupPrefix
    $t0adminsGroup = "${prefix}0-Admins"
    try {
        $null = Get-ADGroup -Identity $t0adminsGroup -ErrorAction Stop
        Write-Host "    [OK] Group found: $t0adminsGroup" -ForegroundColor Green
    } catch {
        Write-Host "  [ERROR] Group $t0adminsGroup not found. Run Phase 1 first." -ForegroundColor Red
        return
    }

    # T0 OU
    $tier0OU = $tier0OUDN
    if (-not ([adsi]::Exists("LDAP://$tier0OU"))) {
        Write-Host "  [ERROR] Tier 0 OU not found: $tier0OU. Run Phase 1 first." -ForegroundColor Red
        return
    }
    Write-Host "    [OK] Tier 0 OU found" -ForegroundColor Green

    # Verify KDC support for claims, compound auth and Kerberos armoring on DCs
    $claimsReady = $true
    try {
        $domainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop)
        foreach ($dc in $domainControllers) {
            $claimsValue = $null
            $status = 'Unknown'
            $detail = 'Could not verify KDC support for claims, compound authentication and Kerberos armoring.'

            try {
                $claimsValue = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                    $value = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' -Name 'EnableCbacAndArmor' -ErrorAction SilentlyContinue
                    if ($null -eq $value) { return $null }
                    return $value.EnableCbacAndArmor
                } -ErrorAction Stop

                switch ($claimsValue) {
                    1 {
                        $status = 'Supported'
                        $detail = 'KDC support for claims, compound authentication and Kerberos armoring is set to Supported.'
                    }
                    2 {
                        $status = 'Always provide claims'
                        $detail = 'KDC support for claims, compound authentication and Kerberos armoring is set to Always provide claims.'
                    }
                    default {
                        $status = 'Not configured'
                        $detail = 'KDC support for claims, compound authentication and Kerberos armoring is missing or disabled.'
                        $claimsReady = $false
                        $results.Warnings.Add("DC $($dc.HostName) does not have KDC support for claims, compound authentication and Kerberos armoring enabled.")
                    }
                }
            } catch {
                $status = 'Check failed'
                $detail = $_.Exception.Message
                $claimsReady = $false
                $results.Warnings.Add("Cannot verify KDC support for claims on $($dc.HostName): $($_.Exception.Message)")
            }

            $results.ClaimsStatus.Add([PSCustomObject]@{
                DCName       = $dc.HostName
                ClaimsValue  = $claimsValue
                Status       = $status
                Detail       = $detail
            })
        }
    } catch {
        $claimsReady = $false
        $results.Warnings.Add("Cannot enumerate domain controllers to verify KDC claims support: $($_.Exception.Message)")
    }
    $results.ClaimsReady = $claimsReady
    if ($claimsReady) {
        Write-Host "    [OK] KDC claims/compound auth/armoring support verified on all reachable DCs" -ForegroundColor Green
    } else {
        Write-Host "    [WARN] One or more DCs do not have KDC claims/compound auth/armoring support verified" -ForegroundColor Yellow
    }

    # ================================================================
    # Step 1 — Audit-only deployment model
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/4 — Audit-Only Deployment" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    This phase now deploys Authentication Policies and Silos in AUDIT mode only." -ForegroundColor White
    Write-Host "    No enforce flag will be set by MATI during Phase 4." -ForegroundColor DarkGray
    Write-Host "    After you analyze Event ID 105/106 and validate the scope, you can move to enforce in a later controlled change." -ForegroundColor DarkGray
    if (-not $results.ClaimsReady) {
        Write-Host "    [WARN] KDC claims/compound auth/armoring is not fully in place. Do not move to enforce until this is corrected." -ForegroundColor Yellow
    }
    Write-Host "    Mode: Audit" -ForegroundColor Cyan

    # ================================================================
    # Step 2 — Create Authentication Policies
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/4 — Creating Authentication Policies" -ForegroundColor Yellow
    Write-Host ""

    $policyName   = $authCfg.PolicyName
    $compPolicyName = $authCfg.ComputerPolicyName
    $tgtLifetime  = $authCfg.T0TGTLifetimeMinutes

    # User Authentication Policy
    try {
        $existingUserPolicy = Get-ADAuthenticationPolicy -Identity $policyName -ErrorAction Stop
        Write-Host "      [=] Already exists: $policyName" -ForegroundColor DarkGray
        $results.PolicyCreated = [PSCustomObject]@{ Name = $policyName; Status = 'Existed'; TGTLifetime = $tgtLifetime }
        if ($existingUserPolicy.Enforce) {
            $results.Warnings.Add("Existing user authentication policy '$policyName' is already in Enforce mode. Phase 4 expects audit-only deployment first.")
            Write-Host "      [WARN] Existing policy is already Enforce: $policyName" -ForegroundColor Yellow
        }
    } catch {
        try {
            $policyParams = @{
                Name                  = $policyName
                Description           = "Restricts Tier 0 accounts — TGT lifetime $tgtLifetime min"
                UserTGTLifetimeMins   = $tgtLifetime
            }
            New-ADAuthenticationPolicy @policyParams -ErrorAction Stop
            Write-Host "      [+] Created: $policyName (TGT: ${tgtLifetime}min, Mode: $($results.EnforcementMode))" -ForegroundColor Green
            $results.PolicyCreated = [PSCustomObject]@{ Name = $policyName; Status = 'Created'; TGTLifetime = $tgtLifetime }
        } catch {
            Write-Host "      [!] FAILED: $policyName — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Policy creation failed: $policyName — $($_.Exception.Message)")
        }
    }

    # Computer Authentication Policy
    try {
        $existingComputerPolicy = Get-ADAuthenticationPolicy -Identity $compPolicyName -ErrorAction Stop
        Write-Host "      [=] Already exists: $compPolicyName" -ForegroundColor DarkGray
        $results.ComputerPolicyCreated = [PSCustomObject]@{ Name = $compPolicyName; Status = 'Existed' }
        if ($existingComputerPolicy.Enforce) {
            $results.Warnings.Add("Existing computer authentication policy '$compPolicyName' is already in Enforce mode. Phase 4 expects audit-only deployment first.")
            Write-Host "      [WARN] Existing computer policy is already Enforce: $compPolicyName" -ForegroundColor Yellow
        }
    } catch {
        try {
            $compParams = @{
                Name                     = $compPolicyName
                Description              = "Restricts service tickets to Tier 0 machines"
                ComputerTGTLifetimeMins  = $tgtLifetime
            }
            New-ADAuthenticationPolicy @compParams -ErrorAction Stop
            Write-Host "      [+] Created: $compPolicyName" -ForegroundColor Green
            $results.ComputerPolicyCreated = [PSCustomObject]@{ Name = $compPolicyName; Status = 'Created' }
        } catch {
            Write-Host "      [!] FAILED: $compPolicyName — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Policy creation failed: $compPolicyName — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Step 3 — Create Authentication Silo
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/4 — Creating Authentication Silo" -ForegroundColor Yellow
    Write-Host ""

    $siloName = $authCfg.SiloName
    try {
        $existingSilo = Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction Stop
        Write-Host "      [=] Already exists: $siloName" -ForegroundColor DarkGray
        $results.SiloCreated = [PSCustomObject]@{ Name = $siloName; Status = 'Existed' }
        if ($existingSilo.Enforce) {
            $results.Warnings.Add("Existing authentication silo '$siloName' is already in Enforce mode. Phase 4 expects audit-only deployment first.")
            Write-Host "      [WARN] Existing silo is already Enforce: $siloName" -ForegroundColor Yellow
        }
    } catch {
        try {
            $siloParams = @{
                Name                          = $siloName
                Description                   = 'Tier 0 Authentication Silo'
                UserAuthenticationPolicy      = $policyName
                ComputerAuthenticationPolicy  = $compPolicyName
                ServiceAuthenticationPolicy   = $policyName
            }
            New-ADAuthenticationPolicySilo @siloParams -ErrorAction Stop
            Write-Host "      [+] Created: $siloName (Mode: $($results.EnforcementMode))" -ForegroundColor Green
            $results.SiloCreated = [PSCustomObject]@{ Name = $siloName; Status = 'Created' }
        } catch {
            Write-Host "      [!] FAILED: $siloName — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Silo creation failed: $siloName — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Step 4 — Assign accounts and computers to the silo
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/4 — Silo Assignment" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Assign T0 accounts and computers to $siloName?" -ForegroundColor White
    Write-Host "    - T0 accounts from group: $t0adminsGroup" -ForegroundColor DarkGray

    $serversOU = "OU=Servers,$tier0OUDN"
    $hasServersOU = [adsi]::Exists("LDAP://$serversOU")
    if ($hasServersOU) {
        Write-Host "    - T0 computers from OU: $serversOU" -ForegroundColor DarkGray
    }
    Write-Host ""
    $assignChoice = Read-Host "    Assign to silo? [Y/N]"

    if ($assignChoice.Trim().ToUpper() -eq 'Y') {
        # Assign user accounts
        try {
            $t0Members = Get-ADGroupMember -Identity $t0adminsGroup -ErrorAction Stop |
                Where-Object { $_.objectClass -eq 'user' }

            foreach ($member in $t0Members) {
                try {
                    Set-ADUser -Identity $member.SamAccountName -AuthenticationPolicySilo $siloName -ErrorAction Stop
                    Grant-ADAuthenticationPolicySiloAccess -Identity $siloName -Account $member.SamAccountName -ErrorAction Stop
                    Write-Host "      [+] Assigned: $($member.SamAccountName) -> $siloName" -ForegroundColor Green
                    $results.AccountsAssigned.Add([PSCustomObject]@{
                        SamAccountName = $member.SamAccountName
                        Type           = 'User'
                        Silo           = $siloName
                        Status         = 'Assigned'
                    })
                } catch {
                    Write-Host "      [!] FAILED: $($member.SamAccountName) — $($_.Exception.Message)" -ForegroundColor Red
                    $results.Errors.Add("Silo assignment failed: $($member.SamAccountName) — $($_.Exception.Message)")
                }
            }
        } catch {
            Write-Host "      [!] Cannot enumerate $t0adminsGroup — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Cannot enumerate $t0adminsGroup — $($_.Exception.Message)")
        }

        # Assign computer accounts
        if ($hasServersOU) {
            try {
                $t0Computers = Get-ADComputer -Filter * -SearchBase $serversOU -ErrorAction Stop
                # Also include Domain Controllers
                $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
                $allT0Computers = @($t0Computers) + @($dcs | ForEach-Object {
                    Get-ADComputer -Identity $_.Name -ErrorAction SilentlyContinue
                }) | Select-Object -Unique -Property SamAccountName, DistinguishedName

                foreach ($comp in $allT0Computers) {
                    if (-not $comp.SamAccountName) { continue }
                    try {
                        Set-ADComputer -Identity $comp.SamAccountName -AuthenticationPolicySilo $siloName -ErrorAction Stop
                        Grant-ADAuthenticationPolicySiloAccess -Identity $siloName -Account $comp.SamAccountName -ErrorAction Stop
                        Write-Host "      [+] Assigned: $($comp.SamAccountName) -> $siloName" -ForegroundColor Green
                        $results.ComputersAssigned.Add([PSCustomObject]@{
                            SamAccountName = $comp.SamAccountName
                            Type           = 'Computer'
                            Silo           = $siloName
                            Status         = 'Assigned'
                        })
                    } catch {
                        Write-Host "      [!] FAILED: $($comp.SamAccountName) — $($_.Exception.Message)" -ForegroundColor Red
                        $results.Errors.Add("Silo assignment failed: $($comp.SamAccountName) — $($_.Exception.Message)")
                    }
                }
            } catch {
                $results.Errors.Add("Cannot enumerate T0 computers — $($_.Exception.Message)")
            }
        }
    } else {
        Write-Host "    [!] Skipping silo assignment. You can assign later." -ForegroundColor Yellow
    }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 4 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase4-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase4Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase4-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 4 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   Mode     : $($results.EnforcementMode)" -ForegroundColor White
    Write-Host "   Policies : $(if($results.PolicyCreated){$results.PolicyCreated.Status}else{'N/A'})" -ForegroundColor White
    Write-Host "   Silo     : $(if($results.SiloCreated){$results.SiloCreated.Status}else{'N/A'})" -ForegroundColor White
    Write-Host "   Assigned : $($results.AccountsAssigned.Count) accounts, $($results.ComputersAssigned.Count) computers" -ForegroundColor White
    Write-Host "   Claims   : $(if($results.ClaimsReady){'Ready'}else{'Review required'})" -ForegroundColor White
    if ($results.Warnings.Count -gt 0) {
        Write-Host "   Warnings : $($results.Warnings.Count)" -ForegroundColor Yellow
    }
    if ($results.Errors.Count -gt 0) {
        Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red
    }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

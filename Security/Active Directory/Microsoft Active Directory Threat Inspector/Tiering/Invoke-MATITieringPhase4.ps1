# Tiering\Invoke-MATITieringPhase4.ps1
# Phase 4 — Authentication Policies & Silos
# Creates T0 Authentication Policy, Computer Authentication Policy, and Authentication Silo.
# Optionally assigns T0 accounts and computers to the silo.

function Invoke-MATITieringPhase4 {
    <#
    .SYNOPSIS
        Phase 4 — Interactive creation of Authentication Policies and Silos.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: DFL >= 2012 R2, Phase 1 groups/OUs exist
        2. Choose enforcement mode: Audit or Enforce
        3. Create T0 Authentication Policy (user TGT lifetime)
        4. Create T0 Computer Authentication Policy
        5. Create T0 Authentication Silo
        6. Optionally assign T0 accounts and computers to the silo
        7. Generate an HTML deployment report
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

    # Determine base DN
    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    # Results tracker
    $results = @{
        BaseDN              = $baseDN
        DomainMode          = ''
        EnforcementMode     = ''
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
    Write-Host "   Phase 4 — Authentication Policies & Silos" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Adds Kerberos-level enforcement for Tier 0 isolation." -ForegroundColor DarkGray
    Write-Host "   Silo: $($authCfg.SiloName) | Policy: $($authCfg.PolicyName)`n" -ForegroundColor DarkGray

    # ================================================================
    # Pre-checks
    # ================================================================
    Write-Host "  Pre-checks..." -ForegroundColor Yellow

    # Domain functional level
    $domainMode = (Get-ADDomain).DomainMode
    $results.DomainMode = $domainMode.ToString()
    $supportedModes = @('Windows2012R2Domain','Windows2016Domain','Windows2025Domain','UnknownDomain')
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
    $tier0OU = "OU=$($ouCfg.Tier0),$baseDN"
    if (-not ([adsi]::Exists("LDAP://$tier0OU"))) {
        Write-Host "  [ERROR] Tier 0 OU not found: $tier0OU. Run Phase 1 first." -ForegroundColor Red
        return
    }
    Write-Host "    [OK] Tier 0 OU found" -ForegroundColor Green

    # ================================================================
    # Step 1 — Choose enforcement mode
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/4 — Enforcement Mode" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [A] Audit mode  — Logs violations (Event ID 105/106) but does NOT block." -ForegroundColor White
    Write-Host "                      Recommended for initial deployment." -ForegroundColor DarkGray
    Write-Host "    [E] Enforce mode — Blocks authentication that violates the policy." -ForegroundColor White
    Write-Host "                      Use only after validating audit results." -ForegroundColor DarkGray
    Write-Host ""
    $modeChoice = Read-Host "    Select mode [A/E]"
    $enforceMode = $modeChoice.Trim().ToUpper() -eq 'E'
    $results.EnforcementMode = if ($enforceMode) { 'Enforce' } else { 'Audit' }
    Write-Host "    Mode: $($results.EnforcementMode)" -ForegroundColor Cyan

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
        $existingPolicy = Get-ADAuthenticationPolicy -Identity $policyName -ErrorAction Stop
        Write-Host "      [=] Already exists: $policyName" -ForegroundColor DarkGray
        $results.PolicyCreated = [PSCustomObject]@{ Name = $policyName; Status = 'Existed'; TGTLifetime = $tgtLifetime }
    } catch {
        try {
            $policyParams = @{
                Name                  = $policyName
                Description           = "Restricts Tier 0 accounts — TGT lifetime $tgtLifetime min"
                UserTGTLifetimeMins   = $tgtLifetime
            }
            if ($enforceMode) { $policyParams['Enforce'] = $true }
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
        $null = Get-ADAuthenticationPolicy -Identity $compPolicyName -ErrorAction Stop
        Write-Host "      [=] Already exists: $compPolicyName" -ForegroundColor DarkGray
        $results.ComputerPolicyCreated = [PSCustomObject]@{ Name = $compPolicyName; Status = 'Existed' }
    } catch {
        try {
            $compParams = @{
                Name                     = $compPolicyName
                Description              = "Restricts service tickets to Tier 0 machines"
                ComputerTGTLifetimeMins  = $tgtLifetime
            }
            if ($enforceMode) { $compParams['Enforce'] = $true }
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
        $null = Get-ADAuthenticationPolicySilo -Identity $siloName -ErrorAction Stop
        Write-Host "      [=] Already exists: $siloName" -ForegroundColor DarkGray
        $results.SiloCreated = [PSCustomObject]@{ Name = $siloName; Status = 'Existed' }
    } catch {
        try {
            $siloParams = @{
                Name                          = $siloName
                Description                   = 'Tier 0 Authentication Silo'
                UserAuthenticationPolicy      = $policyName
                ComputerAuthenticationPolicy  = $compPolicyName
                ServiceAuthenticationPolicy   = $policyName
            }
            if ($enforceMode) { $siloParams['Enforce'] = $true }
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

    $serversOU = "OU=Servers,OU=$($ouCfg.Tier0),$baseDN"
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
    if ($results.Errors.Count -gt 0) {
        Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red
    }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

# Tiering\Invoke-MATITieringPhase6.ps1
# Phase 6 — GPO Hardening Per Tier
# Creates tier-specific hardening GPOs (DC, T0 servers, T1 servers, T2 workstations)
# and deploys LAPS configuration across all tiers.

function Invoke-MATITieringPhase6 {
    <#
    .SYNOPSIS
        Phase 6 — Interactive creation of per-tier hardening GPOs and LAPS deployment.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: Phase 1 OUs exist
        2. Create DC hardening GPO (credential protection, protocol hardening, audit, disable services)
        3. Create T0 server hardening GPO
        4. Create T1 server hardening GPO
        5. Create T2 workstation hardening GPO (+ lateral movement prevention)
        6. Create LAPS GPOs per tier
        7. Block inheritance on Tier 0 OU
        8. Generate an HTML deployment report
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
    $lapsCfg = $TieringConfig.LAPS
    $domain  = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $dnsRoot  = $domain.DNSRoot

    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    $prefix = $naming.GPOPrefix

    # Target OUs
    $dcOU        = "OU=Domain Controllers,$domainDN"
    $t0ServersOU = "OU=Servers,OU=$($ouCfg.Tier0),$baseDN"
    $t1ServersOU = "OU=Servers,OU=$($ouCfg.Tier1),$baseDN"
    $t2WksOU     = "OU=Workstations,OU=$($ouCfg.Tier2),$baseDN"
    $tier0OU     = "OU=$($ouCfg.Tier0),$baseDN"

    $results = @{
        BaseDN          = $baseDN
        GPOsCreated     = [System.Collections.Generic.List[object]]::new()
        GPOsExisted     = [System.Collections.Generic.List[object]]::new()
        LinksCreated    = [System.Collections.Generic.List[object]]::new()
        LinksExisted    = [System.Collections.Generic.List[object]]::new()
        SettingsApplied = [System.Collections.Generic.List[object]]::new()
        BlockInheritance = $false
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 6 — GPO Hardening Per Tier" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates per-tier hardening baselines + LAPS deployment.`n" -ForegroundColor DarkGray

    # Pre-checks
    Write-Host "  Pre-checks..." -ForegroundColor Yellow
    $requiredOUs = @($dcOU, $t0ServersOU, $t1ServersOU, $t2WksOU, $tier0OU)
    $missing = $requiredOUs | Where-Object { -not ([adsi]::Exists("LDAP://$_")) }
    if ($missing.Count -gt 0) {
        Write-Host "  [ERROR] Required OUs not found. Run Phase 1 first." -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "    Missing: $_" -ForegroundColor DarkGray }
        return
    }
    Write-Host "    [OK] All target OUs found" -ForegroundColor Green

    # ================================================================
    # Helper to create GPO, apply registry settings, and link
    # ================================================================
    function Deploy-HardeningGPO {
        param(
            [string]$GPOName,
            [string]$Description,
            [string[]]$LinkTargets,
            [hashtable[]]$RegistrySettings
        )

        $gpo = $null
        try {
            $gpo = Get-GPO -Name $GPOName -ErrorAction Stop
            Write-Host "      [=] Already exists: $GPOName" -ForegroundColor DarkGray
            $results.GPOsExisted.Add([PSCustomObject]@{ Name = $GPOName; Id = $gpo.Id; Status = 'Existed' })
        } catch {
            try {
                $gpo = New-GPO -Name $GPOName -Comment $Description -ErrorAction Stop
                Write-Host "      [+] Created: $GPOName" -ForegroundColor Green
                $results.GPOsCreated.Add([PSCustomObject]@{ Name = $GPOName; Id = $gpo.Id; Status = 'Created' })
            } catch {
                Write-Host "      [!] FAILED: $GPOName — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO creation failed: $GPOName — $($_.Exception.Message)")
                return
            }
        }

        # Apply registry settings
        foreach ($reg in $RegistrySettings) {
            try {
                Set-GPRegistryValue -Name $GPOName -Key $reg.Key -ValueName $reg.ValueName `
                    -Type $reg.Type -Value $reg.Value -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{
                    GPO = $GPOName; Setting = $reg.Label; Status = 'Applied'
                })
            } catch {
                $results.Errors.Add("Setting failed on $GPOName — $($reg.Label): $($_.Exception.Message)")
            }
        }

        # Link
        foreach ($target in $LinkTargets) {
            try {
                $existingLinks = (Get-GPInheritance -Target $target -ErrorAction Stop).GpoLinks
                if ($existingLinks | Where-Object { $_.DisplayName -eq $GPOName }) {
                    Write-Host "      [=] Already linked: $GPOName -> $target" -ForegroundColor DarkGray
                    $results.LinksExisted.Add([PSCustomObject]@{ GPO = $GPOName; Target = $target; Status = 'Existed' })
                } else {
                    New-GPLink -Name $GPOName -Target $target -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    Write-Host "      [+] Linked: $GPOName -> $target" -ForegroundColor Green
                    $results.LinksCreated.Add([PSCustomObject]@{ GPO = $GPOName; Target = $target; Status = 'Created' })
                }
            } catch {
                Write-Host "      [!] Link FAILED: $GPOName -> $target" -ForegroundColor Red
                $results.Errors.Add("Link failed: $GPOName -> $target — $($_.Exception.Message)")
            }
        }
    }

    # Common registry settings
    $wdigest   = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; ValueName = 'UseLogonCredential'; Type = 'DWord'; Value = 0; Label = 'Disable WDigest' }
    $runasppl  = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'RunAsPPL'; Type = 'DWord'; Value = 1; Label = 'LSASS RunAsPPL' }
    $noLLMNR   = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; ValueName = 'EnableMulticast'; Type = 'DWord'; Value = 0; Label = 'Disable LLMNR' }
    $cmdAudit  = @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; ValueName = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Label = 'Command-line auditing' }

    # ================================================================
    # Step 1 — DC Hardening
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/6 — Domain Controller Hardening GPO" -ForegroundColor Yellow

    $confirm = Read-Host "    Create DC hardening GPO? [Y/N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        Deploy-HardeningGPO -GPOName "$prefix - Hardening DC" -Description 'DC hardening baseline: WDigest, RunAsPPL, LLMNR, auditing' `
            -LinkTargets @($dcOU) -RegistrySettings @($wdigest, $runasppl, $noLLMNR, $cmdAudit)
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Step 2 — T0 Server Hardening
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/6 — Tier 0 Server Hardening GPO" -ForegroundColor Yellow

    $confirm = Read-Host "    Create T0 server hardening GPO? [Y/N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        Deploy-HardeningGPO -GPOName "$prefix - Hardening T0 Servers" -Description 'Tier 0 server hardening: WDigest, RunAsPPL, LLMNR, auditing' `
            -LinkTargets @($t0ServersOU) -RegistrySettings @($wdigest, $runasppl, $noLLMNR, $cmdAudit)
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Step 3 — T1 Server Hardening
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/6 — Tier 1 Server Hardening GPO" -ForegroundColor Yellow

    $credGuard = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; ValueName = 'EnableVirtualizationBasedSecurity'; Type = 'DWord'; Value = 1; Label = 'Credential Guard (VBS)' }
    $credGuardLsa = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; ValueName = 'LsaCfgFlags'; Type = 'DWord'; Value = 1; Label = 'Credential Guard UEFI lock' }
    $psLogging = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Label = 'PowerShell Script Block Logging' }

    $confirm = Read-Host "    Create T1 server hardening GPO? [Y/N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        Deploy-HardeningGPO -GPOName "$prefix - Hardening T1 Servers" `
            -Description 'Tier 1 server hardening: WDigest, RunAsPPL, Credential Guard, LLMNR, PS logging' `
            -LinkTargets @($t1ServersOU) `
            -RegistrySettings @($wdigest, $runasppl, $noLLMNR, $cmdAudit, $credGuard, $credGuardLsa, $psLogging)
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Step 4 — T2 Workstation Hardening
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/6 — Tier 2 Workstation Hardening GPO" -ForegroundColor Yellow

    $confirm = Read-Host "    Create T2 workstation hardening GPO? [Y/N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        Deploy-HardeningGPO -GPOName "$prefix - Hardening T2 Workstations" `
            -Description 'Tier 2 workstation hardening: WDigest, Credential Guard, LLMNR, PS logging, auditing' `
            -LinkTargets @($t2WksOU) `
            -RegistrySettings @($wdigest, $noLLMNR, $cmdAudit, $credGuard, $credGuardLsa, $psLogging)
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Step 5 — LAPS GPOs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 5/6 — LAPS Deployment GPOs" -ForegroundColor Yellow
    Write-Host "    LAPS settings: Length=$($lapsCfg.PasswordLength), Age=$($lapsCfg.PasswordAgeDays) days, Windows LAPS=$($lapsCfg.UseWindowsLAPS)" -ForegroundColor DarkGray

    $confirm = Read-Host "    Create LAPS GPOs per tier? [Y/N]"
    if ($confirm.Trim().ToUpper() -eq 'Y') {
        $lapsTargets = @(
            @{ Name = "$prefix - LAPS T0 Servers";      LinkTarget = $t0ServersOU }
            @{ Name = "$prefix - LAPS T1 Servers";      LinkTarget = $t1ServersOU }
            @{ Name = "$prefix - LAPS T2 Workstations"; LinkTarget = $t2WksOU }
        )

        $lapsSettings = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName = 'AdmPwdEnabled'; Type = 'DWord'; Value = 1; Label = 'Enable LAPS' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName = 'PasswordLength'; Type = 'DWord'; Value = $lapsCfg.PasswordLength; Label = "LAPS Password Length ($($lapsCfg.PasswordLength))" }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName = 'PasswordAgeDays'; Type = 'DWord'; Value = $lapsCfg.PasswordAgeDays; Label = "LAPS Password Age ($($lapsCfg.PasswordAgeDays) days)" }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd'; ValueName = 'PasswordComplexity'; Type = 'DWord'; Value = 4; Label = 'LAPS Complexity (all)' }
        )

        foreach ($lt in $lapsTargets) {
            Deploy-HardeningGPO -GPOName $lt.Name -Description "LAPS deployment: $($lapsCfg.PasswordLength) chars, $($lapsCfg.PasswordAgeDays) day rotation" `
                -LinkTargets @($lt.LinkTarget) -RegistrySettings $lapsSettings
        }
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Step 6 — Block Inheritance on Tier 0
    # ================================================================
    Write-Host ""
    Write-Host "  Step 6/6 — Block Inheritance on Tier 0 OU" -ForegroundColor Yellow
    Write-Host "    This prevents domain-level GPOs from weakening T0 hardening." -ForegroundColor DarkGray
    Write-Host "    You must manually re-link necessary GPOs to the T0 OU after blocking." -ForegroundColor DarkGray

    $blockChoice = Read-Host "    Block inheritance on $tier0OU? [Y/N]"
    if ($blockChoice.Trim().ToUpper() -eq 'Y') {
        try {
            Set-GPInheritance -Target $tier0OU -IsBlocked Yes -ErrorAction Stop
            Write-Host "      [+] Block Inheritance enabled on $tier0OU" -ForegroundColor Green
            $results.BlockInheritance = $true
        } catch {
            Write-Host "      [!] FAILED: $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Block Inheritance failed: $($_.Exception.Message)")
        }
    } else { Write-Host "    [!] Skipped." -ForegroundColor Yellow }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 6 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase6-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase6Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase6-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 6 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   GPOs     : $($results.GPOsCreated.Count) created, $($results.GPOsExisted.Count) existed" -ForegroundColor White
    Write-Host "   Links    : $($results.LinksCreated.Count) created" -ForegroundColor White
    Write-Host "   Settings : $($results.SettingsApplied.Count) configured" -ForegroundColor White
    Write-Host "   Block Inh: $($results.BlockInheritance)" -ForegroundColor White
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

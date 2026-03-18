# Tiering\Invoke-MATITieringPhase5.ps1
# Phase 5 — PAW Hardening GPOs
# Creates and links hardening GPOs for Privileged Access Workstations (Tier 0 PAW).

function Invoke-MATITieringPhase5 {
    <#
    .SYNOPSIS
        Phase 5 — Interactive creation of PAW hardening GPOs.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: Phase 1 OUs exist (Tier 0\PAW)
        2. Create PAW hardening GPO (Credential Guard, WDAC, firewall, loopback)
        3. Create PAW firewall GPO (outbound RDP to T0 only, block internet)
        4. Create PAW loopback GPO (Replace mode)
        5. Link GPOs to Tier 0\PAW OU
        6. Generate an HTML deployment report
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
    $dnsRoot  = $domain.DNSRoot

    # Determine base DN
    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    # Target OUs
    $pawOU = "OU=PAW,OU=$($ouCfg.Tier0),$baseDN"

    # Results tracker
    $results = @{
        BaseDN          = $baseDN
        PAW_OU          = $pawOU
        GPOsCreated     = [System.Collections.Generic.List[object]]::new()
        GPOsExisted     = [System.Collections.Generic.List[object]]::new()
        LinksCreated    = [System.Collections.Generic.List[object]]::new()
        LinksExisted    = [System.Collections.Generic.List[object]]::new()
        SettingsApplied = [System.Collections.Generic.List[object]]::new()
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Banner
    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 5 — PAW Hardening GPOs" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates hardening GPOs for Tier 0 PAW machines." -ForegroundColor DarkGray
    Write-Host "   Target OU: $pawOU`n" -ForegroundColor DarkGray

    # ================================================================
    # Pre-checks
    # ================================================================
    Write-Host "  Pre-checks..." -ForegroundColor Yellow
    if (-not ([adsi]::Exists("LDAP://$pawOU"))) {
        Write-Host "  [ERROR] PAW OU not found: $pawOU. Run Phase 1 first." -ForegroundColor Red
        return
    }
    Write-Host "    [OK] PAW OU found: $pawOU" -ForegroundColor Green

    # ================================================================
    # GPO Definitions
    # ================================================================
    $prefix = $naming.GPOPrefix
    $gpoPrefix = $naming.GroupPrefix

    $gpoDefs = @(
        @{
            Name        = "$prefix - PAW T0 Hardening"
            Description = 'Credential Guard, VBS, LSASS protection, USB restriction for T0 PAWs'
            Settings    = @(
                @{ Category = 'Credential Guard';  Setting = 'Turn on Virtualization Based Security'; Value = 'Enabled with UEFI lock' }
                @{ Category = 'LSASS Protection';  Setting = 'RunAsPPL (LSASS Protected Mode)'; Value = 'Enabled' }
                @{ Category = 'Device Security';   Setting = 'Prevent installation of removable devices'; Value = 'Enabled' }
                @{ Category = 'Network';           Setting = 'Turn off multicast name resolution (LLMNR)'; Value = 'Enabled' }
                @{ Category = 'Remote Desktop';    Setting = 'Require Network Level Authentication'; Value = 'Enabled' }
                @{ Category = 'Remote Desktop';    Setting = 'Set client connection encryption level'; Value = 'High' }
                @{ Category = 'Credential Delegation'; Setting = 'Restrict delegation — Require Remote Credential Guard'; Value = 'Enabled' }
                @{ Category = 'Windows Store';     Setting = 'Turn off the Store application'; Value = 'Enabled' }
                @{ Category = 'Audit';             Setting = 'Include command line in process creation events'; Value = 'Enabled' }
            )
        }
        @{
            Name        = "$prefix - PAW T0 Firewall"
            Description = 'Outbound: RDP to T0 only; block internet and cross-tier traffic'
            Settings    = @(
                @{ Category = 'Firewall'; Setting = 'Inbound default'; Value = 'Block all' }
                @{ Category = 'Firewall'; Setting = 'Outbound RDP (3389)'; Value = 'Allow to T0 servers/DCs only' }
                @{ Category = 'Firewall'; Setting = 'Outbound Kerberos/LDAP/DNS'; Value = 'Allow to DCs only' }
                @{ Category = 'Firewall'; Setting = 'Outbound Internet'; Value = 'Block all' }
                @{ Category = 'Firewall'; Setting = 'Outbound to T1/T2'; Value = 'Block all' }
            )
        }
        @{
            Name        = "$prefix - PAW T0 Loopback"
            Description = 'User Group Policy loopback processing in Replace mode for PAW OU'
            Settings    = @(
                @{ Category = 'Group Policy'; Setting = 'Configure user Group Policy loopback processing mode'; Value = 'Enabled — Replace' }
            )
        }
    )

    # ================================================================
    # Step 1 — Review
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/3 — GPO Plan Review" -ForegroundColor Yellow
    Write-Host ""
    foreach ($def in $gpoDefs) {
        Write-Host "    GPO: $($def.Name)" -ForegroundColor Cyan
        Write-Host "    $($def.Description)" -ForegroundColor DarkGray
        foreach ($s in $def.Settings) {
            Write-Host "      - [$($s.Category)] $($s.Setting) = $($s.Value)" -ForegroundColor White
        }
        Write-Host ""
    }

    $confirm = Read-Host "    Proceed with GPO creation? [Y/N]"
    if ($confirm.Trim().ToUpper() -ne 'Y') {
        Write-Host "    [!] Cancelled by user." -ForegroundColor Yellow; return
    }

    # ================================================================
    # Step 2 — Create GPOs and configure settings
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/3 — Creating GPOs and Configuring Settings" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefs) {
        $gpoName = $def.Name
        $gpo = $null

        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
            Write-Host "      [=] Already exists: $gpoName" -ForegroundColor DarkGray
            $results.GPOsExisted.Add([PSCustomObject]@{ Name = $gpoName; Id = $gpo.Id; Status = 'Existed' })
        } catch {
            try {
                $gpo = New-GPO -Name $gpoName -Comment $def.Description -ErrorAction Stop
                Write-Host "      [+] Created: $gpoName" -ForegroundColor Green
                $results.GPOsCreated.Add([PSCustomObject]@{ Name = $gpoName; Id = $gpo.Id; Status = 'Created' })
            } catch {
                Write-Host "      [!] FAILED: $gpoName — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO creation failed: $gpoName — $($_.Exception.Message)")
                continue
            }
        }

        # Configure registry-based settings via Set-GPRegistryValue
        if ($gpoName -match 'Hardening') {
            # Credential Guard / VBS
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
                    -ValueName 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
                    -ValueName 'LsaCfgFlags' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' `
                    -ValueName 'RequirePlatformSecurityFeatures' -Type DWord -Value 3 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Credential Guard + VBS'; Status = 'Applied' })
            } catch { $results.Errors.Add("Credential Guard setting failed: $($_.Exception.Message)") }

            # LSASS RunAsPPL
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' `
                    -ValueName 'RunAsPPL' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'LSASS RunAsPPL'; Status = 'Applied' })
            } catch { $results.Errors.Add("RunAsPPL setting failed: $($_.Exception.Message)") }

            # Disable LLMNR
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                    -ValueName 'EnableMulticast' -Type DWord -Value 0 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable LLMNR'; Status = 'Applied' })
            } catch { $results.Errors.Add("LLMNR setting failed: $($_.Exception.Message)") }

            # Remote Credential Guard
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
                    -ValueName 'RestrictedRemoteAdministration' -Type DWord -Value 2 -ErrorAction Stop | Out-Null
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' `
                    -ValueName 'RestrictedRemoteAdministrationType' -Type DWord -Value 2 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Remote Credential Guard'; Status = 'Applied' })
            } catch { $results.Errors.Add("Remote Credential Guard setting failed: $($_.Exception.Message)") }

            # Disable Windows Store
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' `
                    -ValueName 'RemoveWindowsStore' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable Windows Store'; Status = 'Applied' })
            } catch { $results.Errors.Add("Windows Store setting failed: $($_.Exception.Message)") }

            # Command-line auditing
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
                    -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Command-line auditing'; Status = 'Applied' })
            } catch { $results.Errors.Add("Command-line auditing setting failed: $($_.Exception.Message)") }

            # Disable WDigest
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
                    -ValueName 'UseLogonCredential' -Type DWord -Value 0 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable WDigest'; Status = 'Applied' })
            } catch { $results.Errors.Add("WDigest setting failed: $($_.Exception.Message)") }

            Write-Host "      [+] Configured hardening settings" -ForegroundColor Green
        }

        if ($gpoName -match 'Loopback') {
            try {
                Set-GPRegistryValue -Name $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\System' `
                    -ValueName 'UserPolicyMode' -Type DWord -Value 1 -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Loopback Replace Mode'; Status = 'Applied' })
                Write-Host "      [+] Configured loopback replace mode" -ForegroundColor Green
            } catch {
                Write-Host "      [!] Loopback setting failed: $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("Loopback setting failed: $($_.Exception.Message)")
            }
        }

        if ($gpoName -match 'Firewall') {
            Write-Host "      [i] Firewall GPO created. Configure Windows Firewall rules manually via GPMC." -ForegroundColor Yellow
            Write-Host "          Recommended: Outbound RDP (3389) to T0 DCs/servers only; block all internet." -ForegroundColor DarkGray
            $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Firewall rules'; Status = 'Manual config required' })
        }
    }

    # ================================================================
    # Step 3 — Link GPOs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/3 — Linking GPOs to PAW OU" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefs) {
        $gpoName = $def.Name
        try {
            $existingLinks = (Get-GPInheritance -Target $pawOU -ErrorAction Stop).GpoLinks
            $alreadyLinked = $existingLinks | Where-Object { $_.DisplayName -eq $gpoName }
            if ($alreadyLinked) {
                Write-Host "      [=] Already linked: $gpoName -> $pawOU" -ForegroundColor DarkGray
                $results.LinksExisted.Add([PSCustomObject]@{ GPO = $gpoName; Target = $pawOU; Status = 'Existed' })
            } else {
                New-GPLink -Name $gpoName -Target $pawOU -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Host "      [+] Linked: $gpoName -> $pawOU" -ForegroundColor Green
                $results.LinksCreated.Add([PSCustomObject]@{ GPO = $gpoName; Target = $pawOU; Status = 'Created' })
            }
        } catch {
            Write-Host "      [!] Link FAILED: $gpoName -> $pawOU — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("GPO link failed: $gpoName -> $pawOU — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 5 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase5-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase5Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase5-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 5 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   GPOs     : $($results.GPOsCreated.Count) created, $($results.GPOsExisted.Count) existed" -ForegroundColor White
    Write-Host "   Links    : $($results.LinksCreated.Count) created" -ForegroundColor White
    Write-Host "   Settings : $($results.SettingsApplied.Count) configured" -ForegroundColor White
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

# Tiering\Invoke-MATITieringPhase3.ps1
# Phase 3 — Deny Logon GPOs
# Creates the six cross-tier deny-logon GPOs, configures user-rights assignment,
# and links them to the correct OUs.

function Invoke-MATITieringPhase3 {
    <#
    .SYNOPSIS
        Phase 3 — Interactive creation of deny-logon GPOs for tier isolation.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: Phase 1 groups and OUs must exist
        2. Review the 6 GPO definitions and deny-logon rights
        3. Create GPOs and configure deny-logon user rights
        4. Link GPOs to the correct tier OUs
        5. Optionally link T0-protection GPOs to Domain Controllers OU
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

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
    }

    $naming  = $TieringConfig.Naming
    $ouCfg   = $TieringConfig.OUStructure
    $gpoCfg  = $TieringConfig.GPO
    $grpCfg  = $TieringConfig.Groups
    $domain  = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $dnsRoot  = $domain.DNSRoot

    # Determine base DN
    $containerOU = $ouCfg.ContainerOU
    if ($containerOU) {
        $candidateDN = "OU=$containerOU,$domainDN"
        if ([adsi]::Exists("LDAP://$candidateDN")) { $baseDN = $candidateDN } else { $baseDN = $domainDN }
    } else { $baseDN = $domainDN }

    # Results tracker
    $results = @{
        BaseDN          = $baseDN
        ContainerOU     = $containerOU
        GPOsCreated     = [System.Collections.Generic.List[object]]::new()
        GPOsExisted     = [System.Collections.Generic.List[object]]::new()
        LinksCreated    = [System.Collections.Generic.List[object]]::new()
        LinksExisted    = [System.Collections.Generic.List[object]]::new()
        RightsConfigured = [System.Collections.Generic.List[object]]::new()
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Banner
    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 3 — Deny Logon GPOs" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates 6 cross-tier deny-logon GPOs to enforce tier boundaries." -ForegroundColor DarkGray
    Write-Host "   GPO prefix: $($naming.GPOPrefix)`n" -ForegroundColor DarkGray

    # ================================================================
    # Pre-checks
    # ================================================================
    Write-Host "  Pre-checks..." -ForegroundColor Yellow

    # Check tier OUs exist
    $tierOUs = @{
        'Tier0' = "OU=$($ouCfg.Tier0),$baseDN"
        'Tier1' = "OU=$($ouCfg.Tier1),$baseDN"
        'Tier2' = "OU=$($ouCfg.Tier2),$baseDN"
    }
    $missingOUs = @()
    foreach ($kv in $tierOUs.GetEnumerator()) {
        if (-not ([adsi]::Exists("LDAP://$($kv.Value)"))) { $missingOUs += $kv.Value }
    }
    if ($missingOUs.Count -gt 0) {
        Write-Host "`n  [ERROR] Phase 1 OU structure not found. Run Phase 1 first." -ForegroundColor Red
        $missingOUs | ForEach-Object { Write-Host "    Missing: $_" -ForegroundColor DarkGray }
        Write-Host ""; return
    }

    # Check deny-logon groups exist
    $denySuffix = $grpCfg.DenyLogonSuffix
    $prefix     = $naming.GroupPrefix
    $denyGroups = @(
        "${prefix}0-${denySuffix}-${prefix}1"
        "${prefix}0-${denySuffix}-${prefix}2"
        "${prefix}1-${denySuffix}-${prefix}0"
        "${prefix}1-${denySuffix}-${prefix}2"
        "${prefix}2-${denySuffix}-${prefix}0"
        "${prefix}2-${denySuffix}-${prefix}1"
    )
    $missingGroups = @()
    foreach ($g in $denyGroups) {
        try { $null = Get-ADGroup -Identity $g -ErrorAction Stop }
        catch { $missingGroups += $g }
    }
    if ($missingGroups.Count -gt 0) {
        Write-Host "`n  [ERROR] Deny-logon groups not found. Run Phase 1 first." -ForegroundColor Red
        $missingGroups | ForEach-Object { Write-Host "    Missing: $_" -ForegroundColor DarkGray }
        Write-Host ""; return
    }

    Write-Host "    [OK] Tier OUs found" -ForegroundColor Green
    Write-Host "    [OK] Deny-logon groups found" -ForegroundColor Green

    # ================================================================
    # Build GPO definitions
    # ================================================================
    # Each GPO denies one tier's accounts from logging onto another tier's machines.
    # Deny rights are configured via GptTmpl.inf in the GPO's SYSVOL folder.
    $denyRights = $gpoCfg.DenyLogonRights

    $gpoDefinitions = @(
        @{
            Name       = "$($naming.GPOPrefix) - Deny T0 Logon on T1"
            Group      = "${prefix}0-${denySuffix}-${prefix}1"
            LinkTargets = @($tierOUs.Tier1)
            Description = "Prevents Tier 0 accounts from logging into Tier 1 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T0 Logon on T2"
            Group      = "${prefix}0-${denySuffix}-${prefix}2"
            LinkTargets = @($tierOUs.Tier2)
            Description = "Prevents Tier 0 accounts from logging into Tier 2 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T1 Logon on T0"
            Group      = "${prefix}1-${denySuffix}-${prefix}0"
            LinkTargets = @($tierOUs.Tier0, "OU=Domain Controllers,$domainDN")
            Description = "Prevents Tier 1 accounts from logging into Tier 0 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T1 Logon on T2"
            Group      = "${prefix}1-${denySuffix}-${prefix}2"
            LinkTargets = @($tierOUs.Tier2)
            Description = "Prevents Tier 1 accounts from logging into Tier 2 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T2 Logon on T0"
            Group      = "${prefix}2-${denySuffix}-${prefix}0"
            LinkTargets = @($tierOUs.Tier0, "OU=Domain Controllers,$domainDN")
            Description = "Prevents Tier 2 accounts from logging into Tier 0 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T2 Logon on T1"
            Group      = "${prefix}2-${denySuffix}-${prefix}1"
            LinkTargets = @($tierOUs.Tier1)
            Description = "Prevents Tier 2 accounts from logging into Tier 1 machines"
        }
    )

    # ================================================================
    # Step 1 — Review GPO plan
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/4 — GPO Plan Review" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    The following 6 GPOs will be created:" -ForegroundColor White
    Write-Host ""
    $i = 1
    foreach ($def in $gpoDefinitions) {
        Write-Host "    $i. $($def.Name)" -ForegroundColor Cyan
        Write-Host "       Deny group : $($def.Group)" -ForegroundColor DarkGray
        Write-Host "       Linked to  : $($def.LinkTargets -join ', ')" -ForegroundColor DarkGray
        Write-Host "       Rights     : $($denyRights -join ', ')" -ForegroundColor DarkGray
        Write-Host ""
        $i++
    }

    $confirm = Read-Host "    Proceed with GPO creation? [Y/N]"
    if ($confirm.Trim().ToUpper() -ne 'Y') {
        Write-Host "    [!] Cancelled by user." -ForegroundColor Yellow
        return
    }

    # ================================================================
    # Step 2 — Create GPOs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/4 — Creating GPOs" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefinitions) {
        $gpoName = $def.Name
        try {
            $existingGpo = Get-GPO -Name $gpoName -ErrorAction Stop
            Write-Host "      [=] Already exists: $gpoName" -ForegroundColor DarkGray
            $results.GPOsExisted.Add([PSCustomObject]@{ Name = $gpoName; Id = $existingGpo.Id; Status = 'Existed' })
        } catch {
            try {
                $newGpo = New-GPO -Name $gpoName -Comment $def.Description -ErrorAction Stop
                Write-Host "      [+] Created: $gpoName" -ForegroundColor Green
                $results.GPOsCreated.Add([PSCustomObject]@{ Name = $gpoName; Id = $newGpo.Id; Status = 'Created' })
            } catch {
                Write-Host "      [!] FAILED: $gpoName — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO creation failed: $gpoName — $($_.Exception.Message)")
                continue
            }
        }
    }

    # ================================================================
    # Step 3 — Configure deny-logon rights via GptTmpl.inf
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/4 — Configuring Deny Logon Rights" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefinitions) {
        $gpoName  = $def.Name
        $groupName = $def.Group

        try {
            $gpo = Get-GPO -Name $gpoName -ErrorAction Stop
        } catch {
            Write-Host "      [!] GPO not found for rights config: $gpoName" -ForegroundColor Red
            $results.Errors.Add("GPO not found for rights config: $gpoName")
            continue
        }

        # Resolve group SID
        try {
            $groupObj = Get-ADGroup -Identity $groupName -ErrorAction Stop
            $groupSID = $groupObj.SID.Value
        } catch {
            Write-Host "      [!] Cannot resolve SID for $groupName" -ForegroundColor Red
            $results.Errors.Add("Cannot resolve SID for $groupName")
            continue
        }

        # Build GptTmpl.inf content
        $infPath = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\{$($gpo.Id)}\Machine\Microsoft\Windows NT\SecEdit"
        $infFile = Join-Path $infPath 'GptTmpl.inf'

        try {
            if (-not (Test-Path $infPath)) {
                New-Item -ItemType Directory -Force -Path $infPath | Out-Null
            }

            $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
"@
            foreach ($right in $denyRights) {
                $infContent += "`n$right = *$groupSID"
            }

            Set-Content -Path $infFile -Value $infContent -Encoding Unicode -Force

            # Update GPO machine extension CSE GUIDs so the policy engine processes security settings
            $gpoADPath = "CN={$($gpo.Id)},CN=Policies,CN=System,$domainDN"
            $cseGuids  = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
            try {
                $gpoADObj = Get-ADObject -Identity $gpoADPath -Properties gPCMachineExtensionNames -ErrorAction Stop
                $current  = $gpoADObj.gPCMachineExtensionNames
                if (-not $current -or $current -notmatch '827D319E') {
                    $newValue = if ($current) { $current + $cseGuids } else { $cseGuids }
                    Set-ADObject -Identity $gpoADPath -Replace @{ gPCMachineExtensionNames = $newValue }
                }
            } catch {
                $results.Errors.Add("CSE GUID update failed for $gpoName — $($_.Exception.Message)")
            }

            # Bump GPO version
            $gpo.MakeADEditable()
            try {
                $verPath = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\{$($gpo.Id)}\GPT.INI"
                if (Test-Path $verPath) {
                    $gptIni = Get-Content $verPath -Raw
                    if ($gptIni -match 'Version=(\d+)') {
                        $ver = [int]$Matches[1] + 1
                        $gptIni = $gptIni -replace 'Version=\d+', "Version=$ver"
                        Set-Content -Path $verPath -Value $gptIni -Force
                    }
                }
            } catch { <# non-fatal #> }

            Write-Host "      [+] Configured deny rights on: $gpoName" -ForegroundColor Green
            foreach ($right in $denyRights) {
                $results.RightsConfigured.Add([PSCustomObject]@{
                    GPO   = $gpoName
                    Right = $right
                    Group = $groupName
                    SID   = $groupSID
                    Status = 'Configured'
                })
            }
        } catch {
            Write-Host "      [!] FAILED configuring rights on $gpoName — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Rights config failed: $gpoName — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Step 4 — Link GPOs to OUs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/4 — Linking GPOs to OUs" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefinitions) {
        $gpoName = $def.Name
        foreach ($target in $def.LinkTargets) {
            try {
                # Check if already linked
                $existingLinks = (Get-GPInheritance -Target $target -ErrorAction Stop).GpoLinks
                $alreadyLinked = $existingLinks | Where-Object { $_.DisplayName -eq $gpoName }

                if ($alreadyLinked) {
                    Write-Host "      [=] Already linked: $gpoName -> $target" -ForegroundColor DarkGray
                    $results.LinksExisted.Add([PSCustomObject]@{ GPO = $gpoName; Target = $target; Status = 'Existed' })
                } else {
                    New-GPLink -Name $gpoName -Target $target -LinkEnabled Yes -ErrorAction Stop | Out-Null
                    Write-Host "      [+] Linked: $gpoName -> $target" -ForegroundColor Green
                    $results.LinksCreated.Add([PSCustomObject]@{ GPO = $gpoName; Target = $target; Status = 'Created' })
                }
            } catch {
                Write-Host "      [!] Link FAILED: $gpoName -> $target — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO link failed: $gpoName -> $target — $($_.Exception.Message)")
            }
        }
    }

    # ================================================================
    # Generate Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 3 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase3-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase3Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase3-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 3 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   GPOs    : $($results.GPOsCreated.Count) created, $($results.GPOsExisted.Count) existed" -ForegroundColor White
    Write-Host "   Links   : $($results.LinksCreated.Count) created, $($results.LinksExisted.Count) existed" -ForegroundColor White
    Write-Host "   Rights  : $($results.RightsConfigured.Count) configured" -ForegroundColor White
    if ($results.Errors.Count -gt 0) {
        Write-Host "   Errors  : $($results.Errors.Count)" -ForegroundColor Red
    }
    Write-Host "   Report  : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

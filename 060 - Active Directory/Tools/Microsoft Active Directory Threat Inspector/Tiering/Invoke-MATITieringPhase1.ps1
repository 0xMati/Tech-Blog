# Tiering\Invoke-MATITieringPhase1.ps1
# Phase 1 — Create Recommended OU Structure & Group Model
# Creates the tiering OU hierarchy, security groups, deny-logon group nesting,
# and optionally redirects the default Computers/Users containers.

function Invoke-MATITieringPhase1 {
    <#
    .SYNOPSIS
        Phase 1 — Interactive creation of the tiering OU structure and security groups.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Choose placement: domain root vs. container sub-OU
        2. Create OU hierarchy (idempotent — skips existing OUs)
        3. Create security groups and prepare deny-logon nesting for later GPO enforcement
        4. Optionally redirect default Computers container (redircmp)
        5. Optionally redirect default Users container (redirusr)
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
    $ouCfg    = $TieringConfig.OUStructure
    $grpCfg   = $TieringConfig.Groups
    $naming   = $TieringConfig.Naming
    $domain   = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName

    # Results tracker
    $results = @{
        Placement       = ''
        BaseDN          = ''
        ContainerOU     = $null
        ContainerOUDN   = ''
        Tier0OUDN       = ''
        Tier1OUDN       = ''
        Tier2OUDN       = ''
        OUsCreated      = [System.Collections.Generic.List[string]]::new()
        OUsExisted      = [System.Collections.Generic.List[string]]::new()
        GroupsCreated   = [System.Collections.Generic.List[string]]::new()
        GroupsExisted   = [System.Collections.Generic.List[string]]::new()
        NestingDone     = [System.Collections.Generic.List[string]]::new()
        NestingSkipped  = [System.Collections.Generic.List[string]]::new()
        RedircmpDone    = $false
        RedircmpTarget  = ''
        RedirusrDone    = $false
        RedirusrTarget  = ''
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Helper: Create OU if it doesn't exist (idempotent)
    # ================================================================
    function Ensure-OU {
        param([string]$Name, [string]$ParentDN, [string]$Description)
        $ouDN = "OU=$Name,$ParentDN"
        $existingOu = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction SilentlyContinue
        if ($existingOu) {
            Write-Host "      [=] Already exists: $ouDN" -ForegroundColor DarkGray
            $results.OUsExisted.Add($ouDN)
        } else {
            try {
                New-ADOrganizationalUnit -Name $Name -Path $ParentDN `
                    -Description $Description `
                    -ProtectedFromAccidentalDeletion $true -ErrorAction Stop
                Write-Host "      [+] Created: $ouDN" -ForegroundColor Green
                $results.OUsCreated.Add($ouDN)
            } catch {
                Write-Host "      [!] FAILED: $ouDN — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("OU creation failed: $ouDN — $($_.Exception.Message)")
            }
        }
        return $ouDN
    }

    # ================================================================
    # Helper: Create group if it doesn't exist (idempotent)
    # ================================================================
    function Ensure-Group {
        param([string]$Name, [string]$Path, [string]$Scope, [string]$Description)
        $existingGroup = Get-ADGroup -Identity $Name -ErrorAction SilentlyContinue
        if ($existingGroup) {
            Write-Host "      [=] Already exists: $Name" -ForegroundColor DarkGray
            $results.GroupsExisted.Add($Name)
        } else {
            try {
                New-ADGroup -Name $Name -GroupScope $Scope -GroupCategory Security `
                    -Path $Path -Description $Description -ErrorAction Stop
                Write-Host "      [+] Created: $Name ($Scope)" -ForegroundColor Green
                $results.GroupsCreated.Add($Name)
            } catch {
                Write-Host "      [!] FAILED: $Name — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("Group creation failed: $Name — $($_.Exception.Message)")
            }
        }
    }

    # ================================================================
    # Helper: Add group nesting if not already a member
    # ================================================================
    function Ensure-Nesting {
        param([string]$Group, [string]$Member)
        try {
            $members = Get-ADGroupMember -Identity $Group -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
            if ($Member -in $members) {
                Write-Host "      [=] $Member already in $Group" -ForegroundColor DarkGray
                $results.NestingSkipped.Add("$Member -> $Group")
            } else {
                Add-ADGroupMember -Identity $Group -Members $Member -ErrorAction Stop
                Write-Host "      [+] Added $Member -> $Group" -ForegroundColor Green
                $results.NestingDone.Add("$Member -> $Group")
            }
        } catch {
            Write-Host "      [!] Nesting failed: $Member -> $Group — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("Nesting failed: $Member -> $Group — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Helper: Resolve container OU input
    # The wizard expects a full OU distinguished name.
    # If only a simple name is provided, it is created under the domain root.
    # ================================================================
    function Resolve-ContainerOUInput {
        param(
            [string]$InputValue,
            [string]$DefaultName,
            [string]$DefaultParentDN
        )

        $rawValue = if ($InputValue) { $InputValue.Trim() } else { '' }
        if (-not $rawValue) {
            $rawValue = $DefaultName
        }

        if ($rawValue -match '^(?i)OU=') {
            $parts = $rawValue -split '(?<!\\),', 2
            $leaf = $parts[0]
            $parentDN = if ($parts.Count -gt 1) { $parts[1] } else { $DefaultParentDN }
            $name = ($leaf -replace '^(?i)OU=', '').Trim()

            return [ordered]@{
                Name     = $name
                ParentDN = $parentDN
                TargetDN = "OU=$name,$parentDN"
                RawValue = $rawValue
            }
        }

        return [ordered]@{
            Name     = $rawValue
            ParentDN = $DefaultParentDN
            TargetDN = "OU=$rawValue,$DefaultParentDN"
            RawValue = $rawValue
        }
    }

    # ================================================================
    # STEP 1 — Choose placement
    # ================================================================
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 1 — Create Recommended OU Structure & Group Model" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Step 1/5 — OU Placement" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    Where should the tiering OUs be created?" -ForegroundColor White
    Write-Host ""
    Write-Host "    [A] At the domain root" -ForegroundColor Cyan
    Write-Host "        $domainDN" -ForegroundColor DarkGray
    Write-Host "        └── Tier 0/" -ForegroundColor DarkGray
    Write-Host "        └── Tier 1/" -ForegroundColor DarkGray
    Write-Host "        └── Tier 2/" -ForegroundColor DarkGray
    Write-Host "        └── Quarantine/" -ForegroundColor DarkGray
    Write-Host "        └── ..." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "    [B] Under a container sub-OU (recommended for existing environments)" -ForegroundColor Cyan
    Write-Host "        $domainDN" -ForegroundColor DarkGray
    Write-Host "        └── $($ouCfg.ContainerOU)/" -ForegroundColor DarkGray
    Write-Host "            └── Tier 0/" -ForegroundColor DarkGray
    Write-Host "            └── Tier 1/" -ForegroundColor DarkGray
    Write-Host "            └── ..." -ForegroundColor DarkGray
    Write-Host ""

    $placementValid = $false
    while (-not $placementValid) {
        $placementChoice = Read-Host "    Select placement [A/B]"
        switch ($placementChoice.Trim().ToUpper()) {
            'A' {
                $baseDN = $domainDN
                $results.Placement = 'Domain Root'
                $results.BaseDN = $baseDN
                $placementValid = $true
            }
            'B' {
                $defaultName = $ouCfg.ContainerOU
                $defaultDNExample = "OU=$defaultName,DC=contoso,DC=com"
                $containerInput = Read-Host "    Container OU distinguishedName [$defaultDNExample]"
                $containerInfo = Resolve-ContainerOUInput -InputValue $containerInput -DefaultName $defaultName -DefaultParentDN $domainDN
                $containerName = $containerInfo.Name

                Write-Host ""
                if ($containerInfo.RawValue -notmatch '^(?i)OU=') {
                    Write-Host "    [!] Simple OU name detected. Using domain root as parent: $($containerInfo.TargetDN)" -ForegroundColor Yellow
                }
                Write-Host "    Creating container OU: $($containerInfo.TargetDN)" -ForegroundColor Yellow
                $baseDN = Ensure-OU -Name $containerName -ParentDN $containerInfo.ParentDN -Description 'Tiering Model — container OU for all tiering objects'
                $results.Placement = "Sub-OU: $($containerInfo.TargetDN)"
                $results.BaseDN = $baseDN
                $results.ContainerOU = $containerName
                $results.ContainerOUDN = $baseDN
                $placementValid = $true
            }
            default {
                Write-Host "    [!] Please select A or B." -ForegroundColor Yellow
            }
        }
    }

    # ================================================================
    # STEP 2 — Show planned OU tree and confirm
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/5 — OU Structure Preview" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    The following OU structure will be created under:" -ForegroundColor White
    Write-Host "    $baseDN" -ForegroundColor DarkGray
    Write-Host ""

    # Build the visual tree
    $tierNames = @(
        @{ Key = 'Tier0'; Name = $ouCfg.Tier0; SubOUs = $ouCfg.SubOUs.Tier0 }
        @{ Key = 'Tier1'; Name = $ouCfg.Tier1; SubOUs = $ouCfg.SubOUs.Tier1 }
        @{ Key = 'Tier2'; Name = $ouCfg.Tier2; SubOUs = $ouCfg.SubOUs.Tier2 }
    )
    $otherOUs = @(
        @{ Name = $ouCfg.Quarantine;    SubOUs = $ouCfg.QuarantineSubOUs }
        @{ Name = $ouCfg.Disabled;      SubOUs = $ouCfg.DisabledSubOUs }
        @{ Name = $ouCfg.StandardUsers; SubOUs = @() }
    )

    foreach ($tier in $tierNames) {
        Write-Host "    ├── $($tier.Name)/" -ForegroundColor Green
        for ($i = 0; $i -lt $tier.SubOUs.Count; $i++) {
            $prefix = if ($i -lt $tier.SubOUs.Count - 1) { '│   ├──' } else { '│   └──' }
            Write-Host "    $prefix $($tier.SubOUs[$i])/" -ForegroundColor DarkGreen
        }
    }
    foreach ($ou in $otherOUs) {
        $color = if ($ou.Name -eq $ouCfg.Quarantine) { 'Yellow' } elseif ($ou.Name -eq $ouCfg.Disabled) { 'DarkYellow' } else { 'White' }
        Write-Host "    ├── $($ou.Name)/" -ForegroundColor $color
        for ($i = 0; $i -lt $ou.SubOUs.Count; $i++) {
            $prefix = if ($i -lt $ou.SubOUs.Count - 1) { '│   ├──' } else { '│   └──' }
            Write-Host "    $prefix $($ou.SubOUs[$i])/" -ForegroundColor DarkGray
        }
    }

    Write-Host ""
    $createOUs = Read-Host "    Create this OU structure? [Y/N]"
    if ($createOUs.Trim().ToUpper() -ne 'Y') {
        Write-Host ""
        Write-Host "    [!] Phase 1 cancelled by user." -ForegroundColor Yellow
        return $results
    }

    # ================================================================
    # Create OUs
    # ================================================================
    Write-Host ""
    Write-Host "    Creating OUs..." -ForegroundColor Yellow

    # Tier OUs + sub-OUs
    foreach ($tier in $tierNames) {
        $tierDN = Ensure-OU -Name $tier.Name -ParentDN $baseDN -Description "$($tier.Name) — $(
            switch ($tier.Key) {
                'Tier0' { 'Control Plane (Identity Infrastructure)' }
                'Tier1' { 'Management Plane (Servers and Applications)' }
                'Tier2' { 'User Access (Workstations and End-Users)' }
            }
        )"
        $results["$($tier.Key)OUDN"] = $tierDN
        foreach ($sub in $tier.SubOUs) {
            Ensure-OU -Name $sub -ParentDN $tierDN -Description "$($tier.Name) — $sub" | Out-Null
        }
    }

    # Quarantine + sub-OUs
    $quarantineDN = Ensure-OU -Name $ouCfg.Quarantine -ParentDN $baseDN -Description 'Staging OU for new/unclassified objects'
    foreach ($sub in $ouCfg.QuarantineSubOUs) {
        Ensure-OU -Name $sub -ParentDN $quarantineDN -Description "Quarantine — $sub" | Out-Null
    }

    # Disabled + sub-OUs
    $disabledDN = Ensure-OU -Name $ouCfg.Disabled -ParentDN $baseDN -Description 'Disabled accounts and computers awaiting deletion'
    foreach ($sub in $ouCfg.DisabledSubOUs) {
        Ensure-OU -Name $sub -ParentDN $disabledDN -Description "Disabled — $sub" | Out-Null
    }

    # Standard Users
    Ensure-OU -Name $ouCfg.StandardUsers -ParentDN $baseDN -Description 'Non-admin user accounts' | Out-Null

    Write-Host ""
    Write-Host "    [OK] OU structure complete — $($results.OUsCreated.Count) created, $($results.OUsExisted.Count) already existed." -ForegroundColor Green

    # ================================================================
    # STEP 3 — Security groups + nesting
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/5 — Security Groups & Deny-Logon Nesting" -ForegroundColor Yellow
    Write-Host ""

    # Preview groups
    $grpPrefix = $naming.GroupPrefix
    $tiers = @('0', '1', '2')
    $tierLabels = @{ '0' = 'Tier0'; '1' = 'Tier1'; '2' = 'Tier2' }

    Write-Host "    Groups to create per tier:" -ForegroundColor White
    foreach ($t in $tiers) {
        $prefix = "${grpPrefix}${t}"
        Write-Host "      $($ouCfg.($tierLabels[$t])):" -ForegroundColor Cyan
        foreach ($g in $grpCfg.PerTier) {
            Write-Host "        • ${prefix}-$($g.Suffix)  ($($g.Scope))" -ForegroundColor DarkGray
        }
        # Tier-specific extras
        $extraKey = "$($tierLabels[$t])Extra"
        if ($grpCfg.$extraKey) {
            foreach ($g in $grpCfg.$extraKey) {
                Write-Host "        • ${prefix}-$($g.Suffix)  ($($g.Scope))" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
    Write-Host "    Cross-tier deny-logon groups (DomainLocal):" -ForegroundColor White
    foreach ($src in $tiers) {
        foreach ($dst in $tiers) {
            if ($src -ne $dst) {
                Write-Host "        • ${grpPrefix}${src}-$($grpCfg.DenyLogonSuffix)-${grpPrefix}${dst}" -ForegroundColor DarkGray
            }
        }
    }

    Write-Host ""
    Write-Host "    Nesting: Tx-Admins + Tx-ServiceAccounts → Tx-DenyLogon-Ty groups" -ForegroundColor White
    Write-Host ""

    $createGroups = Read-Host "    Create groups and configure nesting? [Y/N]"
    if ($createGroups.Trim().ToUpper() -ne 'Y') {
        Write-Host "    [!] Skipping group creation." -ForegroundColor Yellow
    } else {
        Write-Host ""
        Write-Host "    Creating security groups..." -ForegroundColor Yellow

        foreach ($t in $tiers) {
            $prefix = "${grpPrefix}${t}"
            $tierKey = $tierLabels[$t]
            $groupsOUDN = "OU=Groups,OU=$($ouCfg.$tierKey),$baseDN"

            # Per-tier common groups
            foreach ($g in $grpCfg.PerTier) {
                Ensure-Group -Name "${prefix}-$($g.Suffix)" -Path $groupsOUDN `
                    -Scope $g.Scope -Description "$($ouCfg.$tierKey) — $($g.Description)"
            }

            # Tier-specific extras
            $extraKey = "${tierKey}Extra"
            if ($grpCfg.$extraKey) {
                foreach ($g in $grpCfg.$extraKey) {
                    Ensure-Group -Name "${prefix}-$($g.Suffix)" -Path $groupsOUDN `
                        -Scope $g.Scope -Description "$($ouCfg.$tierKey) — $($g.Description)"
                }
            }
        }

        # Deny logon cross-tier groups
        Write-Host ""
        Write-Host "    Creating deny-logon groups..." -ForegroundColor Yellow
        foreach ($src in $tiers) {
            $srcKey = $tierLabels[$src]
            $groupsOUDN = "OU=Groups,OU=$($ouCfg.$srcKey),$baseDN"
            foreach ($dst in $tiers) {
                if ($src -ne $dst) {
                    $denyName = "${grpPrefix}${src}-$($grpCfg.DenyLogonSuffix)-${grpPrefix}${dst}"
                    Ensure-Group -Name $denyName -Path $groupsOUDN `
                        -Scope 'DomainLocal' -Description "Deny $($ouCfg.$srcKey) accounts logon on $($ouCfg.($tierLabels[$dst])) machines"
                }
            }
        }

        # Nesting: Tx-Admins + Tx-ServiceAccounts → Tx-DenyLogon-Ty
        Write-Host ""
        Write-Host "    Configuring deny-logon nesting..." -ForegroundColor Yellow
        foreach ($src in $tiers) {
            $srcPrefix = "${grpPrefix}${src}"
            $adminsGroup = "${srcPrefix}-Admins"
            $svcGroup    = "${srcPrefix}-ServiceAccounts"

            foreach ($dst in $tiers) {
                if ($src -ne $dst) {
                    $denyGroup = "${srcPrefix}-$($grpCfg.DenyLogonSuffix)-${grpPrefix}${dst}"
                    Ensure-Nesting -Group $denyGroup -Member $adminsGroup
                    Ensure-Nesting -Group $denyGroup -Member $svcGroup
                }
            }
        }

        Write-Host ""
        Write-Host "    [OK] Groups complete — $($results.GroupsCreated.Count) created, $($results.GroupsExisted.Count) already existed." -ForegroundColor Green
        Write-Host "    [OK] Nesting — $($results.NestingDone.Count) configured, $($results.NestingSkipped.Count) already in place." -ForegroundColor Green
    }

    # ================================================================
    # STEP 4 — Redirect default Computers container (redircmp)
    # ================================================================
    Write-Host ""
    Write-Host "  Step 4/5 — Redirect Default Containers" -ForegroundColor Yellow
    Write-Host ""
    $quarantineComputersDN = "OU=Computers,OU=$($ouCfg.Quarantine),$baseDN"
    Write-Host "    The default Computers container (CN=Computers,$domainDN) has no GPO support." -ForegroundColor White
    Write-Host "    Redirecting it to " -ForegroundColor White -NoNewline
    Write-Host "$quarantineComputersDN" -ForegroundColor Cyan
    Write-Host "    ensures new machines land in a managed OU where baseline GPOs apply." -ForegroundColor White
    Write-Host ""
    $doRedircmp = Read-Host "    Redirect default Computers container (redircmp)? [Y/N]"
    if ($doRedircmp.Trim().ToUpper() -eq 'Y') {
        try {
            $redircmpResult = & redircmp $quarantineComputersDN 2>&1
            Write-Host "      [+] redircmp done: $quarantineComputersDN" -ForegroundColor Green
            $results.RedircmpDone = $true
            $results.RedircmpTarget = $quarantineComputersDN
        } catch {
            Write-Host "      [!] redircmp failed: $_" -ForegroundColor Red
            $results.Errors.Add("redircmp failed: $_")
        }
    } else {
        Write-Host "    [!] Skipping redircmp." -ForegroundColor Yellow
    }

    # ================================================================
    # STEP 5 — Redirect default Users container (redirusr)
    # ================================================================
    Write-Host ""
    $standardUsersDN = "OU=$($ouCfg.StandardUsers),$baseDN"
    Write-Host "    The default Users container (CN=Users,$domainDN) also has no GPO support." -ForegroundColor White
    Write-Host "    Redirecting it to " -ForegroundColor White -NoNewline
    Write-Host "$standardUsersDN" -ForegroundColor Cyan
    Write-Host "    ensures new user accounts land in a managed OU." -ForegroundColor White
    Write-Host ""
    $doRedirusr = Read-Host "    Redirect default Users container (redirusr)? [Y/N]"
    if ($doRedirusr.Trim().ToUpper() -eq 'Y') {
        try {
            $redirusrResult = & redirusr $standardUsersDN 2>&1
            Write-Host "      [+] redirusr done: $standardUsersDN" -ForegroundColor Green
            $results.RedirusrDone = $true
            $results.RedirusrTarget = $standardUsersDN
        } catch {
            Write-Host "      [!] redirusr failed: $_" -ForegroundColor Red
            $results.Errors.Add("redirusr failed: $_")
        }
    } else {
        Write-Host "    [!] Skipping redirusr." -ForegroundColor Yellow
    }

    # ================================================================
    # Generate HTML Report
    # ================================================================
    Write-Host ""
    Write-Host "  Generating Phase 1 report..." -ForegroundColor Yellow
    $htmlPath = Join-Path $OutputDir "MATI-Tiering-Phase1-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    Export-TieringPhase1Html -Results $results -DomainDN $domainDN -TieringConfig $TieringConfig -OutputPath $htmlPath

    # Export JSON
    $jsonPath = Join-Path $OutputDir "MATI-Tiering-Phase1-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
    Write-Host "    JSON : $jsonPath" -ForegroundColor DarkGray

    $statePath = Join-Path $RootPath 'Outputs\Tiering\MATI-Tiering-Phase1-Latest.json'
    $results | ConvertTo-Json -Depth 10 | Set-Content -Path $statePath -Encoding UTF8
    Write-Host "    State: $statePath" -ForegroundColor DarkGray

    $sw.Stop()
    Write-Host ""
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 1 Complete — Duration: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s" -ForegroundColor Cyan
    Write-Host "   OUs     : $($results.OUsCreated.Count) created, $($results.OUsExisted.Count) existed" -ForegroundColor White
    Write-Host "   Groups  : $($results.GroupsCreated.Count) created, $($results.GroupsExisted.Count) existed" -ForegroundColor White
    Write-Host "   Nesting : $($results.NestingDone.Count) configured" -ForegroundColor White
    if ($results.Errors.Count -gt 0) {
        Write-Host "   Errors  : $($results.Errors.Count)" -ForegroundColor Red
    }
    Write-Host "   Report  : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    # Offer to open the report
    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') {
        Start-Process $htmlPath
    }

    return $results
}

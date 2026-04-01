# Tiering\Invoke-MATITieringPhase5.ps1
# Phase 5 — Create PAW Hardening GPOs
# Creates and links hardening GPOs for Tier 0, Tier 1, and Tier 2 PAWs.

function Invoke-MATITieringPhase5 {
    <#
    .SYNOPSIS
        Phase 5 — Interactive creation of PAW hardening GPOs.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: Phase 1 OUs exist for Tier 0 PAW, Tier 1 PAW, and Tier 2 PAW
        2. Create PAW hardening GPOs per tier
        3. Create firewall GPOs per tier and populate baseline rules
        4. Create loopback GPOs for all PAW tiers
        5. Link all GPOs to the exact OUs from Phase 1
        6. Generate an HTML deployment report with warnings and follow-up actions
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
    $domain  = Get-ADDomain
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
    $tier1OUDN = [string]$phase1State.Tier1OUDN
    $tier2OUDN = [string]$phase1State.Tier2OUDN

    $tierTargets = [ordered]@{
        'Tier0' = [ordered]@{
            Label = 'Tier 0 PAW'
            TargetOU = if ([string]::IsNullOrWhiteSpace($tier0OUDN)) { $null } else { "OU=PAW,$tier0OUDN" }
            HardeningGpo = 'PAW T0 Hardening'
            FirewallGpo  = 'PAW T0 Firewall'
            LoopbackGpo  = 'PAW T0 Loopback'
            ApplyLoopback = $true
            FirewallConfigKey = 'Tier0AllowedRemoteAddresses'
            Role = 'PAW'
        }
        'Tier1' = [ordered]@{
            Label = 'Tier 1 PAW'
            TargetOU = if ([string]::IsNullOrWhiteSpace($tier1OUDN)) { $null } else { "OU=PAW,$tier1OUDN" }
            HardeningGpo = 'PAW T1 Hardening'
            FirewallGpo  = 'PAW T1 Firewall'
            LoopbackGpo  = 'PAW T1 Loopback'
            ApplyLoopback = $true
            FirewallConfigKey = 'Tier1AllowedRemoteAddresses'
            Role = 'PAW'
        }
        'Tier2' = [ordered]@{
            Label = 'Tier 2 PAW'
            TargetOU = if ([string]::IsNullOrWhiteSpace($tier2OUDN)) { $null } else { "OU=PAW,$tier2OUDN" }
            HardeningGpo = 'PAW T2 Hardening'
            FirewallGpo  = 'PAW T2 Firewall'
            LoopbackGpo  = 'PAW T2 Loopback'
            ApplyLoopback = $true
            FirewallConfigKey = 'Tier2AllowedRemoteAddresses'
            Role = 'PAW'
        }
    }

    if ([string]::IsNullOrWhiteSpace($baseDN) -or [string]::IsNullOrWhiteSpace($tier0OUDN) -or [string]::IsNullOrWhiteSpace($tier1OUDN) -or [string]::IsNullOrWhiteSpace($tier2OUDN)) {
        Write-Host "`n  [ERROR] Phase 1 state is incomplete. Run Phase 1 again." -ForegroundColor Red
        Write-Host "    State file: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $phase5Config = if ($TieringConfig.ContainsKey('Phase5')) { $TieringConfig.Phase5 } else { @{} }
    $firewallConfig = if ($phase5Config.ContainsKey('Firewall')) { $phase5Config.Firewall } else { @{} }
    $pawConfig = if ($phase5Config.ContainsKey('PAW')) { $phase5Config.PAW } else { @{} }
    $deviceGuardConfig = if ($pawConfig.ContainsKey('DeviceGuard')) { $pawConfig.DeviceGuard } else { @{} }
    $bitLockerConfig = if ($pawConfig.ContainsKey('BitLocker')) { $pawConfig.BitLocker } else { @{} }

    $enableHVCI = if ($deviceGuardConfig.ContainsKey('EnableHVCI')) { [bool]$deviceGuardConfig.EnableHVCI } else { $true }
    $hvciModeText = if ($deviceGuardConfig.ContainsKey('HVCIMode')) { [string]$deviceGuardConfig.HVCIMode } else { 'EnabledWithoutLock' }
    $hvciMode = switch ($hvciModeText) {
        'EnabledWithUefiLock' { 1 }
        'EnabledWithoutLock' { 2 }
        default { 2 }
    }

    $bitLockerIdentificationField = if ($bitLockerConfig.ContainsKey('IdentificationField')) { [string]$bitLockerConfig.IdentificationField } else { 'MATI-PAW' }
    $bitLockerEncryptionTypeText = if ($bitLockerConfig.ContainsKey('EncryptionType')) { [string]$bitLockerConfig.EncryptionType } else { 'Full' }
    $bitLockerEncryptionType = if ($bitLockerEncryptionTypeText -eq 'UsedSpaceOnly') { 2 } else { 1 }
    $requireTpmPin = if ($bitLockerConfig.ContainsKey('RequireTPMPin')) { [bool]$bitLockerConfig.RequireTPMPin } else { $true }
    $minimumPinLength = if ($bitLockerConfig.ContainsKey('MinimumPinLength')) { [int]$bitLockerConfig.MinimumPinLength } else { 8 }
    $requireAdRecoveryBackup = if ($bitLockerConfig.ContainsKey('RequireADRecoveryBackup')) { [bool]$bitLockerConfig.RequireADRecoveryBackup } else { $true }
    $denyWriteUnencryptedFixedDrives = if ($bitLockerConfig.ContainsKey('DenyWriteUnencryptedFixedDrives')) { [bool]$bitLockerConfig.DenyWriteUnencryptedFixedDrives } else { $true }
    $denyWriteUnencryptedRemovableDrives = if ($bitLockerConfig.ContainsKey('DenyWriteUnencryptedRemovableDrives')) { [bool]$bitLockerConfig.DenyWriteUnencryptedRemovableDrives } else { $true }

    # Results tracker
    $results = @{
        BaseDN          = $baseDN
        ContainerOU     = $containerOU
        Phase1StatePath = $phase1StatePath
        Targets         = [System.Collections.Generic.List[object]]::new()
        GPOsCreated     = [System.Collections.Generic.List[object]]::new()
        GPOsExisted     = [System.Collections.Generic.List[object]]::new()
        LinksCreated    = [System.Collections.Generic.List[object]]::new()
        LinksExisted    = [System.Collections.Generic.List[object]]::new()
        SettingsApplied = [System.Collections.Generic.List[object]]::new()
        Warnings        = [System.Collections.Generic.List[string]]::new()
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    # ================================================================
    # Banner
    # ================================================================
    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 5 — Create PAW Hardening GPOs" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates hardening GPOs for Tier 0, Tier 1, and Tier 2 PAWs." -ForegroundColor DarkGray
    foreach ($tierKey in $tierTargets.Keys) {
        $target = $tierTargets[$tierKey]
        Write-Host "   Target: $($target.Label) -> $($target.TargetOU)" -ForegroundColor DarkGray
        $results.Targets.Add([PSCustomObject]@{ Tier = $tierKey; Label = $target.Label; TargetOU = $target.TargetOU })
    }
    Write-Host ""

    # ================================================================
    # Pre-checks
    # ================================================================
    function Resolve-AddressList {
        param(
            [object[]]$ConfiguredValues,
            [bool]$IncludeDomainControllers,
            [bool]$IncludeTierServers,
            [string]$TierKey,
            [string]$TargetOU
        )

        $resolved = New-Object System.Collections.Generic.List[string]
        $pendingNames = New-Object System.Collections.Generic.List[string]

        foreach ($value in ($ConfiguredValues | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })) {
            $text = [string]$value
            if ($text -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$') {
                $resolved.Add($text)
                continue
            }

            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($text) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -ExpandProperty IPAddressToString -Unique
                if ($addresses) {
                    foreach ($address in $addresses) { $resolved.Add($address) }
                } else {
                    $pendingNames.Add($text)
                }
            } catch {
                $pendingNames.Add($text)
            }
        }

        if ($IncludeDomainControllers) {
            try {
                $dcHosts = Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName -Unique
                foreach ($dcHost in $dcHosts) {
                    try {
                        $addresses = [System.Net.Dns]::GetHostAddresses($dcHost) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -ExpandProperty IPAddressToString -Unique
                        foreach ($address in $addresses) { $resolved.Add($address) }
                    } catch {
                        $pendingNames.Add($dcHost)
                    }
                }
            } catch {
                $results.Warnings.Add("Could not enumerate domain controllers for $TierKey firewall rules: $($_.Exception.Message)")
            }
        }

        if ($IncludeTierServers -and -not [string]::IsNullOrWhiteSpace($TargetOU)) {
            $serverOu = "OU=Servers,OU=$($TieringConfig.OUStructure.$TierKey.Replace('Tier','Tier ')),$baseDN"
            if ($TierKey -eq 'Tier0') { $serverOu = "OU=Servers,$tier0OUDN" }
            if ($TierKey -eq 'Tier1') { $serverOu = "OU=Servers,$tier1OUDN" }
            if ($TierKey -eq 'Tier2') { $serverOu = "OU=Workstations,$tier2OUDN" }
            if ($serverOu -and [adsi]::Exists("LDAP://$serverOu")) {
                try {
                    $serverDns = Get-ADComputer -SearchBase $serverOu -LDAPFilter '(objectClass=computer)' -Properties DNSHostName -ErrorAction Stop |
                        Where-Object { -not [string]::IsNullOrWhiteSpace($_.DNSHostName) } |
                        Select-Object -ExpandProperty DNSHostName -Unique
                    foreach ($dnsName in $serverDns) {
                        try {
                            $addresses = [System.Net.Dns]::GetHostAddresses($dnsName) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } | Select-Object -ExpandProperty IPAddressToString -Unique
                            foreach ($address in $addresses) { $resolved.Add($address) }
                        } catch {
                            $pendingNames.Add($dnsName)
                        }
                    }
                } catch {
                    $results.Warnings.Add("Could not enumerate tier server addresses for $TierKey firewall rules: $($_.Exception.Message)")
                }
            }
        }

        return [PSCustomObject]@{
            Addresses = @($resolved | Select-Object -Unique)
            PendingNames = @($pendingNames | Select-Object -Unique)
        }
    }

    function Ensure-Gpo {
        param(
            [string]$Name,
            [string]$Description
        )

        $gpo = Get-GPO -Name $Name -ErrorAction SilentlyContinue
        if ($gpo) {
            Write-Host "      [=] Already exists: $Name" -ForegroundColor DarkGray
            $results.GPOsExisted.Add([PSCustomObject]@{ Name = $Name; Id = $gpo.Id; Status = 'Existed' })
            return $gpo
        }

        try {
            $gpo = New-GPO -Name $Name -Comment $Description -ErrorAction Stop
            Write-Host "      [+] Created: $Name" -ForegroundColor Green
            $results.GPOsCreated.Add([PSCustomObject]@{ Name = $Name; Id = $gpo.Id; Status = 'Created' })
            return $gpo
        } catch {
            Write-Host "      [!] FAILED: $Name — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("GPO creation failed: $Name — $($_.Exception.Message)")
            return $null
        }
    }

    function Ensure-GpoLink {
        param(
            [string]$GpoName,
            [string]$TargetOu
        )

        try {
            $existingLinks = (Get-GPInheritance -Target $TargetOu -ErrorAction Stop).GpoLinks
            $alreadyLinked = $existingLinks | Where-Object { $_.DisplayName -eq $GpoName }
            if ($alreadyLinked) {
                Write-Host "      [=] Already linked: $GpoName -> $TargetOu" -ForegroundColor DarkGray
                $results.LinksExisted.Add([PSCustomObject]@{ GPO = $GpoName; Target = $TargetOu; Status = 'Existed' })
            } else {
                New-GPLink -Name $GpoName -Target $TargetOu -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Host "      [+] Linked: $GpoName -> $TargetOu" -ForegroundColor Green
                $results.LinksCreated.Add([PSCustomObject]@{ GPO = $GpoName; Target = $TargetOu; Status = 'Created' })
            }
        } catch {
            if ($_.Exception.Message -match 'already linked to a Scope of Management') {
                Write-Host "      [=] Already linked: $GpoName -> $TargetOu" -ForegroundColor DarkGray
                $results.LinksExisted.Add([PSCustomObject]@{ GPO = $GpoName; Target = $TargetOu; Status = 'Existed' })
            } else {
                Write-Host "      [!] Link FAILED: $GpoName -> $TargetOu — $($_.Exception.Message)" -ForegroundColor Red
                $results.Errors.Add("GPO link failed: $GpoName -> $TargetOu — $($_.Exception.Message)")
            }
        }
    }

    function Set-GpoRegistryValueWithRetry {
        param(
            [string]$GpoName,
            [string]$Key,
            [string]$ValueName,
            [string]$Type,
            [object]$Value,
            [string]$Label,
            [int]$MaxAttempts = 4
        )

        for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
            try {
                Set-GPRegistryValue -Name $GpoName -Key $Key -ValueName $ValueName -Type $Type -Value $Value -ErrorAction Stop | Out-Null
                return $true
            } catch {
                if ($attempt -eq $MaxAttempts) {
                    $results.Errors.Add("$Label setting failed: $($_.Exception.Message)")
                    return $false
                }

                Start-Sleep -Milliseconds (250 * $attempt)
            }
        }

        return $false
    }

    function Set-FirewallRulesInGpo {
        param(
            [string]$GpoName,
            [string]$TierKey,
            [string[]]$AllowedAddresses,
            [string[]]$PendingNames,
            [bool]$StrictOutboundBlock,
            [string]$TargetLabel
        )

        $policyStore = "$($domain.DNSRoot)\$GpoName"
        try {
            $gpoSession = Open-NetGPO -PolicyStore $policyStore -ErrorAction Stop
        } catch {
            $results.Errors.Add("Firewall GPO session failed for $GpoName — $($_.Exception.Message)")
            return
        }

        try {
            $ruleGroup = "MATI Phase 5 - $TierKey"

            Get-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue |
                Where-Object { $_.Group -eq $ruleGroup } |
                Remove-NetFirewallRule -PolicyStore $policyStore -ErrorAction SilentlyContinue | Out-Null

            foreach ($profile in @('Domain', 'Private', 'Public')) {
                Set-NetFirewallProfile -GPOSession $gpoSession -Profile $profile -Enabled True -DefaultInboundAction Block -DefaultOutboundAction $(if ($StrictOutboundBlock) { 'Block' } else { 'Allow' }) -AllowInboundRules True -AllowLocalFirewallRules False -ErrorAction Stop | Out-Null
            }
            $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = 'Firewall Domain/Private/Public Profiles'; Status = if ($StrictOutboundBlock) { 'Applied (Strict)' } else { 'Applied (Baseline)' } })

            if ($AllowedAddresses.Count -gt 0) {
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow DNS" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow Kerberos TCP" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemotePort 88 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow Kerberos UDP" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol UDP -RemotePort 88 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow LDAP" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemotePort 389 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow LDAPS" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemotePort 636 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow SMB" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemotePort 445 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Allow RDP" -Group $ruleGroup -Profile Any -Direction Outbound -Action Allow -Protocol TCP -RemotePort 3389 -RemoteAddress $AllowedAddresses -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = "Firewall allow rules for $TargetLabel"; Status = 'Applied' })
            } else {
                $results.Warnings.Add("$GpoName has no resolved allowed remote addresses. Populate Config\\Tiering.config.psd1 or verify AD auto-discovery before broad deployment.")
            }

            if ($StrictOutboundBlock) {
                New-NetFirewallRule -GPOSession $gpoSession -DisplayName "MATI $TierKey - Block Internet" -Group $ruleGroup -Profile Any -Direction Outbound -Action Block -RemoteAddress 'Any' -ErrorAction Stop | Out-Null
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = 'Firewall explicit outbound block rule'; Status = 'Applied' })
            }

            Save-NetGPO -GPOSession $gpoSession -ErrorAction Stop | Out-Null

            if ($PendingNames.Count -gt 0) {
                $results.Warnings.Add("$GpoName could not resolve these configured names to IP addresses yet: $($PendingNames -join ', ')")
            }
        } catch {
            $results.Errors.Add("Firewall rule deployment failed for $GpoName — $($_.Exception.Message)")
        }
    }

    Write-Host "  Pre-checks..." -ForegroundColor Yellow
    foreach ($tierKey in $tierTargets.Keys) {
        $target = $tierTargets[$tierKey]
        if (-not ([adsi]::Exists("LDAP://$($target.TargetOU)"))) {
            Write-Host "  [ERROR] Target OU not found: $($target.TargetOU). Run Phase 1 first." -ForegroundColor Red
            return
        }
        Write-Host "    [OK] $($target.Label) OU found: $($target.TargetOU)" -ForegroundColor Green
    }

    $autoDc = if ($firewallConfig.ContainsKey('AutoDiscoverDomainControllers')) { [bool]$firewallConfig.AutoDiscoverDomainControllers } else { $true }
    $autoTier = if ($firewallConfig.ContainsKey('AutoDiscoverTierServerAddresses')) { [bool]$firewallConfig.AutoDiscoverTierServerAddresses } else { $true }

    # ================================================================
    # GPO Definitions
    # ================================================================
    $prefix = $naming.GPOPrefix

    $gpoDefs = New-Object System.Collections.Generic.List[object]
    foreach ($tierKey in $tierTargets.Keys) {
        $target = $tierTargets[$tierKey]
        $gpoDefs.Add(@{
            TierKey     = $tierKey
            TargetOU    = $target.TargetOU
            Name        = "$prefix - $($target.HardeningGpo)"
            Type        = 'Hardening'
            Description = "Credential Guard, HVCI, BitLocker posture, LSASS protection, LLMNR disable, Remote Credential Guard, and WDigest disable for $($target.Label)"
            Settings    = @(
                @{ Category = 'Credential Guard';  Setting = 'Turn on Virtualization Based Security'; Value = 'Enabled with UEFI lock' }
                @{ Category = 'Device Guard';      Setting = 'Memory Integrity (HVCI)'; Value = $(if ($enableHVCI) { $hvciModeText } else { 'Not configured' }) }
                @{ Category = 'LSASS Protection';  Setting = 'RunAsPPL (LSASS Protected Mode)'; Value = 'Enabled' }
                @{ Category = 'Network';           Setting = 'Turn off multicast name resolution (LLMNR)'; Value = 'Enabled' }
                @{ Category = 'Credential Delegation'; Setting = 'Restrict delegation — Require Remote Credential Guard'; Value = 'Enabled' }
                @{ Category = 'Windows Store';     Setting = 'Turn off the Store application'; Value = 'Enabled' }
                @{ Category = 'Audit';             Setting = 'Include command line in process creation events'; Value = 'Enabled' }
                @{ Category = 'Authentication';    Setting = 'Disable WDigest cached credentials'; Value = 'Enabled' }
                @{ Category = 'BitLocker';        Setting = 'Enforce OS and fixed drive encryption type'; Value = $bitLockerEncryptionTypeText }
                @{ Category = 'BitLocker';        Setting = 'Require TPM startup PIN'; Value = $(if ($requireTpmPin) { "Enabled (minimum PIN length: $minimumPinLength)" } else { 'Not configured' }) }
                @{ Category = 'BitLocker';        Setting = 'Back up recovery secrets to AD DS'; Value = $(if ($requireAdRecoveryBackup) { 'Required (recovery password only)' } else { 'Not configured' }) }
                @{ Category = 'BitLocker';        Setting = 'Deny writes to unencrypted fixed/removable drives'; Value = "Fixed: $(if ($denyWriteUnencryptedFixedDrives) { 'Enabled' } else { 'Disabled' }) | Removable: $(if ($denyWriteUnencryptedRemovableDrives) { 'Enabled' } else { 'Disabled' })" }
            ) | Where-Object { $null -ne $_ }
        })
        $gpoDefs.Add(@{
            TierKey     = $tierKey
            TargetOU    = $target.TargetOU
            Name        = "$prefix - $($target.FirewallGpo)"
            Type        = 'Firewall'
            Description = "Firewall baseline for $($target.Label): default inbound block, tier-scoped outbound allow list, and restricted outbound profile"
            Settings    = @(
                @{ Category = 'Firewall'; Setting = 'Inbound default'; Value = 'Block all' }
                @{ Category = 'Firewall'; Setting = 'Outbound default'; Value = 'Block with explicit tier allow rules' }
                @{ Category = 'Firewall'; Setting = 'Outbound DNS/Kerberos/LDAP/SMB'; Value = 'Allow to resolved tier endpoints only' }
                @{ Category = 'Firewall'; Setting = 'Outbound RDP (3389)'; Value = 'Allow to resolved tier endpoints only' }
                @{ Category = 'Firewall'; Setting = 'Tier endpoint source'; Value = 'Phase5 config + AD auto-discovery' }
            )
        })
        if ($target.ApplyLoopback) {
            $gpoDefs.Add(@{
                TierKey     = $tierKey
                TargetOU    = $target.TargetOU
                Name        = "$prefix - $($target.LoopbackGpo)"
                Type        = 'Loopback'
                Description = "User Group Policy loopback processing in Replace mode for $($target.Label)"
                Settings    = @(
                    @{ Category = 'Group Policy'; Setting = 'Configure user Group Policy loopback processing mode'; Value = 'Enabled — Replace' }
                )
            })
        }
    }

    # ================================================================
    # Step 1 — Review
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/3 — GPO Plan Review" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [i] Microsoft recommendation for PAWs: add WDAC / App Control for Business in audit mode first, then move to enforcement once allowed software is validated." -ForegroundColor DarkCyan
    Write-Host "    [i] This phase does not deploy WDAC yet. Treat it as the next PAW hardening brick after firewall, BitLocker, Credential Guard, and HVCI." -ForegroundColor DarkGray
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
        $tierKey = $def.TierKey
        $targetMeta = $tierTargets[$tierKey]
        $gpo = Ensure-Gpo -Name $gpoName -Description $def.Description
        if (-not $gpo) { continue }

        # Configure registry-based settings via Set-GPRegistryValue
        if ($def.Type -eq 'Hardening') {
            # Credential Guard / VBS
            $cg1 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ValueName 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 -Label 'Credential Guard'
            $cg2 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ValueName 'LsaCfgFlags' -Type DWord -Value 1 -Label 'Credential Guard'
            $cg3 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ValueName 'RequirePlatformSecurityFeatures' -Type DWord -Value 3 -Label 'Credential Guard'
            if ($cg1 -and $cg2 -and $cg3) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Credential Guard + VBS'; Status = 'Applied' })
            }

            if ($enableHVCI) {
                if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ValueName 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value $hvciMode -Label 'HVCI / Memory Integrity') {
                    $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'HVCI / Memory Integrity'; Status = 'Applied' })
                }
            }

            # LSASS RunAsPPL
            if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -ValueName 'RunAsPPL' -Type DWord -Value 1 -Label 'RunAsPPL') {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'LSASS RunAsPPL'; Status = 'Applied' })
            }

            # Disable LLMNR
            if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ValueName 'EnableMulticast' -Type DWord -Value 0 -Label 'LLMNR') {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable LLMNR'; Status = 'Applied' })
            }

            # Remote Credential Guard
            $rcg1 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -ValueName 'RestrictedRemoteAdministration' -Type DWord -Value 2 -Label 'Remote Credential Guard'
            $rcg2 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -ValueName 'RestrictedRemoteAdministrationType' -Type DWord -Value 2 -Label 'Remote Credential Guard'
            if ($rcg1 -and $rcg2) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Remote Credential Guard'; Status = 'Applied' })
            }

            # Disable Windows Store
            if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore' -ValueName 'RemoveWindowsStore' -Type DWord -Value 1 -Label 'Windows Store') {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable Windows Store'; Status = 'Applied' })
            }

            # Command-line auditing
            if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ValueName 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 -Label 'Command-line auditing') {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Command-line auditing'; Status = 'Applied' })
            }

            # Disable WDigest
            if (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ValueName 'UseLogonCredential' -Type DWord -Value 0 -Label 'WDigest') {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'Disable WDigest'; Status = 'Applied' })
            }

            $bitLockerOs1 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\FVE' -ValueName 'OSEncryptionType' -Type DWord -Value $bitLockerEncryptionType -Label 'BitLocker OS encryption type'
            $bitLockerFdv1 = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\FVE' -ValueName 'FDVEncryptionType' -Type DWord -Value $bitLockerEncryptionType -Label 'BitLocker fixed drive encryption type'
            if ($bitLockerOs1 -and $bitLockerFdv1) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'BitLocker OS and fixed drive encryption type'; Status = 'Applied' })
            }

            $bitLockerId = Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SOFTWARE\Policies\Microsoft\FVE' -ValueName 'IdentificationField' -Type String -Value $bitLockerIdentificationField -Label 'BitLocker identification field'
            if ($bitLockerId) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'BitLocker organization identification field'; Status = 'Applied' })
            }

            if ($requireTpmPin) {
                $bitLockerStartupSettings = @(
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseAdvancedStartup'; Type = 'DWord'; Value = 1; Label = 'BitLocker advanced startup' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'EnableBDEWithNoTPM'; Type = 'DWord'; Value = 0; Label = 'BitLocker without TPM' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseTPM'; Type = 'DWord'; Value = 1; Label = 'BitLocker TPM startup' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseTPMKey'; Type = 'DWord'; Value = 0; Label = 'BitLocker TPM startup key' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseTPMPIN'; Type = 'DWord'; Value = 1; Label = 'BitLocker TPM startup PIN' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseTPMKeyPIN'; Type = 'DWord'; Value = 0; Label = 'BitLocker TPM startup key and PIN' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'UseEnhancedPin'; Type = 'DWord'; Value = 1; Label = 'BitLocker enhanced PINs' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'MinimumPIN'; Type = 'DWord'; Value = $minimumPinLength; Label = 'BitLocker minimum PIN length' }
                )

                $bitLockerStartupSucceeded = $true
                foreach ($setting in $bitLockerStartupSettings) {
                    if (-not (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -Label $setting.Label)) {
                        $bitLockerStartupSucceeded = $false
                    }
                }

                if ($bitLockerStartupSucceeded) {
                    $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'BitLocker TPM + PIN startup policy'; Status = 'Applied' })
                }
            }

            if ($requireAdRecoveryBackup) {
                $bitLockerRecoverySettings = @(
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSRecoveryPassword'; Type = 'DWord'; Value = 1; Label = 'BitLocker OS recovery password' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSRecoveryKey'; Type = 'DWord'; Value = 0; Label = 'BitLocker OS recovery key' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSHideRecoveryPage'; Type = 'DWord'; Value = 1; Label = 'BitLocker OS recovery wizard page' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSActiveDirectoryBackup'; Type = 'DWord'; Value = 1; Label = 'BitLocker OS AD backup' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSActiveDirectoryInfoToStore'; Type = 'DWord'; Value = 2; Label = 'BitLocker OS AD backup content' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'OSRequireActiveDirectoryBackup'; Type = 'DWord'; Value = 1; Label = 'BitLocker OS AD backup requirement' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVRecoveryPassword'; Type = 'DWord'; Value = 1; Label = 'BitLocker fixed drive recovery password' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVRecoveryKey'; Type = 'DWord'; Value = 0; Label = 'BitLocker fixed drive recovery key' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVHideRecoveryPage'; Type = 'DWord'; Value = 1; Label = 'BitLocker fixed drive recovery wizard page' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVActiveDirectoryBackup'; Type = 'DWord'; Value = 1; Label = 'BitLocker fixed drive AD backup' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVActiveDirectoryInfoToStore'; Type = 'DWord'; Value = 2; Label = 'BitLocker fixed drive AD backup content' }
                    @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\FVE'; ValueName = 'FDVRequireActiveDirectoryBackup'; Type = 'DWord'; Value = 1; Label = 'BitLocker fixed drive AD backup requirement' }
                )

                $bitLockerRecoverySucceeded = $true
                foreach ($setting in $bitLockerRecoverySettings) {
                    if (-not (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -Label $setting.Label)) {
                        $bitLockerRecoverySucceeded = $false
                    }
                }

                if ($bitLockerRecoverySucceeded) {
                    $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'BitLocker AD recovery escrow'; Status = 'Applied' })
                }
            }

            $bitLockerWriteRestrictions = $true
            if ($denyWriteUnencryptedFixedDrives) {
                if (-not (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' -ValueName 'FDVDenyWriteAccess' -Type DWord -Value 1 -Label 'BitLocker fixed drive write restriction')) {
                    $bitLockerWriteRestrictions = $false
                }
            }
            if ($denyWriteUnencryptedRemovableDrives) {
                if (-not (Set-GpoRegistryValueWithRetry -GpoName $gpoName -Key 'HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE' -ValueName 'RDVDenyWriteAccess' -Type DWord -Value 1 -Label 'BitLocker removable drive write restriction')) {
                    $bitLockerWriteRestrictions = $false
                }
            }
            if ($bitLockerWriteRestrictions -and ($denyWriteUnencryptedFixedDrives -or $denyWriteUnencryptedRemovableDrives)) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $gpoName; Setting = 'BitLocker unencrypted drive write restrictions'; Status = 'Applied' })
            }

            Write-Host "      [+] Configured hardening settings" -ForegroundColor Green
        }

        if ($def.Type -eq 'Loopback') {
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

        if ($def.Type -eq 'Firewall') {
            $configuredAddresses = if ($firewallConfig.ContainsKey($targetMeta.FirewallConfigKey)) { @($firewallConfig[$targetMeta.FirewallConfigKey]) } else { @() }
            $resolvedAddresses = Resolve-AddressList -ConfiguredValues $configuredAddresses -IncludeDomainControllers $autoDc -IncludeTierServers $autoTier -TierKey $tierKey -TargetOU $def.TargetOU
            $strictOutboundBlock = $true
            Set-FirewallRulesInGpo -GpoName $gpoName -TierKey $tierKey -AllowedAddresses $resolvedAddresses.Addresses -PendingNames $resolvedAddresses.PendingNames -StrictOutboundBlock $strictOutboundBlock -TargetLabel $targetMeta.Label

        }
    }

    # ================================================================
    # Step 3 — Link GPOs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/3 — Linking GPOs to PAW OU" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefs) {
        Ensure-GpoLink -GpoName $def.Name -TargetOu $def.TargetOU
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
    if ($results.Warnings.Count -gt 0) { Write-Host "   Warnings : $($results.Warnings.Count)" -ForegroundColor Yellow }
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

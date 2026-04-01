# Tiering\Invoke-MATITieringPhase6.ps1
# Phase 6 — Create GPO Hardening Per Tier
# Creates tier-specific hardening GPOs and Windows LAPS GPOs based on the exact
# OU state exported by Phase 1.

function Invoke-MATITieringPhase6 {
    <#
    .SYNOPSIS
        Phase 6 — Interactive creation of per-tier hardening GPOs and Windows LAPS deployment.
    .DESCRIPTION
        Guided, step-by-step deployment:
        1. Pre-check: consume the exact OU state exported by Phase 1
        2. Create per-tier hardening GPOs for Tier 0, Tier 1, and Tier 2
        3. Create Windows LAPS GPOs for Tier 0, Tier 1, and Tier 2
        4. Generate an HTML deployment report with warnings and follow-up actions
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

    $naming = $TieringConfig.Naming
    $lapsCfg = $TieringConfig.LAPS
    $domain = Get-ADDomain
    $domainDN = $domain.DistinguishedName
    $prefix = $naming.GPOPrefix

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

    if ([string]::IsNullOrWhiteSpace($baseDN) -or [string]::IsNullOrWhiteSpace($tier0OUDN) -or [string]::IsNullOrWhiteSpace($tier1OUDN) -or [string]::IsNullOrWhiteSpace($tier2OUDN)) {
        Write-Host "`n  [ERROR] Phase 1 state is incomplete. Run Phase 1 again." -ForegroundColor Red
        Write-Host "    State file: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""
        return
    }

    $tierTargets = [ordered]@{
        'Tier0' = [ordered]@{
            Label = 'Tier 0'
            TargetOU = $tier0OUDN
            HardeningGpo = 'Hardening T0'
            LapsGpo = 'Windows LAPS T0'
            Notes = 'Created and linked only to the Tier 0 root OU. Domain Controllers OU is intentionally not linked in Phase 6.'
        }
        'Tier1' = [ordered]@{
            Label = 'Tier 1'
            TargetOU = $tier1OUDN
            HardeningGpo = 'Hardening T1'
            LapsGpo = 'Windows LAPS T1'
            Notes = 'Created and linked to the exact Tier 1 OU exported by Phase 1.'
        }
        'Tier2' = [ordered]@{
            Label = 'Tier 2'
            TargetOU = $tier2OUDN
            HardeningGpo = 'Hardening T2'
            LapsGpo = 'Windows LAPS T2'
            Notes = 'Created and linked to the exact Tier 2 OU exported by Phase 1.'
        }
    }

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
        Artifacts       = [System.Collections.Generic.List[object]]::new()
        Warnings        = [System.Collections.Generic.List[string]]::new()
        Errors          = [System.Collections.Generic.List[string]]::new()
    }

    if (-not [bool]$lapsCfg.UseWindowsLAPS) {
        $results.Warnings.Add('Config\\Tiering.config.psd1 does not request Windows LAPS, but Phase 6 deploys Windows LAPS only. Legacy Microsoft LAPS is not deployed by this phase.')
    }
    $results.Warnings.Add('Tier 0 hardening is intentionally linked only to the Tier 0 OU from Phase 1. Phase 6 does not link a hardening GPO to the Domain Controllers OU.')

    Write-Host "`n  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Phase 6 — Create GPO Hardening Per Tier" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates per-tier hardening baselines from exact Phase 1 OU state." -ForegroundColor DarkGray
    Write-Host "   Deploys Windows LAPS only. Legacy Microsoft LAPS is not configured by this phase." -ForegroundColor DarkGray
    Write-Host ""

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

    function Apply-RegistrySettingsToGpo {
        param(
            [string]$GpoName,
            [System.Collections.IEnumerable]$RegistrySettings
        )

        foreach ($setting in $RegistrySettings) {
            if (Set-GpoRegistryValueWithRetry -GpoName $GpoName -Key $setting.Key -ValueName $setting.ValueName -Type $setting.Type -Value $setting.Value -Label $setting.Label) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = $setting.Label; Status = 'Applied' })
            }
        }
    }

    function New-AuditPolicyRow {
        param(
            [string]$Subcategory,
            [string]$Guid,
            [string]$Inclusion
        )

        $settingValue = switch ($Inclusion) {
            'Success' { 1 }
            'Failure' { 2 }
            'Success and Failure' { 3 }
            'No Auditing' { 0 }
            'Not specified' { 0 }
            default { throw "Unsupported audit inclusion setting: $Inclusion" }
        }

        return [ordered]@{
            Subcategory  = $Subcategory
            Guid         = $Guid
            Inclusion    = $Inclusion
            SettingValue = $settingValue
        }
    }

    function New-AuditCsvContent {
        param(
            [System.Collections.IEnumerable]$AuditRows,
            [System.Collections.IEnumerable]$OptionRows
        )

        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')

        foreach ($row in $AuditRows) {
            $lines.Add((",System,Audit {0},{1},{2},,{3}" -f $row.Subcategory, $row.Guid, $row.Inclusion, $row.SettingValue))
        }

        foreach ($row in $OptionRows) {
            $lines.Add((",,Option:{0},,{1},,{2}" -f $row.Name, $row.State, $row.Value))
        }

        return (($lines -join "`r`n") + "`r`n")
    }

    function Apply-AdvancedAuditPolicyToGpo {
        param(
            [string]$GpoName,
            [string]$TierLabel,
            [System.Collections.IEnumerable]$AuditRows,
            [System.Collections.IEnumerable]$OptionRows
        )

        if (-not (Get-Command -Name Backup-GPO -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Import-GPO -ErrorAction SilentlyContinue)) {
            $results.Warnings.Add("Advanced audit policy for $GpoName was not imported because Backup-GPO/Import-GPO is unavailable on this host.")
            return $false
        }

        $artifactDir = Join-Path $OutputDir 'AuditPolicies'
        if (-not (Test-Path $artifactDir)) {
            New-Item -ItemType Directory -Force -Path $artifactDir | Out-Null
        }

        $safeArtifactName = ($GpoName -replace '[\\/:*?"<>|]', '_') + '.Audit.csv'
        $artifactPath = Join-Path $artifactDir $safeArtifactName
        $csvContent = New-AuditCsvContent -AuditRows $AuditRows -OptionRows $OptionRows
        Set-Content -Path $artifactPath -Value $csvContent -Encoding UTF8
        $results.Artifacts.Add([PSCustomObject]@{ Type = 'AdvancedAuditCsv'; Tier = $TierLabel; GPO = $GpoName; Path = $artifactPath })

        $backupRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("MATI-Phase6-Audit-{0}" -f ([guid]::NewGuid().Guid))
        New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null

        try {
            $backup = Backup-GPO -Name $GpoName -Path $backupRoot -ErrorAction Stop
            $backupFolder = Get-ChildItem -Path $backupRoot -Directory -Recurse -ErrorAction Stop |
                Where-Object { Test-Path (Join-Path $_.FullName 'bkupInfo.xml') } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1

            if (-not $backupFolder) {
                throw 'Unable to locate the temporary GPO backup folder for advanced audit policy import.'
            }

            $auditFolder = Join-Path $backupFolder.FullName 'DomainSysvol\GPO\Machine\Microsoft\Windows NT\Audit'
            New-Item -ItemType Directory -Force -Path $auditFolder | Out-Null
            Set-Content -Path (Join-Path $auditFolder 'Audit.csv') -Value $csvContent -Encoding UTF8

            Import-GPO -BackupId $backup.Id -Path $backupRoot -TargetName $GpoName -ErrorAction Stop | Out-Null

            foreach ($row in $AuditRows) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = "Advanced audit: $($row.Subcategory)"; Status = $row.Inclusion })
            }

            foreach ($row in $OptionRows) {
                $results.SettingsApplied.Add([PSCustomObject]@{ GPO = $GpoName; Setting = "Advanced audit option: $($row.Name)"; Status = $row.State })
            }

            return $true
        } catch {
            $results.Errors.Add("Advanced audit policy import failed for $GpoName — $($_.Exception.Message)")
            return $false
        } finally {
            Remove-Item -Path $backupRoot -Recurse -Force -ErrorAction SilentlyContinue
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
        $results.Targets.Add([PSCustomObject]@{ Tier = $tierKey; Label = $target.Label; TargetOU = $target.TargetOU; Notes = $target.Notes })
    }

    $domainModeText = [string]$domain.DomainMode
    if ($domainModeText -notmatch '2016|2019|2022|2025') {
        $results.Warnings.Add("Current domain functional level is $domainModeText. Windows LAPS AD password encryption requires a domain functional level of Windows Server 2016 or later.")
    }

    $wdigest = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; ValueName = 'UseLogonCredential'; Type = 'DWord'; Value = 0; Label = 'Disable WDigest cached credentials' }
    $runAsPpl = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'RunAsPPL'; Type = 'DWord'; Value = 1; Label = 'LSASS protection (RunAsPPL)' }
    $noLmHash = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'NoLMHash'; Type = 'DWord'; Value = 1; Label = 'Do not store LAN Manager hash values' }
    $sceNoApplyLegacyAuditPolicy = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'; ValueName = 'SCENoApplyLegacyAuditPolicy'; Type = 'DWord'; Value = 1; Label = 'Force advanced audit subcategory policies over legacy audit policy' }
    $disableLlmnr = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; ValueName = 'EnableMulticast'; Type = 'DWord'; Value = 0; Label = 'Disable LLMNR' }
    $commandLineAudit = @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; ValueName = 'ProcessCreationIncludeCmdLine_Enabled'; Type = 'DWord'; Value = 1; Label = 'Include command line in process creation events' }
    $scriptBlockLogging = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1; Label = 'PowerShell script block logging' }
    $moduleLogging = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; ValueName = 'EnableModuleLogging'; Type = 'DWord'; Value = 1; Label = 'PowerShell module logging' }
    $moduleLoggingAllModules = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; ValueName = '*'; Type = 'String'; Value = '*'; Label = 'PowerShell module logging for all modules' }
    $transcription = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'EnableTranscripting'; Type = 'DWord'; Value = 1; Label = 'PowerShell transcription' }
    $invocationHeader = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'EnableInvocationHeader'; Type = 'DWord'; Value = 1; Label = 'PowerShell transcription invocation headers' }
    $transcriptionDirectory = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; ValueName = 'OutputDirectory'; Type = 'String'; Value = '%ProgramData%\Microsoft\Windows\PowerShell\Transcripts'; Label = 'PowerShell transcription output directory' }
    $disableInsecureGuestAuth = @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName = 'AllowInsecureGuestAuth'; Type = 'DWord'; Value = 0; Label = 'Disable insecure guest logons' }
    $smbClientEnableSigning = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'EnableSecuritySignature'; Type = 'DWord'; Value = 1; Label = 'SMB client signing enabled' }
    $smbClientRequireSigning = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Label = 'SMB client signing required' }
    $smbServerEnableSigning = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'EnableSecuritySignature'; Type = 'DWord'; Value = 1; Label = 'SMB server signing enabled' }
    $smbServerRequireSigning = @{ Key = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; ValueName = 'RequireSecuritySignature'; Type = 'DWord'; Value = 1; Label = 'SMB server signing required' }

    $commonHardeningSettings = @(
        $wdigest,
        $runAsPpl,
        $noLmHash,
        $sceNoApplyLegacyAuditPolicy,
        $disableLlmnr,
        $commandLineAudit,
        $scriptBlockLogging,
        $moduleLogging,
        $moduleLoggingAllModules,
        $transcription,
        $invocationHeader,
        $transcriptionDirectory,
        $disableInsecureGuestAuth,
        $smbClientEnableSigning,
        $smbClientRequireSigning,
        $smbServerEnableSigning,
        $smbServerRequireSigning
    )

    $eventLogSettingsByTier = @{
        'Tier0' = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 1048576; Label = 'Security event log maximum size (1024 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 262144; Label = 'Application event log maximum size (256 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 262144; Label = 'System event log maximum size (256 MB)' }
        )
        'Tier1' = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 524288; Label = 'Security event log maximum size (512 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 131072; Label = 'Application event log maximum size (128 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 131072; Label = 'System event log maximum size (128 MB)' }
        )
        'Tier2' = @(
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 262144; Label = 'Security event log maximum size (256 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 65536; Label = 'Application event log maximum size (64 MB)' }
            @{ Key = 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; ValueName = 'MaxSize'; Type = 'DWord'; Value = 65536; Label = 'System event log maximum size (64 MB)' }
        )
    }

    $commonAuditPolicy = @(
        (New-AuditPolicyRow -Subcategory 'Credential Validation' -Guid '{0CCE923F-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Logon' -Guid '{0CCE9215-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Account Lockout' -Guid '{0CCE9217-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Special Logon' -Guid '{0CCE921B-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'Other Logon/Logoff Events' -Guid '{0CCE921C-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Group Membership' -Guid '{0CCE9249-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'File Share' -Guid '{0CCE9224-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Filtering Platform Connection' -Guid '{0CCE9226-69AE-11D9-BED3-505054503030}' -Inclusion 'Failure')
        (New-AuditPolicyRow -Subcategory 'Other Object Access Events' -Guid '{0CCE9227-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Sensitive Privilege Use' -Guid '{0CCE9228-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Process Creation' -Guid '{0CCE922B-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'Audit Policy Change' -Guid '{0CCE922F-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'Authentication Policy Change' -Guid '{0CCE9230-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'Authorization Policy Change' -Guid '{0CCE9231-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'User Account Management' -Guid '{0CCE9235-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Computer Account Management' -Guid '{0CCE9236-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Security Group Management' -Guid '{0CCE9237-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Security State Change' -Guid '{0CCE9210-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'Security System Extension' -Guid '{0CCE9211-69AE-11D9-BED3-505054503030}' -Inclusion 'Success')
        (New-AuditPolicyRow -Subcategory 'System Integrity' -Guid '{0CCE9212-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
        (New-AuditPolicyRow -Subcategory 'Other System Events' -Guid '{0CCE9214-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
    )

    $advancedAuditByTier = @{
        'Tier0' = @(
            $commonAuditPolicy + @(
                (New-AuditPolicyRow -Subcategory 'Kerberos Service Ticket Operations' -Guid '{0CCE9240-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Other Account Logon Events' -Guid '{0CCE9241-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Kerberos Authentication Service' -Guid '{0CCE9242-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Directory Service Access' -Guid '{0CCE923B-69AE-11D9-BED3-505054503030}' -Inclusion 'Failure')
                (New-AuditPolicyRow -Subcategory 'Directory Service Changes' -Guid '{0CCE923C-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Directory Service Replication' -Guid '{0CCE923D-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Detailed Directory Service Replication' -Guid '{0CCE923E-69AE-11D9-BED3-505054503030}' -Inclusion 'Failure')
            )
        )
        'Tier1' = @(
            $commonAuditPolicy + @(
                (New-AuditPolicyRow -Subcategory 'Kerberos Service Ticket Operations' -Guid '{0CCE9240-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Other Account Logon Events' -Guid '{0CCE9241-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
                (New-AuditPolicyRow -Subcategory 'Kerberos Authentication Service' -Guid '{0CCE9242-69AE-11D9-BED3-505054503030}' -Inclusion 'Success and Failure')
            )
        )
        'Tier2' = @(
            $commonAuditPolicy
        )
    }

    $auditOptionRows = @(
        @{ Name = 'CrashOnAuditFail'; State = 'Disabled'; Value = 0 }
    )

    $lapsSettings = @(
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'BackupDirectory'; Type = 'DWord'; Value = 2; Label = 'Windows LAPS backup to Active Directory' }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PasswordAgeDays'; Type = 'DWord'; Value = $lapsCfg.PasswordAgeDays; Label = "Windows LAPS password age ($($lapsCfg.PasswordAgeDays) days)" }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PasswordLength'; Type = 'DWord'; Value = $lapsCfg.PasswordLength; Label = "Windows LAPS password length ($($lapsCfg.PasswordLength))" }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PasswordComplexity'; Type = 'DWord'; Value = 4; Label = 'Windows LAPS password complexity (upper, lower, numbers, special)' }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PasswordExpirationProtectionEnabled'; Type = 'DWord'; Value = 1; Label = 'Windows LAPS password expiration protection' }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'ADPasswordEncryptionEnabled'; Type = 'DWord'; Value = 1; Label = 'Windows LAPS AD password encryption' }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PostAuthenticationResetDelay'; Type = 'DWord'; Value = 24; Label = 'Windows LAPS post-authentication reset delay (24h)' }
        @{ Key = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; ValueName = 'PostAuthenticationActions'; Type = 'DWord'; Value = 3; Label = 'Windows LAPS post-authentication actions (reset password and sign out)' }
    )

    $gpoDefs = New-Object System.Collections.Generic.List[object]
    foreach ($tierKey in $tierTargets.Keys) {
        $target = $tierTargets[$tierKey]
        $gpoDefs.Add(@{
            TierKey = $tierKey
            Type = 'Hardening'
            TargetOU = $target.TargetOU
            Name = "$prefix - $($target.HardeningGpo)"
            Description = "Microsoft-aligned conservative hardening baseline for $($target.Label): credential protection, naming resolution hardening, PowerShell auditing, and client-side SMB protections"
            Settings = @(
                @{ Category = 'Authentication'; Setting = 'Disable WDigest cached credentials'; Value = 'Enabled' }
                @{ Category = 'Credential Protection'; Setting = 'LSASS protection (RunAsPPL)'; Value = 'Enabled' }
                @{ Category = 'Authentication'; Setting = 'Do not store LM hashes'; Value = 'Enabled' }
                @{ Category = 'Network'; Setting = 'Turn off multicast name resolution (LLMNR)'; Value = 'Enabled' }
                @{ Category = 'Audit'; Setting = 'Include command line in process creation events'; Value = 'Enabled' }
                @{ Category = 'Audit'; Setting = 'Force advanced audit subcategories'; Value = 'Enabled' }
                @{ Category = 'PowerShell'; Setting = 'Script block, module, and transcription logging'; Value = 'Enabled' }
                @{ Category = 'SMB Client'; Setting = 'Disable insecure guest logons'; Value = 'Enabled' }
                @{ Category = 'SMB'; Setting = 'Require SMB signing on client and server'; Value = 'Enabled' }
                @{ Category = 'Event Log'; Setting = 'Increase event log maximum sizes'; Value = 'Enabled' }
                @{ Category = 'Advanced Audit'; Setting = 'Apply Microsoft-aligned advanced audit subcategories'; Value = if ($tierKey -eq 'Tier0') { 'Expanded Tier 0 set including directory service auditing' } elseif ($tierKey -eq 'Tier1') { 'Expanded Tier 1 set including Kerberos auditing' } else { 'Core endpoint audit set' } }
            )
            RegistrySettings = @($commonHardeningSettings + $eventLogSettingsByTier[$tierKey])
            AdvancedAuditRows = $advancedAuditByTier[$tierKey]
            AdvancedAuditOptions = $auditOptionRows
        })
        $gpoDefs.Add(@{
            TierKey = $tierKey
            Type = 'WindowsLAPS'
            TargetOU = $target.TargetOU
            Name = "$prefix - $($target.LapsGpo)"
            Description = "Windows LAPS baseline for $($target.Label): backup to Active Directory, encrypted password storage, password rotation, and post-authentication reset actions"
            Settings = @(
                @{ Category = 'Windows LAPS'; Setting = 'Backup directory'; Value = 'Active Directory only' }
                @{ Category = 'Windows LAPS'; Setting = 'Password length'; Value = [string]$lapsCfg.PasswordLength }
                @{ Category = 'Windows LAPS'; Setting = 'Password age'; Value = "$($lapsCfg.PasswordAgeDays) days" }
                @{ Category = 'Windows LAPS'; Setting = 'Password complexity'; Value = 'Value 4 (upper, lower, numbers, special)' }
                @{ Category = 'Windows LAPS'; Setting = 'AD password encryption'; Value = 'Enabled' }
                @{ Category = 'Windows LAPS'; Setting = 'Legacy Microsoft LAPS'; Value = 'Not deployed by Phase 6' }
            )
            RegistrySettings = $lapsSettings
        })
    }

    Write-Host ""
    Write-Host "  Step 1/3 — GPO Plan Review" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    [i] Phase 6 uses only the exact OU DNs exported by Phase 1. No OU reconstruction or deduction is used here." -ForegroundColor DarkCyan
    Write-Host "    [i] Microsoft recommends starting from well-known security baselines. This phase now applies a broader Microsoft-aligned subset: credential protections, SMB signing, event log sizing, PowerShell logging, and advanced audit policy by tier." -ForegroundColor DarkCyan
    Write-Host "    [i] Windows LAPS only. Legacy Microsoft LAPS is not deployed by this phase." -ForegroundColor DarkGray
    Write-Host "    [i] Tier 0 hardening is not linked to the Domain Controllers OU in this phase." -ForegroundColor DarkGray
    Write-Host ""

    foreach ($def in $gpoDefs) {
        Write-Host "    GPO: $($def.Name)" -ForegroundColor Cyan
        Write-Host "    Target: $($def.TargetOU)" -ForegroundColor DarkGray
        Write-Host "    $($def.Description)" -ForegroundColor DarkGray
        foreach ($setting in $def.Settings) {
            Write-Host "      - [$($setting.Category)] $($setting.Setting) = $($setting.Value)" -ForegroundColor White
        }
        Write-Host ""
    }

    $confirm = Read-Host "    Proceed with GPO creation? [Y/N]"
    if ($confirm.Trim().ToUpper() -ne 'Y') {
        Write-Host "    [!] Cancelled by user." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Step 2/3 — Creating GPOs and Configuring Settings" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefs) {
        $gpo = Ensure-Gpo -Name $def.Name -Description $def.Description
        if (-not $gpo) { continue }

        Apply-RegistrySettingsToGpo -GpoName $def.Name -RegistrySettings $def.RegistrySettings
        if ($def.Type -eq 'Hardening') {
            Apply-AdvancedAuditPolicyToGpo -GpoName $def.Name -TierLabel $def.TierKey -AuditRows $def.AdvancedAuditRows -OptionRows $def.AdvancedAuditOptions | Out-Null
        }
        Ensure-GpoLink -GpoName $def.Name -TargetOu $def.TargetOU
    }

    Write-Host ""
    Write-Host "  Step 3/3 — Generating Report" -ForegroundColor Yellow
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
    if ($results.Warnings.Count -gt 0) { Write-Host "   Warnings : $($results.Warnings.Count)" -ForegroundColor Yellow }
    if ($results.Errors.Count -gt 0) { Write-Host "   Errors   : $($results.Errors.Count)" -ForegroundColor Red }
    Write-Host "   Report   : $htmlPath" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

    $openChoice = Read-Host "  Open HTML report in browser? (Y/N)"
    if ($openChoice -match '^[Yy]') { Start-Process $htmlPath }

    return $results
}

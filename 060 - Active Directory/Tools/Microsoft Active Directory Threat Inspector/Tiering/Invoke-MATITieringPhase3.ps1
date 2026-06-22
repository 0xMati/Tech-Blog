# Tiering\Invoke-MATITieringPhase3.ps1
# Phase 3 — Create Deny Logon GPOs for each Tiers
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

    $phase1StatePath = Join-Path $RootPath 'Outputs\Tiering\MATI-Tiering-Phase1-Latest.json'
    if (-not (Test-Path $phase1StatePath)) {
        Write-Host "`n  [ERROR] Phase 1 state file not found. Run Phase 1 first." -ForegroundColor Red
        Write-Host "    Expected: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""; return
    }

    try {
        $phase1State = Get-Content -Path $phase1StatePath -Raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Host "`n  [ERROR] Failed to read Phase 1 state file." -ForegroundColor Red
        Write-Host "    $phase1StatePath" -ForegroundColor DarkGray
        Write-Host "    $($_.Exception.Message)" -ForegroundColor DarkGray
        Write-Host ""; return
    }

    $baseDN = [string]$phase1State.BaseDN
    $containerOU = if ($null -ne $phase1State.ContainerOU -and [string]$phase1State.ContainerOU -ne '') { [string]$phase1State.ContainerOU } else { $null }
    $tier0OUDN = [string]$phase1State.Tier0OUDN
    $tier1OUDN = [string]$phase1State.Tier1OUDN
    $tier2OUDN = [string]$phase1State.Tier2OUDN

    if ([string]::IsNullOrWhiteSpace($baseDN) -or [string]::IsNullOrWhiteSpace($tier0OUDN) -or [string]::IsNullOrWhiteSpace($tier1OUDN) -or [string]::IsNullOrWhiteSpace($tier2OUDN)) {
        Write-Host "`n  [ERROR] Phase 1 state is incomplete. Run Phase 1 again." -ForegroundColor Red
        Write-Host "    State file: $phase1StatePath" -ForegroundColor DarkGray
        Write-Host ""; return
    }

    # Results tracker
    $results = @{
        BaseDN          = $baseDN
        ContainerOU     = $containerOU
        Phase1StatePath = $phase1StatePath
        IncludeDomainControllersLinks = $false
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
    Write-Host "   Phase 3 — Create Deny Logon GPOs for each Tiers" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "   Creates 6 cross-tier deny-logon GPOs to enforce tier boundaries." -ForegroundColor DarkGray
    Write-Host "   GPO prefix: $($naming.GPOPrefix)`n" -ForegroundColor DarkGray

    # ================================================================
    # Pre-checks
    # ================================================================
    Write-Host "  Pre-checks..." -ForegroundColor Yellow

    # Check tier OUs exist
    $tierOUs = @{
        'Tier0' = $tier0OUDN
        'Tier1' = $tier1OUDN
        'Tier2' = $tier2OUDN
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

    function New-MATIUserRightsAssignmentBackup {
        param(
            [Parameter(Mandatory)]
            [string]$GpoName,

            [Parameter(Mandatory)]
            [string[]]$Rights,

            [Parameter(Mandatory)]
            [string]$GroupSid
        )

        $backupId = ([guid]::NewGuid().ToString().ToUpper())
        $templateGpoGuid = ([guid]::NewGuid().ToString().ToUpper())
        $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
        $backupRoot = Join-Path $tempRoot ("{" + $backupId + "}")
        $gptRelativePath = 'DomainSysvol\GPO\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
        $gptFilePath = Join-Path $backupRoot $gptRelativePath
        $gptDirectory = Split-Path -Path $gptFilePath -Parent

        New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $gptDirectory -Force | Out-Null

        $manifestXml = '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest" xmlns:mfst="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest" mfst:version="1.0"><BackupInst><GPOGuid><![CDATA[{' + $templateGpoGuid + '}]]></GPOGuid><GPODomain/><GPODomainGuid/><GPODomainController/><BackupTime/><ID><![CDATA[{' + $backupId + '}]]></ID><Comment/><GPODisplayName><![CDATA[' + $GpoName + ']]></GPODisplayName></BackupInst><Backups/></BackupInst>'
        $bkupInfoXml = '<BackupInst xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations/Manifest"><GPOGuid><![CDATA[{' + $templateGpoGuid + '}]]></GPOGuid><GPODomain/><GPODomainGuid/><GPODomainController/><BackupTime/><ID><![CDATA[{' + $backupId + '}]]></ID><Comment/><GPODisplayName><![CDATA[' + $GpoName + ']]></GPODisplayName></BackupInst>'
        $backupXml = '<?xml version="1.0" encoding="utf-8"?><GroupPolicyBackupScheme bkp:version="2.0" bkp:type="GroupPolicyBackupTemplate" xmlns:bkp="http://www.microsoft.com/GroupPolicy/GPOOperations" xmlns="http://www.microsoft.com/GroupPolicy/GPOOperations"><GroupPolicyObject><SecurityGroups/><FilePaths/><GroupPolicyCoreSettings><ID/><Domain/><SecurityDescriptor/><DisplayName/><Options/><UserVersionNumber/><MachineVersionNumber/><MachineExtensionGuids><![CDATA[[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]]]></MachineExtensionGuids><UserExtensionGuids/><WMIFilter/></GroupPolicyCoreSettings><GroupPolicyExtension bkp:ID="{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}" bkp:DescName="Security"><FSObjectFile bkp:Path="%GPO_MACH_FSPATH%\Microsoft\Windows NT\SecEdit\GptTmpl.inf" bkp:Location="DomainSysvol\GPO\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"/></GroupPolicyExtension></GroupPolicyObject></GroupPolicyBackupScheme>'

        $gptLines = [System.Collections.Generic.List[string]]::new()
        $gptLines.Add('[Unicode]') | Out-Null
        $gptLines.Add('Unicode=yes') | Out-Null
        $gptLines.Add('[Version]') | Out-Null
        $gptLines.Add('signature="$CHICAGO$"') | Out-Null
        $gptLines.Add('Revision=1') | Out-Null
        $gptLines.Add('[Privilege Rights]') | Out-Null
        foreach ($right in $Rights) {
            $gptLines.Add("$right = *$GroupSid") | Out-Null
        }

        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        $utf16Le = New-Object System.Text.UnicodeEncoding

        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'manifest.xml'), $manifestXml, $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $backupRoot 'bkupInfo.xml'), $bkupInfoXml, $utf8NoBom)
        [System.IO.File]::WriteAllText((Join-Path $backupRoot 'backup.xml'), $backupXml, $utf8NoBom)
        [System.IO.File]::WriteAllLines($gptFilePath, $gptLines, $utf16Le)

        return [PSCustomObject]@{
            BackupId = $backupId
            TempRoot = $tempRoot
        }
    }

    function Import-MATIUserRightsAssignmentGpo {
        param(
            [Parameter(Mandatory)]
            [string]$Name,

            [Parameter(Mandatory)]
            [string]$Description,

            [Parameter(Mandatory)]
            [string[]]$Rights,

            [Parameter(Mandatory)]
            [string]$GroupSid
        )

        function Test-MATIImportedGpoState {
            param(
                [Parameter(Mandatory)]
                [string]$GpoName,

                [Parameter(Mandatory)]
                [string[]]$ExpectedRights,

                [Parameter(Mandatory)]
                [string]$ExpectedSid
            )

            $candidate = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue
            if (-not $candidate) {
                return $null
            }

            $infPath = "\\$dnsRoot\SYSVOL\$dnsRoot\Policies\{$($candidate.Id)}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
            if (-not (Test-Path $infPath)) {
                return $null
            }

            $raw = Get-Content -Path $infPath -Raw -ErrorAction SilentlyContinue
            if ([string]::IsNullOrWhiteSpace($raw)) {
                return $null
            }

            foreach ($expectedRight in $ExpectedRights) {
                $pattern = [regex]::Escape($expectedRight + ' = *' + $ExpectedSid)
                if ($raw -notmatch $pattern) {
                    return $null
                }
            }

            return $candidate
        }

        $backup = New-MATIUserRightsAssignmentBackup -GpoName $Name -Rights $Rights -GroupSid $GroupSid
        try {
            try {
                Import-GPO -BackupId $backup.BackupId -Path $backup.TempRoot -TargetName $Name -CreateIfNeeded -ErrorAction Stop | Out-Null
            } catch {
                Start-Sleep -Milliseconds 500
                $validatedGpo = Test-MATIImportedGpoState -GpoName $Name -ExpectedRights $Rights -ExpectedSid $GroupSid
                if ($validatedGpo) {
                    return $validatedGpo
                }

                throw
            }

            $gpo = Get-GPO -Name $Name -ErrorAction Stop
            try {
                if ($Description) {
                    $gpo.Description = $Description
                }
            } catch {
                # Non-fatal: the import result is what matters.
            }

            return $gpo
        }
        finally {
            if ($backup -and (Test-Path $backup.TempRoot)) {
                try {
                    Remove-Item -Path $backup.TempRoot -Recurse -Force -ErrorAction Stop
                } catch {
                    Start-Sleep -Milliseconds 300
                    try {
                        Get-ChildItem -Path $backup.TempRoot -Force -ErrorAction SilentlyContinue |
                            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path $backup.TempRoot -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {
                        # Cleanup failures must never make the import look failed.
                    }
                }
            }
        }
    }

    Write-Host "    [OK] Tier OUs found" -ForegroundColor Green
    Write-Host "    [OK] Deny-logon groups found" -ForegroundColor Green

    # ================================================================
    # Build GPO definitions
    # ================================================================
    # Each GPO denies one tier's accounts from logging onto another tier's machines.
    # Deny rights are configured via GptTmpl.inf in the GPO's SYSVOL folder.
    $denyRights = $gpoCfg.DenyLogonRights

    $domainControllersOU = "OU=Domain Controllers,$domainDN"
    $includeDomainControllersLinks = $false
    if ([adsi]::Exists("LDAP://$domainControllersOU")) {
        Write-Host "" 
        Write-Host "  Domain Controllers OU" -ForegroundColor Yellow
        Write-Host "    This will also link the following GPOs to the Domain Controllers OU:" -ForegroundColor White
        Write-Host "      - $($naming.GPOPrefix) - Deny T1 Logon on T0" -ForegroundColor Cyan
        Write-Host "      - $($naming.GPOPrefix) - Deny T2 Logon on T0" -ForegroundColor Cyan
        $dcLinkChoice = Read-Host "    Link the Tier 0 protection GPOs to Domain Controllers? [Y/N]"
        $includeDomainControllersLinks = $dcLinkChoice.Trim().ToUpper() -eq 'Y'
    }
    $results.IncludeDomainControllersLinks = $includeDomainControllersLinks

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
            LinkTargets = @($tierOUs.Tier0)
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
            LinkTargets = @($tierOUs.Tier0)
            Description = "Prevents Tier 2 accounts from logging into Tier 0 machines"
        }
        @{
            Name       = "$($naming.GPOPrefix) - Deny T2 Logon on T1"
            Group      = "${prefix}2-${denySuffix}-${prefix}1"
            LinkTargets = @($tierOUs.Tier1)
            Description = "Prevents Tier 2 accounts from logging into Tier 1 machines"
        }
    )

    if ($includeDomainControllersLinks) {
        foreach ($def in $gpoDefinitions) {
            if ($def.Name -match 'Deny T[12] Logon on T0') {
                $def.LinkTargets += $domainControllersOU
            }
        }
    }

    # ================================================================
    # Step 1 — Review GPO plan
    # ================================================================
    Write-Host ""
    Write-Host "  Step 1/3 — GPO Plan Review" -ForegroundColor Yellow
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
    # Step 2 — Create or update GPOs via Import-GPO
    # ================================================================
    Write-Host ""
    Write-Host "  Step 2/3 — Importing Deny Logon GPOs" -ForegroundColor Yellow
    Write-Host ""

    foreach ($def in $gpoDefinitions) {
        $gpoName = $def.Name
        $groupName = $def.Group
        try {
            $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue

            $groupObj = Get-ADGroup -Identity $groupName -ErrorAction Stop
            $groupSID = [string]$groupObj.SID

            $importedGpo = Import-MATIUserRightsAssignmentGpo -Name $gpoName -Description $def.Description -Rights $denyRights -GroupSid $groupSID

            if ($existingGpo) {
                Write-Host "      [=] Updated: $gpoName" -ForegroundColor DarkGray
                $results.GPOsExisted.Add([PSCustomObject]@{ Name = $gpoName; Id = $importedGpo.Id; Status = 'Existed' })
            } else {
                Write-Host "      [+] Created: $gpoName" -ForegroundColor Green
                $results.GPOsCreated.Add([PSCustomObject]@{ Name = $gpoName; Id = $importedGpo.Id; Status = 'Created' })
            }

            foreach ($right in $denyRights) {
                $results.RightsConfigured.Add([PSCustomObject]@{
                    GPO    = $gpoName
                    Right  = $right
                    Group  = $groupName
                    SID    = $groupSID
                    Status = 'Configured'
                })
            }
        } catch {
            Write-Host "      [!] FAILED import on $gpoName — $($_.Exception.Message)" -ForegroundColor Red
            $results.Errors.Add("GPO import failed: $gpoName — $($_.Exception.Message)")
        }
    }

    # ================================================================
    # Step 3 — Link GPOs to OUs
    # ================================================================
    Write-Host ""
    Write-Host "  Step 3/3 — Linking GPOs to OUs" -ForegroundColor Yellow
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

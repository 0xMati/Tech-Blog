# ==========================================================================
# 05-OneDriveMigrationPlan.Functions.ps1
# Phase 05 - OneDrive Cross-Tenant Migration (Plan)
#
# Steps:
#   05-01  Build Users Mapping
#          - Load Phase 02 creation results (OnPrem + CloudOnly)
#          - Build SourceUPN -> TargetUPN mapping
#          - Export Users_Mapping CSV
#
#   05-02  Setup Cross-Tenant Trust
#          - Connect to SOURCE and TARGET SPO Admin
#          - Retrieve CrossTenantHostUrl on both sides
#          - Establish MnA trust (Set-SPOCrossTenantRelationship)
#          - Verify trust is GoodToProceed
#
#   05-03  Build CTIM Mapping
#          - Load Users Mapping (from 05-01)
#          - Ask for SOURCE tenant GUID
#          - Generate CTIM identity map file (no header)
#
#   05-04  Assign Licenses & Pre-Provision OneDrive
#          - Connect to Graph TARGET
#          - Load user mapping (from 05-01)
#          - List available SKUs, let operator choose
#          - Assign licenses via Set-MgUserLicense
#          - Pre-provision OneDrive for each user
#          - Export OK / Issues CSVs
# ==========================================================================

function Get-EIDMOneDriveMigrationPlanSteps {
    <#
    .SYNOPSIS
        Returns the ordered step descriptors for the OneDrive Migration Plan phase.
    .DESCRIPTION
        Each descriptor is a hashtable consumed by Invoke-EIDMPhase / Invoke-EIDMStep,
        with keys Id, Phase, Handler, Requires (and optionally AllowRerun).
        The OneDrive Migration Plan phase builds the source-to-target user mapping,
        sets up the SharePoint cross-tenant trust, produces the CTIM identity map
        and assigns the required target licenses.
    .PARAMETER Ctx
        The migration context object (run root, config, connections).
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id      = "05-01-BuildUsersMapping"
            Phase   = "05-OneDriveMigrationPlan"
            Handler = "Step-05-01-BuildUsersMapping"
            Requires = @()
        },
        @{
            Id      = "05-02-SetupCrossTenantTrust"
            Phase   = "05-OneDriveMigrationPlan"
            Handler = "Step-05-02-SetupCrossTenantTrust"
            Requires = @()
        },
        @{
            Id      = "05-03-BuildCtimMapping"
            Phase   = "05-OneDriveMigrationPlan"
            Handler = "Step-05-03-BuildCtimMapping"
            Requires = @()
        },
        @{
            Id         = "05-04-AssignLicenses"
            Phase      = "05-OneDriveMigrationPlan"
            Handler    = "Step-05-04-AssignLicenses"
            Requires   = @()
            AllowRerun = $true
        }
    )
}

# ==========================================================================
# STEP 05-01 - Build Users Mapping (Source UPN -> Target UPN)
# ==========================================================================

function Step-05-01-BuildUsersMapping {
    <#
    .SYNOPSIS  Build a source-to-target user mapping for OneDrive migration.
    .DESCRIPTION
        Loads Phase 02 creation results (OnPrem + CloudOnly),
        builds a mapping with P5Status (OK / SKIP / FAILED),
        checks for duplicates, and exports to CSV.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Build Users Mapping for OneDrive Migration"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Load Phase 02 user creation results" -ForegroundColor Gray
    Write-Host "    - Build SourceUPN -> TargetUPN mapping" -ForegroundColor Gray
    Write-Host "    - Export Users_Mapping CSV" -ForegroundColor Gray
    Write-Host ""

    $planFolder = Join-Path $Ctx.RunRoot "05-OneDriveMigrationPlan"
    Assert-EIDMDirectory -Path $planFolder

    # ----------------------------------------------------------------
    # 1) Idempotency check
    # ----------------------------------------------------------------
    $existingCsv = @(Get-ChildItem -Path $planFolder -Filter "OneDrive_UsersMapping_*.csv" -ErrorAction SilentlyContinue)
    if ($existingCsv.Count -gt 0) {
        $latest = $existingCsv | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-EIDMTag -Tag "INFO" -Text ("Users mapping CSV already exists: {0}" -f $latest.Name) -Color Yellow

        $redo = Read-EIDMSimpleYesNo "Regenerate the users mapping?"
        if (-not $redo) {
            Write-EIDMTag -Tag "SKIP" -Text "Keeping existing CSV." -Color Gray
            return $script:EIDMStatus_Completed
        }
        Write-Host ""
    }

    # ----------------------------------------------------------------
    # 2) Load Phase 02 creation results
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Phase 02 Creation Results"

    $idPrepFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    $onPremCsvPath = Join-Path $idPrepFolder "Users_OnPrem_CreationResults.csv"
    $cloudCsvPath  = Join-Path $idPrepFolder "Users_CloudOnly_CreationResults.csv"

    $hasOnPrem = Test-Path $onPremCsvPath
    $hasCloud  = Test-Path $cloudCsvPath

    if (-not $hasOnPrem -and -not $hasCloud) {
        Write-EIDMTag -Tag "ERROR" -Text "No Phase 02 user creation results. Run Phase 02 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $allRows = @()

    if ($hasOnPrem) {
        $rawOnPrem = @(Import-Csv -Path $onPremCsvPath)
        Write-EIDMTag -Tag "INFO" -Text ("OnPrem creation results: {0} rows" -f $rawOnPrem.Count) -Color Gray
        foreach ($r in $rawOnPrem) {
            $allRows += [PSCustomObject]@{
                SourceUPN = $r.SourceUPN
                TargetUPN = $r.TargetUPN
                UserKind  = "SYNCED"
                ExecutionStatus = $r.ExecutionStatus
                AccountCreated  = $r.AccountCreated
                AccountAlreadyExists = $r.AccountAlreadyExists
            }
        }
    }

    if ($hasCloud) {
        $rawCloud = @(Import-Csv -Path $cloudCsvPath)
        Write-EIDMTag -Tag "INFO" -Text ("CloudOnly creation results: {0} rows" -f $rawCloud.Count) -Color Gray
        foreach ($r in $rawCloud) {
            $allRows += [PSCustomObject]@{
                SourceUPN = $r.SourceUPN
                TargetUPN = $r.TargetUPN
                UserKind  = "CLOUD"
                ExecutionStatus = $r.ExecutionStatus
                AccountCreated  = $r.AccountCreated
                AccountAlreadyExists = $r.AccountAlreadyExists
            }
        }
    }

    Write-EIDMTag -Tag "INFO" -Text ("Total rows loaded: {0}" -f $allRows.Count) -Color Gray

    # ----------------------------------------------------------------
    # 3) Build mapping with status
    # ----------------------------------------------------------------
    Write-EIDMSection "Build Mapping"

    $mapping = @()

    foreach ($u in $allRows) {
        $sourceUpn = if ($u.SourceUPN) { $u.SourceUPN.Trim().ToLowerInvariant() } else { $null }
        $targetUpn = if ($u.TargetUPN) { $u.TargetUPN.Trim().ToLowerInvariant() } else { $null }

        $status = "OK"
        $reason = ""

        if (-not $sourceUpn -or -not $targetUpn) {
            $status = "FAILED"
            if (-not $sourceUpn -and -not $targetUpn) { $reason = "Missing SourceUPN and TargetUPN" }
            elseif (-not $sourceUpn) { $reason = "Missing SourceUPN" }
            else { $reason = "Missing TargetUPN" }
        }
        elseif ($u.ExecutionStatus -ne "Success" -and $u.AccountAlreadyExists -ne "True") {
            $status = "FAILED"
            $reason = "ExecutionStatus={0}" -f $u.ExecutionStatus
        }

        $mapping += [PSCustomObject]@{
            SourceUPN   = $sourceUpn
            TargetUPN   = $targetUpn
            UserKind    = $u.UserKind
            P5Status    = $status
            P5Reason    = $reason
            GeneratedOn = (Get-Date).ToString("s")
        }
    }

    # ----------------------------------------------------------------
    # 4) Duplicate checks among OK rows
    # ----------------------------------------------------------------
    Write-EIDMSection "Check for Duplicates"

    $okRows = @($mapping | Where-Object { $_.P5Status -eq "OK" -and $_.SourceUPN -and $_.TargetUPN })

    $dupSource = @($okRows | Group-Object SourceUPN | Where-Object { $_.Count -gt 1 })
    $dupTarget = @($okRows | Group-Object TargetUPN | Where-Object { $_.Count -gt 1 })

    if ($dupSource.Count -gt 0 -or $dupTarget.Count -gt 0) {
        Write-EIDMTag -Tag "WARN" -Text "Duplicates detected. Marking as FAILED." -Color Yellow

        foreach ($g in $dupSource) {
            $mapping | Where-Object { $_.P5Status -eq "OK" -and $_.SourceUPN -eq $g.Name } | ForEach-Object {
                $_.P5Status = "FAILED"
                $_.P5Reason = "Duplicate SourceUPN"
            }
        }
        foreach ($g in $dupTarget) {
            $mapping | Where-Object { $_.P5Status -eq "OK" -and $_.TargetUPN -eq $g.Name } | ForEach-Object {
                $_.P5Status = "FAILED"
                $_.P5Reason = "Duplicate TargetUPN"
            }
        }
    } else {
        Write-EIDMTag -Tag "INFO" -Text "No duplicates detected." -Color Gray
    }

    # ----------------------------------------------------------------
    # 5) Export
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Users Mapping"

    $stamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $planFolder ("OneDrive_UsersMapping_{0}.csv" -f $stamp)

    $mapping | Sort-Object P5Status, UserKind, TargetUPN | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $total  = $mapping.Count
    $okCnt  = @($mapping | Where-Object { $_.P5Status -eq "OK" }).Count
    $failCnt = @($mapping | Where-Object { $_.P5Status -eq "FAILED" }).Count

    Write-EIDMTag -Tag "OK" -Text ("Users mapping exported: {0}" -f $csvPath) -Color Green
    Write-Host ""
    Write-Host ("  Total : {0}" -f $total) -ForegroundColor Gray
    Write-Host ("  OK    : {0}" -f $okCnt) -ForegroundColor Green
    Write-Host ("  FAILED: {0}" -f $failCnt) -ForegroundColor $(if ($failCnt -gt 0) { "Red" } else { "Gray" })

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 05-02 - Setup Cross-Tenant Trust (MnA)
# ==========================================================================

function Step-05-02-SetupCrossTenantTrust {
    <#
    .SYNOPSIS  Establish cross-tenant OneDrive trust between SOURCE and TARGET.
    .DESCRIPTION
        1) License prerequisite confirmations.
        2) Connect to both SPO Admin tenants.
        3) Retrieve CrossTenantHostUrl on both sides.
        4) Set-SPOCrossTenantRelationship on both sides.
        5) Verify trust (GoodToProceed).
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Setup Cross-Tenant Trust (OneDrive MnA)"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Verify license prerequisites (Cross-tenant user data migration)" -ForegroundColor Gray
    Write-Host "    - Connect to SOURCE and TARGET SharePoint Online Admin" -ForegroundColor Gray
    Write-Host "    - Establish cross-tenant trust (Set-SPOCrossTenantRelationship)" -ForegroundColor Gray
    Write-Host "    - Verify trust is GoodToProceed" -ForegroundColor Gray
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) License prerequisites
    # ----------------------------------------------------------------
    Write-EIDMSection "License Prerequisites"

    Write-Host "Before continuing, confirm the following:" -ForegroundColor Yellow
    Write-Host "  1) SOURCE admin has a 'Cross-tenant user data migration' license" -ForegroundColor Yellow
    Write-Host "  2) TARGET admin has a 'Cross-tenant user data migration' license" -ForegroundColor Yellow
    Write-Host "  3) Users to migrate have a 'Cross-tenant user data migration' license" -ForegroundColor Yellow
    Write-Host ""

    $licOk = Read-EIDMSimpleYesNo "Are all license prerequisites met?"
    if (-not $licOk) {
        Write-EIDMTag -Tag "ERROR" -Text "License prerequisites not confirmed. Aborting." -Color Red
        return $script:EIDMStatus_Failed
    }

    # ----------------------------------------------------------------
    # 2) Get CrossTenantHostUrl from SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve CrossTenantHostUrl (SOURCE)"

    # Disconnect any existing SPO session
    Disconnect-EIDMSharePointIfNeeded

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    $sourceHostUrl = $null
    try {
        $sourceHostUrl = Get-EIDMCrossTenantHostUrl -Label "SOURCE"
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to get CrossTenantHostUrl on SOURCE: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 3) Get CrossTenantHostUrl from TARGET
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve CrossTenantHostUrl (TARGET)"

    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $targetHostUrl = $null
    try {
        $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET"
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to get CrossTenantHostUrl on TARGET: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    if (-not $sourceHostUrl -or -not $targetHostUrl) {
        Write-EIDMTag -Tag "ERROR" -Text "CrossTenantHostUrl missing on one or both sides." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-Host ""
    Write-Host ("  SOURCE CrossTenantHostUrl: {0}" -f $sourceHostUrl) -ForegroundColor Gray
    Write-Host ("  TARGET CrossTenantHostUrl: {0}" -f $targetHostUrl) -ForegroundColor Gray
    Write-Host ""

    # ----------------------------------------------------------------
    # 4) Establish trust: SOURCE -> TARGET
    # ----------------------------------------------------------------
    Write-EIDMSection "Establish Trust: SOURCE -> TARGET"

    Write-Host "Sign in with the SOURCE admin account." -ForegroundColor DarkGray
    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    try {
        Set-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Set-SPOCrossTenantRelationship on SOURCE (PartnerRole=Target) succeeded." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Set-SPOCrossTenantRelationship failed on SOURCE: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 5) Establish trust: TARGET -> SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Establish Trust: TARGET -> SOURCE"

    Write-Host "Sign in with the TARGET admin account." -ForegroundColor DarkGray
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    try {
        Set-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Set-SPOCrossTenantRelationship on TARGET (PartnerRole=Source) succeeded." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Set-SPOCrossTenantRelationship failed on TARGET: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 6) Verify trust on both sides
    # ----------------------------------------------------------------
    Write-EIDMSection "Verify Trust (GoodToProceed)"

    # Verify from SOURCE
    Write-Host "Verifying from SOURCE... Sign in with SOURCE admin." -ForegroundColor DarkGray
    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    $srcOk = $false
    try {
        $srcVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
        $srcText = ($srcVerify | Out-String).Trim()
        Write-EIDMTag -Tag "INFO" -Text ("SOURCE verify result: {0}" -f $srcText) -Color Gray
        $srcOk = ($srcText -match 'GoodToProceed')
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Verify failed on SOURCE: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # Verify from TARGET
    Write-Host "Verifying from TARGET... Sign in with TARGET admin." -ForegroundColor DarkGray
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $tgtOk = $false
    try {
        $tgtVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
        $tgtText = ($tgtVerify | Out-String).Trim()
        Write-EIDMTag -Tag "INFO" -Text ("TARGET verify result: {0}" -f $tgtText) -Color Gray
        $tgtOk = ($tgtText -match 'GoodToProceed')
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Verify failed on TARGET: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 7) Summary
    # ----------------------------------------------------------------
    Write-EIDMSection "Trust Summary"

    if ($srcOk -and $tgtOk) {
        Write-EIDMTag -Tag "OK" -Text "Cross-tenant trust is GoodToProceed on both sides." -Color Green
        return $script:EIDMStatus_Completed
    }
    else {
        Write-Host ("  SOURCE GoodToProceed: {0}" -f $srcOk) -ForegroundColor $(if ($srcOk) { "Green" } else { "Red" })
        Write-Host ("  TARGET GoodToProceed: {0}" -f $tgtOk) -ForegroundColor $(if ($tgtOk) { "Green" } else { "Red" })
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text "Trust is NOT GoodToProceed on both sides. It may take a few minutes to propagate. Retry later." -Color Yellow
        return $script:EIDMStatus_Completed
    }
}

# ==========================================================================
# STEP 05-03 - Build CTIM Mapping (Cross-Tenant Identity Map)
# ==========================================================================

function Step-05-03-BuildCtimMapping {
    <#
    .SYNOPSIS  Generate a CTIM identity map file for OneDrive migration.
    .DESCRIPTION
        1) Load Users Mapping CSV from 05-01.
        2) Filter rows with P5Status = OK.
        3) Ask for SOURCE tenant GUID.
        4) Generate CTIM file (no header, CSV format).
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Build CTIM Mapping for OneDrive Migration"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Load the Users Mapping CSV (from step 05-01)" -ForegroundColor Gray
    Write-Host "    - Filter eligible users (P5Status=OK)" -ForegroundColor Gray
    Write-Host "    - Ask for the SOURCE tenant directory ID (GUID)" -ForegroundColor Gray
    Write-Host "    - Generate a CTIM identity map file" -ForegroundColor Gray
    Write-Host ""

    $planFolder = Join-Path $Ctx.RunRoot "05-OneDriveMigrationPlan"
    Assert-EIDMDirectory -Path $planFolder

    # ----------------------------------------------------------------
    # 1) Idempotency check
    # ----------------------------------------------------------------
    $existingCtim = @(Get-ChildItem -Path $planFolder -Filter "OneDrive_CTIM_*.csv" -ErrorAction SilentlyContinue)
    if ($existingCtim.Count -gt 0) {
        $latest = $existingCtim | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-EIDMTag -Tag "INFO" -Text ("CTIM file already exists: {0}" -f $latest.Name) -Color Yellow

        $redo = Read-EIDMSimpleYesNo "Regenerate the CTIM mapping?"
        if (-not $redo) {
            Write-EIDMTag -Tag "SKIP" -Text "Keeping existing CTIM file." -Color Gray
            return $script:EIDMStatus_Completed
        }
        Write-Host ""
    }

    # ----------------------------------------------------------------
    # 2) Locate Users Mapping CSV
    # ----------------------------------------------------------------
    Write-EIDMSection "Locate Users Mapping CSV"

    $mappingFile = Get-ChildItem -Path $planFolder -Filter "OneDrive_UsersMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $mappingFile) {
        Write-EIDMTag -Tag "ERROR" -Text "No OneDrive_UsersMapping CSV found. Run step 05-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Using: {0}" -f $mappingFile.FullName) -Color Gray

    # ----------------------------------------------------------------
    # 3) Load and filter
    # ----------------------------------------------------------------
    $users = @(Import-Csv -Path $mappingFile.FullName)
    Write-EIDMTag -Tag "INFO" -Text ("Total rows: {0}" -f $users.Count) -Color Gray

    $eligible = @($users | Where-Object { $_.P5Status -eq "OK" })
    Write-EIDMTag -Tag "INFO" -Text ("Eligible rows (P5Status=OK): {0}" -f $eligible.Count) -Color Gray

    if ($eligible.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No eligible users. CTIM file will be empty." -Color Yellow
    }

    # ----------------------------------------------------------------
    # 4) Ask for SOURCE tenant GUID
    # ----------------------------------------------------------------
    Write-EIDMSection "SOURCE Tenant Directory ID (GUID)"

    Write-Host "The CTIM mapping requires the SOURCE tenant company ID (directory GUID)." -ForegroundColor Yellow
    Write-Host "You can find it in Azure Portal -> Entra ID -> Overview -> Tenant ID." -ForegroundColor Yellow
    Write-Host ""

    $sourceTenantId = $null
    while (-not $sourceTenantId) {
        $input = Read-Host "Enter SOURCE tenant ID (GUID)"
        if (-not $input -or -not $input.Trim()) {
            Write-Host "Tenant ID is required." -ForegroundColor Yellow
            continue
        }

        $cleaned = $input.Trim().Replace('"', '').Replace("'", '')

        if ($cleaned -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            Write-Host "Not a valid GUID format. Please retry." -ForegroundColor Yellow
            continue
        }

        $sourceTenantId = $cleaned
    }

    Write-EIDMTag -Tag "INFO" -Text ("SOURCE Tenant GUID: {0}" -f $sourceTenantId) -Color Gray

    # ----------------------------------------------------------------
    # 5) Build CTIM lines
    # ----------------------------------------------------------------
    Write-EIDMSection "Generate CTIM Lines"

    $ctimLines = @()

    foreach ($u in $eligible) {
        $srcUpn = $u.SourceUPN
        $tgtUpn = $u.TargetUPN

        if (-not $srcUpn -or -not $tgtUpn) { continue }

        # CTIM format: User,SourceTenantGUID,SourceUPN,TargetUPN,TargetEmail,UserType
        $line = "User,{0},{1},{2},{3},RegularUser" -f $sourceTenantId, $srcUpn, $tgtUpn, $tgtUpn
        $ctimLines += $line
    }

    Write-EIDMTag -Tag "INFO" -Text ("CTIM lines built: {0}" -f $ctimLines.Count) -Color Gray

    if ($ctimLines.Count -gt 0) {
        Write-Host ("  First line: {0}" -f $ctimLines[0]) -ForegroundColor DarkGray
    }

    # ----------------------------------------------------------------
    # 6) Write CTIM file (no header, UTF-8)
    # ----------------------------------------------------------------
    Write-EIDMSection "Export CTIM File"

    $stamp    = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $ctimPath = Join-Path $planFolder ("OneDrive_CTIM_{0}.csv" -f $stamp)

    if ($ctimLines.Count -gt 0) {
        [System.IO.File]::WriteAllLines($ctimPath, $ctimLines, [System.Text.Encoding]::UTF8)
    }
    else {
        [System.IO.File]::WriteAllText($ctimPath, "", [System.Text.Encoding]::UTF8)
    }

    Write-EIDMTag -Tag "OK" -Text ("CTIM file exported: {0}" -f $ctimPath) -Color Green
    Write-Host ""
    Write-Host ("  CTIM entries: {0}" -f $ctimLines.Count) -ForegroundColor Gray

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 05-04 - Assign Licenses & Pre-Provision OneDrive
# ==========================================================================

function Step-05-04-AssignLicenses {
    <#
    .SYNOPSIS  Assigns OneDrive/SPO licenses to target users and pre-provisions
               their OneDrive sites before cross-tenant migration.
    .DESCRIPTION
        Per https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration
        target users MUST:
          - Be licensed for OneDrive for Business
          - Have their OneDrive site pre-provisioned

        This step:
        1) Loads user mapping from 05-01.
        2) Connects to TARGET Graph.
        3) Lists available SKUs, lets operator pick.
        4) Assigns selected licenses via Set-MgUserLicense.
        5) (Removed) OneDrive pre-provisioning is NOT done here because
           Start-SPOCrossTenantUserContentMove creates the target site
           automatically. Pre-provisioning causes a target site conflict.
        6) Exports OK / Issues CSVs.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Assign Licenses for OneDrive Migration (TARGET)"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Load user mapping from step 05-01" -ForegroundColor DarkGray
    Write-Host "    - Connect to TARGET Graph and assign chosen license SKUs" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Target users MUST be licensed for OneDrive before migration." -ForegroundColor Yellow
    Write-Host "OneDrive sites will be created automatically during the cross-tenant move." -ForegroundColor DarkGray
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) Output folder
    # ----------------------------------------------------------------
    $planFolder = Join-Path $Ctx.RunRoot "05-OneDriveMigrationPlan"
    Assert-EIDMDirectory -Path $planFolder

    # ----------------------------------------------------------------
    # 2) Load user mapping from 05-01
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Users Mapping (Step 05-01)"

    $mappingFile = Get-ChildItem -Path $planFolder -Filter "OneDrive_UsersMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $mappingFile) {
        Write-EIDMTag -Tag "ERROR" -Text "No OneDrive_UsersMapping CSV found. Run step 05-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $allRows = @(Import-Csv -Path $mappingFile.FullName -Encoding UTF8)
    $eligible = @($allRows | Where-Object { $_.P5Status -eq "OK" })

    Write-EIDMTag -Tag "INFO" -Text ("Mapping file: {0}" -f $mappingFile.Name) -Color Gray
    Write-EIDMTag -Tag "INFO" -Text ("Total rows: {0}  |  Eligible (OK): {1}" -f $allRows.Count, $eligible.Count) -Color Gray

    if ($eligible.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "No eligible users (P5Status=OK). Cannot assign licenses." -Color Red
        return $script:EIDMStatus_Failed
    }

    # Show user list
    Write-Host ""
    Write-Host "  Eligible users:" -ForegroundColor DarkGray
    foreach ($u in $eligible) {
        Write-Host ("    [{0}] {1} -> {2}" -f $u.UserKind, $u.SourceUPN, $u.TargetUPN) -ForegroundColor DarkGray
    }
    Write-Host ""

    # ----------------------------------------------------------------
    # 3) Connect to TARGET Graph
    # ----------------------------------------------------------------
    Write-EIDMSection "Connect to TARGET tenant (Graph)"

    try {
        Ensure-EIDMGraphTargetConnection -Ctx $Ctx
        Write-EIDMTag -Tag "OK" -Text "Connected to TARGET Graph" -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Graph connection failed: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    # ----------------------------------------------------------------
    # 4) List available SKUs
    # ----------------------------------------------------------------
    Write-EIDMSection "Available License SKUs on TARGET Tenant"

    try {
        $skus = @(Get-MgSubscribedSku -All -ErrorAction Stop)
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to retrieve SKUs: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    if ($skus.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "No license SKUs found on target tenant." -Color Red
        return $script:EIDMStatus_Failed
    }

    # Build display table
    Write-Host ""
    Write-Host ("  {0,-6} {1,-40} {2,-10} {3,-10} {4,-10} {5}" -f "Index", "SkuPartNumber", "Enabled", "Consumed", "Available", "SkuId") -ForegroundColor Cyan
    Write-Host ("  {0}" -f ("-" * 110)) -ForegroundColor DarkGray

    for ($i = 0; $i -lt $skus.Count; $i++) {
        $sku       = $skus[$i]
        $enabled   = $sku.PrepaidUnits.Enabled
        $consumed  = $sku.ConsumedUnits
        $available = $enabled - $consumed

        $color = if ($available -gt 0) { "Green" } else { "Red" }

        Write-Host ("  {0,-6} {1,-40} {2,-10} {3,-10} {4,-10} {5}" -f `
            "[$i]", $sku.SkuPartNumber, $enabled, $consumed, $available, $sku.SkuId) -ForegroundColor $color
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # 5) Let operator pick SKUs
    # ----------------------------------------------------------------
    Write-EIDMSection "Select SKUs to Assign"

    Write-Host "Enter the index numbers of the SKUs to assign (comma-separated)." -ForegroundColor Cyan
    Write-Host "Pick a SKU that includes OneDrive for Business (e.g. SPE_E3, SPE_E5, SHAREPOINTENTERPRISE...)." -ForegroundColor Cyan
    Write-Host "Example: 0,2" -ForegroundColor DarkGray
    Write-Host ""

    $skuInput = Read-EIDMNonEmpty "SKU indexes to assign"
    $selectedIndexes = @()
    foreach ($part in ($skuInput -split ',')) {
        $trimmed = $part.Trim()
        if ($trimmed -match '^\d+$') {
            $idx = [int]$trimmed
            if ($idx -ge 0 -and $idx -lt $skus.Count) {
                $selectedIndexes += $idx
            }
            else {
                Write-EIDMTag -Tag "WARN" -Text ("Index {0} out of range - ignored" -f $idx) -Color Yellow
            }
        }
        else {
            Write-EIDMTag -Tag "WARN" -Text ("Invalid input '{0}' - ignored" -f $trimmed) -Color Yellow
        }
    }

    if ($selectedIndexes.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "No valid SKU indexes selected. Aborting." -Color Red
        return $script:EIDMStatus_Failed
    }

    # Build AddLicenses array
    $addLicenses = @()
    foreach ($idx in $selectedIndexes) {
        $sku = $skus[$idx]
        $addLicenses += @{ SkuId = [guid]$sku.SkuId }
        Write-EIDMTag -Tag "INFO" -Text ("Selected: [{0}] {1}  (SkuId: {2})" -f $idx, $sku.SkuPartNumber, $sku.SkuId) -Color Cyan
    }

    Write-Host ""

    # ----------------------------------------------------------------
    # 6) Confirm
    # ----------------------------------------------------------------
    $confirmMsg = "Assign {0} SKU(s) to {1} user(s) and pre-provision OneDrive?" -f $addLicenses.Count, $eligible.Count
    if (-not (Read-EIDMSimpleYesNo $confirmMsg)) {
        Write-EIDMTag -Tag "INFO" -Text "Operator cancelled." -Color Yellow
        return $script:EIDMStatus_WaitingUser
    }

    # ----------------------------------------------------------------
    # 7) Assign licenses per user
    # ----------------------------------------------------------------
    Write-EIDMSection "Assigning Licenses"

    $resultsOK     = @()
    $resultsIssues = @()
    $totalCount    = $eligible.Count
    $currentIndex  = 0
    $provisionUpns = @()

    foreach ($userRow in $eligible) {
        $currentIndex++
        $targetUpn = $userRow.TargetUPN
        $userKind  = $userRow.UserKind

        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text ("[{0}/{1}] Processing: {2} ({3})" -f $currentIndex, $totalCount, $targetUpn, $userKind) -Color Gray

        # Resolve user in Graph
        $mgUser  = $null
        $userId  = $null
        try {
            $mgUser = Get-MgUser -UserId $targetUpn -Property "id,userPrincipalName,assignedLicenses,usageLocation" -ErrorAction Stop
            $userId = $mgUser.Id
        }
        catch {
            $errMsg = "Failed to resolve user in Graph: {0}" -f $_.Exception.Message
            Write-EIDMTag -Tag "ERROR" -Text $errMsg -Color Red
            $resultsIssues += [PSCustomObject]@{
                Status    = "Failed"
                Kind      = $userKind
                UserId    = ""
                UPN       = $targetUpn
                SKUs      = ($addLicenses | ForEach-Object { $_.SkuId }) -join ";"
                Error     = $errMsg
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            continue
        }

        # Check UsageLocation
        if ([string]::IsNullOrWhiteSpace($mgUser.UsageLocation)) {
            Write-EIDMTag -Tag "WARN" -Text ("UsageLocation is empty for {0} - setting to 'US'" -f $targetUpn) -Color Yellow
            try {
                Update-MgUser -UserId $userId -UsageLocation "US" -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text "UsageLocation set to 'US'" -Color Green
            }
            catch {
                $errMsg = "Failed to set UsageLocation: {0}" -f $_.Exception.Message
                Write-EIDMTag -Tag "ERROR" -Text $errMsg -Color Red
                $resultsIssues += [PSCustomObject]@{
                    Status    = "Failed"
                    Kind      = $userKind
                    UserId    = $userId
                    UPN       = $targetUpn
                    SKUs      = ($addLicenses | ForEach-Object { $_.SkuId }) -join ";"
                    Error     = $errMsg
                    Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                }
                continue
            }
        }

        # Check which selected SKUs are already assigned
        $existingSkuIds = @()
        if ($null -ne $mgUser.AssignedLicenses) {
            $existingSkuIds = @($mgUser.AssignedLicenses | ForEach-Object { $_.SkuId })
        }

        $licensesToAdd     = @()
        $alreadyAssignedSkus = @()
        foreach ($lic in $addLicenses) {
            if ($existingSkuIds -contains $lic.SkuId) {
                $alreadyAssignedSkus += $lic.SkuId
            }
            else {
                $licensesToAdd += @{ SkuId = $lic.SkuId }
            }
        }

        if ($alreadyAssignedSkus.Count -gt 0) {
            $skuNames = @()
            foreach ($aId in $alreadyAssignedSkus) {
                $match = $skus | Where-Object { $_.SkuId -eq $aId } | Select-Object -First 1
                if ($match) { $skuNames += $match.SkuPartNumber } else { $skuNames += $aId }
            }
            Write-EIDMTag -Tag "SKIP" -Text ("Already assigned: {0}" -f ($skuNames -join ", ")) -Color DarkGray
        }

        if ($licensesToAdd.Count -eq 0) {
            Write-EIDMTag -Tag "SKIP" -Text "All selected SKUs already assigned" -Color DarkGray
            $resultsOK += [PSCustomObject]@{
                Status    = "AlreadyAssigned"
                Kind      = $userKind
                UserId    = $userId
                UPN       = $targetUpn
                SKUs      = ($addLicenses | ForEach-Object { $_.SkuId }) -join ";"
                Error     = ""
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $provisionUpns += $targetUpn
            continue
        }

        # Assign
        try {
            Set-MgUserLicense -UserId $userId -AddLicenses $licensesToAdd -RemoveLicenses @() -ErrorAction Stop | Out-Null

            $assignedNames = @()
            foreach ($l in $licensesToAdd) {
                $match = $skus | Where-Object { $_.SkuId -eq $l.SkuId } | Select-Object -First 1
                if ($match) { $assignedNames += $match.SkuPartNumber } else { $assignedNames += $l.SkuId }
            }
            Write-EIDMTag -Tag "OK" -Text ("Assigned: {0}" -f ($assignedNames -join ", ")) -Color Green

            $resultsOK += [PSCustomObject]@{
                Status    = "Assigned"
                Kind      = $userKind
                UserId    = $userId
                UPN       = $targetUpn
                SKUs      = ($licensesToAdd | ForEach-Object { $_.SkuId }) -join ";"
                Error     = ""
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            $provisionUpns += $targetUpn
        }
        catch {
            $errMsg = $_.Exception.Message
            Write-EIDMTag -Tag "ERROR" -Text ("License assignment failed: {0}" -f $errMsg) -Color Red
            $resultsIssues += [PSCustomObject]@{
                Status    = "Failed"
                Kind      = $userKind
                UserId    = $userId
                UPN       = $targetUpn
                SKUs      = ($licensesToAdd | ForEach-Object { $_.SkuId }) -join ";"
                Error     = $errMsg
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }
    }

    # ----------------------------------------------------------------
    # 8) OneDrive pre-provisioning - SKIPPED
    # ----------------------------------------------------------------
    # NOTE: We intentionally do NOT pre-provision OneDrive sites on the target.
    # Start-SPOCrossTenantUserContentMove creates the target OneDrive site
    # automatically during migration. Pre-provisioning causes a "target tenant
    # has a conflict" error that requires the site to be deleted first.

    Write-Host ""
    Write-EIDMSection "OneDrive Pre-Provisioning"
    Write-Host "  OneDrive sites on TARGET will be created automatically during the cross-tenant move." -ForegroundColor DarkGray
    Write-Host "  Pre-provisioning is skipped to avoid target site conflicts." -ForegroundColor DarkGray

    # ----------------------------------------------------------------
    # 9) Export results
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Export Results"

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    if ($resultsOK.Count -gt 0) {
        $okPath = Join-Path $planFolder ("OneDrive_AssignLicenses_OK_{0}.csv" -f $stamp)
        $resultsOK | Export-Csv -Path $okPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("OK results exported: {0}" -f $okPath) -Color Green
    }

    if ($resultsIssues.Count -gt 0) {
        $issuesPath = Join-Path $planFolder ("OneDrive_AssignLicenses_Issues_{0}.csv" -f $stamp)
        $resultsIssues | Export-Csv -Path $issuesPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "WARN" -Text ("Issues exported: {0}" -f $issuesPath) -Color Yellow
    }

    # ----------------------------------------------------------------
    # 10) Summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Summary"

    $assignedCount        = @($resultsOK     | Where-Object { $_.Status -eq "Assigned" }).Count
    $alreadyAssignedCount = @($resultsOK     | Where-Object { $_.Status -eq "AlreadyAssigned" }).Count
    $failedCount          = $resultsIssues.Count

    Write-Host ("  Assigned:           {0}" -f $assignedCount) -ForegroundColor Green
    Write-Host ("  Already assigned:   {0}" -f $alreadyAssignedCount) -ForegroundColor DarkGray
    Write-Host ("  Failed:             {0}" -f $failedCount) -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })
    Write-Host "  OneDrive provision: skipped (created during migration)" -ForegroundColor DarkGray
    Write-Host ""

    if ($failedCount -gt 0) {
        Write-Host "  Failed users:" -ForegroundColor Red
        foreach ($issue in $resultsIssues) {
            Write-Host ("    {0}: {1}" -f $issue.UPN, $issue.Error) -ForegroundColor Red
        }
        Write-Host ""
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# 06-OneDriveMigrationExecution.Functions.ps1
# Phase 06 - OneDrive Cross-Tenant Migration (Execution)
#
# Steps:
#   06-01  Start OneDrive Migrations
#          - Upload CTIM identity map to TARGET (Add-SPOTenantIdentityMap)
#          - Start cross-tenant user content moves on SOURCE
#            (Start-SPOCrossTenantUserContentMove per user)
#
#   06-02  Check Migration Status
#          - Get-SPOCrossTenantUserContentMoveState from both tenants
#          - Export status CSVs
#
#   06-03  Reset Cross-Tenant Trust
#          - Remove-SPOCrossTenantRelationship on both sides
#          - Verify removal
# ==========================================================================

function Get-EIDMOneDriveMigrationExecutionSteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id      = "06-01-StartOneDriveMigrations"
            Phase   = "06-OneDriveMigrationExecution"
            Handler = "Step-06-01-StartOneDriveMigrations"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id      = "06-02-CheckMigrationStatus"
            Phase   = "06-OneDriveMigrationExecution"
            Handler = "Step-06-02-CheckMigrationStatus"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id      = "06-03-ResetCrossTenantTrust"
            Phase   = "06-OneDriveMigrationExecution"
            Handler = "Step-06-03-ResetCrossTenantTrust"
            Requires   = @()
            AllowRerun = $true
        }
    )
}

# ==========================================================================
# STEP 06-01 - Start OneDrive Migrations
# ==========================================================================

function Step-06-01-StartOneDriveMigrations {
    <#
    .SYNOPSIS  Upload CTIM identity map and start OneDrive cross-tenant moves.
    .DESCRIPTION
        1) Locate the CTIM file from Phase 05.
        2) Locate the Users Mapping from Phase 05.
        3) Upload CTIM identity map to TARGET (Add-SPOTenantIdentityMap).
        4) Start cross-tenant moves on SOURCE per user
           (Start-SPOCrossTenantUserContentMove).
        5) Export results CSV.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Start OneDrive Cross-Tenant Migrations"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Upload the CTIM identity map to the TARGET tenant" -ForegroundColor Gray
    Write-Host "    - Start OneDrive content moves from SOURCE for each user" -ForegroundColor Gray
    Write-Host "    - Export results CSV" -ForegroundColor Gray
    Write-Host ""

    $planFolder = Join-Path $Ctx.RunRoot "05-OneDriveMigrationPlan"
    $execFolder = Join-Path $Ctx.RunRoot "06-OneDriveMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Locate CTIM file
    # ----------------------------------------------------------------
    Write-EIDMSection "Locate CTIM File"

    $ctimFile = Get-ChildItem -Path $planFolder -Filter "OneDrive_CTIM_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $ctimFile) {
        Write-EIDMTag -Tag "ERROR" -Text "No OneDrive_CTIM CSV found in Phase 05 output. Run step 05-03 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("CTIM file: {0}" -f $ctimFile.FullName) -Color Gray

    $ctimLines = @([System.IO.File]::ReadAllLines($ctimFile.FullName) | Where-Object { $_ -and $_.Trim() })
    Write-EIDMTag -Tag "INFO" -Text ("CTIM entries: {0}" -f $ctimLines.Count) -Color Gray

    if ($ctimLines.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "CTIM file is empty. Nothing to migrate." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ----------------------------------------------------------------
    # 2) Locate Users Mapping
    # ----------------------------------------------------------------
    Write-EIDMSection "Locate Users Mapping"

    $mappingFile = Get-ChildItem -Path $planFolder -Filter "OneDrive_UsersMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if (-not $mappingFile) {
        Write-EIDMTag -Tag "ERROR" -Text "No OneDrive_UsersMapping CSV. Run step 05-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $mappingData = @(Import-Csv -Path $mappingFile.FullName | Where-Object { $_.P5Status -eq "OK" })
    Write-EIDMTag -Tag "INFO" -Text ("OK users from mapping: {0}" -f $mappingData.Count) -Color Gray

    # ----------------------------------------------------------------
    # 3) Safety confirmation
    # ----------------------------------------------------------------
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " PRODUCTION ACTION: OneDrive Migration                      " -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ("  Users to migrate : {0}" -f $mappingData.Count) -ForegroundColor Yellow
    Write-Host ("  CTIM entries     : {0}" -f $ctimLines.Count) -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""

    $confirm1 = Read-Host "Type YES (uppercase) to proceed"
    if ($confirm1 -ne "YES") {
        Write-EIDMTag -Tag "ABORT" -Text "Aborted by operator." -Color Yellow
        return $script:EIDMStatus_Failed
    }

    # ----------------------------------------------------------------
    # 4) Upload CTIM identity map to TARGET
    # ----------------------------------------------------------------
    Write-EIDMSection "Upload CTIM Identity Map to TARGET"

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    try {
        Write-EIDMTag -Tag "INFO" -Text ("Uploading CTIM file: {0}" -f $ctimFile.FullName) -Color Gray
        Add-SPOTenantIdentityMap -IdentityMapPath $ctimFile.FullName -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "CTIM identity map uploaded to TARGET successfully." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to upload CTIM: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 5) Get TARGET CrossTenantHostUrl (needed for Source-side commands)
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve TARGET CrossTenantHostUrl"

    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $targetHostUrl = $null
    try {
        $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET"
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to get TARGET CrossTenantHostUrl: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    if (-not $targetHostUrl) {
        Write-EIDMTag -Tag "ERROR" -Text "TARGET CrossTenantHostUrl is empty." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("TARGET CrossTenantHostUrl: {0}" -f $targetHostUrl) -Color Gray

    # ----------------------------------------------------------------
    # 6) Start moves from SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Start OneDrive Moves (SOURCE)"

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    $results = @()
    $iUser   = 0
    $total   = $mappingData.Count

    foreach ($user in $mappingData) {
        $iUser++
        $srcUpn = $user.SourceUPN
        $tgtUpn = $user.TargetUPN

        Write-Host ("[{0}/{1}] {2} -> {3}" -f $iUser, $total, $srcUpn, $tgtUpn) -ForegroundColor Gray

        $moveStatus = "OK"
        $moveError  = ""

        try {
            Start-SPOCrossTenantUserContentMove `
                -SourceUserPrincipalName $srcUpn `
                -TargetUserPrincipalName $tgtUpn `
                -TargetCrossTenantHostUrl $targetHostUrl `
                -ErrorAction Stop

            Write-EIDMTag -Tag "OK" -Text ("Move started: {0}" -f $srcUpn) -Color Green
        }
        catch {
            $moveStatus = "FAILED"
            $moveError  = $_.Exception.Message
            Write-EIDMTag -Tag "ERROR" -Text ("Move failed: {0} - {1}" -f $srcUpn, $moveError) -Color Red
        }

        $results += [PSCustomObject]@{
            SourceUPN = $srcUpn
            TargetUPN = $tgtUpn
            Status    = $moveStatus
            Error     = $moveError
            StartedOn = (Get-Date).ToString("s")
        }
    }

    Disconnect-EIDMSharePointIfNeeded

    # ----------------------------------------------------------------
    # 7) Export results
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Results"

    $stamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $execFolder ("OneDrive_StartResults_{0}.csv" -f $stamp)

    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $okCnt   = @($results | Where-Object { $_.Status -eq "OK" }).Count
    $failCnt = @($results | Where-Object { $_.Status -eq "FAILED" }).Count

    Write-EIDMTag -Tag "OK" -Text ("Results exported: {0}" -f $csvPath) -Color Green
    Write-Host ""
    Write-Host ("  Total  : {0}" -f $results.Count) -ForegroundColor Gray
    Write-Host ("  OK     : {0}" -f $okCnt) -ForegroundColor Green
    Write-Host ("  FAILED : {0}" -f $failCnt) -ForegroundColor $(if ($failCnt -gt 0) { "Red" } else { "Gray" })

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 06-02 - Check Migration Status
# ==========================================================================

function Step-06-02-CheckMigrationStatus {
    <#
    .SYNOPSIS  Check OneDrive cross-tenant migration status from both tenants.
    .DESCRIPTION
        1) Connect to SOURCE SPO, retrieve move states.
        2) Connect to TARGET SPO, retrieve move states.
        3) Display combined summary.
        4) Export status CSVs.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Check OneDrive Migration Status"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Check migration status from SOURCE tenant" -ForegroundColor Gray
    Write-Host "    - Check migration status from TARGET tenant" -ForegroundColor Gray
    Write-Host "    - Export status CSVs" -ForegroundColor Gray
    Write-Host ""

    $execFolder = Join-Path $Ctx.RunRoot "06-OneDriveMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Determine CrossTenantHostUrls
    # ----------------------------------------------------------------

    # TARGET CrossTenantHostUrl (needed for SOURCE-side query)
    Write-EIDMSection "Retrieve CrossTenantHostUrls"

    Disconnect-EIDMSharePointIfNeeded

    # Get TARGET host URL
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
    $targetHostUrl = $null
    try {
        $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET"
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not get TARGET CrossTenantHostUrl: {0}" -f $_.Exception.Message) -Color Yellow
    }
    Disconnect-EIDMSharePointIfNeeded

    # Get SOURCE host URL
    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
    $sourceHostUrl = $null
    try {
        $sourceHostUrl = Get-EIDMCrossTenantHostUrl -Label "SOURCE"
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not get SOURCE CrossTenantHostUrl: {0}" -f $_.Exception.Message) -Color Yellow
    }
    Disconnect-EIDMSharePointIfNeeded

    Write-Host ("  SOURCE HostUrl: {0}" -f $(if ($sourceHostUrl) { $sourceHostUrl } else { "(not available)" })) -ForegroundColor Gray
    Write-Host ("  TARGET HostUrl: {0}" -f $(if ($targetHostUrl) { $targetHostUrl } else { "(not available)" })) -ForegroundColor Gray
    Write-Host ""

    $sourceResults = @()
    $targetResults = @()

    # ----------------------------------------------------------------
    # 2) Check from SOURCE
    # ----------------------------------------------------------------
    if ($targetHostUrl) {
        Write-EIDMSection "Migration Status from SOURCE"

        Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

        try {
            $rawSource = @(Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop)
            Write-EIDMTag -Tag "INFO" -Text ("SOURCE returned {0} move state(s)" -f $rawSource.Count) -Color Gray

            foreach ($s in $rawSource) {
                $safe = $s | Select-Object MoveId, SourceUserPrincipalName, TargetUserPrincipalName, MoveState, MoveDirection, StatusCode, Result
                $sourceResults += [PSCustomObject]@{
                    MoveId       = $safe.MoveId
                    SourceUPN    = $safe.SourceUserPrincipalName
                    TargetUPN    = $safe.TargetUserPrincipalName
                    MoveState    = $safe.MoveState
                    MoveDirection = $safe.MoveDirection
                    StatusCode   = $safe.StatusCode
                    Result       = $safe.Result
                    QuerySide    = "SOURCE"
                    QueryTime    = (Get-Date).ToString("s")
                }
            }
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Check from SOURCE failed: {0}" -f $_.Exception.Message) -Color Red
        }
        finally {
            Disconnect-EIDMSharePointIfNeeded
        }
    }
    else {
        Write-EIDMTag -Tag "SKIP" -Text "Skipping SOURCE status check (no TARGET HostUrl)." -Color Yellow
    }

    # ----------------------------------------------------------------
    # 3) Check from TARGET
    # ----------------------------------------------------------------
    if ($sourceHostUrl) {
        Write-EIDMSection "Migration Status from TARGET"

        Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

        try {
            $rawTarget = @(Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop)
            Write-EIDMTag -Tag "INFO" -Text ("TARGET returned {0} move state(s)" -f $rawTarget.Count) -Color Gray

            foreach ($t in $rawTarget) {
                $safe = $t | Select-Object MoveId, SourceUserPrincipalName, TargetUserPrincipalName, MoveState, MoveDirection, StatusCode, Result
                $targetResults += [PSCustomObject]@{
                    MoveId       = $safe.MoveId
                    SourceUPN    = $safe.SourceUserPrincipalName
                    TargetUPN    = $safe.TargetUserPrincipalName
                    MoveState    = $safe.MoveState
                    MoveDirection = $safe.MoveDirection
                    StatusCode   = $safe.StatusCode
                    Result       = $safe.Result
                    QuerySide    = "TARGET"
                    QueryTime    = (Get-Date).ToString("s")
                }
            }
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Check from TARGET failed: {0}" -f $_.Exception.Message) -Color Red
        }
        finally {
            Disconnect-EIDMSharePointIfNeeded
        }
    }
    else {
        Write-EIDMTag -Tag "SKIP" -Text "Skipping TARGET status check (no SOURCE HostUrl)." -Color Yellow
    }

    # ----------------------------------------------------------------
    # 4) Display summary
    # ----------------------------------------------------------------
    Write-EIDMSection "Migration Status Summary"

    if ($sourceResults.Count -gt 0) {
        Write-Host "`n  -- SOURCE perspective --" -ForegroundColor Cyan
        $sourceResults | ForEach-Object {
            $color = switch ($_.MoveState) {
                "Completed"  { "Green" }
                "Failed"     { "Red" }
                "InProgress" { "Yellow" }
                default      { "Gray" }
            }
            Write-Host ("    {0} -> {1}   State={2}  Status={3}" -f $_.SourceUPN, $_.TargetUPN, $_.MoveState, $_.StatusCode) -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No move states from SOURCE." -ForegroundColor Gray
    }

    if ($targetResults.Count -gt 0) {
        Write-Host "`n  -- TARGET perspective --" -ForegroundColor Cyan
        $targetResults | ForEach-Object {
            $color = switch ($_.MoveState) {
                "Completed"  { "Green" }
                "Failed"     { "Red" }
                "InProgress" { "Yellow" }
                default      { "Gray" }
            }
            Write-Host ("    {0} -> {1}   State={2}  Status={3}" -f $_.SourceUPN, $_.TargetUPN, $_.MoveState, $_.StatusCode) -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No move states from TARGET." -ForegroundColor Gray
    }

    # ----------------------------------------------------------------
    # 5) Export CSVs
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Status CSVs"

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    if ($sourceResults.Count -gt 0) {
        $srcCsvPath = Join-Path $execFolder ("OneDrive_Status_Source_{0}.csv" -f $stamp)
        $sourceResults | Export-Csv -Path $srcCsvPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("SOURCE status CSV: {0}" -f $srcCsvPath) -Color Green
    }

    if ($targetResults.Count -gt 0) {
        $tgtCsvPath = Join-Path $execFolder ("OneDrive_Status_Target_{0}.csv" -f $stamp)
        $targetResults | Export-Csv -Path $tgtCsvPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("TARGET status CSV: {0}" -f $tgtCsvPath) -Color Green
    }

    if ($sourceResults.Count -eq 0 -and $targetResults.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No move states were returned from either tenant." -Color Yellow
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 06-03 - Reset Cross-Tenant Trust
# ==========================================================================

function Step-06-03-ResetCrossTenantTrust {
    <#
    .SYNOPSIS  Remove cross-tenant MnA trust from both tenants.
    .DESCRIPTION
        1) Safety confirmation.
        2) Remove trust from SOURCE.
        3) Remove trust from TARGET.
        4) Verify removal.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Reset Cross-Tenant Trust (OneDrive MnA)"

    Write-Host ""
    Write-Host "This step will:" -ForegroundColor Gray
    Write-Host "    - Remove cross-tenant MnA trust from SOURCE" -ForegroundColor Gray
    Write-Host "    - Remove cross-tenant MnA trust from TARGET" -ForegroundColor Gray
    Write-Host "    - Verify trust removal on both sides" -ForegroundColor Gray
    Write-Host ""

    Write-Host "WARNING: Only do this after all OneDrive migrations are complete." -ForegroundColor Red
    Write-Host ""

    $confirm = Read-EIDMSimpleYesNo "Remove cross-tenant trust?"
    if (-not $confirm) {
        Write-EIDMTag -Tag "ABORT" -Text "Aborted by operator." -Color Yellow
        return $script:EIDMStatus_Failed
    }

    # ----------------------------------------------------------------
    # 1) Get CrossTenantHostUrls (needed for verification)
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve CrossTenantHostUrls"

    Disconnect-EIDMSharePointIfNeeded

    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
    $targetHostUrl = $null
    try { $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET" } catch { }
    Disconnect-EIDMSharePointIfNeeded

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
    $sourceHostUrl = $null
    try { $sourceHostUrl = Get-EIDMCrossTenantHostUrl -Label "SOURCE" } catch { }
    Disconnect-EIDMSharePointIfNeeded

    # ----------------------------------------------------------------
    # 2) Remove trust from SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Remove Trust from SOURCE"

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    try {
        Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Trust removed from SOURCE." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Remove from SOURCE failed (may already be removed): {0}" -f $_.Exception.Message) -Color Yellow
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 3) Remove trust from TARGET
    # ----------------------------------------------------------------
    Write-EIDMSection "Remove Trust from TARGET"

    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    try {
        Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Trust removed from TARGET." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Remove from TARGET failed (may already be removed): {0}" -f $_.Exception.Message) -Color Yellow
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 4) Verify removal
    # ----------------------------------------------------------------
    Write-EIDMSection "Verify Trust Removal"

    # Verify from SOURCE
    if ($targetHostUrl) {
        Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
        try {
            $srcVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
            $srcText = ($srcVerify | Out-String).Trim()
            Write-EIDMTag -Tag "INFO" -Text ("SOURCE verify after removal: {0}" -f $srcText) -Color Gray

            if ($srcText -match 'NotEstablished') {
                Write-EIDMTag -Tag "OK" -Text "SOURCE trust confirmed removed." -Color Green
            }
            else {
                Write-EIDMTag -Tag "WARN" -Text "SOURCE trust may still be active. Check again later." -Color Yellow
            }
        }
        catch {
            Write-EIDMTag -Tag "INFO" -Text ("SOURCE verify returned error (trust likely removed): {0}" -f $_.Exception.Message) -Color Gray
        }
        finally {
            Disconnect-EIDMSharePointIfNeeded
        }
    }

    # Verify from TARGET
    if ($sourceHostUrl) {
        Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
        try {
            $tgtVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
            $tgtText = ($tgtVerify | Out-String).Trim()
            Write-EIDMTag -Tag "INFO" -Text ("TARGET verify after removal: {0}" -f $tgtText) -Color Gray

            if ($tgtText -match 'NotEstablished') {
                Write-EIDMTag -Tag "OK" -Text "TARGET trust confirmed removed." -Color Green
            }
            else {
                Write-EIDMTag -Tag "WARN" -Text "TARGET trust may still be active. Check again later." -Color Yellow
            }
        }
        catch {
            Write-EIDMTag -Tag "INFO" -Text ("TARGET verify returned error (trust likely removed): {0}" -f $_.Exception.Message) -Color Gray
        }
        finally {
            Disconnect-EIDMSharePointIfNeeded
        }
    }

    Write-EIDMTag -Tag "OK" -Text "Cross-tenant trust reset completed." -Color Green

    return $script:EIDMStatus_Completed
}

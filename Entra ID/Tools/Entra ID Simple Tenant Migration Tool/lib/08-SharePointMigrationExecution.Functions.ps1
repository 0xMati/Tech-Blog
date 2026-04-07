# ==========================================================================
# 08-SharePointMigrationExecution.Functions.ps1
# Phase 08 - SharePoint Site Migration (Execution)
#
# Steps:
#   08-01  Start SharePoint Site Migrations
#   08-02  Check Migration Status
#   08-03  Stop/Cancel Migrations
#   08-04  Cleanup (Remove trust + redirect sites)
#   08-05  Post-Migration: Fix Site Admins
#
# Based on Microsoft docs:
#   https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step6
#   https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step7
# ==========================================================================

function Get-EIDMSharePointMigrationExecutionSteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id         = "08-01-StartSharePointMigrations"
            Phase      = "08-SharePointMigrationExecution"
            Handler    = "Step-08-01-StartSharePointMigrations"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "08-02-CheckMigrationStatus"
            Phase      = "08-SharePointMigrationExecution"
            Handler    = "Step-08-02-CheckMigrationStatus"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "08-03-StopMigrations"
            Phase      = "08-SharePointMigrationExecution"
            Handler    = "Step-08-03-StopMigrations"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "08-04-Cleanup"
            Phase      = "08-SharePointMigrationExecution"
            Handler    = "Step-08-04-Cleanup"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "08-05-FixSiteAdmins"
            Phase      = "08-SharePointMigrationExecution"
            Handler    = "Step-08-05-FixSiteAdmins"
            Requires   = @()
            AllowRerun = $true
        }
    )
}

# ==========================================================================
# STEP 08-01 - Start SharePoint Site Migrations
# ==========================================================================
function Step-08-01-StartSharePointMigrations {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Start SharePoint Site Migrations"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Load the sites mapping CSV from step 07-01" -ForegroundColor DarkGray
    Write-Host "    - Start cross-tenant site moves from SOURCE" -ForegroundColor DarkGray
    Write-Host "    - Use Start-SPOCrossTenantSiteContentMove" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NOTE: Group-connected (M365 Group) sites are NOT supported by this tool." -ForegroundColor Yellow
    Write-Host "  They require manual migration via Start-SPOCrossTenantGroupContentMove." -ForegroundColor DarkGray
    Write-Host "  See: https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step4" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  IMPORTANT: This is a MOVE, not a copy." -ForegroundColor Red
    Write-Host "  Content is moved from SOURCE to TARGET. A redirect is left on SOURCE." -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  PREREQUISITE: 'Cross-Tenant Shared Data Migration' license required." -ForegroundColor Yellow
    Write-Host "  This is a separate paid license (per 100 GB), different from the" -ForegroundColor DarkGray
    Write-Host "  'Cross-Tenant User Data Migration' license used for OneDrive/mailbox moves." -ForegroundColor DarkGray
    Write-Host "  It must be assigned to at least one user on SOURCE or TARGET tenant." -ForegroundColor DarkGray
    Write-Host ""

    $hasLicense = Read-Host "Do you have the 'Cross-Tenant Shared Data Migration' license assigned? (Y/N)"
    if ($hasLicense.Trim().ToUpper() -ne 'Y') {
        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text "Purchase from M365 admin center: Billing > Purchase services" -Color Cyan
        Write-EIDMTag -Tag "INFO" -Text "Search for 'Cross-Tenant Shared Data Migration'" -Color Cyan
        Write-EIDMTag -Tag "INFO" -Text "Assign the license to at least one user on either tenant." -Color Cyan
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text "Migration cannot proceed without this license." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    $execFolder = Join-Path $Ctx.RunRoot "08-SharePointMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Load mapping CSV
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Sites Mapping"

    $planFolder = Join-Path $Ctx.RunRoot "07-SharePointMigrationPlan"
    $mappingCsv = Get-ChildItem -Path $planFolder -Filter "SharePoint_SitesMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $mappingCsv) {
        Write-EIDMTag -Tag "ERROR" -Text "No sites mapping CSV found. Run Phase 07 step 07-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $allSites = @(Import-Csv -Path $mappingCsv.FullName -Encoding UTF8)
    $sitesToMigrate = @($allSites | Where-Object { $_.Migrate.Trim().ToUpper() -eq 'YES' })

    # Exclude group-connected sites (not supported by this tool)
    $groupSites = @($sitesToMigrate | Where-Object { $_.IsGroupConnected -eq 'True' })
    $sitesToMigrate = @($sitesToMigrate | Where-Object { $_.IsGroupConnected -ne 'True' })

    Write-EIDMTag -Tag "INFO" -Text ("Mapping file: {0}" -f $mappingCsv.Name) -Color Gray
    Write-EIDMTag -Tag "INFO" -Text ("Total sites: {0}  |  Marked for migration: {1}" -f $allSites.Count, ($sitesToMigrate.Count + $groupSites.Count)) -Color Cyan

    if ($groupSites.Count -gt 0) {
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text ("{0} group-connected site(s) skipped (not supported by this tool):" -f $groupSites.Count) -Color Yellow
        foreach ($gs in $groupSites) {
            Write-Host ("    [SKIP] {0}" -f $gs.SourceSiteUrl) -ForegroundColor DarkGray
        }
        Write-Host "  Migrate these manually via Start-SPOCrossTenantGroupContentMove." -ForegroundColor DarkGray
    }

    if ($sitesToMigrate.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No standard sites to migrate (group-connected sites excluded)." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # Display sites to migrate
    Write-Host ""
    foreach ($site in $sitesToMigrate) {
        Write-Host ("    [SITE] {0}" -f $site.SourceSiteUrl) -ForegroundColor Gray
        Write-Host ("           -> {0}  ({1} GB)" -f $site.TargetSiteUrl, $site.StorageGB) -ForegroundColor DarkGray
    }
    Write-Host ""

    $confirm = Read-Host ("Start migration for {0} site(s)? (Y/N)" -f $sitesToMigrate.Count)
    if ($confirm.Trim().ToUpper() -ne 'Y') {
        Write-EIDMTag -Tag "INFO" -Text "Migration cancelled by user." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ----------------------------------------------------------------
    # 2) Get target CrossTenantHostUrl
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve Target CrossTenantHostUrl"

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $targetHostUrl = $null
    try {
        $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET"
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to get TARGET HostUrl: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 3) Start migrations from SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Start Site Moves (SOURCE)"

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    $results = @()
    $iSite   = 0
    $total   = $sitesToMigrate.Count

    foreach ($site in $sitesToMigrate) {
        $iSite++
        $srcUrl = $site.SourceSiteUrl
        $tgtUrl = $site.TargetSiteUrl

        Write-Host ("[{0}/{1}] {2}" -f $iSite, $total, $srcUrl) -ForegroundColor Gray

        $moveStatus = "OK"
        $moveError  = ""

        try {
            Start-SPOCrossTenantSiteContentMove `
                -SourceSiteUrl $srcUrl `
                -TargetSiteUrl $tgtUrl `
                -TargetCrossTenantHostUrl $targetHostUrl `
                -ErrorAction Stop

            Write-EIDMTag -Tag "OK" -Text ("Move started: {0}" -f $srcUrl) -Color Green
        }
        catch {
            $moveStatus = "FAILED"
            $moveError  = $_.Exception.Message
            Write-EIDMTag -Tag "ERROR" -Text ("Move failed: {0} - {1}" -f $srcUrl, $moveError) -Color Red
        }

        $results += [PSCustomObject]@{
            SourceSiteUrl    = $srcUrl
            TargetSiteUrl    = $tgtUrl
            Status           = $moveStatus
            Error            = $moveError
            StartedOn        = (Get-Date).ToString("s")
        }
    }

    Disconnect-EIDMSharePointIfNeeded

    # ----------------------------------------------------------------
    # 5) Export results
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Results"

    $stamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $execFolder ("SharePoint_StartResults_{0}.csv" -f $stamp)
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
# STEP 08-02 - Check Migration Status
# ==========================================================================
function Step-08-02-CheckMigrationStatus {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Check SharePoint Migration Status"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Query migration status from SOURCE and TARGET" -ForegroundColor DarkGray
    Write-Host "    - Display per-site status" -ForegroundColor DarkGray
    Write-Host "    - Export status CSVs" -ForegroundColor DarkGray
    Write-Host ""

    $execFolder = Join-Path $Ctx.RunRoot "08-SharePointMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Get CrossTenantHostUrls
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
                $sourceResults += [PSCustomObject]@{
                    MoveJobId     = $s.MoveJobId
                    SourceSiteUrl = $s.SourceSiteUrl
                    TargetSiteUrl = $s.TargetSiteUrl
                    MoveState     = $s.MoveState
                    TimeStamp     = $s.TimeStamp
                    QuerySide     = "SOURCE"
                    QueryTime     = (Get-Date).ToString("s")
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
                $targetResults += [PSCustomObject]@{
                    MoveJobId     = $t.MoveJobId
                    SourceSiteUrl = $t.SourceSiteUrl
                    TargetSiteUrl = $t.TargetSiteUrl
                    MoveState     = $t.MoveState
                    TimeStamp     = $t.TimeStamp
                    QuerySide     = "TARGET"
                    QueryTime     = (Get-Date).ToString("s")
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

    # ----------------------------------------------------------------
    # 4) Display summary
    # ----------------------------------------------------------------
    Write-EIDMSection "Migration Status Summary"

    # Filter to show only SharePoint sites (not OneDrive personal sites)
    $spSourceResults = @($sourceResults | Where-Object { $_.SourceSiteUrl -notmatch '-my\.sharepoint\.com/personal/' })
    $spTargetResults = @($targetResults | Where-Object { $_.SourceSiteUrl -notmatch '-my\.sharepoint\.com/personal/' })

    if ($spSourceResults.Count -gt 0) {
        Write-Host "`n  -- SOURCE perspective (SharePoint sites only) --" -ForegroundColor Cyan
        $spSourceResults | ForEach-Object {
            $color = switch ($_.MoveState) {
                "Success"        { "Green" }
                "Completed"      { "Green" }
                "Failed"         { "Red" }
                "InProgress"     { "Yellow" }
                "Scheduled"      { "Cyan" }
                "ReadytoTrigger" { "Cyan" }
                "NotStarted"     { "Gray" }
                "Rescheduled"    { "Yellow" }
                default          { "Gray" }
            }
            Write-Host ("    {0} -> {1}   State={2}" -f $_.SourceSiteUrl, $_.TargetSiteUrl, $_.MoveState) -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No SharePoint site moves from SOURCE." -ForegroundColor Gray
    }

    if ($spTargetResults.Count -gt 0) {
        Write-Host "`n  -- TARGET perspective (SharePoint sites only) --" -ForegroundColor Cyan
        $spTargetResults | ForEach-Object {
            $color = switch ($_.MoveState) {
                "Success"        { "Green" }
                "Completed"      { "Green" }
                "Failed"         { "Red" }
                "InProgress"     { "Yellow" }
                "Scheduled"      { "Cyan" }
                "ReadytoTrigger" { "Cyan" }
                "NotStarted"     { "Gray" }
                "Rescheduled"    { "Yellow" }
                default          { "Gray" }
            }
            Write-Host ("    {0} -> {1}   State={2}" -f $_.SourceSiteUrl, $_.TargetSiteUrl, $_.MoveState) -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No SharePoint site moves from TARGET." -ForegroundColor Gray
    }

    # State counts
    $allResults = $spSourceResults + $spTargetResults
    if ($allResults.Count -gt 0) {
        $grouped = $allResults | Group-Object MoveState
        Write-Host ""
        Write-Host "  State counts:" -ForegroundColor Gray
        foreach ($g in $grouped) {
            Write-Host ("    {0}: {1}" -f $g.Name, $g.Count) -ForegroundColor Gray
        }
    }

    # ----------------------------------------------------------------
    # 5) Export CSVs
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Status CSVs"

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    if ($sourceResults.Count -gt 0) {
        $srcPath = Join-Path $execFolder ("SharePoint_Status_Source_{0}.csv" -f $stamp)
        $sourceResults | Export-Csv -Path $srcPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("SOURCE status CSV: {0}" -f $srcPath) -Color Green
    }

    if ($targetResults.Count -gt 0) {
        $tgtPath = Join-Path $execFolder ("SharePoint_Status_Target_{0}.csv" -f $stamp)
        $targetResults | Export-Csv -Path $tgtPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("TARGET status CSV: {0}" -f $tgtPath) -Color Green
    }

    if ($sourceResults.Count -eq 0 -and $targetResults.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No move states returned from either tenant." -Color Yellow
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 08-03 - Stop/Cancel Migrations
# ==========================================================================
function Step-08-03-StopMigrations {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Stop/Cancel SharePoint Migrations"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Let you cancel pending or queued site migrations" -ForegroundColor DarkGray
    Write-Host "    - Uses Stop-SPOCrossTenantSiteContentMove" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NOTE: Migrations that are InProgress or Success cannot be cancelled." -ForegroundColor Yellow
    Write-Host ""

    $siteUrl = Read-Host "Enter the SOURCE site URL to cancel (or X to go back)"
    if ([string]::IsNullOrWhiteSpace($siteUrl) -or $siteUrl.Trim().ToUpper() -eq 'X') {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        return $script:EIDMStatus_Completed
    }

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    try {
        Stop-SPOCrossTenantSiteContentMove -SourceSiteUrl $siteUrl.Trim() -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text ("Migration cancelled for: {0}" -f $siteUrl.Trim()) -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Cancel failed: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 08-04 - Cleanup (Post-Migration)
# ==========================================================================
function Step-08-04-Cleanup {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "SharePoint Migration Cleanup"

    Write-Host "This step can:" -ForegroundColor Cyan
    Write-Host "    1) Remove cross-tenant trust (SOURCE and TARGET)" -ForegroundColor DarkGray
    Write-Host "    2) List and remove redirect sites on SOURCE" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  WARNING: Only run this after ALL migrations (OneDrive + SharePoint) are complete!" -ForegroundColor Red
    Write-Host "  Removing the trust will prevent any future cross-tenant moves." -ForegroundColor Red
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) Remove trust
    # ----------------------------------------------------------------
    $removeTrust = Read-Host "Remove cross-tenant trust on both tenants? (Y/N)"
    if ($removeTrust.Trim().ToUpper() -eq 'Y') {
        Write-EIDMSection "Remove Cross-Tenant Trust"

        # Get host URLs
        Disconnect-EIDMSharePointIfNeeded
        Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
        $targetHostUrl = $null
        try { $targetHostUrl = Get-EIDMCrossTenantHostUrl -Label "TARGET" } catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Cannot get TARGET HostUrl: {0}" -f $_.Exception.Message) -Color Red
        }
        Disconnect-EIDMSharePointIfNeeded

        Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
        $sourceHostUrl = $null
        try { $sourceHostUrl = Get-EIDMCrossTenantHostUrl -Label "SOURCE" } catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Cannot get SOURCE HostUrl: {0}" -f $_.Exception.Message) -Color Red
        }
        Disconnect-EIDMSharePointIfNeeded

        if ($targetHostUrl) {
            Write-Host "  Removing trust on SOURCE (PartnerRole=Target)..." -ForegroundColor Yellow
            Ensure-EIDMSharePointSourceConnection -Ctx $Ctx
            try {
                Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text "Trust removed on SOURCE." -Color Green
            }
            catch {
                Write-EIDMTag -Tag "ERROR" -Text ("Remove trust SOURCE failed: {0}" -f $_.Exception.Message) -Color Red
            }
            finally {
                Disconnect-EIDMSharePointIfNeeded
            }
        }

        if ($sourceHostUrl) {
            Write-Host "  Removing trust on TARGET (PartnerRole=Source)..." -ForegroundColor Yellow
            Ensure-EIDMSharePointTargetConnection -Ctx $Ctx
            try {
                Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text "Trust removed on TARGET." -Color Green
            }
            catch {
                Write-EIDMTag -Tag "ERROR" -Text ("Remove trust TARGET failed: {0}" -f $_.Exception.Message) -Color Red
            }
            finally {
                Disconnect-EIDMSharePointIfNeeded
            }
        }
    }

    # ----------------------------------------------------------------
    # 2) Remove redirect sites
    # ----------------------------------------------------------------
    Write-Host ""
    $removeRedirects = Read-Host "List and remove redirect sites on SOURCE? (Y/N)"
    if ($removeRedirects.Trim().ToUpper() -eq 'Y') {
        Write-EIDMSection "Remove Redirect Sites (SOURCE)"

        Disconnect-EIDMSharePointIfNeeded
        Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

        try {
            $redirectSites = @(Get-SPOSite -Template RedirectSite#0 -Limit All -ErrorAction Stop)

            if ($redirectSites.Count -eq 0) {
                Write-EIDMTag -Tag "INFO" -Text "No redirect sites found on SOURCE." -Color Gray
            }
            else {
                Write-EIDMTag -Tag "INFO" -Text ("Found {0} redirect site(s):" -f $redirectSites.Count) -Color Cyan

                foreach ($rs in $redirectSites) {
                    Write-Host ("    {0}" -f $rs.Url) -ForegroundColor Gray
                }

                Write-Host ""
                $confirmRemove = Read-Host ("Remove all {0} redirect site(s)? (Y/N)" -f $redirectSites.Count)
                if ($confirmRemove.Trim().ToUpper() -eq 'Y') {
                    foreach ($rs in $redirectSites) {
                        try {
                            Remove-SPOSite -Identity $rs.Url -NoWait -Confirm:$false -ErrorAction Stop
                            Write-EIDMTag -Tag "OK" -Text ("Removed: {0}" -f $rs.Url) -Color Green
                        }
                        catch {
                            Write-EIDMTag -Tag "ERROR" -Text ("Failed to remove {0}: {1}" -f $rs.Url, $_.Exception.Message) -Color Red
                        }
                    }
                }
            }
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Failed to list redirect sites: {0}" -f $_.Exception.Message) -Color Red
        }
        finally {
            Disconnect-EIDMSharePointIfNeeded
        }
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 08-05 - Post-Migration: Fix Site Collection Admins
# ==========================================================================
function Step-08-05-FixSiteAdmins {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Post-Migration: Fix Site Collection Admins"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Add a TARGET admin as Site Collection Admin on migrated sites" -ForegroundColor DarkGray
    Write-Host "    - Uses Set-SPOUser -IsSiteCollectionAdmin on each site" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  After migration, the SOURCE admin remains as Site Collection Admin." -ForegroundColor Yellow
    Write-Host "  Use this step to grant a TARGET admin full control." -ForegroundColor Yellow
    Write-Host ""

    # Load mapping CSV to get migrated sites
    $planFolder = Join-Path $Ctx.RunRoot "07-SharePointMigrationPlan"
    $mappingCsv = Get-ChildItem -Path $planFolder -Filter "SharePoint_SitesMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if (-not $mappingCsv) {
        Write-EIDMTag -Tag "ERROR" -Text "No sites mapping CSV found. Run Phase 07 step 07-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $allSites = @(Import-Csv -Path $mappingCsv.FullName -Encoding UTF8)
    $migratedSites = @($allSites | Where-Object { $_.Migrate.Trim().ToUpper() -eq 'YES' -and $_.IsGroupConnected -ne 'True' })

    if ($migratedSites.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No migrated sites found." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("{0} site(s) to fix:" -f $migratedSites.Count) -Color Cyan
    foreach ($s in $migratedSites) {
        Write-Host ("    {0}" -f $s.TargetSiteUrl) -ForegroundColor Gray
    }
    Write-Host ""

    $adminUpn = Read-Host "Enter the TARGET admin UPN to add as Site Collection Admin"
    if ([string]::IsNullOrWhiteSpace($adminUpn)) {
        Write-EIDMTag -Tag "ERROR" -Text "No UPN provided." -Color Red
        return $script:EIDMStatus_Failed
    }
    $adminUpn = $adminUpn.Trim()

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $execFolder = Join-Path $Ctx.RunRoot "08-SharePointMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    $results = @()

    foreach ($site in $migratedSites) {
        $tgtUrl = $site.TargetSiteUrl
        $status = "OK"
        $err    = ""

        try {
            Set-SPOUser -Site $tgtUrl -LoginName $adminUpn -IsSiteCollectionAdmin $true -ErrorAction Stop
            Write-EIDMTag -Tag "OK" -Text ("Admin added: {0}" -f $tgtUrl) -Color Green
        }
        catch {
            $status = "FAILED"
            $err    = $_.Exception.Message
            Write-EIDMTag -Tag "ERROR" -Text ("Failed: {0} - {1}" -f $tgtUrl, $err) -Color Red
        }

        $results += [PSCustomObject]@{
            TargetSiteUrl = $tgtUrl
            AdminUPN      = $adminUpn
            Status        = $status
            Error         = $err
        }
    }

    Disconnect-EIDMSharePointIfNeeded

    # Export results
    $stamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $execFolder ("SharePoint_FixAdmins_{0}.csv" -f $stamp)
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

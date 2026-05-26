# ==========================================================================
# 07-SharePointMigrationPlan.Functions.ps1
# Phase 07 - SharePoint Site Migration (Planning)
#
# Steps:
#   07-01  Discover & Build Sites Mapping
#   07-02  Verify Cross-Tenant Trust
#   07-03  Build & Upload Identity Map
#   07-04  Verify Cross-Tenant Compatibility
#
# Based on Microsoft docs:
#   https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration
# ==========================================================================

function Get-EIDMSharePointMigrationPlanSteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id         = "07-01-DiscoverAndBuildSitesMapping"
            Phase      = "07-SharePointMigrationPlan"
            Handler    = "Step-07-01-DiscoverAndBuildSitesMapping"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "07-02-VerifyCrossTenantTrust"
            Phase      = "07-SharePointMigrationPlan"
            Handler    = "Step-07-02-VerifyCrossTenantTrust"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "07-03-BuildAndUploadIdentityMap"
            Phase      = "07-SharePointMigrationPlan"
            Handler    = "Step-07-03-BuildAndUploadIdentityMap"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "07-04-VerifyCompatibility"
            Phase      = "07-SharePointMigrationPlan"
            Handler    = "Step-07-04-VerifyCompatibility"
            Requires   = @()
            AllowRerun = $true
        }
    )
}

# ==========================================================================
# STEP 07-01 - Discover & Build Sites Mapping
# ==========================================================================
function Step-07-01-DiscoverAndBuildSitesMapping {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Discover SharePoint Sites & Build Migration Mapping"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Connect to SOURCE SharePoint Online Admin" -ForegroundColor DarkGray
    Write-Host "    - List all SharePoint sites (excluding OneDrive personal sites)" -ForegroundColor DarkGray
    Write-Host "    - Export a mapping CSV for review" -ForegroundColor DarkGray
    Write-Host "    - Open the CSV so you can mark sites to migrate" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  PREREQUISITE: Cross-Tenant Shared Data Migration license" -ForegroundColor Yellow
    Write-Host "  Unlike OneDrive migration, SharePoint site migration requires a separate" -ForegroundColor DarkGray
    Write-Host "  paid license: 'Cross-Tenant Shared Data Migration' (per 100 GB of data)." -ForegroundColor DarkGray
    Write-Host "  This is different from the 'Cross-Tenant User Data Migration' license" -ForegroundColor DarkGray
    Write-Host "  used for OneDrive/mailbox moves." -ForegroundColor DarkGray
    Write-Host "  More info: https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  NOTE: Group-connected (M365 Group) SharePoint sites are NOT supported" -ForegroundColor Yellow
    Write-Host "  by this tool. They will be marked Migrate=NO in the CSV." -ForegroundColor Yellow
    Write-Host "  For group-connected sites, use manual migration:" -ForegroundColor DarkGray
    Write-Host "  https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step4" -ForegroundColor DarkGray
    Write-Host ""

    $planFolder = Join-Path $Ctx.RunRoot "07-SharePointMigrationPlan"
    Assert-EIDMDirectory -Path $planFolder

    # Check for existing mapping
    $existingCsv = Get-ChildItem -Path $planFolder -Filter "SharePoint_SitesMapping_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($existingCsv) {
        Write-EIDMTag -Tag "INFO" -Text ("Existing mapping found: {0}" -f $existingCsv.Name) -Color Gray
        $reuse = Read-Host "Use existing mapping? (Y to reuse, N to rediscover)"
        if ($reuse.Trim().ToUpper() -eq 'Y') {
            Write-EIDMTag -Tag "OK" -Text ("Using: {0}" -f $existingCsv.FullName) -Color Green
            return $script:EIDMStatus_Completed
        }
    }

    # ----------------------------------------------------------------
    # 1) Connect to SOURCE SPO Admin
    # ----------------------------------------------------------------
    Write-EIDMSection "Connect to SOURCE SharePoint Admin"

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    # ----------------------------------------------------------------
    # 2) Enumerate all SharePoint sites (exclude OneDrive)
    # ----------------------------------------------------------------
    Write-EIDMSection "Enumerate SharePoint Sites (SOURCE)"

    Write-Host "  Retrieving all sites... (this may take a moment)" -ForegroundColor DarkGray

    $allSites = @()
    try {
        $allSites = @(Get-SPOSite -Limit All -ErrorAction Stop |
            Where-Object {
                # Exclude OneDrive personal sites and admin/search/app sites
                $_.Url -notmatch '-my\.sharepoint\.com/personal/' -and
                $_.Template -ne 'SPSMSITEHOST#0' -and
                $_.Template -ne 'SRCHCEN#0' -and
                $_.Template -ne 'APPCATALOG#0' -and
                $_.Template -ne 'RedirectSite#0'
            })
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to enumerate sites: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    Disconnect-EIDMSharePointIfNeeded

    Write-EIDMTag -Tag "INFO" -Text ("Found {0} SharePoint site(s) (excluding OneDrive, search, app catalog)" -f $allSites.Count) -Color Cyan

    if ($allSites.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No SharePoint sites found on SOURCE." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ----------------------------------------------------------------
    # 3) Display sites
    # ----------------------------------------------------------------
    Write-EIDMSection "SharePoint Sites Found"

    $idx = 0
    foreach ($site in $allSites) {
        $idx++
        $sizeGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)
        Write-Host ("  [{0,3}] {1}" -f $idx, $site.Url) -ForegroundColor Gray
        Write-Host ("        Template={0}  Storage={1} GB  Owner={2}" -f $site.Template, $sizeGB, $site.Owner) -ForegroundColor DarkGray
    }
    Write-Host ""

    # ----------------------------------------------------------------
    # 4) Build mapping CSV
    # ----------------------------------------------------------------
    Write-EIDMSection "Build Sites Mapping CSV"

    $srcTenant = $Ctx.Config.Tenants.Source.TenantIdOrDomain
    $tgtTenant = $Ctx.Config.Tenants.Target.TenantIdOrDomain

    # Derive tenant short names for URL construction
    $srcName = $srcTenant
    if ($srcName -match '^([^\.]+)\.onmicrosoft\.com$') { $srcName = $Matches[1] }
    $tgtName = $tgtTenant
    if ($tgtName -match '^([^\.]+)\.onmicrosoft\.com$') { $tgtName = $Matches[1] }

    $mappingData = @()
    foreach ($site in $allSites) {
        # Auto-generate target URL by replacing tenant name in the URL
        $suggestedTargetUrl = $site.Url -replace [regex]::Escape("$srcName.sharepoint.com"), "$tgtName.sharepoint.com"

        $isGroupConnected = ($site.Template -match 'GROUP#0' -or $site.GroupId -ne [Guid]::Empty)

        $sizeGB = [math]::Round($site.StorageUsageCurrent / 1024, 2)

        $mappingData += [PSCustomObject]@{
            Migrate          = if ($isGroupConnected) { "NO" } else { "YES" }
            SourceSiteUrl    = $site.Url
            TargetSiteUrl    = $suggestedTargetUrl
            Template         = $site.Template
            IsGroupConnected = $isGroupConnected
            GroupId          = if ($site.GroupId -ne [Guid]::Empty) { $site.GroupId } else { "" }
            StorageGB        = $sizeGB
            StorageBytes     = $site.StorageUsageCurrent * 1024 * 1024
            Owner            = $site.Owner
            Status           = ""
            Notes            = if ($isGroupConnected) { "Group-connected site - not supported by this tool (manual migration required)" } else { "" }
        }
    }

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $planFolder ("SharePoint_SitesMapping_{0}.csv" -f $stamp)
    $mappingData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Mapping CSV exported: {0}" -f $csvPath) -Color Green
    Write-Host ""
    Write-Host ("  Total sites: {0}" -f $allSites.Count) -ForegroundColor Gray

    $totalStorageGB = ($mappingData | Measure-Object -Property StorageGB -Sum).Sum
    Write-Host ("  Total storage: {0:N2} GB" -f $totalStorageGB) -ForegroundColor Gray
    Write-Host ""

    # ----------------------------------------------------------------
    # 5) Open CSV for review
    # ----------------------------------------------------------------
    Write-EIDMSection "Review Mapping"

    Write-Host "  The CSV has been generated with standard sites set to Migrate=YES." -ForegroundColor Yellow
    Write-Host "  Group-connected sites are set to Migrate=NO (not supported by this tool)." -ForegroundColor Yellow
    Write-Host "  Please review and edit the CSV:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "    - Set Migrate=NO for sites you do NOT want to migrate" -ForegroundColor DarkGray
    Write-Host "    - Adjust TargetSiteUrl if the auto-generated URL is wrong" -ForegroundColor DarkGray
    Write-Host "    - Group-connected sites require manual migration" -ForegroundColor DarkGray
    Write-Host "      (see https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step4)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  IMPORTANT (from Microsoft docs):" -ForegroundColor Red
    Write-Host "    - Do NOT create target SharePoint sites before migration!" -ForegroundColor Red
    Write-Host "    - The migration creates the target site automatically." -ForegroundColor Red
    Write-Host "    - Each site must be < 5 TB and < 1 million items." -ForegroundColor Red
    Write-Host ""

    $openCsv = Read-Host "Open the CSV now for editing? (Y/N)"
    if ($openCsv.Trim().ToUpper() -eq 'Y') {
        try {
            Start-Process $csvPath
            Write-Host ""
            Write-Host "  CSV opened. Edit it, save, and close before continuing." -ForegroundColor Yellow
            Read-Host "  Press Enter when done editing"
        }
        catch {
            Write-EIDMTag -Tag "WARN" -Text ("Could not open CSV: {0}" -f $_.Exception.Message) -Color Yellow
            Write-Host "  Please open manually: $csvPath" -ForegroundColor Yellow
            Read-Host "  Press Enter when done editing"
        }
    }

    # Re-read and validate
    $finalMapping = @(Import-Csv -Path $csvPath -Encoding UTF8)
    $migrateCount = @($finalMapping | Where-Object { $_.Migrate.Trim().ToUpper() -eq 'YES' }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Sites marked for migration: {0} / {1}" -f $migrateCount, $finalMapping.Count) -Color Cyan

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 07-02 - Verify Cross-Tenant Trust
# ==========================================================================
function Step-07-02-VerifyCrossTenantTrust {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Verify Cross-Tenant Trust (SharePoint)"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Verify the MnA cross-tenant trust on SOURCE and TARGET" -ForegroundColor DarkGray
    Write-Host "    - The trust is shared with OneDrive (Phase 05)" -ForegroundColor DarkGray
    Write-Host "    - If not set up, run Phase 05 step 05-02 first" -ForegroundColor DarkGray
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) Get CrossTenantHostUrls
    # ----------------------------------------------------------------
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

    # ----------------------------------------------------------------
    # 2) Verify trust from SOURCE
    # ----------------------------------------------------------------
    Write-EIDMSection "Verify Trust"

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    $srcOk = $false
    try {
        $srcVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl -ErrorAction Stop
        $srcText = ($srcVerify | Out-String).Trim()
        Write-EIDMTag -Tag "INFO" -Text ("SOURCE verify: {0}" -f $srcText) -Color Gray
        $srcOk = ($srcText -match 'GoodToProceed')
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Verify failed on SOURCE: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # Verify from TARGET
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    $tgtOk = $false
    try {
        $tgtVerify = Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl -ErrorAction Stop
        $tgtText = ($tgtVerify | Out-String).Trim()
        Write-EIDMTag -Tag "INFO" -Text ("TARGET verify: {0}" -f $tgtText) -Color Gray
        $tgtOk = ($tgtText -match 'GoodToProceed')
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Verify failed on TARGET: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    # ----------------------------------------------------------------
    # 3) Summary
    # ----------------------------------------------------------------
    Write-EIDMSection "Trust Summary"

    if ($srcOk -and $tgtOk) {
        Write-EIDMTag -Tag "OK" -Text "Cross-tenant trust is GoodToProceed on both sides." -Color Green
    }
    else {
        Write-Host ("  SOURCE GoodToProceed: {0}" -f $srcOk) -ForegroundColor $(if ($srcOk) { "Green" } else { "Red" })
        Write-Host ("  TARGET GoodToProceed: {0}" -f $tgtOk) -ForegroundColor $(if ($tgtOk) { "Green" } else { "Red" })
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text "Trust is not GoodToProceed. Run Phase 05 step 05-02 to establish trust first." -Color Yellow
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 07-03 - Build & Upload Identity Map
# ==========================================================================
function Step-07-03-BuildAndUploadIdentityMap {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Build & Upload Identity Map (SharePoint)"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Build an identity mapping CSV (users + groups)" -ForegroundColor DarkGray
    Write-Host "    - Upload it to TARGET via Add-SPOTenantIdentityMap" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  The identity map ensures permissions are preserved after migration." -ForegroundColor Yellow
    Write-Host "  Format: User,SourceTenantId,SourceUPN,TargetUPN,TargetEmail,UserType" -ForegroundColor DarkGray
    Write-Host "  Format: Group,SourceTenantId,SourceGroupObjId,TargetGroupObjId,GroupName,GroupType" -ForegroundColor DarkGray
    Write-Host ""

    $planFolder = Join-Path $Ctx.RunRoot "07-SharePointMigrationPlan"
    Assert-EIDMDirectory -Path $planFolder

    # ----------------------------------------------------------------
    # 1) Check for existing OneDrive CTIM (reuse user mappings)
    # ----------------------------------------------------------------
    $odPlanFolder = Join-Path $Ctx.RunRoot "05-OneDriveMigrationPlan"
    $existingCtim = $null
    if (Test-Path $odPlanFolder) {
        $existingCtim = Get-ChildItem -Path $odPlanFolder -Filter "OneDrive_CTIM_*.csv" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    }

    # Check for existing SP identity map
    $skipBuild = $false
    $existingSpMap = Get-ChildItem -Path $planFolder -Filter "SharePoint_IdentityMap_*.csv" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1

    if ($existingSpMap) {
        Write-EIDMTag -Tag "INFO" -Text ("Existing identity map found: {0}" -f $existingSpMap.Name) -Color Gray
        $reuse = Read-Host "Reuse existing map? (Y to reuse and re-upload, N to rebuild)"
        if ($reuse.Trim().ToUpper() -eq 'Y') {
            $mapPath = $existingSpMap.FullName
            # Skip to upload
            $mapData = @(Import-Csv -Path $mapPath -Encoding UTF8 -Header C1,C2,C3,C4,C5,C6)

            Write-EIDMTag -Tag "INFO" -Text ("Identity map entries: {0}" -f $mapData.Count) -Color Cyan
            # Jump to upload section below
            $skipBuild = $true
        }
    }

    if (-not $skipBuild) {
        # ----------------------------------------------------------------
        # 2) Source tenant ID
        # ----------------------------------------------------------------
        Write-EIDMSection "Source Tenant ID"

        $srcTenantId = Read-Host "Enter SOURCE tenant ID (GUID)"
        if ([string]::IsNullOrWhiteSpace($srcTenantId)) {
            Write-EIDMTag -Tag "ERROR" -Text "Tenant ID is required." -Color Red
            return $script:EIDMStatus_Failed
        }
        $srcTenantId = $srcTenantId.Trim()

        # ----------------------------------------------------------------
        # 3) Build user lines from OneDrive CTIM or users mapping
        # ----------------------------------------------------------------
        Write-EIDMSection "Build User Mappings"

        $mapLines = @()

        if ($existingCtim) {
            Write-EIDMTag -Tag "INFO" -Text ("Reusing user mappings from OneDrive CTIM: {0}" -f $existingCtim.Name) -Color Gray
            $ctimData = @(Import-Csv -Path $existingCtim.FullName -Encoding UTF8 -Header C1,C2,C3,C4,C5,C6)
            $mapLines += $ctimData
            Write-EIDMTag -Tag "INFO" -Text ("User entries from CTIM: {0}" -f $ctimData.Count) -Color Cyan
        }
        else {
            Write-Host "  No OneDrive CTIM found. Building user map from Discovery data..." -ForegroundColor Yellow

            # Try to use discovery users CSV
            $discFolder = Join-Path $Ctx.RunRoot "01-Discovery"
            $usersCsv = Get-ChildItem -Path $discFolder -Filter "EntraUsers_*.csv" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1

            if ($usersCsv) {
                $users = @(Import-Csv -Path $usersCsv.FullName -Encoding UTF8)
                Write-EIDMTag -Tag "INFO" -Text ("Users from Discovery: {0}" -f $users.Count) -Color Gray

                foreach ($u in $users) {
                    $srcUpn = $u.UserPrincipalName
                    if ([string]::IsNullOrWhiteSpace($srcUpn)) { continue }

                    # Derive target UPN from config domains
                    $tgtUpn = $srcUpn
                    $srcDomains = $Ctx.Config.Tenants.Source.Domains
                    $tgtDomains = $Ctx.Config.Tenants.Target.Domains
                    if ($srcDomains -and $tgtDomains) {
                        foreach ($i in 0..([Math]::Min($srcDomains.Count, $tgtDomains.Count) - 1)) {
                            if ($srcUpn -match ("@{0}$" -f [regex]::Escape($srcDomains[$i]))) {
                                $tgtUpn = $srcUpn -replace [regex]::Escape($srcDomains[$i]), $tgtDomains[$i]
                                break
                            }
                        }
                    }

                    $mapLines += [PSCustomObject]@{
                        C1 = "User"
                        C2 = $srcTenantId
                        C3 = $srcUpn
                        C4 = $tgtUpn
                        C5 = $tgtUpn
                        C6 = "RegularUser"
                    }
                }
                Write-EIDMTag -Tag "INFO" -Text ("User map lines built: {0}" -f $mapLines.Count) -Color Cyan
            }
            else {
                Write-EIDMTag -Tag "WARN" -Text "No user data found. Run Discovery (Phase 01) first, or build the identity map manually." -Color Yellow
            }
        }

        # ----------------------------------------------------------------
        # 4) Group mappings — Security Groups only (no M365 Group site migration)
        # ----------------------------------------------------------------
        Write-EIDMSection "Group Mappings (Security Groups)"

        Write-Host "  Group mappings map SOURCE group ObjectIds to TARGET group ObjectIds" -ForegroundColor DarkGray
        Write-Host "  so that group-based permissions are preserved after migration." -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  NOTE: M365 Group-connected SharePoint sites are NOT supported by this tool." -ForegroundColor Yellow
        Write-Host "  They require specific manual steps (see Microsoft docs Step 4)." -ForegroundColor DarkGray
        Write-Host "  https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step4" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  The tool can auto-discover Security Groups on both tenants via Microsoft Graph" -ForegroundColor DarkGray
        Write-Host "  and match them by DisplayName." -ForegroundColor DarkGray
        Write-Host ""

        $addGroups = Read-Host "Add group mappings now? (Y/N)"
        if ($addGroups.Trim().ToUpper() -eq 'Y') {

            Write-Host ""
            Write-Host "  [A] Auto-discover groups via Graph (recommended)" -ForegroundColor Green
            Write-Host "  [M] Manual entry (SourceObjId,TargetObjId,GroupName)" -ForegroundColor Yellow
            Write-Host ""
            $groupMode = Read-Host "  Choose mode [A/M]"

            if ($groupMode.Trim().ToUpper() -eq 'A') {
                # --- Auto-discover via Graph ---
                Write-EIDMSection "Auto-Discover Groups via Graph"

                Write-Host "  Connecting to SOURCE Graph to list groups..." -ForegroundColor DarkGray
                Ensure-EIDMGraphSourceConnection -Ctx $Ctx
                $srcGroups = @(Get-MgGroup -All -Property Id,DisplayName,GroupTypes,SecurityEnabled,MailEnabled,Mail |
                    Select-Object Id, DisplayName, GroupTypes, SecurityEnabled, MailEnabled, Mail)
                Write-EIDMTag -Tag "INFO" -Text ("SOURCE groups found: {0}" -f $srcGroups.Count) -Color Cyan

                Write-Host "  Connecting to TARGET Graph to list groups..." -ForegroundColor DarkGray
                Ensure-EIDMGraphTargetConnection -Ctx $Ctx
                $tgtGroups = @(Get-MgGroup -All -Property Id,DisplayName,GroupTypes,SecurityEnabled,MailEnabled,Mail |
                    Select-Object Id, DisplayName, GroupTypes, SecurityEnabled, MailEnabled, Mail)
                Write-EIDMTag -Tag "INFO" -Text ("TARGET groups found: {0}" -f $tgtGroups.Count) -Color Cyan

                # Build lookup by DisplayName
                $tgtLookup = @{}
                foreach ($tg in $tgtGroups) {
                    if (-not [string]::IsNullOrWhiteSpace($tg.DisplayName)) {
                        $tgtLookup[$tg.DisplayName] = $tg
                    }
                }

                # Match by DisplayName
                $matched   = @()
                $unmatched = @()

                foreach ($sg in $srcGroups) {
                    if ([string]::IsNullOrWhiteSpace($sg.DisplayName)) { continue }

                    $groupType = if ($sg.GroupTypes -contains 'Unified') { 'M365Group' }
                                 elseif ($sg.SecurityEnabled) { 'SecurityGroup' }
                                 elseif ($sg.MailEnabled)     { 'MailGroup' }
                                 else                         { 'Group' }

                    if ($tgtLookup.ContainsKey($sg.DisplayName)) {
                        $tg = $tgtLookup[$sg.DisplayName]
                        $matched += [PSCustomObject]@{
                            DisplayName   = $sg.DisplayName
                            SourceId      = $sg.Id
                            TargetId      = $tg.Id
                            GroupType     = $groupType
                        }
                    }
                    else {
                        $unmatched += [PSCustomObject]@{
                            DisplayName = $sg.DisplayName
                            SourceId    = $sg.Id
                            GroupType   = $groupType
                        }
                    }
                }

                Write-Host ""
                Write-EIDMTag -Tag "INFO" -Text ("Matched: {0}  |  Unmatched: {1}" -f $matched.Count, $unmatched.Count) -Color Cyan

                if ($matched.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  Matched groups:" -ForegroundColor Green
                    $i = 0
                    foreach ($m in $matched) {
                        $i++
                        Write-Host ("    [{0,3}] {1}" -f $i, $m.DisplayName) -ForegroundColor Gray
                        Write-Host ("          SRC={0}  TGT={1}  Type={2}" -f $m.SourceId, $m.TargetId, $m.GroupType) -ForegroundColor DarkGray
                    }
                }

                if ($unmatched.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  Unmatched SOURCE groups (no same-name group on TARGET):" -ForegroundColor Yellow
                    foreach ($u in $unmatched) {
                        Write-Host ("    - {0}  (SRC={1}, Type={2})" -f $u.DisplayName, $u.SourceId, $u.GroupType) -ForegroundColor DarkGray
                    }
                }

                Write-Host ""
                $confirmGroups = Read-Host ("Add {0} matched group(s) to the identity map? (Y/N)" -f $matched.Count)
                if ($confirmGroups.Trim().ToUpper() -eq 'Y') {
                    foreach ($m in $matched) {
                        $mapLines += [PSCustomObject]@{
                            C1 = "Group"
                            C2 = $srcTenantId
                            C3 = $m.SourceId
                            C4 = $m.TargetId
                            C5 = $m.DisplayName
                            C6 = $m.GroupType
                        }
                    }
                    Write-EIDMTag -Tag "OK" -Text ("{0} group mapping(s) added." -f $matched.Count) -Color Green
                }
            }
            else {
                # --- Manual mode (fallback) ---
                Write-Host ""
                Write-Host "  Enter group mappings one per line: SourceGroupObjectId,TargetGroupObjectId,GroupName" -ForegroundColor DarkGray
                Write-Host "  Type 'done' when finished." -ForegroundColor DarkGray
                Write-Host ""

                while ($true) {
                    $groupLine = Read-Host "  Group (or 'done')"
                    if ($groupLine.Trim().ToLower() -eq 'done') { break }

                    $parts = $groupLine.Trim().Split(',')
                    if ($parts.Count -ge 3) {
                        $mapLines += [PSCustomObject]@{
                            C1 = "Group"
                            C2 = $srcTenantId
                            C3 = $parts[0].Trim()
                            C4 = $parts[1].Trim()
                            C5 = $parts[2].Trim()
                            C6 = "Group"
                        }
                        Write-EIDMTag -Tag "OK" -Text ("Added group: {0}" -f $parts[2].Trim()) -Color Green
                    }
                    else {
                        Write-EIDMTag -Tag "WARN" -Text "Invalid format. Use: SourceObjId,TargetObjId,GroupName" -Color Yellow
                    }
                }
            }
        }

        # ----------------------------------------------------------------
        # 5) Export identity map CSV (NO headers - Microsoft requirement)
        # ----------------------------------------------------------------
        Write-EIDMSection "Export Identity Map"

        if ($mapLines.Count -eq 0) {
            Write-EIDMTag -Tag "WARN" -Text "No identity map entries built. Upload skipped." -Color Yellow
            return $script:EIDMStatus_Completed
        }

        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $mapPath = Join-Path $planFolder ("SharePoint_IdentityMap_{0}.csv" -f $stamp)

        # Export WITHOUT headers (Microsoft requirement: no column headings)
        $mapLines | ForEach-Object {
            "{0},{1},{2},{3},{4},{5}" -f $_.C1, $_.C2, $_.C3, $_.C4, $_.C5, $_.C6
        } | Set-Content -Path $mapPath -Encoding UTF8

        Write-EIDMTag -Tag "OK" -Text ("Identity map exported: {0}" -f $mapPath) -Color Green
        Write-EIDMTag -Tag "INFO" -Text ("Total entries: {0}" -f $mapLines.Count) -Color Cyan
    }

    # ----------------------------------------------------------------
    # 6) Upload to TARGET
    # ----------------------------------------------------------------
    Write-EIDMSection "Upload Identity Map to TARGET"

    Write-Host "  Uploading via Add-SPOTenantIdentityMap on TARGET tenant..." -ForegroundColor Cyan
    Write-Host "  (This overwrites any previously uploaded map)" -ForegroundColor DarkGray
    Write-Host ""

    Disconnect-EIDMSharePointIfNeeded
    Ensure-EIDMSharePointTargetConnection -Ctx $Ctx

    try {
        Add-SPOTenantIdentityMap -IdentityMapPath $mapPath -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Identity map uploaded to TARGET successfully." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Upload failed: {0}" -f $_.Exception.Message) -Color Red
        Write-Host "  Make sure the CSV file is closed before uploading." -ForegroundColor Yellow
        return $script:EIDMStatus_Failed
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 07-04 - Verify Cross-Tenant Compatibility
# ==========================================================================
function Step-07-04-VerifyCompatibility {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Verify Cross-Tenant Compatibility"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Run Get-SPOCrossTenantCompatibilityStatus on SOURCE" -ForegroundColor DarkGray
    Write-Host "    - Verify both tenants' SharePoint schemas are compatible" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Status must be 'Compatible' or 'Warning' to proceed with migration." -ForegroundColor Yellow
    Write-Host "  If 'Incompatible', wait 48 hours for patching then retry." -ForegroundColor DarkGray
    Write-Host ""

    # Get target host URL
    Disconnect-EIDMSharePointIfNeeded
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

    # Run compatibility check from SOURCE
    Write-EIDMSection "Compatibility Check (SOURCE)"

    Ensure-EIDMSharePointSourceConnection -Ctx $Ctx

    try {
        $result = Get-SPOCrossTenantCompatibilityStatus -PartnerCrossTenantHostURL $targetHostUrl -ErrorAction Stop
        $statusText = ($result | Out-String).Trim()

        Write-Host ""
        Write-Host "  Compatibility status: " -NoNewline -ForegroundColor Gray

        if ($statusText -match 'Compatible') {
            Write-Host $statusText -ForegroundColor Green
            Write-EIDMTag -Tag "OK" -Text "Tenants are compatible. You can proceed with SharePoint migration." -Color Green
        }
        elseif ($statusText -match 'Warning') {
            Write-Host $statusText -ForegroundColor Yellow
            Write-EIDMTag -Tag "WARN" -Text "Tenants report Warning status. Migration can proceed but review warnings." -Color Yellow
        }
        elseif ($statusText -match 'Incompatible') {
            Write-Host $statusText -ForegroundColor Red
            Write-EIDMTag -Tag "ERROR" -Text "Tenants are INCOMPATIBLE. Wait 48 hours for patching and retry. Contact support if it persists." -Color Red
        }
        else {
            Write-Host $statusText -ForegroundColor Gray
            Write-EIDMTag -Tag "INFO" -Text "Unrecognized status. Review the output above." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Compatibility check failed: {0}" -f $_.Exception.Message) -Color Red
    }
    finally {
        Disconnect-EIDMSharePointIfNeeded
    }

    return $script:EIDMStatus_Completed
}

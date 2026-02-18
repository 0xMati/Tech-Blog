# ==========================================================================
# 04-ExchangeMigrationExecution.Functions.ps1
# Phase 04 - Exchange Online Cross-Tenant Mailbox Migration (Execution)
#
# Steps:
#   04-01  Start Migration Batch
#          - Load mailbox CSV (READY rows)
#          - Add SOURCE users to scope group (SOURCE EXO)
#          - Create migration batch via New-MigrationBatch (TARGET EXO)
#
#   04-02  Check Migration Batches
#          - List migration batches on TARGET, aggregate per-user status
#          - Export BatchStatus + UserStatus CSVs
#
#   04-03  Stop / Remove Migration Batches
#          - Stop and/or Remove selected batches on TARGET
#          - Export operations summary CSV
#
#   04-04  Assign Licenses
#          - Connect to Graph TARGET
#          - Load user CSVs from Phase 02 (OnPrem + CloudOnly creation results)
#          - List available SKUs, let operator choose
#          - Assign licenses via Set-MgUserLicense
#          - Export OK / Issues CSVs
# ==========================================================================

function Get-EIDMExchangeMigrationExecutionSteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id         = "04-01-StartMigrationBatch"
            Phase      = "04-ExchangeMigrationExecution"
            Handler    = "Step-04-01-StartMigrationBatch"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "04-02-CheckMigrationBatches"
            Phase      = "04-ExchangeMigrationExecution"
            Handler    = "Step-04-02-CheckMigrationBatches"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "04-03-StopMigrationBatches"
            Phase      = "04-ExchangeMigrationExecution"
            Handler    = "Step-04-03-StopMigrationBatches"
            Requires   = @()
            AllowRerun = $true
        },
        @{
            Id         = "04-04-AssignLicenses"
            Phase      = "04-ExchangeMigrationExecution"
            Handler    = "Step-04-04-AssignLicenses"
            Requires   = @()
            AllowRerun = $true
        }
    )
}

# ==========================================================================
# STEP 04-01 - Start Migration Batch
# ==========================================================================

function Step-04-01-StartMigrationBatch {
    <#
    .SYNOPSIS  Adds READY users to the SOURCE scope group and creates a
               cross-tenant migration batch on the TARGET tenant.
    .DESCRIPTION
        1) Loads the ExchangeMigration_Mailboxes CSV (from Phase 03 Plan).
        2) Filters rows with ExoStatus = READY.
        3) Connects to SOURCE EXO - adds each SOURCE mailbox to the scope group.
        4) Connects to TARGET EXO - creates a New-MigrationBatch with a CSV
           containing the TARGET UPNs as EmailAddress.
        5) Exports results CSV.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Start Exchange Migration Batch"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Add READY source mailboxes to the SOURCE scope security group" -ForegroundColor DarkGray
    Write-Host "    - Create a migration batch on TARGET (New-MigrationBatch)" -ForegroundColor DarkGray
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) Load config values from Phase 03 Plan
    # ----------------------------------------------------------------
    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    $exMig = @{}
    if ($config.ContainsKey("ExchangeMigration") -and $config.ExchangeMigration -is [hashtable]) {
        $exMig = $config.ExchangeMigration
    }

    # ----------------------------------------------------------------
    # 2) Locate the Exchange mailbox CSV from Phase 03
    # ----------------------------------------------------------------
    Write-EIDMSection "Locate Mailbox CSV"

    $planFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    $execFolder = Join-Path $Ctx.RunRoot "04-ExchangeMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    $mbxCsvPath = $null

    # Try config path first
    if ($exMig.ContainsKey("MailboxCsvPath") -and (Test-Path $exMig.MailboxCsvPath -ErrorAction SilentlyContinue)) {
        $mbxCsvPath = $exMig.MailboxCsvPath
    }

    # Fallback to latest file in plan folder
    if (-not $mbxCsvPath -and (Test-Path $planFolder)) {
        $latest = Get-ChildItem -Path $planFolder -Filter "ExchangeMigration_Mailboxes_*.csv" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike "*_ForBatch_*" } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1

        if ($latest) { $mbxCsvPath = $latest.FullName }
    }

    if (-not $mbxCsvPath) {
        Write-EIDMTag -Tag "ERROR" -Text "No ExchangeMigration_Mailboxes CSV found. Run Phase 03 Plan (step 03-04) first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Using mailbox CSV: {0}" -f $mbxCsvPath) -Color Gray

    # ----------------------------------------------------------------
    # 3) Load and filter READY rows
    # ----------------------------------------------------------------
    Write-EIDMSection "Load and Filter READY Rows"

    $allRows = @(Import-Csv -Path $mbxCsvPath)
    Write-EIDMTag -Tag "INFO" -Text ("Total rows loaded: {0}" -f $allRows.Count) -Color Gray

    $readyRows = @($allRows | Where-Object {
        $_.ExoStatus -eq "READY" -and
        $_.SourceUPN -and $_.SourceUPN.Trim() -ne "" -and
        $_.TargetUPN -and $_.TargetUPN.Trim() -ne ""
    })

    Write-EIDMTag -Tag "INFO" -Text ("READY rows with both UPNs: {0}" -f $readyRows.Count) -Color Cyan

    if ($readyRows.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No READY rows found. Nothing to migrate." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # Display the users
    Write-Host ""
    foreach ($r in $readyRows) {
        Write-Host ("    {0}  ->  {1}  ({2})" -f $r.SourceUPN, $r.TargetUPN, $r.UserKind) -ForegroundColor White
    }
    Write-Host ""

    # ----------------------------------------------------------------
    # 4) Collect batch parameters
    # ----------------------------------------------------------------
    Write-EIDMSection "Migration Batch Parameters"

    # Scope group (from config or prompt)
    # Try ScopeGroupName (singular, saved by 03-03),
    # then ScopeGroupNames (plural, saved by 03-01 prerequisites)
    $defaultScopeGroup = ""
    if ($exMig.ContainsKey("ScopeGroupName") -and $exMig.ScopeGroupName) {
        $defaultScopeGroup = $exMig.ScopeGroupName
    }
    elseif ($exMig.ContainsKey("ScopeGroupNames") -and $exMig.ScopeGroupNames) {
        $defaultScopeGroup = ($exMig.ScopeGroupNames -split ",")[0].Trim()
    }
    if (-not $defaultScopeGroup) { $defaultScopeGroup = "CrossTenant-MailboxMove-Scope" }
    $scopeGroupInput = Read-Host ("SOURCE scope security group name (Enter for '{0}')" -f $defaultScopeGroup)
    $scopeGroupName  = if ([string]::IsNullOrWhiteSpace($scopeGroupInput)) { $defaultScopeGroup } else { $scopeGroupInput.Trim() }

    # Endpoint name (from config or prompt)
    $defaultEndpoint = if ($exMig.ContainsKey("EndpointName") -and $exMig.EndpointName) { $exMig.EndpointName } else { "CrossTenantMailboxEndpoint" }
    $endpointInput = Read-Host ("TARGET migration endpoint name (Enter for '{0}')" -f $defaultEndpoint)
    $endpointName  = if ([string]::IsNullOrWhiteSpace($endpointInput)) { $defaultEndpoint } else { $endpointInput.Trim() }

    # Target delivery domain (target *.mail.onmicrosoft.com)
    $defaultDeliveryDomain = ""
    $targetTenant = $config.Tenants.Target.TenantIdOrDomain
    if ($targetTenant -match "\.onmicrosoft\.com$") {
        $defaultDeliveryDomain = $targetTenant -replace "\.onmicrosoft\.com$", ".mail.onmicrosoft.com"
    }

    if ($defaultDeliveryDomain) {
        $ddInput = Read-Host ("TARGET delivery domain (Enter for '{0}')" -f $defaultDeliveryDomain)
    }
    else {
        $ddInput = Read-Host "TARGET delivery domain (e.g. contoso.mail.onmicrosoft.com)"
    }
    $targetDeliveryDomain = if ([string]::IsNullOrWhiteSpace($ddInput) -and $defaultDeliveryDomain) { $defaultDeliveryDomain } else { $ddInput.Trim() }

    if ([string]::IsNullOrWhiteSpace($targetDeliveryDomain)) {
        Write-EIDMTag -Tag "ERROR" -Text "Target delivery domain is required." -Color Red
        return $script:EIDMStatus_Failed
    }

    # Batch name
    $defaultBatchName = "CTM_Batch_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss")
    $batchNameInput = Read-Host ("Migration batch name (Enter for '{0}')" -f $defaultBatchName)
    $batchName = if ([string]::IsNullOrWhiteSpace($batchNameInput)) { $defaultBatchName } else { $batchNameInput.Trim() }

    # AutoStart / AutoComplete
    $autoStart    = Read-EIDMSimpleYesNo "AutoStart batch after creation?"
    $autoComplete = Read-EIDMSimpleYesNo "AutoComplete batch when synced (complete migration automatically)?"

    # Summary
    Write-Host ""
    Write-EIDMTag -Tag "BLOCK" -Text "Batch configuration summary" -Color Cyan
    Write-Host ("  Scope group          : {0}" -f $scopeGroupName) -ForegroundColor Gray
    Write-Host ("  Migration endpoint   : {0}" -f $endpointName) -ForegroundColor Gray
    Write-Host ("  Target delivery dom. : {0}" -f $targetDeliveryDomain) -ForegroundColor Gray
    Write-Host ("  Batch name           : {0}" -f $batchName) -ForegroundColor Gray
    Write-Host ("  AutoStart            : {0}" -f $autoStart) -ForegroundColor Gray
    Write-Host ("  AutoComplete         : {0}" -f $autoComplete) -ForegroundColor Gray
    Write-Host ("  Users count          : {0}" -f $readyRows.Count) -ForegroundColor Gray
    Write-Host ""

    $proceed = Read-EIDMSimpleYesNo "Proceed with migration batch creation?"
    if (-not $proceed) {
        Write-EIDMTag -Tag "SKIP" -Text "Migration batch creation cancelled by user." -Color Yellow
        return $script:EIDMStatus_WaitingUser
    }

    # ================================================================
    # A) SOURCE - Add users to scope group
    # ================================================================
    Write-EIDMSection "A) SOURCE - Add users to scope security group"

    # Disconnect any current EXO session first
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    Ensure-EIDMExchangeSourceConnection -Ctx $Ctx

    # Verify scope group exists, create if missing (with retry for transient failures)
    $scopeGroup = $null
    $maxRetries = 3
    for ($retryIdx = 1; $retryIdx -le $maxRetries; $retryIdx++) {
        try {
            $scopeGroup = Get-DistributionGroup -Identity $scopeGroupName -ErrorAction Stop
            Write-EIDMTag -Tag "OK" -Text ("Scope group found: {0} (PrimarySmtp={1})" -f $scopeGroup.DisplayName, $scopeGroup.PrimarySmtpAddress) -Color Green
            break
        }
        catch {
            if ($retryIdx -lt $maxRetries) {
                Write-EIDMTag -Tag "WARN" -Text ("Scope group lookup failed (attempt {0}/{1}), retrying in 10s..." -f $retryIdx, $maxRetries) -Color Yellow
                Start-Sleep -Seconds 10
            }
            else {
                Write-EIDMTag -Tag "WARN" -Text ("Scope group '{0}' not found in SOURCE." -f $scopeGroupName) -Color Yellow
                $doCreate = Read-EIDMSimpleYesNo ("Create mail-enabled security group '{0}' in SOURCE?" -f $scopeGroupName)
                if ($doCreate) {
                    try {
                        $scopeGroup = New-DistributionGroup -Type Security -Name $scopeGroupName -ErrorAction Stop
                        Write-EIDMTag -Tag "OK" -Text ("Scope group '{0}' created in SOURCE." -f $scopeGroupName) -Color Green
                    }
                    catch {
                        Write-EIDMTag -Tag "ERROR" -Text ("Failed to create scope group: {0}" -f $_.Exception.Message) -Color Red
                        return $script:EIDMStatus_Failed
                    }
                }
                else {
                    Write-EIDMTag -Tag "ERROR" -Text "Cannot proceed without scope group." -Color Red
                    return $script:EIDMStatus_Failed
                }
            }
        }
    }

    $addedCount   = 0
    $alreadyCount = 0
    $failedCount  = 0
    $groupResults = @()

    foreach ($row in $readyRows) {
        $sourceUpn = $row.SourceUPN.Trim()

        try {
            Add-DistributionGroupMember -Identity $scopeGroupName -Member $sourceUpn -BypassSecurityGroupManagerCheck:$true -ErrorAction Stop
            Write-EIDMTag -Tag "OK" -Text ("[SOURCE] {0} added to group" -f $sourceUpn) -Color Green
            $addedCount++
            $groupResults += [PSCustomObject]@{ SourceUPN = $sourceUpn; GroupAction = "Added"; Error = "" }
        }
        catch {
            $msg = $_.Exception.Message
            if ($msg -like "*is already a member*") {
                Write-EIDMTag -Tag "SKIP" -Text ("[SOURCE] {0} already in group" -f $sourceUpn) -Color DarkGray
                $alreadyCount++
                $groupResults += [PSCustomObject]@{ SourceUPN = $sourceUpn; GroupAction = "AlreadyMember"; Error = "" }
            }
            else {
                Write-EIDMTag -Tag "ERROR" -Text ("[SOURCE] Failed to add {0}: {1}" -f $sourceUpn, $msg) -Color Red
                $failedCount++
                $groupResults += [PSCustomObject]@{ SourceUPN = $sourceUpn; GroupAction = "Failed"; Error = $msg }
            }
        }
    }

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("[SOURCE] Group membership: Added={0}, Already={1}, Failed={2}" -f $addedCount, $alreadyCount, $failedCount) -Color Cyan

    # ================================================================
    # B) TARGET - Create migration batch
    # ================================================================
    Write-EIDMSection "B) TARGET - Create Migration Batch"

    # Switch to TARGET EXO
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

    # Build dedicated CSV for New-MigrationBatch (EmailAddress = TargetUPN)
    Write-EIDMTag -Tag "INFO" -Text "Building batch CSV (EmailAddress = TargetUPN)..." -Color Gray

    $batchRows = @()
    foreach ($row in $readyRows) {
        $tUpn = $row.TargetUPN.Trim()
        if ($tUpn) {
            $batchRows += [PSCustomObject]@{
                EmailAddress = $tUpn
            }
        }
    }

    if ($batchRows.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "No TargetUPN available for batch CSV." -Color Red
        return $script:EIDMStatus_Failed
    }

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $batchCsvPath = Join-Path $execFolder ("ExchangeMigration_ForBatch_{0}.csv" -f $stamp)
    $batchRows | Export-Csv -Path $batchCsvPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Batch CSV generated: {0}" -f $batchCsvPath) -Color Green

    # Load CSV as bytes
    $csvBytes = [System.IO.File]::ReadAllBytes($batchCsvPath)

    # Build New-MigrationBatch parameters
    $batchParams = @{
        Name                 = $batchName
        CSVData              = $csvBytes
        SourceEndpoint       = $endpointName
        TargetDeliveryDomain = $targetDeliveryDomain
        AutoStart            = $autoStart
        AutoComplete         = $autoComplete
    }

    Write-EIDMTag -Tag "INFO" -Text ("Creating migration batch '{0}'..." -f $batchName) -Color Cyan

    $createdBatch = $null
    try {
        $createdBatch = New-MigrationBatch @batchParams
        Write-EIDMTag -Tag "OK" -Text ("Migration batch '{0}' created successfully." -f $batchName) -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("New-MigrationBatch failed: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    # Read initial batch status
    $mb = $null
    try {
        Start-Sleep -Seconds 3
        $mb = Get-MigrationBatch -Identity $batchName -ErrorAction Stop
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not read batch status: {0}" -f $_.Exception.Message) -Color Yellow
    }

    if ($mb) {
        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text ("Batch '{0}' - Status={1}, State={2}, TotalCount={3}" -f $mb.Identity, $mb.Status, $mb.State, $mb.TotalCount) -Color Cyan
    }

    # ================================================================
    # C) Export results
    # ================================================================
    Write-EIDMSection "C) Export Results"

    $resultRows = @()
    foreach ($row in $readyRows) {
        $grp = $groupResults | Where-Object { $_.SourceUPN -eq $row.SourceUPN.Trim() } | Select-Object -First 1
        $groupAction = if ($grp) { $grp.GroupAction } else { "Unknown" }
        $groupError  = if ($grp) { $grp.Error } else { "" }

        $resultRows += [PSCustomObject]@{
            SourceUPN           = $row.SourceUPN
            TargetUPN           = $row.TargetUPN
            UserKind            = $row.UserKind
            ScopeGroupAction    = $groupAction
            ScopeGroupError     = $groupError
            BatchName           = $batchName
            Endpoint            = $endpointName
            TargetDeliveryDomain = $targetDeliveryDomain
            AutoStart           = $autoStart
            AutoComplete        = $autoComplete
        }
    }

    $resultCsvPath = Join-Path $execFolder ("ExchangeMigration_StartBatch_{0}.csv" -f $stamp)
    $resultRows | Export-Csv -Path $resultCsvPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Results exported: {0}" -f $resultCsvPath) -Color Green

    # ================================================================
    # D) Final summary
    # ================================================================
    Write-Host ""
    Write-EIDMSection "Final Summary"

    Write-Host ("  READY rows processed    : {0}" -f $readyRows.Count) -ForegroundColor Gray
    Write-Host ("  Scope group add         : Added={0}, Already={1}, Failed={2}" -f $addedCount, $alreadyCount, $failedCount) -ForegroundColor Gray
    Write-Host ("  Migration batch         : {0}" -f $batchName) -ForegroundColor Yellow
    Write-Host ("  Endpoint                : {0}" -f $endpointName) -ForegroundColor Gray
    Write-Host ("  TargetDeliveryDomain    : {0}" -f $targetDeliveryDomain) -ForegroundColor Gray
    Write-Host ""
    Write-Host "Monitor progress with:" -ForegroundColor DarkGray
    Write-Host ("  Get-MigrationBatch -Identity '{0}' | FL *" -f $batchName) -ForegroundColor DarkGray
    Write-Host ("  Get-MigrationUser -BatchId '{0}' | FT Identity,Status,SyncStatus -AutoSize" -f $batchName) -ForegroundColor DarkGray
    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text "Use step 04-02 (Check Migration Batches) to monitor progress." -Color Cyan

    # Disconnect
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    return $script:EIDMStatus_Completed
}


# ==========================================================================
# STEP 04-02 - Check Migration Batches
# ==========================================================================

function Step-04-02-CheckMigrationBatches {
    <#
    .SYNOPSIS  Lists cross-tenant migration batches on TARGET and exports
               per-batch and per-user status to CSV.
    .DESCRIPTION
        1) Connects to TARGET EXO.
        2) Retrieves all migration batches (optionally filtered by name).
        3) For each batch: aggregates MigrationUser status counts.
        4) Exports batch summary + user detail CSVs.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Check Exchange Migration Batches"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Connect to TARGET Exchange Online" -ForegroundColor DarkGray
    Write-Host "    - List migration batches and per-user status" -ForegroundColor DarkGray
    Write-Host "    - Export status CSVs" -ForegroundColor DarkGray
    Write-Host ""

    $execFolder = Join-Path $Ctx.RunRoot "04-ExchangeMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Batch filter
    # ----------------------------------------------------------------
    $defaultFilter = "CTM_Batch_*"
    $filterInput = Read-Host ("Batch name filter - wildcards allowed (Enter for '{0}', or '*' for all)" -f $defaultFilter)
    $batchFilter = if ([string]::IsNullOrWhiteSpace($filterInput)) { $defaultFilter } else { $filterInput.Trim() }

    # ----------------------------------------------------------------
    # 2) Connect to TARGET EXO
    # ----------------------------------------------------------------
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

    # ----------------------------------------------------------------
    # 3) Get batches
    # ----------------------------------------------------------------
    Write-EIDMSection "Retrieve Migration Batches"

    $allBatches = @()
    try {
        $allBatches = @(Get-MigrationBatch -ErrorAction Stop)
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to retrieve migration batches: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    if ($allBatches.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No migration batches found in TARGET tenant." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Total batches in tenant: {0}" -f $allBatches.Count) -Color Gray

    $filteredBatches = @($allBatches | Where-Object { $_.Identity -like $batchFilter })

    if ($filteredBatches.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text ("No batches match filter '{0}'." -f $batchFilter) -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Batches matching filter '{0}': {1}" -f $batchFilter, $filteredBatches.Count) -Color Cyan

    # ----------------------------------------------------------------
    # 4) Collect status per batch and per user
    # ----------------------------------------------------------------
    Write-EIDMSection "Collect Status"

    $batchSummaryList = @()
    $userStatusList   = @()

    foreach ($batch in $filteredBatches) {

        Write-EIDMTag -Tag "INFO" -Text ("Batch: {0}  Status={1}  State={2}  TotalCount={3}" -f $batch.Identity, $batch.Status, $batch.State, $batch.TotalCount) -Color Gray

        # Get users in this batch
        $users = @()
        try {
            $users = @(Get-MigrationUser -BatchId $batch.Identity -ErrorAction Stop)
        }
        catch {
            Write-EIDMTag -Tag "WARN" -Text ("  Failed to get MigrationUser for '{0}': {1}" -f $batch.Identity, $_.Exception.Message) -Color Yellow
            continue
        }

        Write-EIDMTag -Tag "INFO" -Text ("  Users in batch: {0}" -f $users.Count) -Color Gray

        # Aggregate by Status
        $grouped = @()
        if ($users.Count -gt 0) {
            $grouped = @($users | Group-Object Status)
        }

        $countCompleted = 0; $countSynced = 0; $countSyncing = 0; $countFailed = 0; $countQueued = 0

        foreach ($g in $grouped) {
            switch ($g.Name) {
                "Completed" { $countCompleted = $g.Count }
                "Synced"    { $countSynced    = $g.Count }
                "Syncing"   { $countSyncing   = $g.Count }
                "Failed"    { $countFailed    = $g.Count }
                "Queued"    { $countQueued    = $g.Count }
            }
        }

        $batchSummaryList += [PSCustomObject]@{
            BatchIdentity    = $batch.Identity
            BatchStatus      = $batch.Status
            BatchState       = $batch.State
            TotalCount       = $batch.TotalCount
            UsersCompleted   = $countCompleted
            UsersSynced      = $countSynced
            UsersSyncing     = $countSyncing
            UsersQueued      = $countQueued
            UsersFailed      = $countFailed
            UsersTotal       = $users.Count
            CheckedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }

        # Per-user detail - Select-Object creates safe PSObject even if props are missing
        foreach ($u in $users) {
            $uSafe = $u | Select-Object Identity, PrimaryEmailAddress, Status, SyncStatus, BatchId, ErrorSummary

            # For failed users, get detailed error via Get-MigrationUserStatistics
            $detailedError = ""
            $skippedItems  = ""
            $syncedItems   = ""
            if ($uSafe.Status -eq 'Failed') {
                try {
                    $stats = Get-MigrationUserStatistics -Identity $uSafe.Identity -ErrorAction Stop |
                        Select-Object Error, SkippedItemCount, SyncedItemCount
                    $detailedError = if ($stats.Error) { ($stats.Error | Out-String).Trim() } else { "" }
                    $skippedItems  = $stats.SkippedItemCount
                    $syncedItems   = $stats.SyncedItemCount
                }
                catch {
                    $detailedError = "(could not retrieve stats: {0})" -f $_.Exception.Message
                }
            }

            $userStatusList += [PSCustomObject]@{
                BatchIdentity  = $batch.Identity
                UserIdentity   = $uSafe.Identity
                PrimaryEmail   = $uSafe.PrimaryEmailAddress
                Status         = $uSafe.Status
                SyncStatus     = $uSafe.SyncStatus
                BatchId        = $uSafe.BatchId
                ErrorSummary   = $uSafe.ErrorSummary
                DetailedError  = $detailedError
                SkippedItems   = $skippedItems
                SyncedItems    = $syncedItems
                CheckedAt      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
        }

        # Display per-user status inline
        if ($users.Count -gt 0 -and $users.Count -le 50) {
            foreach ($u in $users) {
                $uSafe = $u | Select-Object Identity, Status, SyncStatus, ErrorSummary
                $statusColor = switch ($uSafe.Status) {
                    "Completed" { "Green" }
                    "Synced"    { "Green" }
                    "Syncing"   { "Cyan" }
                    "Failed"    { "Red" }
                    "Queued"    { "Yellow" }
                    default     { "Gray" }
                }
                $line = "    {0}: Status={1}, SyncStatus={2}" -f $uSafe.Identity, $uSafe.Status, $uSafe.SyncStatus
                if ($uSafe.Status -eq 'Failed' -and $uSafe.ErrorSummary) {
                    $line += "  Error={0}" -f $uSafe.ErrorSummary
                }
                Write-Host $line -ForegroundColor $statusColor
            }
            Write-Host ""
        }
    }

    # ----------------------------------------------------------------
    # 5) Export CSVs
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Status CSVs"

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    if ($batchSummaryList.Count -gt 0) {
        $batchCsvPath = Join-Path $execFolder ("ExchangeMigration_BatchStatus_{0}.csv" -f $stamp)
        $batchSummaryList | Export-Csv -Path $batchCsvPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("Batch summary CSV: {0}" -f $batchCsvPath) -Color Green
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "No batch summary to export." -Color Yellow
    }

    if ($userStatusList.Count -gt 0) {
        $userCsvPath = Join-Path $execFolder ("ExchangeMigration_UserStatus_{0}.csv" -f $stamp)
        $userStatusList | Export-Csv -Path $userCsvPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("User status CSV: {0}" -f $userCsvPath) -Color Green
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "No user status to export." -Color Yellow
    }

    # ----------------------------------------------------------------
    # 6) Console summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Summary"

    foreach ($bs in $batchSummaryList) {
        Write-Host ("  Batch: {0}" -f $bs.BatchIdentity) -ForegroundColor White
        Write-Host ("    Status={0}  State={1}  Total={2}" -f $bs.BatchStatus, $bs.BatchState, $bs.TotalCount) -ForegroundColor Gray
        Write-Host ("    Completed={0}  Synced={1}  Syncing={2}  Queued={3}  Failed={4}" -f $bs.UsersCompleted, $bs.UsersSynced, $bs.UsersSyncing, $bs.UsersQueued, $bs.UsersFailed) -ForegroundColor Gray
        Write-Host ""
    }

    # Disconnect
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    return $script:EIDMStatus_Completed
}


# ==========================================================================
# STEP 04-03 - Stop / Remove Migration Batches
# ==========================================================================

function Step-04-03-StopMigrationBatches {
    <#
    .SYNOPSIS  Stops and/or removes cross-tenant migration batches from
               the TARGET tenant.
    .DESCRIPTION
        1) Connects to TARGET EXO.
        2) Lists batches (optionally filtered).
        3) User selects action: Complete, Stop, or Remove.
        4) Executes chosen action on each matching batch.
        5) Exports operations summary CSV.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Stop / Remove Exchange Migration Batches"

    Write-Host "This step lets you:" -ForegroundColor Cyan
    Write-Host "    - Complete migration batches (finalize)" -ForegroundColor DarkGray
    Write-Host "    - Stop running batches" -ForegroundColor DarkGray
    Write-Host "    - Remove batches entirely" -ForegroundColor DarkGray
    Write-Host ""

    $execFolder = Join-Path $Ctx.RunRoot "04-ExchangeMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 1) Batch filter
    # ----------------------------------------------------------------
    $defaultFilter = "CTM_Batch_*"
    $filterInput = Read-Host ("Batch name filter - wildcards allowed (Enter for '{0}', or '*' for all)" -f $defaultFilter)
    $batchFilter = if ([string]::IsNullOrWhiteSpace($filterInput)) { $defaultFilter } else { $filterInput.Trim() }

    # ----------------------------------------------------------------
    # 2) Connect to TARGET EXO
    # ----------------------------------------------------------------
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

    # ----------------------------------------------------------------
    # 3) Get batches
    # ----------------------------------------------------------------
    Write-EIDMSection "List Migration Batches"

    $allBatches = @()
    try {
        $allBatches = @(Get-MigrationBatch -ErrorAction Stop)
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to retrieve migration batches: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    if ($allBatches.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No migration batches found in TARGET tenant." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    $filteredBatches = @($allBatches | Where-Object { $_.Identity -like $batchFilter })

    if ($filteredBatches.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text ("No batches match filter '{0}'." -f $batchFilter) -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Batches matching filter: {0}" -f $filteredBatches.Count) -Color Cyan
    Write-Host ""

    foreach ($b in $filteredBatches) {
        Write-Host ("    {0}  [Status: {1}]" -f $b.Identity, $b.Status) -ForegroundColor White
    }
    Write-Host ""

    # ----------------------------------------------------------------
    # 4) Choose action
    # ----------------------------------------------------------------
    Write-Host "Select an action:" -ForegroundColor Cyan
    Write-Host "  1) Complete batch(es)  - Complete-MigrationBatch (finalize sync)" -ForegroundColor Green
    Write-Host "  2) Stop batch(es)      - Stop-MigrationBatch (halt sync)" -ForegroundColor Yellow
    Write-Host "  3) Remove batch(es)    - Remove-MigrationBatch (delete)" -ForegroundColor Red
    Write-Host "  4) Stop + Remove       - Stop then Remove" -ForegroundColor Magenta
    Write-Host "  X) Cancel" -ForegroundColor DarkGray
    Write-Host ""

    $actionChoice = Read-Host "Enter choice [1-4 or X]"

    if ([string]::IsNullOrWhiteSpace($actionChoice) -or $actionChoice.Trim().ToUpper() -eq "X") {
        Write-EIDMTag -Tag "SKIP" -Text "Cancelled by user." -Color DarkGray
        return $script:EIDMStatus_WaitingUser
    }

    $actionName = ""
    switch ($actionChoice.Trim()) {
        "1" { $actionName = "Complete" }
        "2" { $actionName = "Stop" }
        "3" { $actionName = "Remove" }
        "4" { $actionName = "StopAndRemove" }
        default {
            Write-EIDMTag -Tag "ERROR" -Text "Invalid selection." -Color Red
            return $script:EIDMStatus_Failed
        }
    }

    $confirmText = "Apply '{0}' to {1} batch(es)?" -f $actionName, $filteredBatches.Count
    $confirmed = Read-EIDMSimpleYesNo $confirmText
    if (-not $confirmed) {
        Write-EIDMTag -Tag "SKIP" -Text "Operation cancelled." -Color Yellow
        return $script:EIDMStatus_WaitingUser
    }

    # ----------------------------------------------------------------
    # 5) Execute action
    # ----------------------------------------------------------------
    Write-EIDMSection "Executing: $actionName"

    $results = @()

    foreach ($b in $filteredBatches) {
        $identity     = $b.Identity
        $statusBefore = [string]$b.Status
        $actionResult = ""
        $errorMsg     = ""

        Write-EIDMTag -Tag "INFO" -Text ("Processing: {0} (Status: {1})" -f $identity, $statusBefore) -Color Gray

        # --- Complete ---
        if ($actionName -eq "Complete") {
            try {
                Complete-MigrationBatch -Identity $identity -Confirm:$false -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text ("Complete-MigrationBatch issued for: {0}" -f $identity) -Color Green
                $actionResult = "CompleteIssued"
            }
            catch {
                Write-EIDMTag -Tag "ERROR" -Text ("Complete failed for {0}: {1}" -f $identity, $_.Exception.Message) -Color Red
                $actionResult = "CompleteFailed"
                $errorMsg = $_.Exception.Message
            }
        }

        # --- Stop ---
        if ($actionName -eq "Stop" -or $actionName -eq "StopAndRemove") {
            try {
                Stop-MigrationBatch -Identity $identity -Confirm:$false -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text ("Stop-MigrationBatch issued for: {0}" -f $identity) -Color Green
                $actionResult = "StopIssued"
            }
            catch {
                $msg = $_.Exception.Message
                Write-EIDMTag -Tag "WARN" -Text ("Stop failed for {0}: {1}" -f $identity, $msg) -Color Yellow
                $actionResult = "StopFailed"
                $errorMsg = $msg
            }
        }

        # --- Remove ---
        if ($actionName -eq "Remove" -or $actionName -eq "StopAndRemove") {
            try {
                Remove-MigrationBatch -Identity $identity -Confirm:$false -ErrorAction Stop
                Write-EIDMTag -Tag "OK" -Text ("Remove-MigrationBatch succeeded for: {0}" -f $identity) -Color Green
                if ($actionName -eq "StopAndRemove") {
                    $actionResult = "StopAndRemoved"
                }
                else {
                    $actionResult = "Removed"
                }
            }
            catch {
                $msg = $_.Exception.Message
                Write-EIDMTag -Tag "ERROR" -Text ("Remove failed for {0}: {1}" -f $identity, $msg) -Color Red
                if ($errorMsg) { $errorMsg = "{0} | Remove: {1}" -f $errorMsg, $msg }
                else { $errorMsg = $msg }
                $actionResult = "{0}_RemoveFailed" -f $actionResult
            }
        }

        $results += [PSCustomObject]@{
            BatchIdentity  = $identity
            StatusBefore   = $statusBefore
            Action         = $actionName
            ActionResult   = $actionResult
            ErrorMessage   = $errorMsg
            ExecutedAt     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
    }

    # ----------------------------------------------------------------
    # 6) Export results
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Results"

    if ($results.Count -gt 0) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $resultPath = Join-Path $execFolder ("ExchangeMigration_BatchActions_{0}.csv" -f $stamp)
        $results | Export-Csv -Path $resultPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("Actions summary exported: {0}" -f $resultPath) -Color Green
    }

    # ----------------------------------------------------------------
    # 7) Summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Summary"

    foreach ($r in $results) {
        $color = if ($r.ErrorMessage) { "Red" } else { "Green" }
        Write-Host ("  {0}: {1} -> {2}" -f $r.BatchIdentity, $r.StatusBefore, $r.ActionResult) -ForegroundColor $color
        if ($r.ErrorMessage) {
            Write-Host ("    Error: {0}" -f $r.ErrorMessage) -ForegroundColor Red
        }
    }

    Write-Host ""

    # Disconnect
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 04-04 - Assign Licenses to Migrated Users
# ==========================================================================

function Step-04-04-AssignLicenses {
    <#
    .SYNOPSIS  Assigns Exchange Online (or other) licenses to migrated users
               on the TARGET tenant via Microsoft Graph.
    .DESCRIPTION
        1) Loads target users from Phase 02 CreationResults CSVs (OnPrem + CloudOnly).
        2) Connects to TARGET tenant via Graph.
        3) Lists available SKUs and lets the operator pick which to assign.
        4) Assigns selected licenses via Set-MgUserLicense.
        5) Exports OK and Issues result CSVs.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Assign Licenses to Migrated Users (TARGET)"

    Write-Host "This step will:" -ForegroundColor Cyan
    Write-Host "    - Load users created/identified in Phase 02 (OnPrem + CloudOnly)" -ForegroundColor DarkGray
    Write-Host "    - Connect to TARGET tenant via Microsoft Graph" -ForegroundColor DarkGray
    Write-Host "    - List available license SKUs and let you pick which to assign" -ForegroundColor DarkGray
    Write-Host "    - Assign selected licenses via Set-MgUserLicense" -ForegroundColor DarkGray
    Write-Host ""

    # ----------------------------------------------------------------
    # 1) Output folder
    # ----------------------------------------------------------------
    $execFolder = Join-Path $Ctx.RunRoot "04-ExchangeMigrationExecution"
    Assert-EIDMDirectory -Path $execFolder

    # ----------------------------------------------------------------
    # 2) Load users from Phase 02 CreationResults CSVs
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Target Users from Phase 02"

    $idPrepFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"

    $onPremCsvPath    = Join-Path $idPrepFolder "Users_OnPrem_CreationResults.csv"
    $cloudOnlyCsvPath = Join-Path $idPrepFolder "Users_CloudOnly_CreationResults.csv"

    $allUsers = @()

    # -- OnPrem users --
    if (Test-Path $onPremCsvPath) {
        $onPremRows = @(Import-Csv -Path $onPremCsvPath -Encoding UTF8)
        $validOnPrem = @($onPremRows | Where-Object {
            ($_.ExecutionStatus -eq "Success") -or ($_.AccountAlreadyExists -eq "True")
        })
        foreach ($row in $validOnPrem) {
            $allUsers += [PSCustomObject]@{
                TargetUPN      = $row.TargetUPN
                TargetObjectId = ""
                UserKind       = "OnPrem"
                SourceUPN      = $row.SourceUPN
            }
        }
        Write-EIDMTag -Tag "INFO" -Text ("{0} OnPrem users loaded from Phase 02 ({1} valid)" -f $onPremRows.Count, $validOnPrem.Count) -Color Gray
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "OnPrem CreationResults CSV not found - skipping OnPrem users" -Color Yellow
    }

    # -- CloudOnly users --
    if (Test-Path $cloudOnlyCsvPath) {
        $cloudRows = @(Import-Csv -Path $cloudOnlyCsvPath -Encoding UTF8)
        $validCloud = @($cloudRows | Where-Object {
            ($_.ExecutionStatus -eq "Success") -or ($_.AccountAlreadyExists -eq "True")
        })
        foreach ($row in $validCloud) {
            $allUsers += [PSCustomObject]@{
                TargetUPN      = $row.TargetUPN
                TargetObjectId = if ($row.PSObject.Properties.Match('TargetObjectId').Count -gt 0) { $row.TargetObjectId } else { "" }
                UserKind       = "CloudOnly"
                SourceUPN      = $row.SourceUPN
            }
        }
        Write-EIDMTag -Tag "INFO" -Text ("{0} CloudOnly users loaded from Phase 02 ({1} valid)" -f $cloudRows.Count, $validCloud.Count) -Color Gray
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "CloudOnly CreationResults CSV not found - skipping CloudOnly users" -Color Yellow
    }

    if ($allUsers.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "No valid target users found in Phase 02 CSVs. Cannot assign licenses." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Total users to process: {0}  (OnPrem: {1}, CloudOnly: {2})" -f `
        $allUsers.Count,
        @($allUsers | Where-Object { $_.UserKind -eq "OnPrem" }).Count,
        @($allUsers | Where-Object { $_.UserKind -eq "CloudOnly" }).Count) -Color Green

    # Show user list
    Write-Host ""
    Write-Host "  Users:" -ForegroundColor DarkGray
    foreach ($u in $allUsers) {
        Write-Host ("    [{0}] {1}" -f $u.UserKind, $u.TargetUPN) -ForegroundColor DarkGray
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
    Write-Host "Example: 0,2,5" -ForegroundColor DarkGray
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
    # 6) Confirm before proceeding
    # ----------------------------------------------------------------
    $confirmMsg = "Assign {0} SKU(s) to {1} user(s)?" -f $addLicenses.Count, $allUsers.Count
    if (-not (Read-EIDMSimpleYesNo $confirmMsg)) {
        Write-EIDMTag -Tag "INFO" -Text "Operator cancelled license assignment." -Color Yellow
        return $script:EIDMStatus_WaitingUser
    }

    # ----------------------------------------------------------------
    # 7) Assign licenses to each user
    # ----------------------------------------------------------------
    Write-EIDMSection "Assigning Licenses"

    $resultsOK     = @()
    $resultsIssues = @()
    $totalCount    = $allUsers.Count
    $currentIndex  = 0

    foreach ($user in $allUsers) {
        $currentIndex++
        $targetUpn = $user.TargetUPN
        $userKind  = $user.UserKind

        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text ("[{0}/{1}] Processing: {2} ({3})" -f $currentIndex, $totalCount, $targetUpn, $userKind) -Color Gray

        # Resolve user in Graph to get ObjectId
        $userId = $user.TargetObjectId
        if ([string]::IsNullOrWhiteSpace($userId)) {
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
        }
        else {
            # Still fetch to check usageLocation
            try {
                $mgUser = Get-MgUser -UserId $userId -Property "id,userPrincipalName,assignedLicenses,usageLocation" -ErrorAction Stop
            }
            catch {
                $errMsg = "Failed to retrieve user by ObjectId: {0}" -f $_.Exception.Message
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

        # Check UsageLocation - required for license assignment
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

        $licensesToAdd = @()
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
            Write-EIDMTag -Tag "SKIP" -Text "All selected SKUs already assigned - nothing to do" -Color DarkGray
            $resultsOK += [PSCustomObject]@{
                Status    = "AlreadyAssigned"
                Kind      = $userKind
                UserId    = $userId
                UPN       = $targetUpn
                SKUs      = ($addLicenses | ForEach-Object { $_.SkuId }) -join ";"
                Error     = ""
                Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            }
            continue
        }

        # Assign licenses
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
    # 8) Export results
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Export Results"

    $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")

    if ($resultsOK.Count -gt 0) {
        $okPath = Join-Path $execFolder ("ExchangeMigration_AssignLicenses_OK_{0}.csv" -f $stamp)
        $resultsOK | Export-Csv -Path $okPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "OK" -Text ("OK results exported: {0}" -f $okPath) -Color Green
    }

    if ($resultsIssues.Count -gt 0) {
        $issuesPath = Join-Path $execFolder ("ExchangeMigration_AssignLicenses_Issues_{0}.csv" -f $stamp)
        $resultsIssues | Export-Csv -Path $issuesPath -NoTypeInformation -Encoding UTF8
        Write-EIDMTag -Tag "WARN" -Text ("Issues exported: {0}" -f $issuesPath) -Color Yellow
    }

    # ----------------------------------------------------------------
    # 9) Summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Summary"

    $assignedCount        = @($resultsOK     | Where-Object { $_.Status -eq "Assigned" }).Count
    $alreadyAssignedCount = @($resultsOK     | Where-Object { $_.Status -eq "AlreadyAssigned" }).Count
    $failedCount          = $resultsIssues.Count

    Write-Host ("  Assigned:         {0}" -f $assignedCount) -ForegroundColor Green
    Write-Host ("  Already assigned: {0}" -f $alreadyAssignedCount) -ForegroundColor DarkGray
    Write-Host ("  Failed:           {0}" -f $failedCount) -ForegroundColor $(if ($failedCount -gt 0) { "Red" } else { "Green" })
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

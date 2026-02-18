# ==========================================================================
# 03-ExchangeMigrationPlan.Functions.ps1
# Phase 03 - Exchange Online Cross-Tenant Mailbox Migration (Plan)
# ==========================================================================

# ==========================================================================
# Helper - Extract source routing address (*.mail.onmicrosoft.com)
# ==========================================================================

function Get-EIDMSourceRoutingAddress {
    <#
    .SYNOPSIS  Extracts the source MOERA routing address (*.mail.onmicrosoft.com)
               from the EmailAddresses proxy list or constructs it from PrimarySmtpAddress.
    .PARAMETER EmailAddresses  Semicolon-separated proxy addresses from EXO Discovery CSV or mailbox object.
    .PARAMETER PrimarySmtpAddress  Fallback source SMTP address.
    .PARAMETER SourceOnMsDomain  e.g. mamotron.onmicrosoft.com (used to derive .mail. domain).
    .OUTPUTS   The routing address WITHOUT the "SMTP:" prefix (e.g. user@mamotron.mail.onmicrosoft.com)
    #>
    param(
        [string]$EmailAddresses,
        [string]$PrimarySmtpAddress,
        [string]$SourceOnMsDomain
    )

    # 1) Try to find *.mail.onmicrosoft.com in proxy addresses
    if ($EmailAddresses) {
        $addrList = @()
        if ($EmailAddresses -is [string]) {
            $addrList = $EmailAddresses -split ";"
        }
        elseif ($EmailAddresses -is [array] -or $EmailAddresses -is [System.Collections.IEnumerable]) {
            $addrList = @($EmailAddresses | ForEach-Object { [string]$_ })
        }

        foreach ($a in $addrList) {
            $trimmed = ([string]$a).Trim()
            if ($trimmed -match "(?i)^smtp:(.+\.mail\.onmicrosoft\.com)$") {
                return $Matches[1]
            }
        }
    }

    # 2) Fallback: construct from SourceOnMsDomain
    if ($SourceOnMsDomain) {
        $mailDomain = $SourceOnMsDomain -replace "\.onmicrosoft\.com$", ".mail.onmicrosoft.com"
        if ($PrimarySmtpAddress -and $PrimarySmtpAddress -match "^([^@]+)@") {
            return ("{0}@{1}" -f $Matches[1], $mailDomain)
        }
    }

    # 3) Last fallback: the onmicrosoft.com address (without .mail.)
    if ($EmailAddresses) {
        $addrList2 = @()
        if ($EmailAddresses -is [string]) {
            $addrList2 = $EmailAddresses -split ";"
        }
        elseif ($EmailAddresses -is [array] -or $EmailAddresses -is [System.Collections.IEnumerable]) {
            $addrList2 = @($EmailAddresses | ForEach-Object { [string]$_ })
        }

        foreach ($a in $addrList2) {
            $trimmed = ([string]$a).Trim()
            if ($trimmed -match "(?i)^smtp:(.+\.onmicrosoft\.com)$") {
                return $Matches[1]
            }
        }
    }

    # 4) Absolute fallback: return PrimarySmtpAddress
    return $PrimarySmtpAddress
}

function Get-EIDMExchangeMigrationPlanSteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id       = "03-01-ExchangeMigrationPrerequisites"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-01-ExchangeMigrationPrerequisites"
            Requires = @()
        },
        @{
            Id       = "03-02-CreateTargetApp"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-02-CreateTargetApp"
            Requires = @()   # Custom Graph scopes handled inside the step
        },
        @{
            Id       = "03-03-EndpointAndOrgRelationships"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-03-EndpointAndOrgRelationships"
            Requires = @()   # EXO connections handled inside (TARGET then SOURCE)
        },
        @{
            Id       = "03-04-BuildMailboxCsv"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-04-BuildMailboxCsv"
            Requires = @()
        },
        @{
            Id       = "03-05-CheckTargetRecipients"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-05-CheckTargetRecipients"
            Requires = @()
        },
        @{
            Id       = "03-06-PrepareMailUsers"
            Phase    = "03-ExchangeMigrationPlan"
            Handler  = "Step-03-06-PrepareMailUsers"
            Requires = @()
        }
    )
}

# ==========================================================================
# Private helper - Assign Mailbox.Migration permission + configured perms
# ==========================================================================

function Grant-EIDMMailboxMigrationPermission {
    <#
    .SYNOPSIS  Assigns the Mailbox.Migration app role to the migration app SP
               and adds it to the app's requiredResourceAccess so admin-consent works.
    .OUTPUTS   The Mailbox.Migration AppRole object (for CSV export), or $null on failure.
    #>
    param(
        [Parameter(Mandatory)]$ServicePrincipal,
        [Parameter(Mandatory)]$Application
    )

    # ---- Locate Exchange Online SP ----
    $exoAppId      = "00000002-0000-0ff1-ce00-000000000000"   # EXO first-party app
    $exoCandidates = @()

    try {
        $exoCandidates = @(Get-MgServicePrincipal -Filter ("appId eq '{0}'" -f $exoAppId))
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Failed to query EXO SP by appId: {0}" -f $_.Exception.Message) -Color Yellow
    }

    if ($exoCandidates.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No SP found by AppId, trying displayName fallback..." -Color Yellow
        try {
            $exoCandidates = @(Get-MgServicePrincipal -Filter "contains(displayName,'Exchange Online')")
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Fallback search failed: {0}" -f $_.Exception.Message) -Color Red
            return $null
        }
    }

    if ($exoCandidates.Count -eq 0) {
        Write-EIDMTag -Tag "ERROR" -Text "Could not locate the Exchange Online service principal in this tenant." -Color Red
        return $null
    }

    $exoSp = $exoCandidates[0]
    Write-EIDMTag -Tag "INFO" -Text ("Exchange Online SP found. Id={0} DisplayName='{1}'" -f $exoSp.Id, $exoSp.DisplayName) -Color Gray

    # ---- Find Mailbox.Migration app role ----
    $appRole = $exoSp.AppRoles | Where-Object {
        $_.Value -eq "Mailbox.Migration" -and $_.AllowedMemberTypes -contains "Application"
    }

    if (-not $appRole) {
        Write-EIDMTag -Tag "ERROR" -Text "Could not find Mailbox.Migration app role on Exchange Online SP." -Color Red
        return $null
    }

    Write-EIDMTag -Tag "INFO" -Text ("Mailbox.Migration app role Id = {0}" -f $appRole.Id) -Color Gray

    # ---- 1) Assign app role to SP ----
    $alreadyAssigned = $false
    try {
        $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id
        $match = $existing | Where-Object { $_.ResourceId -eq $exoSp.Id -and $_.AppRoleId -eq $appRole.Id }
        if ($match) { $alreadyAssigned = $true }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Unable to query existing role assignments: {0}" -f $_.Exception.Message) -Color Yellow
    }

    if ($alreadyAssigned) {
        Write-EIDMTag -Tag "OK" -Text "Mailbox.Migration permission is already assigned." -Color Green
    }
    else {
        $body = @{
            principalId = $ServicePrincipal.Id
            resourceId  = $exoSp.Id
            appRoleId   = $appRole.Id
        }
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipal.Id -BodyParameter $body | Out-Null
        Write-EIDMTag -Tag "OK" -Text "Mailbox.Migration permission assigned successfully." -Color Green
    }

    # ---- 2) Update requiredResourceAccess (configured permissions) ----
    $appFull = Get-MgApplication -ApplicationId $Application.Id

    $currentRra = @()
    if ($appFull.RequiredResourceAccess) {
        foreach ($r in $appFull.RequiredResourceAccess) {
            $raList = @()
            if ($r.ResourceAccess) {
                foreach ($ra in $r.ResourceAccess) {
                    $raList += @{ id = $ra.Id; type = $ra.Type }
                }
            }
            $currentRra += @{
                resourceAppId  = $r.ResourceAppId
                resourceAccess = $raList
            }
        }
    }

    $exoRra = $null
    if ($currentRra.Count -gt 0) {
        $exoRra = $currentRra | Where-Object { $_.resourceAppId -eq $exoSp.AppId } | Select-Object -First 1
    }

    if ($exoRra) {
        $hasIt = $false
        foreach ($ra in $exoRra.resourceAccess) { if ($ra.id -eq $appRole.Id) { $hasIt = $true; break } }

        if ($hasIt) {
            Write-EIDMTag -Tag "OK" -Text "Mailbox.Migration already present in configured permissions." -Color Green
        }
        else {
            $exoRra.resourceAccess += @{ id = $appRole.Id; type = "Role" }
        }
    }
    else {
        $currentRra += @{
            resourceAppId  = $exoSp.AppId
            resourceAccess = @( @{ id = $appRole.Id; type = "Role" } )
        }
    }

    Update-MgApplication -ApplicationId $Application.Id -RequiredResourceAccess $currentRra | Out-Null
    Write-EIDMTag -Tag "OK" -Text "Configured permissions updated with Mailbox.Migration." -Color Green

    # Return role + EXO SP info for the results CSV
    return [PSCustomObject]@{
        AppRoleId = $appRole.Id
        ExoSpId   = $exoSp.Id
    }
}

# ==========================================================================
# STEP 03-01 - Exchange Migration Prerequisites (Questionnaire)
# ==========================================================================

function Step-03-01-ExchangeMigrationPrerequisites {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Exchange Migration Prerequisites (Questionnaire)"

    Write-Host "This wizard helps you confirm all prerequisites for Exchange" -ForegroundColor Gray
    Write-Host "Online cross-tenant mailbox migration, as per Microsoft" -ForegroundColor Gray
    Write-Host "documentation (Move Mailbox app, migration endpoint," -ForegroundColor Gray
    Write-Host "organization relationship, scoping groups, licenses, etc.)." -ForegroundColor Gray
    Write-Host ""

    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    $results = New-Object System.Collections.Generic.List[object]
    $order = 0

    # Helper to add a result row
    function Add-CheckResult {
        param(
            [int]$Order, [string]$Block, [string]$Question,
            [bool]$Answer, [string]$ImpactIfNo
        )
        $results.Add([PSCustomObject]@{
            Order      = $Order
            Block      = $Block
            Question   = $Question
            Answer     = if ($Answer) { "Yes" } else { "No" }
            ImpactIfNo = if ($Answer) { "" } else { $ImpactIfNo }
            Detail     = ""
            AssessedAt = (Get-Date)
        }) | Out-Null
    }

    # ===========================================================
    # Block 1 - Admin accounts
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 1 - Admin accounts" -Color Cyan
    Write-Host ""

    $sourceAdminUpn = Read-EIDMNonEmpty "Source tenant admin UPN (will configure migration)"
    $targetAdminUpn = Read-EIDMNonEmpty "Target tenant admin UPN (will configure migration)"

    Write-Host ""

    # ===========================================================
    # Block 2 - Cross Tenant User Data Migration license
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 2 - Cross Tenant User Data Migration license" -Color Cyan
    Write-Host ""

    Write-Host "The 'Cross Tenant User Data Migration' license must be assigned:" -ForegroundColor Gray
    Write-Host "  - To the admin accounts that drive the migration (source & target)" -ForegroundColor Gray
    Write-Host "  - To ALL users that will be migrated, either in the SOURCE tenant" -ForegroundColor Gray
    Write-Host "    OR in the TARGET tenant (per user)." -ForegroundColor Gray
    Write-Host ""

    $order++
    $q = "Is the 'Cross Tenant User Data Migration' license assigned to SOURCE admin '$sourceAdminUpn' ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Cross Tenant License" $q $a "SOURCE admin cannot drive the migration without this license."
    $results[-1].Detail = "Admin: $sourceAdminUpn"

    $order++
    $q = "Is the 'Cross Tenant User Data Migration' license assigned to TARGET admin '$targetAdminUpn' ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Cross Tenant License" $q $a "TARGET admin cannot drive the migration without this license."
    $results[-1].Detail = "Admin: $targetAdminUpn"

    $order++
    $q = "For ALL users to be migrated, is the 'Cross Tenant User Data Migration' license assigned in EITHER the source OR the target tenant (per user) ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Cross Tenant License" $q $a "Users without this license cannot be migrated cross-tenant."

    Write-Host ""

    # ===========================================================
    # Block 3 - Permissions & roles
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 3 - Permissions & roles" -Color Cyan
    Write-Host ""

    Write-Host "Before starting, you must have permissions to configure:" -ForegroundColor Gray
    Write-Host "  - The Move Mailbox application in Azure (app registration, permissions)" -ForegroundColor Gray
    Write-Host "  - The EXO Migration Endpoint" -ForegroundColor Gray
    Write-Host "  - The EXO Organization Relationship" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Typically this means roles such as:" -ForegroundColor DarkGray
    Write-Host "  - Global Administrator / Privileged Role Administrator / App Administrator (for Azure app)" -ForegroundColor DarkGray
    Write-Host "  - Exchange Administrator / Organization Management (for Exchange configuration)" -ForegroundColor DarkGray
    Write-Host ""

    $order++
    $q = "Does the SOURCE admin '$sourceAdminUpn' have the required Azure AD permissions to create and configure the Move Mailbox app ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Permissions" $q $a "Cannot create/configure the Move Mailbox app in SOURCE."
    $results[-1].Detail = "Admin: $sourceAdminUpn"

    $order++
    $q = "Does the SOURCE admin '$sourceAdminUpn' have the required Exchange Online roles (e.g. Organization Management) ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Permissions" $q $a "Cannot configure EXO endpoints/relationships in SOURCE."
    $results[-1].Detail = "Admin: $sourceAdminUpn"

    $order++
    $q = "Does the TARGET admin '$targetAdminUpn' have the required Azure AD permissions to create and configure the Move Mailbox app ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Permissions" $q $a "Cannot create/configure the Move Mailbox app in TARGET."
    $results[-1].Detail = "Admin: $targetAdminUpn"

    $order++
    $q = "Does the TARGET admin '$targetAdminUpn' have the required Exchange Online roles (e.g. Organization Management) ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "Permissions" $q $a "Cannot configure EXO endpoints/relationships in TARGET."
    $results[-1].Detail = "Admin: $targetAdminUpn"

    Write-Host ""

    # ===========================================================
    # Block 4 - Mail-enabled security groups (scoping)
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 4 - Mail-enabled security groups (scoping)" -Color Cyan
    Write-Host ""

    Write-Host "The source tenant MUST have at least one mail-enabled security group" -ForegroundColor Gray
    Write-Host "to scope the list of mailboxes that can be moved. Only users that are" -ForegroundColor Gray
    Write-Host "members of these groups will be allowed to move from the source tenant." -ForegroundColor Gray
    Write-Host ""
    Write-Host "If you're migrating more than 10,000 users, Microsoft recommends" -ForegroundColor Gray
    Write-Host "creating multiple groups for best performance." -ForegroundColor Gray
    Write-Host ""

    $order++
    $q = "In the SOURCE tenant, do you have at least one mail-enabled security group dedicated to scoping migrations ?"
    $a = Read-EIDMSimpleYesNo $q

    $groupsNames = ""
    if ($a) {
        $groupsNames = Read-Host "Optional: enter the name(s) of the mail-enabled security group(s), comma-separated (press Enter to skip)"
    }
    else {
        # Offer to create one automatically
        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text "A mail-enabled security group is required to scope the migration." -Color Yellow
        Write-Host ""

        $defaultGroupName = "MAILBOXMIGRATION"
        $createGroup = Read-EIDMSimpleYesNo ("Do you want to create one now in the SOURCE tenant? (default name: $defaultGroupName)")

        if ($createGroup) {
            $inputName = Read-Host ("Group name [$defaultGroupName]")
            if ([string]::IsNullOrWhiteSpace($inputName)) { $inputName = $defaultGroupName }

            Write-Host ""
            Write-EIDMTag -Tag "INFO" -Text "Connecting to Exchange Online (SOURCE) to create the group..." -Color Cyan

            Ensure-EIDMExchangeSourceConnection -Ctx $Ctx

            # Check if group already exists
            $existingGroup = $null
            try {
                $existingGroup = Get-DistributionGroup -Identity $inputName -ErrorAction Stop
            }
            catch { $existingGroup = $null }

            if ($existingGroup) {
                Write-EIDMTag -Tag "OK" -Text ("Group '$inputName' already exists (PrimarySmtpAddress: {0})." -f $existingGroup.PrimarySmtpAddress) -Color Green
                $groupsNames = $inputName
                $a = $true
            }
            else {
                try {
                    $newGroup = New-DistributionGroup `
                        -Name $inputName `
                        -Type Security `
                        -ErrorAction Stop

                    Write-EIDMTag -Tag "OK" -Text ("Mail-enabled security group '$inputName' created successfully (PrimarySmtpAddress: {0})." -f $newGroup.PrimarySmtpAddress) -Color Green
                    $groupsNames = $inputName
                    $a = $true
                }
                catch {
                    Write-EIDMTag -Tag "ERROR" -Text ("Failed to create group '$inputName': {0}" -f $_.Exception.Message) -Color Red
                    Write-Host "You will need to create this group manually before proceeding." -ForegroundColor Yellow
                }
            }
        }
        else {
            Write-Host "You will need to create a mail-enabled security group manually before proceeding." -ForegroundColor Yellow
        }
    }

    Add-CheckResult $order "Scoping Groups" $q $a "No scoping group = no mailbox can be moved from the source tenant."
    $results[-1].Detail = if ($groupsNames) { $groupsNames } else { "<none specified>" }

    Write-Host ""

    # ===========================================================
    # Block 5 - Tenant IDs
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 5 - Tenant IDs" -Color Cyan
    Write-Host ""

    Write-Host "You must know the Microsoft 365 tenant IDs of both SOURCE and TARGET." -ForegroundColor Gray
    Write-Host "The target tenant ID will be used in the Organization Relationship" -ForegroundColor Gray
    Write-Host "DomainName field during configuration." -ForegroundColor Gray
    Write-Host ""

    $sourceTenantId = Read-EIDMNonEmpty "Enter SOURCE tenant ID (GUID)"
    $targetTenantId = Read-EIDMNonEmpty "Enter TARGET tenant ID (GUID)"

    $sourceTidOk = Test-EIDMGuidFormat $sourceTenantId
    $targetTidOk = Test-EIDMGuidFormat $targetTenantId

    if (-not $sourceTidOk) {
        Write-EIDMTag -Tag "WARN" -Text "SOURCE tenant ID format does not look like a valid GUID." -Color Yellow
    }
    if (-not $targetTidOk) {
        Write-EIDMTag -Tag "WARN" -Text "TARGET tenant ID format does not look like a valid GUID." -Color Yellow
    }

    $order++
    Add-CheckResult $order "Tenant IDs" "SOURCE tenant ID format is valid GUID" $sourceTidOk "Invalid GUID will cause configuration errors."
    $results[-1].Detail = $sourceTenantId

    $order++
    Add-CheckResult $order "Tenant IDs" "TARGET tenant ID format is valid GUID" $targetTidOk "Invalid GUID will cause configuration errors."
    $results[-1].Detail = $targetTenantId

    Write-Host ""

    # ===========================================================
    # Block 6 - Exchange Online licenses
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 6 - Exchange Online licenses" -Color Cyan
    Write-Host ""

    Write-Host "All users in both the source and target organizations must be licensed" -ForegroundColor Gray
    Write-Host "with appropriate Exchange Online subscriptions." -ForegroundColor Gray
    Write-Host ""

    $order++
    $q = "Are ALL relevant users (source & target) licensed with appropriate Exchange Online subscriptions ?"
    $a = Read-EIDMSimpleYesNo $q
    Add-CheckResult $order "EXO Licenses" $q $a "Users without Exchange Online licenses cannot have mailboxes migrated."

    Write-Host ""

    # ===========================================================
    # Summary & Export
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Summary" -Color Cyan
    Write-Host ""

    $allOk = $true
    foreach ($r in $results) {
        $detailText = if ($r.Detail) { "($($r.Detail))" } else { "" }

        if ($r.Answer -eq "Yes") {
            Write-EIDMTag -Tag "OK" -Text ("{0} - OK {1}" -f $r.Question, $detailText) -Color Green
        }
        else {
            Write-EIDMTag -Tag "FAIL" -Text ("{0} - MISSING / NOT CONFIRMED {1}" -f $r.Question, $detailText) -Color Red
            $allOk = $false
        }
    }

    Write-Host ""

    if ($allOk) {
        Write-EIDMTag -Tag "VERDICT" -Text "GO - All Exchange cross-tenant migration prerequisites CONFIRMED. You can proceed." -Color Green
    }
    else {
        Write-EIDMTag -Tag "VERDICT" -Text "NO-GO - Some prerequisites are NOT confirmed. Fix the FAILED items before proceeding." -Color Red
    }

    # Persist tenant IDs and admin UPNs in config for later steps
    if (-not $config.ContainsKey("ExchangeMigration")) {
        $config.ExchangeMigration = @{}
    }
    $config.ExchangeMigration.SourceAdminUpn = $sourceAdminUpn
    $config.ExchangeMigration.TargetAdminUpn = $targetAdminUpn
    $config.ExchangeMigration.SourceTenantId = $sourceTenantId
    $config.ExchangeMigration.TargetTenantId = $targetTenantId
    if ($groupsNames) {
        $config.ExchangeMigration.ScopeGroupNames = $groupsNames
    }
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    # Export CSV report
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "ExchangeMigration_Prerequisites_Assessment.csv"
    $results | Sort-Object Order | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Prerequisites assessment exported to: {0}" -f $outputPath) -Color Green
    Write-Host ""
    Write-Host "How to read this report:" -ForegroundColor Cyan
    Write-Host "  - Block       : Thematic area (license, permissions, scoping, tenant IDs, EXO licenses)." -ForegroundColor Gray
    Write-Host "  - Question    : Exact question asked during the assessment." -ForegroundColor Gray
    Write-Host "  - Answer      : Yes / No." -ForegroundColor Gray
    Write-Host "  - ImpactIfNo  : Concrete impact or risk if the answer is No." -ForegroundColor Gray
    Write-Host "  - Detail      : Additional context (admin UPN, tenant ID, group names)." -ForegroundColor Gray
    Write-Host "  - AssessedAt  : Timestamp for audit/traceability." -ForegroundColor Gray

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 03-02 - Create Target Migration App
# ==========================================================================

function Step-03-02-CreateTargetApp {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Create Target Migration Application (Entra ID)"

    Write-Host "This step creates a multi-tenant Entra ID application in the" -ForegroundColor Gray
    Write-Host "TARGET tenant that will be used as the 'Move Mailbox' app for" -ForegroundColor Gray
    Write-Host "cross-tenant Exchange Online mailbox migration." -ForegroundColor Gray
    Write-Host ""
    Write-Host "Actions performed:" -ForegroundColor DarkGray
    Write-Host "  1. Connect to Microsoft Graph in the TARGET tenant" -ForegroundColor DarkGray
    Write-Host "     (with Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All," -ForegroundColor DarkGray
    Write-Host "      Directory.Read.All scopes)" -ForegroundColor DarkGray
    Write-Host "  2. Create (or reuse) a multi-tenant app registration" -ForegroundColor DarkGray
    Write-Host "  3. Create a service principal for the app" -ForegroundColor DarkGray
    Write-Host "  4. Create a client secret" -ForegroundColor DarkGray
    Write-Host "  5. Assign 'Mailbox.Migration' permission (Exchange Online)" -ForegroundColor DarkGray
    Write-Host "  6. Add 'Mailbox.Migration' to configured permissions" -ForegroundColor DarkGray
    Write-Host ""

    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    # ------------------------------------------------------------------
    # Idempotency check - offer to skip if already completed
    # ------------------------------------------------------------------
    if ($config.ContainsKey("ExchangeMigration") -and
        $config.ExchangeMigration -is [hashtable] -and
        $config.ExchangeMigration.ContainsKey("TargetAppId") -and
        $config.ExchangeMigration.TargetAppId) {
        Write-EIDMTag -Tag "INFO" -Text ("A target app is already recorded in config: {0} (AppId={1})" -f `
            $config.ExchangeMigration.TargetAppDisplayName, $config.ExchangeMigration.TargetAppId) -Color Yellow
        $redo = Read-EIDMSimpleYesNo "Do you want to create a NEW app (this will overwrite the config)?"
        if (-not $redo) {
            Write-EIDMTag -Tag "SKIP" -Text "Skipping - existing app retained." -Color DarkGray
            return $script:EIDMStatus_Completed
        }
    }

    # ------------------------------------------------------------------
    # Collect parameters
    # ------------------------------------------------------------------
    $defaultAppName      = "CrossTenantMailboxMigration"
    $defaultSecretMonths = 12

    $appDisplayName = Read-Host ("App display name (leave blank for '{0}')" -f $defaultAppName)
    if ([string]::IsNullOrWhiteSpace($appDisplayName)) { $appDisplayName = $defaultAppName }

    $secretMonthsInput = Read-Host ("Client secret validity in months (leave blank for {0})" -f $defaultSecretMonths)
    [int]$secretValidityMonths = $defaultSecretMonths
    if (-not [string]::IsNullOrWhiteSpace($secretMonthsInput)) {
        [int]$parsed = 0
        if ([int]::TryParse($secretMonthsInput, [ref]$parsed) -and $parsed -gt 0) {
            $secretValidityMonths = $parsed
        }
    }

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Planned app display name : {0}" -f $appDisplayName) -Color Gray
    Write-EIDMTag -Tag "INFO" -Text ("Planned secret validity  : {0} month(s)" -f $secretValidityMonths) -Color Gray
    Write-Host ""

    # ------------------------------------------------------------------
    # 1. Connect to Graph TARGET tenant with elevated scopes
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "STEP" -Text "Connecting to Microsoft Graph (TARGET tenant)..." -Color Cyan
    Write-Host ""

    $targetTenantId = $null
    if ($config.ContainsKey("ExchangeMigration") -and $config.ExchangeMigration.TargetTenantId) {
        $targetTenantId = $config.ExchangeMigration.TargetTenantId
    }
    elseif ($config.ContainsKey("Tenants") -and $config.Tenants.Target.TenantIdOrDomain) {
        $targetTenantId = $config.Tenants.Target.TenantIdOrDomain
    }

    if (-not $targetTenantId) {
        Write-EIDMTag -Tag "ERROR" -Text "TARGET tenant ID not found in config. Please run step 03-01 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-Host "This step requires elevated Graph permissions. An interactive" -ForegroundColor DarkGray
    Write-Host "sign-in window will appear. Use the TARGET tenant admin account." -ForegroundColor DarkGray
    Write-Host ("TARGET tenant: {0}" -f $targetTenantId) -ForegroundColor Gray
    Write-Host ""
    Write-Host "Required scopes:" -ForegroundColor DarkGray
    Write-Host "  - Application.ReadWrite.All" -ForegroundColor DarkGray
    Write-Host "  - AppRoleAssignment.ReadWrite.All" -ForegroundColor DarkGray
    Write-Host "  - Directory.Read.All" -ForegroundColor DarkGray
    Write-Host ""

    try {
        # Disconnect any existing Graph session to force re-auth with elevated scopes
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch {}

        $elevatedScopes = @(
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "Directory.Read.All"
        )
        Connect-MgGraph -TenantId $targetTenantId -Scopes $elevatedScopes | Out-Null

        $graphCtx = Get-MgContext
        if (-not $graphCtx -or -not $graphCtx.TenantId) {
            throw "No Graph context returned after Connect-MgGraph."
        }

        Write-EIDMTag -Tag "OK" -Text ("Connected to Graph. TenantId = {0}" -f $graphCtx.TenantId) -Color Green

        # Reset auth state so next step re-authenticates with standard scopes
        $script:EIDMAuthState.GraphSourceConnected = $false
        $script:EIDMAuthState.GraphTargetConnected = $false
        $script:EIDMAuthState.GraphConnectedTenant = $null
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to connect to Microsoft Graph: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    # ------------------------------------------------------------------
    # 2. Create (or reuse) multi-tenant Entra ID application
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "STEP" -Text "Creating Entra ID application (TARGET tenant)..." -Color Cyan
    Write-Host ""

    $app = $null
    try {
        $existingApps = @(Get-MgApplication -Filter ("displayName eq '{0}'" -f $appDisplayName) -ErrorAction SilentlyContinue)
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Unable to query existing apps: {0}" -f $_.Exception.Message) -Color Yellow
        $existingApps = @()
    }

    if ($existingApps.Count -gt 0) {
        Write-EIDMTag -Tag "WARN" -Text ("An application named '{0}' already exists (AppId={1})." -f $appDisplayName, $existingApps[0].AppId) -Color Yellow
        $reuse = Read-EIDMSimpleYesNo "Do you want to REUSE the existing application?"

        if (-not $reuse) {
            Write-EIDMTag -Tag "INFO" -Text "Aborted. Choose a different app name and re-run this step." -Color Yellow
            return $script:EIDMStatus_Failed
        }

        $app = $existingApps[0]
        Write-EIDMTag -Tag "INFO" -Text ("Reusing existing application. Id={0} AppId={1}" -f $app.Id, $app.AppId) -Color Gray
    }
    else {
        $app = New-MgApplication -DisplayName $appDisplayName `
                                 -SignInAudience "AzureADMultipleOrgs" `
                                 -Web @{ redirectUris = @("https://office.com") }

        Write-EIDMTag -Tag "OK" -Text ("Application created. Id={0} AppId={1}" -f $app.Id, $app.AppId) -Color Green
    }

    # ------------------------------------------------------------------
    # 3. Create service principal (if not present)
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "STEP" -Text "Creating service principal for the app..." -Color Cyan

    $sp = $null
    try {
        $spResults = @(Get-MgServicePrincipal -Filter ("appId eq '{0}'" -f $app.AppId) -ErrorAction SilentlyContinue)
    }
    catch {
        $spResults = @()
    }

    if ($spResults.Count -gt 0) {
        $sp = $spResults[0]
        Write-EIDMTag -Tag "INFO" -Text ("Reusing existing SP. Id={0}" -f $sp.Id) -Color Gray
    }
    else {
        $sp = New-MgServicePrincipal -AppId $app.AppId
        Write-EIDMTag -Tag "OK" -Text ("Service principal created. Id={0}" -f $sp.Id) -Color Green
    }

    # ------------------------------------------------------------------
    # 4. Create client secret
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "STEP" -Text "Creating client secret (password credential)..." -Color Cyan

    $startDate = Get-Date
    $endDate   = $startDate.AddMonths($secretValidityMonths)

    Write-Host ("  Valid from {0} to {1}" -f $startDate.ToString("yyyy-MM-dd"), $endDate.ToString("yyyy-MM-dd")) -ForegroundColor Gray

    $passwordParams = @{
        displayName   = "CrossTenantMailboxMigrationSecret"
        startDateTime = $startDate
        endDateTime   = $endDate
    }

    $secretResult = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential $passwordParams
    $clientSecret = $secretResult.SecretText

    Write-EIDMTag -Tag "OK" -Text "Client secret created successfully." -Color Green

    # ------------------------------------------------------------------
    # 5 & 6. Assign Mailbox.Migration + update configured permissions
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "STEP" -Text "Assigning Mailbox.Migration permission and updating configured permissions..." -Color Cyan
    Write-Host ""

    $permResult = Grant-EIDMMailboxMigrationPermission -ServicePrincipal $sp -Application $app

    if (-not $permResult) {
        Write-EIDMTag -Tag "ERROR" -Text "Failed to grant Mailbox.Migration permission. See errors above." -Color Red
        return $script:EIDMStatus_Failed
    }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    Write-Host ""
    Write-EIDMSection "Target Migration App - Summary"

    $tenantId = $graphCtx.TenantId

    Write-Host "TARGET tenant ID:" -ForegroundColor Gray
    Write-Host ("  {0}" -f $tenantId) -ForegroundColor Green
    Write-Host ""
    Write-Host "Migration application (Entra ID app registration):" -ForegroundColor Gray
    Write-Host ("  Display name     : {0}" -f $app.DisplayName) -ForegroundColor Green
    Write-Host ("  Application (Id) : {0}" -f $app.AppId) -ForegroundColor Green
    Write-Host ("  Object Id        : {0}" -f $app.Id) -ForegroundColor Green
    Write-Host ""
    Write-Host "Service principal:" -ForegroundColor Gray
    Write-Host ("  Object Id        : {0}" -f $sp.Id) -ForegroundColor Green
    Write-Host ""
    Write-Host "Client secret (store securely - this value will NOT be shown again):" -ForegroundColor Yellow
    Write-Host ("  Secret           : {0}" -f $clientSecret) -ForegroundColor Magenta
    Write-Host ("  Expires on       : {0}" -f $endDate.ToString("yyyy-MM-dd")) -ForegroundColor Green
    Write-Host ""
    Write-Host "IMPORTANT:" -ForegroundColor Yellow
    Write-Host "  - Store the Application Id, Tenant Id and Secret securely." -ForegroundColor Yellow
    Write-Host "  - You will use these values when creating the EXO migration" -ForegroundColor Yellow
    Write-Host "    endpoint (RemoteServer=outlook.office.com, ApplicationId," -ForegroundColor Yellow
    Write-Host "    Password=<Secret>, RemoteTenant=<SourceTenant>)." -ForegroundColor Yellow
    Write-Host ""

    # ------------------------------------------------------------------
    # Persist to config
    # ------------------------------------------------------------------
    if (-not $config.ContainsKey("ExchangeMigration")) {
        $config.ExchangeMigration = @{}
    }
    $config.ExchangeMigration.TargetAppDisplayName  = $app.DisplayName
    $config.ExchangeMigration.TargetAppId           = $app.AppId
    $config.ExchangeMigration.TargetAppObjectId     = $app.Id
    $config.ExchangeMigration.TargetSpObjectId      = $sp.Id
    $config.ExchangeMigration.TargetSecretExpiry     = $endDate.ToString("yyyy-MM-dd")
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    Write-EIDMTag -Tag "OK" -Text "App details saved to config (except the secret - store it securely)." -Color Green

    # ------------------------------------------------------------------
    # Export results CSV
    # ------------------------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    $resultRow = [PSCustomObject]@{
        TenantId          = $tenantId
        AppDisplayName    = $app.DisplayName
        AppId             = $app.AppId
        AppObjectId       = $app.Id
        SpObjectId        = $sp.Id
        SecretExpiry      = $endDate.ToString("yyyy-MM-dd")
        MailboxMigRoleId  = $permResult.AppRoleId
        ExoSpId           = $permResult.ExoSpId
        CreatedAt         = (Get-Date)
    }

    $outputPath = Join-Path $phaseFolder "ExchangeMigration_TargetApp_Results.csv"
    @($resultRow) | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Results exported to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# STEP 03-03 - Endpoint & Organization Relationships (TARGET + SOURCE)
# ==========================================================================

function Step-03-03-EndpointAndOrgRelationships {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Exchange Migration Endpoint & Organization Relationships"

    Write-Host "This step configures BOTH tenants for cross-tenant mailbox migration:" -ForegroundColor Gray
    Write-Host "" -ForegroundColor Gray
    Write-Host "  TARGET tenant:" -ForegroundColor DarkGray
    Write-Host "    - Ensure organization customization is enabled" -ForegroundColor DarkGray
    Write-Host "    - Create migration endpoint (New-MigrationEndpoint)" -ForegroundColor DarkGray
    Write-Host "    - Create/update Org Relationship (Inbound)" -ForegroundColor DarkGray
    Write-Host "" -ForegroundColor DarkGray
    Write-Host "  SOURCE tenant:" -ForegroundColor DarkGray
    Write-Host "    - Ensure organization customization is enabled" -ForegroundColor DarkGray
    Write-Host "    - Ensure mail-enabled security group (scope)" -ForegroundColor DarkGray
    Write-Host "    - Create/update Org Relationship (RemoteOutbound)" -ForegroundColor DarkGray
    Write-Host ""

    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    # ------------------------------------------------------------------
    # Read defaults from config (populated by earlier steps)
    # ------------------------------------------------------------------
    $exMig = @{}
    if ($config.ContainsKey("ExchangeMigration") -and $config.ExchangeMigration -is [hashtable]) {
        $exMig = $config.ExchangeMigration
    }

    $defaultSourceTenantId = if ($exMig.ContainsKey("SourceTenantId"))  { $exMig.SourceTenantId }  else { "" }
    $defaultTargetTenantId = if ($exMig.ContainsKey("TargetTenantId"))  { $exMig.TargetTenantId }  else { "" }
    $defaultAppId          = if ($exMig.ContainsKey("TargetAppId"))     { $exMig.TargetAppId }     else { "" }
    $defaultScopeGroups    = if ($exMig.ContainsKey("ScopeGroupNames")) { $exMig.ScopeGroupNames } else { "" }

    # ------------------------------------------------------------------
    # Collect TARGET-side parameters
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "BLOCK" -Text "TARGET tenant parameters" -Color Cyan
    Write-Host ""

    # Endpoint name
    $endpointNameInput = Read-Host "Migration endpoint name (Enter for 'CrossTenantMailboxEndpoint')"
    $endpointName = if ([string]::IsNullOrWhiteSpace($endpointNameInput)) { "CrossTenantMailboxEndpoint" } else { $endpointNameInput.Trim() }

    # Remote server
    $remoteServerInput = Read-Host "Remote server (Enter for 'outlook.office.com')"
    $remoteServer = if ([string]::IsNullOrWhiteSpace($remoteServerInput)) { "outlook.office.com" } else { $remoteServerInput.Trim() }

    # Source onmicrosoft domain
    $sourceOnMsDomain = Read-EIDMNonEmpty "SOURCE tenant onmicrosoft.com domain (e.g. contoso.onmicrosoft.com)"

    # Migration AppId (auto from config)
    $migrationAppId = $defaultAppId
    if ([string]::IsNullOrWhiteSpace($migrationAppId)) {
        Write-EIDMTag -Tag "ERROR" -Text "Migration ApplicationId not found in config. Run step 03-02 first." -Color Red
        return $script:EIDMStatus_Failed
    }
    Write-EIDMTag -Tag "INFO" -Text ("Migration AppId  : {0} (from config)" -f $migrationAppId) -Color Gray

    # Source tenant ID
    if ($defaultSourceTenantId) {
        Write-Host ("  Config has SOURCE tenant ID: {0}" -f $defaultSourceTenantId) -ForegroundColor DarkGray
    }
    $srcTidInput = Read-Host ("SOURCE tenant ID - GUID (Enter to use '{0}')" -f $defaultSourceTenantId)
    $sourceTenantId = if ([string]::IsNullOrWhiteSpace($srcTidInput) -and $defaultSourceTenantId) { $defaultSourceTenantId } else { $srcTidInput.Trim() }

    # TARGET OrgRelationship name
    $tgtOrgRelInput = Read-Host "TARGET OrgRelationship name - Inbound (Enter for 'CrossTenantMailboxRel-Inbound')"
    $targetOrgRelName = if ([string]::IsNullOrWhiteSpace($tgtOrgRelInput)) { "CrossTenantMailboxRel-Inbound" } else { $tgtOrgRelInput.Trim() }

    Write-Host ""

    # ------------------------------------------------------------------
    # Collect SOURCE-side parameters
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "BLOCK" -Text "SOURCE tenant parameters" -Color Cyan
    Write-Host ""

    # Target tenant ID
    if ($defaultTargetTenantId) {
        Write-Host ("  Config has TARGET tenant ID: {0}" -f $defaultTargetTenantId) -ForegroundColor DarkGray
    }
    $tgtTidInput = Read-Host ("TARGET tenant ID - GUID (Enter to use '{0}')" -f $defaultTargetTenantId)
    $targetTenantId = if ([string]::IsNullOrWhiteSpace($tgtTidInput) -and $defaultTargetTenantId) { $defaultTargetTenantId } else { $tgtTidInput.Trim() }

    # SOURCE OrgRelationship name
    $srcOrgRelInput = Read-Host "SOURCE OrgRelationship name - RemoteOutbound (Enter for 'CrossTenantMailboxRel-Outbound')"
    $sourceOrgRelName = if ([string]::IsNullOrWhiteSpace($srcOrgRelInput)) { "CrossTenantMailboxRel-Outbound" } else { $srcOrgRelInput.Trim() }

    # Scope group
    $defaultScopeGroup = if ($defaultScopeGroups) { ($defaultScopeGroups -split ",")[0].Trim() } else { "CrossTenant-MailboxMove-Scope" }
    $scopeGroupInput = Read-Host ("SOURCE scope group name (Enter for '{0}')" -f $defaultScopeGroup)
    $scopeGroupName = if ([string]::IsNullOrWhiteSpace($scopeGroupInput)) { $defaultScopeGroup } else { $scopeGroupInput.Trim() }

    Write-Host ""

    # ------------------------------------------------------------------
    # Summary of collected values
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "BLOCK" -Text "Summary of planned configuration" -Color Cyan
    Write-Host ""
    Write-Host "TARGET side:" -ForegroundColor Gray
    Write-Host ("  Endpoint name      : {0}" -f $endpointName) -ForegroundColor Gray
    Write-Host ("  Remote server      : {0}" -f $remoteServer) -ForegroundColor Gray
    Write-Host ("  SOURCE onmicrosoft : {0}" -f $sourceOnMsDomain) -ForegroundColor Gray
    Write-Host ("  Migration AppId    : {0}" -f $migrationAppId) -ForegroundColor Gray
    Write-Host ("  SOURCE tenant ID   : {0}" -f $sourceTenantId) -ForegroundColor Gray
    Write-Host ("  OrgRel name        : {0}" -f $targetOrgRelName) -ForegroundColor Gray
    Write-Host ""
    Write-Host "SOURCE side:" -ForegroundColor Gray
    Write-Host ("  TARGET tenant ID   : {0}" -f $targetTenantId) -ForegroundColor Gray
    Write-Host ("  OrgRel name        : {0}" -f $sourceOrgRelName) -ForegroundColor Gray
    Write-Host ("  Scope group        : {0}" -f $scopeGroupName) -ForegroundColor Gray
    Write-Host ("  OAuth AppId        : {0}" -f $migrationAppId) -ForegroundColor Gray
    Write-Host ""

    # ------------------------------------------------------------------
    # Admin consent URL (SOURCE tenant must consent to the migration app)
    # ------------------------------------------------------------------
    Write-EIDMTag -Tag "BLOCK" -Text "Admin consent (SOURCE tenant)" -Color Yellow
    Write-Host ""

    $adminConsentUrl = "https://login.microsoftonline.com/{0}/adminconsent?client_id={1}&redirect_uri=https://office.com" -f $sourceOnMsDomain, $migrationAppId
    Write-Host "The SOURCE tenant admin must grant admin consent to the migration app." -ForegroundColor Yellow
    Write-Host "Admin consent URL:" -ForegroundColor DarkGray
    Write-Host ("  {0}" -f $adminConsentUrl) -ForegroundColor Cyan
    Write-Host ""

    $openBrowser = Read-EIDMSimpleYesNo "Open admin consent URL in default browser now?"
    if ($openBrowser) {
        Write-EIDMTag -Tag "INFO" -Text "Opening browser. Sign in as SOURCE tenant admin and grant consent." -Color Gray
        try { Start-Process $adminConsentUrl } catch {}
        Write-Host ""
        Read-Host "After completing admin consent in the browser, press Enter to continue"
    }

    Write-Host ""
    $confirmed = Read-EIDMSimpleYesNo "Confirm that SOURCE admin consent is done and values above are correct?"
    if (-not $confirmed) {
        Write-EIDMTag -Tag "WARN" -Text "Cancelled by user." -Color Yellow
        return $script:EIDMStatus_Failed
    }

    # ------------------------------------------------------------------
    # Client secret (for TARGET migration endpoint)
    # ------------------------------------------------------------------
    Write-Host ""
    Write-EIDMTag -Tag "BLOCK" -Text "Migration app client secret" -Color Cyan
    Write-Host ""
    Write-Host "Enter the client secret for the migration application." -ForegroundColor DarkGray
    Write-Host "Value will NOT be echoed to the screen." -ForegroundColor DarkGray
    Write-Host ""

    $clientSecretSecure = Read-Host "Migration app client secret" -AsSecureString

    # ==================================================================
    # PART 1 - TARGET TENANT
    # ==================================================================
    Write-Host ""
    Write-EIDMSection "Part 1 - TARGET tenant configuration"

    # ---- Connect to EXO TARGET ----
    Write-EIDMTag -Tag "STEP" -Text "Connecting to Exchange Online (TARGET tenant)..." -Color Cyan
    Write-Host "Sign in with the TARGET tenant admin account." -ForegroundColor DarkGray
    Write-Host ""

    try {
        # Disconnect any existing EXO session
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
        $script:EIDMExoState.SourceConnected = $false
        $script:EIDMExoState.TargetConnected = $false

        Connect-ExchangeOnline -ShowBanner:$false
        $null = Get-OrganizationConfig -ErrorAction Stop
        Write-EIDMTag -Tag "OK" -Text "Connected to Exchange Online (TARGET)." -Color Green
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("Failed to connect to EXO TARGET: {0}" -f $_.Exception.Message) -Color Red
        return $script:EIDMStatus_Failed
    }

    # ---- Ensure organization customization ----
    Write-EIDMTag -Tag "STEP" -Text "Checking organization customization (TARGET)..." -Color Cyan

    try {
        $orgConfig = Get-OrganizationConfig | Select-Object -First 1 -Property IsDehydrated
        if ($orgConfig.IsDehydrated -eq $true) {
            Write-EIDMTag -Tag "WARN" -Text "TARGET tenant is dehydrated. Enabling organization customization..." -Color Yellow
            Enable-OrganizationCustomization
            Write-EIDMTag -Tag "OK" -Text "Organization customization enabled." -Color Green
        }
        else {
            Write-EIDMTag -Tag "OK" -Text "TARGET tenant is not dehydrated." -Color Green
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not check/enable org customization: {0}" -f $_.Exception.Message) -Color Yellow
    }

    # ---- Create or reuse migration endpoint ----
    Write-EIDMTag -Tag "STEP" -Text "Creating migration endpoint (TARGET)..." -Color Cyan
    Write-Host ""

    $endpoint = $null
    $existingEndpoint = $null
    try { $existingEndpoint = Get-MigrationEndpoint -Identity $endpointName -ErrorAction SilentlyContinue } catch {}

    if ($existingEndpoint) {
        Write-EIDMTag -Tag "WARN" -Text ("Endpoint '{0}' already exists." -f $endpointName) -Color Yellow
        $reuseEp = Read-EIDMSimpleYesNo "Reuse existing migration endpoint?"

        if ($reuseEp) {
            $endpoint = $existingEndpoint
            Write-EIDMTag -Tag "OK" -Text ("Reusing endpoint '{0}'." -f $endpointName) -Color Green
        }
        else {
            $recreate = Read-EIDMSimpleYesNo "Remove and recreate it?"
            if ($recreate) {
                Remove-MigrationEndpoint -Identity $endpointName -Confirm:$false
                Write-EIDMTag -Tag "INFO" -Text ("Removed endpoint '{0}'." -f $endpointName) -Color Gray
            }
            else {
                Write-EIDMTag -Tag "ERROR" -Text "Cannot proceed without an endpoint. Aborting." -Color Red
                return $script:EIDMStatus_Failed
            }
        }
    }

    if (-not $endpoint) {
        $credential = New-Object System.Management.Automation.PSCredential -ArgumentList $migrationAppId, $clientSecretSecure

        try {
            $endpoint = New-MigrationEndpoint `
                -RemoteServer $remoteServer `
                -RemoteTenant $sourceOnMsDomain `
                -Credentials $credential `
                -ExchangeRemoteMove:$true `
                -Name $endpointName `
                -ApplicationId $migrationAppId

            Write-EIDMTag -Tag "OK" -Text ("Migration endpoint '{0}' created." -f $endpointName) -Color Green
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Failed to create endpoint: {0}" -f $_.Exception.Message) -Color Red
            Write-Host ""
            Write-Host "Common causes:" -ForegroundColor Yellow
            Write-Host "  - SOURCE admin consent not granted for the migration app" -ForegroundColor Yellow
            Write-Host "  - Incorrect AppId or client secret" -ForegroundColor Yellow
            return $script:EIDMStatus_Failed
        }
    }

    # ---- Create or update TARGET Org Relationship (Inbound) ----
    Write-EIDMTag -Tag "STEP" -Text "Configuring Organization Relationship - Inbound (TARGET)..." -Color Cyan
    Write-Host ""

    $orgRelTarget = $null
    $orgRelTarget = Invoke-EIDMOrgRelationshipSetup `
        -RemoteTenantId $sourceTenantId `
        -OrgRelName     $targetOrgRelName `
        -Capability     "Inbound"

    if (-not $orgRelTarget) {
        Write-EIDMTag -Tag "ERROR" -Text "Failed to configure TARGET OrgRelationship. See errors above." -Color Red
        return $script:EIDMStatus_Failed
    }

    # ---- TARGET summary ----
    Write-Host ""
    Write-Host "TARGET - Migration Endpoint:" -ForegroundColor Gray
    Write-Host ("  Name         : {0}" -f $endpoint.Identity) -ForegroundColor Green
    Write-Host ("  RemoteServer : {0}" -f $endpoint.RemoteServer) -ForegroundColor Green
    Write-Host ("  RemoteTenant : {0}" -f $endpoint.RemoteTenant) -ForegroundColor Green
    Write-Host ""
    Write-Host "TARGET - OrgRelationship (Inbound):" -ForegroundColor Gray
    Write-Host ("  Name         : {0}" -f $orgRelTarget.Name) -ForegroundColor Green
    Write-Host ("  DomainNames  : {0}" -f ($orgRelTarget.DomainNames -join ", ")) -ForegroundColor Green
    Write-Host ("  Capability   : {0}" -f $orgRelTarget.MailboxMoveCapability) -ForegroundColor Green
    Write-Host ""

    # ==================================================================
    # PART 2 - SOURCE TENANT
    # ==================================================================
    Write-EIDMSection "Part 2 - SOURCE tenant configuration"

    $doSource = Read-EIDMSimpleYesNo "Configure SOURCE OrgRelationship (RemoteOutbound) now?"
    $orgRelSource = $null

    if ($doSource) {
        # ---- Switch EXO session to SOURCE ----
        Write-EIDMTag -Tag "STEP" -Text "Switching to Exchange Online (SOURCE tenant)..." -Color Cyan
        Write-Host "Sign in with the SOURCE tenant admin account." -ForegroundColor DarkGray
        Write-Host ""

        try {
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
            $script:EIDMExoState.SourceConnected = $false
            $script:EIDMExoState.TargetConnected = $false

            Connect-ExchangeOnline -ShowBanner:$false
            $null = Get-OrganizationConfig -ErrorAction Stop
            Write-EIDMTag -Tag "OK" -Text "Connected to Exchange Online (SOURCE)." -Color Green
        }
        catch {
            Write-EIDMTag -Tag "ERROR" -Text ("Failed to connect to EXO SOURCE: {0}" -f $_.Exception.Message) -Color Red
            Write-EIDMTag -Tag "WARN" -Text "TARGET config succeeded but SOURCE config failed. You can re-run this step." -Color Yellow
            return $script:EIDMStatus_Failed
        }

        # ---- Ensure organization customization ----
        Write-EIDMTag -Tag "STEP" -Text "Checking organization customization (SOURCE)..." -Color Cyan

        try {
            $orgConfig2 = Get-OrganizationConfig | Select-Object -First 1 -Property IsDehydrated
            if ($orgConfig2.IsDehydrated -eq $true) {
                Write-EIDMTag -Tag "WARN" -Text "SOURCE tenant is dehydrated. Enabling..." -Color Yellow
                Enable-OrganizationCustomization
                Write-EIDMTag -Tag "OK" -Text "Organization customization enabled." -Color Green
            }
            else {
                Write-EIDMTag -Tag "OK" -Text "SOURCE tenant is not dehydrated." -Color Green
            }
        }
        catch {
            Write-EIDMTag -Tag "WARN" -Text ("Could not check/enable org customization: {0}" -f $_.Exception.Message) -Color Yellow
        }

        # ---- Ensure mail-enabled security group ----
        Write-EIDMTag -Tag "STEP" -Text ("Ensuring mail-enabled security group '{0}' (SOURCE)..." -f $scopeGroupName) -Color Cyan

        $scopeGroup = $null
        try { $scopeGroup = Get-DistributionGroup -Identity $scopeGroupName -ErrorAction SilentlyContinue } catch {}

        if ($scopeGroup) {
            Write-EIDMTag -Tag "OK" -Text ("Scope group '{0}' already exists." -f $scopeGroupName) -Color Green
        }
        else {
            try {
                $scopeGroup = New-DistributionGroup -Type Security -Name $scopeGroupName
                Write-EIDMTag -Tag "OK" -Text ("Scope group '{0}' created." -f $scopeGroupName) -Color Green
            }
            catch {
                Write-EIDMTag -Tag "ERROR" -Text ("Failed to create scope group: {0}" -f $_.Exception.Message) -Color Red
                return $script:EIDMStatus_Failed
            }
        }

        # ---- Create or update SOURCE Org Relationship (RemoteOutbound) ----
        Write-EIDMTag -Tag "STEP" -Text "Configuring Organization Relationship - RemoteOutbound (SOURCE)..." -Color Cyan
        Write-Host ""

        $orgRelSource = Invoke-EIDMOrgRelationshipSetup `
            -RemoteTenantId  $targetTenantId `
            -OrgRelName      $sourceOrgRelName `
            -Capability      "RemoteOutbound" `
            -OAuthAppId      $migrationAppId `
            -ScopeGroupName  $scopeGroupName

        if (-not $orgRelSource) {
            Write-EIDMTag -Tag "ERROR" -Text "Failed to configure SOURCE OrgRelationship. See errors above." -Color Red
            return $script:EIDMStatus_Failed
        }

        # ---- SOURCE summary ----
        Write-Host ""
        Write-Host "SOURCE - OrgRelationship (RemoteOutbound):" -ForegroundColor Gray
        Write-Host ("  Name           : {0}" -f $orgRelSource.Name) -ForegroundColor Green
        Write-Host ("  DomainNames    : {0}" -f ($orgRelSource.DomainNames -join ", ")) -ForegroundColor Green
        Write-Host ("  Capability     : {0}" -f $orgRelSource.MailboxMoveCapability) -ForegroundColor Green
        Write-Host ("  OAuthAppId     : {0}" -f $orgRelSource.OAuthApplicationId) -ForegroundColor Green
        Write-Host ("  PublishedScopes: {0}" -f ($orgRelSource.MailboxMovePublishedScopes -join ", ")) -ForegroundColor Green
        Write-Host ""
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "SOURCE OrgRelationship skipped. You can re-run this step later." -Color Yellow
    }

    # ------------------------------------------------------------------
    # Disconnect EXO and reset state
    # ------------------------------------------------------------------
    try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
    $script:EIDMExoState.SourceConnected = $false
    $script:EIDMExoState.TargetConnected = $false

    # ------------------------------------------------------------------
    # Persist to config
    # ------------------------------------------------------------------
    if (-not $config.ContainsKey("ExchangeMigration") -or $config.ExchangeMigration -isnot [hashtable]) {
        $config.ExchangeMigration = @{}
    }
    $config.ExchangeMigration.EndpointName         = $endpointName
    $config.ExchangeMigration.SourceOnMsDomain      = $sourceOnMsDomain
    $config.ExchangeMigration.TargetOrgRelName      = $targetOrgRelName
    $config.ExchangeMigration.SourceOrgRelName      = $sourceOrgRelName
    $config.ExchangeMigration.ScopeGroupName        = $scopeGroupName
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    # ------------------------------------------------------------------
    # Export results CSV
    # ------------------------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    $rows = @()

    if ($endpoint) {
        $rows += [PSCustomObject]@{
            Side       = "TARGET"
            Type       = "MigrationEndpoint"
            Name       = $endpoint.Identity
            Detail1    = "RemoteServer=$($endpoint.RemoteServer)"
            Detail2    = "RemoteTenant=$($endpoint.RemoteTenant)"
            Detail3    = "AppId=$migrationAppId"
            CreatedAt  = (Get-Date)
        }
    }

    if ($orgRelTarget) {
        $rows += [PSCustomObject]@{
            Side       = "TARGET"
            Type       = "OrgRelationship-Inbound"
            Name       = $orgRelTarget.Name
            Detail1    = "DomainNames=$($orgRelTarget.DomainNames -join ';')"
            Detail2    = "Capability=$($orgRelTarget.MailboxMoveCapability)"
            Detail3    = "Enabled=$($orgRelTarget.Enabled)"
            CreatedAt  = (Get-Date)
        }
    }

    if ($orgRelSource) {
        $rows += [PSCustomObject]@{
            Side       = "TARGET"
            Type       = "OrgRelationship-RemoteOutbound"
            Name       = $orgRelSource.Name
            Detail1    = "DomainNames=$($orgRelSource.DomainNames -join ';')"
            Detail2    = "Capability=$($orgRelSource.MailboxMoveCapability)"
            Detail3    = "OAuthAppId=$($orgRelSource.OAuthApplicationId)"
            CreatedAt  = (Get-Date)
        }
    }

    $outputPath = Join-Path $phaseFolder "ExchangeMigration_EndpointAndOrgRel_Results.csv"
    $rows | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Results exported to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# Private helper - Create or update Organization Relationship
# ==========================================================================

function Invoke-EIDMOrgRelationshipSetup {
    <#
    .SYNOPSIS  Creates or updates an Organization Relationship for cross-tenant moves.
    .PARAMETER RemoteTenantId   The GUID of the remote tenant (put in DomainNames).
    .PARAMETER OrgRelName       Desired name for the OrgRelationship.
    .PARAMETER Capability       Inbound or RemoteOutbound.
    .PARAMETER OAuthAppId       (RemoteOutbound only) The migration app Application ID.
    .PARAMETER ScopeGroupName   (RemoteOutbound only) Mail-enabled security group name.
    .OUTPUTS   The OrganizationRelationship object, or $null on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$RemoteTenantId,
        [Parameter(Mandatory)][string]$OrgRelName,
        [Parameter(Mandatory)][ValidateSet("Inbound","RemoteOutbound")][string]$Capability,
        [string]$OAuthAppId,
        [string]$ScopeGroupName
    )

    # ---- Look for existing OrgRel by DomainNames containing the remote tenant ID ----
    $orgrels = @()
    try { $orgrels = @(Get-OrganizationRelationship) } catch {}

    $existingById = $null
    if ($orgrels.Count -gt 0) {
        $existingById = $orgrels | Where-Object {
            $_.DomainNames -contains $RemoteTenantId -or
            ($_.DomainNames -join ";") -like ("*{0}*" -f $RemoteTenantId)
        } | Select-Object -First 1
    }

    # ---- Look by name ----
    $existingByName = $null
    try { $existingByName = Get-OrganizationRelationship -Identity $OrgRelName -ErrorAction SilentlyContinue } catch {}

    # ---- Build common Set parameters ----
    $setParams = @{
        Enabled              = $true
        MailboxMoveEnabled   = $true
        MailboxMoveCapability = $Capability
    }
    if ($Capability -eq "RemoteOutbound") {
        if ($OAuthAppId)      { $setParams.OAuthApplicationId        = $OAuthAppId }
        if ($ScopeGroupName)  { $setParams.MailboxMovePublishedScopes = $ScopeGroupName }
    }

    try {
        if ($existingById) {
            Write-EIDMTag -Tag "INFO" -Text ("Existing OrgRel found referencing tenant ID: {0}" -f $existingById.Name) -Color Gray
            Set-OrganizationRelationship -Identity $existingById.Name @setParams
            Write-EIDMTag -Tag "OK" -Text ("OrgRelationship '{0}' updated ({1})." -f $existingById.Name, $Capability) -Color Green
            return (Get-OrganizationRelationship -Identity $existingById.Name)
        }
        elseif ($existingByName) {
            Write-EIDMTag -Tag "INFO" -Text ("OrgRel '{0}' exists but does not reference tenant ID. Updating..." -f $OrgRelName) -Color Gray

            $domains = @()
            if ($existingByName.DomainNames) { $domains = @($existingByName.DomainNames) }
            $domains = @($domains + $RemoteTenantId) | Where-Object { $_ -and $_.ToString().Trim() -ne "" } | Select-Object -Unique
            $setParams.DomainNames = $domains

            Set-OrganizationRelationship -Identity $existingByName.Name @setParams
            Write-EIDMTag -Tag "OK" -Text ("OrgRelationship '{0}' updated with DomainNames ({1})." -f $OrgRelName, $Capability) -Color Green
            return (Get-OrganizationRelationship -Identity $existingByName.Name)
        }
        else {
            Write-EIDMTag -Tag "INFO" -Text ("Creating new OrgRelationship '{0}' ({1})..." -f $OrgRelName, $Capability) -Color Gray

            $newParams = @{
                Name                  = $OrgRelName
                Enabled               = $true
                MailboxMoveEnabled    = $true
                MailboxMoveCapability = $Capability
                DomainNames           = $RemoteTenantId
            }
            if ($Capability -eq "RemoteOutbound") {
                if ($OAuthAppId)      { $newParams.OAuthApplicationId        = $OAuthAppId }
                if ($ScopeGroupName)  { $newParams.MailboxMovePublishedScopes = $ScopeGroupName }
            }

            $newRel = New-OrganizationRelationship @newParams
            Write-EIDMTag -Tag "OK" -Text ("OrgRelationship '{0}' created ({1})." -f $OrgRelName, $Capability) -Color Green
            return $newRel
        }
    }
    catch {
        Write-EIDMTag -Tag "ERROR" -Text ("OrgRelationship error ({0}): {1}" -f $Capability, $_.Exception.Message) -Color Red
        return $null
    }
}

# ==========================================================================
# Step 03-04 - Build Exchange Mailbox Migration CSV
# ==========================================================================

function Step-03-04-BuildMailboxCsv {
    <#
    .SYNOPSIS  Builds the Exchange mailbox migration CSV from Phase 02
               creation results + Discovery mailbox data.
    .DESCRIPTION
        - Reads Users_OnPrem_CreationResults.csv and Users_CloudOnly_CreationResults.csv
        - Cross-references with EXO-Mailboxes_SOURCE.csv (Discovery) to keep only
          users that have a mailbox in the source tenant.
        - Applies skip rules (missing UPN, creation failed, no mailbox, etc.)
        - Outputs an Exchange migration CSV ready for New-MigrationBatch.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Build Exchange Mailbox Migration CSV"

    $config = $Ctx.Config

    # ----------------------------------------------------------------
    # Idempotency - check if CSV already exists
    # ----------------------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    $existingCsv = @(Get-ChildItem -Path $phaseFolder -Filter "ExchangeMigration_Mailboxes_*.csv" -ErrorAction SilentlyContinue)
    if ($existingCsv.Count -gt 0) {
        $latest = $existingCsv | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        Write-EIDMTag -Tag "INFO" -Text ("Exchange mailbox CSV already exists: {0}" -f $latest.Name) -Color Yellow

        $redo = Read-EIDMSimpleYesNo "Regenerate the Exchange mailbox CSV?"
        if (-not $redo) {
            Write-EIDMTag -Tag "SKIP" -Text "Keeping existing CSV. Step complete." -Color Gray
            return $script:EIDMStatus_Completed
        }
        Write-Host ""
    }

    # ----------------------------------------------------------------
    # 1) Load Phase 02 creation results
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Phase 02 Creation Results"

    $allResults = @()

    $onPremPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_OnPrem_CreationResults.csv"
    $cloudPath  = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_CloudOnly_CreationResults.csv"

    $foundAny = $false

    if (Test-Path $onPremPath) {
        $onPremRows = @(Import-Csv -LiteralPath $onPremPath)
        Write-EIDMTag -Tag "INFO" -Text ("OnPrem creation results loaded: {0} rows" -f $onPremRows.Count) -Color Gray
        foreach ($r in $onPremRows) {
            $allResults += [PSCustomObject]@{
                SourceObjectId  = $r.SourceObjectId
                SourceUPN       = $r.SourceUPN
                TargetUPN       = $r.TargetUPN
                UserKind        = "OnPrem"
                AccountCreated  = $r.AccountCreated
                AlreadyExists   = $r.AccountAlreadyExists
                ExecStatus      = $r.ExecutionStatus
                ExecMessage     = $r.ExecutionMessage
            }
        }
        $foundAny = $true
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "Users_OnPrem_CreationResults.csv not found - skipped." -Color Yellow
    }

    if (Test-Path $cloudPath) {
        $cloudRows = @(Import-Csv -LiteralPath $cloudPath)
        Write-EIDMTag -Tag "INFO" -Text ("CloudOnly creation results loaded: {0} rows" -f $cloudRows.Count) -Color Gray
        foreach ($r in $cloudRows) {
            $allResults += [PSCustomObject]@{
                SourceObjectId  = $r.SourceObjectId
                SourceUPN       = $r.SourceUPN
                TargetUPN       = $r.TargetUPN
                UserKind        = "CloudOnly"
                AccountCreated  = $r.AccountCreated
                AlreadyExists   = $r.AccountAlreadyExists
                ExecStatus      = $r.ExecutionStatus
                ExecMessage     = $r.ExecutionMessage
            }
        }
        $foundAny = $true
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "Users_CloudOnly_CreationResults.csv not found - skipped." -Color Yellow
    }

    if (-not $foundAny) {
        Write-EIDMTag -Tag "ERROR" -Text "No creation results found. Run Phase 02 (Identity Preparation) first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Total creation result rows: {0}" -f @($allResults).Count) -Color Cyan

    # ----------------------------------------------------------------
    # 2) Load Discovery mailbox data
    # ----------------------------------------------------------------
    Write-EIDMSection "Load Discovery Mailbox Data"

    $mbxPath = Join-Path $Ctx.RunRoot "01-Discovery\EXO-Mailboxes_SOURCE.csv"
    if (-not (Test-Path $mbxPath)) {
        Write-EIDMTag -Tag "ERROR" -Text "EXO-Mailboxes_SOURCE.csv not found. Run Discovery first." -Color Red
        return $script:EIDMStatus_Failed
    }

    $mbxRows = @(Import-Csv -LiteralPath $mbxPath)
    Write-EIDMTag -Tag "INFO" -Text ("Source mailboxes loaded: {0}" -f $mbxRows.Count) -Color Gray

    # Build lookup by PrimarySmtpAddress (lowercase)
    $mbxBySmtp = @{}
    foreach ($m in $mbxRows) {
        $smtp = ([string]$m.PrimarySmtpAddress).Trim().ToLowerInvariant()
        if ($smtp) { $mbxBySmtp[$smtp] = $m }
    }

    # Also build lookup by ExternalDirectoryObjectId for stronger matching
    $mbxByObjectId = @{}
    foreach ($m in $mbxRows) {
        $oid = ([string]$m.ExternalDirectoryObjectId).Trim()
        if ($oid) { $mbxByObjectId[$oid] = $m }
    }

    Write-EIDMTag -Tag "INFO" -Text ("Mailbox lookups built - BySmtp:{0}, ByObjectId:{1}" -f $mbxBySmtp.Count, $mbxByObjectId.Count) -Color Gray

    # ----------------------------------------------------------------
    # 3) Build Exchange migration rows
    # ----------------------------------------------------------------
    Write-EIDMSection "Evaluate users for Exchange migration"

    $exoRows = @()

    foreach ($u in $allResults) {

        $sourceUpn = [string]$u.SourceUPN
        $targetUpn = [string]$u.TargetUPN
        $userKind  = [string]$u.UserKind

        $exoStatus = "READY"
        $exoReason = ""
        $mailboxType   = ""
        $emailAddress  = ""

        # -- Rule 1: Missing UPNs => SKIP
        if ([string]::IsNullOrWhiteSpace($sourceUpn) -or [string]::IsNullOrWhiteSpace($targetUpn)) {
            $exoStatus = "SKIP"
            if ([string]::IsNullOrWhiteSpace($sourceUpn) -and [string]::IsNullOrWhiteSpace($targetUpn)) {
                $exoReason = "Missing SourceUPN and TargetUPN"
            }
            elseif ([string]::IsNullOrWhiteSpace($sourceUpn)) {
                $exoReason = "Missing SourceUPN"
            }
            else {
                $exoReason = "Missing TargetUPN"
            }
        }
        # -- Rule 2: Creation not successful and user does not already exist => SKIP
        elseif ($u.AccountCreated -ne "True" -and $u.AlreadyExists -ne "True") {
            $exoStatus = "SKIP"
            $exoReason = "Target account not created (ExecutionStatus={0})" -f $u.ExecStatus
            if (-not [string]::IsNullOrWhiteSpace($u.ExecMessage)) {
                $exoReason = "{0} - {1}" -f $exoReason, $u.ExecMessage
            }
        }

        # -- Rule 3: Check if source user has a mailbox
        if ($exoStatus -eq "READY") {
            $mbx = $null

            # Try matching by ObjectId first
            $srcObjId = [string]$u.SourceObjectId
            if ($srcObjId -and $mbxByObjectId.ContainsKey($srcObjId)) {
                $mbx = $mbxByObjectId[$srcObjId]
            }

            # Fallback: match by SourceUPN as SMTP address
            if (-not $mbx) {
                $srcSmtp = $sourceUpn.Trim().ToLowerInvariant()
                if ($mbxBySmtp.ContainsKey($srcSmtp)) {
                    $mbx = $mbxBySmtp[$srcSmtp]
                }
            }

            if (-not $mbx) {
                $exoStatus = "SKIP"
                $exoReason = "No mailbox found in source tenant"
            }
            else {
                $mailboxType  = [string]$mbx.RecipientTypeDetails
                $emailAddress = [string]$mbx.PrimarySmtpAddress
            }
        }

        # Truncate reason
        if ($exoReason.Length -gt 254) {
            $exoReason = $exoReason.Substring(0, 254)
        }

        # If still READY, EmailAddress = source PrimarySmtpAddress
        if ($exoStatus -eq "READY" -and [string]::IsNullOrWhiteSpace($emailAddress)) {
            $emailAddress = $sourceUpn
        }

        $exoRows += [PSCustomObject]@{
            EmailAddress = $emailAddress
            SourceUPN    = $sourceUpn
            TargetUPN    = $targetUpn
            UserKind     = $userKind
            MailboxType  = $mailboxType
            ExoStatus    = $exoStatus
            ExoReason    = $exoReason
        }
    }

    # ----------------------------------------------------------------
    # 4) Export CSV + Summary
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Exchange Migration CSV"

    $stamp   = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $csvPath = Join-Path $phaseFolder ("ExchangeMigration_Mailboxes_{0}.csv" -f $stamp)
    $sumPath = Join-Path $phaseFolder ("ExchangeMigration_Mailboxes_Summary_{0}.txt" -f $stamp)

    $exoRows |
        Sort-Object ExoStatus, UserKind, SourceUPN |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    $total      = @($exoRows).Count
    $readyCount = @($exoRows | Where-Object { $_.ExoStatus -eq "READY" }).Count
    $skipCount  = @($exoRows | Where-Object { $_.ExoStatus -eq "SKIP" }).Count

    # SKIP reasons breakdown
    $reasons = @(
        $exoRows |
            Where-Object { $_.ExoStatus -eq "SKIP" -and $_.ExoReason -and $_.ExoReason.Trim().Length -gt 0 } |
            Group-Object ExoReason |
            Sort-Object Count -Descending
    )

    # Build summary lines
    $lines = @()
    $lines += "Exchange Mailbox Migration CSV - Summary"
    $lines += ("Generated   : {0}" -f (Get-Date).ToString("s"))
    $lines += ""
    $lines += ("Total rows  : {0}" -f $total)
    $lines += ("READY       : {0}" -f $readyCount)
    $lines += ("SKIP        : {0}" -f $skipCount)
    $lines += ""

    if ($reasons.Count -gt 0) {
        $lines += "Top SKIP reasons:"
        foreach ($r in ($reasons | Select-Object -First 15)) {
            $lines += ("  - [{0}] {1}" -f $r.Count, $r.Name)
        }
        $lines += ""
    }

    $lines += "Outputs:"
    $lines += ("  - Exchange CSV : {0}" -f $csvPath)
    $lines += ("  - Summary TXT  : {0}" -f $sumPath)

    $lines | Set-Content -Path $sumPath -Encoding UTF8

    # ----------------------------------------------------------------
    # 5) Display summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMTag -Tag "OK"   -Text ("Exchange CSV exported: {0}" -f $csvPath) -Color Green
    Write-EIDMTag -Tag "INFO" -Text ("Summary:  Total={0}  READY={1}  SKIP={2}" -f $total, $readyCount, $skipCount) -Color Cyan

    if ($reasons.Count -gt 0) {
        Write-Host ""
        Write-EIDMTag -Tag "INFO" -Text "Top SKIP reasons:" -Color Yellow
        foreach ($r in ($reasons | Select-Object -First 10)) {
            Write-Host ("   [{0}] {1}" -f $r.Count, $r.Name) -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text "Review the CSV before proceeding to the next step." -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text "Remove or mark SKIP any users you do not want to migrate." -Color Cyan

    # Persist CSV path in config for later steps
    if (-not ($config -is [hashtable]) -or -not $config.ContainsKey("ExchangeMigration") -or -not ($config["ExchangeMigration"] -is [hashtable])) {
        $config["ExchangeMigration"] = @{}
    }
    $config["ExchangeMigration"]["MailboxCsvPath"] = $csvPath
    Save-EIDMConfigPsd1 -Config $config -Path $Ctx.ConfigPath

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# Step 03-05 - Check Target Recipients
# ==========================================================================

function Step-03-05-CheckTargetRecipients {
    <#
    .SYNOPSIS  Checks the state of each READY user in the TARGET Exchange Online.
    .DESCRIPTION
        Connects to TARGET EXO and checks each READY TargetUPN:
        - MailUser     (ready for migration)
        - UserMailbox  (unexpected - Exchange license should not be assigned before migration)
        - SoftDeletedMailbox (needs PermanentlyClearPreviousMailboxInfo)
        - NotFound     (not yet provisioned in EXO)
        Exports a TargetRecipientState CSV for review.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Check Target Recipients in Exchange Online"

    $config = $Ctx.Config

    # ----------------------------------------------------------------
    # 1) Locate the Exchange mailbox CSV
    # ----------------------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    # Try config path first, fallback to latest file
    $csvPath = $null
    if ($config -is [hashtable] -and $config.ContainsKey("ExchangeMigration") -and
        $config["ExchangeMigration"] -is [hashtable] -and $config["ExchangeMigration"].ContainsKey("MailboxCsvPath")) {
        $csvPath = $config["ExchangeMigration"]["MailboxCsvPath"]
    }

    if (-not $csvPath -or -not (Test-Path $csvPath)) {
        $latest = Get-ChildItem -Path $phaseFolder -Filter "ExchangeMigration_Mailboxes_*.csv" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $csvPath = $latest.FullName }
    }

    if (-not $csvPath -or -not (Test-Path $csvPath)) {
        Write-EIDMTag -Tag "ERROR" -Text "No Exchange mailbox CSV found. Run step 03-04 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Using mailbox CSV: {0}" -f $csvPath) -Color Gray

    # ----------------------------------------------------------------
    # 2) Load and filter READY rows
    # ----------------------------------------------------------------
    $mailboxes = @(Import-Csv -Path $csvPath)
    $readyRows = @($mailboxes | Where-Object {
        $_.ExoStatus -eq "READY" -and $_.TargetUPN -and $_.TargetUPN.Trim() -ne ""
    })

    Write-EIDMTag -Tag "INFO" -Text ("Total rows: {0}, READY with TargetUPN: {1}" -f $mailboxes.Count, $readyRows.Count) -Color Cyan

    if ($readyRows.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No READY rows with TargetUPN found. Nothing to check." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ----------------------------------------------------------------
    # 3) Connect to TARGET Exchange Online
    # ----------------------------------------------------------------
    Write-EIDMSection "Connect to TARGET Exchange Online"
    Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

    # ----------------------------------------------------------------
    # 4) Check each TargetUPN
    # ----------------------------------------------------------------
    Write-EIDMSection "Check recipient state for each TargetUPN"

    $results = @()
    $countUserMailbox    = 0
    $countMailUser       = 0
    $countSoftDeleted    = 0
    $countNotFound       = 0
    $countOther          = 0

    foreach ($row in $readyRows) {

        $tgtUpn = $row.TargetUPN
        $state      = "Unknown"
        $typeDetail = ""
        $notes      = ""

        Write-Host ("  Checking: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline

        # Try Get-Recipient
        $recip = $null
        try {
            $recip = Get-Recipient -Identity $tgtUpn -ErrorAction Stop
        }
        catch {
            $recip = $null
        }

        if ($recip) {
            $typeDetail = [string]$recip.RecipientTypeDetails

            if ($typeDetail -eq "UserMailbox") {
                $state = "UserMailbox"
                $countUserMailbox++
                $notes = "Unexpected - Exchange license should not be assigned before ExchangeGuid stamping"
            }
            elseif ($typeDetail -eq "MailUser") {
                $state = "MailUser"
                $countMailUser++
            }
            else {
                $state = $typeDetail
                $countOther++
                $notes = "Unexpected recipient type"
            }
        }
        else {
            # Try SoftDeletedMailbox
            $soft = $null
            try {
                $soft = Get-Mailbox -SoftDeletedMailbox -Filter ("UserPrincipalName -eq '{0}'" -f $tgtUpn) -ErrorAction Stop
            }
            catch {
                $soft = $null
            }

            if ($soft) {
                $state      = "SoftDeletedMailbox"
                $typeDetail = "SoftDeletedMailbox"
                $countSoftDeleted++
                $notes = "Needs PermanentlyClearPreviousMailboxInfo"
            }
            else {
                $state      = "NotFound"
                $countNotFound++
                $notes = "No recipient found in TARGET"
            }
        }

        $stateColor = switch ($state) {
            "MailUser"           { "Green" }
            "UserMailbox"        { "Yellow" }
            "SoftDeletedMailbox" { "Yellow" }
            "NotFound"           { "Red" }
            default              { "Gray" }
        }
        Write-Host (" -> {0}" -f $state) -ForegroundColor $stateColor

        $results += [PSCustomObject]@{
            EmailAddress         = $row.EmailAddress
            SourceUPN            = $row.SourceUPN
            TargetUPN            = $tgtUpn
            UserKind             = $row.UserKind
            MailboxType          = $row.MailboxType
            RecipientState       = $state
            RecipientTypeDetails = $typeDetail
            Notes                = $notes
        }
    }

    # ----------------------------------------------------------------
    # 5) Export results
    # ----------------------------------------------------------------
    Write-EIDMSection "Export Target Recipient State"

    $stamp      = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $outputPath = Join-Path $phaseFolder ("TargetRecipientState_{0}.csv" -f $stamp)

    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Target recipient state exported: {0}" -f $outputPath) -Color Green

    # ----------------------------------------------------------------
    # 6) Summary
    # ----------------------------------------------------------------
    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary:  Checked={0}  MailUser={1}  UserMailbox={2}  SoftDeleted={3}  NotFound={4}  Other={5}" -f `
        $readyRows.Count, $countMailUser, $countUserMailbox, $countSoftDeleted, $countNotFound, $countOther) -Color Cyan

    if ($countUserMailbox -gt 0) {
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text ("{0} user(s) have a UserMailbox in TARGET - Exchange license should NOT be assigned before stamping ExchangeGuid." -f $countUserMailbox) -Color Yellow
        Write-EIDMTag -Tag "WARN" -Text "Remove the Exchange license manually or the migration will fail." -Color Yellow
    }

    if ($countSoftDeleted -gt 0) {
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text ("{0} user(s) have a SoftDeletedMailbox in TARGET." -f $countSoftDeleted) -Color Yellow
        Write-EIDMTag -Tag "INFO" -Text "Step 03-06 will clear PreviousMailboxInfo for them." -Color Cyan
    }

    if ($countNotFound -gt 0) {
        Write-Host ""
        Write-EIDMTag -Tag "WARN" -Text ("{0} user(s) were NOT FOUND in TARGET Exchange." -f $countNotFound) -Color Yellow
        Write-EIDMTag -Tag "INFO" -Text "Check that these users exist in the TARGET tenant and have synced properly." -Color Cyan
    }

    # Persist state CSV path in config
    if (-not ($config -is [hashtable]) -or -not $config.ContainsKey("ExchangeMigration") -or -not ($config["ExchangeMigration"] -is [hashtable])) {
        $config["ExchangeMigration"] = @{}
    }
    $config["ExchangeMigration"]["TargetRecipientStateCsvPath"] = $outputPath
    Save-EIDMConfigPsd1 -Config $config -Path $Ctx.ConfigPath

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# Step 03-06 - Prepare Mail Users (SoftDeleted cleanup + MailUser stamping)
# ==========================================================================

function Step-03-06-PrepareMailUsers {
    <#
    .SYNOPSIS  Prepares TARGET users for cross-tenant mailbox migration.
    .DESCRIPTION
        Two sub-steps:
        A) Clear PreviousMailboxInfo for SoftDeletedMailbox recipients (via EXO)
        B) Stamp MailUsers: ExchangeGuid, ExternalEmailAddress, x500 LegacyExchangeDN (via EXO SOURCE+TARGET)
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Prepare Mail Users for Cross-Tenant Migration"

    $config = $Ctx.Config

    # ----------------------------------------------------------------
    # 1) Locate TargetRecipientState CSV
    # ----------------------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "03-ExchangeMigrationPlan"
    Assert-EIDMDirectory -Path $phaseFolder

    $stateCsvPath = $null
    if ($config -is [hashtable] -and $config.ContainsKey("ExchangeMigration") -and
        $config["ExchangeMigration"] -is [hashtable] -and $config["ExchangeMigration"].ContainsKey("TargetRecipientStateCsvPath")) {
        $stateCsvPath = $config["ExchangeMigration"]["TargetRecipientStateCsvPath"]
    }

    if (-not $stateCsvPath -or -not (Test-Path $stateCsvPath)) {
        $latest = Get-ChildItem -Path $phaseFolder -Filter "TargetRecipientState_*.csv" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { $stateCsvPath = $latest.FullName }
    }

    if (-not $stateCsvPath -or -not (Test-Path $stateCsvPath)) {
        Write-EIDMTag -Tag "ERROR" -Text "No TargetRecipientState CSV found. Run step 03-05 first." -Color Red
        return $script:EIDMStatus_Failed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Using state CSV: {0}" -f $stateCsvPath) -Color Gray

    $stateRows = @(Import-Csv -Path $stateCsvPath)
    Write-EIDMTag -Tag "INFO" -Text ("State rows loaded: {0}" -f $stateRows.Count) -Color Gray

    # ================================================================
    # A) Clear PreviousMailboxInfo for SoftDeletedMailbox
    # ================================================================
    $softDeletedRows = @($stateRows | Where-Object { $_.RecipientState -eq "SoftDeletedMailbox" })

    if ($softDeletedRows.Count -gt 0) {
        Write-EIDMSection "A) Clear PreviousMailboxInfo for SoftDeletedMailbox recipients"

        Write-EIDMTag -Tag "INFO" -Text ("{0} user(s) have a SoftDeletedMailbox." -f $softDeletedRows.Count) -Color Yellow

        $doClear = Read-EIDMSimpleYesNo "Clear PreviousMailboxInfo for these users?"
        if (-not $doClear) {
            Write-EIDMTag -Tag "SKIP" -Text "SoftDeleted cleanup skipped by operator." -Color Yellow
        }
        else {
            # Must be connected to TARGET EXO
            Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

            foreach ($row in $softDeletedRows) {
                $tgt = $row.TargetUPN
                try {
                    Set-User -Identity $tgt -PermanentlyClearPreviousMailboxInfo -ErrorAction Stop
                    Write-EIDMTag -Tag "OK" -Text ("Cleared PreviousMailboxInfo: {0}" -f $tgt) -Color Green
                }
                catch {
                    Write-EIDMTag -Tag "ERROR" -Text ("Failed to clear for {0}: {1}" -f $tgt, $_.Exception.Message) -Color Red
                }
            }
        }
    }
    else {
        Write-EIDMTag -Tag "OK" -Text "No SoftDeletedMailbox recipients found - no cleanup needed." -Color Green
    }

    # ================================================================
    # B) Stamp MailUsers: ExchangeGuid, ExternalEmailAddress, x500
    #    ALL users (CloudOnly + OnPrem) are stamped via Set-MailUser.
    #    ExchangeGuid/ArchiveGuid/ExternalEmailAddress work for DirSync objects.
    #    Only EmailAddresses (x500/proxyAddresses) may fail for DirSync objects
    #    with "on-premises mastered" error - handled reactively below.
    # ================================================================
    $allMailUserRows = @($stateRows | Where-Object {
        $_.RecipientState -eq "MailUser" -or $_.RecipientState -eq "NotFound"
    })

    Write-EIDMSection "B) Stamp MailUsers with SOURCE mailbox attributes"

    $onPremX500Tasks = @()

    if ($allMailUserRows.Count -eq 0) {
        Write-EIDMTag -Tag "WARN" -Text "No MailUser/NotFound rows to stamp." -Color Yellow
    }
    else {
        $onPremCount  = @($allMailUserRows | Where-Object { $_.UserKind -eq "OnPrem" }).Count
        $cloudCount   = $allMailUserRows.Count - $onPremCount
        Write-EIDMTag -Tag "INFO" -Text ("{0} user(s) to stamp ({1} CloudOnly, {2} OnPrem)." -f $allMailUserRows.Count, $cloudCount, $onPremCount) -Color Cyan
        if ($onPremCount -gt 0) {
            Write-EIDMTag -Tag "INFO" -Text "OnPrem users: ExchangeGuid/ExternalEmailAddress stamped via EXO. x500 may require on-prem AD fallback." -Color Gray
        }

        $doStamp = Read-EIDMSimpleYesNo "Stamp ExchangeGuid, ExternalEmailAddress, and x500 on TARGET MailUsers?"
        if (-not $doStamp) {
            Write-EIDMTag -Tag "SKIP" -Text "MailUser stamping skipped by operator." -Color Yellow
        }
        else {
            # --- Collect SOURCE mailbox data ---
            Write-EIDMSection "Collect SOURCE mailbox data"

            # Disconnect TARGET first, then connect SOURCE
            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            $script:EIDMExoState = @{ SourceConnected = $false; TargetConnected = $false }

            Ensure-EIDMExchangeSourceConnection -Ctx $Ctx

            $sourceInfo = @{}
            foreach ($row in $allMailUserRows) {
                $srcUpn = $row.SourceUPN
                $mbx = $null

                # Try by UPN first
                try {
                    $mbx = @(Get-Mailbox -Filter ("UserPrincipalName -eq '{0}'" -f $srcUpn) -ErrorAction Stop)
                    if ($mbx.Count -eq 0) { $mbx = $null }
                    elseif ($mbx.Count -eq 1) { $mbx = $mbx[0] }
                }
                catch { $mbx = $null }

                # Fallback: try by PrimarySmtpAddress (handles UPN mismatch for on-prem synced users)
                if (-not $mbx) {
                    try {
                        $mbx = @(Get-Mailbox -Filter ("PrimarySmtpAddress -eq '{0}'" -f $srcUpn) -ErrorAction Stop)
                        if ($mbx.Count -eq 0) { $mbx = $null }
                        elseif ($mbx.Count -eq 1) { $mbx = $mbx[0] }
                    }
                    catch { $mbx = $null }
                }

                # Fallback: try by alias (username part before @)
                if (-not $mbx) {
                    $alias = ($srcUpn -split '@')[0]
                    try {
                        $mbx = @(Get-Mailbox -Filter ("Alias -eq '{0}'" -f $alias) -ErrorAction Stop)
                        if ($mbx.Count -eq 0) { $mbx = $null }
                        elseif ($mbx.Count -eq 1) {
                            $mbx = $mbx[0]
                            Write-EIDMTag -Tag "WARN" -Text ("  Found by alias '{0}' -> UPN={1}" -f $alias, $mbx.UserPrincipalName) -Color Yellow
                        }
                        else {
                            Write-EIDMTag -Tag "WARN" -Text ("  Multiple mailboxes match alias '{0}'. Skipping." -f $alias) -Color Yellow
                            $mbx = $null
                        }
                    }
                    catch { $mbx = $null }
                }

                if ($mbx) {
                    $sourceInfo[$srcUpn.ToLowerInvariant()] = $mbx
                    Write-EIDMTag -Tag "OK" -Text ("SOURCE mailbox found: {0} (ExoUPN={1})" -f $srcUpn, $mbx.UserPrincipalName) -Color Green
                }
                else {
                    Write-EIDMTag -Tag "ERROR" -Text ("SOURCE mailbox NOT found: {0} (tried UPN, PrimarySmtpAddress, Alias)" -f $srcUpn) -Color Red
                }
            }

            # --- Switch to TARGET ---
            Write-EIDMSection "Stamp TARGET MailUsers"

            try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
            $script:EIDMExoState = @{ SourceConnected = $false; TargetConnected = $false }

            Ensure-EIDMExchangeTargetConnection -Ctx $Ctx

            # Derive TARGET mail routing domain (*.mail.onmicrosoft.com)
            $targetOnMsDomain  = $Ctx.Config.Tenants.Target.TenantIdOrDomain
            $targetMailDomain  = $targetOnMsDomain -replace '\.onmicrosoft\.com$', '.mail.onmicrosoft.com'
            Write-EIDMTag -Tag "INFO" -Text ("TARGET mail routing domain: {0}" -f $targetMailDomain) -Color Gray

            $stampResults = @()
            $stampOk      = 0
            $stampSkip    = 0
            $stampFail    = 0

            foreach ($row in $allMailUserRows) {
                $tgtUpn = $row.TargetUPN
                $srcUpn = $row.SourceUPN
                $srcKey = $srcUpn.ToLowerInvariant()

                # For MailUser state, print inline; for NotFound, output is handled inside the block
                if ($row.RecipientState -ne "NotFound") {
                    Write-Host ("  Stamping: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline
                }

                if (-not $sourceInfo.ContainsKey($srcKey)) {
                    if ($row.RecipientState -eq "NotFound") {
                        Write-Host ("  Stamping: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline
                    }
                    Write-Host " -> SKIP (no source data)" -ForegroundColor Yellow
                    $stampSkip++
                    $stampResults += [PSCustomObject]@{
                        TargetUPN        = $tgtUpn
                        SourceUPN        = $srcUpn
                        Status           = "Skipped"
                        Reason           = "No source mailbox data"
                        ExchangeGuid     = ""
                        LegacyExchangeDN = ""
                    }
                    continue
                }

                $mbx = $sourceInfo[$srcKey]

                # Extract routing address (*.mail.onmicrosoft.com)
                $emailAddrs = $mbx.EmailAddresses
                if ($emailAddrs -is [array] -or $emailAddrs -is [System.Collections.IEnumerable]) {
                    $emailAddrsStr = ($emailAddrs | ForEach-Object { [string]$_ }) -join ";"
                }
                else {
                    $emailAddrsStr = [string]$emailAddrs
                }

                $routingAddr = Get-EIDMSourceRoutingAddress `
                    -EmailAddresses     $emailAddrsStr `
                    -PrimarySmtpAddress ([string]$mbx.PrimarySmtpAddress)

                $extAddr = "SMTP:{0}" -f $routingAddr
                $legDn   = [string]$mbx.LegacyExchangeDN

                try {
                    # For NotFound users, verify EXO directory awareness first
                    if ($row.RecipientState -eq "NotFound") {
                        Write-EIDMTag -Tag "INFO" -Text ("  Checking EXO directory for: {0}" -f $tgtUpn) -Color Gray

                        $exoUser = $null
                        try { $exoUser = Get-User -Identity $tgtUpn -ErrorAction Stop } catch {}

                        if (-not $exoUser) {
                            Write-Host ("  Stamping: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline
                            Write-Host " -> SKIP (not yet in EXO directory)" -ForegroundColor Yellow
                            Write-EIDMTag -Tag "WARN" -Text "  User not yet provisioned in Exchange Online. Wait for Entra ID -> EXO sync (can take minutes to hours) and re-run." -Color Yellow
                            $stampSkip++
                            $stampResults += [PSCustomObject]@{
                                TargetUPN        = $tgtUpn
                                SourceUPN        = $srcUpn
                                Status           = "Skipped"
                                Reason           = "Not yet provisioned in EXO directory - wait for sync"
                                ExchangeGuid     = [string]$mbx.ExchangeGuid
                                LegacyExchangeDN = $legDn
                            }
                            continue
                        }

                        Write-EIDMTag -Tag "OK" -Text ("  Found in EXO directory: {0} (RecipientType={1})" -f $tgtUpn, $exoUser.RecipientType) -Color Green
                    }

                    # ---- Step 1: Stamp core attributes ----
                    # OnPrem (DirSync) users: ExternalEmailAddress/PrimarySmtpAddress are mastered on-prem
                    #  -> only stamp ExchangeGuid via EXO (works for DirSync objects)
                    # CloudOnly users: stamp all three together
                    $isOnPrem = ($row.UserKind -eq "OnPrem")

                    if ($isOnPrem) {
                        # ExchangeGuid only - ExternalEmailAddress/PrimarySmtpAddress already set on-prem
                        Set-MailUser -Identity $tgtUpn -ExchangeGuid $mbx.ExchangeGuid -ErrorAction Stop
                        Write-EIDMTag -Tag "INFO" -Text ("  OnPrem user: ExchangeGuid stamped via EXO. ExternalEmailAddress/PrimarySmtpAddress managed on-prem.") -Color Gray
                    }
                    else {
                        # CloudOnly: stamp ExchangeGuid + ExternalEmailAddress + PrimarySmtpAddress
                        # IMPORTANT: PrimarySmtpAddress MUST be set together with ExternalEmailAddress,
                        # otherwise ExternalEmailAddress overwrites PrimarySmtpAddress with the source domain.
                        # NOTE: PrimarySmtpAddress and EmailAddresses cannot be used in the same call.
                        $setParams = @{
                            Identity             = $tgtUpn
                            ExchangeGuid         = $mbx.ExchangeGuid
                            ExternalEmailAddress = $extAddr
                            PrimarySmtpAddress   = $tgtUpn
                        }
                        Set-MailUser @setParams -ErrorAction Stop
                    }

                    # ---- Step 2: Add x500 + target routing address (separate call) ----
                    # For DirSync objects, EmailAddresses may be "on-premises mastered" and fail.
                    # In that case, queue the x500 task for on-prem AD execution.
                    $addAddresses = @()
                    if ($legDn) {
                        $addAddresses += "x500:{0}" -f $legDn
                    }

                    # Add target mail routing address (alias@target.mail.onmicrosoft.com)
                    $tgtAlias = ($tgtUpn -split '@')[0]
                    $tgtRoutingAddr = "{0}@{1}" -f $tgtAlias, $targetMailDomain
                    $addAddresses += "smtp:{0}" -f $tgtRoutingAddr

                    $x500Queued = $false
                    if ($addAddresses.Count -gt 0) {
                        try {
                            Set-MailUser -Identity $tgtUpn -EmailAddresses @{Add=$addAddresses} -ErrorAction Stop
                        }
                        catch {
                            $errMsg = $_.Exception.Message
                            if ($errMsg -match 'on-premises mastered|directory sync') {
                                # DirSync object - x500/proxyAddresses must be set on-prem
                                Write-EIDMTag -Tag "WARN" -Text ("  EmailAddresses blocked by DirSync - queuing x500 for on-prem AD stamping") -Color Yellow
                                $archGuid = [string]$mbx.ArchiveGuid
                                $hasArchive = ($archGuid -and $archGuid -ne "00000000-0000-0000-0000-000000000000")
                                $onPremX500Tasks += [PSCustomObject]@{
                                    TargetUPN        = $tgtUpn
                                    SourceUPN        = $srcUpn
                                    ExchangeGuid     = [string]$mbx.ExchangeGuid
                                    ArchiveGuid      = $(if ($hasArchive) { $archGuid } else { "" })
                                    LegacyExchangeDN = $legDn
                                    RoutingAddress   = $tgtRoutingAddr
                                }
                                $x500Queued = $true
                            }
                            else {
                                throw  # Re-throw non-DirSync errors
                            }
                        }
                    }

                    Write-Host ("  Stamping: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline
                    if ($x500Queued) {
                        Write-Host " -> OK (x500 queued for on-prem)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host " -> OK" -ForegroundColor Green
                    }

                    # --- Clean source-domain SMTP proxy addresses from target MailUser ---
                    # Skip for OnPrem/DirSync users - their proxyAddresses are mastered on-prem.
                    # All SMTP proxyAddresses on a target MailUser MUST belong to target tenant domains.
                    # Source-domain proxies (e.g. @mamotron.onmicrosoft.com) cause MRS move failures.
                    if (-not $isOnPrem) {
                        $sourceDomain = $Ctx.Config.Tenants.Source.TenantIdOrDomain   # e.g. mamotron.onmicrosoft.com
                        $sourceBaseName = ($sourceDomain -replace '\.onmicrosoft\.com$', '')
                        $currentMailUser = Get-MailUser -Identity $tgtUpn -ErrorAction SilentlyContinue
                        if ($currentMailUser) {
                            $badAddresses = @()
                            foreach ($addr in $currentMailUser.EmailAddresses) {
                                $addrStr = [string]$addr
                                # Match any smtp/SMTP address containing the source onmicrosoft domain
                                if ($addrStr -match '^(smtp|SMTP):' -and $addrStr -like "*@$sourceDomain") {
                                    $badAddresses += $addrStr
                                }
                                # Also match source mail routing domain (*.mail.onmicrosoft.com)
                                $sourceMailDomain = "{0}.mail.onmicrosoft.com" -f $sourceBaseName
                                if ($addrStr -match '^(smtp|SMTP):' -and $addrStr -like "*@$sourceMailDomain") {
                                    $badAddresses += $addrStr
                                }
                            }
                            if ($badAddresses.Count -gt 0) {
                                Write-EIDMTag -Tag "INFO" -Text ("  Removing {0} source-domain proxy address(es): {1}" -f $badAddresses.Count, ($badAddresses -join ', ')) -Color Yellow
                                Set-MailUser -Identity $tgtUpn -EmailAddresses @{Remove=$badAddresses} -ErrorAction Stop
                                Write-EIDMTag -Tag "OK" -Text "  Source-domain proxies removed" -Color Green
                            }
                        }
                    }

                    $stampOk++
                    $stampResults += [PSCustomObject]@{
                        TargetUPN        = $tgtUpn
                        SourceUPN        = $srcUpn
                        Status           = "Success"
                        Reason           = ""
                        ExchangeGuid     = [string]$mbx.ExchangeGuid
                        LegacyExchangeDN = $legDn
                    }
                }
                catch {
                    if ($row.RecipientState -ne "NotFound") {
                        # Already printed "Stamping: ..." with NoNewline above
                    }
                    else {
                        Write-Host ("  Stamping: {0}" -f $tgtUpn) -ForegroundColor Gray -NoNewline
                    }
                    Write-Host " -> FAILED" -ForegroundColor Red
                    Write-EIDMTag -Tag "ERROR" -Text ("  {0}" -f $_.Exception.Message) -Color Red
                    $stampFail++
                    $stampResults += [PSCustomObject]@{
                        TargetUPN        = $tgtUpn
                        SourceUPN        = $srcUpn
                        Status           = "Failed"
                        Reason           = $_.Exception.Message
                        ExchangeGuid     = [string]$mbx.ExchangeGuid
                        LegacyExchangeDN = $legDn
                    }
                }
            }

            # Export stamp results
            $stampCsvPath = Join-Path $phaseFolder ("MailUserStamping_{0}.csv" -f (Get-Date).ToString("yyyyMMdd_HHmmss"))
            $stampResults | Export-Csv -Path $stampCsvPath -NoTypeInformation -Encoding UTF8

            Write-Host ""
            Write-EIDMTag -Tag "OK"   -Text ("Stamping results: {0}" -f $stampCsvPath) -Color Green
            Write-EIDMTag -Tag "INFO" -Text ("Success={0}  Skipped={1}  Failed={2}" -f $stampOk, $stampSkip, $stampFail) -Color Cyan

            if ($stampSkip -gt 0) {
                Write-Host ""
                Write-EIDMTag -Tag "WARN" -Text ("{0} user(s) skipped - not yet provisioned in EXO directory." -f $stampSkip) -Color Yellow
                Write-EIDMTag -Tag "INFO" -Text "Wait for the Entra ID -> Exchange Online sync to complete, then re-run steps 03-05 and 03-06." -Color Cyan
                Write-EIDMTag -Tag "INFO" -Text "Sync typically takes 15-60 minutes but can take up to 24 hours." -Color Cyan
            }
        }
    }

    # ================================================================
    # C) Stamp x500 in on-prem AD for DirSync users whose
    #    EmailAddresses could not be modified via Set-MailUser.
    #    Uses Set-ADUser directly (like old script 26).
    #    Falls back to script export if AD module is not available.
    # ================================================================
    if ($onPremX500Tasks.Count -gt 0) {
        Write-EIDMSection "C) Stamp x500 in on-prem AD for DirSync users"
        Write-EIDMTag -Tag "INFO" -Text ("{0} user(s) need x500/proxyAddresses set in TARGET on-premises AD." -f $onPremX500Tasks.Count) -Color Cyan

        # Check if ActiveDirectory module is available
        $adModuleAvailable = $false
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $null = Get-ADDomain -ErrorAction Stop
            $adModuleAvailable = $true
            Write-EIDMTag -Tag "OK" -Text "ActiveDirectory module loaded and domain reachable." -Color Green
        }
        catch {
            Write-EIDMTag -Tag "WARN" -Text ("ActiveDirectory module not available or domain not reachable: {0}" -f $_.Exception.Message) -Color Yellow
        }

        if ($adModuleAvailable) {
            # Direct AD stamping
            $adOk   = 0
            $adSkip = 0
            $adFail = 0

            foreach ($task in $onPremX500Tasks) {
                $upn  = $task.TargetUPN
                $x500 = "x500:{0}" -f $task.LegacyExchangeDN

                Write-Host ("    {0}" -f $upn) -ForegroundColor Gray -NoNewline

                if (-not $task.LegacyExchangeDN) {
                    Write-Host " -> SKIP (no LegacyExchangeDN)" -ForegroundColor Yellow
                    $adSkip++
                    continue
                }

                try {
                    # Find user by UPN
                    $adUser = Get-ADUser -Filter ("UserPrincipalName -eq '{0}'" -f $upn) -Properties proxyAddresses -ErrorAction Stop

                    if (-not $adUser) {
                        # Fallback by SamAccountName
                        $sam = ($upn -split '@')[0]
                        $adUser = Get-ADUser -Filter ("SamAccountName -eq '{0}'" -f $sam) -Properties proxyAddresses -ErrorAction Stop
                    }

                    if (-not $adUser) {
                        Write-Host " -> SKIP (AD user not found)" -ForegroundColor Yellow
                        $adSkip++
                        continue
                    }

                    # Check if x500 already present
                    $needsUpdate = $false

                    if ($adUser.proxyAddresses -notcontains $x500) {
                        $adUser.proxyAddresses.Add($x500)
                        $needsUpdate = $true
                    }

                    # Also add target routing address (smtp:alias@target.mail.onmicrosoft.com)
                    # Required by MRS for cross-tenant migration
                    $routingSmtp = "smtp:{0}" -f $task.RoutingAddress
                    if ($task.RoutingAddress -and $adUser.proxyAddresses -notcontains $routingSmtp) {
                        $adUser.proxyAddresses.Add($routingSmtp)
                        $needsUpdate = $true
                    }

                    if (-not $needsUpdate) {
                        Write-Host " -> SKIP (x500 + routing already present)" -ForegroundColor Yellow
                        $adSkip++
                        continue
                    }

                    # Write changes
                    Set-ADUser -Instance $adUser -ErrorAction Stop
                    Write-Host " -> OK" -ForegroundColor Green
                    if ($task.RoutingAddress) {
                        Write-EIDMTag -Tag "INFO" -Text ("      x500 + routing ({0}) added" -f $routingSmtp) -Color Gray
                    }
                    $adOk++
                }
                catch {
                    Write-Host " -> FAILED" -ForegroundColor Red
                    Write-EIDMTag -Tag "ERROR" -Text ("      {0}" -f $_.Exception.Message) -Color Red
                    $adFail++
                }
            }

            Write-Host ""
            Write-EIDMTag -Tag "INFO" -Text ("AD stamping: OK={0}  Skipped={1}  Failed={2}" -f $adOk, $adSkip, $adFail) -Color Cyan

            if ($adOk -gt 0) {
                Write-Host ""
                Write-EIDMTag -Tag "WARN" -Text "Trigger AAD Connect delta sync: Start-ADSyncSyncCycle -PolicyType Delta" -Color Yellow
                Write-EIDMTag -Tag "WARN" -Text "Wait for sync to complete before creating migration batches." -Color Yellow
            }
        }
        else {
            # Fallback: export script for manual execution
            Write-EIDMTag -Tag "WARN" -Text "Cannot stamp AD directly. Exporting commands for manual execution." -Color Yellow

            $onPremCommands = @()
            $onPremCommands += "# x500 stamping - run on a machine with ActiveDirectory module"
            $onPremCommands += "Import-Module ActiveDirectory"
            $onPremCommands += ""

            foreach ($task in $onPremX500Tasks) {
                if ($task.LegacyExchangeDN) {
                    $onPremCommands += '# {0}' -f $task.TargetUPN
                    $onPremCommands += '$user = Get-ADUser -Filter "UserPrincipalName -eq ''{0}''" -Properties proxyAddresses' -f $task.TargetUPN
                    $onPremCommands += '$x500 = "x500:{0}"' -f $task.LegacyExchangeDN
                    $onPremCommands += 'if ($user.proxyAddresses -notcontains $x500) { $user.proxyAddresses.Add($x500) }'
                    if ($task.RoutingAddress) {
                        $onPremCommands += '$routing = "smtp:{0}"' -f $task.RoutingAddress
                        $onPremCommands += 'if ($user.proxyAddresses -notcontains $routing) { $user.proxyAddresses.Add($routing) }'
                    }
                    $onPremCommands += 'Set-ADUser -Instance $user; Write-Host "OK: {0}"' -f $task.TargetUPN
                    $onPremCommands += ""
                }
                Write-Host ("    {0}: x500={1}" -f $task.TargetUPN, $task.LegacyExchangeDN) -ForegroundColor DarkGray
            }

            $onPremCommands += "# Then run: Start-ADSyncSyncCycle -PolicyType Delta"

            $onPremScriptPath = Join-Path $phaseFolder ("OnPrem_x500_Commands_{0}.ps1" -f (Get-Date).ToString("yyyyMMdd_HHmmss"))
            $onPremCommands | Out-File -FilePath $onPremScriptPath -Encoding utf8

            Write-Host ""
            Write-EIDMTag -Tag "OK"   -Text ("Fallback script exported: {0}" -f $onPremScriptPath) -Color Green
            Write-EIDMTag -Tag "WARN" -Text "Run this script on a DC or machine with AD module, then trigger AAD Connect sync." -Color Yellow
        }
    }

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text "Step 03-06 PrepareMailUsers completed." -Color Green

    return $script:EIDMStatus_Completed
}

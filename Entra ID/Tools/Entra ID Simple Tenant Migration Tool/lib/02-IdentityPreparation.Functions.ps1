function Step-02-01-BuildUsersOnPremProvisioningPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Users_OnPrem_ProvisioningPlan"

    # --------------------------------------------------
    # Context shortcuts (do NOT use global $config)
    # --------------------------------------------------
    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    # Ensure OnPremIdentity section exists in config (safety)
    if (-not $config.ContainsKey("OnPremIdentity")) {
        $config.OnPremIdentity = @{}
    }
    if (-not $config.OnPremIdentity.ContainsKey("LastUsedTargetOU")) {
        $config.OnPremIdentity.LastUsedTargetOU = ""
    }

    # --------------------------------------------------
    # Load Discovery Users
    # --------------------------------------------------
    $usersPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraUsers_SOURCE.csv"
    if (-not (Test-Path $usersPath)) {
        throw "EntraUsers_SOURCE.csv not found. Run Discovery first."
    }

    $users = Import-Csv $usersPath

    # Filter Synced users only
    $synced = $users | Where-Object { $_.OnPremisesSyncEnabled -eq "True" }

    if (-not $synced -or $synced.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No synced users detected." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Synced users detected: {0}" -f $synced.Count) -Color Cyan
    Write-Host ""

    # --------------------------------------------------
    # Ask Target OU (interactive)
    # --------------------------------------------------
    $defaultOU = [string]$config.OnPremIdentity.LastUsedTargetOU
    if (-not $defaultOU) { $defaultOU = "" }

    $prompt = "Enter Target OU for synced users"
    if ($defaultOU) {
        $inputOU = Read-Host ("{0} [{1}]" -f $prompt, $defaultOU)
        if ([string]::IsNullOrWhiteSpace($inputOU)) { $inputOU = $defaultOU }
    }
    else {
        $inputOU = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($inputOU)) {
            throw "Target OU cannot be empty."
        }
    }

    # Persist last used OU in config.psd1
    $config.OnPremIdentity.LastUsedTargetOU = $inputOU
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    # --------------------------------------------------
    # Derive SOURCE technical mail routing domain from EntraDomains_SOURCE.csv
    # Use the '*.mail.onmicrosoft.com' domain (prefer IsVerified=True)
    # --------------------------------------------------
    $domainsPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraDomains_SOURCE.csv"
    if (-not (Test-Path $domainsPath)) {
        throw "EntraDomains_SOURCE.csv not found. Run Discovery first."
    }

    $domains = Import-Csv $domainsPath

    $mailDomains = $domains | Where-Object {
        $_.DomainName -and $_.DomainName.ToLower().EndsWith(".mail.onmicrosoft.com")
    }

    $mailDomains = @($mailDomains)
    if (-not $mailDomains -or $mailDomains.Count -eq 0) {
        throw "No '*.mail.onmicrosoft.com' domain found in EntraDomains_SOURCE.csv. Cannot compute targetAddress."
    }

    $technicalMailDomain = ($mailDomains | Where-Object { $_.IsVerified -eq "True" } | Select-Object -First 1).DomainName
    if (-not $technicalMailDomain) {
        $technicalMailDomain = ($mailDomains | Select-Object -First 1).DomainName
    }

    Write-EIDMTag -Tag "INFO" -Text ("SOURCE technical mail domain detected: {0}" -f $technicalMailDomain) -Color Cyan
    Write-Host ""

    # --------------------------------------------------
    # Load Exchange discovery (mailboxes) to detect who has a mailbox in SOURCE
    # Matching priority:
    #   1) EntraUsers.Id  <-> EXO-Mailboxes.ExternalDirectoryObjectId
    # Fallbacks:
    #   2) EXO PrimarySmtpAddress <-> EntraUsers.UserPrincipalName
    #   3) EXO PrimarySmtpAddress <-> EntraUsers.Mail
    # --------------------------------------------------
    $mailboxesPath = Join-Path $Ctx.RunRoot "01-Discovery\EXO-Mailboxes_SOURCE.csv"
    if (-not (Test-Path $mailboxesPath)) {
        throw "EXO-Mailboxes_SOURCE.csv not found. Run Discovery first."
    }

    $mailboxes = Import-Csv $mailboxesPath

    $mbxByObjectId     = @{}  # ExternalDirectoryObjectId -> mailbox row
    $mbxByPrimarySmtp  = @{}  # PrimarySmtpAddress (lower) -> mailbox row

    foreach ($m in $mailboxes) {

        if ($m.ExternalDirectoryObjectId) {
            $k = $m.ExternalDirectoryObjectId.Trim().ToLower()
            if (-not $mbxByObjectId.ContainsKey($k)) { $mbxByObjectId[$k] = $m }
        }

        if ($m.PrimarySmtpAddress) {
            $k2 = $m.PrimarySmtpAddress.Trim().ToLower()
            if (-not $mbxByPrimarySmtp.ContainsKey($k2)) { $mbxByPrimarySmtp[$k2] = $m }
        }
    }

    # --------------------------------------------------
    # Extract distinct UPN suffixes from synced users (source)
    # Use OnPremisesUserPrincipalName if present, else UserPrincipalName
    # --------------------------------------------------
    $suffixes = $synced | ForEach-Object {
        $upn = if ($_.OnPremisesUserPrincipalName) { $_.OnPremisesUserPrincipalName } else { $_.UserPrincipalName }
        if ($upn -and $upn.Contains("@")) { $upn.Split("@")[1] } else { "" }
    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique

    $suffixDecisions = @{}  # key = SourceSuffix, value = @{ Target=""; Status="Ready|Blocked" }

    foreach ($suffix in $suffixes) {

        Write-Host ""
        Write-EIDMTag -Tag "SUFFIX" -Text $suffix -Color Yellow

        do {
            $use = Read-Host "Use this suffix in target AD? (Y/N)"
            if ([string]::IsNullOrWhiteSpace($use)) { $use = "N" }  # default behavior
            $use = $use.Trim().ToUpper()
        } while ($use -notin @("Y","N"))

        if ($use -eq "Y") {
            $targetSuffix = $suffix
        }
        else {
            $targetSuffix = Read-Host "Enter target suffix to use instead (e.g. newcorp.com)"
            if ([string]::IsNullOrWhiteSpace($targetSuffix)) {
                $suffixDecisions[$suffix] = @{ Target = ""; Status = "Blocked" }
                continue
            }
            $targetSuffix = $targetSuffix.Trim()
        }

        # Check if suffix exists in AD
        $forest = Get-ADForest
        $exists = $false

        # forest.UPNSuffixes is the authoritative list; RootDomain can also be used as a suffix sometimes
        if ($forest.UPNSuffixes -contains $targetSuffix -or $forest.RootDomain -eq $targetSuffix) {
            $exists = $true
        }

        if (-not $exists) {
            $create = Read-Host ("Target AD does not contain UPN suffix '{0}'. Create it now? (Y/N)" -f $targetSuffix)
            $create = ($create | ForEach-Object { $_.Trim() })

            if ($create.ToUpper() -eq "Y") {
                Set-ADForest -Identity $forest.Name -UPNSuffixes @{ Add = $targetSuffix }
                # Re-check (fail-fast if not added)
                $forest2 = Get-ADForest
                if ($forest2.UPNSuffixes -contains $targetSuffix -or $forest2.RootDomain -eq $targetSuffix) {
                    $exists = $true
                }
            }
        }

        if (-not $exists) {
            $suffixDecisions[$suffix] = @{ Target = $targetSuffix; Status = "Blocked" }
        }
        else {
            $suffixDecisions[$suffix] = @{ Target = $targetSuffix; Status = "Ready" }
        }
    }

    # --------------------------------------------------
    # Build Provisioning Plan (single output file)
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    # Mailbox matching counters (for visibility)
    $mbxCount_ObjectId = 0
    $mbxCount_UPN      = 0
    $mbxCount_Mail     = 0
    $mbxCount_None     = 0

    foreach ($u in $synced) {

        $sourceUPN = if ($u.OnPremisesUserPrincipalName) { $u.OnPremisesUserPrincipalName } else { $u.UserPrincipalName }
        $sourceSuffix = if ($sourceUPN -and $sourceUPN.Contains("@")) { $sourceUPN.Split("@")[1] } else { "" }

        $localPart = [string]$u.OnPremisesSamAccountName

        # Detect mailbox in SOURCE (reliable matching first)
        $mbxMatchedBy = "None"
        $hasMailbox = $false
        $sourcePrimarySmtp = ""

        $userIdKey = ""
        if ($u.Id) { $userIdKey = $u.Id.Trim().ToLower() }

        if ($userIdKey -and $mbxByObjectId.ContainsKey($userIdKey)) {
            $hasMailbox = $true
            $mbxMatchedBy = "ObjectId"
            $sourcePrimarySmtp = [string]$mbxByObjectId[$userIdKey].PrimarySmtpAddress
        }
        else {
            $upnKey = ""
            if ($u.UserPrincipalName) { $upnKey = $u.UserPrincipalName.Trim().ToLower() }

            $mailKey = ""
            if ($u.Mail) { $mailKey = $u.Mail.Trim().ToLower() }

            # Fallback 1: PrimarySmtpAddress <-> UPN
            if ($upnKey -and $mbxByPrimarySmtp.ContainsKey($upnKey)) {
                $hasMailbox = $true
                $mbxMatchedBy = "UPN"
                $sourcePrimarySmtp = [string]$mbxByPrimarySmtp[$upnKey].PrimarySmtpAddress
            }
            # Fallback 2: PrimarySmtpAddress <-> Mail
            elseif ($mailKey -and $mbxByPrimarySmtp.ContainsKey($mailKey)) {
                $hasMailbox = $true
                $mbxMatchedBy = "Mail"
                $sourcePrimarySmtp = [string]$mbxByPrimarySmtp[$mailKey].PrimarySmtpAddress
            }
        }

        switch ($mbxMatchedBy) {
            "ObjectId" { $mbxCount_ObjectId++ }
            "UPN"      { $mbxCount_UPN++ }
            "Mail"     { $mbxCount_Mail++ }
            default    { $mbxCount_None++ }
        }

        $mailUserAction = "None"
        $targetAddressProposed = ""
        if ($hasMailbox) {
            $mailUserAction = "EnableMailUser"
            # IMPORTANT: routing to SOURCE technical domain while mailbox stays in SOURCE
            $targetAddressProposed = ("{0}@{1}" -f $localPart, $technicalMailDomain)
        }

        # If samAccountName is missing, we block (do not invent)
        if ([string]::IsNullOrWhiteSpace($localPart)) {
            $plan.Add([PSCustomObject]@{
                SourceObjectId                 = $u.Id
                SourceUPN                      = $u.UserPrincipalName
                SourceDisplayName              = $u.DisplayName
                SourceOnPremisesSamAccountName = $u.OnPremisesSamAccountName
                SourceUPNSuffix                = $sourceSuffix
                TargetUPNSuffix_Selected        = ""
                ProvisioningAction              = "Blocked"
                TargetOU_Proposed               = $inputOU
                TargetSamAccountName_Proposed   = ""
                TargetUPN_Proposed              = ""
                SourceHasMailbox                = if ($hasMailbox) { "True" } else { "False" }
                SourcePrimarySmtpAddress        = $sourcePrimarySmtp
                MailUserAction                  = $mailUserAction
                TargetAddress_Proposed          = $targetAddressProposed
                TargetGivenName_Proposed = $u.GivenName
                TargetSurname_Proposed = $u.Surname
                TargetDisplayName_Proposed= $u.DisplayName
                TargetMail_Proposed = $u.Mail
                TargetEmployeeId_Proposed = $u.EmployeeId
                TargetDepartment_Proposed = $u.Department
                TargetJobTitle_Proposed = $u.JobTitle
                TargetCompanyName_Proposed= $u.CompanyName
            })
            continue
        }

        $decision = $suffixDecisions[$sourceSuffix]
        if (-not $decision) {
            $decision = @{ Target = ""; Status = "Blocked" }
        }

        $status = $decision.Status
        $targetSuffix = [string]$decision.Target

        $targetUPN = ""
        if ($status -eq "Ready" -and -not [string]::IsNullOrWhiteSpace($targetSuffix)) {
            $targetUPN = ("{0}@{1}" -f $localPart, $targetSuffix)
        }

        $plan.Add([PSCustomObject]@{
            SourceObjectId                 = $u.Id
            SourceUPN                      = $u.UserPrincipalName
            SourceDisplayName              = $u.DisplayName
            SourceOnPremisesSamAccountName = $u.OnPremisesSamAccountName
            SourceUPNSuffix                = $sourceSuffix
            TargetUPNSuffix_Selected        = $targetSuffix
            ProvisioningAction              = if ($status -eq "Ready") { "CreateInOnPrem" } else { "Blocked" }
            TargetOU_Proposed               = $inputOU
            TargetSamAccountName_Proposed   = $localPart
            TargetUPN_Proposed              = $targetUPN
            SourceHasMailbox                = if ($hasMailbox) { "True" } else { "False" }
            SourcePrimarySmtpAddress        = $sourcePrimarySmtp
            MailUserAction                  = $mailUserAction
            TargetAddress_Proposed          = $targetAddressProposed
            TargetGivenName_Proposed      = $u.GivenName
            TargetSurname_Proposed        = $u.Surname
            TargetDisplayName_Proposed    = $u.DisplayName
            TargetMail_Proposed           = $u.Mail
            TargetEmployeeId_Proposed     = $u.EmployeeId
            TargetDepartment_Proposed     = $u.Department
            TargetJobTitle_Proposed       = $u.JobTitle
            TargetCompanyName_Proposed    = $u.CompanyName
        })
    }

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Mailbox match summary (Synced users): ObjectId={0}, UPN={1}, Mail={2}, None={3}" -f `
        $mbxCount_ObjectId, $mbxCount_UPN, $mbxCount_Mail, $mbxCount_None) -Color Cyan
    Write-Host ""

    # Ensure phase folder exists
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "Users_OnPrem_ProvisioningPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Provisioning plan generated: {0}" -f $outputPath) -Color Green

    # Plan generation is done. Review gate happens in Step 02-02.
    return $script:EIDMStatus_Completed
}
function Step-02-02-ConfirmUsersOnPremProvisioningPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Users_OnPrem_ProvisioningPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_OnPrem_ProvisioningPlan.csv"

    # --------------------------------------------------
    # Checks (global only)
    # --------------------------------------------------
    if (-not (Test-Path $planPath)) {
        throw ("Users_OnPrem_ProvisioningPlan.csv not found: {0}" -f $planPath)
    }

    $plan = Import-Csv -Path $planPath
    $plan = @($plan) # force array semantics

    if ($plan.Count -eq 0) {
        throw "Users_OnPrem_ProvisioningPlan.csv is empty."
    }

    # Required columns check (minimal set)
    $requiredColumns = @("ProvisioningAction", "TargetOU_Proposed", "TargetSamAccountName_Proposed", "TargetUPN_Proposed")
    $headerProps = @()
    if ($plan[0]) { $headerProps = @($plan[0].PSObject.Properties.Name) }

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Users_OnPrem_ProvisioningPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInOnPrem" })
    if ($toCreate.Count -lt 1) {
        throw "No line with ProvisioningAction=CreateInOnPrem found. Nothing to create."
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("CreateInOnPrem lines: {0}" -f $toCreate.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Users_OnPrem_ProvisioningPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to remove any users that you do NOT want to create on-prem" -ForegroundColor Yellow
    Write-Host "(service accounts, test accounts, etc.)." -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------
    # Open CSV automatically (Notepad)
    # --------------------------------------------------
    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened provisioning plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    # --------------------------------------------------
    # Interactive confirmation loop (no engine WaitingUser)
    # --------------------------------------------------
    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Users_OnPrem_ProvisioningPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to user creation." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            # Re-load and re-check (in case operator edited)
            if (-not (Test-Path $planPath)) {
                throw ("Users_OnPrem_ProvisioningPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = Import-Csv -Path $planPath
            $plan2 = @($plan2)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toCreate2 = @($plan2 | Where-Object { $_.ProvisioningAction -eq "CreateInOnPrem" })
            if ($toCreate2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No CreateInOnPrem lines found. Add lines or fix ProvisioningAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("CreateInOnPrem lines (after edit): {0}" -f $toCreate2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Get-EIDMIdentityPreparationSteps {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id       = "02-01-BuildUsersOnPremProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-01-BuildUsersOnPremProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-02-ConfirmUsersOnPremProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-02-ConfirmUsersOnPremProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-03-CreateUsersOnPrem"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-03-CreateUsersOnPrem"
            Requires = @()
        },
        @{
            Id       = "02-04-BuildUsersCloudOnlyProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-04-BuildUsersCloudOnlyProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-05-ConfirmUsersCloudOnlyProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-05-ConfirmUsersCloudOnlyProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-06-CreateUsersCloudOnly"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-06-CreateUsersCloudOnly"
            Requires = @("GraphTarget")
        },
        @{
            Id       = "02-07-BuildGuestsProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-07-BuildGuestsProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-08-ConfirmGuestsProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-08-ConfirmGuestsProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-09-CreateGuests"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-09-CreateGuests"
            Requires = @("GraphTarget")
        },
        @{
            Id       = "02-10-BuildGroupsOnPremProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-10-BuildGroupsOnPremProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-11-ConfirmGroupsOnPremProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-11-ConfirmGroupsOnPremProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-12-CreateGroupsOnPrem"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-12-CreateGroupsOnPrem"
            Requires = @()
        },
        @{
            Id       = "02-13-BuildGroupsMembershipPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-13-BuildGroupsMembershipPlan"
            Requires = @()
        },
        @{
            Id       = "02-14-ConfirmGroupsMembershipPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-14-ConfirmGroupsMembershipPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-15-ApplyGroupsMembership"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-15-ApplyGroupsMembership"
            Requires = @()
        },
        @{
            Id       = "02-16-BuildGroupsCloudOnlyProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-16-BuildGroupsCloudOnlyProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-17-ConfirmGroupsCloudOnlyProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-17-ConfirmGroupsCloudOnlyProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-18-CreateGroupsCloudOnly"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-18-CreateGroupsCloudOnly"
            Requires = @("GraphTarget")
        },
        @{
            Id       = "02-19-BuildGroupsCloudOnlyMembershipPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-19-BuildGroupsCloudOnlyMembershipPlan"
            Requires = @()
        },
        @{
            Id       = "02-20-ConfirmGroupsCloudOnlyMembershipPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-20-ConfirmGroupsCloudOnlyMembershipPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-21-ApplyGroupsCloudOnlyMembership"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-21-ApplyGroupsCloudOnlyMembership"
            Requires = @("GraphTarget")
        },
        @{
            Id       = "02-22-AADConnectScopeAssessment"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-22-AADConnectScopeAssessment"
            Requires = @()
        },
        @{
            Id       = "02-23-BuildContactsProvisioningPlan"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-23-BuildContactsProvisioningPlan"
            Requires = @()
        },
        @{
            Id       = "02-24-ConfirmContactsProvisioningPlanReview"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-24-ConfirmContactsProvisioningPlanReview"
            Requires = @()
        },
        @{
            Id       = "02-25-RecreateContacts"
            Phase    = "02-IdentityPreparation"
            Handler  = "Step-02-25-RecreateContacts"
            Requires = @("ExchangeTarget")
        }
    )
}


function New-EIDMStrongPassword {
    param(
        [int]$Length = 18
    )

    $chars = @(
        (48..57)  +    # 0-9
        (65..90)  +    # A-Z
        (97..122) +    # a-z
        33,35,36,37,38,42,43,45,64,95  # selected safe symbols
    ) | ForEach-Object { [char]$_ }

    -join (1..$Length | ForEach-Object { $chars | Get-Random })
}
function Step-02-03-CreateUsersOnPrem {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Creating On-Prem AD Users"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_OnPrem_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Users_OnPrem_ProvisioningPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Provisioning plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        # Default result values
        $accountCreated = $false
        $alreadyExists  = $false
        $mailUserEnabled = $false
        $tempPassword   = ""
        $status         = "Skipped"
        $message        = ""

        if ($row.ProvisioningAction -ne "CreateInOnPrem") {

            $results.Add([PSCustomObject]@{
                Timestamp               = $timestamp
                SourceObjectId          = $row.SourceObjectId
                SourceUPN               = $row.SourceUPN
                TargetSamAccountName    = $row.TargetSamAccountName_Proposed
                TargetUPN               = $row.TargetUPN_Proposed
                TargetOU                = $row.TargetOU_Proposed
                TargetGivenName         = $row.TargetGivenName_Proposed
                TargetSurname           = $row.TargetSurname_Proposed
                TargetDisplayName       = $row.TargetDisplayName_Proposed
                TargetMail              = $row.TargetMail_Proposed
                TargetEmployeeId        = $row.TargetEmployeeId_Proposed
                TargetDepartment        = $row.TargetDepartment_Proposed
                TargetJobTitle          = $row.TargetJobTitle_Proposed
                TargetCompanyName       = $row.TargetCompanyName_Proposed
                ProvisioningAttempted   = "False"
                AccountCreated          = "False"
                AccountAlreadyExists    = "False"
                MailUserEnabled         = "False"
                TemporaryPassword       = ""
                ExecutionStatus         = "Skipped"
                ExecutionMessage        = "ProvisioningAction != CreateInOnPrem"
            })

            continue
        }

        try {

            # Check if account exists
            $existing = Get-ADUser -Filter "SamAccountName -eq '$($row.TargetSamAccountName_Proposed)'" -ErrorAction SilentlyContinue

            if ($existing) {
                $alreadyExists = $true
                $status = "AlreadyExists"
                $message = "Account already exists in AD."
            }
            else {

                # Generate password
                $plainPassword = New-EIDMStrongPassword
                $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

                # Create AD user
                New-ADUser `
                -SamAccountName $row.TargetSamAccountName_Proposed `
                -UserPrincipalName $row.TargetUPN_Proposed `
                -Name $row.TargetDisplayName_Proposed `
                -DisplayName $row.TargetDisplayName_Proposed `
                -GivenName $row.TargetGivenName_Proposed `
                -Surname $row.TargetSurname_Proposed `
                -EmailAddress $row.TargetMail_Proposed `
                -EmployeeID $row.TargetEmployeeId_Proposed `
                -Department $row.TargetDepartment_Proposed `
                -Title $row.TargetJobTitle_Proposed `
                -Company $row.TargetCompanyName_Proposed `
                -Path $row.TargetOU_Proposed `
                -AccountPassword $securePassword `
                -ChangePasswordAtLogon $true `
                -Enabled $true


                $accountCreated = $true
                $status = "Success"
                $tempPassword = $plainPassword

                # MailUser stamping if required
                if ($row.MailUserAction -eq "EnableMailUser" -and $row.TargetAddress_Proposed) {

                    Set-ADUser $row.TargetSamAccountName_Proposed `
                        -Replace @{
                            targetAddress = $row.TargetAddress_Proposed
                        }

                    $mailUserEnabled = $true
                }
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp               = $timestamp
            SourceObjectId          = $row.SourceObjectId
            SourceUPN               = $row.SourceUPN
            TargetSamAccountName    = $row.TargetSamAccountName_Proposed
            TargetUPN               = $row.TargetUPN_Proposed
            TargetOU                = $row.TargetOU_Proposed
            ProvisioningAttempted   = "True"
            AccountCreated          = if ($accountCreated) { "True" } else { "False" }
            AccountAlreadyExists    = if ($alreadyExists) { "True" } else { "False" }
            MailUserEnabled         = if ($mailUserEnabled) { "True" } else { "False" }
            TemporaryPassword       = $tempPassword
            ExecutionStatus         = $status
            ExecutionMessage        = $message
        })
    }

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_OnPrem_CreationResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Creation results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-04-BuildUsersCloudOnlyProvisioningPlan {
    param(
        [Parameter(Mandatory)]
        $Ctx
    )

    Write-EIDMSection "Building Cloud-Only Users Provisioning Plan"

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    $discoveryPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraUsers_SOURCE.csv"
    $outputDir     = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    $outputPath    = Join-Path $outputDir  "Users_CloudOnly_ProvisioningPlan.csv"

    if (-not (Test-Path -LiteralPath $discoveryPath)) {
        throw "EntraUsers_SOURCE.csv not found."
    }

    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    # ------------------------------------------------------------------
    # Load SOURCE users
    # ------------------------------------------------------------------
    $users = @(Import-Csv -LiteralPath $discoveryPath)

    if ($users.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No users found in SOURCE discovery." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ------------------------------------------------------------------
    # Filter Cloud-only Members
    # ------------------------------------------------------------------
    $cloudOnly = @(
        $users | Where-Object {
            ($_.UserType -eq "Member") -and
            ($_.OnPremisesSyncEnabled -ne "True")
        }
    )

    if ($cloudOnly.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No Cloud-only users detected." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Cloud-only users detected: {0}" -f $cloudOnly.Count) -Color Cyan

    # ------------------------------------------------------------------
    # Build UPN suffix mapping (interactive)
    # ------------------------------------------------------------------
    $suffixes = @(
        $cloudOnly |
        ForEach-Object {
            if ($_.UserPrincipalName -match "@(.+)$") {
                $Matches[1].ToLowerInvariant()
            }
        } |
        Sort-Object -Unique
    )

    $suffixMap = @{}

    foreach ($suffix in $suffixes) {

        Write-Host ""
        Write-EIDMTag -Tag "UPN" -Text ("Source suffix detected: @{0}" -f $suffix) -Color Gray

        $useSame = Read-Host "Use same suffix in TARGET? (Y/N)"

        if ($useSame -match "^(Y|y)$") {
            $suffixMap[$suffix] = $suffix
        }
        else {
            $newSuffix = Read-Host "Enter TARGET suffix to use"
            if ([string]::IsNullOrWhiteSpace($newSuffix)) {
                $suffixMap[$suffix] = $suffix
            }
            else {
                $suffixMap[$suffix] = $newSuffix.Trim().ToLowerInvariant()
            }
        }
    }

    # ------------------------------------------------------------------
    # Build plan rows (no Graph checks here - done at creation time)
    # ------------------------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($user in $cloudOnly) {

        $sourceUpn = $user.UserPrincipalName

        if ($sourceUpn -match "^([^@]+)@(.+)$") {
            $prefix = $Matches[1]
            $srcSuffix = $Matches[2].ToLowerInvariant()
        }
        else {
            $prefix = $sourceUpn
            $srcSuffix = ""
        }

        $targetSuffix = $suffixMap[$srcSuffix]
        if (-not $targetSuffix) { $targetSuffix = $srcSuffix }

        $targetUpn = "$prefix@$targetSuffix"

        $targetMail = if (-not [string]::IsNullOrWhiteSpace($user.Mail)) {
            $user.Mail
        } else {
            $targetUpn
        }

        $plan.Add([PSCustomObject]@{
            ProvisioningAction            = "CreateInTarget"
            BlockingReason                = ""
            OperatorNotes                 = ""

            SourceObjectId                = $user.Id
            SourceUPN                     = $sourceUpn
            SourceMail                    = $user.Mail
            SourceDisplayName             = $user.DisplayName
            SourceGivenName               = $user.GivenName
            SourceSurname                 = $user.Surname
            SourceAccountEnabled          = $user.AccountEnabled
            SourceUsageLocation           = $user.UsageLocation
            SourceAssignedLicenses        = $user.AssignedLicenses

            TargetUPN_Proposed            = $targetUpn
            TargetMail_Proposed           = $targetMail
            TargetAccountEnabled_Proposed = $user.AccountEnabled
        }) | Out-Null
    }

    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Cloud-only provisioning plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-05-ConfirmUsersCloudOnlyProvisioningPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Users_CloudOnly_ProvisioningPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_CloudOnly_ProvisioningPlan.csv"

    # --------------------------------------------------
    # Checks
    # --------------------------------------------------
    if (-not (Test-Path $planPath)) {
        throw ("Users_CloudOnly_ProvisioningPlan.csv not found: {0}" -f $planPath)
    }

    $plan = Import-Csv -Path $planPath
    $plan = @($plan)

    if ($plan.Count -eq 0) {
        throw "Users_CloudOnly_ProvisioningPlan.csv is empty."
    }

    # Required columns check
    $requiredColumns = @("ProvisioningAction", "TargetUPN_Proposed", "TargetMail_Proposed")
    $headerProps = @()
    if ($plan[0]) { $headerProps = @($plan[0].PSObject.Properties.Name) }

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Users_CloudOnly_ProvisioningPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInTarget" })
    if ($toCreate.Count -lt 1) {
        throw "No line with ProvisioningAction=CreateInTarget found. Nothing to create."
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("CreateInTarget lines: {0}" -f $toCreate.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Users_CloudOnly_ProvisioningPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to change ProvisioningAction to 'Skip' for any users" -ForegroundColor Yellow
    Write-Host "you do NOT want to create in the target tenant (service accounts, test accounts, etc.)." -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------
    # Open CSV automatically (Notepad)
    # --------------------------------------------------
    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened provisioning plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    # --------------------------------------------------
    # Interactive confirmation loop
    # --------------------------------------------------
    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Users_CloudOnly_ProvisioningPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to cloud-only user creation." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            # Re-load and re-check
            if (-not (Test-Path $planPath)) {
                throw ("Users_CloudOnly_ProvisioningPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = Import-Csv -Path $planPath
            $plan2 = @($plan2)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toCreate2 = @($plan2 | Where-Object { $_.ProvisioningAction -eq "CreateInTarget" })
            if ($toCreate2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No CreateInTarget lines found. Add lines or fix ProvisioningAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("CreateInTarget lines (after edit): {0}" -f $toCreate2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-06-CreateUsersCloudOnly {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Creating Cloud-Only Users in Target Tenant"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_CloudOnly_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Users_CloudOnly_ProvisioningPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Provisioning plan is empty."
    }

    # ------------------------------------------------------------------
    # Load SOURCE mailbox data from Discovery (to decide New-MailUser vs New-MgUser)
    # ------------------------------------------------------------------
    $mbxCsvPath = Join-Path $Ctx.RunRoot "01-Discovery\EXO-Mailboxes_SOURCE.csv"
    $srcMailboxLookup = @{}

    if (Test-Path $mbxCsvPath) {
        $mbxRows = @(Import-Csv -Path $mbxCsvPath)
        foreach ($m in $mbxRows) {
            $oid = ([string]$m.ExternalDirectoryObjectId).Trim()
            if ($oid) { $srcMailboxLookup[$oid] = $m }
        }
        Write-EIDMTag -Tag "INFO" -Text ("Source mailbox data loaded: {0} entries" -f $srcMailboxLookup.Count) -Color Gray
    }
    else {
        Write-EIDMTag -Tag "WARN" -Text "EXO-Mailboxes_SOURCE.csv not found. All users will be created via Graph (no MailUser)." -Color Yellow
    }

    # Check if any CreateInTarget users need EXO MailUser creation
    $needsExoConnection = $false
    if ($srcMailboxLookup.Count -gt 0) {
        foreach ($chk in $plan) {
            if ($chk.ProvisioningAction -eq "CreateInTarget") {
                $chkOid = ([string]$chk.SourceObjectId).Trim()
                if ($chkOid -and $srcMailboxLookup.ContainsKey($chkOid)) {
                    $needsExoConnection = $true
                    break
                }
            }
        }
    }

    if ($needsExoConnection) {
        Write-EIDMSection "Connect to TARGET Exchange Online (for MailUser creation)"
        Write-EIDMTag -Tag "INFO" -Text "Some cloud-only users have a SOURCE mailbox. They will be created as MailUsers via EXO." -Color Cyan
        Ensure-EIDMExchangeTargetConnection -Ctx $Ctx
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        # Default result values
        $accountCreated  = $false
        $alreadyExists   = $false
        $tempPassword    = ""
        $status          = "Skipped"
        $message         = ""
        $targetObjectId  = ""
        $creationMethod  = ""

        if ($row.ProvisioningAction -ne "CreateInTarget") {

            $results.Add([PSCustomObject]@{
                Timestamp               = $timestamp
                SourceObjectId          = $row.SourceObjectId
                SourceUPN               = $row.SourceUPN
                TargetUPN               = $row.TargetUPN_Proposed
                TargetMail              = $row.TargetMail_Proposed
                TargetDisplayName       = $row.SourceDisplayName
                TargetGivenName         = $row.SourceGivenName
                TargetSurname           = $row.SourceSurname
                TargetAccountEnabled    = $row.TargetAccountEnabled_Proposed
                TargetUsageLocation     = $row.SourceUsageLocation
                ProvisioningAttempted   = "False"
                AccountCreated          = "False"
                AccountAlreadyExists    = "False"
                TargetObjectId          = ""
                TemporaryPassword       = ""
                CreationMethod          = ""
                ExecutionStatus         = "Skipped"
                ExecutionMessage        = ("ProvisioningAction = {0}" -f $row.ProvisioningAction)
            })

            continue
        }

        # Determine if this user has a source mailbox -> MailUser creation
        $srcOid = ([string]$row.SourceObjectId).Trim()
        $srcMailbox = $null
        if ($srcOid -and $srcMailboxLookup.ContainsKey($srcOid)) {
            $srcMailbox = $srcMailboxLookup[$srcOid]
        }

        try {

            # Check if user already exists in target (UPN)
            $existing = $null
            try {
                $existing = @(Get-MgUser -Filter ("userPrincipalName eq '{0}'" -f $row.TargetUPN_Proposed.Replace("'","''")) -ErrorAction Stop)
            }
            catch {
                $existing = @()
            }

            if ($existing.Count -gt 0) {
                $alreadyExists = $true
                $targetObjectId = $existing[0].Id
                $status = "AlreadyExists"
                $message = "User already exists in target tenant."
                $creationMethod = "AlreadyExists"
            }
            elseif ($srcMailbox) {
                # ======================================================
                # CREATE VIA EXO: New-MailUser (user has source mailbox)
                # ======================================================
                $creationMethod = "EXO-MailUser"

                $plainPassword = New-EIDMStrongPassword
                $securePass = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force

                # Extract routing address (*.mail.onmicrosoft.com)
                $routingAddr = Get-EIDMSourceRoutingAddress `
                    -EmailAddresses    ([string]$srcMailbox.EmailAddresses) `
                    -PrimarySmtpAddress ([string]$srcMailbox.PrimarySmtpAddress)

                $extEmailAddr = "SMTP:{0}" -f $routingAddr

                $mailUserParams = @{
                    MicrosoftOnlineServicesID = $row.TargetUPN_Proposed
                    Name                     = $row.SourceDisplayName
                    DisplayName              = $row.SourceDisplayName
                    ExternalEmailAddress     = $extEmailAddr
                    Password                 = $securePass
                }

                # Optional parameters
                $alias = ($row.TargetUPN_Proposed -split "@")[0]
                if ($alias) { $mailUserParams.Alias = $alias }
                if (-not [string]::IsNullOrWhiteSpace($row.SourceGivenName)) {
                    $mailUserParams.FirstName = $row.SourceGivenName
                }
                if (-not [string]::IsNullOrWhiteSpace($row.SourceSurname)) {
                    $mailUserParams.LastName = $row.SourceSurname
                }

                Write-Host ("  Creating MailUser: {0} (ExternalEmail: {1})" -f $row.TargetUPN_Proposed, $routingAddr) -ForegroundColor Gray

                $newMailUser = New-MailUser @mailUserParams -ErrorAction Stop

                $targetObjectId = [string]$newMailUser.ExternalDirectoryObjectId
                $accountCreated = $true
                $tempPassword = $plainPassword

                Write-Host ("  -> MailUser created OK (ObjectId: {0})" -f $targetObjectId) -ForegroundColor Green

                # Set UsageLocation via Graph if needed (New-MailUser doesn't support it)
                if (-not [string]::IsNullOrWhiteSpace($row.SourceUsageLocation)) {
                    try {
                        # Brief delay for Entra ID sync
                        Start-Sleep -Seconds 2

                        $graphId = if ($targetObjectId) { $targetObjectId } else { $row.TargetUPN_Proposed }
                        Update-MgUser -UserId $graphId -UsageLocation $row.SourceUsageLocation -ErrorAction Stop
                        Write-Host ("  -> UsageLocation set: {0}" -f $row.SourceUsageLocation) -ForegroundColor Green
                    }
                    catch {
                        Write-EIDMTag -Tag "WARN" -Text ("  Could not set UsageLocation for {0}: {1}" -f $row.TargetUPN_Proposed, $_.Exception.Message) -Color Yellow
                    }
                }

                $status = "Success"
            }
            else {
                # ======================================================
                # CREATE VIA GRAPH: New-MgUser (no source mailbox)
                # ======================================================
                $creationMethod = "Graph-User"

                $plainPassword = New-EIDMStrongPassword

                $passwordProfile = @{
                    Password                             = $plainPassword
                    ForceChangePasswordNextSignIn        = $true
                    ForceChangePasswordNextSignInWithMfa = $false
                }

                $userBody = @{
                    UserPrincipalName = $row.TargetUPN_Proposed
                    DisplayName       = $row.SourceDisplayName
                    MailNickname      = ($row.TargetUPN_Proposed -split "@")[0]
                    AccountEnabled    = ($row.TargetAccountEnabled_Proposed -eq "True")
                    PasswordProfile   = $passwordProfile
                }

                if (-not [string]::IsNullOrWhiteSpace($row.SourceGivenName)) {
                    $userBody.GivenName = $row.SourceGivenName
                }
                if (-not [string]::IsNullOrWhiteSpace($row.SourceSurname)) {
                    $userBody.Surname = $row.SourceSurname
                }
                if (-not [string]::IsNullOrWhiteSpace($row.SourceUsageLocation)) {
                    $userBody.UsageLocation = $row.SourceUsageLocation
                }

                $newUser = New-MgUser -BodyParameter $userBody -ErrorAction Stop

                $accountCreated = $true
                $targetObjectId = $newUser.Id
                $status = "Success"
                $tempPassword = $plainPassword
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp               = $timestamp
            SourceObjectId          = $row.SourceObjectId
            SourceUPN               = $row.SourceUPN
            TargetUPN               = $row.TargetUPN_Proposed
            TargetMail              = $row.TargetMail_Proposed
            TargetDisplayName       = $row.SourceDisplayName
            TargetGivenName         = $row.SourceGivenName
            TargetSurname           = $row.SourceSurname
            TargetAccountEnabled    = $row.TargetAccountEnabled_Proposed
            TargetUsageLocation     = $row.SourceUsageLocation
            ProvisioningAttempted   = "True"
            AccountCreated          = if ($accountCreated) { "True" } else { "False" }
            AccountAlreadyExists    = if ($alreadyExists) { "True" } else { "False" }
            TargetObjectId          = $targetObjectId
            TemporaryPassword       = $tempPassword
            CreationMethod          = $creationMethod
            ExecutionStatus         = $status
            ExecutionMessage        = $message
        })
    }

    # Summary
    $created  = @($results | Where-Object { $_.AccountCreated -eq "True" }).Count
    $exists   = @($results | Where-Object { $_.AccountAlreadyExists -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count
    $asMailUser = @($results | Where-Object { $_.CreationMethod -eq "EXO-MailUser" -and $_.AccountCreated -eq "True" }).Count
    $asGraphUser = @($results | Where-Object { $_.CreationMethod -eq "Graph-User" -and $_.AccountCreated -eq "True" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Created={0} (MailUser={1}, GraphUser={2}), AlreadyExists={3}, Failed={4}, Skipped={5}" -f `
        $created, $asMailUser, $asGraphUser, $exists, $failed, $skipped) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Users_CloudOnly_CreationResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Creation results written to: {0}" -f $outputPath) -Color Green

    # Disconnect EXO if we connected
    if ($needsExoConnection) {
        try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue } catch {}
        $script:EIDMExoState = @{ SourceConnected = $false; TargetConnected = $false }
    }

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# GUESTS
# ==========================================================================

function Step-02-07-BuildGuestsProvisioningPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Guests Provisioning Plan"

    # ------------------------------------------------------------------
    # Paths
    # ------------------------------------------------------------------
    $discoveryPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraUsers_SOURCE.csv"
    $outputDir     = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    $outputPath    = Join-Path $outputDir  "Guests_ProvisioningPlan.csv"

    if (-not (Test-Path -LiteralPath $discoveryPath)) {
        throw "EntraUsers_SOURCE.csv not found. Run Discovery first."
    }

    if (-not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

    # ------------------------------------------------------------------
    # Load SOURCE users
    # ------------------------------------------------------------------
    $users = @(Import-Csv -LiteralPath $discoveryPath)

    if ($users.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No users found in SOURCE discovery." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # ------------------------------------------------------------------
    # Filter Guests only
    # ------------------------------------------------------------------
    $guests = @(
        $users | Where-Object { $_.UserType -eq "Guest" }
    )

    if ($guests.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No Guest users detected in SOURCE." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Guest users detected: {0}" -f $guests.Count) -Color Cyan
    Write-Host ""

    # ------------------------------------------------------------------
    # Ask: Send invitation emails?
    # ------------------------------------------------------------------
    $sendInvite = $false
    do {
        $answer = Read-Host "Send invitation emails to guests upon creation? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()
    } while ($answer -notin @("Y","N"))

    if ($answer -eq "Y") {
        $sendInvite = $true
        Write-EIDMTag -Tag "INFO" -Text "Invitation emails WILL be sent." -Color Cyan
    }
    else {
        Write-EIDMTag -Tag "INFO" -Text "Invitation emails will NOT be sent." -Color Cyan
    }
    Write-Host ""

    # ------------------------------------------------------------------
    # Redirect URL (hardcoded)
    # ------------------------------------------------------------------
    $redirectUrl = "https://myapps.microsoft.com"

    # ------------------------------------------------------------------
    # Build plan rows
    # ------------------------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($guest in $guests) {

        # External email: prefer Mail, fallback to OtherMails first entry
        $externalEmail = $guest.Mail
        if ([string]::IsNullOrWhiteSpace($externalEmail) -and -not [string]::IsNullOrWhiteSpace($guest.OtherMails)) {
            $externalEmail = ($guest.OtherMails -split ';')[0].Trim()
        }

        $action = "InviteToTarget"
        $blockingReason = ""

        # Block if no external email (cannot invite)
        if ([string]::IsNullOrWhiteSpace($externalEmail)) {
            $action = "Blocked"
            $blockingReason = "NoExternalEmailFound"
        }

        $plan.Add([PSCustomObject]@{
            ProvisioningAction       = $action
            BlockingReason           = $blockingReason
            OperatorNotes            = ""

            SourceObjectId           = $guest.Id
            SourceUPN                = $guest.UserPrincipalName
            SourceDisplayName        = $guest.DisplayName
            SourceMail               = $guest.Mail
            SourceOtherMails         = $guest.OtherMails
            SourceExternalUserState  = $guest.ExternalUserState
            SourceAccountEnabled     = $guest.AccountEnabled
            SourceCompanyName        = $guest.CompanyName
            SourceDepartment         = $guest.Department
            SourceJobTitle           = $guest.JobTitle

            TargetInvitedEmail       = $externalEmail
            TargetDisplayName        = $guest.DisplayName
            TargetRedirectUrl        = $redirectUrl
            TargetSendInvitation     = if ($sendInvite) { "True" } else { "False" }
        }) | Out-Null
    }

    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    $actionable = @($plan | Where-Object { $_.ProvisioningAction -eq "InviteToTarget" }).Count
    $blocked    = @($plan | Where-Object { $_.ProvisioningAction -eq "Blocked" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Plan summary: InviteToTarget={0}, Blocked={1}" -f $actionable, $blocked) -Color Cyan
    Write-EIDMTag -Tag "OK" -Text ("Guests provisioning plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-08-ConfirmGuestsProvisioningPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Guests_ProvisioningPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Guests_ProvisioningPlan.csv"

    # --------------------------------------------------
    # Checks
    # --------------------------------------------------
    if (-not (Test-Path $planPath)) {
        throw ("Guests_ProvisioningPlan.csv not found: {0}" -f $planPath)
    }

    $plan = Import-Csv -Path $planPath
    $plan = @($plan)

    if ($plan.Count -eq 0) {
        throw "Guests_ProvisioningPlan.csv is empty."
    }

    # Required columns check
    $requiredColumns = @("ProvisioningAction", "TargetInvitedEmail", "TargetDisplayName")
    $headerProps = @()
    if ($plan[0]) { $headerProps = @($plan[0].PSObject.Properties.Name) }

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Guests_ProvisioningPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toInvite = @($plan | Where-Object { $_.ProvisioningAction -eq "InviteToTarget" })
    if ($toInvite.Count -lt 1) {
        throw "No line with ProvisioningAction=InviteToTarget found. Nothing to create."
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("InviteToTarget lines: {0}" -f $toInvite.Count) -Color Cyan

    $sendYes = @($toInvite | Where-Object { $_.TargetSendInvitation -eq "True" }).Count
    $sendNo  = $toInvite.Count - $sendYes
    Write-EIDMTag -Tag "INFO" -Text ("Invitation email: Send={0}, DoNotSend={1}" -f $sendYes, $sendNo) -Color Cyan
    Write-Host ""

    Write-Host "Review Guests_ProvisioningPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to change ProvisioningAction, TargetSendInvitation," -ForegroundColor Yellow
    Write-Host "or remove guests you do NOT want to invite." -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------
    # Open CSV automatically (Notepad)
    # --------------------------------------------------
    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened guest plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    # --------------------------------------------------
    # Interactive confirmation loop
    # --------------------------------------------------
    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Guests_ProvisioningPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to guest invitation." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            # Re-load and re-check
            if (-not (Test-Path $planPath)) {
                throw ("Guests_ProvisioningPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = Import-Csv -Path $planPath
            $plan2 = @($plan2)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toInvite2 = @($plan2 | Where-Object { $_.ProvisioningAction -eq "InviteToTarget" })
            if ($toInvite2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No InviteToTarget lines found. Add lines or fix ProvisioningAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("InviteToTarget lines (after edit): {0}" -f $toInvite2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-09-CreateGuests {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Creating Guest Users in Target Tenant"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Guests_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Guests_ProvisioningPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Guests provisioning plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        # Default result values
        $guestCreated    = $false
        $alreadyExists   = $false
        $invitationSent  = $false
        $status          = "Skipped"
        $message         = ""
        $targetObjectId  = ""

        if ($row.ProvisioningAction -ne "InviteToTarget") {

            $results.Add([PSCustomObject]@{
                Timestamp               = $timestamp
                SourceObjectId          = $row.SourceObjectId
                SourceUPN               = $row.SourceUPN
                TargetInvitedEmail      = $row.TargetInvitedEmail
                TargetDisplayName       = $row.TargetDisplayName
                TargetSendInvitation    = $row.TargetSendInvitation
                ProvisioningAttempted   = "False"
                GuestCreated            = "False"
                GuestAlreadyExists      = "False"
                InvitationSent          = "False"
                TargetObjectId          = ""
                ExecutionStatus         = "Skipped"
                ExecutionMessage        = ("ProvisioningAction = {0}" -f $row.ProvisioningAction)
            })

            continue
        }

        try {

            # Check if guest already exists by mail
            $existing = $null
            try {
                $existing = @(Get-MgUser -Filter ("mail eq '{0}'" -f $row.TargetInvitedEmail.Replace("'","''")) -ErrorAction Stop)
            }
            catch {
                $existing = @()
            }

            if ($existing.Count -gt 0) {
                $alreadyExists = $true
                $targetObjectId = $existing[0].Id
                $status = "AlreadyExists"
                $message = "Guest with this email already exists in target tenant."
            }
            else {

                $sendMessage = ($row.TargetSendInvitation -eq "True")

                $invitationBody = @{
                    InvitedUserEmailAddress = $row.TargetInvitedEmail
                    InvitedUserDisplayName  = $row.TargetDisplayName
                    InviteRedirectUrl       = $row.TargetRedirectUrl
                    SendInvitationMessage   = $sendMessage
                }

                $invitation = New-MgInvitation -BodyParameter $invitationBody -ErrorAction Stop

                $guestCreated   = $true
                $targetObjectId = $invitation.InvitedUser.Id
                $invitationSent = $sendMessage
                $status         = "Success"
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp               = $timestamp
            SourceObjectId          = $row.SourceObjectId
            SourceUPN               = $row.SourceUPN
            TargetInvitedEmail      = $row.TargetInvitedEmail
            TargetDisplayName       = $row.TargetDisplayName
            TargetSendInvitation    = $row.TargetSendInvitation
            ProvisioningAttempted   = "True"
            GuestCreated            = if ($guestCreated) { "True" } else { "False" }
            GuestAlreadyExists      = if ($alreadyExists) { "True" } else { "False" }
            InvitationSent          = if ($invitationSent) { "True" } else { "False" }
            TargetObjectId          = $targetObjectId
            ExecutionStatus         = $status
            ExecutionMessage        = $message
        })
    }

    # Summary
    $created  = @($results | Where-Object { $_.GuestCreated -eq "True" }).Count
    $exists   = @($results | Where-Object { $_.GuestAlreadyExists -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count
    $invited  = @($results | Where-Object { $_.InvitationSent -eq "True" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Created={0}, AlreadyExists={1}, Failed={2}, Skipped={3}, InvitationsSent={4}" -f $created, $exists, $failed, $skipped, $invited) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Guests_CreationResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Creation results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# GROUPS ON-PREM (SYNCED)
# ==========================================================================

function Step-02-10-BuildGroupsOnPremProvisioningPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Groups_OnPrem_ProvisioningPlan"

    # --------------------------------------------------
    # Context shortcuts
    # --------------------------------------------------
    $config     = $Ctx.Config
    $ConfigPath = $Ctx.ConfigPath

    if (-not $config.ContainsKey("OnPremIdentity")) {
        $config.OnPremIdentity = @{}
    }
    if (-not $config.OnPremIdentity.ContainsKey("LastUsedGroupTargetOU")) {
        $config.OnPremIdentity.LastUsedGroupTargetOU = ""
    }

    # --------------------------------------------------
    # Load Discovery Groups
    # --------------------------------------------------
    $groupsPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraGroups_SOURCE.csv"
    if (-not (Test-Path $groupsPath)) {
        throw "EntraGroups_SOURCE.csv not found. Run Discovery first."
    }

    $groups = Import-Csv $groupsPath

    # Filter synced security groups only (no M365/dynamic/mail-enabled)
    $synced = @($groups | Where-Object {
        ($_.OnPremisesSyncEnabled -eq "True") -and
        ($_.SecurityEnabled -eq "True")
    })

    if ($synced.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No synced security groups detected." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Synced security groups detected: {0}" -f $synced.Count) -Color Cyan
    Write-Host ""

    # --------------------------------------------------
    # Ask Target OU for groups (interactive)
    # --------------------------------------------------
    $defaultOU = [string]$config.OnPremIdentity.LastUsedGroupTargetOU
    if (-not $defaultOU) { $defaultOU = "" }

    $prompt = "Enter Target OU for synced groups"
    if ($defaultOU) {
        $inputOU = Read-Host ("{0} [{1}]" -f $prompt, $defaultOU)
        if ([string]::IsNullOrWhiteSpace($inputOU)) { $inputOU = $defaultOU }
    }
    else {
        $inputOU = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($inputOU)) {
            throw "Target OU cannot be empty."
        }
    }

    # Persist last used OU
    $config.OnPremIdentity.LastUsedGroupTargetOU = $inputOU
    Save-EIDMConfigPsd1 -Config $config -Path $ConfigPath

    # --------------------------------------------------
    # Build Provisioning Plan
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($g in $synced) {

        $samAccountName = $g.OnPremisesSamAccountName
        $action = "CreateInOnPrem"
        $blockingReason = ""

        # Block if no SamAccountName
        if ([string]::IsNullOrWhiteSpace($samAccountName)) {
            $action = "Blocked"
            $blockingReason = "NoSamAccountName"
        }

        # Detect group scope from GroupTypes / source properties
        $groupScope = "Global"  # default for synced security groups

        $plan.Add([PSCustomObject]@{
            ProvisioningAction               = $action
            BlockingReason                   = $blockingReason
            OperatorNotes                    = ""

            SourceObjectId                   = $g.Id
            SourceDisplayName                = $g.DisplayName
            SourceMail                       = $g.Mail
            SourceMailEnabled                = $g.MailEnabled
            SourceSecurityEnabled            = $g.SecurityEnabled
            SourceGroupTypes                 = $g.GroupTypes
            SourceDescription                = $g.Description
            SourceOnPremisesSamAccountName   = $samAccountName
            SourceOnPremisesDomainName       = $g.OnPremisesDomainName

            TargetOU_Proposed                = $inputOU
            TargetSamAccountName_Proposed    = $samAccountName
            TargetDisplayName_Proposed       = $g.DisplayName
            TargetDescription_Proposed       = $g.Description
            TargetGroupScope_Proposed        = $groupScope
            TargetGroupCategory_Proposed     = "Security"
        }) | Out-Null
    }

    # Ensure phase folder exists
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "Groups_OnPrem_ProvisioningPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    $actionable = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInOnPrem" }).Count
    $blocked    = @($plan | Where-Object { $_.ProvisioningAction -eq "Blocked" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Plan summary: CreateInOnPrem={0}, Blocked={1}" -f $actionable, $blocked) -Color Cyan
    Write-EIDMTag -Tag "OK" -Text ("Groups provisioning plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-11-ConfirmGroupsOnPremProvisioningPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Groups_OnPrem_ProvisioningPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_ProvisioningPlan.csv"

    # --------------------------------------------------
    # Checks
    # --------------------------------------------------
    if (-not (Test-Path $planPath)) {
        throw ("Groups_OnPrem_ProvisioningPlan.csv not found: {0}" -f $planPath)
    }

    $plan = Import-Csv -Path $planPath
    $plan = @($plan)

    if ($plan.Count -eq 0) {
        throw "Groups_OnPrem_ProvisioningPlan.csv is empty."
    }

    # Required columns check
    $requiredColumns = @("ProvisioningAction", "TargetOU_Proposed", "TargetSamAccountName_Proposed", "TargetDisplayName_Proposed")
    $headerProps = @()
    if ($plan[0]) { $headerProps = @($plan[0].PSObject.Properties.Name) }

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Groups_OnPrem_ProvisioningPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInOnPrem" })
    if ($toCreate.Count -lt 1) {
        throw "No line with ProvisioningAction=CreateInOnPrem found. Nothing to create."
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("CreateInOnPrem lines: {0}" -f $toCreate.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Groups_OnPrem_ProvisioningPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to remove groups you do NOT want to create on-prem." -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------
    # Open CSV automatically (Notepad)
    # --------------------------------------------------
    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened groups plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    # --------------------------------------------------
    # Interactive confirmation loop
    # --------------------------------------------------
    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Groups_OnPrem_ProvisioningPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to group creation." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            # Re-load and re-check
            if (-not (Test-Path $planPath)) {
                throw ("Groups_OnPrem_ProvisioningPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = Import-Csv -Path $planPath
            $plan2 = @($plan2)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toCreate2 = @($plan2 | Where-Object { $_.ProvisioningAction -eq "CreateInOnPrem" })
            if ($toCreate2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No CreateInOnPrem lines found. Add lines or fix ProvisioningAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("CreateInOnPrem lines (after edit): {0}" -f $toCreate2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-12-CreateGroupsOnPrem {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Creating On-Prem AD Groups"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Groups_OnPrem_ProvisioningPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Groups provisioning plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        # Default result values
        $groupCreated   = $false
        $alreadyExists  = $false
        $status         = "Skipped"
        $message        = ""

        if ($row.ProvisioningAction -ne "CreateInOnPrem") {

            $results.Add([PSCustomObject]@{
                Timestamp                   = $timestamp
                SourceObjectId              = $row.SourceObjectId
                SourceDisplayName           = $row.SourceDisplayName
                TargetSamAccountName        = $row.TargetSamAccountName_Proposed
                TargetDisplayName           = $row.TargetDisplayName_Proposed
                TargetOU                    = $row.TargetOU_Proposed
                TargetGroupScope            = $row.TargetGroupScope_Proposed
                TargetGroupCategory         = $row.TargetGroupCategory_Proposed
                ProvisioningAttempted       = "False"
                GroupCreated                = "False"
                GroupAlreadyExists          = "False"
                ExecutionStatus             = "Skipped"
                ExecutionMessage            = ("ProvisioningAction = {0}" -f $row.ProvisioningAction)
            })

            continue
        }

        try {

            # Check if group exists
            $existing = Get-ADGroup -Filter "SamAccountName -eq '$($row.TargetSamAccountName_Proposed)'" -ErrorAction SilentlyContinue

            if ($existing) {
                $alreadyExists = $true
                $status = "AlreadyExists"
                $message = "Group already exists in AD."
            }
            else {

                $newGroupParams = @{
                    Name            = $row.TargetDisplayName_Proposed
                    SamAccountName  = $row.TargetSamAccountName_Proposed
                    DisplayName     = $row.TargetDisplayName_Proposed
                    GroupScope      = $row.TargetGroupScope_Proposed
                    GroupCategory   = $row.TargetGroupCategory_Proposed
                    Path            = $row.TargetOU_Proposed
                }

                if (-not [string]::IsNullOrWhiteSpace($row.TargetDescription_Proposed)) {
                    $newGroupParams.Description = $row.TargetDescription_Proposed
                }

                New-ADGroup @newGroupParams

                $groupCreated = $true
                $status = "Success"
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp                   = $timestamp
            SourceObjectId              = $row.SourceObjectId
            SourceDisplayName           = $row.SourceDisplayName
            TargetSamAccountName        = $row.TargetSamAccountName_Proposed
            TargetDisplayName           = $row.TargetDisplayName_Proposed
            TargetOU                    = $row.TargetOU_Proposed
            TargetGroupScope            = $row.TargetGroupScope_Proposed
            TargetGroupCategory         = $row.TargetGroupCategory_Proposed
            ProvisioningAttempted       = "True"
            GroupCreated                = if ($groupCreated) { "True" } else { "False" }
            GroupAlreadyExists          = if ($alreadyExists) { "True" } else { "False" }
            ExecutionStatus             = $status
            ExecutionMessage            = $message
        })
    }

    # Summary
    $created  = @($results | Where-Object { $_.GroupCreated -eq "True" }).Count
    $exists   = @($results | Where-Object { $_.GroupAlreadyExists -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Created={0}, AlreadyExists={1}, Failed={2}, Skipped={3}" -f $created, $exists, $failed, $skipped) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_CreationResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Creation results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# GROUPS ON-PREM MEMBERSHIP
# ==========================================================================

function Step-02-13-BuildGroupsMembershipPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Groups_OnPrem_MembershipPlan"

    $phaseRoot = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    $discoveryRoot = Join-Path $Ctx.RunRoot "01-Discovery"

    # --------------------------------------------------
    # Load source data
    # --------------------------------------------------
    $membersPath = Join-Path $discoveryRoot "EntraGroupMembers_SOURCE.csv"
    if (-not (Test-Path $membersPath)) {
        throw "EntraGroupMembers_SOURCE.csv not found. Run Discovery first."
    }
    $members = @(Import-Csv $membersPath)

    if ($members.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No group memberships found in discovery." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # --------------------------------------------------
    # Load Groups provisioning plan (to map GroupId -> TargetSamAccountName)
    # --------------------------------------------------
    $groupsPlanPath = Join-Path $phaseRoot "Groups_OnPrem_ProvisioningPlan.csv"
    if (-not (Test-Path $groupsPlanPath)) {
        throw "Groups_OnPrem_ProvisioningPlan.csv not found. Run step 02-10 first."
    }
    $groupsPlan = @(Import-Csv $groupsPlanPath)

    # Build lookup: SourceObjectId -> row (only CreateInOnPrem)
    $groupLookup = @{}
    foreach ($g in $groupsPlan) {
        if ($g.ProvisioningAction -eq "CreateInOnPrem") {
            $groupLookup[$g.SourceObjectId] = $g
        }
    }

    # --------------------------------------------------
    # Load Users provisioning plan (to map MemberId -> TargetSamAccountName)
    # --------------------------------------------------
    $userLookup = @{}

    # On-prem users
    $usersOnPremPlanPath = Join-Path $phaseRoot "Users_OnPrem_ProvisioningPlan.csv"
    if (Test-Path $usersOnPremPlanPath) {
        $usersOnPremPlan = @(Import-Csv $usersOnPremPlanPath)
        foreach ($u in $usersOnPremPlan) {
            if ($u.ProvisioningAction -eq "CreateInOnPrem" -and -not [string]::IsNullOrWhiteSpace($u.TargetSamAccountName_Proposed)) {
                $userLookup[$u.SourceObjectId] = $u.TargetSamAccountName_Proposed
            }
        }
    }

    Write-EIDMTag -Tag "INFO" -Text ("Loaded: {0} target groups, {1} target users" -f $groupLookup.Count, $userLookup.Count) -Color Cyan

    # --------------------------------------------------
    # Build membership plan
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($m in $members) {

        # Only handle user members (skip devices, service principals, etc.)
        if ($m.MemberType -ne "user") { continue }

        $action = "AddToGroup"
        $blockingReason = ""
        $targetGroupSam = ""
        $targetMemberSam = ""

        # Resolve target group
        if ($groupLookup.ContainsKey($m.GroupId)) {
            $targetGroupSam = $groupLookup[$m.GroupId].TargetSamAccountName_Proposed
        }
        else {
            $action = "Blocked"
            $blockingReason = "GroupNotInOnPremPlan"
        }

        # Resolve target member
        if ($userLookup.ContainsKey($m.MemberId)) {
            $targetMemberSam = $userLookup[$m.MemberId]
        }
        else {
            $action = "Blocked"
            if ($blockingReason) {
                $blockingReason += ";MemberNotInOnPremPlan"
            } else {
                $blockingReason = "MemberNotInOnPremPlan"
            }
        }

        $plan.Add([PSCustomObject]@{
            MembershipAction            = $action
            BlockingReason              = $blockingReason
            OperatorNotes               = ""

            SourceGroupId               = $m.GroupId
            SourceGroupDisplayName       = $m.GroupDisplayName
            SourceMemberId              = $m.MemberId
            SourceMemberDisplayName     = $m.MemberDisplayName
            SourceMemberUPN             = $m.MemberUserPrincipalName

            TargetGroupSamAccountName   = $targetGroupSam
            TargetMemberSamAccountName  = $targetMemberSam
        }) | Out-Null
    }

    if ($plan.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No user memberships to plan (all members are non-user types or no data)." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # Ensure phase folder exists
    Assert-EIDMDirectory -Path $phaseRoot

    $outputPath = Join-Path $phaseRoot "Groups_OnPrem_MembershipPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    $actionable = @($plan | Where-Object { $_.MembershipAction -eq "AddToGroup" }).Count
    $blocked    = @($plan | Where-Object { $_.MembershipAction -eq "Blocked" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Membership plan summary: AddToGroup={0}, Blocked={1}" -f $actionable, $blocked) -Color Cyan
    Write-EIDMTag -Tag "OK" -Text ("Membership plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-14-ConfirmGroupsMembershipPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Groups_OnPrem_MembershipPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_MembershipPlan.csv"

    # --------------------------------------------------
    # Checks
    # --------------------------------------------------
    if (-not (Test-Path $planPath)) {
        throw ("Groups_OnPrem_MembershipPlan.csv not found: {0}" -f $planPath)
    }

    $plan = @(Import-Csv -Path $planPath)

    if ($plan.Count -eq 0) {
        throw "Groups_OnPrem_MembershipPlan.csv is empty."
    }

    # Required columns check
    $requiredColumns = @("MembershipAction", "TargetGroupSamAccountName", "TargetMemberSamAccountName")
    $headerProps = @($plan[0].PSObject.Properties.Name)

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Groups_OnPrem_MembershipPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toAdd = @($plan | Where-Object { $_.MembershipAction -eq "AddToGroup" })
    if ($toAdd.Count -lt 1) {
        Write-EIDMTag -Tag "INFO" -Text "No line with MembershipAction=AddToGroup found. Nothing to apply - skipping." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("AddToGroup lines: {0}" -f $toAdd.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Groups_OnPrem_MembershipPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to remove memberships you do NOT want to apply." -ForegroundColor Yellow
    Write-Host ""

    # --------------------------------------------------
    # Open CSV automatically (Notepad)
    # --------------------------------------------------
    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened membership plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    # --------------------------------------------------
    # Interactive confirmation loop
    # --------------------------------------------------
    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Groups_OnPrem_MembershipPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to membership application." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            # Re-load and re-check
            if (-not (Test-Path $planPath)) {
                throw ("Groups_OnPrem_MembershipPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = @(Import-Csv -Path $planPath)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toAdd2 = @($plan2 | Where-Object { $_.MembershipAction -eq "AddToGroup" })
            if ($toAdd2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No AddToGroup lines found. Add lines or fix MembershipAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("AddToGroup lines (after edit): {0}" -f $toAdd2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-15-ApplyGroupsMembership {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Applying On-Prem Group Memberships"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_MembershipPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Groups_OnPrem_MembershipPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Groups membership plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        $memberAdded    = $false
        $alreadyMember  = $false
        $status         = "Skipped"
        $message        = ""

        if ($row.MembershipAction -ne "AddToGroup") {

            $results.Add([PSCustomObject]@{
                Timestamp                   = $timestamp
                SourceGroupId               = $row.SourceGroupId
                SourceGroupDisplayName      = $row.SourceGroupDisplayName
                SourceMemberId              = $row.SourceMemberId
                SourceMemberDisplayName     = $row.SourceMemberDisplayName
                TargetGroupSamAccountName   = $row.TargetGroupSamAccountName
                TargetMemberSamAccountName  = $row.TargetMemberSamAccountName
                MembershipAttempted         = "False"
                MemberAdded                 = "False"
                AlreadyMember               = "False"
                ExecutionStatus             = "Skipped"
                ExecutionMessage            = ("MembershipAction = {0}" -f $row.MembershipAction)
            })

            continue
        }

        try {

            # Check if user is already a member
            $existingMembers = Get-ADGroupMember -Identity $row.TargetGroupSamAccountName -ErrorAction Stop | Where-Object { $_.SamAccountName -eq $row.TargetMemberSamAccountName }

            if ($existingMembers) {
                $alreadyMember = $true
                $status = "AlreadyMember"
                $message = "User is already a member of this group."
            }
            else {
                Add-ADGroupMember -Identity $row.TargetGroupSamAccountName -Members $row.TargetMemberSamAccountName -ErrorAction Stop

                $memberAdded = $true
                $status = "Success"
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp                   = $timestamp
            SourceGroupId               = $row.SourceGroupId
            SourceGroupDisplayName      = $row.SourceGroupDisplayName
            SourceMemberId              = $row.SourceMemberId
            SourceMemberDisplayName     = $row.SourceMemberDisplayName
            TargetGroupSamAccountName   = $row.TargetGroupSamAccountName
            TargetMemberSamAccountName  = $row.TargetMemberSamAccountName
            MembershipAttempted         = "True"
            MemberAdded                 = if ($memberAdded) { "True" } else { "False" }
            AlreadyMember               = if ($alreadyMember) { "True" } else { "False" }
            ExecutionStatus             = $status
            ExecutionMessage            = $message
        })
    }

    # Summary
    $added    = @($results | Where-Object { $_.MemberAdded -eq "True" }).Count
    $already  = @($results | Where-Object { $_.AlreadyMember -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Added={0}, AlreadyMember={1}, Failed={2}, Skipped={3}" -f $added, $already, $failed, $skipped) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_OnPrem_MembershipResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Membership results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# GROUPS CLOUD-ONLY
# ==========================================================================

function Step-02-16-BuildGroupsCloudOnlyProvisioningPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Groups_CloudOnly_ProvisioningPlan"

    # --------------------------------------------------
    # Load Discovery Groups
    # --------------------------------------------------
    $groupsPath = Join-Path $Ctx.RunRoot "01-Discovery\EntraGroups_SOURCE.csv"
    if (-not (Test-Path $groupsPath)) {
        throw "EntraGroups_SOURCE.csv not found. Run Discovery first."
    }

    $groups = Import-Csv $groupsPath

    # Filter cloud-only security groups:
    #   - NOT synced (OnPremisesSyncEnabled is empty or not True)
    #   - SecurityEnabled = True
    #   - NOT dynamic (GroupTypes does not contain DynamicMembership)
    #   - NOT M365/Unified (GroupTypes does not contain Unified)
    $cloudOnly = @($groups | Where-Object {
        ($_.SecurityEnabled -eq "True") -and
        ([string]::IsNullOrWhiteSpace($_.OnPremisesSyncEnabled) -or $_.OnPremisesSyncEnabled -ne "True") -and
        ($_.GroupTypes -notmatch 'DynamicMembership') -and
        ($_.GroupTypes -notmatch 'Unified')
    })

    if ($cloudOnly.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No cloud-only security groups detected." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Cloud-only security groups detected: {0}" -f $cloudOnly.Count) -Color Cyan
    Write-Host ""

    # --------------------------------------------------
    # Build Provisioning Plan
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($g in $cloudOnly) {

        $action = "CreateInCloud"
        $blockingReason = ""

        # Generate a MailNickname from DisplayName (fallback)
        $mailNickname = ($g.DisplayName -replace '[^a-zA-Z0-9_-]', '')
        if ([string]::IsNullOrWhiteSpace($mailNickname)) {
            $mailNickname = "group-" + [guid]::NewGuid().ToString().Substring(0, 8)
        }

        $plan.Add([PSCustomObject]@{
            ProvisioningAction               = $action
            BlockingReason                   = $blockingReason
            OperatorNotes                    = ""

            SourceObjectId                   = $g.Id
            SourceDisplayName                = $g.DisplayName
            SourceMail                       = $g.Mail
            SourceMailEnabled                = $g.MailEnabled
            SourceSecurityEnabled            = $g.SecurityEnabled
            SourceGroupTypes                 = $g.GroupTypes
            SourceDescription                = $g.Description
            SourceIsAssignableToRole         = $g.IsAssignableToRole

            TargetDisplayName_Proposed       = $g.DisplayName
            TargetMailNickname_Proposed      = $mailNickname
            TargetMailEnabled_Proposed       = $g.MailEnabled
            TargetSecurityEnabled_Proposed   = $g.SecurityEnabled
            TargetDescription_Proposed       = $g.Description
            TargetIsAssignableToRole_Proposed = $g.IsAssignableToRole
        }) | Out-Null
    }

    # Ensure phase folder exists
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "Groups_CloudOnly_ProvisioningPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    $actionable = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInCloud" }).Count
    $blocked    = @($plan | Where-Object { $_.ProvisioningAction -eq "Blocked" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Plan summary: CreateInCloud={0}, Blocked={1}" -f $actionable, $blocked) -Color Cyan
    Write-EIDMTag -Tag "OK" -Text ("Cloud-only groups provisioning plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-17-ConfirmGroupsCloudOnlyProvisioningPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Groups_CloudOnly_ProvisioningPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_ProvisioningPlan.csv"

    if (-not (Test-Path $planPath)) {
        throw ("Groups_CloudOnly_ProvisioningPlan.csv not found: {0}" -f $planPath)
    }

    $plan = @(Import-Csv -Path $planPath)

    if ($plan.Count -eq 0) {
        throw "Groups_CloudOnly_ProvisioningPlan.csv is empty."
    }

    $requiredColumns = @("ProvisioningAction", "TargetDisplayName_Proposed", "TargetMailNickname_Proposed", "TargetSecurityEnabled_Proposed")
    $headerProps = @($plan[0].PSObject.Properties.Name)

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Groups_CloudOnly_ProvisioningPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInCloud" })
    if ($toCreate.Count -lt 1) {
        throw "No line with ProvisioningAction=CreateInCloud found. Nothing to create."
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("CreateInCloud lines: {0}" -f $toCreate.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Groups_CloudOnly_ProvisioningPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to remove groups you do NOT want to create." -ForegroundColor Yellow
    Write-Host ""

    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened cloud-only groups plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Groups_CloudOnly_ProvisioningPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to cloud-only group creation." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            if (-not (Test-Path $planPath)) {
                throw ("Groups_CloudOnly_ProvisioningPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = @(Import-Csv -Path $planPath)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toCreate2 = @($plan2 | Where-Object { $_.ProvisioningAction -eq "CreateInCloud" })
            if ($toCreate2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No CreateInCloud lines found. Add lines or fix ProvisioningAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("CreateInCloud lines (after edit): {0}" -f $toCreate2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-18-CreateGroupsCloudOnly {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Creating Cloud-Only Groups in Target Tenant"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Groups_CloudOnly_ProvisioningPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Cloud-only groups provisioning plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        $groupCreated   = $false
        $alreadyExists  = $false
        $targetObjectId = ""
        $status         = "Skipped"
        $message        = ""

        if ($row.ProvisioningAction -ne "CreateInCloud") {

            $results.Add([PSCustomObject]@{
                Timestamp                   = $timestamp
                SourceObjectId              = $row.SourceObjectId
                SourceDisplayName           = $row.SourceDisplayName
                TargetDisplayName           = $row.TargetDisplayName_Proposed
                TargetMailNickname          = $row.TargetMailNickname_Proposed
                TargetSecurityEnabled       = $row.TargetSecurityEnabled_Proposed
                TargetMailEnabled           = $row.TargetMailEnabled_Proposed
                ProvisioningAttempted       = "False"
                GroupCreated                = "False"
                GroupAlreadyExists          = "False"
                TargetObjectId              = ""
                ExecutionStatus             = "Skipped"
                ExecutionMessage            = ("ProvisioningAction = {0}" -f $row.ProvisioningAction)
            })

            continue
        }

        try {

            # Check if a group with same DisplayName already exists in target
            $filter = "displayName eq '{0}'" -f ($row.TargetDisplayName_Proposed -replace "'", "''")
            try {
                $existing = @(Get-MgGroup -Filter $filter -ErrorAction Stop)
            }
            catch {
                $existing = @()
            }

            if ($existing.Count -gt 0) {
                $alreadyExists = $true
                $targetObjectId = $existing[0].Id
                $status = "AlreadyExists"
                $message = "Group already exists in target tenant."
            }
            else {

                $groupBody = @{
                    DisplayName     = $row.TargetDisplayName_Proposed
                    MailNickname    = $row.TargetMailNickname_Proposed
                    MailEnabled     = ($row.TargetMailEnabled_Proposed -eq "True")
                    SecurityEnabled = ($row.TargetSecurityEnabled_Proposed -eq "True")
                }

                if (-not [string]::IsNullOrWhiteSpace($row.TargetDescription_Proposed)) {
                    $groupBody.Description = $row.TargetDescription_Proposed
                }

                if ($row.TargetIsAssignableToRole_Proposed -eq "True") {
                    $groupBody.IsAssignableToRole = $true
                }

                $newGroup = New-MgGroup -BodyParameter $groupBody -ErrorAction Stop

                $groupCreated = $true
                $targetObjectId = $newGroup.Id
                $status = "Success"
            }
        }
        catch {
            $status = "Failed"
            $message = $_.Exception.Message
        }

        $results.Add([PSCustomObject]@{
            Timestamp                   = $timestamp
            SourceObjectId              = $row.SourceObjectId
            SourceDisplayName           = $row.SourceDisplayName
            TargetDisplayName           = $row.TargetDisplayName_Proposed
            TargetMailNickname          = $row.TargetMailNickname_Proposed
            TargetSecurityEnabled       = $row.TargetSecurityEnabled_Proposed
            TargetMailEnabled           = $row.TargetMailEnabled_Proposed
            ProvisioningAttempted       = "True"
            GroupCreated                = if ($groupCreated) { "True" } else { "False" }
            GroupAlreadyExists          = if ($alreadyExists) { "True" } else { "False" }
            TargetObjectId              = $targetObjectId
            ExecutionStatus             = $status
            ExecutionMessage            = $message
        })
    }

    # Summary
    $created  = @($results | Where-Object { $_.GroupCreated -eq "True" }).Count
    $exists   = @($results | Where-Object { $_.GroupAlreadyExists -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Created={0}, AlreadyExists={1}, Failed={2}, Skipped={3}" -f $created, $exists, $failed, $skipped) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_CreationResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Creation results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# GROUPS CLOUD-ONLY MEMBERSHIP
# ==========================================================================

function Step-02-19-BuildGroupsCloudOnlyMembershipPlan {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Groups_CloudOnly_MembershipPlan"

    $phaseRoot = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    $discoveryRoot = Join-Path $Ctx.RunRoot "01-Discovery"

    # --------------------------------------------------
    # Load source data
    # --------------------------------------------------
    $membersPath = Join-Path $discoveryRoot "EntraGroupMembers_SOURCE.csv"
    if (-not (Test-Path $membersPath)) {
        throw "EntraGroupMembers_SOURCE.csv not found. Run Discovery first."
    }
    $members = @(Import-Csv $membersPath)

    if ($members.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No group memberships found in discovery." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    # --------------------------------------------------
    # Load Cloud-Only Groups creation results (to map GroupId -> TargetObjectId)
    # --------------------------------------------------
    $groupsResultsPath = Join-Path $phaseRoot "Groups_CloudOnly_CreationResults.csv"
    if (-not (Test-Path $groupsResultsPath)) {
        throw "Groups_CloudOnly_CreationResults.csv not found. Run step 02-18 first."
    }
    $groupsResults = @(Import-Csv $groupsResultsPath)

    # Build lookup: SourceObjectId -> TargetObjectId (only Success or AlreadyExists)
    $groupLookup = @{}
    foreach ($g in $groupsResults) {
        if (($g.ExecutionStatus -eq "Success" -or $g.ExecutionStatus -eq "AlreadyExists") -and -not [string]::IsNullOrWhiteSpace($g.TargetObjectId)) {
            $groupLookup[$g.SourceObjectId] = @{
                TargetObjectId    = $g.TargetObjectId
                TargetDisplayName = $g.TargetDisplayName
            }
        }
    }

    # --------------------------------------------------
    # Load Cloud-Only Users creation results (to map MemberId -> TargetObjectId)
    # --------------------------------------------------
    $memberLookup = @{}

    $usersCloudResultsPath = Join-Path $phaseRoot "Users_CloudOnly_CreationResults.csv"
    if (Test-Path $usersCloudResultsPath) {
        $usersCloudResults = @(Import-Csv $usersCloudResultsPath)
        foreach ($u in $usersCloudResults) {
            if (($u.ExecutionStatus -eq "Success" -or $u.ExecutionStatus -eq "AlreadyExists") -and -not [string]::IsNullOrWhiteSpace($u.TargetObjectId)) {
                $memberLookup[$u.SourceObjectId] = @{
                    TargetObjectId = $u.TargetObjectId
                    TargetUPN      = $u.TargetUPN
                }
            }
        }
    }

    # Also check Guests creation results
    $guestsResultsPath = Join-Path $phaseRoot "Guests_CreationResults.csv"
    if (Test-Path $guestsResultsPath) {
        $guestsResults = @(Import-Csv $guestsResultsPath)
        foreach ($gu in $guestsResults) {
            if (($gu.ExecutionStatus -eq "Success" -or $gu.ExecutionStatus -eq "AlreadyExists") -and -not [string]::IsNullOrWhiteSpace($gu.TargetObjectId)) {
                if (-not $memberLookup.ContainsKey($gu.SourceObjectId)) {
                    $memberLookup[$gu.SourceObjectId] = @{
                        TargetObjectId = $gu.TargetObjectId
                        TargetUPN      = $gu.TargetInvitedEmail
                    }
                }
            }
        }
    }

    Write-EIDMTag -Tag "INFO" -Text ("Loaded: {0} target groups, {1} target members" -f $groupLookup.Count, $memberLookup.Count) -Color Cyan

    # --------------------------------------------------
    # Build membership plan
    # --------------------------------------------------
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($m in $members) {

        # Only handle user members
        if ($m.MemberType -ne "user") { continue }

        $action = "AddToGroup"
        $blockingReason = ""
        $targetGroupId = ""
        $targetGroupName = ""
        $targetMemberId = ""
        $targetMemberIdentifier = ""

        # Resolve target group
        if ($groupLookup.ContainsKey($m.GroupId)) {
            $targetGroupId   = $groupLookup[$m.GroupId].TargetObjectId
            $targetGroupName = $groupLookup[$m.GroupId].TargetDisplayName
        }
        else {
            $action = "Blocked"
            $blockingReason = "GroupNotInCloudOnlyResults"
        }

        # Resolve target member
        if ($memberLookup.ContainsKey($m.MemberId)) {
            $targetMemberId         = $memberLookup[$m.MemberId].TargetObjectId
            $targetMemberIdentifier = $memberLookup[$m.MemberId].TargetUPN
        }
        else {
            $action = "Blocked"
            if ($blockingReason) {
                $blockingReason += ";MemberNotInCloudResults"
            } else {
                $blockingReason = "MemberNotInCloudResults"
            }
        }

        $plan.Add([PSCustomObject]@{
            MembershipAction            = $action
            BlockingReason              = $blockingReason
            OperatorNotes               = ""

            SourceGroupId               = $m.GroupId
            SourceGroupDisplayName      = $m.GroupDisplayName
            SourceMemberId              = $m.MemberId
            SourceMemberDisplayName     = $m.MemberDisplayName
            SourceMemberUPN             = $m.MemberUserPrincipalName

            TargetGroupObjectId         = $targetGroupId
            TargetGroupDisplayName      = $targetGroupName
            TargetMemberObjectId        = $targetMemberId
            TargetMemberIdentifier      = $targetMemberIdentifier
        }) | Out-Null
    }

    if ($plan.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No user memberships to plan for cloud-only groups." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Assert-EIDMDirectory -Path $phaseRoot

    $outputPath = Join-Path $phaseRoot "Groups_CloudOnly_MembershipPlan.csv"
    $plan | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    $actionable = @($plan | Where-Object { $_.MembershipAction -eq "AddToGroup" }).Count
    $blocked    = @($plan | Where-Object { $_.MembershipAction -eq "Blocked" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Membership plan summary: AddToGroup={0}, Blocked={1}" -f $actionable, $blocked) -Color Cyan
    Write-EIDMTag -Tag "OK" -Text ("Cloud-only membership plan generated: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

function Step-02-20-ConfirmGroupsCloudOnlyMembershipPlanReview {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm review of Groups_CloudOnly_MembershipPlan.csv"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_MembershipPlan.csv"

    if (-not (Test-Path $planPath)) {
        throw ("Groups_CloudOnly_MembershipPlan.csv not found: {0}" -f $planPath)
    }

    $plan = @(Import-Csv -Path $planPath)

    if ($plan.Count -eq 0) {
        throw "Groups_CloudOnly_MembershipPlan.csv is empty."
    }

    $requiredColumns = @("MembershipAction", "TargetGroupObjectId", "TargetMemberObjectId")
    $headerProps = @($plan[0].PSObject.Properties.Name)

    $missingCols = @()
    foreach ($c in $requiredColumns) {
        if ($headerProps -notcontains $c) { $missingCols += $c }
    }
    if ($missingCols.Count -gt 0) {
        throw ("Groups_CloudOnly_MembershipPlan.csv is missing required column(s): {0}" -f ($missingCols -join ", "))
    }

    $toAdd = @($plan | Where-Object { $_.MembershipAction -eq "AddToGroup" })
    if ($toAdd.Count -lt 1) {
        Write-EIDMTag -Tag "INFO" -Text "No line with MembershipAction=AddToGroup found. Nothing to apply - skipping." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Plan file: {0}" -f $planPath) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("AddToGroup lines: {0}" -f $toAdd.Count) -Color Cyan
    Write-Host ""

    Write-Host "Review Groups_CloudOnly_MembershipPlan.csv before proceeding." -ForegroundColor Yellow
    Write-Host "You can EDIT this file to remove memberships you do NOT want to apply." -ForegroundColor Yellow
    Write-Host ""

    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened cloud-only membership plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }

    Write-Host ""

    while ($true) {

        $answer = Read-Host "Have you reviewed/edited Groups_CloudOnly_MembershipPlan.csv and are you ready to continue? (Y/N)"
        if ([string]::IsNullOrWhiteSpace($answer)) { $answer = "N" }
        $answer = $answer.Trim().ToUpper()

        if ($answer -eq "Y") {
            Write-EIDMTag -Tag "OK" -Text "Operator confirmed review. Proceeding to cloud-only membership application." -Color Green
            return $script:EIDMStatus_Completed
        }

        if ($answer -eq "N") {
            Write-EIDMTag -Tag "INFO" -Text "OK. Edit the file, then confirm when ready." -Color Cyan
            Read-Host "Press Enter when you are ready to answer again" | Out-Null

            if (-not (Test-Path $planPath)) {
                throw ("Groups_CloudOnly_MembershipPlan.csv not found anymore: {0}" -f $planPath)
            }

            $plan2 = @(Import-Csv -Path $planPath)

            if ($plan2.Count -eq 0) {
                Write-EIDMTag -Tag "WARN" -Text "The plan is now empty." -Color Yellow
                continue
            }

            $headerProps2 = @($plan2[0].PSObject.Properties.Name)
            $missingCols2 = @()
            foreach ($c in $requiredColumns) {
                if ($headerProps2 -notcontains $c) { $missingCols2 += $c }
            }
            if ($missingCols2.Count -gt 0) {
                Write-EIDMTag -Tag "WARN" -Text ("The plan is missing required column(s): {0}" -f ($missingCols2 -join ", ")) -Color Yellow
                continue
            }

            $toAdd2 = @($plan2 | Where-Object { $_.MembershipAction -eq "AddToGroup" })
            if ($toAdd2.Count -lt 1) {
                Write-EIDMTag -Tag "WARN" -Text "No AddToGroup lines found. Add lines or fix MembershipAction before continuing." -Color Yellow
                continue
            }

            Write-EIDMTag -Tag "INFO" -Text ("AddToGroup lines (after edit): {0}" -f $toAdd2.Count) -Color Cyan
            Write-Host ""
            continue
        }

        Write-EIDMTag -Tag "WARN" -Text "Invalid input. Please type Y or N." -Color Yellow
        Write-Host ""
    }
}

function Step-02-21-ApplyGroupsCloudOnlyMembership {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Applying Cloud-Only Group Memberships"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_MembershipPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Groups_CloudOnly_MembershipPlan.csv not found."
    }

    $plan = @(Import-Csv -Path $planPath)

    if (-not $plan -or $plan.Count -eq 0) {
        throw "Cloud-only groups membership plan is empty."
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($row in $plan) {

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

        $memberAdded    = $false
        $alreadyMember  = $false
        $status         = "Skipped"
        $message        = ""

        if ($row.MembershipAction -ne "AddToGroup") {

            $results.Add([PSCustomObject]@{
                Timestamp                   = $timestamp
                SourceGroupId               = $row.SourceGroupId
                SourceGroupDisplayName      = $row.SourceGroupDisplayName
                SourceMemberId              = $row.SourceMemberId
                SourceMemberDisplayName     = $row.SourceMemberDisplayName
                TargetGroupObjectId         = $row.TargetGroupObjectId
                TargetGroupDisplayName      = $row.TargetGroupDisplayName
                TargetMemberObjectId        = $row.TargetMemberObjectId
                TargetMemberIdentifier      = $row.TargetMemberIdentifier
                MembershipAttempted         = "False"
                MemberAdded                 = "False"
                AlreadyMember               = "False"
                ExecutionStatus             = "Skipped"
                ExecutionMessage            = ("MembershipAction = {0}" -f $row.MembershipAction)
            })

            continue
        }

        try {

            # Check if already a member
            $existingMembers = @()
            try {
                $existingMembers = @(Get-MgGroupMember -GroupId $row.TargetGroupObjectId -All -ErrorAction Stop)
            }
            catch {
                # If we can't list members, proceed to add
            }

            $isMember = $existingMembers | Where-Object { $_.Id -eq $row.TargetMemberObjectId }

            if ($isMember) {
                $alreadyMember = $true
                $status = "AlreadyMember"
                $message = "User is already a member of this group."
            }
            else {

                $body = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/{0}" -f $row.TargetMemberObjectId
                }

                New-MgGroupMemberByRef -GroupId $row.TargetGroupObjectId -BodyParameter $body -ErrorAction Stop

                $memberAdded = $true
                $status = "Success"
            }
        }
        catch {
            # Graph returns 400 if already member in some cases
            if ($_.Exception.Message -match 'already exist') {
                $alreadyMember = $true
                $status = "AlreadyMember"
                $message = "Member already exists (Graph)." 
            }
            else {
                $status = "Failed"
                $message = $_.Exception.Message
            }
        }

        $results.Add([PSCustomObject]@{
            Timestamp                   = $timestamp
            SourceGroupId               = $row.SourceGroupId
            SourceGroupDisplayName      = $row.SourceGroupDisplayName
            SourceMemberId              = $row.SourceMemberId
            SourceMemberDisplayName     = $row.SourceMemberDisplayName
            TargetGroupObjectId         = $row.TargetGroupObjectId
            TargetGroupDisplayName      = $row.TargetGroupDisplayName
            TargetMemberObjectId        = $row.TargetMemberObjectId
            TargetMemberIdentifier      = $row.TargetMemberIdentifier
            MembershipAttempted         = "True"
            MemberAdded                 = if ($memberAdded) { "True" } else { "False" }
            AlreadyMember               = if ($alreadyMember) { "True" } else { "False" }
            ExecutionStatus             = $status
            ExecutionMessage            = $message
        })
    }

    # Summary
    $added    = @($results | Where-Object { $_.MemberAdded -eq "True" }).Count
    $already  = @($results | Where-Object { $_.AlreadyMember -eq "True" }).Count
    $failed   = @($results | Where-Object { $_.ExecutionStatus -eq "Failed" }).Count
    $skipped  = @($results | Where-Object { $_.ExecutionStatus -eq "Skipped" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "INFO" -Text ("Summary: Added={0}, AlreadyMember={1}, Failed={2}, Skipped={3}" -f $added, $already, $failed, $skipped) -Color Cyan

    $outputPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Groups_CloudOnly_MembershipResults.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-EIDMTag -Tag "OK" -Text ("Membership results written to: {0}" -f $outputPath) -Color Green

    return $script:EIDMStatus_Completed
}

# ==========================================================================
# AAD CONNECT SCOPE ASSESSMENT (Questionnaire)
# ==========================================================================

function Step-02-22-AADConnectScopeAssessment {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "AAD Connect Scope Assessment (Questionnaire)"

    Write-Host "This step does NOT perform any technical change." -ForegroundColor Gray
    Write-Host "It captures your answers to key AAD Connect / Entra Connect prerequisites" -ForegroundColor Gray
    Write-Host "so you can keep a traceable GO / NO-GO decision for the migration." -ForegroundColor Gray
    Write-Host ""

    $results = New-Object System.Collections.Generic.List[object]
    $order = 0

    # ===========================================================
    # Block 1 - AAD Connect scope
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 1 - AAD Connect scope" -Color Cyan
    Write-Host ""

    $order++
    $q = "Is the OU containing the new migrated Users included in the AAD Connect synchronization scope?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "AAD Connect scope"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Users will not be synchronized to Entra ID." }; AssessedAt = (Get-Date) }) | Out-Null

    $order++
    $q = "Do the migrated Users comply with any attribute-based filtering rules (attribute filtering)?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "AAD Connect scope"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Filtered users will not be synchronized." }; AssessedAt = (Get-Date) }) | Out-Null

    $order++
    $q = "Is the OU containing the new Groups included in the AAD Connect synchronization scope?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "AAD Connect scope"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Groups will not be synchronized to Entra ID." }; AssessedAt = (Get-Date) }) | Out-Null

    $order++
    $q = "Do the Groups comply with any attribute-based filtering rules (attribute filtering)?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "AAD Connect scope"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Filtered groups will not be synchronized." }; AssessedAt = (Get-Date) }) | Out-Null

    $order++
    $q = "Is the Usage Location (ISO country code, e.g., FR/US) correctly set for users that will receive M365 licenses (either synced from AD or set in Entra)?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "AAD Connect scope"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "License assignment will fail with 'invalid usage location' until Usage Location is set correctly." }; AssessedAt = (Get-Date) }) | Out-Null

    Write-Host ""

    # ===========================================================
    # Block 2 - UPN domains / Entra ID / Mail routing
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 2 - UPN domains / Entra ID / Mail routing" -Color Cyan
    Write-Host ""

    $order++
    $q = "Are the UPN suffixes used for the new Users already added and verified in Entra ID?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "UPN / Entra ID"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Cloud UPN reconciliation will require adding and verifying the domains in Entra ID first." }; AssessedAt = (Get-Date) }) | Out-Null

    Write-Host ""
    Write-Host "CRITICAL MAIL ROUTING PREREQUISITE:" -ForegroundColor Yellow
    Write-Host "You MUST ensure that a synchronization rule exists in AAD Connect / Cloud Sync" -ForegroundColor Yellow
    Write-Host "to flow the on-premises 'targetAddress' attribute to Entra ID." -ForegroundColor Yellow
    Write-Host "If this is missing, mailUsers will not be correctly created and the Exchange migration" -ForegroundColor Yellow
    Write-Host "or hybrid mail routing is very likely to FAIL." -ForegroundColor Yellow
    Write-Host ""

    $order++
    $q = "Is there an AAD Connect / Cloud Sync rule that synchronizes the on-premises 'targetAddress' attribute to Entra ID (for hybrid mail routing / mailUsers)?"
    $a = Read-EIDMSimpleYesNo $q
    if (-not $a) {
        Write-EIDMTag -Tag "CRITICAL" -Text "No sync rule for 'targetAddress' -> mailUsers in Entra ID will miss their external routing address and the Exchange migration / hybrid mail routing is likely to FAIL." -Color Red
    }
    $results.Add([PSCustomObject]@{ Order = $order; Block = "UPN / Entra ID / Mail routing"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "MailUsers in Entra ID will not be correctly provisioned (no targetAddress), and Exchange migration / hybrid mail routing is likely to fail." }; AssessedAt = (Get-Date) }) | Out-Null

    Write-Host ""

    # ===========================================================
    # Block 3 - AAD Connect readiness (operational)
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 3 - AAD Connect readiness (operational)" -Color Cyan
    Write-Host ""

    $order++
    $q = "Is AAD Connect (or Cloud Sync) healthy and monitored (no active sync errors / alerting in place)?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "Operational readiness"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Risk of missing objects or inconsistent sync state during migration." }; AssessedAt = (Get-Date) }) | Out-Null

    $order++
    $q = "Is the change window approved and are rollback / support contacts identified?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "Operational readiness"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "Higher risk during execution if issues arise (no clear escalation/rollback)." }; AssessedAt = (Get-Date) }) | Out-Null

    Write-Host ""

    # ===========================================================
    # Block 4 - Synchronization verification
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 4 - Synchronization verification" -Color Cyan
    Write-Host ""

    Write-Host "Before proceeding, you MUST ensure that an AAD Connect / Cloud Sync" -ForegroundColor Yellow
    Write-Host "synchronization cycle has been triggered and completed successfully." -ForegroundColor Yellow
    Write-Host "All objects created on-premises (users, groups) must appear in the TARGET" -ForegroundColor Yellow
    Write-Host "Entra ID tenant before continuing with the next migration phases." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "How to verify:" -ForegroundColor Gray
    Write-Host "  1) On the AAD Connect server: Start-ADSyncSyncCycle -PolicyType Delta" -ForegroundColor Gray
    Write-Host "  2) Wait for the cycle to complete (check with: Get-ADSyncScheduler)" -ForegroundColor Gray
    Write-Host "  3) In the Entra ID portal (TARGET tenant), confirm the new users/groups are visible" -ForegroundColor Gray
    Write-Host ""

    $order++
    $q = "Has an AAD Connect synchronization cycle been completed and have you confirmed that all on-premises objects (users, groups) are now present in the TARGET Entra ID tenant?"
    $a = Read-EIDMSimpleYesNo $q
    if (-not $a) {
        Write-EIDMTag -Tag "CRITICAL" -Text "Objects created on-premises may not be visible in Entra ID yet. Run an AAD Connect sync cycle and verify before continuing." -Color Red
    }
    $results.Add([PSCustomObject]@{ Order = $order; Block = "Sync verification"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "On-premises objects may not be visible in Entra ID. Next phases (Exchange, OneDrive) will fail if objects are missing." }; AssessedAt = (Get-Date) }) | Out-Null

    Write-Host ""

    # ===========================================================
    # Block 5 - Global verdict
    # ===========================================================
    Write-EIDMTag -Tag "BLOCK" -Text "Block 5 - Global verdict" -Color Cyan
    Write-Host ""

    $order++
    $q = "Are all AAD Connect prerequisites validated to proceed with the migration?"
    $a = Read-EIDMSimpleYesNo $q
    $results.Add([PSCustomObject]@{ Order = $order; Block = "Verdict"; Question = $q; Answer = if ($a) { "Yes" } else { "No" }; ImpactIfNo = if ($a) { "" } else { "STOP - Fix the failed points before continuing the migration." }; AssessedAt = (Get-Date) }) | Out-Null

    # --------------------------------------------------
    # Export
    # --------------------------------------------------
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outputPath = Join-Path $phaseFolder "AADConnect_Scope_Assessment.csv"
    $results | Sort-Object Order | Export-Csv -Path $outputPath -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("AAD Connect scope assessment exported to: {0}" -f $outputPath) -Color Green
    Write-Host ""
    Write-Host "How to read this report:" -ForegroundColor Cyan
    Write-Host "  - Block       : Thematic area (scope, UPN, mail routing, operational readiness, verdict)." -ForegroundColor Gray
    Write-Host "  - Question    : Exact question asked during the workshop." -ForegroundColor Gray
    Write-Host "  - Answer      : Yes / No." -ForegroundColor Gray
    Write-Host "  - ImpactIfNo  : Concrete impact or risk if the answer is No." -ForegroundColor Gray
    Write-Host "  - AssessedAt  : Timestamp of the assessment for audit/traceability." -ForegroundColor Gray
    Write-Host ""

    if ($a) {
        Write-EIDMTag -Tag "VERDICT" -Text "GO - AAD Connect prerequisites validated to proceed with the migration." -Color Green
    }
    else {
        Write-EIDMTag -Tag "VERDICT" -Text "NO-GO - Fix the failed points above before continuing the migration." -Color Red
    }

    return $script:EIDMStatus_Completed
}

# ============================================================
# Contacts (Mail Contacts) - Build plan, confirm, recreate
# ============================================================

function Normalize-EIDMAlias {
    <#
    .SYNOPSIS  Normalizes a string to be a valid EXO alias (MailNickName).
    #>
    param([AllowNull()][string]$Alias)
    if (-not $Alias) { return $null }

    $a = $Alias.Trim()
    $a = $a -replace '\s+', '.'
    $a = $a -replace '[^a-zA-Z0-9\.\-_]', ''
    if ($a.Length -gt 64) { $a = $a.Substring(0, 64) }
    if (-not $a) { return $null }
    return $a
}

function Step-02-23-BuildContactsProvisioningPlan {
    <#
    .SYNOPSIS  Reads EXO-MailContacts_SOURCE.csv from Discovery and builds a
               Contacts_ProvisioningPlan.csv listing each contact to create in
               the TARGET tenant.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Building Contacts Provisioning Plan"

    # ---- Load Discovery export ----
    $sourcePath = Join-Path $Ctx.RunRoot "01-Discovery\EXO-MailContacts_SOURCE.csv"
    if (-not (Test-Path $sourcePath)) {
        throw "EXO-MailContacts_SOURCE.csv not found. Run Discovery (EXO Mail Contacts) first."
    }

    $contacts = @(Import-Csv -Path $sourcePath)

    if (-not $contacts -or $contacts.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No mail contacts found in source export. Nothing to plan." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Source mail contacts loaded: {0}" -f $contacts.Count) -Color Cyan

    # ---- Build plan rows ----
    $plan = New-Object System.Collections.Generic.List[object]

    foreach ($c in $contacts) {

        $displayName = [string]$c.DisplayName
        $name        = [string]$c.Name
        $alias       = [string]$c.Alias
        $external    = [string]$c.ExternalEmailAddress
        $primary     = [string]$c.PrimarySmtpAddress

        # Minimal required: ExternalEmailAddress
        if ([string]::IsNullOrWhiteSpace($external)) {
            $plan.Add([PSCustomObject]@{
                SourceObjectId       = [string]$c.ExternalDirectoryObjectId
                DisplayName          = $displayName
                Name                 = $name
                Alias                = $alias
                ExternalEmailAddress = $external
                PrimarySmtpAddress   = $primary
                ProvisioningAction   = "Skip"
                SkipReason           = "Missing ExternalEmailAddress"
            }) | Out-Null
            continue
        }

        # Fallbacks
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $name }
        if ([string]::IsNullOrWhiteSpace($displayName)) { $displayName = $external }
        if ([string]::IsNullOrWhiteSpace($name))        { $name = $displayName }

        if ([string]::IsNullOrWhiteSpace($alias)) {
            $alias = ($external.Split("@")[0])
        }
        $alias = Normalize-EIDMAlias $alias
        if ([string]::IsNullOrWhiteSpace($alias)) {
            $alias = Normalize-EIDMAlias ($external.Split("@")[0])
        }

        $plan.Add([PSCustomObject]@{
            SourceObjectId       = [string]$c.ExternalDirectoryObjectId
            DisplayName          = $displayName
            Name                 = $name
            Alias                = $alias
            ExternalEmailAddress = $external
            PrimarySmtpAddress   = $primary
            ProvisioningAction   = "CreateInTarget"
            SkipReason           = ""
        }) | Out-Null
    }

    # ---- Export ----
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $outPath = Join-Path $phaseFolder "Contacts_ProvisioningPlan.csv"
    $plan | Export-Csv -Path $outPath -NoTypeInformation -Encoding UTF8

    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInTarget" }).Count
    $toSkip   = @($plan | Where-Object { $_.ProvisioningAction -eq "Skip" }).Count

    Write-Host ""
    Write-EIDMTag -Tag "OK" -Text ("Contacts provisioning plan exported: {0}" -f $outPath) -Color Green
    Write-EIDMTag -Tag "INFO" -Text ("To create : {0}" -f $toCreate) -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("Skipped   : {0}" -f $toSkip)   -Color Yellow
    Write-Host ""
    Write-Host "Review and edit Contacts_ProvisioningPlan.csv before the next step." -ForegroundColor Yellow
    Write-Host "You can remove rows or change ProvisioningAction to 'Skip' for contacts you don't want to recreate." -ForegroundColor DarkGray

    return $script:EIDMStatus_Completed
}

function Step-02-24-ConfirmContactsProvisioningPlanReview {
    <#
    .SYNOPSIS  Asks the operator to confirm they have reviewed Contacts_ProvisioningPlan.csv.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Confirm Contacts Provisioning Plan Review"

    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Contacts_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Contacts_ProvisioningPlan.csv not found. Run Step 02-23 first."
    }

    $plan = @(Import-Csv -Path $planPath)
    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInTarget" }).Count
    $toSkip   = @($plan | Where-Object { $_.ProvisioningAction -eq "Skip" }).Count

    Write-EIDMTag -Tag "INFO" -Text ("Contacts plan : {0}" -f $planPath)  -Color Cyan
    Write-EIDMTag -Tag "INFO" -Text ("To create     : {0}" -f $toCreate)  -Color Green
    Write-EIDMTag -Tag "INFO" -Text ("Skipped       : {0}" -f $toSkip)    -Color Yellow
    Write-Host ""

    try {
        $notepad = Join-Path $env:WINDIR "System32\notepad.exe"
        if (Test-Path $notepad) {
            Start-Process -FilePath $notepad -ArgumentList @("$planPath") | Out-Null
            Write-EIDMTag -Tag "OK" -Text "Opened contacts provisioning plan in Notepad." -Color Green
        }
        else {
            Start-Process -FilePath $planPath | Out-Null
            Write-EIDMTag -Tag "WARN" -Text "Notepad not found; opened file with default associated app." -Color Yellow
        }
    }
    catch {
        Write-EIDMTag -Tag "WARN" -Text ("Could not auto-open the plan file: {0}" -f $_.Exception.Message) -Color Yellow
    }
    Write-Host ""

    $confirmed = Read-EIDMYesNo `
        -Question "Have you reviewed the Contacts provisioning plan?" `
        -Details @(
            "Open the CSV, verify contact names and external addresses.",
            "Remove or mark as 'Skip' any contacts you don't want to recreate.",
            "This is your last chance to adjust before contacts are created in the TARGET tenant."
        ) `
        -DefaultYes $false `
        -Tag "REVIEW" -TagColor "Yellow"

    if (-not $confirmed) {
        Write-EIDMTag -Tag "INFO" -Text "Operator did not confirm. Returning to menu." -Color Yellow
        return $script:EIDMStatus_WaitingUser
    }

    Write-EIDMTag -Tag "OK" -Text "Contacts provisioning plan review confirmed." -Color Green
    return $script:EIDMStatus_Completed
}

function Step-02-25-RecreateContacts {
    <#
    .SYNOPSIS  Recreates Mail Contacts in the TARGET tenant from the reviewed
               Contacts_ProvisioningPlan.csv (rows with ProvisioningAction = CreateInTarget).
    .DESCRIPTION
    - Uses Exchange Online PowerShell (New-MailContact) on the TARGET tenant.
    - For each row: if a contact already exists (by ExternalEmailAddress or PrimarySmtpAddress), SKIP.
    - Otherwise create it.
    - Exports a results CSV.
    #>
    param(
        [Parameter(Mandatory)]$Ctx
    )

    Write-EIDMSection "Recreating Mail Contacts in TARGET tenant"

    # ---- Load plan ----
    $planPath = Join-Path $Ctx.RunRoot "02-IdentityPreparation\Contacts_ProvisioningPlan.csv"
    if (-not (Test-Path $planPath)) {
        throw "Contacts_ProvisioningPlan.csv not found. Run Step 02-23 first."
    }

    $plan = @(Import-Csv -Path $planPath)
    $toCreate = @($plan | Where-Object { $_.ProvisioningAction -eq "CreateInTarget" })

    if ($toCreate.Count -eq 0) {
        Write-EIDMTag -Tag "INFO" -Text "No contacts to create (all rows skipped or plan empty)." -Color Yellow
        return $script:EIDMStatus_Completed
    }

    Write-EIDMTag -Tag "INFO" -Text ("Contacts to process: {0}" -f $toCreate.Count) -Color Cyan
    Write-Host ""

    # ---- Process each contact ----
    $results = New-Object System.Collections.Generic.List[object]
    $i = 0

    foreach ($row in $toCreate) {
        $i++

        $displayName = $row.DisplayName
        $name        = $row.Name
        $alias       = $row.Alias
        $external    = $row.ExternalEmailAddress
        $primary     = $row.PrimarySmtpAddress

        Write-Host ("[{0}/{1}] {2} -> {3}" -f $i, $toCreate.Count, $displayName, $external) -ForegroundColor DarkGray

        # ---- Existence checks ----
        $existing = $null
        try {
            $f = "ExternalEmailAddress -eq '$external'"
            $existing = Get-MailContact -Filter $f -ResultSize 1 -ErrorAction Stop
        }
        catch { $existing = $null }

        if (-not $existing -and -not [string]::IsNullOrWhiteSpace($primary)) {
            try {
                $f = "PrimarySmtpAddress -eq '$primary'"
                $existing = Get-MailContact -Filter $f -ResultSize 1 -ErrorAction Stop
            }
            catch { $existing = $null }
        }

        if ($existing) {
            $results.Add([PSCustomObject]@{
                Row                  = $i
                Status               = "OK"
                Action               = "EXISTS"
                DisplayName          = $displayName
                Name                 = $name
                Alias                = $alias
                ExternalEmailAddress = $external
                PrimarySmtpAddress   = $primary
                ResultObjectId       = [string]$existing.ExternalDirectoryObjectId
                Error                = ""
            }) | Out-Null
            continue
        }

        # ---- Create ----
        try {
            $created = New-MailContact `
                -Name $name `
                -DisplayName $displayName `
                -ExternalEmailAddress $external `
                -Alias $alias `
                -ErrorAction Stop

            $results.Add([PSCustomObject]@{
                Row                  = $i
                Status               = "OK"
                Action               = "CREATED"
                DisplayName          = $displayName
                Name                 = $name
                Alias                = $alias
                ExternalEmailAddress = $external
                PrimarySmtpAddress   = $primary
                ResultObjectId       = [string]$created.ExternalDirectoryObjectId
                Error                = ""
            }) | Out-Null
        }
        catch {
            $results.Add([PSCustomObject]@{
                Row                  = $i
                Status               = "FAILED"
                Action               = "CREATE"
                DisplayName          = $displayName
                Name                 = $name
                Alias                = $alias
                ExternalEmailAddress = $external
                PrimarySmtpAddress   = $primary
                ResultObjectId       = ""
                Error                = $_.Exception.Message
            }) | Out-Null
        }
    }

    # ---- Export results ----
    $phaseFolder = Join-Path $Ctx.RunRoot "02-IdentityPreparation"
    Assert-EIDMDirectory -Path $phaseFolder

    $resultsPath = Join-Path $phaseFolder "Contacts_Provisioning_Results.csv"
    $results | Export-Csv -Path $resultsPath -NoTypeInformation -Encoding UTF8

    # ---- Summary ----
    $created  = ($results | Where-Object { $_.Action -eq "CREATED" } | Measure-Object).Count
    $existed  = ($results | Where-Object { $_.Action -eq "EXISTS" }  | Measure-Object).Count
    $failed   = ($results | Where-Object { $_.Status -eq "FAILED" }  | Measure-Object).Count

    Write-Host ""
    Write-EIDMTag -Tag "OK"   -Text ("Results exported   : {0}" -f $resultsPath) -Color Green
    Write-EIDMTag -Tag "INFO" -Text ("Created            : {0}" -f $created)     -Color Green
    Write-EIDMTag -Tag "INFO" -Text ("Already existed    : {0}" -f $existed)     -Color DarkGray
    Write-EIDMTag -Tag "INFO" -Text ("Failed             : {0}" -f $failed)      -Color Red
    Write-Host ""

    if ($failed -gt 0) {
        Write-EIDMTag -Tag "WARN" -Text "Some contacts failed. Review Contacts_Provisioning_Results.csv for details." -Color Red
    }

    return $script:EIDMStatus_Completed
}

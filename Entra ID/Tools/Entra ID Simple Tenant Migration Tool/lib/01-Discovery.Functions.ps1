#Requires -Version 5.1

Set-StrictMode -Version Latest
$script:ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# Discovery - Step Definitions
# ------------------------------------------------------------

function Get-EIDMDiscoverySteps {
    param(
        [Parameter(Mandatory)]$Ctx
    )

    return @(
        @{
            Id       = 'Discovery-ExportUsers-Source'
            Phase    = '01-Discovery'
            Handler  = 'Invoke-DiscoveryExportUsersSource'
            Requires = @('GraphSource')
        },
                @{
            Id       = 'Discovery-ExportDomains-Source'
            Phase    = '01-Discovery'
            Handler  = 'Invoke-DiscoveryExportDomainsSource'
            Requires = @('GraphSource')
        },
        @{
            Id       = 'Discovery-ExportGroups-Source'
            Phase    = '01-Discovery'
            Handler  = 'Invoke-DiscoveryExportGroupsSource'
            Requires = @('GraphSource')
        },
        @{
            Id       = 'Discovery-ExportGroupMembers-Source'
            Phase    = '01-Discovery'
            Handler  = 'Invoke-DiscoveryExportGroupMembersSource'
            Requires = @('GraphSource')
        }
        @{
        Id       = "Discovery-EXO-ExportMailboxes-Source"
        Phase    = "01-Discovery"
        Handler  = "Invoke-DiscoveryEXOExportMailboxesSource"
        Requires = @("ExchangeSource")
        },
        @{
        Id       = "Discovery-EXO-ExportRecipients-Source"
        Phase    = "01-Discovery"
        Handler  = "Invoke-DiscoveryEXOExportRecipientsSource"
        Requires = @("ExchangeSource")
        },
        @{
        Id       = "Discovery-EXO-ExportMailContacts-Source"
        Phase    = "01-Discovery"
        Handler  = "Invoke-DiscoveryEXOExportMailContactsSource"
        Requires = @("ExchangeSource")
        }
        @{
        Id       = "Discovery-SPO-ExportOneDriveSites-Source"
        Phase    = "01-Discovery"
        Handler  = "Invoke-DiscoverySPOExportOneDriveSitesSource"
        Requires = @("SharePointSource")
        }
        @{
        Id       = "Discovery-SPO-ExportSites-Source"
        Phase    = "01-Discovery"
        Handler  = "Invoke-DiscoverySPOExportSitesSource"
        Requires = @("SharePointSource")
        }


    )
}

# ------------------------------------------------------------
# Discovery - Handlers
# ------------------------------------------------------------

function Invoke-DiscoveryExportUsersSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $outDir  = Join-Path $Ctx.RunRoot '01-Discovery'
    $outFile = Join-Path $outDir 'EntraUsers_SOURCE.csv'

    Assert-EIDMDirectory -Path $outDir

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message "Discovery: exporting Entra users (SOURCE) to '$outFile'..."

    $properties = @(
        'id',
        'userPrincipalName',
        'displayName',
        'givenName',
        'surname',
        'mail',
        'proxyAddresses',
        'otherMails',
        'accountEnabled',
        'userType',
        'createdDateTime',

        # Organization / HR
        'department',
        'jobTitle',
        'companyName',
        'usageLocation',
        'employeeId',

        # Hybrid (AAD Connect)
        'onPremisesSyncEnabled',
        'onPremisesImmutableId',
        'onPremisesSecurityIdentifier',
        'onPremisesSamAccountName',
        'onPremisesDomainName',
        'onPremisesUserPrincipalName',

        # Guests governance
        'externalUserState',
        'externalUserStateChangeDateTime',

        # Policies
        'passwordPolicies',

        # Licenses (lightweight form)
        'assignedLicenses',
        'assignedPlans'
    )

    $users = Get-MgUser -All -Property $properties

    $export = $users | Select-Object `
        @{n='Id';e={$_.Id}}, `
        @{n='UserPrincipalName';e={$_.UserPrincipalName}}, `
        @{n='DisplayName';e={$_.DisplayName}}, `
        @{n='GivenName';e={$_.GivenName}}, `
        @{n='Surname';e={$_.Surname}}, `
        @{n='Mail';e={$_.Mail}}, `
        @{n='ProxyAddresses';e={ if ($_.ProxyAddresses) { ($_.ProxyAddresses -join ';') } else { '' } }}, `
        @{n='OtherMails';e={ if ($_.OtherMails) { ($_.OtherMails -join ';') } else { '' } }}, `
        @{n='EmployeeId';e={$_.EmployeeId}}, `
        @{n='AccountEnabled';e={$_.AccountEnabled}}, `
        @{n='UserType';e={$_.UserType}}, `
        @{n='CreatedDateTime';e={$_.CreatedDateTime}}, `
        @{n='Department';e={$_.Department}}, `
        @{n='JobTitle';e={$_.JobTitle}}, `
        @{n='CompanyName';e={$_.CompanyName}}, `
        @{n='UsageLocation';e={$_.UsageLocation}}, `
        @{n='OnPremisesSyncEnabled';e={$_.OnPremisesSyncEnabled}}, `
        @{n='OnPremisesImmutableId';e={$_.OnPremisesImmutableId}}, `
        @{n='OnPremisesSecurityIdentifier';e={$_.OnPremisesSecurityIdentifier}}, `
        @{n='OnPremisesSamAccountName';e={$_.OnPremisesSamAccountName}}, `
        @{n='OnPremisesDomainName';e={$_.OnPremisesDomainName}}, `
        @{n='OnPremisesUserPrincipalName';e={$_.OnPremisesUserPrincipalName}}, `
        @{n='ExternalUserState';e={$_.ExternalUserState}}, `
        @{n='ExternalUserStateChangeDateTime';e={$_.ExternalUserStateChangeDateTime}}, `
        @{n='PasswordPolicies';e={$_.PasswordPolicies}}, `
        @{n='AssignedLicenses';e={
            if ($_.AssignedLicenses) {
                ($_.AssignedLicenses | ForEach-Object { $_.SkuId } | Where-Object { $_ } | ForEach-Object { $_.ToString() }) -join ';'
            } else { '' }
        }}, `
        @{n='AssignedPlans';e={
            if ($_.AssignedPlans) {
                ($_.AssignedPlans | ForEach-Object {
                    if ($_.ServicePlanId) { "{0}:{1}" -f ($_.ServicePlanId.ToString()), $_.CapabilityStatus } else { $null }
                } | Where-Object { $_ }) -join ';'
            } else { '' }
        }}

    $export | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: exported {0} users (SOURCE)." -f ($export.Count))
}

function Invoke-DiscoveryExportGroupsSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $outDir  = Join-Path $Ctx.RunRoot '01-Discovery'
    $outFile = Join-Path $outDir 'EntraGroups_SOURCE.csv'

    Assert-EIDMDirectory -Path $outDir

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message "Discovery: exporting Entra groups (SOURCE) to '$outFile'..."

    $properties = @(
        'id',
        'displayName',
        'mail',
        'mailEnabled',
        'securityEnabled',
        'groupTypes',
        'membershipRule',
        'membershipRuleProcessingState',
        'createdDateTime',
        'description',
        'visibility',
        'isAssignableToRole',
        'onPremisesSyncEnabled',
        'onPremisesSamAccountName',
        'onPremisesNetBiosName',
        'onPremisesDomainName',
        'onPremisesSecurityIdentifier'
    )

    $groups = Get-MgGroup -All -Property $properties

    $export = $groups | Select-Object `
        @{n='Id';e={$_.Id}}, `
        @{n='DisplayName';e={$_.DisplayName}}, `
        @{n='Mail';e={$_.Mail}}, `
        @{n='MailEnabled';e={$_.MailEnabled}}, `
        @{n='SecurityEnabled';e={$_.SecurityEnabled}}, `
        @{n='GroupTypes';e={ if ($_.GroupTypes) { ($_.GroupTypes -join ';') } else { '' } }}, `
        @{n='MembershipRule';e={$_.MembershipRule}}, `
        @{n='MembershipRuleProcessingState';e={$_.MembershipRuleProcessingState}}, `
        @{n='CreatedDateTime';e={$_.CreatedDateTime}}, `
        @{n='Description';e={$_.Description}}, `
        @{n='Visibility';e={$_.Visibility}}, `
        @{n='IsAssignableToRole';e={$_.IsAssignableToRole}}, `
        @{n='OnPremisesSyncEnabled';e={$_.OnPremisesSyncEnabled}}, `
        @{n='OnPremisesSamAccountName';e={$_.OnPremisesSamAccountName}}, `
        @{n='OnPremisesNetBiosName';e={$_.OnPremisesNetBiosName}}, `
        @{n='OnPremisesDomainName';e={$_.OnPremisesDomainName}}, `
        @{n='OnPremisesSecurityIdentifier';e={$_.OnPremisesSecurityIdentifier}}

    $export | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: exported {0} groups (SOURCE)." -f ($export.Count))
}

function Invoke-DiscoveryExportGroupMembersSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $outDir  = Join-Path $Ctx.RunRoot '01-Discovery'
    $outFile = Join-Path $outDir 'EntraGroupMembers_SOURCE.csv'

    Assert-EIDMDirectory -Path $outDir

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message "Discovery: exporting group memberships (SOURCE) to '$outFile'..."
    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message "Note: Dynamic groups are skipped (membership is rule-based)."

    # Load groups from Graph to decide which ones are dynamic and to get names.
    $groups = Get-MgGroup -All -Property @('id','displayName','groupTypes','membershipRule')

    $rows = New-Object System.Collections.Generic.List[object]

    $skippedDynamic = 0
    $processed = 0

    foreach ($g in $groups) {

        $isDynamic = $false
        if ($g.GroupTypes -and ($g.GroupTypes -contains 'DynamicMembership')) { $isDynamic = $true }
        if (-not [string]::IsNullOrWhiteSpace($g.MembershipRule)) { $isDynamic = $true }

        if ($isDynamic) {
            $skippedDynamic++
            continue
        }

        $processed++

        # Get direct members. (Transitive members can be a separate step later.)
        $members = @()
        try {
            $members = @(Get-MgGroupMember -GroupId $g.Id -All)
        }
        catch {
            Write-EIDMLog -LogPath $Ctx.LogPath -Level 'WARN' -Message ("Failed to read members for group '{0}' ({1}): {2}" -f $g.DisplayName, $g.Id, $_.Exception.Message)
            continue
        }

        foreach ($m in $members) {

            # Best-effort: member object may not contain UPN/mail for all types.
            $odataType = $null
            if ($m.AdditionalProperties -and $m.AdditionalProperties.ContainsKey('@odata.type')) {
                $odataType = [string]$m.AdditionalProperties['@odata.type']
            }

            $memberType = if ($odataType) { $odataType.Replace('#microsoft.graph.','') } else { 'directoryObject' }

            $memberDisplayName = $null
            $memberUPN = $null
            $memberMail = $null

            # Some returned objects have DisplayName directly.
            if ($m.PSObject.Properties.Match('DisplayName').Count -gt 0) { $memberDisplayName = $m.DisplayName }

            # Try to capture UPN/mail if present (users sometimes include them, often not).
            if ($m.PSObject.Properties.Match('UserPrincipalName').Count -gt 0) { $memberUPN = $m.UserPrincipalName }
            if ($m.PSObject.Properties.Match('Mail').Count -gt 0) { $memberMail = $m.Mail }

            $rows.Add([pscustomobject]@{
                GroupId           = $g.Id
                GroupDisplayName  = $g.DisplayName
                MemberId          = $m.Id
                MemberType        = $memberType
                MemberDisplayName = $memberDisplayName
                MemberUserPrincipalName = $memberUPN
                MemberMail        = $memberMail
            }) | Out-Null
        }
    }

    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: processed {0} non-dynamic groups (SOURCE)." -f $processed)
    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: skipped {0} dynamic groups (SOURCE)." -f $skippedDynamic)
    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: exported {0} membership rows (SOURCE)." -f $rows.Count)
}
function Invoke-DiscoveryExportDomainsSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $outDir  = Join-Path $Ctx.RunRoot '01-Discovery'
    $outFile = Join-Path $outDir 'EntraDomains_SOURCE.csv'

    Assert-EIDMDirectory -Path $outDir

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message "Discovery: exporting Entra domains (SOURCE) to '$outFile'..."

    # Graph returns domains as /domains objects
    $domains = @(Get-MgDomain -All)

    $export = $domains | Select-Object `
        @{n='DomainName';e={$_.Id}}, `
        @{n='IsVerified';e={$_.IsVerified}}, `
        @{n='IsDefault';e={$_.IsDefault}}, `
        @{n='IsInitial';e={$_.IsInitial}}, `
        @{n='AuthenticationType';e={$_.AuthenticationType}}, `
        @{n='State';e={
            # Keep it simple + robust:
            # - if State.Status exists -> export it
            # - else -> compact JSON (or empty)
            try {
                if ($null -ne $_.State -and $_.State.PSObject.Properties.Match('Status').Count -gt 0 -and $_.State.Status) {
                    [string]$_.State.Status
                }
                elseif ($null -ne $_.State) {
                    ($_.State | ConvertTo-Json -Compress -Depth 6)
                }
                else {
                    ''
                }
            }
            catch {
                ''
            }
        }}

    $export | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level 'INFO' -Message ("Discovery: exported {0} domains (SOURCE)." -f ($export.Count))
}
function Invoke-DiscoveryEXOExportMailboxesSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $phaseFolder = Join-Path $Ctx.RunRoot "01-Discovery"
    $outFile     = Join-Path $phaseFolder "EXO-Mailboxes_SOURCE.csv"

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message "EXO Discovery (SOURCE) - Exporting mailboxes (User/Shared/Room/Equipment) + statistics to a single CSV."

    # Safety: ensure folder exists
    Assert-EIDMDirectory -Path $phaseFolder

    # Only keep the relevant mailbox types (validated)
    $allowedTypes = @('UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox')

    # 1) Get mailboxes
    # Using Get-EXOMailbox (REST-backed) - keep property set explicit to reduce payload.
    $mailboxes = @(Get-EXOMailbox -ResultSize Unlimited -PropertySets All |
        Where-Object { $_.RecipientTypeDetails -in $allowedTypes })

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Mailboxes found: {0}" -f $mailboxes.Count)

    # 2) Get statistics (merge later)
    # Statistics Identity usually matches mailbox identity/UPN; we use PrimarySmtpAddress as merge key for robustness.
    $statsBySmtp = @{}
    foreach ($mb in $mailboxes) {
        $smtp = [string]$mb.PrimarySmtpAddress
        if ([string]::IsNullOrWhiteSpace($smtp)) { continue }

        try {
            $st = Get-EXOMailboxStatistics -Identity $smtp -ErrorAction Stop
            $statsBySmtp[$smtp.ToLowerInvariant()] = $st
        }
        catch {
            # Some mailboxes may fail statistics retrieval (rare). Keep going but log.
            Write-EIDMLog -LogPath $Ctx.LogPath -Level WARN -Message ("EXO Discovery (SOURCE) - Failed to get statistics for {0}: {1}" -f $smtp, $_.Exception.Message)
        }
    }

    # 3) Build output rows (mailbox + stats merged)
    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($mb in $mailboxes) {
        $smtpKey = ([string]$mb.PrimarySmtpAddress).ToLowerInvariant()

        $st = $null
        if ($statsBySmtp.ContainsKey($smtpKey)) { $st = $statsBySmtp[$smtpKey] }

        # Convert size objects to strings to keep CSV readable/portable
        $totalItemSize        = if ($st -and $st.TotalItemSize) { [string]$st.TotalItemSize } else { "" }
        $totalDeletedItemSize = if ($st -and $st.TotalDeletedItemSize) { [string]$st.TotalDeletedItemSize } else { "" }
        $itemCount            = if ($st -and $null -ne $st.ItemCount) { [int]$st.ItemCount } else { "" }

        $rows.Add([pscustomobject]@{
            ExternalDirectoryObjectId     = $mb.ExternalDirectoryObjectId
            ExchangeGuid                  = $mb.ExchangeGuid
            LegacyExchangeDN              = $mb.LegacyExchangeDN
            RecipientTypeDetails          = [string]$mb.RecipientTypeDetails

            PrimarySmtpAddress            = [string]$mb.PrimarySmtpAddress
            EmailAddresses                = ($mb.EmailAddresses -join ';')
            HiddenFromAddressListsEnabled = [bool]$mb.HiddenFromAddressListsEnabled

            LitigationHoldEnabled         = [bool]$mb.LitigationHoldEnabled
            ArchiveStatus                 = [string]$mb.ArchiveStatus

            TotalItemSize                 = $totalItemSize
            ItemCount                     = $itemCount
            TotalDeletedItemSize          = $totalDeletedItemSize
        }) | Out-Null
    }

    # 4) Export
    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Export completed: {0} (rows: {1})" -f $outFile, $rows.Count)

    return @{
        Status  = "Completed"
        Message = ("Exported EXO mailboxes + statistics to {0} (rows: {1})." -f (Split-Path $outFile -Leaf), $rows.Count)
    }
}
function Get-EIDMObjectPropertyValue {
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)][string]$Name
    )
    $p = $Object.PSObject.Properties[$Name]
    if ($null -eq $p) { return $null }
    return $p.Value
}
function Invoke-DiscoveryEXOExportRecipientsSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $phaseFolder = Join-Path $Ctx.RunRoot "01-Discovery"
    $outFile     = Join-Path $phaseFolder "EXO-Recipients_SOURCE.csv"

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message "EXO Discovery (SOURCE) - Exporting mail-enabled recipients to CSV."

    Assert-EIDMDirectory -Path $phaseFolder

    # Export a broad set of mail-enabled objects.
    # We'll rely on Get-EXORecipient (REST-backed) and keep it simple.
    $recipients = @(Get-EXORecipient -ResultSize Unlimited -PropertySets All)
        
        # Exclude system mailboxes
        $excludedTypes = @(
            "DiscoverySearchMailbox",
            "DiscoveryMailbox"
            "ArbitrationMailbox",
            "AuditLogMailbox",
            "MonitoringMailbox",
            "PublicFolderMailbox"
        )

        $recipients = $recipients | Where-Object {
            $_.RecipientTypeDetails -notin $excludedTypes
        }

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Recipients found: {0}" -f $recipients.Count)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($r in $recipients) {

        # Some properties can be null depending on recipient type
        $emailAddresses = ""
        try {
            if ($null -ne $r.EmailAddresses) { $emailAddresses = ($r.EmailAddresses -join ';') }
        }
        catch { $emailAddresses = "" }

        $rows.Add([pscustomobject]@{
            ExternalDirectoryObjectId     = [string]$r.ExternalDirectoryObjectId
            RecipientTypeDetails          = [string]$r.RecipientTypeDetails
            DisplayName                   = [string]$r.DisplayName
            Alias                         = [string]$r.Alias
            PrimarySmtpAddress            = [string]$r.PrimarySmtpAddress
            EmailAddresses                = $emailAddresses
            HiddenFromAddressListsEnabled = [bool]$r.HiddenFromAddressListsEnabled
        }) | Out-Null
    }

    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Export completed: {0} (rows: {1})" -f $outFile, $rows.Count)

    return @{
        Status  = "Completed"
        Message = ("Exported EXO recipients to {0} (rows: {1})." -f (Split-Path $outFile -Leaf), $rows.Count)
    }
}
function Invoke-DiscoveryEXOExportMailContactsSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $phaseFolder = Join-Path $Ctx.RunRoot "01-Discovery"
    $outFile     = Join-Path $phaseFolder "EXO-MailContacts_SOURCE.csv"

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message "EXO Discovery (SOURCE) - Exporting Mail Contacts to CSV."

    Assert-EIDMDirectory -Path $phaseFolder

    # Export all mail contacts from the source tenant
    $contacts = @(Get-MailContact -ResultSize Unlimited)

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Mail Contacts found: {0}" -f $contacts.Count)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($c in $contacts) {

        $emailAddresses = ""
        try {
            if ($null -ne $c.EmailAddresses) { $emailAddresses = ($c.EmailAddresses -join ';') }
        }
        catch { $emailAddresses = "" }

        $rows.Add([pscustomobject]@{
            ExternalDirectoryObjectId     = [string]$c.ExternalDirectoryObjectId
            DisplayName                   = [string]$c.DisplayName
            Name                          = [string]$c.Name
            Alias                         = [string]$c.Alias
            ExternalEmailAddress          = [string]$c.ExternalEmailAddress
            PrimarySmtpAddress            = [string]$c.PrimarySmtpAddress
            EmailAddresses                = $emailAddresses
            HiddenFromAddressListsEnabled = [bool]$c.HiddenFromAddressListsEnabled
            WhenCreated                   = [string]$c.WhenCreated
            WhenChanged                   = [string]$c.WhenChanged
        }) | Out-Null
    }

    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("EXO Discovery (SOURCE) - Export completed: {0} (rows: {1})" -f $outFile, $rows.Count)

    return @{
        Status  = "Completed"
        Message = ("Exported EXO Mail Contacts to {0} (rows: {1})." -f (Split-Path $outFile -Leaf), $rows.Count)
    }
}
function Invoke-DiscoverySPOExportOneDriveSitesSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $phaseFolder = Join-Path $Ctx.RunRoot "01-Discovery"
    $outFile     = Join-Path $phaseFolder "SPO-OneDriveSites_SOURCE.csv"

    Assert-EIDMDirectory -Path $phaseFolder

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message "SPO Discovery (SOURCE) - Exporting OneDrive sites inventory (with size/quota)."

    # OneDrive personal sites are returned by Get-SPOSite when IncludePersonalSite is used.
    $sites = @(Get-SPOSite -IncludePersonalSite $true -Limit All | Where-Object {
        # Keep only OneDrive personal sites
        ([string]$_.Template) -eq "SPSPERS" -or
        ([string]$_.Url).Contains("/personal/")
    })

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("SPO Discovery (SOURCE) - OneDrive sites found: {0}" -f $sites.Count)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($s in $sites) {
        $rows.Add([pscustomobject]@{
            Url                   = [string]$s.Url
            Owner                 = [string]$s.Owner
            StorageQuotaMB        = [int]$s.StorageQuota
            StorageUsageCurrentMB = [int]$s.StorageUsageCurrent
            LastContentModifiedDate = $s.LastContentModifiedDate
            Status                = [string]$s.Status
            LockState             = [string]$s.LockState
        }) | Out-Null
    }

    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("SPO Discovery (SOURCE) - Export completed: {0} (rows: {1})" -f $outFile, $rows.Count)

    return @{
        Status  = "Completed"
        Message = ("Exported OneDrive sites to {0} (rows: {1})." -f (Split-Path $outFile -Leaf), $rows.Count)
    }
}
function Invoke-DiscoverySPOExportSitesSource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Ctx
    )

    $phaseFolder = Join-Path $Ctx.RunRoot "01-Discovery"
    $outFile     = Join-Path $phaseFolder "SPO-Sites_SOURCE.csv"

    Assert-EIDMDirectory -Path $phaseFolder

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message "SPO Discovery (SOURCE) - Exporting SharePoint sites inventory (minimal + hub awareness)."

    $allSites = @(Get-SPOSite -Limit All)

    # Exclude OneDrive personal sites
    $sites = @($allSites | Where-Object {
        -not (([string]$_.Url).Contains("/personal/"))
    })

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("SPO Discovery (SOURCE) - Sites found (excluding OneDrive): {0}" -f $sites.Count)

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($s in $sites) {

        # Hub fields might be absent depending on module/tenant; keep safe casts
        $isHub = $false
        $hubId = ""

        try { $isHub = [bool]$s.IsHubSite } catch { $isHub = $false }
        try { $hubId = [string]$s.HubSiteId } catch { $hubId = "" }

        $rows.Add([pscustomobject]@{
            Url                   = [string]$s.Url
            Title                 = [string]$s.Title
            Template              = [string]$s.Template
            Owner                 = [string]$s.Owner
            StorageQuotaMB        = [int]$s.StorageQuota
            StorageUsageCurrentMB = [int]$s.StorageUsageCurrent
            LastContentModifiedDate = $s.LastContentModifiedDate
            Status                = [string]$s.Status
            LockState             = [string]$s.LockState
            IsHubSite             = $isHub
            HubSiteId             = $hubId
        }) | Out-Null
    }

    $rows | Export-Csv -LiteralPath $outFile -NoTypeInformation -Encoding UTF8

    Write-EIDMLog -LogPath $Ctx.LogPath -Level INFO -Message ("SPO Discovery (SOURCE) - Export completed: {0} (rows: {1})" -f $outFile, $rows.Count)

    return @{
        Status  = "Completed"
        Message = ("Exported SharePoint sites to {0} (rows: {1})." -f (Split-Path $outFile -Leaf), $rows.Count)
    }
}

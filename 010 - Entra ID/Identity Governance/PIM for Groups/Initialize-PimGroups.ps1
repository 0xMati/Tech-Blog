#requires -Version 5.1
<#
.SYNOPSIS
Creates role-assignable security groups with active Entra roles and eligible PIM members.
.DESCRIPTION
Uses delegated Microsoft Graph v1.0 APIs. Existing compatible settings are reused.
Does not remove assignments, renew eligibility, activate beneficiaries, or change Entra role policies.
Without ConfigurationPath, an interactive assistant configures the article's two-role example.
The assistant accepts user UPNs or object IDs and offers permanent or time-bound eligibility.
Requires Microsoft.Graph.Authentication and an active directory-scoped Privileged Role
Administrator or Global Administrator. See the accompanying article for permissions and limitations.
If the module is missing, reports the installation command and stops without connecting.
The module is never installed automatically.
.EXAMPLE
.\Initialize-PimGroups.ps1 -Interactive -WhatIf
.EXAMPLE
.\Initialize-PimGroups.ps1 -ConfigurationPath .\pim-groups.json -WhatIf
.EXAMPLE
.\Initialize-PimGroups.ps1 -ConfigurationPath .\pim-groups.json -UseExistingConnection
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Configuration')]
    [string]$ConfigurationPath,
    [Parameter(ParameterSetName = 'Interactive')]
    [switch]$Interactive,
    [switch]$UseExistingConnection,
    [ValidateRange(1, 600)]
    [int]$PropagationTimeoutSeconds = 120
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:GraphRoot = 'https://graph.microsoft.com/v1.0'
$script:GraphWritesAllowed = $false

function Assert-Properties {
    param($Object, [string[]]$Required, [string[]]$Optional = @(), [string]$Context, [string[]]$AllowNull = @())
    if ($Object -isnot [pscustomobject]) { throw "$Context must be a JSON object." }
    foreach ($name in $Required) {
        if ($null -eq $Object.PSObject.Properties[$name] -or ($null -eq $Object.$name -and $name -notin $AllowNull)) {
            throw "$Context.$name is required."
        }
    }
    foreach ($property in $Object.PSObject.Properties.Name) {
        if ($property -notin ($Required + $Optional)) { throw "Unknown property: $Context.$property." }
    }
}

function ConvertTo-ObjectId {
    param($Value, [string]$Context)
    $id = [guid]::Empty
    if ($Value -isnot [string] -or -not [guid]::TryParse($Value, [ref]$id) -or $id -eq [guid]::Empty) {
        throw [System.ArgumentException]::new("$Context must be a non-empty object ID (GUID), not a name or placeholder.")
    }
    return $id.ToString('D')
}

function ConvertTo-IdList {
    param($Value, [string]$Context)
    if ($Value -isnot [array] -or $Value.Count -eq 0) { throw "$Context must be a non-empty JSON array." }
    $ids = @($Value | ForEach-Object { ConvertTo-ObjectId $_ $Context })
    if (@($ids | Sort-Object -Unique).Count -ne $ids.Count) { throw "$Context contains duplicate IDs." }
    return $ids
}

function ConvertTo-UtcDate {
    param($Value, [string]$Context)
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { throw [System.ArgumentException]::new("$Context must include an explicit time zone.") }
        return ([datetimeoffset]$Value).ToUniversalTime()
    }
    $date = [datetimeoffset]::MinValue
    if ($Value -isnot [string] -or $Value -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$' -or
        -not [datetimeoffset]::TryParse($Value, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$date)) {
        throw [System.ArgumentException]::new("$Context must be an absolute timestamp with a time zone, for example 2030-01-08T12:00:00Z.")
    }
    return $date.ToUniversalTime()
}

function ConvertTo-Duration {
    param($Value, [string]$Context)
    if ($Value -isnot [string] -or $Value -notmatch '^P(?=\d|T)(?:\d+D)?(?:T(?=\d)(?:\d+H)?(?:\d+M)?(?:\d+(?:\.\d+)?S)?)?$') {
        throw [System.ArgumentException]::new("$Context must be an ISO 8601 day/time duration, for example PT1H or P7D.")
    }
    $duration = [System.Xml.XmlConvert]::ToTimeSpan($Value)
    if ($duration -le [timespan]::Zero) { throw [System.ArgumentException]::new("$Context must be greater than zero.") }
    return $duration
}

function ConvertTo-GroupName {
    param($Value)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt 256) {
        throw [System.ArgumentException]::new('group.displayName must contain 1 to 256 characters.')
    }
    return $Value
}

function ConvertTo-MailNickname {
    param($Value, [switch]$ExistingGroup)
    if ($ExistingGroup) {
        if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) {
            throw [System.ArgumentException]::new('The existing group mailNickname must be provided unchanged.')
        }
        return $Value
    }
    if ($Value -isnot [string] -or $Value -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$') {
        throw [System.ArgumentException]::new('Invalid mailNickname; use 1 to 64 ASCII letters, digits, dots, underscores or hyphens.')
    }
    return $Value
}

function Read-Configuration {
    $config = Get-Content -LiteralPath $ConfigurationPath -Raw -Encoding UTF8 | ConvertFrom-Json
    ConvertTo-Configuration $config
}

function ConvertTo-Configuration {
    param($Config)
    Assert-Properties $config @('tenantId', 'justification', 'groups') @() 'configuration'
    $tenantId = ConvertTo-ObjectId $config.tenantId 'tenantId'
    if ($config.justification -isnot [string] -or [string]::IsNullOrWhiteSpace($config.justification)) {
        throw 'justification must be a non-empty string.'
    }
    if ($config.groups -isnot [array] -or $config.groups.Count -eq 0) { throw 'groups must be a non-empty JSON array.' }
    $groups = @(
        foreach ($group in $config.groups) {
            $required = @('displayName', 'mailNickname', 'description', 'ownerIds', 'approverIds',
                'eligibleMemberIds', 'eligibilityEndDateTime', 'maximumActivationDuration',
                'maximumEligibilityDuration', 'roles')
            Assert-Properties $group $required @('groupId') 'group' -AllowNull @('eligibilityEndDateTime')
            $groupId = $null
            if ($null -ne $group.PSObject.Properties['groupId'] -and $null -ne $group.groupId) {
                $groupId = ConvertTo-ObjectId $group.groupId 'groupId'
            }
            $displayName = ConvertTo-GroupName $group.displayName
            $mailNickname = ConvertTo-MailNickname $group.mailNickname -ExistingGroup:($null -ne $groupId)
            if ($group.description -isnot [string]) { throw 'group.description must be a string.' }
            $owners = @(ConvertTo-IdList $group.ownerIds 'ownerIds')
            $approvers = @(ConvertTo-IdList $group.approverIds 'approverIds')
            $members = @(ConvertTo-IdList $group.eligibleMemberIds 'eligibleMemberIds')
            foreach ($member in $members) {
                if ($member -in ($owners + $approvers)) {
                    throw "$($group.displayName): eligible members must not be group owners or activation approvers."
                }
            }
            $activationDuration = ConvertTo-Duration $group.maximumActivationDuration 'maximumActivationDuration'
            if ($activationDuration.TotalHours -lt 1 -or $activationDuration.TotalHours -gt 24) {
                throw 'maximumActivationDuration must be between 1 and 24 hours.'
            }
            $eligibilityDuration = ConvertTo-Duration $group.maximumEligibilityDuration 'maximumEligibilityDuration'
            $eligibilityEnd = $null
            $now = [datetimeoffset]::UtcNow
            if ($null -ne $group.eligibilityEndDateTime) {
                $eligibilityEnd = ConvertTo-UtcDate $group.eligibilityEndDateTime 'eligibilityEndDateTime'
                if ($eligibilityEnd -le $now -or ($eligibilityEnd - $now) -gt $eligibilityDuration) {
                    throw "$($group.displayName): eligibilityEndDateTime must be in the future and within maximumEligibilityDuration from now."
                }
            }
            if ($group.roles -isnot [array] -or $group.roles.Count -eq 0) { throw 'roles must be a non-empty JSON array.' }
            $roles = @(
                foreach ($role in $group.roles) {
                    Assert-Properties $role @('roleDefinitionId', 'directoryScopeId') @('endDateTime') 'role'
                    $roleId = ConvertTo-ObjectId $role.roleDefinitionId 'roleDefinitionId'
                    if ($role.directoryScopeId -isnot [string] -or
                        $role.directoryScopeId -notmatch '^/$|^/administrativeUnits/[0-9a-fA-F-]{36}$') {
                        throw 'directoryScopeId must be / or /administrativeUnits/{object-id}.'
                    }
                    $scope = $role.directoryScopeId
                    if ($scope -ne '/') {
                        $unitId = ConvertTo-ObjectId ($scope.Split('/')[-1]) 'administrative unit ID'
                        $scope = "/administrativeUnits/$unitId"
                    }
                    $end = $null
                    if ($null -ne $role.PSObject.Properties['endDateTime'] -and $null -ne $role.endDateTime) {
                        $end = ConvertTo-UtcDate $role.endDateTime 'role.endDateTime'
                        if ($end -le $now) { throw 'role.endDateTime must be in the future.' }
                        if ($null -ne $eligibilityEnd -and $end -lt $eligibilityEnd) {
                            throw 'A time-bound active role must cover the entire eligibility window.'
                        }
                    }
                    [pscustomobject]@{ RoleDefinitionId = $roleId; DirectoryScopeId = $scope; EndDateTime = $end }
                }
            )
            $keys = @($roles | ForEach-Object { "$($_.RoleDefinitionId)|$($_.DirectoryScopeId)" })
            if (@($keys | Sort-Object -Unique).Count -ne $keys.Count) { throw "$($group.displayName): duplicate role and scope." }
            [pscustomobject]@{
                GroupId = $groupId; DisplayName = $displayName; MailNickname = $mailNickname
                Description = $group.description; OwnerIds = $owners; ApproverIds = $approvers
                EligibleMemberIds = $members; EligibilityEnd = $eligibilityEnd
                ActivationDuration = $activationDuration; EligibilityDuration = $eligibilityDuration; Roles = $roles
            }
        }
    )
    foreach ($property in @('DisplayName', 'MailNickname')) {
        if (@($groups.$property | Sort-Object -Unique).Count -ne $groups.Count) { throw "Duplicate group $property in configuration." }
    }
    $boundIds = @($groups | Where-Object { $null -ne $_.GroupId } | ForEach-Object { $_.GroupId })
    if (@($boundIds | Sort-Object -Unique).Count -ne $boundIds.Count) { throw 'Duplicate groupId in configuration.' }
    return [pscustomobject]@{ TenantId = $tenantId; Justification = $config.justification; Groups = $groups }
}

function Invoke-Graph {
    param([ValidateSet('GET', 'POST', 'PATCH')][string]$Method = 'GET', [string]$Uri, $Body)
    if ($Uri.StartsWith('/')) { $Uri = $script:GraphRoot + $Uri }
    $address = [uri]$Uri
    if ($address.Scheme -ne 'https' -or $address.Host -ne 'graph.microsoft.com' -or
        -not $address.AbsolutePath.StartsWith('/v1.0/') -or -not $address.IsDefaultPort -or $address.UserInfo) {
        throw "Refusing an unexpected Graph URL: $Uri"
    }
    if ($Method -ne 'GET' -and (-not $script:GraphWritesAllowed -or $WhatIfPreference)) {
        throw "Graph write outside an approved deployment: $Method $Uri"
    }
    Write-Verbose "$Method $Uri"
    $parameters = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.Body = ConvertTo-Json -InputObject $Body -Depth 30 -Compress
        $parameters.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @parameters
}

function Get-GraphCollection {
    param([string]$Uri)
    $seen = @{}
    while ($Uri) {
        if ($seen.ContainsKey($Uri)) { throw "Graph returned a pagination loop: $Uri" }
        $seen[$Uri] = $true
        $response = Invoke-Graph -Uri $Uri
        if ($null -eq $response -or $null -eq $response.PSObject.Properties['value'] -or $response.value -isnot [array]) {
            throw "Graph did not return a collection: $Uri"
        }
        foreach ($item in $response.value) { $item }
        $Uri = $null
        if ($null -ne $response.PSObject.Properties['@odata.nextLink']) { $Uri = $response.'@odata.nextLink' }
    }
}

function Get-FilteredCollection {
    param([string]$Path, [string]$Filter, [string]$Select)
    $uri = $Path + '?$filter=' + [uri]::EscapeDataString($Filter)
    if ($Select) { $uri += '&$select=' + [uri]::EscapeDataString($Select) }
    Get-GraphCollection -Uri $uri
}

function Wait-GraphState {
    param([string]$Description, [scriptblock]$Condition)
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        if (& $Condition) { return }
        if ($timer.Elapsed.TotalSeconds -ge $PropagationTimeoutSeconds) { break }
        Start-Sleep -Seconds 2
    } while ($true)
    throw "Timed out waiting for $Description. Changes may already exist; inspect the tenant before rerunning. No automatic rollback was attempted."
}

function Get-LiveInstances {
    param([string]$Path, [string]$Filter)
    Get-FilteredCollection $Path $Filter | Where-Object {
        $null -eq $_.endDateTime -or [datetimeoffset]$_.endDateTime -gt [datetimeoffset]::UtcNow
    }
}

function Assert-InstanceDates {
    param($Instance, $ExpectedEnd, [string]$Context)
    if ([datetimeoffset]$Instance.startDateTime -gt [datetimeoffset]::UtcNow) {
        throw "$Context starts in the future; it is not effective now."
    }
    $end = $null
    if ($null -ne $Instance.endDateTime) { $end = [datetimeoffset]$Instance.endDateTime }
    if ($end -ne $ExpectedEnd) { throw "$Context has a different expiration. Existing assignments are never shortened, extended or converted automatically." }
}

function Test-UnfinishedRequest {
    param($Request)
    if ($Request.status -like 'Pending*' -or $Request.status -eq 'Accepted') { return $true }
    if ($Request.status -notin @('Granted', 'ScheduleCreated')) { return $false }
    $schedule = $Request.scheduleInfo
    $expiration = $schedule.expiration
    switch ($expiration.type) {
        'noExpiration' { return $true }
        'afterDateTime' { return [datetimeoffset]$expiration.endDateTime -gt [datetimeoffset]::UtcNow }
        'afterDuration' {
            return ([datetimeoffset]$schedule.startDateTime + [System.Xml.XmlConvert]::ToTimeSpan($expiration.duration)) -gt [datetimeoffset]::UtcNow
        }
        default { throw "Unknown expiration type on schedule request $($Request.id)." }
    }
}

function Get-MemberPolicy {
    param([string]$GroupId)
    $assignments = @(Get-FilteredCollection '/policies/roleManagementPolicyAssignments' "scopeId eq '$GroupId' and scopeType eq 'Group'")
    $member = @($assignments | Where-Object { $_.roleDefinitionId -eq 'member' })
    if ($member.Count -ne 1) { throw "Expected one Member policy assignment for group $GroupId; found $($member.Count)." }
    Invoke-Graph -Uri ("/policies/roleManagementPolicies/$([uri]::EscapeDataString($member[0].policyId))" + '?$expand=rules')
}

function Get-PolicyChanges {
    param($Policy, $Group)
    $rules = @{}
    foreach ($rule in $Policy.rules) { $rules[$rule.id] = $rule }
    $requiredIds = @('Expiration_EndUser_Assignment', 'Enablement_EndUser_Assignment',
        'Approval_EndUser_Assignment', 'Expiration_Admin_Eligibility', 'Expiration_Admin_Assignment')
    foreach ($id in $requiredIds) {
        if (-not $rules.ContainsKey($id)) { throw "Missing PIM rule $id in Member policy $($Policy.id)." }
    }
    foreach ($spec in @(
            @{ Id = 'Expiration_EndUser_Assignment'; Duration = $Group.ActivationDuration; Required = $true },
            @{
                Id = 'Expiration_Admin_Eligibility'; Required = ($null -ne $Group.EligibilityEnd)
                Duration = $(if ($null -ne $Group.EligibilityEnd) { $Group.EligibilityDuration } else { $null })
            },
            @{ Id = 'Expiration_Admin_Assignment'; Duration = $null; Required = $true }
        )) {
        $rule = $rules[$spec.Id]
        $durationChanged = $null -ne $spec.Duration -and
            [System.Xml.XmlConvert]::ToTimeSpan($rule.maximumDuration) -ne $spec.Duration
        if ($rule.isExpirationRequired -ne $spec.Required -or $durationChanged) {
            $change = @{
                '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'
                id = $rule.id; target = $rule.target; isExpirationRequired = $spec.Required
                maximumDuration = $rule.maximumDuration
            }
            if ($null -ne $spec.Duration) { $change.maximumDuration = [System.Xml.XmlConvert]::ToString($spec.Duration) }
            $change
        }
    }
    $rule = $rules['Enablement_EndUser_Assignment']
    $enabled = @(@($rule.enabledRules) + @('MultiFactorAuthentication', 'Justification') | Sort-Object -Unique)
    if (@($rule.enabledRules | Sort-Object -Unique) -join ',' -ne ($enabled -join ',')) {
        @{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'
            id = $rule.id; target = $rule.target; enabledRules = $enabled
        }
    }
    $rule = $rules['Approval_EndUser_Assignment']
    $setting = $rule.setting
    $stages = @($setting.approvalStages)
    if ($stages.Count -gt 1 -or ($setting.isApprovalRequired -and $setting.approvalMode -ne 'SingleStage') -or
        ($stages.Count -eq 1 -and $stages[0].isEscalationEnabled)) {
        throw "$($Group.DisplayName): an existing multi-stage or escalated approval policy requires manual review; it will not be replaced."
    }
    $currentIds = @()
    if ($stages.Count -eq 1) {
        foreach ($approver in $stages[0].primaryApprovers) {
            if ($approver.'@odata.type' -ne '#microsoft.graph.singleUser') {
                throw "$($Group.DisplayName): V1 supports individual user approvers only; the existing approval policy will not be replaced."
            }
            $currentIds += $approver.userId
        }
    }
    $approvalChanged = -not $setting.isApprovalRequired -or -not $setting.isRequestorJustificationRequired -or
        $stages.Count -ne 1 -or (($currentIds | Sort-Object) -join ',') -ne (($Group.ApproverIds | Sort-Object) -join ',')
    if ($stages.Count -eq 1 -and -not $stages[0].isApproverJustificationRequired) { $approvalChanged = $true }
    if ($approvalChanged) {
        $timeout = 1
        if ($stages.Count -eq 1) { $timeout = $stages[0].approvalStageTimeOutInDays }
        @{
            '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyApprovalRule'
            id = $rule.id; target = $rule.target
            setting = @{
                isApprovalRequired = $true; isRequestorJustificationRequired = $true
                isApprovalRequiredForExtension = $setting.isApprovalRequiredForExtension
                approvalMode = 'SingleStage'
                approvalStages = @(@{
                    approvalStageTimeOutInDays = $timeout; isApproverJustificationRequired = $true
                    isEscalationEnabled = $false; escalationTimeInMinutes = 0; escalationApprovers = @()
                    primaryApprovers = @($Group.ApproverIds | Sort-Object | ForEach-Object {
                        @{ '@odata.type' = '#microsoft.graph.singleUser'; userId = $_ }
                    })
                })
            }
        }
    }
}

function Find-ExistingGroup {
    param($Group)
    $select = 'id,displayName,mailNickname,isAssignableToRole,securityEnabled,mailEnabled,groupTypes,onPremisesSyncEnabled'
    if ($Group.GroupId) {
        $found = @(Get-FilteredCollection '/groups' "id eq '$($Group.GroupId)'" $select)
        if ($found.Count -eq 0) { throw "Configured groupId $($Group.GroupId) was not found." }
    }
    else {
        $name = $Group.DisplayName.Replace("'", "''")
        $found = @(Get-FilteredCollection '/groups' "displayName eq '$name'" $select)
    }
    if ($found.Count -gt 1) { throw "Ambiguous group name $($Group.DisplayName); set groupId explicitly." }
    if ($found.Count -eq 0) { return }
    return $found[0]
}

function Get-ExistingGroup {
    param($Group)
    $item = Find-ExistingGroup $Group
    if ($null -eq $item) { return }
    $checks = @(
        @{ Name = 'displayName'; Expected = $Group.DisplayName; Requirement = 'Use the current display name; this script does not rename groups.' },
        @{ Name = 'mailNickname'; Expected = $Group.MailNickname; Requirement = 'Use the existing mailNickname, which can differ from the display name.' },
        @{ Name = 'isAssignableToRole'; Expected = $true; Requirement = 'This flag is immutable; an ordinary group cannot be converted into a role-assignable group.' },
        @{ Name = 'securityEnabled'; Expected = $true; Requirement = 'A role-assignable Security group is required.' },
        @{ Name = 'mailEnabled'; Expected = $false; Requirement = 'This script supports Security groups, not Microsoft 365 groups.' },
        @{ Name = 'groupTypes'; Expected = @(); Requirement = 'Assigned Security membership is required; Microsoft 365 and dynamic groups are not supported by this script.' },
        @{ Name = 'onPremisesSyncEnabled'; Expected = $false; Requirement = 'The group must be cloud-only; synchronized groups are not supported.' }
    )
    $mismatches = @(
        foreach ($check in $checks) {
            $property = $item.PSObject.Properties[$check.Name]
            if ($null -eq $property) {
                "$($check.Name) was not returned by Graph; compatibility could not be verified."
                continue
            }
            $actual = $property.Value
            $compatible = switch ($check.Name) {
                'groupTypes' { @($actual).Count -eq 0 }
                'onPremisesSyncEnabled' { $actual -ne $true }
                default { $actual -eq $check.Expected }
            }
            if (-not $compatible) {
                $actualText = ConvertTo-Json -InputObject $actual -Depth 5 -Compress
                $expectedText = ConvertTo-Json -InputObject $check.Expected -Depth 5 -Compress
                if ($check.Name -eq 'onPremisesSyncEnabled') { $expectedText += ' or null' }
                "{0}: actual {1}; expected {2}. {3}" -f $check.Name, $actualText, $expectedText, $check.Requirement
            }
        }
    )
    if ($mismatches.Count -gt 0) {
        throw ("Existing group {0} cannot be reused:`n - {1}`nNo conversion or rename will be attempted." -f
            $item.id, ($mismatches -join "`n - "))
    }
    return $item
}

function Get-GroupPlan {
    param($Group)
    $existing = Get-ExistingGroup $Group
    $ownersToAdd = @($Group.OwnerIds)
    $rolesToAdd = @($Group.Roles)
    $membersToAdd = @($Group.EligibleMemberIds)
    $policy = $null
    $changes = @()
    if ($null -ne $existing) {
        $id = $existing.id
        $owners = @(Get-GraphCollection -Uri ("/groups/$id/owners" + '?$select=id'))
        if (@($owners | Where-Object { $_.id -notin $Group.OwnerIds }).Count -gt 0) {
            throw "Group $id has owners outside ownerIds. Review them manually; no owners will be removed."
        }
        $existingOwnerIds = @($owners | ForEach-Object { $_.id })
        $ownersToAdd = @($Group.OwnerIds | Where-Object { $_ -notin $existingOwnerIds })
        $members = @(Get-GraphCollection -Uri ("/groups/$id/members" + '?$select=id'))
        $active = @(Get-LiveInstances '/identityGovernance/privilegedAccess/group/assignmentScheduleInstances' "groupId eq '$id'")
        foreach ($instance in $active) {
            if ($instance.accessId -eq 'member' -and
                ($instance.assignmentType -ne 'activated' -or $instance.principalId -notin $Group.EligibleMemberIds)) {
                throw "Group $id has an unexpected or standing active member schedule for $($instance.principalId). Review it manually."
            }
            if ($instance.accessId -eq 'owner' -and $instance.principalId -notin $Group.OwnerIds) {
                throw "Group $id has an owner schedule outside ownerIds. Review it manually."
            }
        }
        foreach ($member in $members) {
            $activation = @($active | Where-Object {
                $_.principalId -eq $member.id -and $_.accessId -eq 'member' -and $_.assignmentType -eq 'activated' -and
                [datetimeoffset]$_.startDateTime -le [datetimeoffset]::UtcNow
            })
            if ($member.id -notin $Group.EligibleMemberIds -or $activation.Count -ne 1) {
                throw "Group $id has an unexpected or standing active member $($member.id). Review membership manually before granting roles."
            }
        }
        $roleInstances = @(Get-LiveInstances '/roleManagement/directory/roleAssignmentScheduleInstances' "principalId eq '$id'")
        foreach ($instance in $roleInstances) {
            if (@($Group.Roles | Where-Object {
                    $_.RoleDefinitionId -eq $instance.roleDefinitionId -and $_.DirectoryScopeId -eq $instance.directoryScopeId
                }).Count -eq 0) { throw "Group $id carries a role or scope outside the configuration. No role assignments will be removed." }
        }
        $rolesToAdd = @(
            foreach ($role in $Group.Roles) {
                $matches = @($roleInstances | Where-Object {
                    $_.roleDefinitionId -eq $role.RoleDefinitionId -and $_.directoryScopeId -eq $role.DirectoryScopeId
                })
                if ($matches.Count -gt 1) { throw "Multiple active assignments for role $($role.RoleDefinitionId) on group $id." }
                if ($matches.Count -eq 0) { $role }
                else {
                    if ($matches[0].assignmentType -ne 'Assigned') { throw "Group $id must carry assigned active roles, not activated eligible roles." }
                    Assert-InstanceDates $matches[0] $role.EndDateTime "Role $($role.RoleDefinitionId) on group $id"
                }
            }
        )
        $eligible = @(Get-LiveInstances '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances' "groupId eq '$id'")
        foreach ($instance in $eligible) {
            if ($instance.accessId -ne 'member' -or $instance.principalId -notin $Group.EligibleMemberIds) {
                throw "Group $id has eligibility outside eligibleMemberIds, or eligible ownership. Review it manually."
            }
        }
        $membersToAdd = @(
            foreach ($memberId in $Group.EligibleMemberIds) {
                $matches = @($eligible | Where-Object { $_.principalId -eq $memberId -and $_.accessId -eq 'member' })
                if ($matches.Count -gt 1) { throw "Multiple eligibility instances for $memberId on group $id." }
                if ($matches.Count -eq 0) { $memberId }
                else { Assert-InstanceDates $matches[0] $Group.EligibilityEnd "Eligibility for $memberId on group $id" }
            }
        )
        foreach ($spec in @(
                @{ Path = '/roleManagement/directory/roleAssignmentScheduleRequests'; Filter = "principalId eq '$id'"; Needed = $rolesToAdd; Kind = 'Role' },
                @{ Path = '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'; Filter = "groupId eq '$id'"; Needed = $membersToAdd; Kind = 'Member' }
            )) {
            if (@($spec.Needed).Count -gt 0) {
                $requests = @(Get-FilteredCollection $spec.Path $spec.Filter | Where-Object {
                    $request = $_
                    $relevant = $false
                    if ($spec.Kind -eq 'Role') {
                        $relevant = @($spec.Needed | Where-Object {
                            $_.RoleDefinitionId -eq $request.roleDefinitionId -and $_.DirectoryScopeId -eq $request.directoryScopeId
                        }).Count -gt 0
                    }
                    else { $relevant = $request.accessId -eq 'member' -and $request.principalId -in $spec.Needed }
                    $relevant -and (Test-UnfinishedRequest $request)
                })
                if ($requests.Count -gt 0) {
                    throw "Group $id has an unfinished schedule request $($requests[0].id) ($($requests[0].status)); inspect it before rerunning."
                }
            }
        }
        $policy = Get-MemberPolicy $id
        $changes = @(Get-PolicyChanges $policy $Group)
    }
    return [pscustomobject]@{
        Configuration = $Group; Existing = $existing; OwnersToAdd = $ownersToAdd
        RolesToAdd = $rolesToAdd; MembersToAdd = $membersToAdd; Policy = $policy; PolicyChanges = $changes
        HasChanges = ($null -eq $existing -or $ownersToAdd.Count -gt 0 -or $rolesToAdd.Count -gt 0 -or
            $membersToAdd.Count -gt 0 -or $changes.Count -gt 0)
    }
}

function Get-RoleAssignmentPolicy {
    param([string]$Id)
    $assignments = @(Get-FilteredCollection '/policies/roleManagementPolicyAssignments' "scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$id'")
    if ($assignments.Count -ne 1) { throw "Expected one directory-role policy assignment for role $id." }
    $policyId = [uri]::EscapeDataString($assignments[0].policyId)
    $policy = Invoke-Graph -Uri ("/policies/roleManagementPolicies/$policyId" + '?$expand=rules')
    $expiration = @($policy.rules | Where-Object { $_.id -eq 'Expiration_Admin_Assignment' })
    if ($expiration.Count -ne 1) { throw "Missing active-assignment expiration rule for role $id." }
    $enablement = @($policy.rules | Where-Object { $_.id -eq 'Enablement_Admin_Assignment' })
    return [pscustomobject]@{
        IsExpirationRequired = $expiration[0].isExpirationRequired
        MaximumDuration = [System.Xml.XmlConvert]::ToTimeSpan($expiration[0].maximumDuration)
        RequiresTicket = ($enablement.Count -eq 1 -and 'Ticketing' -in $enablement[0].enabledRules)
    }
}

function Assert-RoleAssignmentPolicy {
    param($Role)
    $id = $Role.RoleDefinitionId
    $policy = Get-RoleAssignmentPolicy $id
    if ($null -eq $Role.EndDateTime) {
        if ($policy.IsExpirationRequired) { throw "Role $id requires an end date. Set role.endDateTime; its Entra role policy will not be weakened." }
    }
    else {
        if ($Role.EndDateTime -le [datetimeoffset]::UtcNow) { throw "role.endDateTime must still be in the future for role $id." }
        if (($Role.EndDateTime - [datetimeoffset]::UtcNow) -gt $policy.MaximumDuration) {
            throw "role.endDateTime exceeds the active-assignment maximum duration for role $id."
        }
    }
    if ($policy.RequiresTicket) {
        throw "Role $id requires ticket information. V1 does not submit tickets or change the policy; configure this assignment separately."
    }
}

function New-ScheduleInfo {
    param($End)
    $expiration = @{ type = 'noExpiration' }
    if ($null -ne $End) { $expiration = @{ type = 'afterDateTime'; endDateTime = $End.ToString('o') } }
    return @{ startDateTime = [datetimeoffset]::UtcNow.ToString('o'); expiration = $expiration }
}

function Assert-AuthenticationModule {
    $authenticationModule = 'Microsoft.Graph.Authentication'
    if (-not (Get-Module -Name $authenticationModule)) {
        if (-not (Get-Module -Name $authenticationModule -ListAvailable)) {
            throw "Required module '$authenticationModule' was not found. Install it with: Install-Module -Name $authenticationModule -Scope CurrentUser. Then rerun the script. No connection or tenant changes were attempted."
        }
        Import-Module -Name $authenticationModule -ErrorAction Stop
    }
}

function Read-InteractiveValue {
    param([string]$Prompt, [string]$Default, [scriptblock]$Convert)
    while ($true) {
        $label = $Prompt
        if (-not [string]::IsNullOrEmpty($Default)) { $label += " [$Default]" }
        $value = [string](Read-Host -Prompt $label)
        if ([string]::IsNullOrWhiteSpace($value)) { $value = $Default }
        try {
            return (& $Convert $value.Trim())
        }
        catch [System.ArgumentException], [System.FormatException], [System.OverflowException] {
            Write-Warning $_.Exception.Message
        }
    }
}

function Read-InteractiveUsers {
    param([string]$Prompt, [string]$Default, [string[]]$ForbiddenIds = @())
    while ($true) {
        $inputText = Read-InteractiveValue "$Prompt (UPNs or object IDs, comma/semicolon-separated)" $Default {
            param($value)
            if ([string]::IsNullOrWhiteSpace($value)) { throw [System.ArgumentException]::new('Enter at least one user.') }
            return $value
        }
        $ids = @()
        $valid = $true
        foreach ($identifier in ($inputText -split '[,;]')) {
            $identifier = $identifier.Trim()
            $guid = [guid]::Empty
            if ([guid]::TryParse($identifier, [ref]$guid) -and $guid -ne [guid]::Empty) {
                $filter = "id eq '$($guid.ToString('D'))'"
            }
            elseif ($identifier -match '^[^@\s]+@[^@\s]+$') {
                $filter = "userPrincipalName eq '$($identifier.Replace("'", "''"))'"
            }
            else {
                Write-Warning "Invalid user '$identifier': enter a UPN or a non-empty object ID."
                $valid = $false
                break
            }
            $users = @(Get-FilteredCollection '/users' $filter 'id,userPrincipalName,accountEnabled')
            if ($users.Count -ne 1 -or $users[0].accountEnabled -ne $true) {
                Write-Warning "User '$identifier' was not found uniquely in this tenant, or is not enabled."
                $valid = $false
                break
            }
            $id = ConvertTo-ObjectId $users[0].id 'resolved user ID'
            if ($id -in $ForbiddenIds) {
                Write-Warning "User '$identifier' is an owner or approver and cannot also be an eligible member in this configuration."
                $valid = $false
                break
            }
            $ids += $id
        }
        if ($valid) {
            if (@($ids | Sort-Object -Unique).Count -ne $ids.Count) {
                Write-Warning 'The same user was selected more than once. Enter each user only once.'
            }
            else { return $ids }
        }
    }
}

function Read-InteractiveConfiguration {
    param([string]$TenantId, [string]$ConnectedUserId)
    Write-Host "`nArticle example: role-assignable Security group, User Administrator + Groups Administrator, directory scope."
    Write-Host 'MFA, justification and single-stage approval remain required. These two roles overlap; review the bundle before deployment.'
    $name = Read-InteractiveValue 'Group name' 'PIM-Identity-Admins' { param($value) ConvertTo-GroupName $value }
    $defaultAlias = 'PIM-Identity-Admins'
    if ($name -match '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$') { $defaultAlias = $name }
    $identity = [pscustomobject]@{ GroupId = $null; DisplayName = $name; MailNickname = $defaultAlias }
    $discovered = Find-ExistingGroup $identity
    if ($null -ne $discovered) {
        $identity.GroupId = $discovered.id
        $defaultAlias = $discovered.mailNickname
    }
    $alias = Read-InteractiveValue 'Group mail nickname' $defaultAlias {
        param($value)
        if ($null -ne $discovered) {
            if ($value -ne $discovered.mailNickname) {
                throw [System.ArgumentException]::new('The existing group mailNickname must be kept. Press Enter to use its current value; this script does not rename groups.')
            }
            return (ConvertTo-MailNickname $discovered.mailNickname -ExistingGroup)
        }
        ConvertTo-MailNickname $value
    }
    $identity.MailNickname = $alias
    $existing = Get-ExistingGroup $identity
    $existingEligible = @()
    $existingRoles = @()
    $existingPolicy = $null
    $ownerDefault = $ConnectedUserId
    if ($null -ne $existing) {
        Write-Host "Found existing group $($existing.id). Existing assignments will not be renewed or converted."
        $owners = @(Get-GraphCollection -Uri ("/groups/$($existing.id)/owners" + '?$select=id'))
        if ($owners.Count -gt 0) { $ownerDefault = ($owners | ForEach-Object { $_.id }) -join ',' }
        $existingEligible = @(Get-LiveInstances '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances' "groupId eq '$($existing.id)'")
        $existingRoles = @(Get-LiveInstances '/roleManagement/directory/roleAssignmentScheduleInstances' "principalId eq '$($existing.id)'")
        $existingPolicy = Get-MemberPolicy $existing.id
    }
    $ownerIds = @(Read-InteractiveUsers 'Group owners' $ownerDefault)
    $approverDefault = $ownerIds -join ','
    $activationDefault = '1'
    if ($null -ne $existingPolicy) {
        $approval = @($existingPolicy.rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' })
        if ($approval.Count -eq 1) {
            $stages = @($approval[0].setting.approvalStages)
            if ($stages.Count -eq 1 -and -not $stages[0].isEscalationEnabled) {
                $approvers = @($stages[0].primaryApprovers)
                if ($approvers.Count -gt 0 -and @($approvers | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.singleUser' }).Count -eq 0) {
                    $approverDefault = ($approvers | ForEach-Object { $_.userId }) -join ','
                }
            }
        }
        $activation = @($existingPolicy.rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' })
        if ($activation.Count -eq 1) {
            $hours = [System.Xml.XmlConvert]::ToTimeSpan($activation[0].maximumDuration).TotalHours
            if ($hours -ne [math]::Truncate($hours)) { throw 'The assistant supports whole-hour activation settings. Use JSON for this existing group.' }
            $activationDefault = $hours.ToString([cultureinfo]::InvariantCulture)
        }
    }
    $approverIds = @(Read-InteractiveUsers 'Activation approvers (prefer at least two)' $approverDefault)
    $memberDefault = (@($existingEligible | Where-Object { $_.accessId -eq 'member' } |
            ForEach-Object { $_.principalId } | Sort-Object -Unique)) -join ','
    $memberIds = @(Read-InteractiveUsers 'Eligible members' $memberDefault ($ownerIds + $approverIds))
    $activationHours = Read-InteractiveValue 'Activation maximum duration in whole hours (1-24)' $activationDefault {
        param($value)
        $number = 0
        if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1 -or $number -gt 24) {
            throw [System.ArgumentException]::new('Enter a whole number from 1 to 24 hours.')
        }
        return $number
    }
    $previousEnds = @($existingEligible | Where-Object { $_.accessId -eq 'member' -and $_.principalId -in $memberIds } |
        ForEach-Object {
            if ($null -eq $_.endDateTime) { 'permanent' }
            else { ([datetimeoffset]$_.endDateTime).ToUniversalTime().ToString('o') }
        } | Sort-Object -Unique)
    if ($previousEnds.Count -gt 1) { throw 'Selected users have different existing eligibility deadlines. Review them manually before using this assistant.' }
    $modeDefault = 'T'
    $previousEnd = $null
    if ($previousEnds.Count -eq 1) {
        if ($previousEnds[0] -eq 'permanent') { $modeDefault = 'P' }
        else { $previousEnd = [datetimeoffset]$previousEnds[0] }
    }
    $mode = Read-InteractiveValue 'Eligibility: P = permanent, T = time-bound' $modeDefault {
        param($value)
        switch ($value.ToUpperInvariant()) {
            'P' { return 'P' }
            'T' { return 'T' }
            default { throw [System.ArgumentException]::new('Enter P for permanent eligibility or T for time-bound eligibility.') }
        }
    }
    $eligibilityEnd = $null
    $maximumEligibility = 'P7D'
    if ($mode -eq 'T') {
        $dayDefault = 7
        if ($null -ne $existingPolicy) {
            $eligibilityRule = @($existingPolicy.rules | Where-Object { $_.id -eq 'Expiration_Admin_Eligibility' })
            if ($eligibilityRule.Count -eq 1 -and $eligibilityRule[0].isExpirationRequired) {
                $policyDays = [System.Xml.XmlConvert]::ToTimeSpan($eligibilityRule[0].maximumDuration).TotalDays
                if ($policyDays -lt 1 -or $policyDays -ne [math]::Truncate($policyDays)) {
                    throw 'The assistant supports whole-day eligibility limits. Use JSON for this existing group.'
                }
                $dayDefault = $policyDays
            }
        }
        $days = Read-InteractiveValue 'Maximum eligibility duration in days' ([string]$dayDefault) {
            param($value)
            $number = 0
            if (-not [int]::TryParse($value, [ref]$number) -or $number -lt 1) {
                throw [System.ArgumentException]::new('Enter a positive number of days.')
            }
            $null = [datetimeoffset]::UtcNow.AddDays($number)
            return $number
        }
        $maximumEligibility = "P${days}D"
        $limit = ConvertTo-Duration $maximumEligibility 'maximumEligibilityDuration'
        $endDefault = [datetimeoffset]::UtcNow.AddDays($days)
        if ($null -ne $previousEnd) { $endDefault = $previousEnd }
        $eligibilityEnd = Read-InteractiveValue 'Fixed eligibility end (UTC timestamp, not activation end)' ($endDefault.ToString('o')) {
            param($value)
            $date = ConvertTo-UtcDate $value 'eligibilityEndDateTime'
            $now = [datetimeoffset]::UtcNow
            if ($date -le $now -or ($date - $now) -gt $limit) {
                throw [System.ArgumentException]::new('The eligibility deadline must be in the future and within the selected maximum duration.')
            }
            return $date
        }
    }
    else { Write-Host 'Permanent eligibility selected. Membership still requires a time-limited, approved activation.' }
    Write-Host "`nActive role assignments ON THE GROUP (separate from membership activation):"
    $roles = @(
        foreach ($example in @(
                @{ Name = 'User Administrator'; Id = 'fe930be7-5e62-47db-91af-98c3a49a38b1' },
                @{ Name = 'Groups Administrator'; Id = 'fdd7a751-b60b-444a-984c-02652fe8fa1c' }
            )) {
            $instances = @($existingRoles | Where-Object { $_.roleDefinitionId -eq $example.Id -and $_.directoryScopeId -eq '/' })
            if ($instances.Count -gt 1) { throw "Multiple active assignments for $($example.Name); review them manually." }
            $end = $null
            if ($instances.Count -eq 1) {
                if ($null -ne $instances[0].endDateTime) { $end = [datetimeoffset]$instances[0].endDateTime }
                Write-Host ("Keeping existing {0} assignment (end: {1})." -f $example.Name, $instances[0].endDateTime)
            }
            else {
                $rolePolicy = Get-RoleAssignmentPolicy $example.Id
                if ($rolePolicy.RequiresTicket) { throw "Role $($example.Name) requires ticket information. Configure this assignment separately." }
                $roleDefault = 'permanent'
                if ($rolePolicy.IsExpirationRequired) {
                    $defaultDate = [datetimeoffset]::UtcNow + $rolePolicy.MaximumDuration
                    if ($null -ne $eligibilityEnd) {
                        if ($eligibilityEnd -gt $defaultDate) { throw "The eligibility window exceeds the active-assignment limit for $($example.Name). Rerun with a shorter eligibility window." }
                        $defaultDate = $eligibilityEnd
                    }
                    $roleDefault = $defaultDate.ToString('o')
                }
                $end = Read-InteractiveValue "$($example.Name) active assignment end (permanent or UTC timestamp)" $roleDefault {
                    param($value)
                    if ($value -eq 'permanent') {
                        if ($rolePolicy.IsExpirationRequired) { throw [System.ArgumentException]::new('This role policy requires an end date; it will not be weakened.') }
                        return $null
                    }
                    $date = ConvertTo-UtcDate $value 'role.endDateTime'
                    $now = [datetimeoffset]::UtcNow
                    if ($date -le $now -or ($date - $now) -gt $rolePolicy.MaximumDuration) {
                        throw [System.ArgumentException]::new('The role end date must be in the future and within its active-assignment policy limit.')
                    }
                    if ($null -ne $eligibilityEnd -and $date -lt $eligibilityEnd) {
                        throw [System.ArgumentException]::new('The active role must cover the selected eligibility window.')
                    }
                    return $date
                }
            }
            [pscustomobject]@{
                roleDefinitionId = $example.Id; directoryScopeId = '/'
                endDateTime = $(if ($null -ne $end) { $end.ToString('o') } else { $null })
            }
        }
    )
    $justification = Read-InteractiveValue 'Deployment justification' 'Deploy the reviewed PIM for Groups pilot.' {
        param($value)
        if ([string]::IsNullOrWhiteSpace($value)) { throw [System.ArgumentException]::new('A deployment justification is required.') }
        return $value
    }
    ConvertTo-Configuration ([pscustomobject]@{
        tenantId = $TenantId; justification = $justification
        groups = @([pscustomobject]@{
            groupId = $identity.GroupId
            displayName = $name; mailNickname = $alias; description = 'Temporary user and group administration through PIM membership.'
            ownerIds = $ownerIds; approverIds = $approverIds; eligibleMemberIds = $memberIds
            eligibilityEndDateTime = $(if ($null -ne $eligibilityEnd) { $eligibilityEnd.ToString('o') } else { $null })
            maximumActivationDuration = "PT${activationHours}H"; maximumEligibilityDuration = $maximumEligibility
            roles = $roles
        })
    })
}

function Show-InteractiveSummary {
    param($Configuration)
    $group = $Configuration.Groups[0]
    Write-Host "`nReview the configuration (no tenant changes have been made):"
    Write-Host "Tenant: $($Configuration.TenantId)"
    Write-Host "Group: $($group.DisplayName) / $($group.MailNickname)"
    Write-Host "Owners: $($group.OwnerIds -join ', ')"
    Write-Host "Approvers: $($group.ApproverIds -join ', ')"
    Write-Host "Eligible members: $($group.EligibleMemberIds -join ', ')"
    Write-Host "Activation maximum: $($group.ActivationDuration.TotalHours) hour(s); MFA + justification + approval required."
    $eligibility = 'permanent (not permanently active)'
    if ($null -ne $group.EligibilityEnd) { $eligibility = $group.EligibilityEnd.ToString('o') }
    Write-Host "Eligibility end: $eligibility"
    foreach ($role in $group.Roles) {
        $end = 'permanent'
        if ($null -ne $role.EndDateTime) { $end = $role.EndDateTime.ToString('o') }
        Write-Host "Active role: $($role.RoleDefinitionId), scope $($role.DirectoryScopeId), end $end"
    }
}

$isInteractive = $PSCmdlet.ParameterSetName -eq 'Interactive'
$configuration = $null
$unitIds = @()
if ($isInteractive) {
    Assert-AuthenticationModule
    $defaultTenant = ''
    if ($UseExistingConnection) {
        $existingContext = Get-MgContext
        if ($null -ne $existingContext) { $defaultTenant = $existingContext.TenantId }
    }
    Write-Host 'PIM for Groups assistant. Press Enter to keep a displayed default; Ctrl+C cancels.'
    $tenantId = Read-InteractiveValue 'Tenant ID' $defaultTenant { param($value) ConvertTo-ObjectId $value 'tenantId' }
}
else {
    $configuration = Read-Configuration
    $tenantId = $configuration.TenantId
    $unitIds = @($configuration.Groups.Roles | Where-Object { $_.DirectoryScopeId -ne '/' } |
        ForEach-Object { $_.DirectoryScopeId.Split('/')[-1] } | Sort-Object -Unique)
    Assert-AuthenticationModule
}
$requiredScopes = @('Group.ReadWrite.All', 'User.Read.All', 'RoleManagement.ReadWrite.Directory',
    'RoleManagementPolicy.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
    'PrivilegedAssignmentSchedule.Read.AzureADGroup')
if ($unitIds.Count -gt 0) { $requiredScopes += 'AdministrativeUnit.Read.All' }
if (-not $UseExistingConnection) {
    Connect-MgGraph -TenantId $tenantId -Scopes $requiredScopes -Environment Global -ContextScope Process -NoWelcome -ErrorAction Stop
}
$context = Get-MgContext
if ($null -eq $context -or $context.AuthType -ne 'Delegated' -or
    $context.TenantId -ne $tenantId -or $context.Environment -ne 'Global') {
    throw 'A delegated Global-cloud Graph connection to the configured tenant is required.'
}
foreach ($scope in $requiredScopes) {
    if ($scope -notin $context.Scopes) { throw "The Graph connection is missing scope $scope. Reconnect with the documented delegated scopes." }
}
$me = Invoke-Graph -Uri '/me?$select=id'
$principalIds = @($me.id) + @(Get-GraphCollection -Uri '/me/transitiveMemberOf/microsoft.graph.group?$select=id' | ForEach-Object { $_.id })
$adminAssignments = @(
    foreach ($roleId in @('e8611ab8-c189-46e8-94e1-60213ab1f814', '62e90394-69f5-4237-9190-012177145e10')) {
        Get-FilteredCollection '/roleManagement/directory/roleAssignments' "roleDefinitionId eq '$roleId'"
    }
)
if (@($adminAssignments | Where-Object { $_.principalId -in $principalIds -and $_.directoryScopeId -eq '/' }).Count -eq 0) {
    throw 'Activate a directory-scoped Privileged Role Administrator (recommended) or Global Administrator role before running this script.'
}
Write-Warning 'Licensing is a manual prerequisite: confirm coverage for every eligible user and activation approver. This script does not inspect or assign licenses.'
if ($isInteractive) { $configuration = Read-InteractiveConfiguration $tenantId $me.id }
foreach ($group in $configuration.Groups) {
    if ($null -eq $group.EligibilityEnd) {
        foreach ($role in $group.Roles) {
            if ($null -ne $role.EndDateTime) {
                Write-Warning ("{0}: eligibility is permanent, but active role {1} expires at {2}. It is not renewed automatically." -f
                    $group.DisplayName, $role.RoleDefinitionId, $role.EndDateTime.ToString('o'))
            }
        }
    }
}
$userIds = @($configuration.Groups | ForEach-Object { $_.OwnerIds; $_.ApproverIds; $_.EligibleMemberIds } | Sort-Object -Unique)
foreach ($id in $userIds) {
    $user = Invoke-Graph -Uri ("/users/$id" + '?$select=id,displayName,accountEnabled')
    if ($user.accountEnabled -ne $true) { throw "User $id is disabled or its enabled state could not be verified." }
}
foreach ($id in $unitIds) {
    $null = Invoke-Graph -Uri ("/directory/administrativeUnits/$id" + '?$select=id,displayName')
}
$roleIds = @($configuration.Groups.Roles.RoleDefinitionId | Sort-Object -Unique)
foreach ($id in $roleIds) {
    $definition = Invoke-Graph -Uri ("/roleManagement/directory/roleDefinitions/$id" + '?$select=id,displayName,isEnabled')
    if ($definition.isEnabled -ne $true) { throw "Role definition $id is not enabled." }
    Write-Verbose ("Role {0}: {1}" -f $id, $definition.displayName)
}
$plans = @($configuration.Groups | ForEach-Object { Get-GroupPlan $_ })
foreach ($plan in $plans) {
    foreach ($role in $plan.RolesToAdd) { Assert-RoleAssignmentPolicy $role }
}
if ($isInteractive) { Show-InteractiveSummary $configuration }

foreach ($plan in $plans) {
    $group = $plan.Configuration
    $groupId = $null
    if ($null -ne $plan.Existing) { $groupId = $plan.Existing.id }
    $status = 'Unchanged'
    if ($plan.HasChanges) {
        $action = "Ensure active roles, approved PIM Member policy and eligible membership in tenant $($configuration.TenantId)"
        if (-not $PSCmdlet.ShouldProcess("$($group.DisplayName) [$groupId]", $action)) {
            $status = 'Skipped'
            if ($WhatIfPreference) { $status = 'Planned' }
            [pscustomobject]@{
                GroupName = $group.DisplayName; GroupId = $groupId; Status = $status
                RolesToAdd = $plan.RolesToAdd.Count; EligibleMembersToAdd = $plan.MembersToAdd.Count
            }
            continue
        }
        if ($null -ne $group.EligibilityEnd -and $group.EligibilityEnd -le [datetimeoffset]::UtcNow) {
            throw "$($group.DisplayName): the eligibility deadline expired after planning. No changes were made to this group."
        }
        $script:GraphWritesAllowed = $true
        try {
            if ($null -eq $plan.Existing) {
                $created = Invoke-Graph -Method POST -Uri '/groups' -Body @{
                    displayName = $group.DisplayName; mailNickname = $group.MailNickname; description = $group.Description
                    securityEnabled = $true; mailEnabled = $false; groupTypes = @(); isAssignableToRole = $true
                    'owners@odata.bind' = @($group.OwnerIds | ForEach-Object { "$script:GraphRoot/users/$_" })
                }
                $groupId = ConvertTo-ObjectId $created.id 'created group ID'
                Write-Host "Created $($group.DisplayName): $groupId"
                Wait-GraphState "group $groupId replication" { $null -ne (Get-ExistingGroup $group) }
            }
            # Recheck after confirmation, before granting access to an existing group.
            $currentPlan = Get-GroupPlan $group
            if ($currentPlan.Existing.id -ne $groupId) { throw 'The target group changed after planning; refusing to continue.' }
            foreach ($id in $currentPlan.OwnersToAdd) {
                $null = Invoke-Graph -Method POST -Uri ("/groups/$groupId/owners/" + '$ref') -Body @{
                    '@odata.id' = "$script:GraphRoot/users/$id"
                }
            }
            foreach ($role in $currentPlan.RolesToAdd) {
                Assert-RoleAssignmentPolicy $role
                $request = Invoke-Graph -Method POST -Uri '/roleManagement/directory/roleAssignmentScheduleRequests' -Body @{
                    action = 'adminAssign'; principalId = $groupId; roleDefinitionId = $role.RoleDefinitionId
                    directoryScopeId = $role.DirectoryScopeId; justification = $configuration.Justification
                    scheduleInfo = New-ScheduleInfo $role.EndDateTime
                }
                Write-Host "Requested active role $($role.RoleDefinitionId): $($request.id)"
                Wait-GraphState "active role $($role.RoleDefinitionId) on group $groupId" {
                    @(Get-LiveInstances '/roleManagement/directory/roleAssignmentScheduleInstances' "principalId eq '$groupId'" |
                        Where-Object { $_.roleDefinitionId -eq $role.RoleDefinitionId -and $_.directoryScopeId -eq $role.DirectoryScopeId }).Count -gt 0
                }
            }
            $policy = Get-MemberPolicy $groupId
            $changes = @(Get-PolicyChanges $policy $group)
            if ($changes.Count -gt 0) {
                $null = Invoke-Graph -Method PATCH -Uri "/policies/roleManagementPolicies/$([uri]::EscapeDataString($policy.id))" -Body @{ rules = $changes }
                # Onboarding changes policy IDs. Resolve the Member assignment again before verification.
                Wait-GraphState "Member policy on group $groupId" {
                    $saved = Get-MemberPolicy $groupId
                    @(Get-PolicyChanges $saved $group).Count -eq 0
                }
            }
            $ready = Get-GroupPlan $group
            if ($ready.RolesToAdd.Count -gt 0 -or $ready.PolicyChanges.Count -gt 0 -or $ready.OwnersToAdd.Count -gt 0) {
                throw "Group $groupId is not ready. No new eligibility will be assigned."
            }
            foreach ($id in $ready.MembersToAdd) {
                $request = Invoke-Graph -Method POST -Uri '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests' -Body @{
                    action = 'adminAssign'; accessId = 'member'; principalId = $id; groupId = $groupId
                    justification = $configuration.Justification; scheduleInfo = New-ScheduleInfo $group.EligibilityEnd
                }
                Write-Host "Requested eligible membership for ${id}: $($request.id)"
                Wait-GraphState "eligible membership for $id on group $groupId" {
                    @(Get-LiveInstances '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances' "groupId eq '$groupId'" |
                        Where-Object { $_.principalId -eq $id -and $_.accessId -eq 'member' }).Count -gt 0
                }
            }
            $finalPlan = Get-GroupPlan $group
            if ($finalPlan.HasChanges) { throw "Final verification failed for group $groupId; inspect the partial deployment before rerunning." }
            $status = 'Configured'
        }
        finally {
            $script:GraphWritesAllowed = $false
        }
    }
    [pscustomobject]@{
        GroupName = $group.DisplayName; GroupId = $groupId; Status = $status
        RolesToAdd = 0; EligibleMembersToAdd = 0
    }
}

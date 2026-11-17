#requires -Version 5.1
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:DeploymentPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'Initialize-PimGroups.ps1'
    $script:TenantId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    $script:OperatorId = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    $script:GroupId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
    $script:OwnerId = '11111111-1111-1111-1111-111111111111'
    $script:ApproverId = '22222222-2222-2222-2222-222222222222'
    $script:MemberId = '33333333-3333-3333-3333-333333333333'
    $script:RequiredScopes = @('Group.ReadWrite.All', 'User.Read.All', 'RoleManagement.ReadWrite.Directory',
        'RoleManagementPolicy.ReadWrite.AzureADGroup', 'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
        'PrivilegedAssignmentSchedule.Read.AzureADGroup')

    $identifiers = @{
        TenantId = $script:TenantId; OperatorId = $script:OperatorId; GroupId = $script:GroupId
        OwnerId = $script:OwnerId; ApproverId = $script:ApproverId; MemberId = $script:MemberId
    }
    # Keep mock state in its own script scope when the deployment script calls it.
    $script:OfflineGraphModule = New-Module -Name PimGroupsOfflineGraph -ArgumentList $identifiers -ScriptBlock {
    param($Identifiers)
    foreach ($key in $Identifiers.Keys) { Set-Variable -Name $key -Value $Identifiers[$key] -Scope Script }

    function Set-OfflineGraphState {
        param($State, $Context)
        $script:State = $State
        $script:GraphContext = $Context
    }

    function Get-OfflineGraphContext { $script:GraphContext }

    function Read-TestAnswer {
        param([string]$Prompt)
        [void]$script:State.Prompts.Add($Prompt)
        if ($script:State.Answers.Count -eq 0) { throw "Unexpected interactive prompt: $Prompt" }
        $answer = $script:State.Answers.Dequeue()
        if ($answer -eq '__CANCEL__') { throw [System.OperationCanceledException]::new('Offline cancellation.') }
        return $answer
    }

    function Invoke-MgGraphRequest {
        [CmdletBinding()]
        param($Method, $Uri, $Body, $ContentType, $OutputType)
        throw 'The offline Graph mock was not installed.'
    }
    function Get-MgContext { throw 'The offline context mock was not installed.' }
    function Connect-MgGraph {
        [CmdletBinding()]
        param($TenantId, $Scopes, $Environment, $ContextScope, [switch]$NoWelcome)
        throw 'The offline connection mock was not installed.'
    }

    function Copy-JsonObject {
        param($Object)
        ConvertTo-Json -InputObject $Object -Depth 30 | ConvertFrom-Json
    }

    function New-Collection {
        param([object[]]$Items = @())
        [pscustomobject]@{ value = @($Items) }
    }

    function New-TestConfiguration {
        [pscustomobject]@{
            tenantId = $script:TenantId
            justification = 'Offline test deployment.'
            groups = @([pscustomobject]@{
                displayName = 'PIM-Identity-Admins'; mailNickname = 'PIM-Identity-Admins'; description = 'Offline test.'
                ownerIds = @($script:OwnerId); approverIds = @($script:OwnerId, $script:ApproverId)
                eligibleMemberIds = @($script:MemberId)
                eligibilityEndDateTime = [datetimeoffset]::UtcNow.AddDays(6).ToString('o')
                maximumActivationDuration = 'PT1H'; maximumEligibilityDuration = 'P7D'
                roles = @(
                    [pscustomobject]@{ roleDefinitionId = 'fe930be7-5e62-47db-91af-98c3a49a38b1'; directoryScopeId = '/'; endDateTime = $null },
                    [pscustomobject]@{ roleDefinitionId = 'fdd7a751-b60b-444a-984c-02652fe8fa1c'; directoryScopeId = '/'; endDateTime = $null }
                )
            })
        }
    }

    function New-TestPolicy {
        $endUser = @{ caller = 'EndUser'; operations = @('All'); level = 'Assignment'; inheritableSettings = @(); enforcedSettings = @() }
        $adminAssignment = @{ caller = 'Admin'; operations = @('All'); level = 'Assignment'; inheritableSettings = @(); enforcedSettings = @() }
        $adminEligibility = @{ caller = 'Admin'; operations = @('All'); level = 'Eligibility'; inheritableSettings = @(); enforcedSettings = @() }
        Copy-JsonObject @{
            id = 'Default_Member'
            rules = @(
                @{ id = 'Expiration_EndUser_Assignment'; target = $endUser; isExpirationRequired = $true; maximumDuration = 'PT8H' },
                @{ id = 'Expiration_Admin_Eligibility'; target = $adminEligibility; isExpirationRequired = $false; maximumDuration = 'P365D' },
                @{ id = 'Expiration_Admin_Assignment'; target = $adminAssignment; isExpirationRequired = $false; maximumDuration = 'P180D' },
                @{ id = 'Enablement_EndUser_Assignment'; target = $endUser; enabledRules = @() },
                @{
                    id = 'Approval_EndUser_Assignment'; target = $endUser
                    setting = @{
                        isApprovalRequired = $false; isApprovalRequiredForExtension = $true
                        isRequestorJustificationRequired = $false; approvalMode = 'SingleStage'
                        approvalStages = @(@{
                            approvalStageTimeOutInDays = 1; isApproverJustificationRequired = $false
                            isEscalationEnabled = $false; escalationTimeInMinutes = 0
                            primaryApprovers = @(); escalationApprovers = @()
                        })
                    }
                },
                @{ id = 'AuthenticationContext_EndUser_Assignment'; target = $endUser; isEnabled = $true; claimValue = 'c1' },
                @{ id = 'Notification_Admin_Admin_Eligibility'; target = $adminEligibility; notificationRecipients = @('unchanged@example.invalid') }
            )
        }
    }

    function New-ExistingGroup {
        [pscustomobject]@{
            id = $script:GroupId; displayName = 'PIM-Identity-Admins'; mailNickname = 'PIM-Identity-Admins'
            isAssignableToRole = $true; securityEnabled = $true; mailEnabled = $false
            groupTypes = @(); onPremisesSyncEnabled = $null
        }
    }

    function Get-TestRule {
        param([string]$Id)
        $script:State.Policy.rules | Where-Object { $_.id -eq $Id }
    }

    function Invoke-TestGraph {
        param([string]$Method, [string]$Uri, [string]$Body)
        $address = [uri]$Uri
        $path = $address.AbsolutePath.Substring('/v1.0'.Length)
        $query = [uri]::UnescapeDataString($address.Query)
        $data = $null
        if ($Body) { $data = $Body | ConvertFrom-Json }
        [void]$script:State.Calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Path = $path; Body = $data })
        if ($Method -eq 'GET') {
            if ($path -eq '/me') { return [pscustomobject]@{ id = $script:OperatorId } }
            if ($path -eq '/me/transitiveMemberOf/microsoft.graph.group') {
                return New-Collection $script:State.OperatorGroups
            }
            if ($path -eq '/roleManagement/directory/roleAssignments') {
                if ($query -match 'e8611ab8-c189-46e8-94e1-60213ab1f814') {
                    return New-Collection @([pscustomobject]@{ principalId = $script:State.AdminPrincipalId; directoryScopeId = '/' })
                }
                return New-Collection
            }
            if ($path -eq '/users') {
                $identifier = [regex]::Match($query, " eq '((?:[^']|'')*)'").Groups[1].Value.Replace("''", "'")
                $users = @($script:State.Users | Where-Object { $_.id -eq $identifier -or $_.userPrincipalName -eq $identifier })
                $users = @($users | ForEach-Object {
                    $copy = Copy-JsonObject $_
                    $copy.accountEnabled = $script:State.UserEnabled
                    $copy
                })
                return New-Collection $users
            }
            if ($path -like '/users/*') {
                return [pscustomobject]@{ id = $path.Split('/')[-1]; displayName = 'Synthetic user'; accountEnabled = $script:State.UserEnabled }
            }
            if ($path -like '/directory/administrativeUnits/*') {
                return [pscustomobject]@{ id = $path.Split('/')[-1]; displayName = 'Synthetic unit' }
            }
            if ($path -like '/roleManagement/directory/roleDefinitions/*') {
                return [pscustomobject]@{ id = $path.Split('/')[-1]; displayName = 'Synthetic role'; isEnabled = $true }
            }
            if ($path -eq '/groups') {
                $items = @()
                if ($null -ne $script:State.Group) { $items = @($script:State.Group) }
                $response = New-Collection $items
                if ($script:State.DuplicatePage) {
                    if ($query -match 'skiptoken=duplicate') {
                        $copy = Copy-JsonObject $script:State.Group
                        $copy.id = 'dddddddd-dddd-dddd-dddd-dddddddddddd'
                        return New-Collection @($copy)
                    }
                    $response | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue 'https://graph.microsoft.com/v1.0/groups?$skiptoken=duplicate'
                }
                if ($script:State.HostileNextLink) {
                    $response | Add-Member -NotePropertyName '@odata.nextLink' -NotePropertyValue 'https://example.invalid/v1.0/groups'
                }
                return Copy-JsonObject $response
            }
            if ($path -eq "/groups/$script:GroupId/owners") {
                return New-Collection @($script:State.OwnerIds | ForEach-Object { [pscustomobject]@{ id = $_ } })
            }
            if ($path -eq "/groups/$script:GroupId/members") {
                return New-Collection @($script:State.MemberIds | ForEach-Object { [pscustomobject]@{ id = $_ } })
            }
            if ($path -eq '/roleManagement/directory/roleAssignmentScheduleInstances') {
                return Copy-JsonObject (New-Collection $script:State.RoleInstances)
            }
            if ($path -eq '/roleManagement/directory/roleAssignmentScheduleRequests') {
                return Copy-JsonObject (New-Collection $script:State.RoleRequests)
            }
            if ($path -eq '/identityGovernance/privilegedAccess/group/assignmentScheduleInstances') {
                return Copy-JsonObject (New-Collection $script:State.ActiveInstances)
            }
            if ($path -eq '/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances') {
                return Copy-JsonObject (New-Collection $script:State.EligibleInstances)
            }
            if ($path -eq '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests') {
                return Copy-JsonObject (New-Collection $script:State.EligibilityRequests)
            }
            if ($path -eq '/policies/roleManagementPolicyAssignments') {
                if ($query -match "scopeType eq 'DirectoryRole'") {
                    $roleId = [regex]::Match($query, "roleDefinitionId eq '([^']+)'").Groups[1].Value
                    return New-Collection @([pscustomobject]@{ policyId = "Directory_$roleId"; roleDefinitionId = $roleId })
                }
                return New-Collection @(
                    [pscustomobject]@{ policyId = $script:State.Policy.id; roleDefinitionId = 'member' },
                    [pscustomobject]@{ policyId = 'Owner_DoNotChange'; roleDefinitionId = 'owner' }
                )
            }
            if ($path -like '/policies/roleManagementPolicies/Directory_*') {
                return [pscustomobject]@{ rules = @(
                    [pscustomobject]@{ id = 'Expiration_Admin_Assignment'; isExpirationRequired = $script:State.RoleExpiryRequired; maximumDuration = 'P180D' },
                    [pscustomobject]@{ id = 'Enablement_Admin_Assignment'; enabledRules = @('Justification') }
                ) }
            }
            if ($path -eq "/policies/roleManagementPolicies/$($script:State.Policy.id)") {
                return Copy-JsonObject $script:State.Policy
            }
        }
        if ($Method -eq 'POST' -and $path -eq '/groups') {
            if ($null -ne $script:State.Group) { throw 'The test attempted to create a duplicate group.' }
            $script:State.Group = New-ExistingGroup
            $script:State.Group.displayName = $data.displayName
            $script:State.Group.mailNickname = $data.mailNickname
            $script:State.Group.isAssignableToRole = $data.isAssignableToRole
            $script:State.Group.securityEnabled = $data.securityEnabled
            $script:State.Group.mailEnabled = $data.mailEnabled
            $script:State.Group.groupTypes = @($data.groupTypes)
            $script:State.OwnerIds = @($data.'owners@odata.bind' | ForEach-Object { ([uri]$_).Segments[-1] })
            return Copy-JsonObject $script:State.Group
        }
        if ($Method -eq 'POST' -and $path -eq ("/groups/$script:GroupId/owners/" + '$ref')) {
            $script:State.OwnerIds += ([uri]$data.'@odata.id').Segments[-1]
            return
        }
        if ($Method -eq 'POST' -and $path -eq '/roleManagement/directory/roleAssignmentScheduleRequests') {
            $script:State.RoleInstances += [pscustomobject]@{
                id = [guid]::NewGuid().ToString(); principalId = $data.principalId; roleDefinitionId = $data.roleDefinitionId
                directoryScopeId = $data.directoryScopeId; assignmentType = 'Assigned'; startDateTime = $data.scheduleInfo.startDateTime
                endDateTime = $(if ($data.scheduleInfo.expiration.type -eq 'afterDateTime') { $data.scheduleInfo.expiration.endDateTime } else { $null })
            }
            return [pscustomobject]@{ id = 'role-request'; status = 'Provisioned' }
        }
        if ($Method -eq 'PATCH' -and $path -eq "/policies/roleManagementPolicies/$($script:State.Policy.id)") {
            if (-not $script:State.IgnorePolicyWrites) {
                foreach ($update in $data.rules) {
                    $rule = Get-TestRule $update.id
                    foreach ($property in $update.PSObject.Properties) {
                        $rule | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value -Force
                    }
                }
                $script:State.Policy.id = "Group_${script:GroupId}_Member"
            }
            return Copy-JsonObject $script:State.Policy
        }
        if ($Method -eq 'POST' -and $path -eq '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests') {
            $script:State.EligibleInstances += [pscustomobject]@{
                id = [guid]::NewGuid().ToString(); groupId = $data.groupId; principalId = $data.principalId; accessId = $data.accessId
                startDateTime = $data.scheduleInfo.startDateTime
                endDateTime = $(if ($data.scheduleInfo.expiration.type -eq 'afterDateTime') { $data.scheduleInfo.expiration.endDateTime } else { $null })
            }
            return [pscustomobject]@{ id = 'eligibility-request'; status = 'Provisioned' }
        }
        throw "Unexpected offline Graph call: $Method $Uri"
    }
    }
    Import-Module $script:OfflineGraphModule -Force

    function Save-TestConfiguration {
        $script:Configuration | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $script:ConfigurationFile -Encoding UTF8
    }

    function Invoke-Deployment {
        param([switch]$Plan)
        & $script:DeploymentPath -ConfigurationPath $script:ConfigurationFile -UseExistingConnection `
            -Confirm:$false -WhatIf:$Plan -PropagationTimeoutSeconds 1
    }

    function Set-WizardAnswers {
        param([ValidateSet('P', 'T')][string]$Mode = 'P', [switch]$Existing)
        $answers = @($script:TenantId, '', '', 'owner@example.invalid',
            'owner@example.invalid;approver@example.invalid', 'member@example.invalid', '', $Mode)
        if ($Mode -eq 'T') { $answers += @('', $script:Configuration.groups[0].eligibilityEndDateTime) }
        if (-not $Existing) { $answers += @('', '') }
        $answers += ''
        foreach ($answer in $answers) { $script:State.Answers.Enqueue($answer) }
    }

    function Invoke-Wizard {
        param([switch]$Plan, [switch]$Implicit)
        $parameters = @{
            UseExistingConnection = $true; Confirm = $false
            WhatIf = $Plan.IsPresent; PropagationTimeoutSeconds = 1
        }
        if (-not $Implicit) { $parameters.Interactive = $true }
        & $script:DeploymentPath @parameters
    }
}

Describe 'Initialize-PimGroups' {
    BeforeEach {
        $script:Configuration = New-TestConfiguration
        $script:ConfigurationFile = Join-Path $TestDrive 'pim-groups.json'
        Save-TestConfiguration
        $script:GraphContext = [pscustomobject]@{
            TenantId = $script:TenantId; AuthType = 'Delegated'; Environment = 'Global'; Scopes = $script:RequiredScopes
        }
        $script:State = @{
            Calls = [System.Collections.Generic.List[object]]::new()
            Prompts = [System.Collections.Generic.List[string]]::new()
            Answers = [System.Collections.Generic.Queue[string]]::new()
            Users = @(
                [pscustomobject]@{ id = $script:OperatorId; userPrincipalName = 'operator@example.invalid'; accountEnabled = $true },
                [pscustomobject]@{ id = $script:OwnerId; userPrincipalName = 'owner@example.invalid'; accountEnabled = $true },
                [pscustomobject]@{ id = $script:ApproverId; userPrincipalName = 'approver@example.invalid'; accountEnabled = $true },
                [pscustomobject]@{ id = $script:MemberId; userPrincipalName = 'member@example.invalid'; accountEnabled = $true }
            )
            Group = $null; OwnerIds = @(); MemberIds = @(); OperatorGroups = @(); AdminPrincipalId = $script:OperatorId
            Policy = New-TestPolicy; RoleInstances = @(); ActiveInstances = @(); EligibleInstances = @()
            RoleRequests = @(); EligibilityRequests = @(); RoleExpiryRequired = $false
            UserEnabled = $true; DuplicatePage = $false; HostileNextLink = $false; IgnorePolicyWrites = $false
        }
        Set-OfflineGraphState -State $script:State -Context $script:GraphContext
        Mock Get-Module { [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication' } } -ParameterFilter {
            $Name -contains 'Microsoft.Graph.Authentication'
        }
        Mock Import-Module {} -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        Mock Get-MgContext { Get-OfflineGraphContext }
        Mock Connect-MgGraph {}
        Mock Invoke-MgGraphRequest { param($Method, $Uri, $Body) Invoke-TestGraph $Method $Uri $Body }
        Mock Read-Host { param($Prompt) Read-TestAnswer $Prompt }
        Mock Start-Sleep { [System.Threading.Thread]::Sleep(5) }
    }

    AfterAll {
        Remove-Module -ModuleInfo $script:OfflineGraphModule -Force
    }

    It 'runs the article wizard without a JSON file and resolves UPNs to object IDs' {
        Remove-Item -LiteralPath $script:ConfigurationFile
        Set-WizardAnswers
        $result = Invoke-Wizard -Implicit
        $result.Status | Should -Be 'Configured'
        $script:State.Answers.Count | Should -Be 0
        $script:State.Group.displayName | Should -Be 'PIM-Identity-Admins'
        $script:State.RoleInstances.roleDefinitionId | Should -Contain 'fe930be7-5e62-47db-91af-98c3a49a38b1'
        $script:State.RoleInstances.roleDefinitionId | Should -Contain 'fdd7a751-b60b-444a-984c-02652fe8fa1c'
        $script:State.OwnerIds | Should -Contain $script:OwnerId
        $script:State.EligibleInstances[0].principalId | Should -Be $script:MemberId
        $script:State.EligibleInstances[0].endDateTime | Should -BeNullOrEmpty
        $script:State.MemberIds.Count | Should -Be 0
        Test-Path -LiteralPath $script:ConfigurationFile | Should -BeFalse
    }

    It 'previews interactive permanent eligibility without any Graph writes' {
        Set-WizardAnswers
        (Invoke-Wizard -Plan).Status | Should -Be 'Planned'
        $script:State.Answers.Count | Should -Be 0
        $script:State.Group | Should -BeNullOrEmpty
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'keeps interactive time-bound eligibility and activation on separate clocks' {
        Set-WizardAnswers -Mode T
        (Invoke-Wizard).Status | Should -Be 'Configured'
        $script:State.Answers.Count | Should -Be 0
        [datetimeoffset]$script:State.EligibleInstances[0].endDateTime |
            Should -Be ([datetimeoffset]$script:Configuration.groups[0].eligibilityEndDateTime)
        (Get-TestRule 'Expiration_EndUser_Assignment').maximumDuration | Should -Be 'PT1H'
        (Get-TestRule 'Expiration_Admin_Eligibility').isExpirationRequired | Should -BeTrue
        (Get-TestRule 'Expiration_Admin_Assignment').isExpirationRequired | Should -BeTrue
    }

    It 'keeps existing finite deadlines as wizard defaults instead of extending them' {
        $null = Invoke-Deployment
        $end = $script:State.EligibleInstances[0].endDateTime
        $script:State.Calls.Clear()
        foreach ($answer in @('', '', '', '', '', '', '', '', '', '', '')) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Unchanged'
        $script:State.Answers.Count | Should -Be 0
        $script:State.EligibleInstances[0].endDateTime | Should -Be $end
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reuses a differently named existing nickname and binds the wizard to the discovered object ID' {
        $null = Invoke-Deployment
        $script:State.Group.mailNickname = 'portal-generated-alias'
        $script:State.Calls.Clear()
        foreach ($answer in @('', '', '', '', '', '', '', '', '', '', '')) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Unchanged'
        $script:State.Group.mailNickname | Should -Be 'portal-generated-alias'
        $script:State.Prompts | Should -Contain 'Group mail nickname [portal-generated-alias]'
        @($script:State.Calls | Where-Object {
                $_.Path -eq '/groups' -and [uri]::UnescapeDataString($_.Uri).Contains("id eq '$script:GroupId'")
            }).Count | Should -BeGreaterThan 0
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'does not apply creation-only nickname rules when reusing an existing group' {
        $null = Invoke-Deployment
        $script:State.Group.mailNickname = 'existing+alias'
        $script:State.Calls.Clear()
        foreach ($answer in @('', '', '', '', '', '', '', '', '', '', '')) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Unchanged'
        $script:State.Group.mailNickname | Should -Be 'existing+alias'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reports the exact immutable role-assignable property blocking wizard reuse' {
        $script:State.Group = New-ExistingGroup
        $script:State.Group.isAssignableToRole = $false
        foreach ($answer in @($script:TenantId, '', '')) { $script:State.Answers.Enqueue($answer) }
        { Invoke-Wizard -Plan } | Should -Throw '*isAssignableToRole: actual false; expected true*immutable*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'lists Microsoft 365 type conflicts instead of giving a generic compatibility error' {
        $script:State.Group = New-ExistingGroup
        $script:State.Group.securityEnabled = $false
        $script:State.Group.mailEnabled = $true
        $script:State.Group.groupTypes = @('Unified')
        { Invoke-Deployment } | Should -Throw '*securityEnabled: actual false; expected true*mailEnabled: actual true; expected false*groupTypes:*Unified*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reports a JSON nickname mismatch with its actual and expected values' {
        $script:State.Group = New-ExistingGroup
        $script:State.Group.mailNickname = 'portal-generated-alias'
        { Invoke-Deployment } | Should -Throw '*mailNickname: actual "portal-generated-alias"; expected "PIM-Identity-Admins"*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reports a missing compatibility property rather than treating it as a valid default' {
        $script:State.Group = New-ExistingGroup
        $script:State.Group.PSObject.Properties.Remove('securityEnabled')
        { Invoke-Deployment } | Should -Throw '*securityEnabled was not returned by Graph*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'keeps existing permanent eligibility as a wizard default on rerun' {
        Set-WizardAnswers
        $null = Invoke-Wizard
        $script:State.Calls.Clear()
        foreach ($answer in @('', '', '', '', '', '', '', '', '')) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Unchanged'
        $script:State.Answers.Count | Should -Be 0
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'preserves a policy eligibility limit longer than the existing user eligibility window' {
        $script:Configuration.groups[0].maximumEligibilityDuration = 'P30D'
        Save-TestConfiguration
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        foreach ($answer in @('', '', '', '', '', '', '', '', '', '', '')) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Unchanged'
        (Get-TestRule 'Expiration_Admin_Eligibility').maximumDuration | Should -Be 'P30D'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reprompts for malformed tenants, unknown users, beneficiary overlap and invalid activation hours' {
        $answers = @('not-a-guid', $script:TenantId, '', '', 'missing@example.invalid', 'owner@example.invalid',
            'owner@example.invalid;approver@example.invalid', 'owner@example.invalid', 'member@example.invalid',
            '25', '1', 'invalid', 'P', '', '', '')
        foreach ($answer in $answers) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard -Plan).Status | Should -Be 'Planned'
        $script:State.Answers.Count | Should -Be 0
        @($script:State.Prompts | Where-Object { $_ -like 'Tenant ID*' }).Count | Should -Be 2
        @($script:State.Prompts | Where-Object { $_ -like 'Group owners*' }).Count | Should -Be 2
        @($script:State.Prompts | Where-Object { $_ -like 'Eligible members*' }).Count | Should -Be 2
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'accepts object IDs as well as UPNs in the wizard' {
        $answers = @($script:TenantId, '', '', $script:OwnerId, "$script:OwnerId,$script:ApproverId",
            $script:MemberId, '', 'P', '', '', '')
        foreach ($answer in $answers) { $script:State.Answers.Enqueue($answer) }
        (Invoke-Wizard).Status | Should -Be 'Configured'
        $script:State.EligibleInstances[0].principalId | Should -Be $script:MemberId
    }

    It 'stops before asking questions if the authentication module is missing' {
        Mock Get-Module {} -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        { Invoke-Wizard -Plan } | Should -Throw '*Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser*'
        Should -Invoke Read-Host -Times 0
        Should -Invoke Connect-MgGraph -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'cancels the wizard without granting access' {
        $script:State.Answers.Enqueue('__CANCEL__')
        { Invoke-Wizard } | Should -Throw '*Offline cancellation*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'supports permanent eligibility from JSON without permanent active membership' {
        $script:Configuration.groups[0].eligibilityEndDateTime = $null
        Save-TestConfiguration
        (Get-TestRule 'Expiration_Admin_Eligibility').isExpirationRequired = $true
        (Invoke-Deployment).Status | Should -Be 'Configured'
        $request = $script:State.Calls | Where-Object {
            $_.Method -eq 'POST' -and $_.Path -eq '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
        }
        $request.Body.scheduleInfo.expiration.type | Should -Be 'noExpiration'
        $request.Body.scheduleInfo.expiration.PSObject.Properties.Name | Should -Not -Contain 'endDateTime'
        (Get-TestRule 'Expiration_Admin_Eligibility').isExpirationRequired | Should -BeFalse
        (Get-TestRule 'Expiration_EndUser_Assignment').maximumDuration | Should -Be 'PT1H'
        (Get-TestRule 'Expiration_Admin_Assignment').isExpirationRequired | Should -BeTrue
        (Get-TestRule 'Approval_EndUser_Assignment').setting.isApprovalRequired | Should -BeTrue
        $script:State.MemberIds.Count | Should -Be 0
        $script:State.Calls.Clear()
        (Invoke-Deployment).Status | Should -Be 'Unchanged'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        Should -Invoke Read-Host -Times 0
    }

    It 'does not interpret an omitted eligibility deadline as permanent eligibility' {
        $script:Configuration.groups[0].PSObject.Properties.Remove('eligibilityEndDateTime')
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*eligibilityEndDateTime is required*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'does not convert existing finite eligibility to permanent eligibility automatically' {
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        $script:Configuration.groups[0].eligibilityEndDateTime = $null
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*different expiration*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'asks for policy-compatible active role end dates even with permanent eligibility' {
        $script:State.RoleExpiryRequired = $true
        Set-WizardAnswers
        (Invoke-Wizard).Status | Should -Be 'Configured'
        foreach ($instance in $script:State.RoleInstances) {
            [datetimeoffset]$instance.endDateTime | Should -BeGreaterThan ([datetimeoffset]::UtcNow)
        }
        $script:State.EligibleInstances[0].endDateTime | Should -BeNullOrEmpty
        (Get-TestRule 'Expiration_Admin_Assignment').isExpirationRequired | Should -BeTrue
    }

    It 'enforces the documented one-to-24-hour activation limits before authentication' {
        foreach ($value in @('PT30M', 'PT25H')) {
            $script:Configuration.groups[0].maximumActivationDuration = $value
            Save-TestConfiguration
            { Invoke-Deployment } | Should -Throw '*between 1 and 24 hours*'
        }
        Should -Invoke Invoke-MgGraphRequest -Times 0
        $script:Configuration.groups[0].maximumActivationDuration = 'PT24H'
        Save-TestConfiguration
        (Invoke-Deployment).Status | Should -Be 'Configured'
        (Get-TestRule 'Expiration_EndUser_Assignment').maximumDuration | Should -Be 'P1D'
    }

    It 'reports the installation command and stops before authentication when the module is missing' {
        Mock Get-Module {} -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        {
            & $script:DeploymentPath -ConfigurationPath $script:ConfigurationFile -Confirm:$false
        } | Should -Throw '*Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser*'
        { Invoke-Deployment -Plan } | Should -Throw '*No connection or tenant changes were attempted*'
        Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        Should -Invoke Connect-MgGraph -Times 0
        Should -Invoke Get-MgContext -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'imports an installed but unloaded authentication module before connecting' {
        Mock Get-Module {} -ParameterFilter {
            $Name -contains 'Microsoft.Graph.Authentication' -and -not $ListAvailable
        }
        $result = & $script:DeploymentPath -ConfigurationPath $script:ConfigurationFile -WhatIf
        $result.Status | Should -Be 'Planned'
        Should -Invoke Get-Module -Times 1 -ParameterFilter {
            $Name -contains 'Microsoft.Graph.Authentication' -and $ListAvailable
        }
        Should -Invoke Import-Module -Times 1 -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        Should -Invoke Connect-MgGraph -Times 1
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'reuses a loaded authentication module without importing it again' {
        (Invoke-Deployment -Plan).Status | Should -Be 'Planned'
        Should -Invoke Get-Module -Times 0 -ParameterFilter {
            $Name -contains 'Microsoft.Graph.Authentication' -and $ListAvailable
        }
        Should -Invoke Import-Module -Times 0 -ParameterFilter { $Name -contains 'Microsoft.Graph.Authentication' }
        Should -Invoke Get-MgContext -Times 1
    }

    It 'deploys the exact active-role and eligible-member design, then verifies it' {
        $result = Invoke-Deployment
        $result.Status | Should -Be 'Configured'
        $result.GroupId | Should -Be $script:GroupId
        $script:State.RoleInstances.Count | Should -Be 2
        $script:State.EligibleInstances.Count | Should -Be 1
        $script:State.MemberIds.Count | Should -Be 0
        (Get-TestRule 'Expiration_EndUser_Assignment').maximumDuration | Should -Be 'PT1H'
        (Get-TestRule 'Expiration_Admin_Eligibility').maximumDuration | Should -Be 'P7D'
        (Get-TestRule 'Expiration_Admin_Assignment').isExpirationRequired | Should -BeTrue
        (Get-TestRule 'Enablement_EndUser_Assignment').enabledRules | Should -Contain 'MultiFactorAuthentication'
        (Get-TestRule 'Enablement_EndUser_Assignment').enabledRules | Should -Contain 'Justification'
        $approval = (Get-TestRule 'Approval_EndUser_Assignment').setting
        $approval.isApprovalRequired | Should -BeTrue
        $approval.isRequestorJustificationRequired | Should -BeTrue
        $approval.isApprovalRequiredForExtension | Should -BeTrue
        $approval.approvalStages[0].primaryApprovers.userId | Should -Contain $script:OwnerId
        $approval.approvalStages[0].primaryApprovers.userId | Should -Contain $script:ApproverId
        $writes = @($script:State.Calls | Where-Object { $_.Method -ne 'GET' })
        $writes.Count | Should -Be 5
        $writes[0].Body.isAssignableToRole | Should -BeTrue
        $writes[0].Body.PSObject.Properties.Name | Should -Not -Contain 'members@odata.bind'
        $writes[3].Method | Should -Be 'PATCH'
        $writes[4].Body.accessId | Should -Be 'member'
        $writes[4].Body.action | Should -Be 'adminAssign'
        [datetimeoffset]$writes[4].Body.scheduleInfo.expiration.endDateTime |
            Should -Be ([datetimeoffset]$script:Configuration.groups[0].eligibilityEndDateTime)
    }

    It 'resolves new policy IDs after onboarding and leaves Owner, CA and notification policies alone' {
        $null = Invoke-Deployment
        $script:State.Policy.id | Should -Be "Group_${script:GroupId}_Member"
        @($script:State.Calls | Where-Object { $_.Method -eq 'GET' -and $_.Path -eq "/policies/roleManagementPolicies/$($script:State.Policy.id)" }).Count |
            Should -BeGreaterThan 0
        (Get-TestRule 'AuthenticationContext_EndUser_Assignment').claimValue | Should -Be 'c1'
        (Get-TestRule 'Notification_Admin_Admin_Eligibility').notificationRecipients | Should -Contain 'unchanged@example.invalid'
        $patch = $script:State.Calls | Where-Object { $_.Method -eq 'PATCH' }
        @($patch.Body.rules).Count | Should -Be 5
        foreach ($rule in $patch.Body.rules) { $rule.'@odata.type' | Should -Match '^#microsoft\.graph\.' }
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' -and $_.Path -like '*Owner_DoNotChange*' }).Count | Should -Be 0
    }

    It 'makes a second execution a true no-op without extending eligibility' {
        $null = Invoke-Deployment
        $end = $script:State.EligibleInstances[0].endDateTime
        $script:State.Calls.Clear()
        $result = Invoke-Deployment
        $result.Status | Should -Be 'Unchanged'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        $script:State.EligibleInstances[0].endDateTime | Should -Be $end
    }

    It 'performs no Graph writes in WhatIf for a new group' {
        (Invoke-Deployment -Plan).Status | Should -Be 'Planned'
        $script:State.Group | Should -BeNullOrEmpty
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'performs no Graph writes in WhatIf for an existing group with drift' {
        $script:State.Group = New-ExistingGroup
        $script:State.OwnerIds = @($script:OwnerId)
        (Invoke-Deployment -Plan).Status | Should -Be 'Planned'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
        $script:State.Policy.id | Should -Be 'Default_Member'
    }

    It 'rejects the unedited example before authentication' {
        $example = Join-Path (Split-Path $PSScriptRoot -Parent) 'pim-groups.example.json'
        { & $script:DeploymentPath -ConfigurationPath $example -Confirm:$false } | Should -Throw '*tenantId*'
        Should -Invoke Connect-MgGraph -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'rejects unknown configuration keys before authentication' {
        $script:Configuration.groups[0] | Add-Member -NotePropertyName 'approversIds' -NotePropertyValue @($script:OwnerId)
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*Unknown property*approversIds*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'rejects an expired eligibility window and overlapping administrators' {
        $script:Configuration.groups[0].eligibilityEndDateTime = [datetimeoffset]::UtcNow.AddMinutes(-1).ToString('o')
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*eligibilityEndDateTime*'
        $script:Configuration = New-TestConfiguration
        $script:Configuration.groups[0].eligibleMemberIds = @($script:OwnerId)
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*must not be group owners or activation approvers*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'rejects activation and eligibility durations of zero and an eligibility window over its limit' {
        $script:Configuration.groups[0].maximumActivationDuration = 'PT0H'
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*greater than zero*'
        $script:Configuration = New-TestConfiguration
        $script:Configuration.groups[0].eligibilityEndDateTime = [datetimeoffset]::UtcNow.AddDays(8).ToString('o')
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*within maximumEligibilityDuration*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'accepts UTC Z timestamps and refuses timestamps without a time zone' {
        $script:Configuration.groups[0].eligibilityEndDateTime = [datetimeoffset]::UtcNow.AddDays(6).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
        Save-TestConfiguration
        (Invoke-Deployment -Plan).Status | Should -Be 'Planned'
        $script:State.Calls.Clear()
        $script:Configuration.groups[0].eligibilityEndDateTime = [datetimeoffset]::UtcNow.AddDays(6).ToString("yyyy-MM-dd'T'HH:mm:ss")
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*time zone*'
        $script:State.Calls.Count | Should -Be 0
    }

    It 'rejects duplicate configured role and scope pairs' {
        $script:Configuration.groups[0].roles += $script:Configuration.groups[0].roles[0]
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*duplicate role and scope*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'refuses a connection to another tenant or an app-only connection' {
        $script:GraphContext.TenantId = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        { Invoke-Deployment } | Should -Throw '*delegated Global-cloud*'
        $script:GraphContext.TenantId = $script:TenantId
        $script:GraphContext.AuthType = 'AppOnly'
        { Invoke-Deployment } | Should -Throw '*delegated Global-cloud*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }

    It 'checks delegated scopes and active administrative rights before any write' {
        $script:GraphContext.Scopes = @('User.Read.All')
        { Invoke-Deployment } | Should -Throw '*missing scope*'
        $script:GraphContext.Scopes = $script:RequiredScopes
        $script:State.AdminPrincipalId = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        { Invoke-Deployment } | Should -Throw '*Activate a directory-scoped*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'recognizes an active administrative role inherited through a group' {
        $adminGroup = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        $script:State.OperatorGroups = @([pscustomobject]@{ id = $adminGroup })
        $script:State.AdminPrincipalId = $adminGroup
        (Invoke-Deployment -Plan).Status | Should -Be 'Planned'
    }

    It 'requests a process-scoped connection to the explicit tenant by default' {
        $null = & $script:DeploymentPath -ConfigurationPath $script:ConfigurationFile -WhatIf
        Should -Invoke Connect-MgGraph -Times 1 -ParameterFilter {
            $TenantId -eq $script:TenantId -and $Environment -eq 'Global' -and $ContextScope -eq 'Process'
        }
    }

    It 'refuses a disabled referenced user before creating a group' {
        $script:State.UserEnabled = $false
        { Invoke-Deployment } | Should -Throw '*disabled*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'does not try to convert an ordinary existing group' {
        $script:State.Group = New-ExistingGroup
        $script:State.Group.isAssignableToRole = $false
        { Invoke-Deployment } | Should -Throw '*No conversion or rename*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'follows pagination and refuses ambiguous group names' {
        $script:State.Group = New-ExistingGroup
        $script:State.DuplicatePage = $true
        { Invoke-Deployment } | Should -Throw '*Ambiguous group name*'
        @($script:State.Calls | Where-Object { $_.Uri -like '*skiptoken=duplicate*' }).Count | Should -Be 1
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'never follows a pagination link outside Microsoft Graph' {
        $script:State.HostileNextLink = $true
        { Invoke-Deployment } | Should -Throw '*unexpected Graph URL*'
        @($script:State.Calls | Where-Object { $_.Uri -like '*example.invalid*' }).Count | Should -Be 0
    }

    It 'does not adopt owners or standing active members outside the intended design' {
        $script:State.Group = New-ExistingGroup
        $script:State.OwnerIds = @('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee')
        { Invoke-Deployment } | Should -Throw '*owners outside ownerIds*'
        $script:State.OwnerIds = @($script:OwnerId)
        $script:State.MemberIds = @($script:MemberId)
        { Invoke-Deployment } | Should -Throw '*standing active member*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'allows a rerun while a configured beneficiary has a legitimate PIM activation' {
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        $script:State.MemberIds = @($script:MemberId)
        $script:State.ActiveInstances = @([pscustomobject]@{
            principalId = $script:MemberId; accessId = 'member'; assignmentType = 'activated'
            startDateTime = [datetimeoffset]::UtcNow.AddMinutes(-10).ToString('o')
            endDateTime = [datetimeoffset]::UtcNow.AddMinutes(30).ToString('o')
        })
        (Invoke-Deployment).Status | Should -Be 'Unchanged'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'can add the configured owner to an otherwise compatible empty existing group' {
        $script:State.Group = New-ExistingGroup
        (Invoke-Deployment).Status | Should -Be 'Configured'
        $script:State.OwnerIds | Should -Contain $script:OwnerId
    }

    It 'refuses a future standing member assignment before granting any roles' {
        $script:State.Group = New-ExistingGroup
        $script:State.OwnerIds = @($script:OwnerId)
        $script:State.ActiveInstances = @([pscustomobject]@{
            principalId = $script:MemberId; accessId = 'member'; assignmentType = 'assigned'
            startDateTime = [datetimeoffset]::UtcNow.AddMinutes(10).ToString('o')
            endDateTime = [datetimeoffset]::UtcNow.AddMinutes(30).ToString('o')
        })
        { Invoke-Deployment } | Should -Throw '*standing active member schedule*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'refuses extra active roles rather than silently retaining an oversized bundle' {
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        $extra = Copy-JsonObject $script:State.RoleInstances[0]
        $extra.roleDefinitionId = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        $script:State.RoleInstances += $extra
        { Invoke-Deployment } | Should -Throw '*role or scope outside*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'refuses existing permanent eligibility when a finite deadline is configured' {
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        $script:State.EligibleInstances[0].endDateTime = $null
        { Invoke-Deployment } | Should -Throw '*different expiration*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'does not bypass a role policy requiring an assignment end date' {
        $script:State.RoleExpiryRequired = $true
        { Invoke-Deployment } | Should -Throw '*requires an end date*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'supports explicitly time-bound active roles covering the eligibility window' {
        $script:State.RoleExpiryRequired = $true
        foreach ($role in $script:Configuration.groups[0].roles) {
            $role.endDateTime = $script:Configuration.groups[0].eligibilityEndDateTime
        }
        Save-TestConfiguration
        (Invoke-Deployment).Status | Should -Be 'Configured'
        foreach ($instance in $script:State.RoleInstances) {
            [datetimeoffset]$instance.endDateTime | Should -Be ([datetimeoffset]$script:Configuration.groups[0].eligibilityEndDateTime)
        }
        $script:State.Calls.Clear()
        (Invoke-Deployment).Status | Should -Be 'Unchanged'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'refuses an unfinished role request instead of submitting another' {
        $script:State.Group = New-ExistingGroup
        $script:State.OwnerIds = @($script:OwnerId)
        $script:State.RoleRequests = @([pscustomobject]@{
            id = 'pending-role'; status = 'PendingApproval'
            roleDefinitionId = $script:Configuration.groups[0].roles[0].roleDefinitionId; directoryScopeId = '/'
        })
        { Invoke-Deployment } | Should -Throw '*unfinished schedule request pending-role*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'does not mistake another beneficiary completed request for a pending new assignment' {
        $null = Invoke-Deployment
        $script:State.Calls.Clear()
        $script:State.EligibilityRequests = @([pscustomobject]@{
            id = 'old-granted'; status = 'Granted'; accessId = 'member'; principalId = $script:MemberId
        })
        $script:Configuration.groups[0].eligibleMemberIds += '44444444-4444-4444-4444-444444444444'
        Save-TestConfiguration
        (Invoke-Deployment).Status | Should -Be 'Configured'
        $script:State.EligibleInstances.Count | Should -Be 2
        @($script:State.Calls | Where-Object { $_.Method -eq 'POST' }).Count | Should -Be 1
    }

    It 'does not replace complex existing approval policies' {
        $script:State.Group = New-ExistingGroup
        $script:State.OwnerIds = @($script:OwnerId)
        (Get-TestRule 'Approval_EndUser_Assignment').setting.approvalStages[0].isEscalationEnabled = $true
        { Invoke-Deployment } | Should -Throw '*requires manual review*'
        @($script:State.Calls | Where-Object { $_.Method -ne 'GET' }).Count | Should -Be 0
    }

    It 'preserves additional activation controls rather than weakening them' {
        (Get-TestRule 'Enablement_EndUser_Assignment').enabledRules = @('Ticketing')
        $null = Invoke-Deployment
        (Get-TestRule 'Enablement_EndUser_Assignment').enabledRules | Should -Contain 'Ticketing'
    }

    It 'does not grant eligibility if the Member policy cannot be verified' {
        $script:State.IgnorePolicyWrites = $true
        { Invoke-Deployment } | Should -Throw '*Timed out waiting for Member policy*'
        $script:State.EligibleInstances.Count | Should -Be 0
        @($script:State.Calls | Where-Object {
                $_.Method -eq 'POST' -and $_.Path -eq '/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
            }).Count | Should -Be 0
    }

    It 'requires the additional read scope for administrative-unit targets' {
        $unitId = 'eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
        $script:Configuration.groups[0].roles[0].directoryScopeId = "/administrativeUnits/$unitId"
        Save-TestConfiguration
        { Invoke-Deployment } | Should -Throw '*missing scope AdministrativeUnit.Read.All*'
        $script:GraphContext.Scopes += 'AdministrativeUnit.Read.All'
        (Invoke-Deployment).Status | Should -Be 'Configured'
        $script:State.RoleInstances[0].directoryScopeId | Should -Be "/administrativeUnits/$unitId"
    }
}

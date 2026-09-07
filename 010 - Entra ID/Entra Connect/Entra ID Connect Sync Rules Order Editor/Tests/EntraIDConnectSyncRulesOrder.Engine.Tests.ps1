#requires -Version 5.1

$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'EntraIDConnectSyncRulesOrder.Engine.psm1'
$module = Import-Module $modulePath -Force -PassThru

function New-SyntheticRule {
    param([string]$Identifier, [bool]$IsStandardRule)
    return [pscustomobject]@{
        Identifier     = $Identifier
        Name           = "Rule $Identifier"
        Connector      = 'Synthetic connector'
        IsStandardRule = $IsStandardRule
    }
}

Describe 'Get-ADSyncRuleOrderMovePlan' {
    It 'moves a custom rule before Microsoft rules without selecting a Microsoft source' {
        $ruleA = New-SyntheticRule -Identifier 'A' -IsStandardRule $true
        $ruleB = New-SyntheticRule -Identifier 'B' -IsStandardRule $true
        $ruleC = New-SyntheticRule -Identifier 'C' -IsStandardRule $false

        $plan = @(Get-ADSyncRuleOrderMovePlan `
                -OriginalRules @($ruleA, $ruleB, $ruleC) `
                -DesiredRules @($ruleC, $ruleA, $ruleB))

        $plan.Count | Should Be 1
        $plan[0].Identifier | Should Be 'C'
        $plan[0].Placement | Should Be 'Before'
        $plan[0].AnchorIdentifier | Should Be 'A'
    }

    It 'moves a custom rule after Microsoft rules without selecting a Microsoft source' {
        $ruleA = New-SyntheticRule -Identifier 'A' -IsStandardRule $true
        $ruleB = New-SyntheticRule -Identifier 'B' -IsStandardRule $true
        $ruleC = New-SyntheticRule -Identifier 'C' -IsStandardRule $false

        $plan = @(Get-ADSyncRuleOrderMovePlan `
                -OriginalRules @($ruleC, $ruleA, $ruleB) `
                -DesiredRules @($ruleA, $ruleB, $ruleC))

        $plan.Count | Should Be 1
        $plan[0].Identifier | Should Be 'C'
        $plan[0].Placement | Should Be 'After'
        $plan[0].AnchorIdentifier | Should Be 'B'
    }

    It 'selects exactly one Microsoft source when two Microsoft rules reverse order' {
        $ruleA = New-SyntheticRule -Identifier 'A' -IsStandardRule $true
        $ruleB = New-SyntheticRule -Identifier 'B' -IsStandardRule $true
        $ruleC = New-SyntheticRule -Identifier 'C' -IsStandardRule $false

        $plan = @(Get-ADSyncRuleOrderMovePlan `
                -OriginalRules @($ruleA, $ruleB, $ruleC) `
                -DesiredRules @($ruleB, $ruleA, $ruleC))
        $microsoftOperations = @($plan | Where-Object Identifier -in @('A', 'B'))

        $microsoftOperations.Count | Should Be 1
    }

    It 'preserves all Microsoft sources in a mixed custom-rule reorder' {
        $ruleA = New-SyntheticRule -Identifier 'A' -IsStandardRule $true
        $ruleB = New-SyntheticRule -Identifier 'B' -IsStandardRule $true
        $ruleC = New-SyntheticRule -Identifier 'C' -IsStandardRule $false
        $ruleD = New-SyntheticRule -Identifier 'D' -IsStandardRule $false
        $ruleE = New-SyntheticRule -Identifier 'E' -IsStandardRule $true
        $ruleF = New-SyntheticRule -Identifier 'F' -IsStandardRule $false

        $plan = @(Get-ADSyncRuleOrderMovePlan `
                -OriginalRules @($ruleA, $ruleB, $ruleC, $ruleD, $ruleE, $ruleF) `
                -DesiredRules @($ruleC, $ruleA, $ruleD, $ruleB, $ruleF, $ruleE))
        $microsoftOperations = @($plan | Where-Object Identifier -in @('A', 'B', 'E'))

        $microsoftOperations.Count | Should Be 0
    }
}

& $module {
    function script:New-MockRule {
        param(
            [guid]$Identifier,
            [string]$Name,
            [int]$Precedence,
            [bool]$IsStandardRule
        )
        return [pscustomobject]@{
            Identifier               = $Identifier
            Name                     = $Name
            Description              = "Description for $Name"
            Direction                = 'Inbound'
            Connector                = [guid]'10000000-0000-0000-0000-000000000001'
            SourceObjectType         = 'user'
            TargetObjectType         = 'person'
            LinkType                 = 'Join'
            Precedence               = $Precedence
            Disabled                 = $false
            SoftDeleteExpiryInterval = [timespan]::Zero
            EnablePasswordSync       = $false
            IsStandardRule           = $IsStandardRule
            AttributeFlowMappings    = @()
            ScopeFilter              = @()
            JoinFilter               = @()
        }
    }

    function script:Set-MockPrecedence {
        for ($index = 0; $index -lt $script:MockRules.Count; $index++) {
            $script:MockRules[$index].Precedence = $index
        }
    }

    function script:Get-ADSyncRule {
        return @($script:MockRules)
    }

    function script:New-ADSyncRule {
        param(
            [string]$Name,
            [guid]$Identifier,
            [string]$Description,
            [string]$Direction,
            [guid]$Connector,
            [string]$SourceObjectType,
            [string]$TargetObjectType,
            [string]$LinkType,
            [timespan]$SoftDeleteExpiryInterval,
            [guid]$PrecedenceBefore,
            [guid]$PrecedenceAfter
        )
        $rule = [pscustomobject]@{
            Identifier               = $Identifier
            Name                     = $Name
            Description              = $Description
            Direction                = $Direction
            Connector                = $Connector
            SourceObjectType         = $SourceObjectType
            TargetObjectType         = $TargetObjectType
            LinkType                 = $LinkType
            Precedence               = 0
            Disabled                 = $false
            SoftDeleteExpiryInterval = $SoftDeleteExpiryInterval
            EnablePasswordSync       = $false
            IsStandardRule           = $false
            AttributeFlowMappings    = @()
            ScopeFilter              = @()
            JoinFilter               = @()
        }
        if ($PSBoundParameters.ContainsKey('PrecedenceBefore')) {
            $rule | Add-Member -MemberType NoteProperty -Name MockPlacement -Value 'Before'
            $rule | Add-Member -MemberType NoteProperty -Name MockAnchor -Value $PrecedenceBefore
        }
        else {
            $rule | Add-Member -MemberType NoteProperty -Name MockPlacement -Value 'After'
            $rule | Add-Member -MemberType NoteProperty -Name MockAnchor -Value $PrecedenceAfter
        }
        return $rule
    }

    function script:Add-ADSyncRule {
        [CmdletBinding()]
        param([Parameter(Mandatory)]$SynchronizationRule)

        $existingIndex = -1
        for ($index = 0; $index -lt $script:MockRules.Count; $index++) {
            if ($script:MockRules[$index].Identifier -eq $SynchronizationRule.Identifier) {
                $existingIndex = $index
                break
            }
        }
        if ($existingIndex -ge 0) {
            $script:MockRules[$existingIndex] = $SynchronizationRule
        }
        elseif ('MockAnchor' -in $SynchronizationRule.PSObject.Properties.Name) {
            $anchorIndex = -1
            for ($index = 0; $index -lt $script:MockRules.Count; $index++) {
                if ($script:MockRules[$index].Identifier -eq $SynchronizationRule.MockAnchor) {
                    $anchorIndex = $index
                    break
                }
            }
            if ($anchorIndex -lt 0) {
                throw 'Mock anchor was not found.'
            }
            $insertIndex = if ($SynchronizationRule.MockPlacement -eq 'Before') {
                $anchorIndex
            }
            else {
                $anchorIndex + 1
            }
            $script:MockRules.Insert($insertIndex, $SynchronizationRule)
            if ($script:CorruptNextReplacement) {
                $SynchronizationRule.Description = 'Corrupted by mock'
                $script:CorruptNextReplacement = $false
            }
        }
        else {
            $insertIndex = [Math]::Min([int]$SynchronizationRule.Precedence, $script:MockRules.Count)
            $script:MockRules.Insert($insertIndex, $SynchronizationRule)
        }
        Set-MockPrecedence
    }

    function script:Remove-ADSyncRule {
        [CmdletBinding()]
        param([Parameter(Mandatory)][guid]$Identifier)

        for ($index = 0; $index -lt $script:MockRules.Count; $index++) {
            if ($script:MockRules[$index].Identifier -eq $Identifier) {
                $script:MockRules.RemoveAt($index)
                Set-MockPrecedence
                return
            }
        }
        throw "Mock rule '$Identifier' was not found."
    }

    function script:Test-MockMoveRollback {
        param([bool]$SourceIsStandard)

        $sourceIdentifier = [guid]'20000000-0000-0000-0000-000000000001'
        $anchorIdentifier = [guid]'20000000-0000-0000-0000-000000000002'
        $sourceRule = New-MockRule `
            -Identifier $sourceIdentifier `
            -Name 'Source rule' `
            -Precedence 0 `
            -IsStandardRule $SourceIsStandard
        $anchorRule = New-MockRule `
            -Identifier $anchorIdentifier `
            -Name 'Anchor rule' `
            -Precedence 1 `
            -IsStandardRule $false
        $script:MockRules = [System.Collections.Generic.List[object]]::new()
        $script:MockRules.Add($sourceRule)
        $script:MockRules.Add($anchorRule)
        $script:CorruptNextReplacement = $true
        $errorMessage = $null
        try {
            Move-ADSyncRuleOrderLiveRuleRelative `
                -Identifier $sourceIdentifier `
                -AnchorIdentifier $anchorIdentifier `
                -Placement Before | Out-Null
        }
        catch {
            $errorMessage = $_.Exception.Message
        }

        $original = @($script:MockRules | Where-Object Identifier -eq $sourceIdentifier)
        $replacementCount = @($script:MockRules | Where-Object {
                $_.Identifier -ne $sourceIdentifier -and $_.Identifier -ne $anchorIdentifier
            }).Count
        return [pscustomobject]@{
            Error            = $errorMessage
            RuleCount        = $script:MockRules.Count
            OriginalExists   = $original.Count -eq 1
            OriginalDisabled = if ($original.Count -eq 1) { [bool]$original[0].Disabled } else { $null }
            ReplacementCount = $replacementCount
        }
    }

    function script:Assert-ADSyncRuleOrderAvailable {
    }

    function script:Get-ADSyncScheduler {
        return [pscustomobject]@{
            StagingModeEnabled = $true
            SyncCycleEnabled   = [bool]$script:MockSchedulerEnabled
            SyncCycleInProgress = $false
        }
    }

    function script:Set-ADSyncScheduler {
        [CmdletBinding()]
        param([bool]$SyncCycleEnabled)

        if ($SyncCycleEnabled -and $script:MockFailSchedulerEnable) {
            throw 'Mock scheduler enable failure.'
        }
        $script:MockSchedulerEnabled = $SyncCycleEnabled
    }

    function script:New-ADSyncRuleOrderBackup {
        param([string]$BackupRoot, [string]$Label)
        return [pscustomobject]@{
            Path = Join-Path $BackupRoot $Label
        }
    }

    function script:Test-MockSchedulerRestoreFailure {
        $customRule = New-MockRule `
            -Identifier ([guid]'30000000-0000-0000-0000-000000000001') `
            -Name 'Custom rule' `
            -Precedence 0 `
            -IsStandardRule $false
        $standardRuleA = New-MockRule `
            -Identifier ([guid]'30000000-0000-0000-0000-000000000002') `
            -Name 'Microsoft rule A' `
            -Precedence 1 `
            -IsStandardRule $true
        $standardRuleB = New-MockRule `
            -Identifier ([guid]'30000000-0000-0000-0000-000000000003') `
            -Name 'Microsoft rule B' `
            -Precedence 2 `
            -IsStandardRule $true
        $script:MockRules = [System.Collections.Generic.List[object]]::new()
        $script:MockRules.Add($customRule)
        $script:MockRules.Add($standardRuleA)
        $script:MockRules.Add($standardRuleB)
        $script:CorruptNextReplacement = $false
        $script:MockSchedulerEnabled = $true
        $script:MockFailSchedulerEnable = $true

        $plan = @(Get-ADSyncRuleOrderMovePlan `
                -OriginalRules @($customRule, $standardRuleA, $standardRuleB) `
                -DesiredRules @($standardRuleA, $standardRuleB, $customRule))
        $fingerprint = Get-ADSyncRuleOrderFingerprint
        $result = Invoke-ADSyncRuleOrderMovePlan `
            -MovePlan $plan `
            -ExpectedFingerprint $fingerprint `
            -BackupRoot $env:TEMP `
            -ConfirmationToken "APPLY $($env:COMPUTERNAME)" `
            -Confirm:$false

        return [pscustomobject]@{
            Applied               = [bool]$result.Applied
            OperationCount        = @($result.Operations).Count
            SchedulerRestored     = [bool]$result.SchedulerRestored
            SchedulerRestoreError = [string]$result.SchedulerRestoreError
            SchedulerEnabled      = [bool]$script:MockSchedulerEnabled
        }
    }
}

Describe 'Move-ADSyncRuleOrderLiveRuleRelative rollback' {
    It 'removes a rejected custom replacement and restores the original rule' {
        $result = & $module { Test-MockMoveRollback -SourceIsStandard $false }

        $result.Error | Should Match 'rolled back'
        $result.RuleCount | Should Be 2
        $result.OriginalExists | Should Be $true
        $result.OriginalDisabled | Should Be $false
        $result.ReplacementCount | Should Be 0
    }

    It 'removes a rejected Microsoft clone and preserves the enabled original rule' {
        $result = & $module { Test-MockMoveRollback -SourceIsStandard $true }

        $result.Error | Should Match 'rolled back'
        $result.RuleCount | Should Be 2
        $result.OriginalExists | Should Be $true
        $result.OriginalDisabled | Should Be $false
        $result.ReplacementCount | Should Be 0
    }
}

Describe 'Invoke-ADSyncRuleOrderMovePlan scheduler restoration' {
    It 'reports a successful Apply separately from a scheduler re-enable failure' {
        $result = & $module { Test-MockSchedulerRestoreFailure }

        $result.Applied | Should Be $true
        $result.OperationCount | Should Be 1
        $result.SchedulerRestored | Should Be $false
        $result.SchedulerRestoreError | Should Match 'Mock scheduler enable failure'
        $result.SchedulerEnabled | Should Be $false
    }
}

Remove-Module $module.Name -Force
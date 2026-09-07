Set-StrictMode -Version 2.0

function Invoke-ADSyncRuleOrderProgress {
    param(
        [scriptblock]$ProgressCallback,
        [ValidateRange(0, 100)][int]$Percent,
        [string]$Activity,
        [ValidateRange(0, 100)][int]$ProgressStart = 0,
        [ValidateRange(0, 100)][int]$ProgressEnd = 100
    )

    if ($null -eq $ProgressCallback) {
        return
    }
    $mappedPercent = $ProgressStart + [int][Math]::Round(
        (($ProgressEnd - $ProgressStart) * $Percent) / 100
    )
    try {
        & $ProgressCallback $mappedPercent $Activity
    }
    catch {
        Write-Verbose "Progress callback failed: $($_.Exception.Message)"
    }
}

function Move-ADSyncRuleOrderItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Rules,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Identifier,

        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$NewIndex
    )

    if ($Rules.Count -eq 0) {
        throw 'The rule collection is empty.'
    }
    if ($NewIndex -ge $Rules.Count) {
        throw "NewIndex $NewIndex is outside the rule collection."
    }

    $matchingIndexes = @(for ($index = 0; $index -lt $Rules.Count; $index++) {
            if ([string]$Rules[$index].Identifier -eq $Identifier) {
                $index
            }
        })
    if ($matchingIndexes.Count -ne 1) {
        throw "Expected exactly one rule with identifier '$Identifier'; found $($matchingIndexes.Count)."
    }

    $oldIndex = [int]$matchingIndexes[0]
    if ($oldIndex -eq $NewIndex) {
        return @($Rules)
    }

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $Rules) {
        $result.Add($rule)
    }

    $movedRule = $result[$oldIndex]
    $result.RemoveAt($oldIndex)
    $result.Insert($NewIndex, $movedRule)
    return @($result)
}


function Assert-ADSyncRuleOrderAvailable {
    [CmdletBinding()]
    param()

    Import-Module ADSync -ErrorAction Stop
    foreach ($commandName in @(
            'Get-ADSyncRule',
            'Get-ADSyncConnector',
            'Get-ADSyncScheduler',
            'Set-ADSyncScheduler',
            'Get-ADSyncServerConfiguration',
            'New-ADSyncRule',
            'Add-ADSyncRule',
            'Remove-ADSyncRule'
        )) {
        if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "Required ADSync command '$commandName' is unavailable."
        }
    }
}

function Get-ADSyncRuleOrderSnapshot {
    [CmdletBinding()]
    param()

    Assert-ADSyncRuleOrderAvailable
    $connectors = @(Get-ADSyncConnector)
    $connectorNames = @{}
    foreach ($connector in $connectors) {
        $connectorNames[$connector.Identifier.ToString()] = [string]$connector.Name
    }

    $rules = foreach ($rule in @(Get-ADSyncRule)) {
        $connectorIdentifier = $rule.Connector.ToString()
        $connectorName = if ($connectorNames.ContainsKey($connectorIdentifier)) {
            $connectorNames[$connectorIdentifier]
        }
        else {
            $connectorIdentifier
        }

        [pscustomobject]@{
            Identifier       = $rule.Identifier.ToString()
            Name             = [string]$rule.Name
            Connector        = $connectorName
            ConnectorId      = $connectorIdentifier
            Disabled         = [bool]$rule.Disabled
            IsStandardRule   = [bool]$rule.IsStandardRule
            RuleType         = if ([bool]$rule.IsStandardRule) { 'Standard' } else { 'Custom' }
            OldPrecedence    = [int]$rule.Precedence
            NewPrecedence    = [int]$rule.Precedence
            SourceObjectType = [string]$rule.SourceObjectType
            TargetObjectType = [string]$rule.TargetObjectType
            LinkType         = [string]$rule.LinkType
            Direction        = [string]$rule.Direction
            OriginalOrder    = 0
        }
    }

    $orderedRules = @($rules | Sort-Object OldPrecedence, Identifier)
    for ($index = 0; $index -lt $orderedRules.Count; $index++) {
        $orderedRules[$index].OriginalOrder = $index
    }
    return $orderedRules
}

function Get-ADSyncRuleOrderFingerprint {
    [CmdletBinding()]
    param()

    Assert-ADSyncRuleOrderAvailable
    $canonicalLines = @(
        Get-ADSyncRule |
            Sort-Object { $_.Identifier.ToString() } |
            ForEach-Object {
                '{0}|{1}|{2}|{3}|{4}|{5}' -f `
                    $_.Identifier.ToString(),
                    $_.Precedence,
                    $_.Disabled,
                    $_.Connector.ToString(),
                    $_.Direction,
                    $_.Name
            }
    )
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($canonicalLines -join "`n"))
    $algorithm = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '')
    }
    finally {
        $algorithm.Dispose()
    }
}

function New-ADSyncRuleOrderBackup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupRoot,

        [string]$Label = 'LiveSnapshot',

        [scriptblock]$ProgressCallback,

        [ValidateRange(0, 100)]
        [int]$ProgressStart = 0,

        [ValidateRange(0, 100)]
        [int]$ProgressEnd = 100
    )

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 0 'Checking ADSync commands...' $ProgressStart $ProgressEnd
    Assert-ADSyncRuleOrderAvailable
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 5 'Preparing the safety snapshot folder...' $ProgressStart $ProgressEnd
    if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
        New-Item -Path $BackupRoot -ItemType Directory -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $safeLabel = $Label -replace '[^A-Za-z0-9_.-]', '_'
    $backupPath = Join-Path $BackupRoot "$timestamp-$($env:COMPUTERNAME)-$safeLabel"
    if (Test-Path -LiteralPath $backupPath) {
        $backupPath += "-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
    }
    $configurationPath = Join-Path $backupPath 'ServerConfiguration'
    New-Item -Path $configurationPath -ItemType Directory -ErrorAction Stop | Out-Null

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 12 'Reading live rules, connectors, and scheduler state...' $ProgressStart $ProgressEnd
    $rules = @(Get-ADSyncRule)
    $connectors = @(Get-ADSyncConnector)
    $scheduler = Get-ADSyncScheduler
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 28 'Serializing live ADSync objects...' $ProgressStart $ProgressEnd
    $rules | Export-Clixml -LiteralPath (Join-Path $backupPath 'Rules.clixml') -Depth 20
    $connectors | Export-Clixml -LiteralPath (Join-Path $backupPath 'Connectors.clixml') -Depth 20
    $scheduler | Export-Clixml -LiteralPath (Join-Path $backupPath 'Scheduler.clixml') -Depth 10
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 42 'Exporting the documentary rule inventory...' $ProgressStart $ProgressEnd
    Get-ADSyncRuleOrderSnapshot |
        Select-Object Identifier, Name, Connector, ConnectorId, Disabled, IsStandardRule, RuleType,
            OldPrecedence, SourceObjectType, TargetObjectType, LinkType, Direction |
        Export-Csv -LiteralPath (Join-Path $backupPath 'Rules.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 55 'Exporting the Entra Connect server configuration...' $ProgressStart $ProgressEnd
    Get-ADSyncServerConfiguration -Path $configurationPath -ErrorAction Stop | Out-Null
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 78 'Verifying the server configuration export...' $ProgressStart $ProgressEnd
    $configurationFiles = @(Get-ChildItem -LiteralPath $configurationPath -File -Recurse)
    if ($configurationFiles.Count -eq 0) {
        throw "Get-ADSyncServerConfiguration did not create any file in '$configurationPath'."
    }

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 86 'Calculating snapshot integrity hashes...' $ProgressStart $ProgressEnd
    $files = @(Get-ChildItem -LiteralPath $backupPath -File -Recurse)
    $manifest = @(
        $files | Get-FileHash -Algorithm SHA256 | Select-Object `
            @{Name = 'RelativePath'; Expression = { $_.Path.Substring($backupPath.Length + 1) }},
            Hash
    )
    $manifestPath = Join-Path $backupPath 'SHA256-manifest.csv'
    $manifest | Export-Csv -LiteralPath $manifestPath -Delimiter ';' -NoTypeInformation -Encoding UTF8

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 96 'Calculating the live rule fingerprint...' $ProgressStart $ProgressEnd
    $fingerprint = Get-ADSyncRuleOrderFingerprint
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 100 'Safety snapshot complete.' $ProgressStart $ProgressEnd
    return [pscustomobject]@{
        Path         = $backupPath
        RuleCount    = $rules.Count
        ManifestPath = $manifestPath
        ManifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash
        Fingerprint  = $fingerprint
    }
}

function Get-ADSyncRuleOrderBackupSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupPath,

        [Parameter(Mandatory)]
        [object[]]$CurrentRules,

        [scriptblock]$ProgressCallback
    )

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 0 'Locating the selected safety snapshot...'
    $resolvedBackupPath = (Resolve-Path -LiteralPath $BackupPath -ErrorAction Stop).Path.TrimEnd('\')
    $manifestPath = Join-Path $resolvedBackupPath 'SHA256-manifest.csv'
    $rulesPath = Join-Path $resolvedBackupPath 'Rules.csv'
    foreach ($requiredPath in @($manifestPath, $rulesPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            throw "Required backup file not found: $requiredPath"
        }
    }

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 8 'Reading the snapshot integrity manifest...'
    $manifest = @(Import-Csv -LiteralPath $manifestPath -Delimiter ';')
    if ($manifest.Count -eq 0) {
        throw "The backup manifest is empty: $manifestPath"
    }
    $manifestRelativePaths = @($manifest | ForEach-Object { [string]$_.RelativePath })
    if (@($manifestRelativePaths | Sort-Object -Unique).Count -ne $manifestRelativePaths.Count) {
        throw 'The backup manifest contains duplicate relative paths.'
    }
    if (@($manifestRelativePaths | Where-Object { $_ -ieq 'Rules.csv' }).Count -ne 1) {
        throw 'The backup manifest must contain exactly one Rules.csv entry.'
    }
    $backupPrefix = $resolvedBackupPath + [IO.Path]::DirectorySeparatorChar
    for ($entryIndex = 0; $entryIndex -lt $manifest.Count; $entryIndex++) {
        $entry = $manifest[$entryIndex]
        $hashPercent = 15 + [int][Math]::Round((50 * $entryIndex) / [Math]::Max(1, $manifest.Count))
        Invoke-ADSyncRuleOrderProgress `
            $ProgressCallback `
            $hashPercent `
            "Verifying snapshot file $($entryIndex + 1) of $($manifest.Count): $($entry.RelativePath)"
        if ([string]::IsNullOrWhiteSpace([string]$entry.RelativePath) -or
            [string]::IsNullOrWhiteSpace([string]$entry.Hash)) {
            throw 'The backup manifest contains an incomplete entry.'
        }
        $candidatePath = [IO.Path]::GetFullPath((Join-Path $resolvedBackupPath ([string]$entry.RelativePath)))
        if (-not $candidatePath.StartsWith($backupPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw "The backup manifest contains an unsafe path: $($entry.RelativePath)"
        }
        if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
            throw "A backup file is missing: $($entry.RelativePath)"
        }
        $actualHash = (Get-FileHash -LiteralPath $candidatePath -Algorithm SHA256).Hash
        if ($actualHash -cne ([string]$entry.Hash).ToUpperInvariant()) {
            throw "Backup integrity check failed: $($entry.RelativePath)"
        }
    }

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 68 'Reading the saved rule inventory...'
    $backupRules = @(Import-Csv -LiteralPath $rulesPath -Delimiter ';')
    if ($backupRules.Count -ne $CurrentRules.Count) {
        throw "Rule inventory changed. Backup: $($backupRules.Count); live: $($CurrentRules.Count). Order restore was cancelled."
    }

    $remainingRules = [System.Collections.Generic.List[object]]::new()
    foreach ($rule in $CurrentRules) {
        $remainingRules.Add($rule)
    }
    $desiredRules = [System.Collections.Generic.List[object]]::new()
    $orderedBackupRules = @($backupRules | Sort-Object {[int]$_.OldPrecedence}, Identifier)
    for ($ruleIndex = 0; $ruleIndex -lt $orderedBackupRules.Count; $ruleIndex++) {
        $backupRule = $orderedBackupRules[$ruleIndex]
        $mappingPercent = 72 + [int][Math]::Round((26 * $ruleIndex) / [Math]::Max(1, $orderedBackupRules.Count))
        Invoke-ADSyncRuleOrderProgress `
            $ProgressCallback `
            $mappingPercent `
            "Mapping saved rule $($ruleIndex + 1) of $($orderedBackupRules.Count): $($backupRule.Name)"
        $matchingRules = @($remainingRules | Where-Object {
                [string]$_.Identifier -eq [string]$backupRule.Identifier
            })
        if ($matchingRules.Count -eq 0) {
            $matchingRules = @($remainingRules | Where-Object {
                    [string]$_.ConnectorId -eq [string]$backupRule.ConnectorId -and
                    [string]$_.Name -eq [string]$backupRule.Name -and
                    [string]$_.RuleType -eq [string]$backupRule.RuleType -and
                    [string]$_.Direction -eq [string]$backupRule.Direction -and
                    [string]$_.SourceObjectType -eq [string]$backupRule.SourceObjectType -and
                    [string]$_.TargetObjectType -eq [string]$backupRule.TargetObjectType -and
                    [string]$_.LinkType -eq [string]$backupRule.LinkType
                })
        }
        if ($matchingRules.Count -ne 1) {
            throw "Backup rule '$($backupRule.Name)' could not be matched uniquely to the live inventory. Found: $($matchingRules.Count)."
        }
        $matchedRule = $matchingRules[0]
        $desiredRules.Add($matchedRule)
        [void]$remainingRules.Remove($matchedRule)
    }
    if ($remainingRules.Count -ne 0) {
        throw "$($remainingRules.Count) live rule(s) are not represented in the backup. Order restore was cancelled."
    }

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 100 'Snapshot validation and rule mapping complete.'
    return @($desiredRules)
}

function Get-ADSyncRuleOrderMovePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$OriginalRules,

        [Parameter(Mandatory)]
        [object[]]$DesiredRules
    )

    if ($OriginalRules.Count -ne $DesiredRules.Count) {
        throw 'Original and desired rule collections have different sizes.'
    }

    $originalIdentifiers = @($OriginalRules | ForEach-Object { [string]$_.Identifier })
    $desiredIdentifiers = @($DesiredRules | ForEach-Object { [string]$_.Identifier })
    if (@($originalIdentifiers | Sort-Object -Unique).Count -ne $originalIdentifiers.Count -or
        @($desiredIdentifiers | Sort-Object -Unique).Count -ne $desiredIdentifiers.Count) {
        throw 'Rule identifiers must be unique.'
    }

    $setDifference = @(Compare-Object $originalIdentifiers $desiredIdentifiers)
    if ($setDifference.Count -gt 0) {
        throw 'Original and desired rule collections do not contain the same identifiers.'
    }

    $originalPositions = @{}
    for ($index = 0; $index -lt $originalIdentifiers.Count; $index++) {
        $originalPositions[$originalIdentifiers[$index]] = $index
    }
    $rulesByIdentifier = @{}
    foreach ($rule in $DesiredRules) {
        $rulesByIdentifier[[string]$rule.Identifier] = $rule
    }

    $ruleCount = $desiredIdentifiers.Count
    $bestStandardCounts = [int[]]::new($ruleCount)
    $bestTotalCounts = [int[]]::new($ruleCount)
    $previousIndexes = [int[]]::new($ruleCount)
    for ($index = 0; $index -lt $ruleCount; $index++) {
        $currentRule = $rulesByIdentifier[$desiredIdentifiers[$index]]
        $bestStandardCounts[$index] = if ([bool]$currentRule.IsStandardRule) { 1 } else { 0 }
        $bestTotalCounts[$index] = 1
        $previousIndexes[$index] = -1

        for ($candidateIndex = 0; $candidateIndex -lt $index; $candidateIndex++) {
            if ($originalPositions[$desiredIdentifiers[$candidateIndex]] -ge
                $originalPositions[$desiredIdentifiers[$index]]) {
                continue
            }
            $candidateStandardCount = $bestStandardCounts[$candidateIndex]
            if ([bool]$currentRule.IsStandardRule) {
                $candidateStandardCount++
            }
            $candidateTotalCount = $bestTotalCounts[$candidateIndex] + 1
            if ($candidateStandardCount -gt $bestStandardCounts[$index] -or
                ($candidateStandardCount -eq $bestStandardCounts[$index] -and
                    $candidateTotalCount -gt $bestTotalCounts[$index])) {
                $bestStandardCounts[$index] = $candidateStandardCount
                $bestTotalCounts[$index] = $candidateTotalCount
                $previousIndexes[$index] = $candidateIndex
            }
        }
    }

    $bestEndIndex = 0
    for ($index = 1; $index -lt $ruleCount; $index++) {
        if ($bestStandardCounts[$index] -gt $bestStandardCounts[$bestEndIndex] -or
            ($bestStandardCounts[$index] -eq $bestStandardCounts[$bestEndIndex] -and
                $bestTotalCounts[$index] -gt $bestTotalCounts[$bestEndIndex])) {
            $bestEndIndex = $index
        }
    }
    $keptIdentifiers = @{}
    for ($index = $bestEndIndex; $index -ge 0; $index = $previousIndexes[$index]) {
        $keptIdentifiers[$desiredIdentifiers[$index]] = $true
        if ($previousIndexes[$index] -lt 0) {
            break
        }
    }

    $relativeOperations = [System.Collections.Generic.List[object]]::new()
    $segmentStart = 0
    for ($keepIndex = 0; $keepIndex -lt $ruleCount; $keepIndex++) {
        if (-not $keptIdentifiers.ContainsKey($desiredIdentifiers[$keepIndex])) {
            continue
        }
        for ($index = $keepIndex - 1; $index -ge $segmentStart; $index--) {
            $relativeOperations.Add([pscustomobject]@{
                    Identifier       = $desiredIdentifiers[$index]
                    Placement        = 'Before'
                    AnchorIdentifier = $desiredIdentifiers[$index + 1]
                })
        }
        $segmentStart = $keepIndex + 1
    }
    for ($index = $segmentStart; $index -lt $ruleCount; $index++) {
        $relativeOperations.Add([pscustomobject]@{
                Identifier       = $desiredIdentifiers[$index]
                Placement        = 'After'
                AnchorIdentifier = $desiredIdentifiers[$index - 1]
            })
    }

    $working = [System.Collections.Generic.List[string]]::new()
    foreach ($identifier in $originalIdentifiers) {
        $working.Add($identifier)
    }
    $moves = @()
    foreach ($relativeOperation in $relativeOperations) {
        $sourceIndex = $working.IndexOf($relativeOperation.Identifier)
        if ($sourceIndex -lt 0) {
            throw "Rule '$($relativeOperation.Identifier)' disappeared while calculating the move plan."
        }
        $working.RemoveAt($sourceIndex)
        $anchorIndex = $working.IndexOf($relativeOperation.AnchorIdentifier)
        if ($anchorIndex -lt 0) {
            throw "Anchor rule '$($relativeOperation.AnchorIdentifier)' disappeared while calculating the move plan."
        }
        $targetIndex = if ($relativeOperation.Placement -eq 'Before') { $anchorIndex } else { $anchorIndex + 1 }
        $working.Insert($targetIndex, $relativeOperation.Identifier)

        $rule = $rulesByIdentifier[$relativeOperation.Identifier]
        $anchor = $rulesByIdentifier[$relativeOperation.AnchorIdentifier]
        $moves += [pscustomobject]@{
            Sequence         = $moves.Count + 1
            Identifier       = $relativeOperation.Identifier
            RuleName         = [string]$rule.Name
            Connector        = [string]$rule.Connector
            Placement        = $relativeOperation.Placement
            AnchorIdentifier = $relativeOperation.AnchorIdentifier
            AnchorRuleName   = [string]$anchor.Name
            FromPosition     = $sourceIndex + 1
            ToPosition       = $targetIndex + 1
        }
    }

    for ($index = 0; $index -lt $ruleCount; $index++) {
        if ($working[$index] -ne $desiredIdentifiers[$index]) {
            throw 'The optimized move plan did not reproduce the requested rule order.'
        }
    }
    return @($moves)
}

function New-ADSyncRuleOrderCloneObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$SourceRule,
        [Parameter(Mandatory)][guid]$AnchorIdentifier,
        [Parameter(Mandatory)][ValidateSet('Before', 'After')][string]$Placement,
        [Parameter(Mandatory)][string]$Name
    )

    $softDeleteExpiryInterval = if ($null -ne $SourceRule.SoftDeleteExpiryInterval) {
        $SourceRule.SoftDeleteExpiryInterval
    }
    else {
        [timespan]::Zero
    }
    $newRuleParameters = @{
        Name                     = $Name
        Identifier               = [guid]::NewGuid()
        Description              = [string]$SourceRule.Description
        Direction                = $SourceRule.Direction
        Connector                = $SourceRule.Connector
        SourceObjectType         = $SourceRule.SourceObjectType
        TargetObjectType         = $SourceRule.TargetObjectType
        LinkType                 = $SourceRule.LinkType
        SoftDeleteExpiryInterval = $softDeleteExpiryInterval
    }
    if ($Placement -eq 'Before') {
        $newRuleParameters.PrecedenceBefore = $AnchorIdentifier
    }
    else {
        $newRuleParameters.PrecedenceAfter = $AnchorIdentifier
    }
    $clone = New-ADSyncRule @newRuleParameters

    $clone.Disabled = [bool]$SourceRule.Disabled
    if ('EnablePasswordSync' -in $clone.PSObject.Properties.Name -and
        'EnablePasswordSync' -in $SourceRule.PSObject.Properties.Name) {
        $clone.EnablePasswordSync = [bool]$SourceRule.EnablePasswordSync
    }

    foreach ($mapping in @($SourceRule.AttributeFlowMappings)) {
        $mappingParameters = @{
            SynchronizationRule = $clone
            Destination         = [string]$mapping.Destination
            FlowType            = $mapping.FlowType
            ValueMergeType      = $mapping.ValueMergeType
            ErrorAction         = 'Stop'
        }
        if (@($mapping.Source).Count -gt 0) {
            $mappingParameters.Source = @($mapping.Source)
        }
        if (-not [string]::IsNullOrEmpty([string]$mapping.Expression)) {
            $mappingParameters.Expression = [string]$mapping.Expression
        }
        if ([bool]$mapping.ExecuteOnce) {
            $mappingParameters.ExecuteOnce = $true
        }
        Add-ADSyncAttributeFlowMapping @mappingParameters | Out-Null
    }

    foreach ($scopeGroup in @($SourceRule.ScopeFilter)) {
        $conditionList = [System.Collections.Generic.List[Microsoft.IdentityManagement.PowerShell.ObjectModel.ScopeCondition]]::new()
        foreach ($condition in $scopeGroup.ScopeConditionList) {
            $conditionCopy = New-Object `
                -TypeName 'Microsoft.IdentityManagement.PowerShell.ObjectModel.ScopeCondition' `
                -ArgumentList @(
                    [string]$condition.Attribute,
                    $condition.ComparisonValue,
                    $condition.ComparisonOperator.ToString()
                )
            $conditionList.Add($conditionCopy)
        }
        if ($conditionList.Count -gt 0) {
            Add-ADSyncScopeConditionGroup `
                -SynchronizationRule $clone `
                -ScopeConditions $conditionList `
                -ErrorAction Stop | Out-Null
        }
    }

    foreach ($joinGroup in @($SourceRule.JoinFilter)) {
        $joinList = [System.Collections.Generic.List[Microsoft.IdentityManagement.PowerShell.ObjectModel.JoinCondition]]::new()
        foreach ($condition in $joinGroup.JoinConditionList) {
            $conditionCopy = New-Object `
                -TypeName 'Microsoft.IdentityManagement.PowerShell.ObjectModel.JoinCondition' `
                -ArgumentList @(
                    [string]$condition.CSAttribute,
                    [string]$condition.MVAttribute,
                    [bool]$condition.CaseSensitive
                )
            $joinList.Add($conditionCopy)
        }
        if ($joinList.Count -gt 0) {
            Add-ADSyncJoinConditionGroup `
                -SynchronizationRule $clone `
                -JoinConditions $joinList `
                -ErrorAction Stop | Out-Null
        }
    }

    return $clone
}

function Test-ADSyncRuleOrderClone {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$SourceRule,
        [Parameter(Mandatory)]$CloneRule
    )

    $differences = @()
    foreach ($propertyName in @(
            'Connector', 'Direction', 'SourceObjectType', 'TargetObjectType', 'LinkType',
            'Disabled', 'Description', 'SoftDeleteExpiryInterval', 'EnablePasswordSync'
        )) {
        if ([string]$SourceRule.$propertyName -cne [string]$CloneRule.$propertyName) {
            $differences += $propertyName
        }
    }

    $sourceMappings = @($SourceRule.AttributeFlowMappings | ForEach-Object {
            '{0}|{1}|{2}|{3}|{4}|{5}' -f `
                $_.Destination,
                $_.FlowType,
                (@($_.Source) -join ','),
                $_.Expression,
                $_.ValueMergeType,
                $_.ExecuteOnce
        } | Sort-Object)
    $cloneMappings = @($CloneRule.AttributeFlowMappings | ForEach-Object {
            '{0}|{1}|{2}|{3}|{4}|{5}' -f `
                $_.Destination,
                $_.FlowType,
                (@($_.Source) -join ','),
                $_.Expression,
                $_.ValueMergeType,
                $_.ExecuteOnce
        } | Sort-Object)
    if (@(Compare-Object $sourceMappings $cloneMappings -CaseSensitive).Count -gt 0) {
        $differences += 'AttributeFlowMappings'
    }

    $sourceScopes = @($SourceRule.ScopeFilter | ForEach-Object {
            (@($_.ScopeConditionList | ForEach-Object {
                        '{0}|{1}|{2}' -f $_.Attribute, $_.ComparisonOperator, $_.ComparisonValue
                    } | Sort-Object) -join '&&')
        } | Sort-Object)
    $cloneScopes = @($CloneRule.ScopeFilter | ForEach-Object {
            (@($_.ScopeConditionList | ForEach-Object {
                        '{0}|{1}|{2}' -f $_.Attribute, $_.ComparisonOperator, $_.ComparisonValue
                    } | Sort-Object) -join '&&')
        } | Sort-Object)
    if (@(Compare-Object $sourceScopes $cloneScopes -CaseSensitive).Count -gt 0) {
        $differences += 'ScopeFilter'
    }

    $sourceJoins = @($SourceRule.JoinFilter | ForEach-Object {
            (@($_.JoinConditionList | ForEach-Object {
                        '{0}|{1}|{2}' -f $_.CSAttribute, $_.MVAttribute, $_.CaseSensitive
                    } | Sort-Object) -join '&&')
        })
    $cloneJoins = @($CloneRule.JoinFilter | ForEach-Object {
            (@($_.JoinConditionList | ForEach-Object {
                        '{0}|{1}|{2}' -f $_.CSAttribute, $_.MVAttribute, $_.CaseSensitive
                    } | Sort-Object) -join '&&')
        })
    $joinFiltersDiffer = $sourceJoins.Count -ne $cloneJoins.Count
    if (-not $joinFiltersDiffer) {
        for ($index = 0; $index -lt $sourceJoins.Count; $index++) {
            if ($sourceJoins[$index] -cne $cloneJoins[$index]) {
                $joinFiltersDiffer = $true
                break
            }
        }
    }
    if ($joinFiltersDiffer) {
        $differences += 'JoinFilter'
    }
    return @($differences)
}

function Move-ADSyncRuleOrderLiveRuleRelative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][guid]$Identifier,
        [Parameter(Mandatory)][guid]$AnchorIdentifier,
        [Parameter(Mandatory)][ValidateSet('Before', 'After')][string]$Placement
    )

    $sourceRule = Get-ADSyncRule | Where-Object Identifier -eq $Identifier | Select-Object -First 1
    $anchorRule = Get-ADSyncRule | Where-Object Identifier -eq $AnchorIdentifier | Select-Object -First 1
    if (-not $sourceRule) {
        throw "Rule '$Identifier' was not found."
    }
    if (-not $anchorRule) {
        throw "Anchor rule '$AnchorIdentifier' was not found."
    }
    if ($sourceRule.Identifier -eq $anchorRule.Identifier) {
        throw 'A rule cannot be moved before itself.'
    }

    $sourceWasStandard = [bool]$sourceRule.IsStandardRule
    $originalDisabled = [bool]$sourceRule.Disabled
    $cloneName = if ($sourceWasStandard) {
        '{0} - Reordered {1}' -f $sourceRule.Name, (Get-Date -Format 'yyyyMMdd-HHmmss')
    }
    else {
        [string]$sourceRule.Name
    }
    $clone = New-ADSyncRuleOrderCloneObject `
        -SourceRule $sourceRule `
        -AnchorIdentifier $anchorRule.Identifier `
        -Placement $Placement `
        -Name $cloneName

    $operation = [pscustomobject]@{
        SourceRule        = $sourceRule
        ReplacementId     = $clone.Identifier.ToString()
        OriginalId        = $Identifier.ToString()
        SourceWasStandard = $sourceWasStandard
        OriginalDisabled  = $originalDisabled
        RuleName          = [string]$sourceRule.Name
    }
    $mutationMayHaveStarted = $false
    try {
        if ($sourceWasStandard) {
            $mutationMayHaveStarted = $true
            Add-ADSyncRule -SynchronizationRule $clone -ErrorAction Stop | Out-Null
            $createdRule = Get-ADSyncRule | Where-Object Identifier -eq $clone.Identifier | Select-Object -First 1
            if (-not $createdRule) {
                throw "Clone '$($clone.Identifier)' was not found after creation."
            }
            $differences = @(Test-ADSyncRuleOrderClone -SourceRule $sourceRule -CloneRule $createdRule)
            if ($differences.Count -gt 0) {
                throw "Clone verification failed: $($differences -join ', ')."
            }
            $sourceRule.Disabled = $true
            Add-ADSyncRule -SynchronizationRule $sourceRule -ErrorAction Stop | Out-Null
            $disabledOriginal = Get-ADSyncRule |
                Where-Object Identifier -eq $sourceRule.Identifier |
                Select-Object -First 1
            if (-not $disabledOriginal -or -not [bool]$disabledOriginal.Disabled) {
                throw "Microsoft standard rule '$($sourceRule.Identifier)' was not disabled after clone verification."
            }
        }
        else {
            $mutationMayHaveStarted = $true
            Remove-ADSyncRule -Identifier $sourceRule.Identifier -ErrorAction Stop | Out-Null
            $removedSource = Get-ADSyncRule |
                Where-Object Identifier -eq $sourceRule.Identifier |
                Select-Object -First 1
            if ($removedSource) {
                throw "Custom rule '$($sourceRule.Identifier)' still exists after removal."
            }
            Add-ADSyncRule -SynchronizationRule $clone -ErrorAction Stop | Out-Null
            $createdRule = Get-ADSyncRule | Where-Object Identifier -eq $clone.Identifier | Select-Object -First 1
            if (-not $createdRule) {
                throw "Replacement '$($clone.Identifier)' was not found after creation."
            }
            $differences = @(Test-ADSyncRuleOrderClone -SourceRule $sourceRule -CloneRule $createdRule)
            if ($differences.Count -gt 0) {
                throw "Replacement verification failed: $($differences -join ', ')."
            }
        }

        $liveRules = @(Get-ADSyncRule | Sort-Object Precedence, Identifier)
        $liveIdentifiers = @($liveRules | ForEach-Object { $_.Identifier.ToString() })
        $cloneIndex = [array]::IndexOf($liveIdentifiers, $clone.Identifier.ToString())
        $anchorIndex = [array]::IndexOf($liveIdentifiers, $anchorRule.Identifier.ToString())
        $relativeOrderIsValid = if ($Placement -eq 'Before') {
            $cloneIndex + 1 -eq $anchorIndex
        }
        else {
            $cloneIndex -eq $anchorIndex + 1
        }
        if ($cloneIndex -lt 0 -or $anchorIndex -lt 0 -or -not $relativeOrderIsValid) {
            throw "Exact relative-order verification failed for '$($sourceRule.Name)'."
        }

        return $operation
    }
    catch {
        $moveError = $_
        if (-not $mutationMayHaveStarted) {
            throw
        }
        try {
            Undo-ADSyncRuleOrderLiveMove -Operation $operation
        }
        catch {
            throw "Rule move failed: $($moveError.Exception.Message) Local rollback also failed: $($_.Exception.Message)"
        }
        throw "Rule move failed and was rolled back: $($moveError.Exception.Message)"
    }
}

function Undo-ADSyncRuleOrderLiveMove {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Operation
    )

    $replacement = Get-ADSyncRule |
        Where-Object Identifier -eq ([guid]$Operation.ReplacementId) |
        Select-Object -First 1
    if ($replacement) {
        Remove-ADSyncRule -Identifier ([guid]$Operation.ReplacementId) -ErrorAction Stop | Out-Null
        $replacementStillExists = Get-ADSyncRule |
            Where-Object Identifier -eq ([guid]$Operation.ReplacementId) |
            Select-Object -First 1
        if ($replacementStillExists) {
            throw "Replacement '$($Operation.ReplacementId)' still exists after rollback removal."
        }
    }
    if ($Operation.SourceWasStandard) {
        $original = Get-ADSyncRule | Where-Object Identifier -eq ([guid]$Operation.OriginalId) | Select-Object -First 1
        if (-not $original) {
            $original = $Operation.SourceRule
        }
        $original.Disabled = [bool]$Operation.OriginalDisabled
        Add-ADSyncRule -SynchronizationRule $original -ErrorAction Stop | Out-Null
    }
    else {
        $original = Get-ADSyncRule | Where-Object Identifier -eq ([guid]$Operation.OriginalId) | Select-Object -First 1
        if (-not $original) {
            Add-ADSyncRule -SynchronizationRule $Operation.SourceRule -ErrorAction Stop | Out-Null
        }
    }
    $restoredOriginal = Get-ADSyncRule |
        Where-Object Identifier -eq ([guid]$Operation.OriginalId) |
        Select-Object -First 1
    if (-not $restoredOriginal -or
        [bool]$restoredOriginal.Disabled -ne [bool]$Operation.OriginalDisabled) {
        throw "Original rule '$($Operation.OriginalId)' was not restored to its previous state."
    }
}

function Invoke-ADSyncRuleOrderMovePlan {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [object[]]$MovePlan,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ExpectedFingerprint,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$BackupRoot,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ConfirmationToken,

        [switch]$AllowActiveServer,

        [scriptblock]$ProgressCallback
    )

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 0 'Validating the Apply request...'
    Assert-ADSyncRuleOrderAvailable
    if ($MovePlan.Count -eq 0) {
        throw 'The move plan is empty.'
    }
    $scheduler = Get-ADSyncScheduler
    $expectedToken = if ($scheduler.StagingModeEnabled) {
        "APPLY $($env:COMPUTERNAME)"
    }
    else {
        "APPLY ACTIVE $($env:COMPUTERNAME)"
    }
    if ($ConfirmationToken -cne $expectedToken) {
        throw "Invalid confirmation token. Expected '$expectedToken'."
    }

    if ($scheduler.SyncCycleInProgress) {
        throw 'An ADSync cycle is currently running. Wait for it to finish before applying the plan.'
    }
    if (-not $scheduler.StagingModeEnabled -and -not $AllowActiveServer) {
        throw 'Apply is blocked because this is not a staging server.'
    }
    $currentFingerprint = Get-ADSyncRuleOrderFingerprint
    if ($currentFingerprint -cne $ExpectedFingerprint) {
        throw 'The live ADSync rule set changed after it was loaded. Refresh the editor and review the new order.'
    }

    Invoke-ADSyncRuleOrderProgress $ProgressCallback 5 'Creating the pre-Apply safety snapshot...'
    $backup = New-ADSyncRuleOrderBackup `
        -BackupRoot $BackupRoot `
        -Label 'PreApply' `
        -ProgressCallback $ProgressCallback `
        -ProgressStart 5 `
        -ProgressEnd 30
    $schedulerWasEnabled = [bool]$scheduler.SyncCycleEnabled
    $operations = [System.Collections.Generic.List[object]]::new()
    $identifierMap = @{}

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply $($MovePlan.Count) relative ADSync rule move(s)")) {
        return [pscustomobject]@{
            Backup               = $backup
            Operations           = @()
            Applied              = $false
            SchedulerRestored    = $true
            SchedulerRestoreError = $null
        }
    }

    $applyResult = $null
    $applyFailureMessage = $null
    $schedulerRestoreError = $null
    try {
        Invoke-ADSyncRuleOrderProgress $ProgressCallback 32 'Pausing and verifying the scheduler...'
        if ($schedulerWasEnabled) {
            Set-ADSyncScheduler -SyncCycleEnabled $false -ErrorAction Stop | Out-Null
        }
        $applyScheduler = Get-ADSyncScheduler
        if ($applyScheduler.SyncCycleEnabled -or $applyScheduler.SyncCycleInProgress) {
            throw 'The ADSync scheduler is not safely paused immediately before Apply.'
        }
        $preMutationFingerprint = Get-ADSyncRuleOrderFingerprint
        if ($preMutationFingerprint -cne $ExpectedFingerprint) {
            throw 'The live ADSync rule set changed during backup or safety checks. Apply was cancelled.'
        }

        Invoke-ADSyncRuleOrderProgress $ProgressCallback 38 'Preparing final-order verification...'
        $expectedLogicalOrder = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in @(Get-ADSyncRule | Sort-Object Precedence, Identifier)) {
            $expectedLogicalOrder.Add($rule.Identifier.ToString())
        }
        foreach ($move in $MovePlan) {
            $sourceIndex = $expectedLogicalOrder.IndexOf([string]$move.Identifier)
            if ($sourceIndex -lt 0) {
                throw "Rule '$($move.Identifier)' is unavailable while preparing final-order verification."
            }
            $expectedLogicalOrder.RemoveAt($sourceIndex)
            $anchorIndex = $expectedLogicalOrder.IndexOf([string]$move.AnchorIdentifier)
            if ($anchorIndex -lt 0) {
                throw "Anchor rule '$($move.AnchorIdentifier)' is unavailable while preparing final-order verification."
            }
            $targetIndex = if ($move.Placement -eq 'Before') { $anchorIndex } else { $anchorIndex + 1 }
            $expectedLogicalOrder.Insert($targetIndex, [string]$move.Identifier)
        }

        for ($moveIndex = 0; $moveIndex -lt $MovePlan.Count; $moveIndex++) {
            $move = $MovePlan[$moveIndex]
            $movePercent = 42 + [int][Math]::Round((43 * $moveIndex) / $MovePlan.Count)
            Invoke-ADSyncRuleOrderProgress `
                $ProgressCallback `
                $movePercent `
                "Applying move $($moveIndex + 1) of $($MovePlan.Count): $($move.RuleName)"
            $sourceIdentifier = if ($identifierMap.ContainsKey([string]$move.Identifier)) {
                $identifierMap[[string]$move.Identifier]
            }
            else {
                [string]$move.Identifier
            }
            $anchorIdentifier = if ($identifierMap.ContainsKey([string]$move.AnchorIdentifier)) {
                $identifierMap[[string]$move.AnchorIdentifier]
            }
            else {
                [string]$move.AnchorIdentifier
            }

            $operation = Move-ADSyncRuleOrderLiveRuleRelative `
                -Identifier ([guid]$sourceIdentifier) `
                -AnchorIdentifier ([guid]$anchorIdentifier) `
                -Placement $move.Placement
            $operations.Add($operation)
            $identifierMap[[string]$move.Identifier] = $operation.ReplacementId
        }

        Invoke-ADSyncRuleOrderProgress $ProgressCallback 87 'Verifying the complete live rule order...'
        $replacementToOriginal = @{}
        $retainedStandardOriginals = @{}
        foreach ($operation in $operations) {
            $replacementToOriginal[[string]$operation.ReplacementId] = [string]$operation.OriginalId
            if ($operation.SourceWasStandard) {
                $retainedStandardOriginals[[string]$operation.OriginalId] = $true
            }
        }
        $actualLogicalOrder = [System.Collections.Generic.List[string]]::new()
        foreach ($rule in @(Get-ADSyncRule | Sort-Object Precedence, Identifier)) {
            $liveIdentifier = $rule.Identifier.ToString()
            if ($retainedStandardOriginals.ContainsKey($liveIdentifier)) {
                continue
            }
            if ($replacementToOriginal.ContainsKey($liveIdentifier)) {
                $actualLogicalOrder.Add($replacementToOriginal[$liveIdentifier])
            }
            else {
                $actualLogicalOrder.Add($liveIdentifier)
            }
        }
        if ($actualLogicalOrder.Count -ne $expectedLogicalOrder.Count) {
            throw "Final logical rule count verification failed. Expected $($expectedLogicalOrder.Count); found $($actualLogicalOrder.Count)."
        }
        for ($index = 0; $index -lt $expectedLogicalOrder.Count; $index++) {
            if ($actualLogicalOrder[$index] -cne $expectedLogicalOrder[$index]) {
                throw "Final logical rule order verification failed at position $($index + 1)."
            }
        }

        Invoke-ADSyncRuleOrderProgress $ProgressCallback 92 'Calculating the final rule fingerprint...'
        $applyResult = [pscustomobject]@{
            Backup           = $backup
            Operations       = @($operations)
            Applied          = $true
            FinalFingerprint = Get-ADSyncRuleOrderFingerprint
        }
    }
    catch {
        $applyError = $_
        $rollbackErrors = @()
        Invoke-ADSyncRuleOrderProgress $ProgressCallback 88 'Apply failed. Rolling back completed operations...'
        for ($index = $operations.Count - 1; $index -ge 0; $index--) {
            $rollbackNumber = $operations.Count - $index
            Invoke-ADSyncRuleOrderProgress `
                $ProgressCallback `
                (88 + [int][Math]::Round((7 * $rollbackNumber) / [Math]::Max(1, $operations.Count))) `
                "Rolling back operation $rollbackNumber of $($operations.Count): $($operations[$index].RuleName)"
            try {
                Undo-ADSyncRuleOrderLiveMove -Operation $operations[$index]
            }
            catch {
                $rollbackErrors += "Operation $($index + 1) '$($operations[$index].RuleName)': $($_.Exception.Message)"
            }
        }
        try {
            $rollbackFingerprint = Get-ADSyncRuleOrderFingerprint
            if ($rollbackFingerprint -cne $ExpectedFingerprint) {
                $rollbackErrors += 'The live rule fingerprint does not match the pre-Apply state after rollback.'
            }
        }
        catch {
            $rollbackErrors += "Post-rollback fingerprint verification failed: $($_.Exception.Message)"
        }
        if ($rollbackErrors.Count -gt 0) {
            $applyFailureMessage = "Apply failed: $($applyError.Exception.Message) Rollback also failed: $($rollbackErrors -join ' | ') Backup: $($backup.Path)"
        }
        else {
            $applyFailureMessage = "Apply failed and was rolled back: $($applyError.Exception.Message) Backup: $($backup.Path)"
        }
    }
    finally {
        if ($schedulerWasEnabled) {
            Invoke-ADSyncRuleOrderProgress $ProgressCallback 96 'Restoring the scheduler state...'
            try {
                Set-ADSyncScheduler -SyncCycleEnabled $true -ErrorAction Stop | Out-Null
                $restoredScheduler = Get-ADSyncScheduler
                if (-not [bool]$restoredScheduler.SyncCycleEnabled) {
                    throw 'The scheduler still reports SyncCycleEnabled=False.'
                }
            }
            catch {
                $schedulerRestoreError = $_.Exception.Message
            }
        }
    }

    if ($null -ne $applyFailureMessage) {
        if ($null -ne $schedulerRestoreError) {
            $applyFailureMessage += " Scheduler restoration also failed: $schedulerRestoreError"
        }
        throw $applyFailureMessage
    }
    $applyResult | Add-Member -MemberType NoteProperty -Name SchedulerRestored `
        -Value ($null -eq $schedulerRestoreError)
    $applyResult | Add-Member -MemberType NoteProperty -Name SchedulerRestoreError `
        -Value $schedulerRestoreError
    $completionActivity = if ($null -eq $schedulerRestoreError) {
        'Apply complete. Scheduler state restored.'
    }
    else {
        'Apply complete. Scheduler restoration requires attention.'
    }
    Invoke-ADSyncRuleOrderProgress $ProgressCallback 100 $completionActivity
    return $applyResult
}

Export-ModuleMember -Function @(
    'Move-ADSyncRuleOrderItem',
    'Assert-ADSyncRuleOrderAvailable',
    'Get-ADSyncRuleOrderSnapshot',
    'Get-ADSyncRuleOrderFingerprint',
    'New-ADSyncRuleOrderBackup',
    'Get-ADSyncRuleOrderBackupSequence',
    'Get-ADSyncRuleOrderMovePlan',
    'Invoke-ADSyncRuleOrderMovePlan'
)
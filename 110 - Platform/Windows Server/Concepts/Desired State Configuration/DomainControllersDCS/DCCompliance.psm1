#Requires -Version 5.1

Set-StrictMode -Version Latest

function Assert-DCObject {
    param($Value, [string[]]$Required, [string]$Label)
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        throw "$Label must be a JSON object."
    }
    $names = @($Value.PSObject.Properties.Name)
    foreach ($name in $Required) {
        if ($names -notcontains $name -or $null -eq $Value.$name) {
            throw "$Label is missing '$name'."
        }
    }
}

function Assert-DCDnsName {
    param($Value, [string]$Label)
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value) -or
        $Value -ne $Value.Trim() -or $Value.EndsWith('.') -or -not $Value.Contains('.') -or
        [Uri]::CheckHostName($Value) -ne [UriHostNameType]::Dns) {
        throw "$Label must be an exact DNS name, without wildcards or a trailing dot."
    }
}

function Assert-DCControl {
    param($Control)
    Assert-DCObject $Control @('Id', 'Name', 'Owner', 'Mode', 'ResourceType', 'Properties') 'Control'
    if ($Control.Id -isnot [string] -or $Control.Id -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$') {
        throw 'Control IDs must contain 1-64 letters, digits, underscores, or hyphens.'
    }
    if ($Control.Name -isnot [string] -or [string]::IsNullOrWhiteSpace($Control.Name)) {
        throw "Control '$($Control.Id)' needs a name."
    }
    if ($Control.Mode -cnotin @('Audit', 'Enforce') -or $Control.Owner -cnotin @('DSC', 'GPO', 'External', 'Unknown')) {
        throw "Invalid Mode or Owner on '$($Control.Id)'."
    }
    if ($Control.Mode -eq 'Enforce' -and $Control.Owner -ne 'DSC') {
        throw "Only DSC-owned controls may use Enforce: '$($Control.Id)'."
    }
    $properties = $Control.Properties
    $required = @()
    switch -CaseSensitive ($Control.ResourceType) {
        'Blog.DC/Spooler' {
            $required = @('Name', 'State', 'StartupType')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.Name -cne 'Spooler' -or
                $properties.State -cnotin @('Running', 'Stopped') -or
                $properties.StartupType -cnotin @('Automatic', 'Manual', 'Disabled') -or
                ($properties.State -ceq 'Running' -and $properties.StartupType -ceq 'Disabled')) {
                throw "Invalid Spooler properties on '$($Control.Id)'."
            }
        }
        'Blog.DC/SmbServer' {
            Assert-DCObject $properties @('Name') $Control.Id
            $switchNames = @($properties.PSObject.Properties.Name | Where-Object { $_ -ne 'Name' })
            if ($properties.Name -cne 'Server' -or $switchNames.Count -ne 1 -or
                $switchNames[0] -cnotin @('EnableSMB1Protocol', 'RequireSecuritySignature')) {
                throw "Each SMB control must test one supported Boolean property: '$($Control.Id)'."
            }
            $required = @('Name', $switchNames[0])
            if ($properties.($switchNames[0]) -isnot [bool]) { throw "SMB values must be Booleans: '$($Control.Id)'." }
        }
        'Blog.DC/AuditPolicy' {
            $required = @('Name', 'AuditSuccess', 'AuditFailure')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.Name -cnotin @('Logon', 'User Account Management', 'Directory Service Changes') -or
                $properties.AuditSuccess -isnot [bool] -or $properties.AuditFailure -isnot [bool]) {
                throw "Unsupported audit policy properties on '$($Control.Id)'."
            }
        }
        'Blog.DC/EventLog' {
            $required = @('LogName', 'MaximumSizeInBytes', 'LogMode')
            Assert-DCObject $properties $required $Control.Id
            $size = $properties.MaximumSizeInBytes
            if ($properties.LogName -cnotin @('Security', 'System', 'Directory Service') -or
                $properties.LogMode -cnotin @('Circular', 'AutoBackup', 'Retain') -or
                ($size -isnot [int] -and $size -isnot [long]) -or $size -lt 65536 -or $size % 65536 -ne 0) {
                throw "Invalid log properties on '$($Control.Id)'; size must be a positive multiple of 64 KiB."
            }
        }
        'Blog.DC/LdapPolicy' {
            $required = @('ValueName', 'Exists', 'ValueType', 'ValueData')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.ValueName -cnotin @('LDAPServerIntegrity', 'LdapEnforceChannelBinding') -or
                $properties.ValueType -cne 'DWord' -or $properties.Exists -isnot [bool] -or -not $properties.Exists -or
                ($properties.ValueData -isnot [int] -and $properties.ValueData -isnot [long]) -or $properties.ValueData -notin @(0, 1, 2)) {
                throw "Unsupported explicit LDAP registry policy on '$($Control.Id)'."
            }
        }
        default { throw "Unsupported resource type: '$($Control.ResourceType)'." }
    }
    $unknown = @($properties.PSObject.Properties.Name | Where-Object { $required -cnotcontains $_ })
    if ($unknown.Count -gt 0) { throw "Unknown properties on '$($Control.Id)': $($unknown -join ', ')." }
    if ($Control.Mode -eq 'Enforce' -and $Control.ResourceType -cnotin @('Blog.DC/Spooler', 'Blog.DC/EventLog')) {
        throw "This implementation only enforces Spooler and event-log controls: '$($Control.Id)'."
    }
}

function Read-DCComplianceInput {
    [CmdletBinding()]
    param([string]$InventoryPath, [string]$SettingsPath)
    $inventoryText = Get-Content -LiteralPath $InventoryPath -Raw -Encoding UTF8 -ErrorAction Stop
    $settingsText = Get-Content -LiteralPath $SettingsPath -Raw -Encoding UTF8 -ErrorAction Stop
    $inventory = $inventoryText | ConvertFrom-Json -ErrorAction Stop
    $settings = $settingsText | ConvertFrom-Json -ErrorAction Stop
    Assert-DCObject $inventory @('Domain', 'DiscoveredAtUtc', 'SourceComputer', 'DomainControllers') 'Inventory'
    Assert-DCObject $settings @('SchemaVersion') 'Settings'
    if ($settings.SchemaVersion -ne 2) { throw 'Native DSC v3 requires settings SchemaVersion 2. Migrate the controls and resource package; legacy adapter settings are not accepted.' }
    Assert-DCObject $settings @('BaselineVersion', 'MaximumInventoryAgeHours', 'DscExecutable', 'DscVersion', 'ResourceDirectory', 'ResourceVersion', 'ExcludedDCs', 'Controls') 'Settings'
    if ($settings.BaselineVersion -isnot [string] -or [string]::IsNullOrWhiteSpace($settings.BaselineVersion)) {
        throw 'BaselineVersion must be a non-empty string.'
    }
    $maximumAge = $settings.MaximumInventoryAgeHours
    if (($maximumAge -isnot [int] -and $maximumAge -isnot [long]) -or $maximumAge -lt 1 -or $maximumAge -gt 8760) {
        throw 'MaximumInventoryAgeHours must be an integer from 1 to 8760.'
    }
    if ($settings.DscExecutable -isnot [string] -or $settings.DscExecutable -notmatch '^[A-Za-z]:\\[^"\r\n]+\\dsc\.exe$') {
        throw 'DscExecutable must be an absolute local path to dsc.exe on the DCs.'
    }
    if ($settings.DscVersion -isnot [string] -or $settings.DscVersion -notmatch '^3\.[2-9][0-9]*\.[0-9]+$') {
        throw 'This runner requires a stable DSC version 3.2 or later in the 3.x series.'
    }
    if ($settings.PSObject.Properties['ModuleVersions']) { throw 'ModuleVersions belongs to the old adapter-based implementation. Use ResourceVersion and ResourceDirectory.' }
    if ($settings.ResourceVersion -isnot [string] -or $settings.ResourceVersion -cnotmatch '^\d+\.\d+\.\d+$') {
        throw 'ResourceVersion must be a stable semantic version.'
    }
    if ($settings.ResourceDirectory -isnot [string] -or
        $settings.ResourceDirectory -cne ('C:\Tools\DSC\Resources\DCCompliance\' + $settings.ResourceVersion)) {
        throw 'ResourceDirectory must be C:\Tools\DSC\Resources\DCCompliance\<ResourceVersion>.'
    }
    Assert-DCDnsName $inventory.Domain 'Inventory Domain'
    if ($inventory.DiscoveredAtUtc -is [string] -and $inventory.DiscoveredAtUtc -notmatch '(Z|[+-]\d\d:\d\d)$') {
        throw 'The discovery timestamp must include its UTC offset.'
    }
    try { $discoveredAt = [datetimeoffset]$inventory.DiscoveredAtUtc }
    catch { throw 'The inventory discovery timestamp is invalid.' }
    $age = [datetimeoffset]::UtcNow - $discoveredAt.ToUniversalTime()
    if ($age.TotalHours -gt $maximumAge -or $age.TotalMinutes -lt -5) {
        throw "Inventory is older than $maximumAge hours or dated in the future. Run discovery again."
    }
    if ($inventory.DomainControllers -isnot [array] -or $inventory.DomainControllers.Count -eq 0) {
        throw 'Inventory must contain a non-empty DomainControllers array.'
    }
    foreach ($target in $inventory.DomainControllers) {
        Assert-DCObject $target @('HostName', 'Domain', 'Site', 'OperatingSystem', 'IsReadOnly') 'DC entry'
        Assert-DCDnsName $target.HostName 'DC HostName'
        if ($target.Domain -ine $inventory.Domain -or $target.IsReadOnly -isnot [bool]) {
            throw "Inconsistent domain or DC type on '$($target.HostName)'."
        }
    }
    if (@($inventory.DomainControllers | Group-Object HostName | Where-Object Count -gt 1).Count -gt 0) {
        throw 'The inventory contains duplicate DC hostnames.'
    }
    if ($settings.ExcludedDCs -isnot [array]) { throw 'ExcludedDCs must be a JSON array.' }
    foreach ($excludedHost in $settings.ExcludedDCs) {
        Assert-DCDnsName $excludedHost 'ExcludedDCs entry'
        if ($inventory.DomainControllers.HostName -notcontains $excludedHost) {
            throw "Excluded DC '$excludedHost' was not found in the inventory."
        }
    }
    if ($settings.Controls -isnot [array] -or $settings.Controls.Count -eq 0) {
        throw 'Settings must contain a non-empty Controls array.'
    }
    foreach ($control in $settings.Controls) { Assert-DCControl $control }
    if (@($settings.Controls | Group-Object Id | Where-Object Count -gt 1).Count -gt 0) {
        throw 'Control IDs must be unique.'
    }
    [pscustomobject]@{
        Inventory = $inventory
        Settings = $settings
        InventoryText = $inventoryText
        SettingsText = $settingsText
        InventorySha256 = (Get-FileHash -LiteralPath $InventoryPath -Algorithm SHA256 -ErrorAction Stop).Hash
        SettingsSha256 = (Get-FileHash -LiteralPath $SettingsPath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
}

function New-DCConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Control)
    Assert-DCControl $Control
    $document = [ordered]@{
        '$schema' = 'https://aka.ms/dsc/schemas/v3/bundled/config/document.json'
        resources = @(
            [ordered]@{
                name = $Control.Id
                type = $Control.ResourceType
                properties = $Control.Properties
            }
        )
    }
    ConvertTo-Json -InputObject $document -Depth 12
}

function Get-DCResourcePackage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ResourceVersion,
        [string]$Path = (Join-Path $PSScriptRoot 'Resources')
    )
    $resourceNames = @('Spooler', 'SmbServer', 'AuditPolicy', 'EventLog', 'LdapPolicy')
    foreach ($name in $resourceNames) {
        $manifest = Get-Content -LiteralPath (Join-Path $Path "$name.dsc.resource.json") -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
        if ($manifest.type -cne "Blog.DC/$name" -or $manifest.version -cne $ResourceVersion -or $manifest.kind -cne 'resource' -or
            $manifest.PSObject.Properties['adapter'] -or $manifest.PSObject.Properties['requireAdapter']) {
            throw "Invalid native resource manifest/version for '$name'."
        }
    }
    $fileNames = @($resourceNames | ForEach-Object { "$_.dsc.resource.json" }) + @('Invoke-NativeResource.ps1', 'NativeResources.psm1', 'NativeAudit.cs')
    $files = @(
        foreach ($name in $fileNames) {
            [pscustomobject]@{ Name = $name; Sha256 = (Get-FileHash -LiteralPath (Join-Path $Path $name) -Algorithm SHA256 -ErrorAction Stop).Hash }
        }
    )
    [pscustomobject]@{ Version = $ResourceVersion; Directory = $Path; Files = $files }
}

function Get-DCTestState {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Response, [Parameter(Mandatory)]$Control)
    if ($Response.ExitCode -ne 0) { throw "DSC exit code $($Response.ExitCode). $($Response.StdErr)" }
    $output = $Response.StdOut | ConvertFrom-Json -ErrorAction Stop
    Assert-DCObject $output @('hadErrors', 'results') 'DSC test output'
    if ($output.hadErrors -isnot [bool] -or $output.hadErrors) {
        throw 'DSC reported an operation or resource error. See raw evidence.'
    }
    if ($output.results -isnot [array] -or $output.results.Count -ne 1) {
        throw 'Expected exactly one DSC resource result.'
    }
    $entry = $output.results[0]
    Assert-DCObject $entry @('name', 'type', 'result') 'DSC resource result'
    if ($entry.name -cne $Control.Id -or $entry.type -cne $Control.ResourceType) {
        throw 'The DSC result does not match the requested resource instance.'
    }
    $state = $entry.result
    Assert-DCObject $state @('inDesiredState', 'actualState', 'desiredState', 'differingProperties') 'DSC test state'
    if ($state.inDesiredState -isnot [bool] -or $state.differingProperties -isnot [array]) {
        throw 'DSC returned an invalid compliance Boolean or difference list.'
    }
    Assert-DCObject $state.actualState @() 'DSC actual state'
    $actual = [ordered]@{}
    foreach ($property in $Control.Properties.PSObject.Properties) {
        if ($null -ne $state.actualState.PSObject.Properties[$property.Name]) {
            $actual[$property.Name] = $state.actualState.($property.Name)
        }
        else { $actual[$property.Name] = '<not returned>' }
    }
    [pscustomobject]@{
        InDesiredState = $state.inDesiredState
        ActualState = [pscustomobject]$actual
        DifferingProperties = @($state.differingProperties)
    }
}

function Write-DCComplianceReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$RunDirectory)
    $null = New-Item -Path $RunDirectory -ItemType Directory -Force -WhatIf:$false -Confirm:$false -ErrorAction Stop
    $counts = @{
        Compliant = @($Report.Results | Where-Object Status -eq 'Compliant').Count
        NonCompliant = @($Report.Results | Where-Object Status -eq 'NonCompliant').Count
        Errors = @($Report.Results | Where-Object { $_.Status -in @('Error', 'Unreachable') }).Count
        NotEvaluated = @($Report.Results | Where-Object Status -eq 'NotEvaluated').Count
    }
    $overall = if ($counts.Errors -gt 0) { 'Incomplete' }
        elseif ($counts.NonCompliant -gt 0) { 'NonCompliant' }
        elseif ($counts.NotEvaluated -gt 0 -or $Report.Results.Count -eq 0) { 'NotEvaluated' }
        else { 'Compliant' }
    $Report | Add-Member -NotePropertyName OverallStatus -NotePropertyValue $overall -Force
    $jsonPath = Join-Path $RunDirectory 'report.json'
    $csvPath = Join-Path $RunDirectory 'report.csv'
    $htmlPath = Join-Path $RunDirectory 'report.html'
    [System.IO.File]::WriteAllText($jsonPath, (ConvertTo-Json -InputObject $Report -Depth 40), [System.Text.UTF8Encoding]::new($false))
    $csvRows = @(
        foreach ($result in $Report.Results) {
            $row = [ordered]@{
                HostName = $result.HostName
                ControlId = $result.ControlId
                ControlName = $result.ControlName
                Owner = $result.Owner
                Mode = $result.Mode
                Status = $result.Status
                Action = $result.Action
                EvaluatedAtUtc = $result.EvaluatedAtUtc
                DesiredState = ConvertTo-Json -InputObject $result.DesiredState -Depth 10 -Compress
                ActualState = ConvertTo-Json -InputObject $result.ActualState -Depth 10 -Compress
                DifferingProperties = $result.DifferingProperties -join ', '
                Message = $result.Message
            }
            foreach ($name in @($row.Keys)) {
                $text = [string]$row[$name]
                if ($text -match '^\s*[=+@-]' -or $text -match '^[\t\r\n]') { $text = "'" + $text }
                $row[$name] = $text
            }
            [pscustomobject]$row
        }
    )
    $csvRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false -Confirm:$false -ErrorAction Stop
    function ConvertTo-DCHtml { param($Value) [System.Net.WebUtility]::HtmlEncode([string]$Value) }
    function Get-DCHtmlStatus {
        param([string]$Status)
        switch ($Status) {
            'Compliant' { @{ Class = 'pass'; Label = 'Compliant'; Short = 'Pass'; Rank = 4 } }
            'NonCompliant' { @{ Class = 'fail'; Label = 'Noncompliant'; Short = 'Drift'; Rank = 2 } }
            'Error' { @{ Class = 'error'; Label = 'Error'; Short = 'Error'; Rank = 0 } }
            'Unreachable' { @{ Class = 'error'; Label = 'Unreachable'; Short = 'Offline'; Rank = 1 } }
            'Incomplete' { @{ Class = 'error'; Label = 'Incomplete'; Short = 'Incomplete'; Rank = 0 } }
            'Excluded' { @{ Class = 'neutral'; Label = 'Excluded'; Short = 'Excluded'; Rank = 6 } }
            'NotSelected' { @{ Class = 'neutral'; Label = 'Not selected'; Short = 'Not selected'; Rank = 6 } }
            'NotApplicable' { @{ Class = 'neutral'; Label = 'Not applicable'; Short = 'N/A'; Rank = 5 } }
            default { @{ Class = 'pending'; Label = 'Not evaluated'; Short = 'Pending'; Rank = 3 } }
        }
    }
    function ConvertTo-DCValueHtml {
        param($Value)
        if ($null -eq $Value) { return '<span class="muted">Not returned</span>' }
        $valueText = if ($Value -is [string]) { $Value } else { ConvertTo-Json -InputObject $Value -Depth 10 -Compress }
        ConvertTo-DCHtml $valueText
    }
    $controlIndex = [ordered]@{}
    $resultIndex = @{}
    $resultEntries = @(
        foreach ($result in $Report.Results) {
            if (-not $controlIndex.Contains($result.ControlId)) { $controlIndex[$result.ControlId] = $result }
            $entry = [pscustomobject]@{
                Result = $result
                Anchor = 'result-' + $resultIndex.Count
                StatusInfo = Get-DCHtmlStatus $result.Status
            }
            $resultIndex['{0}|{1}' -f $result.HostName, $result.ControlId] = $entry
            $entry
        }
    )
    $matrixHeaders = foreach ($control in $controlIndex.Values) {
        $parts = $control.ControlId -split '-', 3
        $prefix = if ($parts.Count -eq 3) { $parts[0..1] -join '-' } else { $control.ControlId }
        $label = if ($parts.Count -eq 3) { $parts[2] } else { $control.ControlName }
        $label = [regex]::Replace($label, '([a-z])([A-Z])', '$1 $2')
        '<th scope="col" title="{0}"><span class="control-prefix">{1}</span><span class="control-name">{2}</span><span class="control-owner">{3}</span></th>' -f
            (ConvertTo-DCHtml ('{0}: {1} | Owner: {2} | Mode: {3}' -f $control.ControlId, $control.ControlName, $control.Owner, $control.Mode)),
            (ConvertTo-DCHtml $prefix), (ConvertTo-DCHtml $label), (ConvertTo-DCHtml $control.Owner)
    }
    $matrixRows = foreach ($target in $Report.Targets) {
        $scopeLabel = if ($target.Scope -eq 'NotSelected') { 'Not selected' } else { $target.Scope }
        $cells = foreach ($control in $controlIndex.Values) {
            $entry = $resultIndex['{0}|{1}' -f $target.HostName, $control.ControlId]
            if ($target.Scope -ne 'Included') {
                $status = Get-DCHtmlStatus $target.Scope
                '<td class="matrix-status neutral" data-status="{0}"><span title="{1}">{2}</span></td>' -f
                    (ConvertTo-DCHtml $target.Scope), (ConvertTo-DCHtml $target.Reason), (ConvertTo-DCHtml $status.Short)
            }
            elseif ($null -ne $entry) {
                '<td class="matrix-status {0}" data-status="{1}"><a href="#{2}" data-result-id="{2}" title="{3}" aria-label="{3}">{4}</a></td>' -f
                    $entry.StatusInfo.Class, (ConvertTo-DCHtml $entry.Result.Status), $entry.Anchor,
                    (ConvertTo-DCHtml ('{0} | {1} | {2}' -f $target.HostName, $control.ControlId, $entry.StatusInfo.Label)),
                    (ConvertTo-DCHtml $entry.StatusInfo.Short)
            }
            else {
                '<td class="matrix-status pending" data-status="NotEvaluated"><span title="No result was returned for this DC and control">Pending</span></td>'
            }
        }
        if ($controlIndex.Count -eq 0) { $cells = @('<td class="matrix-status pending">No control results</td>') }
        '<tr data-host="{0}"><th scope="row" class="dc-column"><span class="dc-name">{0}</span><span class="scope-label">{1}</span><span class="scope-reason">{2}</span></th>{3}</tr>' -f
            (ConvertTo-DCHtml $target.HostName), (ConvertTo-DCHtml $scopeLabel), (ConvertTo-DCHtml $target.Reason), ($cells -join '')
    }
    if ($controlIndex.Count -eq 0) { $matrixHeaders = @('<th scope="col">Results</th>') }
    $targetOptions = foreach ($target in $Report.Targets) {
        '<option value="{0}">{0}</option>' -f (ConvertTo-DCHtml $target.HostName)
    }
    $resultRows = foreach ($entry in ($resultEntries | Sort-Object { $_.StatusInfo.Rank }, { $_.Result.HostName }, { $_.Result.ControlId })) {
        $result = $entry.Result
        $propertyNames = [System.Collections.Generic.List[string]]::new()
        foreach ($state in @($result.DesiredState, $result.ActualState)) {
            if ($null -eq $state) { continue }
            $names = if ($state -is [System.Collections.IDictionary]) { @($state.Keys) } else { @($state.PSObject.Properties.Name) }
            foreach ($name in $names) {
                if (-not $propertyNames.Contains([string]$name)) { $propertyNames.Add([string]$name) }
            }
        }
        $propertyRows = foreach ($propertyName in $propertyNames) {
            $values = @(
                foreach ($state in @($result.DesiredState, $result.ActualState)) {
                    $value = $null
                    if ($state -is [System.Collections.IDictionary]) { $value = $state[$propertyName] }
                    elseif ($null -ne $state -and $null -ne $state.PSObject.Properties[$propertyName]) { $value = $state.$propertyName }
                    ConvertTo-DCValueHtml $value
                }
            )
            $differenceClass = if ($result.DifferingProperties -contains $propertyName) { ' class="different"' } else { '' }
            '<tr{0}><th scope="row">{1}</th><td>{2}</td><td>{3}</td></tr>' -f
                $differenceClass, (ConvertTo-DCHtml $propertyName), $values[0], $values[1]
        }
        $differenceCount = @($result.DifferingProperties | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count
        $detailLabel = if ($result.Status -in @('Error', 'Unreachable')) { 'Error details' }
            elseif ($differenceCount -eq 1) { '1 difference' }
            elseif ($differenceCount -gt 1) { "$differenceCount differences" }
            else { 'View state' }
        $message = if ([string]::IsNullOrWhiteSpace($result.Message)) { '' } else { '<p class="diagnostic">{0}</p>' -f (ConvertTo-DCHtml $result.Message) }
        $evaluationTime = if ($result.EvaluatedAtUtc) { [string]$result.EvaluatedAtUtc } else { 'Not evaluated' }
        $comparison = if ($propertyNames.Count -gt 0) {
            '<table class="comparison"><thead><tr><th scope="col">Property</th><th scope="col">Expected</th><th scope="col">Observed</th></tr></thead><tbody>{0}</tbody></table>' -f ($propertyRows -join '')
        }
        else { '<p class="muted">No state data returned.</p>' }
        $searchText = '{0} {1} {2} {3} {4} {5}' -f $result.HostName, $result.ControlId, $result.ControlName, $result.Owner, $result.Message, ($result.DifferingProperties -join ' ')
        '<tr id="{0}" data-result="true" data-host="{1}" data-status="{2}" data-search="{3}"><td class="result-host">{1}</td><th scope="row"><code>{4}</code><span class="result-name">{5}</span></th><td class="owner">{6}</td><td>{7}</td><td><span class="status {8}">{9}</span></td><td class="action">{10}</td><td><details class="state-details"><summary>{11}</summary><div class="state-content">{12}{13}<p class="evaluation-time">{14}</p></div></details></td></tr>' -f
            $entry.Anchor, (ConvertTo-DCHtml $result.HostName), (ConvertTo-DCHtml $result.Status), (ConvertTo-DCHtml $searchText),
            (ConvertTo-DCHtml $result.ControlId), (ConvertTo-DCHtml $result.ControlName), (ConvertTo-DCHtml $result.Owner), (ConvertTo-DCHtml $result.Mode),
            $entry.StatusInfo.Class, (ConvertTo-DCHtml $entry.StatusInfo.Label), (ConvertTo-DCHtml $result.Action),
            (ConvertTo-DCHtml $detailLabel), $comparison, $message, (ConvertTo-DCHtml $evaluationTime)
    }
    if ($resultEntries.Count -eq 0) {
        $resultRows = @('<tr><td colspan="7" class="empty-state">No control results were returned.</td></tr>')
    }
    $overallInfo = Get-DCHtmlStatus $overall
    $completedTime = [string]$Report.CompletedAtUtc
    try { $completedTime = ([datetimeoffset]$Report.CompletedAtUtc).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC' }
    catch { }
    $includedCount = @($Report.Targets | Where-Object Scope -eq 'Included').Count
    $totalTargets = @($Report.Targets).Count
    $matrixWidth = 248 + 96 * [Math]::Max(1, $controlIndex.Count)
    $matrixColumns = '<col class="target-track">' + ('<col>' * [Math]::Max(1, $controlIndex.Count))
    $template = @'
<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Controller Compliance</title>
<style>
:root {
    color-scheme: dark;
    --ink: #ededf0; --muted: #b4b4bd; --line: #3c3c43; --accent: #80b6ff;
    --canvas: #000; --paper: #030303; --top: #070707;
    --wash: #0f0f11; --surface: #08080a; --hover: #17171b;
    --header-start: #111114; --header-end: #080809; --header-line: #3a3a42;
    --accent-bg: #1e2b40; --accent-line: #4c6585;
    --control-line: #74747e; --scroll-thumb: #696974;
    --switch-track: #53535f; --switch-active: #185dbb; --switch-knob: #fff;
    --pass: #8eddb0; --pass-bg: #18251f; --pass-line: #456654;
    --fail: #ffadbd; --fail-bg: #2d1d26; --fail-line: #78505f;
    --error: #f3cc70; --error-bg: #26252b; --error-line: #7e724e;
    --pending: #acccfa; --pending-bg: #1e2531; --pending-line: #506583;
    --neutral-bg: #0e0e11; --neutral-line: #3a3a42;
}
:root[data-theme="light"] {
    color-scheme: light;
    --ink: #20242d; --muted: #59616e; --line: #cdd1d8; --accent: #185dbb;
    --canvas: #eef0f4; --paper: #fff; --top: #f7f8fb;
    --wash: #f1f3f6; --surface: #f8f9fb; --hover: #e9eef7;
    --header-start: #edf1f8; --header-end: #f7f9fc; --header-line: #b5bdcb;
    --accent-bg: #e7effd; --accent-line: #a7bee1;
    --control-line: #8993a3; --scroll-thumb: #929baa;
    --pass: #14633f; --pass-bg: #eaf5ee; --pass-line: #97c4a5;
    --fail: #a32344; --fail-bg: #fdecf0; --fail-line: #d49baa;
    --error: #795009; --error-bg: #faf4e5; --error-line: #c8b47e;
    --pending: #2b5387; --pending-bg: #ecf2fb; --pending-line: #a8bdd8;
    --neutral-bg: #eef0f4; --neutral-line: #bbc1cd;
}
* { box-sizing: border-box; letter-spacing: 0; }
body { margin: 0; color: var(--ink); background: var(--canvas); font: 14px/1.45 "Trebuchet MS", "Liberation Sans", sans-serif; }
main { max-width: 1720px; margin: 0 auto; padding: 28px 32px; background: linear-gradient(180deg, var(--top), var(--paper) 380px); min-height: 100vh; }
h1, h2 { font-family: "Bahnschrift", "Trebuchet MS", sans-serif; font-weight: 600; }
h1 { font-size: 28px; line-height: 1.2; margin: 0 0 10px; overflow-wrap: anywhere; }
h2 { font-size: 19px; margin: 0; }
p { margin: 8px 0; overflow-wrap: anywhere; }
a { color: var(--accent); text-underline-offset: 3px; }
a:focus-visible, summary:focus-visible, input:focus-visible, select:focus-visible, .scroll:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.report-header { padding: 18px 26px 20px; border: 1px solid var(--header-line); border-top: 3px solid var(--accent); border-radius: 8px; background: linear-gradient(115deg, var(--header-start), var(--header-end) 70%); box-shadow: inset 0 1px 0 #ffffff08; }
.header-topline { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px 20px; }
.report-label { display: inline-flex; align-items: center; flex-wrap: wrap; gap: 10px; color: var(--muted); font-size: 11px; }
.product-mark { font: 700 12px Consolas, monospace; color: var(--accent); padding-right: 10px; border-right: 1px solid var(--line); }
.header-actions { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.theme-control { display: inline-flex; align-items: center; gap: 8px; min-height: 40px; cursor: pointer; color: var(--muted); font-size: 12px; white-space: nowrap; }
.theme-control input { appearance: none; position: relative; flex: 0 0 40px; width: 40px; height: 24px; margin: 0; border: 1px solid var(--control-line); border-radius: 999px; background: var(--switch-track); cursor: pointer; }
.theme-control input::before { content: ''; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%; background: var(--switch-knob); }
.theme-control input:checked { background: var(--switch-active); border-color: var(--switch-active); }
.theme-control input:checked::before { transform: translateX(16px); }
.export { font-size: 12px; font-weight: 700; }
.header-overview { display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 16px 28px; margin: 14px 0 18px; }
.report-identity { min-width: 0; }
.title-accent { color: var(--accent); }
.domain-line { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 12px; }
.domain-line strong { font-size: 14px; overflow-wrap: anywhere; min-width: 0; }
.operation { padding: 2px 9px; border: 1px solid var(--accent-line); border-radius: 999px; color: var(--accent); background: var(--accent-bg); font-size: 11px; }
.report-verdict { display: flex; flex-direction: column; align-items: flex-end; gap: 7px; }
.verdict-label { color: var(--muted); font-size: 11px; }
.report-verdict .status { display: inline-flex; align-items: center; gap: 8px; padding: 7px 12px; font-size: 14px; }
.report-verdict .status::before { content: ''; flex: 0 0 6px; width: 6px; height: 6px; background: currentColor; border-radius: 50%; }
.run-meta { display: grid; grid-template-columns: minmax(80px, .6fr) minmax(190px, 1.2fr) minmax(220px, 1.7fr); gap: 12px 24px; margin: 0; padding-top: 14px; border-top: 1px solid var(--line); }
.run-meta > div { min-width: 0; }
.run-meta dt { color: var(--muted); font-size: 10px; }
.run-meta dd { margin: 4px 0 0; font-size: 12px; overflow-wrap: anywhere; }
.run-meta .run-id { font: 11px/1.5 Consolas, monospace; }
.summary { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; border-bottom: 1px solid var(--line); padding: 24px 0; margin-top: 4px; }
.summary div { padding-left: 16px; border-left: 3px solid var(--line); min-width: 0; }
.summary div:nth-child(1) { border-left-color: var(--accent); }
.summary div:nth-child(2) { border-left-color: var(--pass-line); }
.summary div:nth-child(3) { border-left-color: var(--fail-line); }
.summary div:nth-child(4) { border-left-color: var(--error-line); }
.summary div:nth-child(5) { border-left-color: var(--pending-line); }
.summary strong { font: 600 28px/1.2 "Bahnschrift", "Trebuchet MS", sans-serif; display: block; }
.summary span { display: block; margin-top: 4px; color: var(--muted); font-size: 12px; }
.pass { color: var(--pass); } .fail { color: var(--fail); } .error { color: var(--error); } .pending { color: var(--pending); } .neutral, .muted { color: var(--muted); }
.section-heading { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin: 28px 0 12px; }
.section-heading > span { color: var(--muted); font-size: 11px; padding: 4px 10px; background: var(--surface); border: 1px solid var(--line); border-radius: 999px; }
.scroll { width: 100%; overflow: auto; border: 1px solid var(--line); border-radius: 8px; scrollbar-color: var(--scroll-thumb) var(--paper); }
table { border-collapse: separate; border-spacing: 0; width: 100%; text-align: left; }
th, td { border-bottom: 1px solid var(--line); padding: 11px 12px; vertical-align: top; overflow-wrap: anywhere; }
thead th { background: var(--wash); font-size: 12px; color: var(--muted); font-weight: 600; }
tbody tr:last-child > th, tbody tr:last-child > td { border-bottom: 0; }
.matrix { table-layout: fixed; }
.target-track { width: 248px; }
.matrix thead th { vertical-align: bottom; text-align: center; border-right: 1px solid var(--line); padding: 12px 7px; }
.matrix thead th:first-child { text-align: left; padding-left: 14px; }
.matrix .dc-column { position: sticky; left: 0; z-index: 1; background: var(--surface); border-right: 1px solid var(--line); font-weight: 400; padding: 12px 14px; }
.matrix thead .dc-column { background: var(--wash); z-index: 2; }
.dc-name { display: block; font-size: 13px; font-weight: 700; }
.scope-label { display: inline-block; margin-top: 7px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 999px; font-size: 10px; font-weight: 400; color: var(--muted); }
.scope-reason { display: block; color: var(--muted); font-size: 11px; margin-top: 2px; }
.control-prefix { display: block; font: 11px Consolas, monospace; }
.control-name { display: block; color: var(--ink); font-size: 12px; margin: 4px 0; overflow-wrap: anywhere; }
.control-owner { display: inline-block; min-width: 36px; margin-top: 3px; padding: 1px 6px; border-radius: 999px; border: 1px solid var(--line); font-size: 10px; color: var(--muted); font-weight: 400; }
.matrix-status { padding: 0; text-align: center; vertical-align: middle; border-right: 1px solid var(--line); }
.matrix-status a, .matrix-status > span { display: flex; min-height: 72px; height: 100%; align-items: center; justify-content: center; padding: 10px 5px; font-size: 12px; font-weight: 700; color: inherit; }
.matrix-status a { text-decoration: none; }
.matrix-status a:hover { box-shadow: inset 0 0 0 2px currentColor; text-decoration: underline; }
.matrix-status.pass { background: var(--pass-bg); } .matrix-status.fail { background: var(--fail-bg); } .matrix-status.error { background: var(--error-bg); }
.matrix-status.neutral { background: var(--neutral-bg); font-weight: 400; } .matrix-status.pending { background: var(--pending-bg); }
.legend { display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0; font-size: 11px; }
.legend-item { display: inline-flex; align-items: center; gap: 7px; min-height: 30px; padding: 5px 11px; border: 1px solid var(--line); border-radius: 999px; }
.swatch { flex: 0 0 7px; width: 7px; height: 7px; background: currentColor; border-radius: 50%; }
.status { display: inline-block; padding: 4px 9px; border: 1px solid var(--line); border-radius: 999px; font-size: 11px; font-weight: 700; line-height: 1.4; }
.status.pass, .legend-item.pass { background: var(--pass-bg); border-color: var(--pass-line); }
.status.fail, .legend-item.fail { background: var(--fail-bg); border-color: var(--fail-line); }
.status.error, .legend-item.error { background: var(--error-bg); border-color: var(--error-line); }
.status.neutral, .legend-item.neutral { background: var(--neutral-bg); border-color: var(--neutral-line); }
.status.pending, .legend-item.pending { background: var(--pending-bg); border-color: var(--pending-line); }
.filters { display: flex; gap: 12px; align-items: flex-end; flex-wrap: wrap; padding: 12px 0; }
.filters label { display: grid; gap: 4px; font-size: 11px; color: var(--muted); }
.filters input, .filters select { font: 13px "Trebuchet MS", sans-serif; color: var(--ink); background: var(--surface); min-height: 36px; border: 1px solid var(--control-line); border-radius: 6px; padding: 6px 9px; max-width: 100%; }
.filters .search-field { flex: 1 1 220px; }
.filters label:not(.search-field) { flex: 0 1 240px; min-width: 160px; }
.results { min-width: 1150px; table-layout: fixed; }
.results > colgroup > col:nth-child(1) { width: 17%; } .results > colgroup > col:nth-child(2) { width: 23%; }
.results > colgroup > col:nth-child(3), .results > colgroup > col:nth-child(4) { width: 7%; }
.results > colgroup > col:nth-child(5) { width: 11%; } .results > colgroup > col:nth-child(6) { width: 10%; }
.results > colgroup > col:nth-child(7) { width: 25%; }
.results > tbody > tr:nth-child(even) { background: var(--surface); }
.results > tbody > tr:hover { background: var(--hover); }
.results > tbody > tr:target { background: var(--hover); }
.results > tbody > tr:target > td:first-child { box-shadow: inset 3px 0 var(--accent); }
.results > tbody > tr { scroll-margin-top: 16px; }
.results > tbody > tr > th { font-weight: 400; }
.result-host { font-size: 12px; } .owner { font-weight: 700; font-size: 12px; } .action { font-size: 12px; }
code { font: 12px Consolas, monospace; overflow-wrap: anywhere; }
.result-name { display: block; font-size: 12px; color: var(--muted); margin-top: 3px; }
summary { cursor: pointer; color: var(--accent); font-size: 12px; padding: 2px 0; }
.state-content { padding-top: 10px; }
.comparison { table-layout: fixed; font-size: 11px; }
.comparison th, .comparison td { padding: 6px; vertical-align: top; border-bottom: 1px solid var(--line); }
.comparison th { font-weight: 400; }
.comparison thead th { font-size: 10px; background: var(--wash); }
.comparison .different { background: var(--fail-bg); }
.comparison .different > th { color: var(--fail); font-weight: 700; }
.diagnostic { font-size: 12px; border-left: 2px solid var(--error); padding-left: 8px; white-space: pre-wrap; }
.evaluation-time { font: 10px Consolas, monospace; color: var(--muted); }
.empty-state { padding: 22px; color: var(--muted); text-align: center; }
[hidden] { display: none !important; }
.visually-hidden { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0; }
footer { margin-top: 26px; padding-top: 14px; border-top: 1px solid var(--line); font-size: 11px; color: var(--muted); }
@media (max-width: 700px) {
    main { padding: 16px 14px; }
    h1 { font-size: 23px; }
    .report-header { padding: 14px 16px 18px; }
    .header-overview { grid-template-columns: minmax(0, 1fr); }
    .report-verdict { flex-direction: row; flex-wrap: wrap; align-items: center; gap: 10px; }
    .run-meta { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
    .run-meta > div:last-child { grid-column: 1 / -1; }
    .summary { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
    .filters label:not(.search-field) { flex: 1 1 150px; min-width: 0; }
    .target-track { width: 184px; }
    .matrix .dc-column { padding: 10px; }
}
@media print {
    @page { size: landscape; margin: 12mm; }
    :root, :root[data-theme] {
        color-scheme: light;
        --ink: #20242d; --muted: #59616e; --line: #cdd1d8; --accent: #185dbb;
        --paper: #fff; --wash: #f1f3f6; --surface: #f8f9fb; --hover: #e9eef7;
        --accent-bg: #e7effd; --accent-line: #a7bee1;
        --pass: #186541; --pass-bg: #edf7f1; --pass-line: #a5c6b2;
        --fail: #a52d42; --fail-bg: #fff0f1; --fail-line: #d5a7af;
        --error: #855209; --error-bg: #fff5e6; --error-line: #d1bd94;
        --pending: #385d85; --pending-bg: #edf3fa; --pending-line: #a5bbd2;
        --neutral-bg: #f0f3f1; --neutral-line: #c2cec5;
    }
    body, main { background: var(--paper); }
    main { max-width: none; padding: 0; }
    .report-header { background: var(--paper); box-shadow: none; border-color: var(--line); border-top-color: var(--accent); }
    .filters, .header-actions { display: none; }
    .scroll { overflow: visible; border-radius: 0; }
    .matrix, .results { min-width: 0 !important; font-size: 10px; }
    .matrix .dc-column { position: static; }
    .target-track { width: 160px; }
    .matrix th, .matrix td { padding: 5px; }
    .matrix-status a, .matrix-status > span { min-height: 40px; font-size: 10px; }
    tr { break-inside: avoid; }
}
</style>
</head>
<body><main>
<header class="report-header">
<div class="header-topline"><div class="report-label"><span class="product-mark">DSC v3</span><span>Configuration assessment</span></div>
<div class="header-actions"><label class="theme-control" id="theme-control" hidden><input id="theme-toggle" type="checkbox" role="switch"><span>Light mode</span></label><a class="export" href="report.json" download title="Download JSON report">JSON</a><a class="export" href="report.csv" download title="Download CSV report">CSV</a></div></div>
<div class="header-overview"><div class="report-identity"><h1>Domain Controller <span class="title-accent">Compliance</span></h1><div class="domain-line"><strong>{{DOMAIN}}</strong><span class="operation">{{OPERATION}}</span></div></div>
<div class="report-verdict"><span class="verdict-label">Selected scope</span><span class="status {{OVERALLCLASS}}">{{OVERALL}}</span></div></div>
<dl class="run-meta"><div><dt>Baseline</dt><dd>{{BASELINE}}</dd></div><div><dt>Completed</dt><dd>{{TIME}}</dd></div><div><dt>Run ID</dt><dd class="run-id">{{RUN}}</dd></div></dl>
</header>
<section class="summary" aria-label="Run summary">
<div><strong>{{INCLUDED}} / {{TARGETCOUNT}}</strong><span>DCs selected</span></div>
<div><strong class="pass">{{PASS}}</strong><span>Compliant</span></div>
<div><strong class="fail">{{FAIL}}</strong><span>Noncompliant</span></div>
<div><strong class="error">{{ERROR}}</strong><span>Errors / unreachable</span></div>
<div><strong>{{SKIP}}</strong><span>Not evaluated</span></div>
</section>
<section aria-labelledby="matrix-title"><div class="section-heading"><h2 id="matrix-title">DC / Control Matrix</h2><span>{{CONTROLCOUNT}} controls | {{TARGETCOUNT}} DCs</span></div>
<div class="scroll" tabindex="0" role="region" aria-label="DC and control results"><table id="dc-matrix" class="matrix" style="min-width: {{MATRIXWIDTH}}px"><caption class="visually-hidden">Results by domain controller and selected control</caption><colgroup>{{MATRIXCOLUMNS}}</colgroup><thead><tr><th scope="col" class="dc-column">Domain controller</th>{{MATRIXHEADERS}}</tr></thead><tbody>{{MATRIXROWS}}</tbody></table></div>
<div class="legend" aria-label="Result legend"><span class="legend-item pass"><i class="swatch" aria-hidden="true"></i>Pass: compliant</span><span class="legend-item fail"><i class="swatch" aria-hidden="true"></i>Drift: noncompliant</span><span class="legend-item error"><i class="swatch" aria-hidden="true"></i>Error / Offline</span><span class="legend-item neutral"><i class="swatch" aria-hidden="true"></i>Excluded / Not selected</span><span class="legend-item pending"><i class="swatch" aria-hidden="true"></i>Pending: not evaluated</span></div></section>
<section aria-labelledby="results-title"><div class="section-heading"><h2 id="results-title">Control Details</h2><span id="visible-count" aria-live="polite">{{RESULTCOUNT}} results</span></div>
<div class="filters" id="result-filters" hidden>
<label>Domain controller<select id="dc-filter"><option value="">All DCs</option>{{TARGETOPTIONS}}</select></label>
<label>Result<select id="status-filter"><option value="">All results</option><option value="NonCompliant">Noncompliant</option><option value="Error">Error</option><option value="Unreachable">Unreachable</option><option value="Compliant">Compliant</option><option value="NotEvaluated">Not evaluated</option><option value="NotApplicable">Not applicable</option></select></label>
<label class="search-field">Control / keyword<input id="result-search" type="search" autocomplete="off"></label>
</div>
<div class="scroll" tabindex="0" role="region" aria-label="Detailed control results"><table id="control-results" class="results"><caption class="visually-hidden">Control ownership, mode, outcome, and state differences</caption><colgroup><col><col><col><col><col><col><col></colgroup><thead><tr><th scope="col">DC</th><th scope="col">Control</th><th scope="col">Owner</th><th scope="col">Mode</th><th scope="col">Result</th><th scope="col">Action</th><th scope="col">Expected / Observed</th></tr></thead><tbody>{{RESULTS}}<tr id="no-matches" hidden><td colspan="7" class="empty-state">No matching results.</td></tr></tbody></table></div></section>
<footer>Selected scope only. LDAP controls check explicit policy values, not implicit OS defaults. Execution metadata is in report.json; raw DSC output and before/after responses are in Evidence.</footer>
</main>
<script>
(() => {
    const themeToggle = document.getElementById('theme-toggle');
    themeToggle.checked = false;
    themeToggle.addEventListener('change', () => {
        document.documentElement.dataset.theme = themeToggle.checked ? 'light' : 'dark';
    });
    document.getElementById('theme-control').hidden = false;
    const rows = Array.from(document.querySelectorAll('#control-results tr[data-result]'));
    const host = document.getElementById('dc-filter');
    const status = document.getElementById('status-filter');
    const search = document.getElementById('result-search');
    const count = document.getElementById('visible-count');
    const empty = document.getElementById('no-matches');
    if (rows.length) document.getElementById('result-filters').hidden = false;
    function filterResults() {
        const query = search.value.trim().toLowerCase();
        let visible = 0;
        rows.forEach(row => {
            const matches = (!host.value || row.dataset.host === host.value) &&
                (!status.value || row.dataset.status === status.value) &&
                (!query || row.dataset.search.toLowerCase().includes(query));
            row.hidden = !matches;
            if (matches) visible++;
        });
        count.textContent = visible + ' / ' + rows.length + ' results';
        empty.hidden = visible !== 0 || rows.length === 0;
    }
    host.addEventListener('change', filterResults);
    status.addEventListener('change', filterResults);
    search.addEventListener('input', filterResults);
    document.querySelectorAll('#dc-matrix a[data-result-id]').forEach(link => {
        link.addEventListener('click', () => {
            host.value = ''; status.value = ''; search.value = '';
            filterResults();
            const row = document.getElementById(link.dataset.resultId);
            if (row) row.querySelector('details').open = true;
        });
    });
})();
</script>
</body></html>
'@
    $replacements = @{
        DOMAIN = ConvertTo-DCHtml $Report.Domain
        OPERATION = ConvertTo-DCHtml $Report.Operation
        BASELINE = ConvertTo-DCHtml $Report.BaselineVersion
        TIME = ConvertTo-DCHtml $completedTime
        RUN = ConvertTo-DCHtml $Report.RunId
        OVERALL = ConvertTo-DCHtml $overallInfo.Label
        OVERALLCLASS = $overallInfo.Class
        INCLUDED = [string]$includedCount
        TARGETCOUNT = [string]$totalTargets
        CONTROLCOUNT = [string]$controlIndex.Count
        RESULTCOUNT = [string]$resultEntries.Count
        PASS = [string]$counts.Compliant
        FAIL = [string]$counts.NonCompliant
        ERROR = [string]$counts.Errors
        SKIP = [string]$counts.NotEvaluated
        MATRIXWIDTH = [string]$matrixWidth
        MATRIXCOLUMNS = $matrixColumns
        MATRIXHEADERS = $matrixHeaders -join "`n"
        MATRIXROWS = $matrixRows -join "`n"
        TARGETOPTIONS = $targetOptions -join "`n"
        RESULTS = $resultRows -join "`n"
    }
    $html = [regex]::Replace($template, '\{\{([A-Z]+)\}\}', {
        param($match)
        [string]$replacements[$match.Groups[1].Value]
    })
    [System.IO.File]::WriteAllText($htmlPath, $html, [System.Text.UTF8Encoding]::new($false))
    [pscustomobject]@{
        RunDirectory = $RunDirectory
        HtmlPath = $htmlPath
        JsonPath = $jsonPath
        CsvPath = $csvPath
        OverallStatus = $overall
        Compliant = $counts.Compliant
        NonCompliant = $counts.NonCompliant
        Errors = $counts.Errors
        NotEvaluated = $counts.NotEvaluated
    }
}

Export-ModuleMember -Function Read-DCComplianceInput, New-DCConfiguration, Get-DCResourcePackage, Get-DCTestState, Write-DCComplianceReport
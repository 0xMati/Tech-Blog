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
        'PSDscResources/Service' {
            $required = @('Name', 'Ensure', 'State', 'StartupType')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.Name -cne 'Spooler' -or $properties.Ensure -cne 'Present' -or
                $properties.State -cnotin @('Running', 'Stopped') -or
                $properties.StartupType -cnotin @('Automatic', 'Manual', 'Disabled')) {
                throw "Invalid Spooler properties on '$($Control.Id)'."
            }
        }
        'ComputerManagementDsc/SmbServerConfiguration' {
            Assert-DCObject $properties @('IsSingleInstance') $Control.Id
            $switchNames = @($properties.PSObject.Properties.Name | Where-Object { $_ -ne 'IsSingleInstance' })
            if ($properties.IsSingleInstance -cne 'Yes' -or $switchNames.Count -ne 1 -or
                $switchNames[0] -cnotin @('EnableSMB1Protocol', 'RequireSecuritySignature')) {
                throw "Each SMB control must test one supported Boolean property: '$($Control.Id)'."
            }
            $required = @('IsSingleInstance', $switchNames[0])
            if ($properties.($switchNames[0]) -isnot [bool]) { throw "SMB values must be Booleans: '$($Control.Id)'." }
        }
        'AuditPolicyDsc/AuditPolicyGUID' {
            $required = @('Name', 'AuditFlag', 'Ensure')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.Name -cnotin @('Logon', 'User Account Management', 'Directory Service Changes') -or
                $properties.AuditFlag -cnotin @('Success', 'Failure', 'Success And Failure', 'No Auditing') -or
                $properties.Ensure -cne 'Present') {
                throw "Unsupported audit policy properties on '$($Control.Id)'."
            }
        }
        'ComputerManagementDsc/WindowsEventLog' {
            $required = @('LogName', 'MaximumSizeInBytes', 'LogMode')
            Assert-DCObject $properties $required $Control.Id
            $size = $properties.MaximumSizeInBytes
            if ($properties.LogName -cnotin @('Security', 'System', 'Application', 'Directory Service') -or
                $properties.LogMode -cnotin @('Circular', 'AutoBackup', 'Retain') -or
                ($size -isnot [int] -and $size -isnot [long]) -or $size -lt 65536 -or $size % 65536 -ne 0) {
                throw "Invalid log properties on '$($Control.Id)'; size must be a positive multiple of 64 KiB."
            }
        }
        'PSDscResources/Registry' {
            $required = @('Key', 'ValueName', 'ValueType', 'ValueData', 'Ensure')
            Assert-DCObject $properties $required $Control.Id
            if ($properties.Key -ine 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -or
                $properties.ValueName -cnotin @('LDAPServerIntegrity', 'LdapEnforceChannelBinding') -or
                $properties.ValueType -cne 'DWord' -or $properties.Ensure -cne 'Present' -or
                $properties.ValueData -isnot [array] -or $properties.ValueData.Count -ne 1 -or
                $properties.ValueData[0] -isnot [string] -or $properties.ValueData[0] -cnotin @('0', '1', '2')) {
                throw "Unsupported explicit LDAP registry policy on '$($Control.Id)'."
            }
        }
        default { throw "Unsupported resource type: '$($Control.ResourceType)'." }
    }
    $unknown = @($properties.PSObject.Properties.Name | Where-Object { $required -cnotcontains $_ })
    if ($unknown.Count -gt 0) { throw "Unknown properties on '$($Control.Id)': $($unknown -join ', ')." }
    if ($Control.Mode -eq 'Enforce' -and $Control.ResourceType -cnotin @('PSDscResources/Service', 'ComputerManagementDsc/WindowsEventLog')) {
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
    Assert-DCObject $settings @('SchemaVersion', 'BaselineVersion', 'MaximumInventoryAgeHours', 'DscExecutable', 'DscVersion', 'ModuleVersions', 'ExcludedDCs', 'Controls') 'Settings'
    if ($settings.SchemaVersion -ne 1) { throw 'Unsupported compliance settings schema version.' }
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
    Assert-DCObject $settings.ModuleVersions @('PSDscResources', 'ComputerManagementDsc', 'AuditPolicyDsc') 'ModuleVersions'
    foreach ($module in $settings.ModuleVersions.PSObject.Properties) {
        if ($module.Name -notin @('PSDscResources', 'ComputerManagementDsc', 'AuditPolicyDsc') -or
            $module.Value -isnot [string] -or $module.Value -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
            throw "Invalid module/version entry: '$($module.Name)'."
        }
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
                directives = @{ requireAdapter = 'Microsoft.Adapter/WindowsPowerShell' }
            }
        )
    }
    ConvertTo-Json -InputObject $document -Depth 12
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
    $targetRows = foreach ($target in $Report.Targets) {
        '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f (ConvertTo-DCHtml $target.HostName), (ConvertTo-DCHtml $target.Scope), (ConvertTo-DCHtml $target.Reason)
    }
    $resultRows = foreach ($result in $Report.Results) {
        $statusClass = switch ($result.Status) {
            'Compliant' { 'pass' }
            'NonCompliant' { 'fail' }
            'Error' { 'error' }
            'Unreachable' { 'error' }
            default { 'neutral' }
        }
        $desired = ConvertTo-Json -InputObject $result.DesiredState -Depth 10
        $actual = ConvertTo-Json -InputObject $result.ActualState -Depth 10
        '<tr><td>{0}</td><td><strong>{1}</strong><br>{2}<br><small>{3} / {4}</small></td><td class="{5}">{6}<br><small>{7}</small></td><td><pre>{8}</pre></td><td><pre>{9}</pre></td><td>{10}<br><small>{11}</small></td></tr>' -f
            (ConvertTo-DCHtml $result.HostName), (ConvertTo-DCHtml $result.ControlId),
            (ConvertTo-DCHtml $result.ControlName), (ConvertTo-DCHtml $result.Owner), (ConvertTo-DCHtml $result.Mode),
            $statusClass, (ConvertTo-DCHtml $result.Status), (ConvertTo-DCHtml $result.Action),
            (ConvertTo-DCHtml $desired), (ConvertTo-DCHtml $actual), (ConvertTo-DCHtml $result.Message),
            (ConvertTo-DCHtml ($result.DifferingProperties -join ', '))
    }
    $template = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Domain Controller Compliance</title>
<style>
:root { color-scheme: light; --ink: #222829; --muted: #596367; --line: #d8dfe1; --paper: #fff; }
* { box-sizing: border-box; }
body { margin: 0; color: var(--ink); background: #f4f6f6; font: 14px "Aptos", "Trebuchet MS", sans-serif; letter-spacing: 0; }
main { max-width: 1540px; margin: 0 auto; padding: 24px; background: var(--paper); min-height: 100vh; }
header { border-top: 5px solid #236b5b; padding-top: 18px; }
h1 { font-size: 26px; margin: 0 0 10px; overflow-wrap: anywhere; }
h2 { font-size: 18px; margin: 28px 0 10px; }
p { line-height: 1.5; overflow-wrap: anywhere; }
.metadata, small { color: var(--muted); }
.summary { display: flex; flex-wrap: wrap; gap: 16px 30px; border-block: 1px solid var(--line); padding: 14px 0; margin-top: 20px; }
.summary div { min-width: 100px; }
.summary strong { font-size: 22px; display: block; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; text-align: left; }
.results { min-width: 1060px; table-layout: fixed; }
.results th:nth-child(1) { width: 14%; } .results th:nth-child(2) { width: 20%; }
.results th:nth-child(3) { width: 12%; } .results th:nth-child(4), .results th:nth-child(5) { width: 18%; }
.results th:nth-child(6) { width: 18%; }
th, td { border-bottom: 1px solid var(--line); padding: 10px; vertical-align: top; overflow-wrap: anywhere; }
th { background: #edf2f0; font-weight: 600; }
tbody tr:nth-child(even) { background: #fafbfb; }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: 12px Consolas, monospace; }
.pass { color: #14623d; } .fail { color: #a42534; } .error { color: #875600; } .neutral { color: #596367; }
footer { margin-top: 24px; color: var(--muted); border-top: 1px solid var(--line); padding-top: 12px; }
@media (max-width: 600px) { main { padding: 16px; } h1 { font-size: 23px; } }
@media print { main { max-width: none; padding: 0; } .scroll { overflow: visible; } .results { min-width: 0; } th { background: #eee; } }
</style>
</head>
<body><main>
<header><h1>Domain Controller Compliance</h1>
<p class="metadata">{{DOMAIN}} | {{OPERATION}} | Baseline {{BASELINE}}<br>{{TIME}} | Run {{RUN}}</p>
<p><strong>Overall: {{OVERALL}}</strong></p></header>
<section class="summary" aria-label="Control results">
<div><strong class="pass">{{PASS}}</strong>Compliant</div>
<div><strong class="fail">{{FAIL}}</strong>Noncompliant</div>
<div><strong class="error">{{ERROR}}</strong>Errors / unreachable</div>
<div><strong>{{SKIP}}</strong>Not evaluated</div>
</section>
<h2>Target Coverage</h2><div class="scroll"><table><thead><tr><th>DC</th><th>Scope</th><th>Reason</th></tr></thead><tbody>{{TARGETS}}</tbody></table></div>
<h2>Control Results</h2><div class="scroll"><table class="results"><thead><tr><th>DC</th><th>Control</th><th>Result / Action</th><th>Expected</th><th>Observed</th><th>Details</th></tr></thead><tbody>{{RESULTS}}</tbody></table></div>
<footer>Configuration assessment at the recorded time, not a complete AD health or security assessment. LDAP rows check explicit policy values, not implicit OS defaults. Full results and execution metadata are in report.json; raw DSC output is in Evidence.</footer>
</main></body></html>
'@
    $replacements = @{
        DOMAIN = ConvertTo-DCHtml $Report.Domain
        OPERATION = ConvertTo-DCHtml $Report.Operation
        BASELINE = ConvertTo-DCHtml $Report.BaselineVersion
        TIME = ConvertTo-DCHtml $Report.CompletedAtUtc
        RUN = ConvertTo-DCHtml $Report.RunId
        OVERALL = ConvertTo-DCHtml $overall
        PASS = [string]$counts.Compliant
        FAIL = [string]$counts.NonCompliant
        ERROR = [string]$counts.Errors
        SKIP = [string]$counts.NotEvaluated
        TARGETS = $targetRows -join "`n"
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

Export-ModuleMember -Function Read-DCComplianceInput, New-DCConfiguration, Get-DCTestState, Write-DCComplianceReport
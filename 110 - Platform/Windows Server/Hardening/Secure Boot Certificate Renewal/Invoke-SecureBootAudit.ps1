#Requires -Version 7.2
<#
.SYNOPSIS
    Read-only Secure Boot inventory over WinRM, with HTML/CSV/JSON reports.
.DESCRIPTION
    Queries the ComputerName column of a UTF-8, semicolon-delimited CSV.
    Collects the Windows deployment state, firmware/OS inventory, recent
    TPM-WMI events and scheduled-task state. No certificate, policy, task or
    reboot changes. No AD discovery or Internet download.
.PARAMETER CsvPath
    Required input CSV. ComputerName is required; Description is optional.
    Blank/duplicate names and malformed input are rejected before collection.
.PARAMETER Credential
    Optional credential for all WinRM connections. Never saved in reports.
.PARAMETER UseSSL
    Use the existing WinRM HTTPS listener (5986), with normal certificate checks.
    Otherwise use the existing HTTP listener (5985) and normal message encryption.
.PARAMETER TimeoutSeconds
    Per-computer job deadline, including connection and data collection.
.PARAMETER MaxEvents
    Maximum recent matching System/TPM-WMI events per computer, not a time window.
.PARAMETER OutputDir
    New local output directory; existing directories are rejected.
.PARAMETER OpenReport
    Open the HTML report after saving all outputs, including partial reports.
.EXAMPLE
    .\Invoke-SecureBootAudit.ps1 -CsvPath .\Computers.example.csv -OpenReport
.EXAMPLE
    .\Invoke-SecureBootAudit.ps1 -CsvPath .\Computers.csv -Credential (Get-Credential) -UseSSL
.NOTES
    Version 1.0.0. PowerShell 7.2+ on the reporting host; Windows PowerShell
    5.1-compatible payload on Windows targets. Every target uses WinRM.
    Independent implementation of the inventory checks described by Microsoft:
    https://support.microsoft.com/topic/d02971d2-d4b5-42c9-b58a-8527f0ffa30b
    This is not a Microsoft-supported modification of its sample.
    UpdatedReported is Windows evidence, not firmware attestation or compliance.
    Exit 1 means collection errors; exit 0 does not mean all devices are updated.
#>
[CmdletBinding()]
param(
    [string]$CsvPath,
    [pscredential]$Credential,
    [switch]$UseSSL,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 120,
    [ValidateRange(1, 10000)][int]$MaxEvents = 50,
    [string]$OutputDir = (Join-Path $PSScriptRoot ('Outputs\SecureBootAudit_{0}_{1}' -f
        (Get-Date -Format 'yyyyMMdd_HHmmssfff'), [guid]::NewGuid().ToString('N').Substring(0, 8))),
    [switch]$OpenReport
)

function Import-SecureBootTargets {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'CsvPath is required.' }
    $rows = @(Import-Csv -LiteralPath $Path -Delimiter ';' -Encoding utf8 -ErrorAction Stop -WarningAction Stop)
    if ($rows.Count -eq 0) { throw 'The input CSV contains no computers.' }
    if ($rows[0].PSObject.Properties.Name -notcontains 'ComputerName') {
        throw 'CSV requires a ComputerName column and a semicolon (;) delimiter.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($row in $rows) {
        $name = ([string]$row.ComputerName).Trim()
        if ($name.Length -gt 253 -or $name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
            throw "Invalid ComputerName '$name'. Use a DNS or NetBIOS computer name, not a URL or wildcard."
        }
        if (-not $seen.Add($name)) { throw "Duplicate ComputerName '$name' in CSV." }
    }
    foreach ($row in $rows) {
        [pscustomobject]@{
            ComputerName = ([string]$row.ComputerName).Trim()
            Description = if ($row.PSObject.Properties.Name -contains 'Description') { [string]$row.Description } else { '' }
        }
    }
}

function ConvertFrom-SecureBootEventXml {
    param([Parameter(Mandatory)][string]$Xml)

    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $inputReader = [IO.StringReader]::new($Xml)
    $reader = [Xml.XmlReader]::Create($inputReader, $settings)
    try {
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
    }
    finally { $reader.Dispose(); $inputReader.Dispose() }
    $system = $document.SelectSingleNode("/*[local-name()='Event']/*[local-name()='System']")
    if ($null -eq $system) { throw 'Event has no System element.' }
    $provider = $system.SelectSingleNode("*[local-name()='Provider']").GetAttribute('Name')
    $channel = $system.SelectSingleNode("*[local-name()='Channel']").InnerText
    $id = [int]$system.SelectSingleNode("*[local-name()='EventID']").InnerText
    if ($provider -ne 'Microsoft-Windows-TPM-WMI' -or $channel -ne 'System' -or
        $id -notin 1795,1796,1800,1801,1802,1803,1808) {
        throw 'Event is not a selected System/TPM-WMI record.'
    }
    $fields = [ordered]@{}
    foreach ($node in $document.SelectNodes("/*[local-name()='Event']/*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ([string]::IsNullOrEmpty($name)) { $name = 'Unnamed_' + $fields.Count }
        if ($fields.Contains($name)) { throw "Duplicate event field '$name'." }
        $fields[$name] = $node.InnerText
    }
    [pscustomobject]@{
        EventId = $id; Provider = $provider; Channel = $channel
        RecordId = [long]$system.SelectSingleNode("*[local-name()='EventRecordID']").InnerText
        TimeUtc = ([datetimeoffset]::Parse($system.SelectSingleNode("*[local-name()='TimeCreated']").GetAttribute('SystemTime'))).UtcDateTime.ToString('o')
        Fields = $fields; RawXml = $Xml
    }
}

function Get-SecureBootLocalData {
    param([int]$MaxEvents = 50)

    $issues = [Collections.Generic.List[object]]::new()
    function Add-InventoryIssue([string]$Area, [string]$Kind, [string]$Message) {
        $issues.Add([pscustomobject]@{ Area = $Area; Kind = $Kind; Message = $Message })
    }
    function Read-InventoryKey([string]$Path, [string]$Area) {
        try {
            [pscustomobject]@{ Status = 'Read'; Values = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            Add-InventoryIssue $Area 'Missing' "Registry key absent: $Path"
            [pscustomobject]@{ Status = 'Absent'; Values = $null }
        }
        catch {
            Add-InventoryIssue $Area 'Error' $_.Exception.Message
            [pscustomobject]@{ Status = 'Error'; Values = $null }
        }
    }
    function Read-InventoryClass([string]$Class) {
        try { Get-CimInstance -ClassName $Class -ErrorAction Stop }
        catch { Add-InventoryIssue $Class 'Error' $_.Exception.Message }
    }
    function Read-InventoryValue($Object, [string]$Name) {
        if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { $Object.$Name }
    }
    function Format-InventoryTime($Value) {
        if ($null -ne $Value) {
            try { ([datetime]$Value).ToUniversalTime().ToString('o') }
            catch { Add-InventoryIssue 'Timestamp' 'Error' $_.Exception.Message }
        }
    }
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    $base = Read-InventoryKey $root 'Configuration'
    $state = Read-InventoryKey "$root\State" 'SecureBootState'
    $servicing = Read-InventoryKey "$root\Servicing" 'Servicing'
    $attributes = Read-InventoryKey "$root\Servicing\DeviceAttributes" 'DeviceAttributes'
    $os = Read-InventoryClass 'Win32_OperatingSystem'
    $computer = Read-InventoryClass 'Win32_ComputerSystem'
    $bios = Read-InventoryClass 'Win32_BIOS'
    $board = Read-InventoryClass 'Win32_BaseBoard'
    $secureBoot = $null
    $secureBootSource = 'Unavailable'
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        $secureBootSource = 'Confirm-SecureBootUEFI'
    }
    catch {
        $fallback = Read-InventoryValue $state.Values 'UEFISecureBootEnabled'
        if ($null -ne $fallback -and $fallback -in 0,1) {
            $secureBoot = [bool]$fallback
            $secureBootSource = 'RegistryFallback'
            Add-InventoryIssue 'SecureBoot' 'Fallback' $_.Exception.Message
        }
        else { Add-InventoryIssue 'SecureBoot' 'Error' $_.Exception.Message }
    }
    $data = [ordered]@{
        Hostname = $env:COMPUTERNAME; CollectionTimeUtc = [datetime]::UtcNow.ToString('o')
        SecureBootEnabled = $secureBoot; SecureBootSource = $secureBootSource
        UEFICA2023Status = Read-InventoryValue $servicing.Values 'UEFICA2023Status'
        UEFICA2023Error = Read-InventoryValue $servicing.Values 'UEFICA2023Error'
        UEFICA2023ErrorEvent = Read-InventoryValue $servicing.Values 'UEFICA2023ErrorEvent'
        ConfigurationReadStatus = $base.Status; ServicingReadStatus = $servicing.Status
        DeviceAttributesReadStatus = $attributes.Status
        OSName = Read-InventoryValue $os 'Caption'; OSVersion = Read-InventoryValue $os 'Version'
        OSBuild = Read-InventoryValue $os 'BuildNumber'; OSArchitecture = Read-InventoryValue $os 'OSArchitecture'
        LastBootTimeUtc = Format-InventoryTime (Read-InventoryValue $os 'LastBootUpTime')
        Manufacturer = Read-InventoryValue $computer 'Manufacturer'; Model = Read-InventoryValue $computer 'Model'
        FirmwareVersion = Read-InventoryValue $bios 'SMBIOSBIOSVersion'
        FirmwareReleaseDate = Format-InventoryTime (Read-InventoryValue $bios 'ReleaseDate')
        BaseBoardManufacturer = Read-InventoryValue $board 'Manufacturer'; BaseBoardProduct = Read-InventoryValue $board 'Product'
    }
    foreach ($name in 'AvailableUpdates','AvailableUpdatesPolicy','HighConfidenceOptOut','MicrosoftUpdateManagedOptIn') {
        $value = Read-InventoryValue $base.Values $name
        if ($name -in 'AvailableUpdates','AvailableUpdatesPolicy' -and $null -ne $value) {
            $value = '0x{0:X}' -f $value
        }
        $data[$name] = $value
    }
    foreach ($name in 'OEMManufacturerName','OEMModelSystemFamily','OEMModelNumber','CanAttemptUpdateAfter') {
        $value = Read-InventoryValue $attributes.Values $name
        if ($name -eq 'CanAttemptUpdateAfter' -and $null -ne $value) {
            try { $value = [datetime]::FromFileTimeUtc([long]$value).ToString('o') }
            catch { Add-InventoryIssue $name 'Error' $_.Exception.Message; $value = $null }
        }
        $data[$name] = $value
    }
    $data.SecureBootTaskEnabled = $null
    $data.SecureBootTaskStatus = 'Unavailable'
    try {
        $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
        if ($null -eq $task) { throw 'Secure-Boot-Update task returned no data.' }
        if ($null -eq $task.Settings -or $null -eq $task.Settings.Enabled) { throw 'Scheduled-task Enabled state is unavailable.' }
        $data.SecureBootTaskEnabled = [bool]$task.Settings.Enabled
        $data.SecureBootTaskStatus = [string]$task.State
    }
    catch {
        $data.SecureBootTaskStatus = 'Unverified'
        $kind = if ($_.CategoryInfo.Category -eq 'ObjectNotFound' -or
            $_.Exception -is [Management.Automation.CommandNotFoundException]) { 'Unavailable' } else { 'Error' }
        Add-InventoryIssue 'ScheduledTask' $kind $_.Exception.Message
    }
    $events = [Collections.Generic.List[object]]::new()
    $data.EventReadStatus = 'Read'
    $data.EventLimit = $MaxEvents
    $data.EventLimitReached = $false
    try {
        $records = @(Get-WinEvent -FilterHashtable @{
            LogName = 'System'; ProviderName = 'Microsoft-Windows-TPM-WMI'
            Id = 1795,1796,1800,1801,1802,1803,1808
        } -MaxEvents ($MaxEvents + 1) -ErrorAction Stop)
        $data.EventLimitReached = $records.Count -gt $MaxEvents
        foreach ($record in ($records | Select-Object -First $MaxEvents)) {
            try { $events.Add((ConvertFrom-SecureBootEventXml -Xml $record.ToXml())) }
            catch { $data.EventReadStatus = 'Partial'; Add-InventoryIssue 'EventXml' 'Error' $_.Exception.Message }
        }
        if ($data.EventLimitReached) { Add-InventoryIssue 'Events' 'Limited' "Only the newest $MaxEvents matching retained events were collected." }
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            $data.EventReadStatus = 'NoEvents'
            Add-InventoryIssue 'Events' 'Missing' 'No matching retained events; this does not prove completion.'
        }
        else { $data.EventReadStatus = 'Error'; Add-InventoryIssue 'Events' 'Error' $_.Exception.Message }
    }
    $orderedEvents = @($events | Sort-Object @{Expression = { [datetimeoffset]$_.TimeUtc }; Descending = $true}, @{Expression = 'RecordId'; Descending = $true})
    $data.LatestEventId = $null
    $data.LatestEventTimeUtc = $null
    $data.BucketId = $null
    $data.Confidence = $null
    $data.SkipReason = $null
    if ($orderedEvents.Count -gt 0) {
        $latest = $orderedEvents[0]
        $data.LatestEventId = $latest.EventId
        $data.LatestEventTimeUtc = $latest.TimeUtc
        foreach ($mapping in @(@('BucketId','BucketId'), @('Confidence','BucketConfidenceLevel'), @('SkipReason','SkipReason'))) {
            $data[$mapping[0]] = $latest.Fields[$mapping[1]]
        }
    }
    foreach ($id in 1795,1796,1800,1801,1802,1803,1808) {
        $data["Event${id}Count"] = if ($data.EventReadStatus -eq 'Error') { $null } else { @($orderedEvents | Where-Object EventId -eq $id).Count }
    }
    $data.WinCSQueryStatus = 'NotInstalled'
    $data.WinCSQueryExitCode = $null
    $data.WinCSQueryOutput = $null
    try {
        $tool = Join-Path $env:SystemRoot 'System32\WinCsFlags.exe'
        if (Test-Path -LiteralPath $tool -ErrorAction Stop) {
            $nativeOutput = & $tool /query --key F33E0C8E002 2>&1
            $data.WinCSQueryExitCode = $LASTEXITCODE
            $data.WinCSQueryOutput = ($nativeOutput | Out-String).Trim()
            $data.WinCSQueryStatus = if ($LASTEXITCODE -eq 0) { 'Read' } else { 'QueryFailed' }
            if ($LASTEXITCODE -ne 0) { Add-InventoryIssue 'WinCS' 'Unavailable' $data.WinCSQueryOutput }
        }
    }
    catch { $data.WinCSQueryStatus = 'Unverified'; Add-InventoryIssue 'WinCS' 'Unavailable' $_.Exception.Message }
    [pscustomobject]@{ SchemaVersion = 1; Data = [pscustomobject]$data; Events = $orderedEvents; Issues = @($issues.ToArray()) }
}

function Invoke-SecureBootTarget {
    param([string]$ComputerName, [pscredential]$Credential, [switch]$UseSSL, [int]$TimeoutSeconds = 120, [int]$MaxEvents = 50)

    $payload = [scriptblock]::Create(@"
param([int]`$MaxEvents)
function ConvertFrom-SecureBootEventXml { ${function:ConvertFrom-SecureBootEventXml} }
function Get-SecureBootLocalData { ${function:Get-SecureBootLocalData} }
Get-SecureBootLocalData -MaxEvents `$MaxEvents
"@)
    $invoke = @{
        ComputerName = $ComputerName; ScriptBlock = $payload; ArgumentList = @($MaxEvents)
        AsJob = $true; ErrorAction = 'Stop'
        SessionOption = New-PSSessionOption -OpenTimeout ([Math]::Min($TimeoutSeconds * 1000, 60000)) -CancelTimeout 5000
    }
    if ($null -ne $Credential) { $invoke.Credential = $Credential }
    if ($UseSSL) { $invoke.UseSSL = $true }
    $job = $null
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $job = Invoke-Command @invoke
        $remaining = $TimeoutSeconds - $timer.Elapsed.TotalSeconds
        if ($remaining -le 0) { throw [TimeoutException]::new("Connection exceeded $TimeoutSeconds seconds.") }
        $finished = Wait-Job -Job $job -Timeout ([Math]::Max(1, [Math]::Floor($remaining))) -ErrorAction Stop
        if ($null -eq $finished) { throw [TimeoutException]::new("Collection exceeded $TimeoutSeconds seconds.") }
        $result = @(Receive-Job -Job $job -ErrorAction Stop)
        if ($job.State -ne 'Completed') { throw "Remote job ended in state $($job.State)." }
        if ($result.Count -ne 1 -or $result[0].SchemaVersion -ne 1 -or
            $null -eq $result[0].Data -or $result[0].PSObject.Properties.Name -notcontains 'Issues' -or
            $result[0].PSObject.Properties.Name -notcontains 'Events') {
            throw 'Unexpected remote inventory response.'
        }
        foreach ($name in 'SecureBootEnabled','UEFICA2023Status','LatestEventId','CollectionTimeUtc','EventReadStatus') {
            if ($result[0].Data.PSObject.Properties.Name -notcontains $name) { throw "Remote response is missing $name." }
        }
        if ($null -ne $result[0].Data.SecureBootEnabled -and $result[0].Data.SecureBootEnabled -isnot [bool]) {
            throw 'Remote SecureBootEnabled must be a Boolean or null.'
        }
        $result[0]
    }
    finally {
        if ($null -ne $job) {
            try {
                if ($job.State -in 'Running','NotStarted','Blocked','Disconnected') { Stop-Job -Job $job -ErrorAction Stop }
            }
            finally { Remove-Job -Job $job -Force -ErrorAction Stop }
        }
    }
}

function Get-SecureBootAssessment {
    param([Parameter(Mandatory)]$Snapshot, [int]$ErrorCount)

    if ($ErrorCount -gt 0 -or $null -eq $Snapshot.SecureBootEnabled) { return 'Unknown' }
    if (-not $Snapshot.SecureBootEnabled) { return 'Disabled' }
    if ($null -ne $Snapshot.UEFICA2023Error -and $Snapshot.UEFICA2023Error -ne 0) { return 'ReviewRequired' }
    if ($Snapshot.LatestEventId -in 1795,1796,1802,1803) { return 'ReviewRequired' }
    if ($Snapshot.LatestEventId -eq 1800) { return 'RestartIndicated' }
    switch ($Snapshot.UEFICA2023Status) {
        'Updated' {
            if ($Snapshot.LatestEventId -eq 1808) { return 'UpdatedReported' }
            return 'ReviewRequired'
        }
        'InProgress' { return 'InProgress' }
        'NotStarted' { return 'NotStarted' }
        default { return 'Unknown' }
    }
}

function Export-SecureBootCsv {
    param([AllowEmptyCollection()][object[]]$Rows, [string[]]$Columns, [string]$Path)

    $safeRows = @(
        foreach ($row in $Rows) {
            $safe = [ordered]@{}
            foreach ($column in $Columns) {
                $value = $row.$column
                if ($value -is [string] -and $value -match '^\s*[=+@-]') { $value = "'" + $value }
                $safe[$column] = $value
            }
            [pscustomobject]$safe
        }
    )
    if ($safeRows.Count -gt 0) {
        $safeRows | Export-Csv -LiteralPath $Path -Delimiter ';' -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
    }
    else {
        $empty = [ordered]@{}
        foreach ($column in $Columns) { $empty[$column] = $null }
        $header = ([pscustomobject]$empty | ConvertTo-Csv -Delimiter ';' -NoTypeInformation)[0]
        Set-Content -LiteralPath $Path -Value $header -Encoding utf8BOM -ErrorAction Stop
    }
}

function Export-SecureBootReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Directory)

    $computers = @(
        foreach ($item in $Report.Computers) {
            $row = [ordered]@{
                ComputerName = $item.ComputerName; Description = $item.Description
                CollectionStatus = $item.CollectionStatus; Assessment = $item.Assessment; ErrorCount = $item.ErrorCount
            }
            foreach ($name in $Report.DataColumns) { $row[$name] = if ($null -ne $item.Data) { $item.Data.$name } else { $null } }
            [pscustomobject]$row
        }
    )
    $computerColumns = @('ComputerName','Description','CollectionStatus','Assessment','ErrorCount') + @($Report.DataColumns)
    Export-SecureBootCsv -Rows $computers -Columns $computerColumns -Path (Join-Path $Directory 'Computers.csv')
    $eventRows = @(
        foreach ($item in $Report.Computers) {
            foreach ($event in $item.Events) {
                [pscustomobject]@{
                    ComputerName = $item.ComputerName; EventId = $event.EventId; Provider = $event.Provider
                    RecordId = $event.RecordId; TimeUtc = $event.TimeUtc
                    Fields = ConvertTo-Json -InputObject $event.Fields -Compress -Depth 5
                    RawXml = $event.RawXml
                }
            }
        }
    )
    Export-SecureBootCsv -Rows $eventRows -Columns @('ComputerName','EventId','Provider','RecordId','TimeUtc','Fields','RawXml') -Path (Join-Path $Directory 'Events.csv')
    Export-SecureBootCsv -Rows @($Report.Issues) -Columns @('ComputerName','Area','Kind','Message') -Path (Join-Path $Directory 'Issues.csv')
    $Report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $Directory 'SecureBootAudit.json') -Encoding utf8 -ErrorAction Stop
    function Encode($Value) { [Net.WebUtility]::HtmlEncode([string]$Value) }
    $rows = foreach ($item in $computers) {
        $details = [Text.StringBuilder]::new()
        [void]$details.Append('<details><summary>Evidence and collection notes</summary><dl>')
        foreach ($name in $Report.DataColumns) {
            $value = $item.$name
            if ($null -eq $value) { $value = '(unavailable)' }
            [void]$details.Append('<dt>' + (Encode $name) + '</dt><dd>' + (Encode $value) + '</dd>')
        }
        [void]$details.Append('</dl><ul>')
        foreach ($issue in @($Report.Issues | Where-Object ComputerName -eq $item.ComputerName)) {
            [void]$details.Append('<li>' + (Encode "$($issue.Kind) / $($issue.Area): $($issue.Message)") + '</li>')
        }
        [void]$details.Append('</ul></details>')
        $class = switch ($item.Assessment) { 'UpdatedReported' { 'reported' } 'CollectionFailed' { 'failed' } default { 'review' } }
        '<tr><td>' + (Encode $item.ComputerName) + '<br><small>' + (Encode $item.Description) +
            '</small></td><td>' + (Encode $item.CollectionStatus) + '</td><td class="' + $class + '">' +
            (Encode $item.Assessment) + '</td><td>' + (Encode $item.SecureBootEnabled) + '</td><td>' +
            (Encode $item.UEFICA2023Status) + '</td><td>' + (Encode $item.LatestEventId) + '</td><td>' +
            (Encode $item.Model) + '</td><td>' + $details.ToString() + '</td></tr>'
    }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secure Boot audit</title>
<style>
:root{color-scheme:light dark}body{font:15px system-ui;margin:2rem;line-height:1.5}h1{margin-bottom:.2rem}
.banner{padding:1rem;border:1px solid #718096;border-radius:8px}table{width:100%;border-collapse:collapse;margin-top:1rem}
th,td{text-align:left;vertical-align:top;padding:.65rem;border-bottom:1px solid #718096}th{white-space:nowrap}
input{padding:.6rem;min-width:20rem;margin-top:1rem}.reported{color:#2385ce}.failed{color:#d63939}.review{font-weight:600}
dt{font-weight:600}dd{margin:0 0 .4rem;overflow-wrap:anywhere}details{max-width:36rem}small{opacity:.8}.scroll{overflow:auto}
</style></head><body>
<h1>Secure Boot audit</h1><p>Collected: $(Encode $Report.StartedUtc) | Status: $(Encode $Report.Status)</p>
<div class="banner"><strong>$($Report.Computers.Count) computers | $($Report.ErrorCount) collection errors</strong>
<p>UpdatedReported = Secure Boot enabled, Windows status Updated and latest collected TPM-WMI event 1808, with no collection errors or recorded servicing error.
This is not firmware certificate attestation, workload validation or compliance.</p>
<p>Unknown/missing history is not success. ReviewRequired includes conflicting evidence or missing completion history.
Events: newest $($Report.MaxEvents) matching retained records per computer, not a 24-hour window. Check per-computer limits and notes.</p></div>
<p><a href="Computers.csv">Computers CSV</a> | <a href="Events.csv">Events CSV</a> | <a href="Issues.csv">Issues CSV</a> |
<a href="SecureBootAudit.json">Full JSON</a>. CSV files use semicolons. Keep these files together and protect the inventory.</p>
<label for="filter">Filter computers and evidence:</label><br><input id="filter" type="search" placeholder="Name, model, status, error...">
<p id="count" aria-live="polite"></p><div class="scroll"><table>
<thead><tr><th>Computer</th><th>Collection</th><th>Assessment</th><th>Secure Boot</th><th>Windows status</th><th>Latest event</th><th>Model</th><th>Details</th></tr></thead>
<tbody id="computers">$($rows -join "`n")</tbody></table></div>
<script>
const input = document.getElementById('filter');
const rows = Array.from(document.querySelectorAll('#computers > tr'));
function filterRows() {
  const term = input.value.toLowerCase();
  let visible = 0;
  for (const row of rows) {
    row.hidden = !row.textContent.toLowerCase().includes(term);
    if (!row.hidden) visible++;
  }
  document.getElementById('count').textContent = visible + ' / ' + rows.length + ' computers';
}
input.addEventListener('input', filterRows);
filterRows();
</script></body></html>
"@
    $htmlPath = Join-Path $Directory 'SecureBootAudit.html'
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding utf8 -ErrorAction Stop
    $htmlPath
}

function Invoke-SecureBootAuditRun {
    [CmdletBinding()]
    param(
        [string]$CsvPath, [pscredential]$Credential, [switch]$UseSSL,
        [ValidateRange(1,3600)][int]$TimeoutSeconds = 120,
        [ValidateRange(1,10000)][int]$MaxEvents = 50,
        [string]$OutputDir = (Join-Path $PSScriptRoot ('Outputs\SecureBootAudit_' + [guid]::NewGuid().ToString('N'))),
        [switch]$OpenReport
    )

    $targets = @(Import-SecureBootTargets -Path $CsvPath)
    if (-not $IsWindows) { throw 'Live WinRM collection requires a Windows reporting host.' }
    if ([string]::IsNullOrWhiteSpace($OutputDir)) { throw 'OutputDir must not be empty.' }
    if (Test-Path -LiteralPath $OutputDir -ErrorAction Stop) { throw 'OutputDir must be a new local directory.' }
    $directory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
    if ($directory.StartsWith('\\')) { throw 'OutputDir must be local, not a UNC share.' }
    $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $items = [Collections.Generic.List[object]]::new()
    $allIssues = [Collections.Generic.List[object]]::new()
    $started = [datetime]::UtcNow.ToString('o')
    foreach ($target in $targets) {
        Write-Verbose "Collecting $($target.ComputerName)"
        $data = $null
        $events = @()
        $issues = @()
        $collectionStatus = 'Failed'
        $assessment = 'CollectionFailed'
        try {
            $result = Invoke-SecureBootTarget -ComputerName $target.ComputerName -Credential $Credential -UseSSL:$UseSSL -TimeoutSeconds $TimeoutSeconds -MaxEvents $MaxEvents
            $data = $result.Data
            $events = @($result.Events)
            $issues = @($result.Issues)
            $errorCount = @($issues | Where-Object Kind -eq 'Error').Count
            $collectionStatus = if ($errorCount -gt 0) { 'Partial' } else { 'Collected' }
            $assessment = Get-SecureBootAssessment -Snapshot $data -ErrorCount $errorCount
        }
        catch {
            $collectionStatus = 'Failed'
            $assessment = 'CollectionFailed'
            $issues = @($issues) + @([pscustomobject]@{ Area = 'RemoteCollection'; Kind = 'Error'; Message = $_.Exception.Message })
        }
        $errorCount = @($issues | Where-Object Kind -eq 'Error').Count
        foreach ($issue in $issues) {
            $allIssues.Add([pscustomobject]@{ ComputerName = $target.ComputerName; Area = $issue.Area; Kind = $issue.Kind; Message = $issue.Message })
        }
        $items.Add([pscustomobject]@{
            ComputerName = $target.ComputerName; Description = $target.Description
            CollectionStatus = $collectionStatus; Assessment = $assessment; ErrorCount = $errorCount
            Data = $data; Events = $events
        })
    }
    $errorCount = @($allIssues | Where-Object Kind -eq 'Error').Count
    $dataColumns = @(
        'Hostname','CollectionTimeUtc','SecureBootEnabled','SecureBootSource','UEFICA2023Status','UEFICA2023Error','UEFICA2023ErrorEvent',
        'ConfigurationReadStatus','ServicingReadStatus','DeviceAttributesReadStatus','OSName','OSVersion','OSBuild','OSArchitecture','LastBootTimeUtc',
        'Manufacturer','Model','FirmwareVersion','FirmwareReleaseDate','BaseBoardManufacturer','BaseBoardProduct',
        'AvailableUpdates','AvailableUpdatesPolicy','HighConfidenceOptOut','MicrosoftUpdateManagedOptIn',
        'OEMManufacturerName','OEMModelSystemFamily','OEMModelNumber','CanAttemptUpdateAfter',
        'SecureBootTaskEnabled','SecureBootTaskStatus','EventReadStatus','EventLimit','EventLimitReached',
        'LatestEventId','LatestEventTimeUtc','BucketId','Confidence','SkipReason',
        'Event1795Count','Event1796Count','Event1800Count','Event1801Count','Event1802Count','Event1803Count','Event1808Count',
        'WinCSQueryStatus','WinCSQueryExitCode','WinCSQueryOutput'
    )
    $report = [pscustomobject]@{
        SchemaVersion = 1; CollectorVersion = '1.0.0'; StartedUtc = $started; CompletedUtc = [datetime]::UtcNow.ToString('o')
        Status = if ($errorCount -gt 0) { 'Partial' } else { 'Collected' }
        ErrorCount = $errorCount; MaxEvents = $MaxEvents; TimeoutSeconds = $TimeoutSeconds
        Transport = if ($UseSSL) { 'WinRM HTTPS' } else { 'WinRM HTTP' }
        DataColumns = $dataColumns; Computers = @($items.ToArray()); Issues = @($allIssues.ToArray())
    }
    $htmlPath = Export-SecureBootReport -Report $report -Directory $directory
    foreach ($issue in $report.Issues) { Write-Warning "$($issue.ComputerName) [$($issue.Kind)/$($issue.Area)]: $($issue.Message)" }
    Write-Host "Secure Boot report: $htmlPath"
    if ($OpenReport) { Invoke-Item -LiteralPath $htmlPath -ErrorAction Stop }
    [pscustomobject]@{
        Status = $report.Status; ComputerCount = $items.Count; ErrorCount = $errorCount
        HtmlPath = $htmlPath; JsonPath = (Join-Path $directory 'SecureBootAudit.json')
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{} + $PSBoundParameters
    $arguments.TimeoutSeconds = $TimeoutSeconds
    $arguments.MaxEvents = $MaxEvents
    $arguments.OutputDir = $OutputDir
    $result = Invoke-SecureBootAuditRun @arguments
    $result
    if ($result.ErrorCount -gt 0) { exit 1 }
    exit 0
}

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
    Version 1.0.1. PowerShell 7.2+ on the reporting host; Windows PowerShell
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
        if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { ,$Object.$Name }
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
        elseif ($_.Exception -is [PlatformNotSupportedException] -or
            $_.Exception.Message -match '\b0xC0000002\b') {
            $secureBootSource = 'UnsupportedPlatform'
            Add-InventoryIssue 'SecureBoot' 'Unsupported' $_.Exception.Message
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
    foreach ($name in 'OEMManufacturerName','OEMModelSystemFamily','OEMModelNumber') {
        $data[$name] = Read-InventoryValue $attributes.Values $name
    }
    $data.CanAttemptUpdateAfter = $null
    $data.CanAttemptUpdateAfterRaw = $null
    $value = Read-InventoryValue $attributes.Values 'CanAttemptUpdateAfter'
    if ($null -ne $value) {
        $data.CanAttemptUpdateAfterRaw = if ($value -is [byte[]]) {
            [BitConverter]::ToString($value)
        } else { ConvertTo-Json -InputObject $value -Compress }
        try {
            if ($value -is [byte[]]) {
                if ($value.Length -ne 8) { throw 'CanAttemptUpdateAfter REG_BINARY must contain exactly 8 FILETIME bytes.' }
                # Windows stores the FILETIME in little-endian order.
                $fileTime = [BitConverter]::ToInt64($value, 0)
            }
            elseif ($value -is [int] -or $value -is [long] -or $value -is [uint32] -or $value -is [uint64]) {
                $fileTime = [long]$value
            }
            else { throw "Unsupported CanAttemptUpdateAfter type: $($value.GetType().FullName)." }
            $data.CanAttemptUpdateAfter = [datetime]::FromFileTimeUtc($fileTime).ToString('o')
        }
        catch { Add-InventoryIssue 'CanAttemptUpdateAfter' 'Error' $_.Exception.Message }
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

    if ($ErrorCount -gt 0) { return 'Unknown' }
    if ($null -eq $Snapshot.SecureBootEnabled) {
        if ($Snapshot.SecureBootSource -eq 'UnsupportedPlatform') { return 'Unsupported' }
        return 'Unknown'
    }
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
    $received = @($Report.Computers | Where-Object { $null -ne $_.Data }).Count
    $disabled = @($Report.Computers | Where-Object { $null -ne $_.Data.SecureBootEnabled -and -not $_.Data.SecureBootEnabled }).Count
    $unsupported = @($Report.Computers | Where-Object { $_.Data.SecureBootSource -eq 'UnsupportedPlatform' }).Count
    $updated = @($Report.Computers | Where-Object Assessment -eq 'UpdatedReported').Count
    $issuesByComputer = @{}
    if ($Report.Issues.Count -gt 0) { $issuesByComputer = $Report.Issues | Group-Object ComputerName -AsHashTable -AsString }
    $diagnostics = [Collections.Generic.List[string]]::new()
    $rows = foreach ($record in $Report.Computers) {
        $item = $record.Data
        $label, $tone, $action = switch ($record.Assessment) {
            'UpdatedReported' { 'Update reported'; 'reported'; 'Validate boot, applications and recovery before expanding.' }
            'ReviewRequired' { 'Review evidence'; 'warning'; 'Review servicing errors and latest events; confirm completion evidence.' }
            'RestartIndicated' { 'Restart indicated'; 'warning'; 'Arrange an approved restart, then collect again.' }
            'InProgress' { 'Update in progress'; 'neutral'; 'Allow the approved rollout to progress, then collect again.' }
            'NotStarted' { 'Not started'; 'neutral'; 'Check prerequisites and rollout policy before scheduling a pilot.' }
            'Disabled' { 'Secure Boot disabled'; 'warning'; 'Review UEFI/Secure Boot configuration. Enabling it is a separate approved change.' }
            'Unsupported' { 'Platform unsupported'; 'warning'; 'Check firmware mode and platform/VM generation. An unsupported check does not prove Secure Boot is disabled.' }
            'CollectionFailed' { 'Collection failed'; 'danger'; 'Review the collection error. If no inventory returned, check DNS, WinRM and account access, then rerun.' }
            default { 'Unknown state'; 'warning'; 'Resolve read errors or missing evidence, then rerun. Missing data is not success.' }
        }
        $notes = @()
        if ($issuesByComputer.ContainsKey($record.ComputerName)) { $notes = @($issuesByComputer[$record.ComputerName]) }
        $importantNotes = @($notes | Where-Object { $_.Kind -in 'Error','Unsupported' })
        $noteHtml = foreach ($issue in $importantNotes) {
            '<li><strong>' + (Encode "$($issue.Kind) / $($issue.Area)") + '</strong>: ' + (Encode $issue.Message) + '</li>'
        }
        if ($record.Assessment -notin 'UpdatedReported','InProgress','NotStarted' -or $importantNotes.Count -gt 0) {
            $diagnostics.Add('<article class="diagnostic ' + $tone + '"><div class="section-heading"><h3>' +
                (Encode $record.ComputerName) + '</h3><span class="badge ' + $tone + '">' + (Encode $label) +
                '</span></div><p>' + (Encode $action) + '</p><ul class="issue-list">' + ($noteHtml -join '') + '</ul></article>')
        }
        $details = [Text.StringBuilder]::new()
        [void]$details.Append('<details><summary>Technical evidence</summary><dl>')
        foreach ($name in $Report.DataColumns) {
            $value = $item.$name
            if ($null -eq $value) { $value = 'Unavailable' }
            [void]$details.Append('<dt>' + (Encode $name) + '</dt><dd>' + (Encode $value) + '</dd>')
        }
        [void]$details.Append('</dl><h4>Collection notes</h4><ul class="issue-list">')
        foreach ($issue in $notes) {
            [void]$details.Append('<li>' + (Encode "$($issue.Kind) / $($issue.Area): $($issue.Message)") + '</li>')
        }
        if ($notes.Count -eq 0) { [void]$details.Append('<li>No collection notes.</li>') }
        [void]$details.Append('</ul></details>')
        $remote = if ($null -ne $item) { '<span class="badge reported">Data received</span>' } else { '<span class="badge danger">No inventory</span>' }
        $reads = switch ($record.CollectionStatus) {
            'Collected' { 'Reads completed' }
            'Partial' { 'Partial reads' }
            default { 'Collection failed' }
        }
        $bootLabel = if ($null -eq $item.SecureBootEnabled) {
            if ($item.SecureBootSource -eq 'UnsupportedPlatform') { 'Unsupported' } else { 'Unknown' }
        } elseif ($item.SecureBootEnabled) { 'Enabled' } else { 'Disabled' }
        $bootTone = if ($bootLabel -eq 'Enabled') { 'reported' } else { 'warning' }
        $windowsState = if ([string]::IsNullOrWhiteSpace($item.UEFICA2023Status)) { 'Unknown' } else { $item.UEFICA2023Status }
        $servicingError = if ($null -ne $item.UEFICA2023Error -and $item.UEFICA2023Error -ne 0) {
            '<small class="error-text">Servicing error: ' + (Encode $item.UEFICA2023Error) + '</small>'
        } else { '' }
        $eventLabel = if ($null -ne $item.LatestEventId) { Encode $item.LatestEventId } else { 'No evidence' }
        $model = if ([string]::IsNullOrWhiteSpace($item.Model)) { 'Model unavailable' } else { $item.Model }
        '<tr data-assessment="' + (Encode $record.Assessment) + '" data-boot="' + $bootLabel + '" data-errors="' + $record.ErrorCount +
            '"><td><strong>' + (Encode $record.ComputerName) + '</strong><small>' + (Encode $record.Description) +
            '</small><small>' + (Encode $model) + '</small></td><td>' + $remote + '<small>' + (Encode $reads) +
            ' / ' + $record.ErrorCount + ' errors</small></td><td><span class="badge ' + $bootTone + '">' +
            (Encode $bootLabel) + '</span><small>' + (Encode $item.SecureBootSource) + '</small></td><td>' +
            (Encode $windowsState) + $servicingError + '</td><td>' + $eventLabel + '<small>' +
            (Encode $item.LatestEventTimeUtc) + '</small></td><td class="action"><span class="badge ' + $tone +
            '" title="' + (Encode $record.Assessment) + '">' + (Encode $label) + '</span><p>' +
            (Encode $action) + '</p>' + $details.ToString() + '</td></tr>'
    }
    $diagnosticHtml = if ($diagnostics.Count -gt 0) { $diagnostics -join "`n" } else {
        '<p class="muted">No collection errors or immediate review findings. Check pending updates in the inventory below; this is not a compliance verdict.</p>'
    }
    $statusLabel = if ($Report.ErrorCount -gt 0) { 'Collection needs attention' } else { 'Collection completed' }
    $errorTone = if ($Report.ErrorCount -gt 0) { 'danger' } else { 'reported' }
    $disabledTone = if ($disabled -gt 0) { 'warning' } else { 'reported' }
    $unsupportedTone = if ($unsupported -gt 0) { 'warning' } else { 'reported' }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark"><title>Secure Boot audit</title>
<style>
:root{color-scheme:dark;--bg:#09111f;--card:#111e32;--border:#2a405d;--text:#e3edf9;--muted:#a3b5ce;--accent:#78c7ff;--warning:#f0c45c;--danger:#ff9393}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth}
body{margin:0;background:radial-gradient(ellipse at top,#163254,var(--bg) 42%);color:var(--text);font:14px/1.6 'Segoe UI',system-ui,sans-serif}
.container{max-width:1520px;margin:auto;padding:2rem}h1,h2,h3,p{margin:0}h1{font-size:clamp(1.9rem,4vw,2.8rem);line-height:1.15;letter-spacing:-.03em}h2{font-size:1.25rem}h3{font-size:1rem}
a{color:var(--accent)}a:focus-visible,summary:focus-visible,input:focus-visible,select:focus-visible,button:focus-visible,.scroll:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.hero{padding:2rem;border:1px solid #365a7b;border-radius:20px;background:linear-gradient(120deg,#193a5a,#102336);box-shadow:0 20px 60px #0003}
.eyebrow{color:var(--accent);font-size:.75rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase}.section-heading{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.7rem;margin-bottom:.6rem}.hero .section-heading{margin:.5rem 0 1rem}
.muted,small{color:var(--muted)}.metadata{margin-top:1.2rem;padding-top:1rem;border-top:1px solid #ffffff20;overflow-wrap:anywhere;font-size:.82rem}.metadata span+span{margin-left:1rem}
.nav,.export-links{display:flex;flex-wrap:wrap;gap:.6rem;margin:1.2rem 0}.nav a,.export-links a,button{padding:.45rem .85rem;border:1px solid var(--border);border-radius:8px;text-decoration:none;background:#14243a;color:var(--accent);font:inherit;cursor:pointer}.nav a:hover,.export-links a:hover,button:hover{background:#203d59}
.metrics{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.8rem;margin:1.2rem 0}.metric{min-width:0;padding:1.1rem;background:var(--card);border:1px solid var(--border);border-top:3px solid var(--accent);border-radius:12px}
.metric.warning{border-top-color:var(--warning)}.metric.danger{border-top-color:var(--danger)}.metric-label{color:var(--muted);font-size:.73rem;text-transform:uppercase;letter-spacing:.05em}.metric-value{font-size:2rem;line-height:1.3;margin:.35rem 0;color:var(--accent)}.metric.warning .metric-value{color:var(--warning)}.metric.danger .metric-value{color:var(--danger)}.metric-note{font-size:.78rem;color:var(--muted)}
.notice{padding:1rem 1.2rem;border:1px solid #365a7b;border-left:4px solid var(--accent);border-radius:10px;background:#102336;margin:1.2rem 0}.notice p{margin-top:.4rem;color:var(--muted)}
.card{min-width:0;padding:1.4rem;background:var(--card);border:1px solid var(--border);border-radius:14px;margin:1.2rem 0}.section-intro{font-size:.86rem;color:var(--muted);margin-bottom:1rem}
.diagnostics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem}.diagnostic{min-width:0;padding:1rem;background:#0d192b;border:1px solid var(--border);border-left:3px solid var(--warning);border-radius:9px;overflow-wrap:anywhere}.diagnostic.danger{border-left-color:var(--danger)}.diagnostic p,.issue-list{font-size:.85rem}.issue-list{padding-left:1.2rem;margin:.5rem 0 0;overflow-wrap:anywhere}.issue-list:empty{display:none}.issue-list li+li{margin-top:.5rem}
.badge{display:inline-block;padding:.18rem .6rem;border:1px solid #396183;border-radius:999px;font-size:.74rem;font-weight:600;background:#173650;color:#a6ddff;white-space:nowrap}
.badge.warning{background:#3a3018;border-color:#73602e;color:#ffe091}.badge.danger{background:#3d242d;border-color:#824455;color:#ffb5b5}.badge.neutral{background:#1b2b40;border-color:#415772;color:#c4d2e6}.error-text{color:var(--danger)}
.table-tools{display:flex;flex-wrap:wrap;align-items:end;gap:.8rem;margin:1rem 0}.table-tools label{display:flex;flex-direction:column;gap:.25rem;color:var(--muted);font-size:.8rem}.search-label{flex:1 1 220px}
input,select{min-width:0;max-width:100%;padding:.55rem .7rem;border:1px solid #446080;border-radius:7px;background:#0b1728;color:var(--text);font:inherit}.table-tools button{padding:.5rem .85rem}.table-count{font-size:.8rem;color:var(--muted)}
.scroll{overflow:auto;max-height:42rem;border:1px solid var(--border);border-radius:9px;overscroll-behavior:contain}
table{width:100%;min-width:1050px;border-collapse:separate;border-spacing:0;font-size:.82rem}th{position:sticky;top:0;z-index:1;background:#20354e;color:#c4e7ff;padding:.8rem;text-align:left;white-space:nowrap;border-bottom:1px solid #47617f}
td{padding:.85rem;vertical-align:top;border-bottom:1px solid #ffffff0c;min-width:8rem;max-width:20rem;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}tbody tr:nth-child(even){background:#ffffff03}tbody tr:hover{background:#78c7ff08}small{display:block;font-size:.75rem;margin-top:.35rem}.action{min-width:20rem;max-width:30rem}.action p{font-size:.8rem;margin-top:.5rem}
details{margin-top:.8rem;border-top:1px solid var(--border);padding-top:.6rem}summary{cursor:pointer;color:var(--accent);font-size:.8rem;font-weight:600}dl{font-size:.78rem}dt{font-weight:600;color:#c4e7ff;overflow-wrap:anywhere}dd{margin:0 0 .6rem;color:var(--muted);overflow-wrap:anywhere}h4{margin:.8rem 0 .3rem}
.reading-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}.reading-grid p{margin-top:.4rem;font-size:.85rem;color:var(--muted)}.footer{text-align:center;color:var(--muted);font-size:.78rem;padding:1rem}.empty-state{padding:1rem;color:var(--muted)}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:760px){.container{padding:1rem}.hero{padding:1.3rem}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.diagnostics,.reading-grid{grid-template-columns:1fr}.card{padding:1rem}.metadata span{display:block}.metadata span+span{margin-left:0}.table-tools{align-items:stretch;flex-direction:column}.search-label{flex:initial}.badge{white-space:normal}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:white;color:#111}.container{max-width:none;padding:0}.hero,.card,.metric,.notice,.diagnostic{background:white;color:#111;box-shadow:none;border-color:#aaa}.nav,.table-tools,.export-links{display:none}.metrics{grid-template-columns:repeat(3,1fr)}.metric-value,.metric-label,.metric-note,.muted,.section-intro,.metadata,small,.notice p,.reading-grid p{color:#222!important}.scroll{max-height:none;overflow:visible}table{min-width:0;font-size:8pt}th{position:static;background:#eee;color:#111}td,.action{min-width:0;max-width:none;padding:.3rem}.badge{background:white!important;color:#111!important;border-color:#888!important}.diagnostics{grid-template-columns:1fr}}
</style></head><body><main class="container">
<header class="hero" id="overview">
<p class="eyebrow">Certificate renewal / read-only inventory</p>
<div class="section-heading"><h1>Secure Boot audit</h1><span class="badge $errorTone">$(Encode $statusLabel)</span></div>
<p class="muted">See what answered, what Windows reports, and what needs attention before your next rollout step.</p>
<div class="metadata"><span>Collected: $(Encode $Report.StartedUtc)</span><span>$(Encode $Report.Transport)</span><span>Collector $(Encode $Report.CollectorVersion)</span></div>
</header>
<nav class="nav" aria-label="Report sections"><a href="#attention">Needs attention</a><a href="#inventory">Computer inventory</a><a href="#reading">How to read this</a><a href="#exports">Exports</a></nav>
<section class="metrics" aria-label="Fleet overview">
<div class="metric"><p class="metric-label">Requested</p><p class="metric-value">$($Report.Computers.Count)</p><p class="metric-note">Every CSV target is retained</p></div>
<div class="metric"><p class="metric-label">Data received</p><p class="metric-value">$received</p><p class="metric-note">Remote inventory returned</p></div>
<div class="metric $errorTone"><p class="metric-label">Collection errors</p><p class="metric-value">$($Report.ErrorCount)</p><p class="metric-note">Read or remote errors, not devices</p></div>
<div class="metric $disabledTone"><p class="metric-label">Secure Boot disabled</p><p class="metric-value">$disabled</p><p class="metric-note">Explicit False, not unknown</p></div>
<div class="metric $unsupportedTone"><p class="metric-label">Unsupported check</p><p class="metric-value">$unsupported</p><p class="metric-note">Platform limitation, not WinRM</p></div>
<div class="metric"><p class="metric-label">Update reported</p><p class="metric-value">$updated</p><p class="metric-note">Windows evidence, not attestation</p></div>
</section>
<aside class="notice"><strong>$received / $($Report.Computers.Count) returned inventory</strong>
<p>$($Report.Computers.Count - $received) target(s) returned no usable inventory. A partial read or unsupported platform does not mean WinRM failed. Read the actual error before changing connectivity.</p></aside>
<section class="card" id="attention"><div class="section-heading"><h2>Needs attention</h2><span class="badge warning">$($diagnostics.Count) computers to review</span></div>
<p class="section-intro">Start here. Collection errors and unsupported checks are shown directly; all other notes remain in each computer's technical evidence.</p>
<div class="diagnostics">$diagnosticHtml</div></section>
<section class="card" id="inventory"><h2>Computer inventory</h2>
<p class="section-intro">Connection, Secure Boot and certificate rollout are separate signals. Filters below affect this table only, not the fleet totals above.</p>
<div class="table-tools">
<label class="search-label" for="filter">Search computers and evidence<input id="filter" type="search" placeholder="Name, model, status, error..."></label>
<label for="state">Show<select id="state"><option value="">All computers</option><option value="attention">Needs review</option><option value="errors">Collection errors</option><option value="Unsupported">Platform unsupported</option><option value="Disabled">Secure Boot disabled</option><option value="UpdatedReported">Update reported</option><option value="NotStarted">Not started</option><option value="InProgress">In progress</option></select></label>
<button id="reset" type="button">Reset filters</button><span id="count" class="table-count" aria-live="polite"></span></div>
<div class="scroll" tabindex="0" role="region" aria-label="Scrollable computer inventory"><table>
<thead><tr><th scope="col">Computer / model</th><th scope="col">Remote / reads</th><th scope="col">Secure Boot</th><th scope="col">Windows status</th><th scope="col">Latest event (UTC)</th><th scope="col">Assessment / next step</th></tr></thead>
<tbody id="computers">$($rows -join "`n")</tbody></table></div><p id="empty" class="empty-state" hidden>No computers match these filters.</p></section>
<section class="card" id="reading"><h2>How to read this</h2><div class="reading-grid">
<div><h3>1. Check collection</h3><p>Data received means the remote payload answered. Partial reads mean individual checks failed. No inventory means remote collection failed; inspect the error.</p></div>
<div><h3>2. Check the platform</h3><p>Disabled is a measured Secure Boot state. Unsupported means the platform cannot answer that check without a reliable fallback. Do not equate it with Disabled.</p></div>
<div><h3>3. Check renewal evidence</h3><p>Update reported (UpdatedReported) requires Secure Boot enabled, Windows Updated, latest collected event 1808 and no collection or servicing error. This is not firmware certificate attestation, workload validation or compliance.</p></div>
</div><p class="section-intro" style="margin-top:1rem">Events: newest $($Report.MaxEvents) matching retained System / TPM-WMI records per computer, not a 24-hour window. Missing history is not success; review event limits in technical evidence.</p></section>
<section class="card" id="exports"><h2>Take the evidence with you</h2><div class="export-links">
<a href="Computers.csv" download>Computers CSV</a><a href="Events.csv" download>Events CSV</a><a href="Issues.csv" download>Issues CSV</a><a href="SecureBootAudit.json" download>Full JSON</a></div>
<p class="section-intro">CSV files use semicolons. Keep exports beside this HTML and protect the infrastructure inventory. The report works offline; no external resources are loaded.</p></section>
<footer class="footer">Read-only collection. No certificate, policy, scheduled-task or reboot changes.</footer>
</main>
<script>
const input = document.getElementById('filter');
const state = document.getElementById('state');
const rows = Array.from(document.querySelectorAll('#computers > tr'));
function filterRows() {
  const term = input.value.trim().toLowerCase();
  let visible = 0;
  for (const row of rows) {
    const assessment = row.dataset.assessment;
    const matchesState = !state.value ||
      (state.value === 'attention' && !['UpdatedReported', 'InProgress', 'NotStarted'].includes(assessment)) ||
      (state.value === 'errors' && Number(row.dataset.errors) > 0) ||
      (['Disabled', 'Unsupported'].includes(state.value) && row.dataset.boot === state.value) ||
      state.value === assessment;
    row.hidden = !matchesState || !row.textContent.toLowerCase().includes(term);
    if (!row.hidden) visible++;
  }
  document.getElementById('count').textContent = visible + ' / ' + rows.length + ' computers';
  document.getElementById('empty').hidden = visible !== 0;
}
input.addEventListener('input', filterRows);
state.addEventListener('change', filterRows);
document.getElementById('reset').addEventListener('click', () => {
  input.value = '';
  state.value = '';
  filterRows();
});
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
        'OEMManufacturerName','OEMModelSystemFamily','OEMModelNumber','CanAttemptUpdateAfter','CanAttemptUpdateAfterRaw',
        'SecureBootTaskEnabled','SecureBootTaskStatus','EventReadStatus','EventLimit','EventLimitReached',
        'LatestEventId','LatestEventTimeUtc','BucketId','Confidence','SkipReason',
        'Event1795Count','Event1796Count','Event1800Count','Event1801Count','Event1802Count','Event1803Count','Event1808Count',
        'WinCSQueryStatus','WinCSQueryExitCode','WinCSQueryOutput'
    )
    $report = [pscustomobject]@{
        SchemaVersion = 1; CollectorVersion = '1.0.1'; StartedUtc = $started; CompletedUtc = [datetime]::UtcNow.ToString('o')
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

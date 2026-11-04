#Requires -Version 7.2
<#
.SYNOPSIS
    Read-only NTLM evidence collection and HTML/CSV/JSON reporting.
.DESCRIPTION
    Queries explicitly named Windows computers or all DCs in one domain through
    WinRM, or analyzes exported event XML offline. Collects enhanced NTLM/Security-
    Netlogon, classic NTLM and explicitly identified Security evidence.
    Never enables logging or changes policy.
.PARAMETER ComputerName
    Explicit computers to query. Use localhost for local collection without WinRM.
.PARAMETER AllDomainControllers
    Discover all DCs, including RODCs, in one domain. Requires the ActiveDirectory
    module on the reporting host. Cannot be combined with ComputerName or EventXmlPath.
.PARAMETER Domain
    Domain DNS name for DC discovery. Requires AllDomainControllers.
    If omitted, uses the ActiveDirectory module's default domain context.
.PARAMETER EventXmlPath
    Offline XML files containing an Event root or an Events root with Event children.
.PARAMETER StartTime
    Inclusive observation start, with offset. Default: 24 hours ago.
.PARAMETER EndTime
    Inclusive observation end, with offset. Default: now.
.PARAMETER MaxEventsPerSource
    Live collection limit per computer/provider/channel. Default: 10000.
    One additional event is requested to detect truncation.
.PARAMETER Credential
    Optional credential for remote collection and DC discovery when requested.
    Not used for local collection.
.PARAMETER OutputDir
    New local output directory. Existing directories are rejected.
.PARAMETER OpenReport
    Open the HTML report after writing all outputs.
.EXAMPLE
    .\Invoke-NtlmAudit.ps1 -ComputerName workstation01,app01,dc01 -OpenReport
.EXAMPLE
    .\Invoke-NtlmAudit.ps1 -AllDomainControllers -OpenReport
.EXAMPLE
    .\Invoke-NtlmAudit.ps1 -AllDomainControllers -Domain example.test -Credential (Get-Credential)
.EXAMPLE
    .\Invoke-NtlmAudit.ps1 -EventXmlPath .\events.xml -StartTime '2026-11-01T00:00:00Z' -EndTime '2026-11-04T00:00:00Z'
.NOTES
    PowerShell 7.2+ on the reporting host; Windows PowerShell 5.1-compatible
    collection on Windows targets. The ActiveDirectory module is required only
    for AllDomainControllers; explicit targets and offline analysis do not need it.
    Reports contain account, process and network information. Protect the outputs.
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName,

    [Parameter(Mandatory, ParameterSetName = 'DomainControllers')]
    [switch]$AllDomainControllers,

    [Parameter(ParameterSetName = 'DomainControllers')]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('\S')]
    [string]$Domain,

    [Parameter(Mandatory, ParameterSetName = 'Xml')]
    [ValidateNotNullOrEmpty()]
    [string[]]$EventXmlPath,

    [datetimeoffset]$StartTime = [datetimeoffset]::Now.AddDays(-1),
    [datetimeoffset]$EndTime = [datetimeoffset]::Now,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'DomainControllers')]
    [ValidateRange(1, 1000000)]
    [int]$MaxEventsPerSource = 10000,

    [Parameter(ParameterSetName = 'Live')]
    [Parameter(ParameterSetName = 'DomainControllers')]
    [pscredential]$Credential,

    [string]$OutputDir = (Join-Path $PSScriptRoot ('Outputs\NtlmAudit_{0}_{1}' -f
        (Get-Date -Format 'yyyyMMdd_HHmmssfff'), [guid]::NewGuid().ToString('N').Substring(0, 8))),

    [switch]$OpenReport
)

function Get-NtlmReason {
    param([AllowNull()][string]$Id)

    $reasons = @{
        '0' = @('Unknown reason', 'Correlate the process, target and authentication evidence.')
        '1' = @('NTLM called directly', 'Review supported authentication APIs/configuration with the application owner.')
        '2' = @('Local account', 'Confirm the identity design; do not assume domain Kerberos is a replacement.')
        '3' = @('Reserved', 'Preserve the value; no cause is assigned.')
        '4' = @('Cloud account', 'Identify the identity/application flow and its supported authentication methods.')
        '5' = @('Missing target name', 'Inspect the target name supplied by the calling application.')
        '6' = @('Target not resolved by Kerberos or other protocols', 'Investigate service naming, DNS, SPNs and connectivity.')
        '7' = @('Target contains an IP address', 'Test a supported DNS/service name and correct SPN.')
        '8' = @('Duplicate target in Active Directory', 'Identify the legitimate name/SPN owner before correcting duplicates.')
        '9' = @('No line of sight to a domain controller', 'Verify DNS, routing, firewall rules and DC reachability.')
        '10' = @('Loopback', 'Qualify the local application flow separately.')
        '11' = @('Null session', 'Separate anonymous activity from credential-bearing authentication.')
    }
    if ($null -ne $Id -and $reasons.ContainsKey($Id)) {
        return [pscustomobject]@{ Description = $reasons[$Id][0]; Investigation = $reasons[$Id][1] }
    }
    [pscustomobject]@{
        Description = 'Not established'
        Investigation = 'Correlate the available evidence; no client selection reason has been established.'
    }
}

function Read-NtlmXml {
    param([Parameter(Mandatory)][string]$Text)

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $inputReader = [System.IO.StringReader]::new($Text)
    $reader = [System.Xml.XmlReader]::Create($inputReader, $settings)
    try {
        $document = [System.Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        return ,$document
    }
    finally {
        $reader.Dispose()
        $inputReader.Dispose()
    }
}

function Convert-NtlmAuditEvent {
    param([Parameter(Mandatory)][string]$Xml)

    $document = Read-NtlmXml -Text $Xml
    $event = $document.DocumentElement
    if ($event.LocalName -ne 'Event') { throw 'Expected an Event XML root.' }
    $system = $event.SelectSingleNode("*[local-name()='System']")
    if ($null -eq $system) { throw 'Event XML has no System element.' }
    $providerNode = $system.SelectSingleNode("*[local-name()='Provider']")
    $idNode = $system.SelectSingleNode("*[local-name()='EventID']")
    $timeNode = $system.SelectSingleNode("*[local-name()='TimeCreated']")
    $computerNode = $system.SelectSingleNode("*[local-name()='Computer']")
    $channelNode = $system.SelectSingleNode("*[local-name()='Channel']")
    $recordNode = $system.SelectSingleNode("*[local-name()='EventRecordID']")
    if ($null -eq $providerNode -or $null -eq $idNode -or $null -eq $timeNode -or
        $null -eq $computerNode -or $null -eq $channelNode -or $null -eq $recordNode) {
        throw 'Event XML is missing required provenance fields.'
    }
    $provider = $providerNode.GetAttribute('Name')
    $id = [int]$idNode.InnerText
    $channel = $channelNode.InnerText
    $sourceComputer = $computerNode.InnerText
    if ([string]::IsNullOrWhiteSpace($sourceComputer)) { throw 'Event Computer is empty.' }
    $time = [datetimeoffset]::Parse($timeNode.GetAttribute('SystemTime'), [cultureinfo]::InvariantCulture)
    $recordId = [long]$recordNode.InnerText
    $versionNode = $system.SelectSingleNode("*[local-name()='Version']")
    $version = if ($null -eq $versionNode) { 0 } else { [int]$versionNode.InnerText }
    $levelNode = $system.SelectSingleNode("*[local-name()='Level']")
    $level = if ($null -eq $levelNode) { $null } else { $levelNode.InnerText }

    $enhancedClient = $provider -eq 'Microsoft-Windows-NTLM' -and $id -in 4020,4021
    $enhancedServer = $provider -eq 'Microsoft-Windows-NTLM' -and $id -in 4022,4023
    $enhancedDc = $provider -eq 'Microsoft-Windows-Security-Netlogon' -and $id -in 4030,4031,4032,4033
    $classic = ($provider -eq 'Microsoft-Windows-NTLM' -and $id -in 8001,8002,8003) -or
        ($provider -eq 'Microsoft-Windows-Security-Netlogon' -and $id -eq 8004)
    $security = $provider -eq 'Microsoft-Windows-Security-Auditing' -and $id -in 4624,4625,4776
    if (-not ($enhancedClient -or $enhancedServer -or $enhancedDc -or $classic -or $security)) { return }
    if (($security -and $channel -ne 'Security') -or
        (-not $security -and $channel -ne 'Microsoft-Windows-NTLM/Operational')) {
        throw "Unexpected channel '$channel' for $provider/$id."
    }

    $fields = [ordered]@{}
    $index = 0
    foreach ($node in $event.SelectNodes("*[local-name()='EventData']/*[local-name()='Data']")) {
        $name = $node.GetAttribute('Name')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = "#Unnamed$index" }
        if ($fields.Contains($name)) { throw "Duplicate XML data field '$name'." }
        $fields[$name] = $node.InnerText
        $index++
    }
    if ($security -and $id -in 4624,4625 -and $fields['AuthenticationPackageName'] -ne 'NTLM') { return }

    $point = 'ResourceServer'
    $family = 'Classic'
    $accountName = $null
    $accountDomain = $null
    $client = $null
    $clientIp = $null
    $target = $null
    $targetDomain = $null
    $targetIp = $null
    $targetService = $null
    $localProcess = $fields['ProcessName']
    $processId = $null
    $rawVersion = $null
    $reasonId = $null
    $status = $null
    $result = 'Not established'
    $warnings = [System.Collections.Generic.List[string]]::new()

    if ($enhancedClient -or $enhancedServer) {
        $family = 'Enhanced'
        $accountName = $fields['Username']
        $accountDomain = $fields['DomainName']
        $target = $fields['TargetMachine']
        $targetDomain = $fields['TargetDomain']
        $rawVersion = $fields['NtlmVersion']
        $processId = $fields['ProcessPID']
        if ($enhancedClient) {
            $point = 'Client'
            $client = $fields['Hostname']
            $targetIp = $fields['TargetIP']
            $targetService = $fields['TargetService']
            $reasonId = $fields['NtlmUsageId']
            $result = 'Attempt'
        }
        else {
            $client = $fields['RemoteClientMachine']
            $clientIp = $fields['ClientIP']
            $status = $fields['Status']
        }
    }
    elseif ($enhancedDc) {
        $family = 'Enhanced'
        $point = 'DomainController'
        $accountName = $fields['AccountName']
        $accountDomain = $fields['AccountDomain']
        $client = $fields['AccountMachine']
        $target = $fields['ServerName']
        $targetDomain = $fields['ServerDomain']
        $targetIp = $fields['ServerIP']
        $rawVersion = $fields['NtlmVersion']
        $status = $fields['Status']
    }
    elseif ($security) {
        $family = 'Security'
        if ($id -eq 4776) {
            $point = 'CredentialAuthority'
            $accountName = $fields['TargetUserName']
            $client = $fields['Workstation']
            $localProcess = $null
            $status = $fields['Status']
        }
        else {
            $accountName = $fields['TargetUserName']
            $accountDomain = $fields['TargetDomainName']
            $client = $fields['WorkstationName']
            $clientIp = $fields['IpAddress']
            $target = $sourceComputer
            $rawVersion = $fields['LmPackageName']
            $processId = $fields['ProcessId']
            if ($id -eq 4624) { $result = 'LogonSuccess' }
            else { $result = 'LogonFailure'; $status = $fields['Status'] }
        }
    }
    else {
        $processId = $fields['CallerPID']
        if ($id -eq 8001) {
            $point = 'Client'
            $accountName = $fields['UserName']
            $accountDomain = $fields['DomainName']
            $client = $sourceComputer
            $targetService = $fields['TargetName']
        }
        elseif ($id -eq 8002) {
            $accountName = $fields['ClientUserName']
            $accountDomain = $fields['ClientDomainName']
        }
        elseif ($id -eq 8003) {
            $accountName = $fields['UserName']
            $accountDomain = $fields['DomainName']
            $client = $fields['Workstation']
            $target = $sourceComputer
        }
        else {
            $point = 'DomainController'
            $accountName = $fields['UserName']
            $accountDomain = $fields['DomainName']
            $client = $fields['WorkstationName']
        }
    }

    if ($null -ne $status -and $result -eq 'Not established') {
        $statusText = ([string]$status).Trim()
        $code = [uint32]0
        $parsed = if ($statusText -match '^0x[0-9a-fA-F]+$') {
            [uint32]::TryParse($statusText.Substring(2), [Globalization.NumberStyles]::HexNumber,
                [cultureinfo]::InvariantCulture, [ref]$code)
        }
        else { [uint32]::TryParse($statusText, [ref]$code) }
        if ($parsed) {
            $result = if ($code -eq 0) { 'ProcessingSuccess' } else { 'ProcessingFailure' }
        }
        else { $warnings.Add('Unrecognized status code; raw value retained.') }
    }
    $ntlmVersion = 'Unknown'
    if ($null -ne $rawVersion) {
        switch -Regex (([string]$rawVersion) -replace '\s', '') {
            '^NTLMV1$' { $ntlmVersion = 'NTLMv1'; break }
            '^NTLMV2$' { $ntlmVersion = 'NTLMv2'; break }
            '^LM$' { $ntlmVersion = 'LM'; break }
        }
    }
    if ($fields['TargetUserSid'] -eq 'S-1-5-7' -or
        $accountName -eq 'ANONYMOUS LOGON' -or $reasonId -eq '11') {
        $ntlmVersion = 'Unknown'
        $warnings.Add('Anonymous/null-session evidence is not proof of a credential-bearing NTLMv1 exchange.')
    }
    if ($family -eq 'Enhanced' -and $version -ne 0) {
        $warnings.Add('Enhanced event version is not a verified v0 schema; inspect raw XML.')
    }
    $reason = Get-NtlmReason -Id $reasonId
    $key = @($sourceComputer, $provider, $channel, $recordId, $id, $version, $time.UtcDateTime.ToString('o'))
    $hashBytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $key -Compress))
    $evidenceId = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($hashBytes))
    [pscustomobject][ordered]@{
        EvidenceId = $evidenceId
        TimeUtc = $time.UtcDateTime.ToString('o')
        SourceComputer = $sourceComputer
        Provider = $provider
        Channel = $channel
        EventId = $id
        EventVersion = $version
        RecordId = $recordId
        Level = $level
        EventFamily = $family
        ObservationPoint = $point
        AccountDomain = $accountDomain
        AccountName = $accountName
        ClientName = $client
        ClientIP = $clientIp
        TargetName = $target
        TargetDomain = $targetDomain
        TargetIP = $targetIp
        TargetService = $targetService
        InitiatingProcess = $(if ($point -eq 'Client') { $localProcess } else { $null })
        LocalProcess = $localProcess
        ProcessId = $processId
        NtlmVersion = $ntlmVersion
        RawNtlmVersion = $rawVersion
        ReasonId = $reasonId
        ReasonDescription = $reason.Description
        RawReason = $fields['NtlmUsageReason']
        Investigation = $reason.Investigation
        AuthenticationResult = $result
        RawStatus = $status
        RawStatusMessage = $fields['StatusMsg']
        ChannelBindingStatus = $fields['ChannelBindingStatus']
        MicStatus = $fields['Mic Status']
        SessionKeyStatus = $fields['SessionKeyStatus']
        NegotiatedFlags = $fields['NegotiatedFlags']
        ServiceBinding = $fields['ServiceBinding']
        AvFlags = $(if ($fields.Contains('AvFlags')) { $fields['AvFlags'] } else { $fields['AvlFlags'] })
        AvFlagsText = $(if ($fields.Contains('AvFlagsStr')) { $fields['AvFlagsStr'] } else { $fields['AvlFlagsStr'] })
        ForwarderName = $fields['ForwarderName']
        ForwarderDomain = $fields['ForwarderDomain']
        ForwarderIP = $fields['ForwarderIP']
        ParsingWarnings = @($warnings.ToArray())
        RawFields = $fields
        RawXml = $event.OuterXml
    }
}

function Get-NtlmSourceData {
    param([datetime]$StartUtc, [datetime]$EndUtc, [int]$Limit)

    # This function is also the WinRM payload and must remain Windows PowerShell 5.1 compatible.
    $metadataErrors = New-Object 'System.Collections.Generic.List[string]'
    $osName = $null
    $build = $null
    $domainRole = $null
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $osName = $os.Caption
        $build = $os.BuildNumber
        $domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).DomainRole
    }
    catch { $metadataErrors.Add("OS/role metadata: $($_.Exception.Message)") }

    $profiles = @(
        @{ Log = 'Microsoft-Windows-NTLM/Operational'; Provider = 'Microsoft-Windows-NTLM'; Ids = @(4020,4021,4022,4023,8001,8002,8003) },
        @{ Log = 'Microsoft-Windows-NTLM/Operational'; Provider = 'Microsoft-Windows-Security-Netlogon'; Ids = @(4030,4031,4032,4033,8004) },
        @{ Log = 'Security'; Provider = 'Microsoft-Windows-Security-Auditing'; Ids = @(4624,4625,4776) }
    )
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $xmlEvents = New-Object 'System.Collections.Generic.List[string]'
    foreach ($profile in $profiles) {
        $row = [ordered]@{
            Computer = $env:COMPUTERNAME
            OS = $osName
            Build = $build
            DomainRole = $domainRole
            Channel = $profile.Log
            Provider = $profile.Provider
            Status = 'Error'
            RequestedStartUtc = $StartUtc.ToUniversalTime().ToString('o')
            RequestedEndUtc = $EndUtc.ToUniversalTime().ToString('o')
            Enabled = $null
            MaximumSizeInBytes = $null
            LogMode = $null
            OldestAvailableUtc = $null
            RetentionUnproven = $false
            Truncated = $false
            Collected = 0
            SupportedIds = @()
            UnsupportedIds = @()
            Templates = @()
            AuditPolicyCoverage = 'NotVerified'
            Error = $null
        }
        try {
            $log = Get-WinEvent -ListLog $profile.Log -ErrorAction Stop
            $row.Enabled = $log.IsEnabled
            $row.MaximumSizeInBytes = $log.MaximumSizeInBytes
            $row.LogMode = [string]$log.LogMode
            if (-not $log.IsEnabled) {
                $row.Status = 'Disabled'
                $rows.Add([pscustomobject]$row)
                continue
            }
            $provider = Get-WinEvent -ListProvider $profile.Provider -ErrorAction Stop
            $definitions = @($provider.Events | Where-Object { $_.Id -in $profile.Ids })
            $row.SupportedIds = @($definitions | ForEach-Object { [int]$_.Id } | Sort-Object -Unique)
            $row.UnsupportedIds = @($profile.Ids | Where-Object { $_ -notin $row.SupportedIds })
            $row.Templates = @($definitions | ForEach-Object {
                [pscustomobject]@{ Id = $_.Id; Version = $_.Version; Template = $_.Template }
            })
            if ($row.SupportedIds.Count -eq 0) {
                $row.Status = 'Unsupported'
                $rows.Add([pscustomobject]$row)
                continue
            }
            if ($log.RecordCount -gt 0) {
                $oldest = Get-WinEvent -LogName $profile.Log -Oldest -MaxEvents 1 -ErrorAction Stop
                $row.OldestAvailableUtc = $oldest.TimeCreated.ToUniversalTime().ToString('o')
                $row.RetentionUnproven = $oldest.TimeCreated.ToUniversalTime() -gt $StartUtc.ToUniversalTime()
            }
            $start = $StartUtc.ToUniversalTime().ToString('o')
            $end = $EndUtc.ToUniversalTime().ToString('o')
            $idPredicate = ($row.SupportedIds | ForEach-Object { "EventID=$_" }) -join ' or '
            $selection = "*[System[Provider[@Name='$($profile.Provider)'] and ($idPredicate) and TimeCreated[@SystemTime >= '$start' and @SystemTime <= '$end']]]"
            if ($profile.Log -eq 'Security') {
                $selection += " and (*[System[EventID=4776]] or *[EventData[Data[@Name='AuthenticationPackageName']='NTLM']])"
            }
            $escaped = [System.Security.SecurityElement]::Escape($selection)
            $query = "<QueryList><Query Id='0' Path='$($profile.Log)'><Select Path='$($profile.Log)'>$escaped</Select></Query></QueryList>"
            $found = @()
            try {
                $found = @(Get-WinEvent -FilterXml $query -MaxEvents ($Limit + 1) -ErrorAction Stop)
            }
            catch {
                if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
            }
            $row.Truncated = $found.Count -gt $Limit
            foreach ($record in ($found | Select-Object -First $Limit)) {
                $xmlEvents.Add($record.ToXml())
                $row.Collected++
            }
            $row.Status = if ($row.Collected -eq 0) { 'NoEvents' } else { 'Collected' }
        }
        catch {
            $row.Status = if ($_.FullyQualifiedErrorId -like 'NoMatchingProvidersFound*' -or
                $_.FullyQualifiedErrorId -like 'NoMatchingLogsFound*') { 'Unsupported' } else { 'Error' }
            if ($row.Status -eq 'Unsupported') { $row.UnsupportedIds = @($profile.Ids) }
            $row.Error = $_.Exception.Message
        }
        $rows.Add([pscustomobject]$row)
    }
    [pscustomobject]@{
        Coverage = @($rows.ToArray())
        Events = @($xmlEvents.ToArray())
        MetadataErrors = @($metadataErrors.ToArray())
    }
}

function Get-NtlmDependency {
    param([AllowEmptyCollection()][object[]]$Events)

    $groups = @{}
    foreach ($event in $Events) {
        $key = ConvertTo-Json -InputObject @($event.ObservationPoint, $event.SourceComputer,
            $event.ClientName, $event.ClientIP, $event.AccountDomain, $event.AccountName,
            $event.TargetName, $event.TargetDomain, $event.TargetIP, $event.TargetService,
            $event.InitiatingProcess, $event.LocalProcess, $event.ServiceBinding, $event.ReasonId) -Compress
        if (-not $groups.ContainsKey($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add($event)
    }
    foreach ($key in ($groups.Keys | Sort-Object)) {
        $items = @($groups[$key].ToArray() | Sort-Object TimeUtc)
        $first = $items[0]
        [pscustomobject][ordered]@{
            ObservationPoint = $first.ObservationPoint
            SourceComputer = $first.SourceComputer
            ClientName = $first.ClientName
            ClientIP = $first.ClientIP
            AccountDomain = $first.AccountDomain
            AccountName = $first.AccountName
            TargetName = $first.TargetName
            TargetDomain = $first.TargetDomain
            TargetIP = $first.TargetIP
            TargetService = $first.TargetService
            InitiatingProcess = $first.InitiatingProcess
            LocalProcess = $first.LocalProcess
            ServiceBinding = $first.ServiceBinding
            ReasonId = $first.ReasonId
            ReasonDescription = $first.ReasonDescription
            Versions = (@($items.NtlmVersion | Sort-Object -Unique) -join ', ')
            ObservationCount = $items.Count
            FirstObservedUtc = $first.TimeUtc
            LastObservedUtc = $items[-1].TimeUtc
            Owner = 'Unassigned'
            Investigation = $first.Investigation
            EvidenceIds = @($items.EvidenceId)
        }
    }
}

function Export-NtlmCsv {
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string[]]$Columns,
        [Parameter(Mandatory)][string]$Path
    )

    $safeRows = @(
        foreach ($row in $Rows) {
            $safe = [ordered]@{}
            foreach ($column in $Columns) {
                $value = $row.$column
                if ($value -is [array]) { $value = $value -join '; ' }
                if ($value -is [string] -and $value -match '^[\s]*[=+@-]') { $value = "'" + $value }
                $safe[$column] = $value
            }
            [pscustomobject]$safe
        }
    )
    if ($safeRows.Count -gt 0) {
        $safeRows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding utf8BOM -ErrorAction Stop
    }
    else {
        $empty = [ordered]@{}
        foreach ($column in $Columns) { $empty[$column] = $null }
        $header = ([pscustomobject]$empty | ConvertTo-Csv -NoTypeInformation)[0]
        Set-Content -LiteralPath $Path -Value $header -Encoding utf8BOM -ErrorAction Stop
    }
}

function ConvertTo-NtlmHtmlTable {
    param(
        [AllowEmptyCollection()][object[]]$Rows,
        [string[]]$Columns,
        [ValidatePattern('^[a-z][a-z0-9-]*$')][string]$Id,
        [switch]$Deferred
    )

    if ($Deferred -and -not $Id) { throw 'Deferred HTML tables require an ID.' }
    $count = @($Rows).Count
    if ($count -eq 0) { return '<p class="empty-state">No rows to display in the collected evidence.</p>' }
    $shown = [math]::Min($count, 500)
    $labels = @{
        TimeUtc = 'Recorded at (UTC)'; NtlmVersion = 'NTLM version'; Versions = 'NTLM versions'
        Version = 'NTLM version'; ObservationCount = 'Event records in group'; ObservationPoint = 'Role in this record'
        Observations = 'Event records'; SourceComputer = 'Log computer'; Computer = 'Computer checked'
        ClientName = 'Initiating computer'; TargetName = 'Requested destination'; AccountName = 'Account used'
        InitiatingProcess = 'App starting the connection'; LocalProcess = 'Process on log computer'
        Provider = 'Windows event provider'; Channel = 'Windows log'; Status = 'Collection result'; OS = 'Windows version'
        AuthenticationResult = 'Reported outcome'; Result = 'Reported outcome'
        Description = 'Reason reported'; Investigation = 'Suggested next check'
        Enabled = 'Log enabled'; Truncated = 'Event limit reached'
        EventId = 'Event ID'; RecordId = 'Record ID'; ReasonId = 'Reason ID'
        OldestAvailableUtc = 'Oldest retained (UTC)'; FirstObservedUtc = 'First observed (UTC)'
        LastObservedUtc = 'Last observed (UTC)'; RequestedStartUtc = 'Requested start (UTC)'
        RequestedEndUtc = 'Requested end (UTC)'; RetentionUnproven = 'Retention uncertain'
        Collected = 'Matching events read'; EvidenceId = 'Evidence ID'; EvidenceIds = 'Evidence IDs'
    }
    $collectionLabels = @{
        Collected = 'Events read'; NoEvents = 'No matching events'; Disabled = 'Log disabled'
        Unsupported = 'Not supported here'; Error = 'Could not collect'; ImportedEvidenceOnly = 'Imported XML only'
    }
    $roleLabels = @{
        Client = 'Client / initiator'; ResourceServer = 'Server / receiver'
        DomainController = 'Domain controller'; CredentialAuthority = 'Account validator (4776)'
    }
    $outcomeLabels = @{
        Attempt = 'NTLM attempt recorded'; LogonSuccess = 'Windows logon succeeded'; LogonFailure = 'Windows logon failed'
        ProcessingSuccess = 'NTLM processing succeeded'; ProcessingFailure = 'NTLM processing failed'
        'Not established' = 'Outcome not established'
    }
    $html = [Text.StringBuilder]::new()
    $deferredRows = [System.Collections.Generic.List[object]]::new()
    if ($Id) {
        [void]$html.Append(@"
<div class="table-tools" hidden><label for="$Id-filter">Filter rows
<input id="$Id-filter" type="search" data-table="$Id" placeholder="Search displayed rows..." autocomplete="off"></label>
<span class="table-count" id="$Id-count" role="status">$shown displayed / $count total</span></div>
"@)
    }
    [void]$html.Append('<div class="table-scroll" tabindex="0" role="region" aria-label="Scrollable audit data"><table')
    if ($Id) { [void]$html.Append(' id="' + $Id + '"') }
    if ($Deferred) { [void]$html.Append(' data-deferred="' + $Id + '-data"') }
    [void]$html.Append('><thead><tr>')
    foreach ($column in $Columns) {
        $label = if ($labels.ContainsKey($column)) { $labels[$column] } else { $column -creplace '([a-z0-9])([A-Z])', '$1 $2' }
        [void]$html.Append('<th scope="col">' + [Net.WebUtility]::HtmlEncode($label) + '</th>')
    }
    [void]$html.Append('</tr></thead><tbody>')
    foreach ($row in ($Rows | Select-Object -First 500)) {
        $cells = [System.Collections.Generic.List[object]]::new()
        if (-not $Deferred) { [void]$html.Append('<tr>') }
        foreach ($column in $Columns) {
            $value = $row.$column
            if ($value -is [array]) { $value = $value -join '; ' }
            if ($column -match 'Utc$' -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                $value = ([datetimeoffset]$value).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
            $rawValue = [string]$value
            $displayValue = $rawValue
            if ($column -eq 'Status' -and $collectionLabels.ContainsKey($rawValue)) { $displayValue = $collectionLabels[$rawValue] }
            elseif ($column -eq 'ObservationPoint' -and $roleLabels.ContainsKey($rawValue)) { $displayValue = $roleLabels[$rawValue] }
            elseif ($column -in 'AuthenticationResult','Result' -and $outcomeLabels.ContainsKey($rawValue)) { $displayValue = $outcomeLabels[$rawValue] }
            elseif ($column -in 'NtlmVersion','Versions','Version' -and $rawValue -eq 'Unknown') { $displayValue = 'Version not established' }
            elseif ($value -is [bool]) {
                if ($column -eq 'RetentionUnproven') { $displayValue = if ($value) { 'Yes - history may be incomplete' } else { 'No retention gap flagged' } }
                elseif ($column -eq 'Truncated') { $displayValue = if ($value) { 'Yes - results were capped' } else { 'No cap flagged' } }
                elseif ($column -eq 'Enabled') { $displayValue = if ($value) { 'Enabled' } else { 'Disabled' } }
            }
            $cell = $displayValue
            if ([string]::IsNullOrWhiteSpace([string]$value)) { $cell = $null }
            elseif ($column -in 'Status','NtlmVersion','Versions','Version','AuthenticationResult','ObservationPoint','RetentionUnproven','Truncated','Enabled') {
                $tone = switch ([string]$value) {
                    { $_ -in 'NTLMv1','Error','LogonFailure','ProcessingFailure' } { 'danger'; break }
                    { $_ -in 'Unknown','Partial','Disabled','Unsupported','ImportedEvidenceOnly' } { 'warning'; break }
                    'True' { if ($column -in 'RetentionUnproven','Truncated') { 'warning' } else { 'info' }; break }
                    default { 'info' }
                }
                $cell = [ordered]@{ text = $displayValue; raw = $rawValue; tone = $tone }
            }
            if ($Deferred) { $cells.Add($cell) }
            else {
                $encoded = if ($null -eq $cell) { '<span class="missing">Not recorded</span>' }
                elseif ($cell -is [System.Collections.IDictionary]) {
                    '<span class="badge ' + $cell.tone + '" data-raw="' + [Net.WebUtility]::HtmlEncode($cell.raw) + '" title="Export value: ' + [Net.WebUtility]::HtmlEncode($cell.raw) + '">' + [Net.WebUtility]::HtmlEncode($cell.text) + '</span>'
                } else { [Net.WebUtility]::HtmlEncode($cell) }
                [void]$html.Append('<td><span class="cell-value">' + $encoded + '</span></td>')
            }
        }
        if ($Deferred) { $deferredRows.Add($cells.ToArray()) }
        else { [void]$html.Append('</tr>') }
    }
    [void]$html.Append('</tbody></table></div>')
    if ($Deferred) {
        $payload = ConvertTo-Json -InputObject @{ rows = $deferredRows.ToArray() } -Depth 6 -Compress -EscapeHandling EscapeHtml
        [void]$html.Append('<script type="application/json" id="' + $Id + '-data">' + $payload + '</script>')
        [void]$html.Append('<p class="table-note" id="' + $Id + '-pending" role="status">Technical rows load when these details are opened (JavaScript required). Complete fields are also available in the CSV/JSON exports.</p>')
    }
    if ($Id) { [void]$html.Append('<p class="no-matches empty-state" data-for="' + $Id + '" hidden>No matching displayed rows. Clear the filter or search the complete exports.</p>') }
    if ($count -gt 500) {
        [void]$html.Append("<p class=`"table-note`">Showing the first 500 rows of $count. Complete data is in the CSV and JSON exports. Filters search only these displayed rows.</p>")
    }
    $html.ToString()
}

function Export-NtlmReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$Directory)

    if (Test-Path -LiteralPath $Directory) { throw "Output path already exists: $Directory" }
    $null = New-Item -ItemType Directory -Path $Directory -ErrorAction Stop
    $jsonPath = Join-Path $Directory 'NtlmAudit.json'
    $Report | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $jsonPath -Encoding utf8 -ErrorAction Stop
    $eventColumns = @('EvidenceId','TimeUtc','SourceComputer','Provider','Channel','EventId','EventVersion',
        'RecordId','Level','EventFamily','ObservationPoint','AccountDomain','AccountName','ClientName','ClientIP',
        'TargetName','TargetDomain','TargetIP','TargetService','InitiatingProcess','LocalProcess','ProcessId',
        'NtlmVersion','RawNtlmVersion','ReasonId','ReasonDescription','RawReason','AuthenticationResult',
        'RawStatus','ChannelBindingStatus','MicStatus','SessionKeyStatus','Investigation','ParsingWarnings')
    $dependencyColumns = @('ObservationPoint','SourceComputer','ClientName','ClientIP','AccountDomain',
        'AccountName','TargetName','TargetDomain','TargetIP','TargetService','InitiatingProcess',
        'LocalProcess','ServiceBinding','ReasonId','ReasonDescription',
        'Versions','ObservationCount','FirstObservedUtc','LastObservedUtc','Owner','Investigation','EvidenceIds')
    $coverageColumns = @('Computer','OS','Build','DomainRole','Channel','Provider','Status','RequestedStartUtc',
        'RequestedEndUtc','Enabled','MaximumSizeInBytes','LogMode','OldestAvailableUtc','RetentionUnproven',
        'Truncated','Collected','SupportedIds','UnsupportedIds','AuditPolicyCoverage','Error')
    Export-NtlmCsv -Rows $Report.Events -Columns $eventColumns -Path (Join-Path $Directory 'Events.csv')
    Export-NtlmCsv -Rows $Report.Dependencies -Columns $dependencyColumns -Path (Join-Path $Directory 'Dependencies.csv')
    Export-NtlmCsv -Rows $Report.Coverage -Columns $coverageColumns -Path (Join-Path $Directory 'Coverage.csv')
    $versionRows = @($Report.Events | Group-Object NtlmVersion | ForEach-Object {
        [pscustomobject]@{ Version = $_.Name; Observations = $_.Count }
    })
    $reasonRows = @($Report.Events | Where-Object { $null -ne $_.ReasonId } | Group-Object ReasonId |
        Sort-Object Count -Descending | ForEach-Object {
            [pscustomobject]@{
                ReasonId = $_.Name
                Description = $_.Group[0].ReasonDescription
                Observations = $_.Count
                Investigation = $_.Group[0].Investigation
            }
        })
    $resultRows = @($Report.Events | Group-Object AuthenticationResult | ForEach-Object {
        [pscustomobject]@{ Result = $_.Name; Observations = $_.Count }
    })
    $roleRows = @($Report.Events | Group-Object ObservationPoint | ForEach-Object {
        [pscustomobject]@{ ObservationPoint = $_.Name; Observations = $_.Count }
    })
    $eventIssueKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $recordWarnings = @(
        foreach ($event in $Report.Events) {
            foreach ($warning in $event.ParsingWarnings) {
                [void]$eventIssueKeys.Add("$($event.EvidenceId): $warning")
                [pscustomobject]@{ Message = [string]$warning; EvidenceId = $event.EvidenceId }
            }
        }
    )
    $collectionIssues = @($Report.Issues | Where-Object { -not $eventIssueKeys.Contains($_) })
    $recordNotes = @($recordWarnings | Group-Object Message | Sort-Object Count -Descending | ForEach-Object {
        $title = 'Event interpretation needs review'
        $explanation = $_.Name
        if ($_.Name -eq 'Anonymous/null-session evidence is not proof of a credential-bearing NTLMv1 exchange.') {
            $title = 'Anonymous activity is not proof of NTLMv1 with credentials'
            $explanation = 'These records describe anonymous or null-session activity. A raw NTLMv1 label here does not establish that an account''s credentials were used in NTLMv1. They stay in Version not established. This is a classification caution, not a collection failure or a claim that the activity is harmless.'
        }
        elseif ($_.Name -eq 'Enhanced event version is not a verified v0 schema; inspect raw XML.') {
            $title = 'An event format needs technical verification'
            $explanation = 'These records use an enhanced event version that the parser has not verified. Inspect the original XML before relying on its interpretation; the records have not been discarded.'
        }
        [pscustomobject]@{
            Title = $title; Explanation = $explanation
            Records = @($_.Group.EvidenceId | Sort-Object -Unique).Count
        }
    })
    $recordsToInterpret = @($recordWarnings.EvidenceId | Sort-Object -Unique).Count
    $retentionRows = @($Report.Coverage | Where-Object {
        $_.RetentionUnproven -and -not [string]::IsNullOrWhiteSpace($_.OldestAvailableUtc) -and
        ([datetimeoffset]$_.OldestAvailableUtc -gt [datetimeoffset]$_.RequestedStartUtc)
    })
    $collectionIssueHtml = if ($collectionIssues.Count -gt 0) {
        '<ul class="issue-list">' + (($collectionIssues | ForEach-Object {
            $message = [string]$_
            if ($message -match '^(?<Computer>.+?) / (?<Channel>.+): oldest retained event is newer than the requested start; retention coverage is unproven\.$') {
                $message = 'History may be incomplete on {0} ({1}): the earliest retained log entry is later than the requested start.' -f $Matches.Computer, $Matches.Channel
            }
            '<li>' + [Net.WebUtility]::HtmlEncode($message) + '</li>'
        }) -join '') + '</ul>'
    } else { '<p class="muted">No collection limitations recorded. Logging policy coverage is still not verified.</p>' }
    $sourceNames = if ($Report.Run.Mode -eq 'Live') { $Report.Coverage.Computer } else { $Report.Events.SourceComputer }
    $sourceComputers = @($sourceNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $computerLabel = if ($Report.Run.Mode -eq 'Live') { 'Computers checked' } else { 'Computers in imported logs' }
    $computerNote = if ($Report.Run.Mode -eq 'Live') { 'Computers queried, including failed attempts. Not a count of clients.' } else { 'Computer names inside the imported events. No computers were contacted.' }
    $computerRows = @(
        foreach ($name in $sourceComputers) {
            if ($Report.Run.Mode -eq 'Live') {
                $checks = @($Report.Coverage | Where-Object Computer -eq $name)
                $counts = @($checks | Where-Object { $null -ne $_.Collected } | ForEach-Object Collected)
                $readCount = if ($counts.Count -gt 0) { ($counts | Measure-Object -Sum).Sum } else { $null }
                $notes = @(
                    if (@($checks | Where-Object { $_.Status -eq 'Error' -or -not [string]::IsNullOrWhiteSpace($_.Error) }).Count -gt 0) { 'Collection errors' }
                    if ($checks.Status -contains 'Disabled') { 'Log disabled' }
                    if ($checks.Status -contains 'Unsupported') { 'Unsupported source' }
                    if (@($checks | Where-Object RetentionUnproven).Count -gt 0) { 'History uncertain' }
                    if (@($checks | Where-Object Truncated).Count -gt 0) { 'Event limit reached' }
                )
                $collectionSummary = if ($notes.Count -gt 0) { $notes -join '; ' }
                    elseif ($null -eq $readCount -or @($checks | Where-Object { $_.Status -notin 'Collected','NoEvents' }).Count -gt 0) { 'Check source details' }
                    elseif ($readCount -eq 0) { 'No matching events' }
                    else { 'Queries completed' }
                [pscustomobject]@{
                    Computer = $name
                    OS = $checks.OS | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
                    Collected = $readCount
                    CollectionSummary = $collectionSummary
                }
            }
            else {
                [pscustomobject]@{
                    SourceComputer = $name
                    Observations = @($Report.Events | Where-Object SourceComputer -eq $name).Count
                    CollectionSummary = 'Imported XML only - not contacted'
                }
            }
        }
    )
    $computerColumns = if ($Report.Run.Mode -eq 'Live') { @('Computer','OS','Collected','CollectionSummary') }
        else { @('SourceComputer','Observations','CollectionSummary') }
    $computerIntro = if ($Report.Run.Mode -eq 'Live') {
        'One row per checked computer, including empty, failed or incomplete collections. Matching events read sums the provider queries before deduplication and parsing; it is not a count of connections. Expand Collection checks for individual log results.'
    } else {
        'One row per log computer named in the imported event records, not per XML file. These computers were not contacted. Counts describe the normalized records included in this report, not unique connections.'
    }
    $metrics = @(
        @{ Label = $computerLabel; Value = $sourceComputers.Count; Note = $computerNote; Tone = 'info' }
        @{ Label = 'Event records'; Value = $Report.Events.Count; Note = 'Log entries read. Several entries may describe the same connection.'; Tone = 'info' }
        @{ Label = 'Usage groups to review'; Value = $Report.Dependencies.Count; Note = 'Similar records grouped for investigation. Not a count of applications.'; Tone = 'info' }
        @{ Label = 'Records showing NTLMv1'; Value = @($Report.Events | Where-Object NtlmVersion -eq 'NTLMv1').Count; Note = 'The older, weaker version was explicitly identified. Investigate these flows first.'; Tone = 'danger' }
        @{ Label = 'Records showing NTLMv2'; Value = @($Report.Events | Where-Object NtlmVersion -eq 'NTLMv2').Count; Note = 'The version is known, but this alone does not prove the connection was protected.'; Tone = 'info' }
        @{ Label = 'Version not established'; Value = @($Report.Events | Where-Object NtlmVersion -eq 'Unknown').Count; Note = 'The record does not establish a version. Do not treat this as NTLMv1 or as a failure.'; Tone = 'warning' }
    )
    $metricHtml = foreach ($metric in $metrics) {
        $tone = if ($metric.Value -eq 0) { 'info' } else { $metric.Tone }
        '<article class="metric {0}"><span class="metric-label">{1}</span><strong class="metric-value">{2:N0}</strong><span class="metric-note">{3}</span></article>' -f
            $tone, $metric.Label, $metric.Value, $metric.Note
    }
    $statusTone = if ($Report.Run.ErrorCount -gt 0) { 'danger' } elseif ($Report.Run.Status -eq 'Partial') { 'warning' } else { 'info' }
    $statusLabel = switch ($Report.Run.Status) {
        'Partial' { 'Review required' }
        'Collected' { 'Queries completed' }
        default { $Report.Run.Status }
    }
    $collectionExplanation = if ($collectionIssues.Count -gt 0 -or $Report.Run.ErrorCount -gt 0) {
        'Collection or processing limitations are listed under Collection checks. Event interpretation notes are shown separately: they are not additional collection failures. Neither category automatically means that NTLMv1 was used or that authentication failed.'
    } elseif ($recordNotes.Count -gt 0) {
        'No collection limitations were recorded, but some event records need interpretation notes. These notes are not collection failures. Logging policy coverage is still not verified for the whole time window.'
    } else {
        'No collection limitations were recorded. This still does not prove that logging was enabled for the whole time window or that NTLM is absent from other computers.'
    }
    $scopeExplanation = if ($Report.Run.Mode -eq 'Xml') {
        'Offline analysis: only exported XML files were read. Computer access, logging settings and missing history were not checked.'
    } elseif ($Report.Run.Scope -eq 'AllDomainControllers') {
        'DC-only collection: domain controllers were discovered in one domain. Member servers and client computers were not automatically included.'
    } else {
        'Explicit computer list: only the computers supplied to the script were checked. Other clients, servers and domain controllers were not automatically scanned.'
    }
    $windowStart = ([datetimeoffset]$Report.Run.StartUtc).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
    $windowEnd = ([datetimeoffset]$Report.Run.EndUtc).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss')
    $summary = [Net.WebUtility]::HtmlEncode((
        'Mode: {0} | Scope: {1} | Duplicate records ignored: {2}' -f
        $Report.Run.Mode, $Report.Run.Scope, $Report.Run.DuplicateRecords))
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark"><title>NTLM audit report</title>
<style>
:root{--bg:#09111f;--card:#111e32;--border:#2a405d;--text:#e3edf9;--muted:#a3b5ce;--accent:#78c7ff;--warning:#f0c45c;--danger:#ff9393}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth;scroll-padding-top:5rem}
body{margin:0;background:radial-gradient(ellipse at top,#163254,var(--bg) 42%);color:var(--text);font:14px/1.6 'Segoe UI',system-ui,sans-serif}
a{color:var(--accent)}a:focus-visible,summary:focus-visible,input:focus-visible,.table-scroll:focus-visible{outline:2px solid var(--accent);outline-offset:3px}
.container{max-width:1480px;margin:auto;padding:2rem}h1,h2,h3,p{margin:0}h1{font-size:clamp(1.8rem,4vw,2.7rem);line-height:1.15;letter-spacing:-.03em}
h2{font-size:1.25rem}h3{font-size:1.05rem}p+p{margin-top:.65rem}.muted,.section-intro,.table-note{color:var(--muted)}
.hero{padding:2rem;border:1px solid #365a7b;border-radius:20px;background:linear-gradient(120deg,#193a5a,#102336);box-shadow:0 20px 60px #0003}
.eyebrow{color:var(--accent);font-size:.75rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase}.hero-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin:.5rem 0 1rem}
.hero .muted{margin-top:.45rem}.window{margin-top:1.2rem;padding-top:1rem;border-top:1px solid #ffffff20;font-variant-numeric:tabular-nums}.window strong{color:var(--accent)}
.section-nav{position:sticky;top:0;z-index:5;display:flex;gap:.45rem;overflow:auto;padding:.85rem 0;margin:1rem 0;background:#09111f;border-bottom:1px solid var(--border)}
.section-nav a,.export-links a{flex:none;padding:.45rem .85rem;border:1px solid var(--border);border-radius:8px;text-decoration:none;background:#14243a}.section-nav a:hover,.export-links a:hover{background:#203d59}
.metrics{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:.8rem;margin:1.2rem 0}.metric{display:flex;flex-direction:column;min-width:0;padding:1.1rem;background:var(--card);border:1px solid var(--border);border-top:3px solid var(--accent);border-radius:12px}
.metric.warning{border-top-color:var(--warning)}.metric.danger{border-top-color:var(--danger)}.metric-label{color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.05em}.metric-value{font-size:2rem;line-height:1.3;margin:.35rem 0;color:var(--accent)}.metric.warning .metric-value{color:var(--warning)}.metric.danger .metric-value{color:var(--danger)}.metric-note{font-size:.76rem;color:var(--muted)}
.notice{padding:1rem 1.2rem;border:1px solid #69592f;border-left:4px solid var(--warning);border-radius:10px;background:#282719;margin:1.2rem 0}.notice strong{color:var(--warning)}
.card{min-width:0;padding:1.4rem;background:var(--card);border:1px solid var(--border);border-radius:14px;margin:1.2rem 0}.section-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem;margin-bottom:.6rem}.section-intro{font-size:.88rem;margin-bottom:1rem}
.insights-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1.2rem}.insights-grid .card{margin:0}.badge{display:inline-block;padding:.2rem .65rem;border:1px solid #396183;border-radius:999px;font-size:.76rem;font-weight:600;background:#173650;color:#a6ddff;white-space:nowrap}
.badge.warning{background:#3a3018;border-color:#73602e;color:#ffe091}.badge.danger{background:#3d242d;border-color:#824455;color:#ffb5b5}.issue-list{padding-left:1.2rem;margin:.5rem 0;overflow-wrap:anywhere}.issue-list li+li{margin-top:.6rem}
.table-tools{display:flex;flex-wrap:wrap;align-items:end;justify-content:space-between;gap:.6rem 1rem;margin:1rem 0 .65rem}.table-tools label{display:flex;flex:1 1 200px;min-width:0;align-items:center;gap:.6rem;font-size:.8rem;color:var(--muted)}input[type=search]{flex:1;min-width:0;width:240px;max-width:100%;padding:.55rem .7rem;border:1px solid #446080;border-radius:7px;background:#0b1728;color:var(--text);font:inherit}
.table-count,.table-note{font-size:.78rem}.table-count{color:var(--muted)}.table-scroll{overflow:auto;max-height:34rem;border:1px solid var(--border);border-radius:9px;overscroll-behavior:contain}
table{width:100%;border-collapse:separate;border-spacing:0;font-size:.8rem}th{position:sticky;top:0;z-index:1;background:#20354e;color:#c4e7ff;padding:.8rem .85rem;text-align:left;white-space:nowrap;border-bottom:1px solid #47617f}
td{padding:.75rem .85rem;vertical-align:top;border-bottom:1px solid #ffffff0c;min-width:9rem;max-width:28rem;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}tbody tr:nth-child(even){background:#ffffff03}tbody tr:hover{background:#78c7ff0b}.cell-value{display:block;min-width:6rem;max-width:28rem}.missing{color:var(--muted);font-style:italic;font-size:.75rem}
.empty-state{padding:1rem;color:var(--muted);border:1px dashed var(--border);border-radius:8px;font-size:.85rem}.table-note{margin-top:.65rem}.technical{margin-top:1rem;border-top:1px solid var(--border);padding-top:.8rem}.technical>summary{cursor:pointer;color:var(--accent);font-size:.85rem;font-weight:600}.technical[open]>summary{margin-bottom:1rem}
.reading-steps{padding-left:1.3rem;margin:.75rem 0}.reading-steps li+li{margin-top:.6rem}.terms{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem 1.4rem;margin:1rem 0}.terms>div{min-width:0;padding:.75rem;border-left:2px solid #365a7b;background:#ffffff03}.terms dt{color:#d5ecff;font-weight:600;margin-bottom:.3rem}.terms dd{margin:0;color:var(--muted);font-size:.85rem;overflow-wrap:anywhere}.read-next{padding:.75rem 1rem;margin:1rem 0 0;border-radius:8px;background:#173650;color:#d0eaff;font-size:.85rem}.reading-example{padding:.9rem 1rem;margin-top:1rem;background:#0b1728;border:1px solid var(--border);border-radius:8px}.technical p{font-size:.85rem;color:var(--muted);margin-bottom:.75rem}.metric-note{font-size:.8rem}
.interpretation-note{padding:1rem;margin-top:.9rem;border-left:3px solid var(--accent);border-radius:8px;background:#173650}.interpretation-note p{margin-top:.5rem}.section-heading{flex-wrap:wrap}
.export-links{display:flex;flex-wrap:wrap;gap:.6rem;margin:1rem 0}.footer{text-align:center;color:var(--muted);font-size:.78rem;padding:1rem}.sr-only{position:absolute;width:1px;height:1px;padding:0;overflow:hidden;clip:rect(0,0,0,0)}
@media(max-width:1100px){.metrics{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:760px){.container{padding:1rem}.hero{padding:1.3rem}.insights-grid,.terms{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,minmax(0,1fr))}.hero-heading{align-items:flex-start;flex-wrap:wrap}.card{padding:1rem}.table-tools{align-items:stretch;flex-direction:column;gap:.4rem}.table-tools label{flex:initial;flex-wrap:wrap}input[type=search]{flex:1 1 100%;width:100%}.window span{display:block}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:white;color:#111}.container{max-width:none;padding:0}.hero,.card,.metric,.notice{background:white;box-shadow:none;border-color:#aaa;color:#111}.section-nav,.table-tools,.export-links{display:none!important}.metrics{grid-template-columns:repeat(3,1fr)}.metric-value,h2,.hero .muted,.muted,.section-intro,.metric-label,.metric-note,.window strong{color:#222!important}.table-scroll{max-height:none;overflow:visible}table{font-size:8pt}th{position:static;background:#eee;color:#111}td{min-width:0}.cell-value{min-width:0}.badge{background:white!important;color:#111!important;border-color:#888!important}}
</style></head>
<body><div class="container">
<header class="hero" id="overview">
<p class="eyebrow">Authentication evidence / read-only audit</p>
<div class="hero-heading"><h1>NTLM audit report</h1><span class="badge $statusTone">$([Net.WebUtility]::HtmlEncode($statusLabel))</span></div>
<p class="muted">$summary</p>
<p class="muted">NTLM is a Windows authentication method. This report helps identify where it is still used so that applications can be reviewed before restrictions are introduced. It does not change logging or authentication settings.</p>
<p class="muted">$scopeExplanation</p>
<p class="muted">$collectionExplanation</p>
<p class="window"><strong>Observation window (UTC)</strong><br><span>$windowStart &nbsp; to &nbsp; $windowEnd</span></p>
</header>
<nav class="section-nav" aria-label="Report sections"><a href="#overview">Overview</a><a href="#computers">Computers</a><a href="#reading-guide">How to read</a><a href="#coverage">Collection checks</a>$(if ($recordNotes.Count -gt 0) { '<a href="#record-notes">Interpretation notes</a>' })<a href="#signals">Versions and roles</a><a href="#dependencies">Usage groups</a><a href="#observations">Event records</a><a href="#exports">Exports</a></nav>
<main>
<section class="metrics" aria-label="Evidence summary">$($metricHtml -join "`n")</section>
<section class="card" id="computers">
<div class="section-heading"><h2>$computerLabel</h2><span class="badge info">$($sourceComputers.Count) computers</span></div>
<p class="section-intro">$computerIntro</p>
$(ConvertTo-NtlmHtmlTable -Rows $computerRows -Columns $computerColumns -Id 'computers-table')
</section>
<aside class="notice"><strong>This report is not proof that NTLM has been eliminated.</strong> It describes the logs collected, not all activity on your network. Logging may not have been active for the whole time window. One connection can produce several records. A Warning event does not automatically mean NTLMv1. Imported files do not prove that the original collection was complete. Keep these reports private.</aside>
<section class="card" id="reading-guide"><h2>How to read this report</h2>
<p class="muted">Check collection limits, identify the roles, then review usage groups with their owners. Counts describe event records, not unique connections.</p>
<details class="technical" id="reading-details"><summary>Reading steps, role definitions and an example</summary>
<ol class="reading-steps">
<li><strong>Check the collection first.</strong> Missing, inaccessible or incomplete logs can hide usage. A zero count only describes the evidence collected for this time window.</li>
<li><strong>Identify the roles, then the applications.</strong> Find which computer starts the connection, which resource receives it and which account is used. A Windows server can also act as a client.</li>
<li><strong>Review the usage groups with the application owners.</strong> Confirm the business flow and a supported replacement before blocking NTLM. Use the individual records and exports to verify your conclusions.</li>
</ol>
<dl class="terms">
<div><dt>Log computer: where the record was written</dt><dd>The computer that recorded the Windows event. It is not necessarily the computer that started the connection.</dd></div>
<div><dt>Client / initiating computer: who starts the connection</dt><dd>A workstation, server or service requesting access to another resource. This is a role, not an operating-system type.</dd></div>
<div><dt>Server / requested destination: who receives the connection</dt><dd>The computer or service being accessed, such as a file share or an application. Its local process is not the remote client's application.</dd></div>
<div><dt>Domain controller: who validates a domain account</dt><dd>A DC may check the credentials for a domain account. Local-account activity is not fully visible from DC logs alone.</dd></div>
</dl>
<p class="reading-example"><strong>Illustration, not a reconstruction of your records:</strong> PC01 accesses a share on FILE01, which may ask DC01 to validate a domain account. PC01 is the client, FILE01 is the resource server and DC01 is the validator. Each can write its own log entry about the activity. This report does not automatically link those entries into one unique connection.</p>
</details></section>
<section class="card" id="coverage">
<div class="section-heading"><h2>Were the logs collected correctly?</h2><span class="badge $statusTone">Errors: $($Report.Run.ErrorCount) / collection notes: $($collectionIssues.Count)</span></div>
<p class="section-intro">Review the messages below first. Expand the per-computer checks for individual log results and definitions. Logging policy coverage is not verified.</p>
$collectionIssueHtml
$(if ($retentionRows.Count -gt 0) {
    '<h3>History starts later than requested</h3><p class="section-intro">Only affected logs are listed here, not all checked computers. All times are UTC. Activity before the oldest retained entry cannot be verified from this log.</p>' +
    (ConvertTo-NtlmHtmlTable -Rows $retentionRows -Columns @('Computer','Channel','RequestedStartUtc','OldestAvailableUtc','RequestedEndUtc') -Id 'retention-table')
})
<details class="technical" id="collection-details"><summary>Per-computer log checks and field definitions ($($Report.Coverage.Count) checks)</summary>
<p class="section-intro">Each row checks one computer and one Windows event provider: the Windows component that writes a type of log record. Several rows for one computer do not mean several computers or connections.</p>
<dl class="terms">
<div><dt>Events read / No matching events</dt><dd>The query returned matching records, or it returned none in the selected time window. Neither result proves that NTLM is absent elsewhere or that logging was active throughout the window.</dd></div>
<div><dt>Could not collect / Log disabled / Not supported here</dt><dd>The script could not read this source, its log was disabled, or the required log/provider/events were unavailable. Check the error and the OS/logging prerequisites; do not treat these rows as zero usage.</dd></div>
<div><dt>Retention uncertain</dt><dd>The history could not be verified, or the oldest retained log entry is newer than the requested start. Earlier activity may be missing, but this alone does not prove records were overwritten. No retention gap flagged is not proof of complete logging.</dd></div>
<div><dt>Event limit reached</dt><dd>The query found more records than the configured cap and kept only the newest matching records. Increase the cap or use a shorter time window, then rerun. No cap flagged does not prove that collection succeeded; check the collection result too.</dd></div>
<div><dt>Imported XML only</dt><dd>An exported file was analyzed. The script did not contact the original computer or verify its logging settings or retention.</dd></div>
<div><dt>Review required, even with zero errors</dt><dd>Uncertain history or a capped query can limit collection. Separately, some records need interpretation cautions, such as anonymous activity. These are different reasons for the report's Partial status, not proof of NTLMv1 or failed authentication.</dd></div>
</dl>
$(if ($retentionRows.Count -gt 0) {
    '<p class="section-intro">Compare Requested start with Oldest retained above (all times are UTC). The interval between them cannot be verified from this log. A small or cleared log, recently enabled logging, or no earlier recorded activity are possible explanations; the script does not determine the cause. This warning is not a WinRM failure or an NTLM authentication error.</p>'
})
$(ConvertTo-NtlmHtmlTable -Rows $Report.Coverage -Columns @('Computer','Provider','Status','Collected','RetentionUnproven','Truncated','Error') -Id 'coverage-table')
<details class="technical"><summary>Full provider, OS, retention and event-definition fields</summary>
<p>For troubleshooting: the log channel is the Windows log being read; the provider is the component writing events. Event IDs identify record types, and OS/build fields help check feature support. These are not additional clients or authentication attempts.</p>
$(ConvertTo-NtlmHtmlTable -Rows $Report.Coverage -Columns $coverageColumns -Id 'coverage-details' -Deferred)
</details></details><p class="read-next"><strong>Next step:</strong> resolve access/logging problems and decide whether the available history covers the business activity you need to audit before interpreting the usage counts.</p></section>
$(if ($recordNotes.Count -gt 0) {
    '<section class="card" id="record-notes"><div class="section-heading"><h2>How should these event records be interpreted?</h2><span class="badge info">Note types: ' + $recordNotes.Count + ' / records affected: ' + $recordsToInterpret + '</span></div><p class="section-intro">The same caution is shown once, with its affected event count. These are interpretation notes, not additional collection failures or unique authentication counts. A record can contribute to more than one note type.</p>' +
    (($recordNotes | ForEach-Object {
        '<article class="interpretation-note"><h3>' + [Net.WebUtility]::HtmlEncode($_.Title) + '</h3><p><strong>Event records affected: ' + $_.Records + '.</strong> ' + [Net.WebUtility]::HtmlEncode($_.Explanation) + '</p></article>'
    }) -join '') +
    '<p class="table-note">The long hexadecimal strings in the original warnings are technical evidence references, not error codes. Individual references and original warnings remain in the full event fields and JSON export; they are not repeated here. <a href="#exports">Open the complete exports.</a></p></section>'
})
<div class="insights-grid" id="signals">
<section class="card"><h2>Which NTLM version was identified?</h2><p class="section-intro">This counts event records, not connections. NTLMv1 is the older, weaker version. NTLMv2 is newer but still NTLM; its presence alone is not proof that all security protections were used.</p>
<p class="section-intro"><strong>Version not established</strong> means the event did not provide conclusive version evidence. Anonymous/null-session records are also kept out of credential-bearing version claims. Unknown does not mean NTLMv1, NTLMv2 or failed authentication.</p>
$(ConvertTo-NtlmHtmlTable -Rows $versionRows -Columns @('Version','Observations') -Id 'versions-table')
<p class="read-next"><strong>Next step:</strong> investigate explicit NTLMv1 records first. For unknown versions, collect richer evidence before classifying the flow.</p>
</section>
<section class="card"><h2>Which role recorded the activity?</h2><p class="section-intro">These are event counts by role, not counts of client machines or servers. One computer can appear in more than one role, and one connection can produce multiple records.</p>
<dl class="terms">
<div><dt>Client / initiator</dt><dd>The event describes a connection started by this computer.</dd></div>
<div><dt>Server / receiver</dt><dd>The event describes activity received by a resource computer.</dd></div>
<div><dt>Domain controller</dt><dd>The event describes domain-account validation handled by a DC.</dd></div>
<div><dt>Account validator (4776)</dt><dd>A credential-check event. The authority can be a DC for a domain account or a computer checking its own local account. This label alone does not prove the computer is a DC.</dd></div>
</dl>
$(ConvertTo-NtlmHtmlTable -Rows $roleRows -Columns @('ObservationPoint','Observations') -Id 'roles-table')
<p class="read-next"><strong>Next step:</strong> collect the relevant client, resource-server and DC logs. A missing role here means no records for that role were collected, not that the role has no NTLM usage.</p>
</section>
<section class="card"><h2>Why did a client choose NTLM?</h2><p class="section-intro">Enhanced client events can report why NTLM was selected, such as access by IP address or an application explicitly requesting NTLM. The reason code identifies the Windows category; the suggested check is an investigation lead, not a proven fix.</p>
<p class="section-intro">Only records with a client reason code contribute to this table. Older events and server/DC records may not supply one, so this total can be lower than the overall event count. An empty table does not mean there was no NTLM usage.</p>
$(ConvertTo-NtlmHtmlTable -Rows $reasonRows -Columns @('ReasonId','Description','Observations','Investigation') -Id 'reasons-table')
<p class="read-next"><strong>Next step:</strong> use the application, destination and reason together to review naming, connectivity or application settings with the owner.</p>
</section>
<section class="card"><h2>What outcome did Windows record?</h2><p class="section-intro">Different event types describe different steps. Do not add these counts together as unique successful or failed connections.</p>
<dl class="terms">
<div><dt>NTLM attempt recorded</dt><dd>NTLM use was attempted. This record alone does not establish success.</dd></div>
<div><dt>NTLM processing succeeded / failed</dt><dd>The NTLM processing or credential-check step reported success or failure. A successful check does not prove access to the application was granted.</dd></div>
<div><dt>Windows logon succeeded / failed</dt><dd>Windows recorded a successful or failed logon. This is still not an application authorization result.</dd></div>
<div><dt>Outcome not established</dt><dd>The record does not establish a success/failure outcome. This is not a failure finding and does not determine the NTLM version.</dd></div>
</dl>
$(ConvertTo-NtlmHtmlTable -Rows $resultRows -Columns @('Result','Observations') -Id 'results-table')
<p class="read-next"><strong>Next step:</strong> inspect the detailed status/error fields for failures and test actual application access separately.</p>
</section></div>
<section class="card" id="dependencies"><h2>Which usage groups should an owner review?</h2>
<p class="section-intro">Each row groups similar event records using the role, log computer, account, client, destination and process when available. It is a work item for investigation, not a confirmed application inventory. Different roles and log computers stay separate, even when they may describe related activity.</p>
<dl class="terms">
<div><dt>Log computer vs initiating computer</dt><dd>Log computer is where the event was recorded. Initiating computer is the caller named inside the event, if provided. These can be different machines.</dd></div>
<div><dt>Account used and requested destination</dt><dd>The identity presented and the computer/service being accessed, as recorded by Windows. Full account domains, IP addresses and service names are in the expanded fields.</dd></div>
<div><dt>App starting the connection vs process on log computer</dt><dd>The first identifies the initiating application only when client evidence supports it. The second belongs to the computer writing the event; on a receiving server it is not the remote client's application.</dd></div>
<div><dt>Event records in group and Not recorded</dt><dd>The count measures log entries, not users, applications or unique connections. Not recorded means the field was unavailable; it does not mean zero, no process or no dependency.</dd></div>
</dl>
$(ConvertTo-NtlmHtmlTable -Rows $Report.Dependencies -Columns @('ObservationPoint','SourceComputer','AccountName','ClientName','TargetName','InitiatingProcess','LocalProcess','Versions','ObservationCount') -Id 'dependencies-table')
<details class="technical"><summary>Full dependency fields, investigation guidance and evidence IDs</summary>
<p>First/last observed times show when the group appeared in this evidence. Evidence IDs link to individual event records; they do not identify a unique connection. Owner starts as Unassigned: the script does not discover application ownership or perform remediation.</p>
$(ConvertTo-NtlmHtmlTable -Rows $Report.Dependencies -Columns $dependencyColumns -Id 'dependencies-details' -Deferred)
</details><p class="read-next"><strong>Next step:</strong> assign each relevant group to an owner, confirm the business dependency and test a supported authentication change before introducing restrictions.</p></section>
<section class="card" id="observations"><h2>Which individual event records support the findings?</h2>
<p class="section-intro">Each row is one collected Windows log entry. The log computer tells you where it was written; the role tells you which step it describes. The initiating computer and requested destination come from the event's fields, not from assumptions about the log computer.</p>
<p class="section-intro"><strong>Recorded at (UTC)</strong> is the event time, not your browser's local time. <strong>Event ID</strong> identifies the Windows event type. <strong>Reported outcome</strong> has the meanings explained above; Not recorded means Windows did not provide that field in this evidence.</p>
$(ConvertTo-NtlmHtmlTable -Rows $Report.Events -Columns @('TimeUtc','SourceComputer','ObservationPoint','EventId','AccountName','ClientName','TargetName','InitiatingProcess','LocalProcess','NtlmVersion','AuthenticationResult') -Id 'events-table')
<details class="technical"><summary>Full event fields, protection indicators and provenance</summary>
<p>For technical verification: provider and Event ID identify the event type; Record ID identifies an entry within its Windows log, not a unique authentication. MIC helps protect the NTLM exchange from modification, while channel/service binding tie authentication to the intended channel or service. Missing indicators do not prove protection was absent. Use the retained raw XML for the exact original fields.</p>
$(ConvertTo-NtlmHtmlTable -Rows $Report.Events -Columns $eventColumns -Id 'events-details' -Deferred)
</details><p class="read-next"><strong>Next step:</strong> use the log computer, Windows log, timestamp, Event ID and Record ID to verify the original record when investigating a flow.</p></section>
<section class="card" id="exports"><h2>Where can I find the complete data?</h2>
<p class="section-intro">HTML tables show up to 500 rows each. Filters apply only to displayed rows; the CSV and JSON exports retain the complete collected datasets. The summary counts above use all collected records, not just the rows currently visible after filtering.</p>
<dl class="terms">
<div><dt>Events.csv</dt><dd>One row per normalized event record, for detailed investigation or spreadsheet analysis.</dd></div>
<div><dt>Dependencies.csv</dt><dd>One row per usage group, to prepare owner follow-up and remediation work.</dd></div>
<div><dt>Coverage.csv</dt><dd>One row per computer/provider collection check, including failures and limitations.</dd></div>
<div><dt>NtlmAudit.json</dt><dd>The complete collected evidence, including run context, raw event XML and the original named fields. Offline coverage rows describe imports, not live collection checks.</dd></div>
</dl>
<div class="export-links"><a href="Events.csv" download>Events CSV</a><a href="Dependencies.csv" download>Dependencies CSV</a><a href="Coverage.csv" download>Coverage CSV</a><a href="NtlmAudit.json" download>Full evidence JSON</a></div>
<p class="muted">Full raw XML, named fields and provider templates are retained in NtlmAudit.json. CSV formula-like values are prefixed with an apostrophe; JSON preserves the originals.</p>
<p class="read-next"><strong>Keep these files private.</strong> They contain account names, computer names and application paths. HTML labels are simplified for reading; original field names and status/role codes remain unchanged in the exports.</p>
</section>
<noscript><p class="notice">JavaScript is disabled. Summary tables and native expandable explanations remain accessible; row filters and on-demand technical tables are unavailable. Use the complete CSV/JSON exports for all technical fields.</p></noscript>
</main><footer class="footer">Generated by Invoke-NtlmAudit.ps1 / Self-contained report / Sensitive authentication evidence - do not publish</footer>
</div>
<script>
function initializeFilter(input) {
    var table = document.getElementById(input.dataset.table);
    var rows = Array.from(table.tBodies[0].rows);
    var count = document.getElementById(input.dataset.table + '-count');
    var originalCount = count.textContent;
    var empty = document.querySelector('[data-for="' + input.dataset.table + '"]');
    var searchable = rows.map(function (row) {
        var raw = Array.from(row.querySelectorAll('[data-raw]')).map(function (cell) { return cell.dataset.raw; }).join(' ');
        return (row.textContent + ' ' + raw).toLowerCase();
    });
    input.addEventListener('input', function () {
        var query = input.value.trim().toLowerCase();
        var visible = 0;
        rows.forEach(function (row, index) {
            row.hidden = !searchable[index].includes(query);
            if (!row.hidden) visible++;
        });
        count.textContent = query ? visible + ' matching / ' + rows.length + ' displayed rows' : originalCount;
        empty.hidden = visible !== 0;
    });
    input.closest('.table-tools').hidden = false;
}
document.querySelectorAll('input[data-table]').forEach(function (input) {
    if (!document.getElementById(input.dataset.table).hasAttribute('data-deferred')) initializeFilter(input);
});
document.querySelectorAll('table[data-deferred]').forEach(function (table) {
    var details = table.closest('details');
    function loadRows() {
        if (!details.open || !table.hasAttribute('data-deferred')) return;
        var pending = document.getElementById(table.id + '-pending');
        try {
            var data = document.getElementById(table.dataset.deferred);
            var rows = JSON.parse(data.textContent).rows;
            var fragment = document.createDocumentFragment();
            rows.forEach(function (cells) {
                var row = document.createElement('tr');
                cells.forEach(function (cell) {
                    var td = document.createElement('td');
                    var value = document.createElement('span');
                    value.className = 'cell-value';
                    if (cell === null) {
                        value.classList.add('missing');
                        value.textContent = 'Not recorded';
                    } else if (typeof cell === 'object') {
                        var badge = document.createElement('span');
                        badge.className = 'badge ' + cell.tone;
                        badge.dataset.raw = cell.raw;
                        badge.title = 'Export value: ' + cell.raw;
                        badge.textContent = cell.text;
                        value.appendChild(badge);
                    } else {
                        value.textContent = cell;
                    }
                    td.appendChild(value);
                    row.appendChild(td);
                });
                fragment.appendChild(row);
            });
            table.tBodies[0].replaceChildren(fragment);
            initializeFilter(document.getElementById(table.id + '-filter'));
            table.removeAttribute('data-deferred');
            data.remove();
            pending.hidden = true;
        } catch (error) {
            pending.textContent = 'Could not display this technical table. Use the complete CSV/JSON exports. ' + error.message;
            pending.setAttribute('role', 'alert');
            console.error('Could not display technical table ' + table.id, error);
        }
    }
    details.addEventListener('toggle', loadRows);
    loadRows();
});
</script>
</body></html>
"@
    $htmlPath = Join-Path $Directory 'NtlmAudit.html'
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding utf8 -ErrorAction Stop
    $htmlPath
}

function Invoke-NtlmAuditRun {
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [switch]$AllDomainControllers,
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\S')]
        [string]$Domain,
        [string[]]$EventXmlPath,
        [datetimeoffset]$StartTime,
        [datetimeoffset]$EndTime,
        [int]$MaxEventsPerSource = 10000,
        [pscredential]$Credential,
        [Parameter(Mandatory)][string]$OutputDir,
        [switch]$OpenReport
    )

    $ErrorActionPreference = 'Stop'
    if ($StartTime -ge $EndTime) { throw 'StartTime must be earlier than EndTime.' }
    if ($EndTime -gt [datetimeoffset]::Now.AddMinutes(5)) { throw 'EndTime must not be in the future.' }
    $scopeCount = [int]($ComputerName.Count -gt 0) + [int]($EventXmlPath.Count -gt 0) + [int]$AllDomainControllers.IsPresent
    if ($scopeCount -ne 1) {
        throw 'Specify either ComputerName, AllDomainControllers or EventXmlPath; choose exactly one scope.'
    }
    if ($PSBoundParameters.ContainsKey('Domain') -and -not $AllDomainControllers) { throw 'Domain requires AllDomainControllers.' }
    if (Test-Path -LiteralPath $OutputDir) { throw "Output path already exists: $OutputDir" }
    $observations = [System.Collections.Generic.List[object]]::new()
    $coverage = [System.Collections.Generic.List[object]]::new()
    $issues = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $rejectedEvents = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.Dictionary[string,string]]::new()
    $duplicates = 0
    $mode = if ($EventXmlPath.Count -gt 0) { 'Xml' } else { 'Live' }
    $batches = [System.Collections.Generic.List[object]]::new()

    if ($mode -eq 'Live') {
        if (-not $IsWindows) { throw 'Live collection requires Windows. Use EventXmlPath for offline analysis.' }
        if ($AllDomainControllers) {
            Import-Module -Name ActiveDirectory -ErrorAction Stop
            $discoveryArguments = @{ Filter = '*'; ErrorAction = 'Stop' }
            if ($Domain) { $discoveryArguments.Server = $Domain }
            if ($null -ne $Credential) { $discoveryArguments.Credential = $Credential }
            $controllers = @(Get-ADDomainController @discoveryArguments)
            if ($controllers.Count -eq 0) { throw 'No domain controllers were discovered. Check the domain and directory access.' }
            $ComputerName = @($controllers | ForEach-Object {
                if ([string]::IsNullOrWhiteSpace($_.HostName)) { throw 'Domain controller discovery returned an empty HostName.' }
                $_.HostName
            } | Sort-Object -Unique)
        }
        $collector = ${function:Get-NtlmSourceData}
        foreach ($computer in ($ComputerName | Sort-Object -Unique)) {
            if ([string]::IsNullOrWhiteSpace($computer)) { throw 'ComputerName contains an empty value.' }
            try {
                if ($computer -in @('.', 'localhost', $env:COMPUTERNAME)) {
                    $batch = & $collector $StartTime.UtcDateTime $EndTime.UtcDateTime $MaxEventsPerSource
                }
                else {
                    $arguments = @{
                        ComputerName = $computer
                        ScriptBlock = $collector
                        ArgumentList = @($StartTime.UtcDateTime, $EndTime.UtcDateTime, $MaxEventsPerSource)
                        ErrorAction = 'Stop'
                    }
                    if ($null -ne $Credential) { $arguments.Credential = $Credential }
                    $batch = Invoke-Command @arguments
                }
                if ($null -eq $batch -or $batch -is [array] -or
                    $batch.PSObject.Properties.Name -notcontains 'Coverage' -or
                    $batch.PSObject.Properties.Name -notcontains 'Events' -or
                    $batch.PSObject.Properties.Name -notcontains 'MetadataErrors' -or
                    @($batch.Coverage).Count -eq 0) {
                    throw 'The source did not return the expected collection/coverage object.'
                }
                foreach ($row in $batch.Coverage) {
                    $coverage.Add($row)
                    if ($row.Status -eq 'Error') { $errors.Add("$computer / $($row.Provider): $($row.Error)") }
                    if ($row.Status -in 'Disabled','Unsupported','Error') { $issues.Add("$computer / $($row.Provider): $($row.Status)") }
                    if ($row.RetentionUnproven) { $issues.Add("$computer / $($row.Channel): oldest retained event is newer than the requested start; retention coverage is unproven.") }
                    if ($row.Truncated) { $issues.Add("$computer / $($row.Provider): collection truncated at $MaxEventsPerSource newest matching events.") }
                }
                foreach ($message in $batch.MetadataErrors) { $issues.Add("$computer / $message"); $errors.Add("$computer / $message") }
                $batches.Add([pscustomobject]@{ Label = $computer; Events = @($batch.Events) })
            }
            catch {
                $message = "$computer / remote collection: $($_.Exception.Message)"
                $errors.Add($message)
                $issues.Add($message)
                $coverage.Add([pscustomobject]@{
                    Computer = $computer; OS = $null; Build = $null; DomainRole = $null
                    Channel = '*'; Provider = '*'; Status = 'Error'
                    RequestedStartUtc = $StartTime.UtcDateTime.ToString('o')
                    RequestedEndUtc = $EndTime.UtcDateTime.ToString('o')
                    Enabled = $null; MaximumSizeInBytes = $null; LogMode = $null
                    OldestAvailableUtc = $null; RetentionUnproven = $true; Truncated = $false
                    Collected = 0; SupportedIds = @(); UnsupportedIds = @(); Templates = @()
                    AuditPolicyCoverage = 'NotVerified'; Error = $_.Exception.Message
                })
            }
        }
    }
    else {
        $issues.Add('Offline XML import: source machine coverage, logging policy, retention and export completeness are not assessed.')
        foreach ($path in ($EventXmlPath | Sort-Object -Unique)) {
            try {
                $file = Get-Item -LiteralPath $path -ErrorAction Stop
                if ($file.PSIsContainer) { throw 'Expected an XML file, not a directory.' }
                $document = Read-NtlmXml -Text (Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop)
                $root = $document.DocumentElement
                $nodes = if ($root.LocalName -eq 'Event') { @($root) }
                    elseif ($root.LocalName -eq 'Events') { @($root.SelectNodes("*[local-name()='Event']")) }
                    else { throw 'Expected an Event or Events XML root.' }
                if ($nodes.Count -eq 0) { throw 'No Event elements found in the XML file.' }
                $batches.Add([pscustomobject]@{ Label = $file.Name; Events = @($nodes | ForEach-Object { $_.OuterXml }) })
                $coverage.Add([pscustomobject]@{
                    Computer = $file.Name; OS = $null; Build = $null; DomainRole = $null
                    Channel = 'Offline XML'; Provider = '*'; Status = 'ImportedEvidenceOnly'
                    RequestedStartUtc = $StartTime.UtcDateTime.ToString('o')
                    RequestedEndUtc = $EndTime.UtcDateTime.ToString('o')
                    Enabled = $null; MaximumSizeInBytes = $null; LogMode = $null
                    OldestAvailableUtc = $null; RetentionUnproven = $true; Truncated = $false
                    Collected = $nodes.Count; SupportedIds = @(); UnsupportedIds = @(); Templates = @()
                    AuditPolicyCoverage = 'NotVerified'; Error = $null
                })
            }
            catch {
                $message = "$path / XML import: $($_.Exception.Message)"
                $errors.Add($message)
                $issues.Add($message)
            }
        }
    }
    $ignored = 0
    foreach ($batch in $batches) {
        foreach ($xml in $batch.Events) {
            try {
                $event = Convert-NtlmAuditEvent -Xml $xml
                if ($null -eq $event) { $ignored++; continue }
                $time = [datetimeoffset]::Parse($event.TimeUtc, [cultureinfo]::InvariantCulture)
                if ($time -lt $StartTime -or $time -gt $EndTime) { $ignored++; continue }
                if ($seen.ContainsKey($event.EvidenceId)) {
                    if ($seen[$event.EvidenceId] -ne $event.RawXml) { throw 'Conflicting payloads share the same event provenance.' }
                    $duplicates++
                    continue
                }
                $seen.Add($event.EvidenceId, $event.RawXml)
                $observations.Add($event)
                foreach ($warning in $event.ParsingWarnings) { $issues.Add("$($event.EvidenceId): $warning") }
            }
            catch {
                $message = "$($batch.Label) / event normalization: $($_.Exception.Message)"
                $errors.Add($message)
                $issues.Add($message)
                $rejectedEvents.Add([pscustomobject]@{
                    Source = $batch.Label; Error = $_.Exception.Message; RawXml = $xml
                })
            }
        }
    }
    $events = @($observations.ToArray() | Sort-Object TimeUtc, SourceComputer, RecordId)
    $dependencies = @(Get-NtlmDependency -Events $events | Sort-Object ObservationCount -Descending)
    $status = if ($errors.Count -gt 0 -or $issues.Count -gt 0) { 'Partial' } else { 'Collected' }
    $report = [pscustomobject][ordered]@{
        Run = [pscustomobject]@{
            ToolVersion = '1.1.0'; Mode = $mode; Status = $status
            Scope = $(if ($AllDomainControllers) { 'AllDomainControllers' } elseif ($mode -eq 'Xml') { 'EventXmlPath' } else { 'ComputerName' })
            Domain = $(if ($AllDomainControllers -and $Domain) { $Domain } else { $null })
            Computers = @($ComputerName | Sort-Object -Unique)
            GeneratedUtc = [datetime]::UtcNow.ToString('o')
            StartUtc = $StartTime.UtcDateTime.ToString('o'); EndUtc = $EndTime.UtcDateTime.ToString('o')
            MaxEventsPerSource = $(if ($mode -eq 'Live') { $MaxEventsPerSource } else { $null })
            DuplicateRecords = $duplicates; IgnoredRecords = $ignored
            ErrorCount = $errors.Count; AuditPolicyCoverage = 'NotVerified'
            CountMeaning = 'Observations, not unique authentications. Dependency groups remain separate by observation point.'
        }
        Issues = @($issues.ToArray() | Sort-Object -Unique)
        Coverage = @($coverage.ToArray())
        Dependencies = $dependencies
        Events = $events
        RejectedEvents = @($rejectedEvents.ToArray())
    }
    $htmlPath = Export-NtlmReport -Report $report -Directory $OutputDir
    foreach ($issue in $report.Issues) { Write-Warning $issue }
    Write-Host ("NTLM report: {0}" -f $htmlPath)
    if ($errors.Count -gt 0) { throw "Audit incomplete: $($errors.Count) collection/normalization error(s). Partial reports were saved to $OutputDir." }
    if ($OpenReport) { Invoke-Item -LiteralPath $htmlPath -ErrorAction Stop }
    [pscustomobject]@{
        Status = $status; ObservationCount = $events.Count; DependencyGroupCount = $dependencies.Count
        ErrorCount = $errors.Count; HtmlPath = $htmlPath; JsonPath = (Join-Path $OutputDir 'NtlmAudit.json')
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $arguments = @{} + $PSBoundParameters
    $arguments.StartTime = $StartTime
    $arguments.EndTime = $EndTime
    $arguments.OutputDir = $OutputDir
    Invoke-NtlmAuditRun @arguments
}

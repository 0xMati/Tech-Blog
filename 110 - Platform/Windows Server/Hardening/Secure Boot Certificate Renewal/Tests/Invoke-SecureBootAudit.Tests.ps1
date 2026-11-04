$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-SecureBootAudit.ps1'
. $scriptPath

function Assert-SecureBootTestThrows {
    param([scriptblock]$Action)
    # Explicit catch supports the repository's Pester 3.4 on PowerShell 7.6.
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_ }
    ($null -ne $caught) | Should Be $true
}

if (-not ('SecureBootTestJob' -as [type])) {
Add-Type -TypeDefinition @'
public class SecureBootTestJob : System.Management.Automation.Job {
    public SecureBootTestJob(bool running) : base("Synthetic", "SecureBootTest") {
        SetJobState(running ? System.Management.Automation.JobState.Running : System.Management.Automation.JobState.Completed);
    }
    public override string Location { get { return "synthetic"; } }
    public override string StatusMessage { get { return "synthetic"; } }
    public override bool HasMoreData { get { return false; } }
    public override void StopJob() { SetJobState(System.Management.Automation.JobState.Stopped); }
}
'@
}

function New-TestSecureBootEvent {
    param([int]$Id = 1808, [long]$Record = 1, [string]$Time = '2026-11-04T10:00:00Z',
        [string]$Provider = 'Microsoft-Windows-TPM-WMI', [string]$Fields = '<Data Name="BucketId">sample-bucket</Data>')
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{0}"/><EventID>{1}</EventID><TimeCreated SystemTime="{2}"/><EventRecordID>{3}</EventRecordID><Channel>System</Channel></System><EventData>{4}</EventData></Event>' -f $Provider,$Id,$Time,$Record,$Fields
}

function New-TestSecureBootRecord {
    param([string]$Xml)
    $record = [pscustomobject]@{ Xml = $Xml }
    Add-Member -InputObject $record -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    $record
}

function New-TestSecureBootResult {
    [pscustomobject]@{
        SchemaVersion = 1
        Data = [pscustomobject]@{
            Hostname = 'server01'; CollectionTimeUtc = '2026-11-04T10:00:00Z'
            SecureBootEnabled = $true; UEFICA2023Status = 'Updated'; UEFICA2023Error = $null
            LatestEventId = 1808; EventReadStatus = 'Read'; Model = 'Test model'
        }
        Events = @((ConvertFrom-SecureBootEventXml -Xml (New-TestSecureBootEvent)))
        Issues = @()
    }
}

Describe 'Secure Boot CSV input' {
    It 'reads semicolon CSV and preserves optional descriptions' {
        $csv = Join-Path $TestDrive 'computers.csv'
        "ComputerName;Description`n server01.example.test ;Pilot" | Set-Content -LiteralPath $csv -Encoding utf8
        $targets = @(Import-SecureBootTargets $csv)
        $targets.Count | Should Be 1
        $targets[0].ComputerName | Should Be 'server01.example.test'
        $targets[0].Description | Should Be 'Pilot'
    }
    It 'accepts a single ComputerName column' {
        $csv = Join-Path $TestDrive 'one-column.csv'
        "ComputerName`nserver01" | Set-Content -LiteralPath $csv
        (Import-SecureBootTargets $csv).Description | Should BeNullOrEmpty
    }
    It 'rejects comma input rather than changing the scope' {
        $csv = Join-Path $TestDrive 'comma.csv'
        "ComputerName,Description`nserver01,Pilot" | Set-Content -LiteralPath $csv
        Assert-SecureBootTestThrows { Import-SecureBootTargets $csv }
    }
    It 'rejects a missing file' { Assert-SecureBootTestThrows { Import-SecureBootTargets (Join-Path $TestDrive 'absent.csv') } }
    It 'rejects missing input' { Assert-SecureBootTestThrows { Import-SecureBootTargets '' } }
    It 'rejects a header without computers' {
        $csv = Join-Path $TestDrive 'empty.csv'
        'ComputerName;Description' | Set-Content -LiteralPath $csv
        Assert-SecureBootTestThrows { Import-SecureBootTargets $csv }
    }
    foreach ($name in @('', '*.example.test', 'https://server01', 'server01,server02')) {
        It "rejects invalid computer name '$name' before returning targets" {
            $csv = Join-Path $TestDrive 'invalid.csv'
            "ComputerName;Description`nserver01;Valid`n$name;Invalid" | Set-Content -LiteralPath $csv
            Assert-SecureBootTestThrows { Import-SecureBootTargets $csv }
        }
    }
    It 'rejects duplicate computers without case sensitivity' {
        $csv = Join-Path $TestDrive 'duplicates.csv'
        "ComputerName;Description`nserver01;One`nSERVER01;Two" | Set-Content -LiteralPath $csv
        Assert-SecureBootTestThrows { Import-SecureBootTargets $csv }
    }
}

Describe 'Secure Boot event evidence and assessment' {
    It 'reads named fields, UTC time and original XML' {
        $xml = New-TestSecureBootEvent -Fields '<Data Name="BucketId">bucket-a</Data><Data Name="BucketConfidenceLevel">High</Data>'
        $event = ConvertFrom-SecureBootEventXml $xml
        $event.EventId | Should Be 1808
        $event.Fields['BucketId'] | Should Be 'bucket-a'
        $event.Fields['BucketConfidenceLevel'] | Should Be 'High'
        $event.TimeUtc | Should Match '^2026-11-04T10:00:00'
        $event.RawXml | Should Be $xml
    }
    It 'does not accept an unrelated provider with the same event ID' {
        Assert-SecureBootTestThrows { ConvertFrom-SecureBootEventXml (New-TestSecureBootEvent -Provider 'Other') }
    }
    It 'rejects XML entities and duplicate named fields' {
        Assert-SecureBootTestThrows { ConvertFrom-SecureBootEventXml '<!DOCTYPE Event [<!ENTITY x "test">]><Event>&x;</Event>' }
        Assert-SecureBootTestThrows { ConvertFrom-SecureBootEventXml (New-TestSecureBootEvent -Fields '<Data Name="Code">1</Data><Data Name="Code">2</Data>') }
    }
    It 'requires enabled Secure Boot, Updated and latest 1808 for UpdatedReported' {
        $snapshot = (New-TestSecureBootResult).Data
        Get-SecureBootAssessment $snapshot | Should Be 'UpdatedReported'
        $snapshot.SecureBootEnabled = $false
        Get-SecureBootAssessment $snapshot | Should Be 'Disabled'
        $snapshot.SecureBootEnabled = $null
        Get-SecureBootAssessment $snapshot | Should Be 'Unknown'
    }
    It 'does not treat a missing completion event as verified completion' {
        $snapshot = (New-TestSecureBootResult).Data
        $snapshot.LatestEventId = $null
        Get-SecureBootAssessment $snapshot | Should Be 'ReviewRequired'
        $snapshot.UEFICA2023Status = $null
        Get-SecureBootAssessment $snapshot | Should Be 'Unknown'
    }
    foreach ($id in @(1795,1796,1801,1802,1803)) {
        It "does not let Updated hide latest event $id" {
            $snapshot = (New-TestSecureBootResult).Data
            $snapshot.LatestEventId = $id
            Get-SecureBootAssessment $snapshot | Should Be 'ReviewRequired'
        }
    }
    It 'keeps restart, pending and collection errors separate' {
        $snapshot = (New-TestSecureBootResult).Data
        $snapshot.LatestEventId = 1800
        Get-SecureBootAssessment $snapshot | Should Be 'RestartIndicated'
        $snapshot.LatestEventId = $null
        $snapshot.UEFICA2023Status = 'InProgress'
        Get-SecureBootAssessment $snapshot | Should Be 'InProgress'
        $snapshot.UEFICA2023Status = 'NotStarted'
        Get-SecureBootAssessment $snapshot | Should Be 'NotStarted'
        Get-SecureBootAssessment $snapshot -ErrorCount 1 | Should Be 'Unknown'
    }
    It 'does not hide a nonzero servicing error behind Updated' {
        $snapshot = (New-TestSecureBootResult).Data
        $snapshot.UEFICA2023Error = 5
        Get-SecureBootAssessment $snapshot | Should Be 'ReviewRequired'
    }
}

Describe 'Secure Boot local collection without writes' {
    BeforeEach {
        $script:eventMode = 'Read'
        $script:registryMode = 'Read'
        $script:confirmFails = $false
        $script:confirmMode = 'Read'
        $script:retryTime = 133000000000000000
        $script:taskFails = $false
        $script:invalidDate = $false
        $script:highBit = $false
        $script:eventRecords = @(
            (New-TestSecureBootRecord (New-TestSecureBootEvent -Id 1808 -Record 2)),
            (New-TestSecureBootRecord (New-TestSecureBootEvent -Id 1800 -Record 1 -Time '2026-11-03T10:00:00Z'))
        )
        Mock Get-ItemProperty {
            if ($script:registryMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic registry denial') }
            if ($script:registryMode -eq 'Absent') { throw [Management.Automation.ItemNotFoundException]::new('Synthetic absent key') }
            if ($script:registryMode -eq 'NoState' -and $LiteralPath -like '*\State') {
                throw [Management.Automation.ItemNotFoundException]::new('Synthetic absent State key')
            }
            [pscustomobject]@{
                UEFISecureBootEnabled = 1; UEFICA2023Status = 'Updated'; UEFICA2023Error = 0
                AvailableUpdates = if ($script:highBit) { [int]::MinValue } else { 0x5944 }; AvailableUpdatesPolicy = 0x5944
                HighConfidenceOptOut = 1; MicrosoftUpdateManagedOptIn = 0
                OEMManufacturerName = 'Test OEM'; CanAttemptUpdateAfter = $script:retryTime
            }
        }
        Mock Get-CimInstance {
            [pscustomobject]@{
                Caption = 'Test Windows'; Version = '10.0.26100'; BuildNumber = '26100'; OSArchitecture = '64-bit'
                LastBootUpTime = [datetime]'2026-11-01T10:00:00Z'; Manufacturer = 'Test OEM'; Model = 'Model A'
                SMBIOSBIOSVersion = '1.0'; ReleaseDate = if ($script:invalidDate) { 'invalid-date' } else { [datetime]'2026-01-01T00:00:00Z' }; Product = 'Board A'
            }
        }
        Mock Confirm-SecureBootUEFI {
            if ($script:confirmMode -eq 'Unsupported') { throw 'Cmdlet not supported on this platform: 0xC0000002' }
            if ($script:confirmMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic Secure Boot denial') }
            if ($script:confirmMode -eq 'OtherFailure') { throw 'Synthetic unexpected Secure Boot failure' }
            if ($script:confirmFails) { throw 'Synthetic unsupported command' }
            $true
        }
        Mock Get-ScheduledTask {
            if ($script:taskFails) { throw [UnauthorizedAccessException]::new('Synthetic task denial') }
            [pscustomobject]@{ State = 'Ready'; Settings = [pscustomobject]@{ Enabled = $true } }
        }
        Mock Get-WinEvent {
            if ($script:eventMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic log denial') }
            if ($script:eventMode -eq 'Empty') {
                throw [Management.Automation.ErrorRecord]::new([Exception]::new('No events'), 'NoMatchingEventsFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
            }
            $script:eventRecords
        }
        Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*WinCsFlags.exe' }
        Mock New-ItemProperty { throw 'Unexpected write' }
        Mock Start-ScheduledTask { throw 'Unexpected deployment' }
        Mock Restart-Computer { throw 'Unexpected reboot' }
    }
    It 'collects typed state, firmware, task and events using the provider filter' {
        $result = Get-SecureBootLocalData
        $result.Data.SecureBootEnabled | Should Be $true
        $result.Data.AvailableUpdates | Should Be '0x5944'
        $result.Data.AvailableUpdatesPolicy | Should Be '0x5944'
        $result.Data.LatestEventId | Should Be 1808
        $result.Data.BucketId | Should Be 'sample-bucket'
        $result.Data.SecureBootTaskEnabled | Should Be $true
        $result.Data.Model | Should Be 'Model A'
        $result.Events.Count | Should Be 2
        @($result.Issues | Where-Object Kind -eq 'Error').Count | Should Be 0
        Assert-MockCalled Get-WinEvent -Times 1 -Exactly -Scope It -ParameterFilter {
            $FilterHashtable.LogName -eq 'System' -and
            $FilterHashtable.ProviderName -eq 'Microsoft-Windows-TPM-WMI' -and $MaxEvents -eq 51
        }
        Assert-MockCalled New-ItemProperty -Times 0 -Scope It
        Assert-MockCalled Start-ScheduledTask -Times 0 -Scope It
        Assert-MockCalled Restart-Computer -Times 0 -Scope It
    }
    It 'flags truncation and counts only the collected records' {
        $result = Get-SecureBootLocalData -MaxEvents 1
        $result.Data.EventLimitReached | Should Be $true
        $result.Events.Count | Should Be 1
        @($result.Issues | Where-Object Kind -eq 'Limited').Count | Should Be 1
    }
    It 'does not convert event-log failure into zero events or success' {
        $script:eventMode = 'Denied'
        $result = Get-SecureBootLocalData
        $result.Data.EventReadStatus | Should Be 'Error'
        $result.Data.Event1808Count | Should BeNullOrEmpty
        @($result.Issues | Where-Object Kind -eq 'Error').Count | Should BeGreaterThan 0
    }
    It 'distinguishes no retained events from a failed read' {
        $script:eventMode = 'Empty'
        $result = Get-SecureBootLocalData
        $result.Data.EventReadStatus | Should Be 'NoEvents'
        $result.Data.Event1808Count | Should Be 0
        Get-SecureBootAssessment $result.Data | Should Be 'ReviewRequired'
    }
    It 'uses the registry fallback explicitly without hiding the cmdlet failure' {
        $script:confirmFails = $true
        $result = Get-SecureBootLocalData
        $result.Data.SecureBootEnabled | Should Be $true
        $result.Data.SecureBootSource | Should Be 'RegistryFallback'
        @($result.Issues | Where-Object Kind -eq 'Fallback').Count | Should Be 1
    }
    It 'decodes the observed eight-byte FILETIME without unrolling its byte array' {
        $script:retryTime = [byte[]](32,206,102,174,148,106,221,1)
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should Be '2026-11-02T06:37:50.4660000Z'
        $result.Data.CanAttemptUpdateAfterRaw | Should Be '20-CE-66-AE-94-6A-DD-01'
        @($result.Issues | Where-Object Kind -eq 'Error').Count | Should Be 0
    }
    It 'still supports an integer FILETIME' {
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should Be ([datetime]::FromFileTimeUtc(133000000000000000).ToString('o'))
    }
    It 'keeps absent retry metadata absent rather than inventing a date' {
        $script:retryTime = $null
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should BeNullOrEmpty
        @($result.Issues | Where-Object Area -eq 'CanAttemptUpdateAfter').Count | Should Be 0
    }
    It 'records an invalid binary length and preserves the raw evidence' {
        $script:retryTime = [byte[]](1,2,3)
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should BeNullOrEmpty
        $result.Data.CanAttemptUpdateAfterRaw | Should Be '01-02-03'
        @($result.Issues | Where-Object { $_.Area -eq 'CanAttemptUpdateAfter' -and $_.Kind -eq 'Error' }).Count | Should Be 1
    }
    It 'rejects a numeric array that is not REG_BINARY instead of casting it to bytes' {
        $script:retryTime = [object[]](32,206,102,174,148,106,221,1)
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should BeNullOrEmpty
        @($result.Issues | Where-Object { $_.Area -eq 'CanAttemptUpdateAfter' -and $_.Kind -eq 'Error' }).Count | Should Be 1
    }
    It 'records an out-of-range FILETIME without losing the machine inventory' {
        $script:retryTime = [byte[]](255,255,255,255,255,255,255,255)
        $result = Get-SecureBootLocalData
        $result.Data.CanAttemptUpdateAfter | Should BeNullOrEmpty
        $result.Data.Model | Should Be 'Model A'
        @($result.Issues | Where-Object { $_.Area -eq 'CanAttemptUpdateAfter' -and $_.Kind -eq 'Error' }).Count | Should Be 1
    }
    It 'separates unsupported Secure Boot from remote collection failure and disabled state' {
        $script:confirmMode = 'Unsupported'
        $script:registryMode = 'NoState'
        $result = Get-SecureBootLocalData
        $result.Data.SecureBootEnabled | Should BeNullOrEmpty
        $result.Data.SecureBootSource | Should Be 'UnsupportedPlatform'
        @($result.Issues | Where-Object Kind -eq 'Error').Count | Should Be 0
        @($result.Issues | Where-Object Kind -eq 'Unsupported').Count | Should Be 1
        Get-SecureBootAssessment $result.Data | Should Be 'Unsupported'
        Get-SecureBootAssessment $result.Data -ErrorCount 1 | Should Be 'Unknown'
    }
    It 'retains a valid registry fallback even when the cmdlet is unsupported' {
        $script:confirmMode = 'Unsupported'
        $result = Get-SecureBootLocalData
        $result.Data.SecureBootSource | Should Be 'RegistryFallback'
        $result.Data.SecureBootEnabled | Should Be $true
    }
    It 'does not classify a permission denial as unsupported' {
        $script:confirmMode = 'Denied'
        $script:registryMode = 'NoState'
        $result = Get-SecureBootLocalData
        @($result.Issues | Where-Object { $_.Area -eq 'SecureBoot' -and $_.Kind -eq 'Error' }).Count | Should Be 1
        @($result.Issues | Where-Object Kind -eq 'Unsupported').Count | Should Be 0
    }
    It 'does not classify an unexpected cmdlet failure as unsupported' {
        $script:confirmMode = 'OtherFailure'
        $script:registryMode = 'NoState'
        $result = Get-SecureBootLocalData
        @($result.Issues | Where-Object { $_.Area -eq 'SecureBoot' -and $_.Kind -eq 'Error' }).Count | Should Be 1
    }
    It 'keeps unreadable registry values unknown and records the denial' {
        $script:registryMode = 'Denied'
        $result = Get-SecureBootLocalData
        $result.Data.ServicingReadStatus | Should Be 'Error'
        $result.Data.UEFICA2023Status | Should BeNullOrEmpty
        @($result.Issues | Where-Object Kind -eq 'Error').Count | Should BeGreaterThan 0
    }
    It 'distinguishes absent registry keys from access errors' {
        $script:registryMode = 'Absent'
        $result = Get-SecureBootLocalData
        $result.Data.ServicingReadStatus | Should Be 'Absent'
        @($result.Issues | Where-Object Kind -eq 'Missing').Count | Should Be 4
    }
    It 'records task permission failure without saying the task is disabled' {
        $script:taskFails = $true
        $result = Get-SecureBootLocalData
        $result.Data.SecureBootTaskEnabled | Should BeNullOrEmpty
        @($result.Issues | Where-Object Area -eq 'ScheduledTask')[0].Kind | Should Be 'Error'
    }
    It 'preserves other events when one XML record is malformed' {
        $script:eventRecords += New-TestSecureBootRecord '<Event />'
        $result = Get-SecureBootLocalData
        $result.Data.EventReadStatus | Should Be 'Partial'
        $result.Events.Count | Should Be 2
        @($result.Issues | Where-Object Area -eq 'EventXml').Count | Should Be 1
    }
    It 'does not let an older completion hide a newer firmware error' {
        $script:eventRecords += New-TestSecureBootRecord (New-TestSecureBootEvent -Id 1795 -Record 3 -Time '2026-11-04T11:00:00Z')
        $result = Get-SecureBootLocalData
        $result.Data.LatestEventId | Should Be 1795
        Get-SecureBootAssessment $result.Data | Should Be 'ReviewRequired'
    }
    It 'records an invalid firmware timestamp while retaining other inventory' {
        $script:invalidDate = $true
        $result = Get-SecureBootLocalData
        $result.Data.Model | Should Be 'Model A'
        $result.Data.FirmwareReleaseDate | Should BeNullOrEmpty
        @($result.Issues | Where-Object Area -eq 'Timestamp').Count | Should Be 1
    }
    It 'keeps a DWORD high bit in its original hexadecimal width' {
        $script:highBit = $true
        (Get-SecureBootLocalData).Data.AvailableUpdates | Should Be '0x80000000'
    }
}

Describe 'Secure Boot remote deadline and cleanup' {
    BeforeEach {
        $script:jobMode = 'Complete'
        $script:receivedResult = New-TestSecureBootResult
        $script:testJob = $null
        Mock Invoke-Command { $script:testJob = [SecureBootTestJob]::new($script:jobMode -eq 'Timeout'); $script:testJob }
        Mock Wait-Job { if ($script:jobMode -ne 'Timeout') { $Job } }
        Mock Receive-Job { if ($script:jobMode -eq 'Error') { throw 'Synthetic transport error' }; $script:receivedResult }
        Mock Stop-Job {}
        Mock Remove-Job {}
    }
    AfterEach { if ($null -ne $script:testJob) { $script:testJob.Dispose() } }
    It 'passes the deadline, event cap, credential and HTTPS without bypasses' {
        $credential = [pscredential]::new('EXAMPLE\test', (ConvertTo-SecureString 'synthetic-test-value' -AsPlainText -Force))
        $result = Invoke-SecureBootTarget -ComputerName server01 -Credential $credential -UseSSL -TimeoutSeconds 10 -MaxEvents 20
        $result.SchemaVersion | Should Be 1
        Assert-MockCalled Invoke-Command -Times 1 -Exactly -Scope It -ParameterFilter {
            $ComputerName -eq 'server01' -and $UseSSL -and $null -ne $Credential -and $AsJob -and $ArgumentList[0] -eq 20
        }
        Assert-MockCalled Wait-Job -Times 1 -Exactly -Scope It -ParameterFilter { $Timeout -gt 0 -and $Timeout -le 10 }
        Assert-MockCalled Remove-Job -Times 1 -Exactly -Scope It
    }
    It 'stops and removes a timed-out job' {
        $script:jobMode = 'Timeout'
        Assert-SecureBootTestThrows { Invoke-SecureBootTarget -ComputerName server01 -TimeoutSeconds 1 }
        Assert-MockCalled Stop-Job -Times 1 -Exactly -Scope It
        Assert-MockCalled Remove-Job -Times 1 -Exactly -Scope It
        Assert-MockCalled Receive-Job -Times 0 -Scope It
    }
    It 'removes failed jobs and propagates remote errors' {
        $script:jobMode = 'Error'
        Assert-SecureBootTestThrows { Invoke-SecureBootTarget -ComputerName server01 }
        Assert-MockCalled Remove-Job -Times 1 -Exactly -Scope It
    }
    It 'rejects an incomplete remote response' {
        $script:receivedResult.Data = [pscustomobject]@{}
        Assert-SecureBootTestThrows { Invoke-SecureBootTarget -ComputerName server01 }
    }
    It 'rejects a string that could be mistaken for an enabled Boolean' {
        $script:receivedResult.Data.SecureBootEnabled = 'false'
        Assert-SecureBootTestThrows { Invoke-SecureBootTarget -ComputerName server01 }
    }
}

Describe 'Secure Boot reports and partial runs' {
    BeforeEach {
        $script:reportFailureDirectory = $null
        $script:assessmentFailure = $false
        $script:targetMode = 'Mixed'
        $script:observedNames = [Collections.Generic.List[string]]::new()
        Mock Invoke-SecureBootTarget {
            $script:observedNames.Add($ComputerName)
            if ($ComputerName -eq 'offline' -or $script:targetMode -eq 'AllFailed') { throw 'Synthetic WinRM failure' }
            $result = New-TestSecureBootResult
            if ($script:targetMode -eq 'Unknown') { $result.Data.UEFICA2023Status = $null; $result.Data.LatestEventId = $null }
            if ($script:targetMode -eq 'Unsupported') {
                $result.Data.SecureBootEnabled = $null
                Add-Member -InputObject $result.Data -NotePropertyName SecureBootSource -NotePropertyValue 'UnsupportedPlatform'
                $result.Issues = @([pscustomobject]@{
                    Area = 'SecureBoot'; Kind = 'Unsupported'; Message = 'Cmdlet not supported on this platform: 0xC0000002'
                })
            }
            if ($script:targetMode -in 'ReadError','DisabledReadError') {
                $result.Issues = @([pscustomobject]@{ Area = 'Events'; Kind = 'Error'; Message = 'Synthetic event read denial' })
                if ($script:targetMode -eq 'DisabledReadError') { $result.Data.SecureBootEnabled = $false }
            }
            $result
        }
        Mock Invoke-Item {}
        Mock Get-SecureBootAssessment { throw 'Synthetic assessment failure' } -ParameterFilter { $script:assessmentFailure }
        Mock Export-SecureBootReport { throw 'Synthetic report-write failure' } -ParameterFilter { $Directory -eq $script:reportFailureDirectory }
        $script:inputCsv = Join-Path $TestDrive 'input.csv'
        "ComputerName;Description`noffline;Unavailable`nserver01;=SUM(1+1)" | Set-Content -LiteralPath $script:inputCsv
    }
    It 'continues after an unavailable computer and opens the partial HTML' {
        $output = Join-Path $TestDrive 'partial'
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir $output -OpenReport -WarningAction SilentlyContinue
        $result.Status | Should Be 'Partial'
        $result.ComputerCount | Should Be 2
        $result.ErrorCount | Should Be 1
        $script:observedNames.Count | Should Be 2
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Computers[0].Assessment | Should Be 'CollectionFailed'
        $json.Computers[0].Data | Should BeNullOrEmpty
        $json.Computers[1].Assessment | Should Be 'UpdatedReported'
        Assert-MockCalled Invoke-Item -Times 1 -Exactly -Scope It
        $csv = @(Import-Csv -LiteralPath (Join-Path $output 'Computers.csv') -Delimiter ';')
        $csv.Count | Should Be 2
        $csv[1].Description | Should Be "'=SUM(1+1)"
        $json.Computers[1].Description | Should Be '=SUM(1+1)'
        @(Import-Csv -LiteralPath (Join-Path $output 'Events.csv') -Delimiter ';').Count | Should Be 1
        @(Import-Csv -LiteralPath (Join-Path $output 'Issues.csv') -Delimiter ';').Count | Should Be 1
    }
    It 'still reports every requested target when all computers fail' {
        $script:targetMode = 'AllFailed'
        $output = Join-Path $TestDrive 'all-failed'
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir $output -WarningAction SilentlyContinue
        $result.ErrorCount | Should Be 2
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Computers.Count | Should Be 2
        $json.Computers[1].Assessment | Should Be 'CollectionFailed'
        (Get-Content -LiteralPath (Join-Path $output 'Events.csv') -Raw) | Should Match '"ComputerName";"EventId"'
    }
    It 'does not use the process exit meaning as a compliance decision' {
        $script:targetMode = 'Unknown'
        "ComputerName`nserver01" | Set-Content -LiteralPath $script:inputCsv
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir (Join-Path $TestDrive 'unknown')
        $result.ErrorCount | Should Be 0
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Status | Should Be 'Collected'
        $json.Computers[0].Assessment | Should Be 'Unknown'
    }
    It 'shows returned inventory separately from a partial read and a remote failure' {
        $script:targetMode = 'ReadError'
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir (Join-Path $TestDrive 'read-error') -WarningAction SilentlyContinue
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match '1 / 2 returned inventory'
        $html | Should Match 'Data received'
        $html | Should Match 'Partial reads'
        $html | Should Match 'No inventory'
        $html | Should Match 'Synthetic event read denial'
        $html | Should Match 'id="state"'
        $html | Should Match 'id="reset"'
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Computers[1].CollectionStatus | Should Be 'Partial'
        $json.Computers[1].Assessment | Should Be 'Unknown'
    }
    It 'reports platform limitations without claiming a remote failure or disabled Secure Boot' {
        $script:targetMode = 'Unsupported'
        "ComputerName`nserver01" | Set-Content -LiteralPath $script:inputCsv
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir (Join-Path $TestDrive 'unsupported') -WarningAction SilentlyContinue
        $result.ErrorCount | Should Be 0
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Computers[0].CollectionStatus | Should Be 'Collected'
        $json.Computers[0].Assessment | Should Be 'Unsupported'
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match '1 / 1 returned inventory'
        $html | Should Match 'Platform unsupported'
        $html | Should Match '0xC0000002'
        $html | Should Match 'Check firmware mode'
    }
    It 'keeps a measured disabled state filterable even if another read makes the assessment unknown' {
        $script:targetMode = 'DisabledReadError'
        "ComputerName`nserver01" | Set-Content -LiteralPath $script:inputCsv
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir (Join-Path $TestDrive 'disabled-partial') -WarningAction SilentlyContinue
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match 'data-assessment="Unknown" data-boot="Disabled"'
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $json.Computers[0].Data.SecureBootEnabled | Should Be $false
        $json.Computers[0].Assessment | Should Be 'Unknown'
    }
    It 'rejects existing output directories before contacting a computer' {
        Assert-SecureBootTestThrows { Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir $TestDrive }
        $script:observedNames.Count | Should Be 0
    }
    It 'does not leave a success-shaped collection status after interpretation fails' {
        $script:assessmentFailure = $true
        "ComputerName`nserver01" | Set-Content -LiteralPath $script:inputCsv
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir (Join-Path $TestDrive 'assessment-failed') -WarningAction SilentlyContinue
        $json = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $result.ErrorCount | Should Be 1
        $json.Computers[0].CollectionStatus | Should Be 'Failed'
        $json.Computers[0].Assessment | Should Be 'CollectionFailed'
    }
    It 'keeps report-write failures terminating' {
        $script:reportFailureDirectory = Join-Path $TestDrive 'cannot-save'
        Assert-SecureBootTestThrows { Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir $script:reportFailureDirectory }
        Assert-MockCalled Invoke-Item -Times 0 -Scope It
    }
    It 'encodes untrusted HTML and formula-like CSV without changing JSON' {
        $output = Join-Path $TestDrive 'escaped'
        "ComputerName;Description`nserver01;<script>alert(1)</script>" | Set-Content -LiteralPath $script:inputCsv
        $result = Invoke-SecureBootAuditRun -CsvPath $script:inputCsv -OutputDir $output
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Not Match '<script>alert\(1\)</script>'
        $html | Should Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should Match 'not firmware certificate attestation'
    }
}

Describe 'Secure Boot Windows PowerShell 5.1 payload execution' {
    It 'executes binary timestamp, unsupported and denied reads under the actual target runtime' {
        $runner = Join-Path $TestDrive 'payload51.ps1'
        $definitions = @"
function ConvertFrom-SecureBootEventXml { ${function:ConvertFrom-SecureBootEventXml} }
function Get-SecureBootLocalData { ${function:Get-SecureBootLocalData} }
"@
        $syntheticReads = @'
$ErrorActionPreference = 'Stop'
function Get-ItemProperty {
    [CmdletBinding()]param($LiteralPath)
    if ($LiteralPath -like '*\State' -and $script:platformMode -ne 'Enabled') {
        throw [Management.Automation.ItemNotFoundException]::new('Synthetic absent State key')
    }
    [pscustomobject]@{
        UEFISecureBootEnabled = 1; UEFICA2023Status = 'Updated'
        CanAttemptUpdateAfter = [byte[]](32,206,102,174,148,106,221,1)
    }
}
function Get-CimInstance {
    [CmdletBinding()]param($ClassName)
    [pscustomobject]@{ Caption = 'Synthetic Windows'; Model = 'Synthetic model' }
}
function Confirm-SecureBootUEFI {
    [CmdletBinding()]param()
    if ($script:platformMode -eq 'Unsupported') { throw 'Cmdlet not supported on this platform: 0xC0000002' }
    if ($script:platformMode -eq 'Denied') { throw [UnauthorizedAccessException]::new('Synthetic permission denial') }
    $true
}
function Get-ScheduledTask {
    [CmdletBinding()]param($TaskPath, $TaskName)
    [pscustomobject]@{ State = 'Ready'; Settings = [pscustomobject]@{ Enabled = $true } }
}
function Get-WinEvent {
    [CmdletBinding()]param($FilterHashtable, $MaxEvents)
    throw [Management.Automation.ErrorRecord]::new([Exception]::new('No events'), 'NoMatchingEventsFound',
        [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
}
function Test-Path {
    [CmdletBinding()]param($LiteralPath)
    $false
}
$results = foreach ($mode in 'Enabled','Unsupported','Denied') {
    $script:platformMode = $mode
    $result = Get-SecureBootLocalData
    [pscustomobject]@{ Mode = $mode; Result = $result }
}
[pscustomobject]@{
    Version = $PSVersionTable.PSVersion.ToString()
    Results = [Management.Automation.PSSerializer]::Deserialize([Management.Automation.PSSerializer]::Serialize(@($results)))
} | ConvertTo-Json -Depth 12 -Compress
'@
        $definitions + "`n" + $syntheticReads | Set-Content -LiteralPath $runner -Encoding utf8
        $legacy = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $output = & $legacy -NoProfile -NonInteractive -File $runner | Out-String
        $LASTEXITCODE | Should Be 0
        $output | Should Match '"CanAttemptUpdateAfter":"2026-11-02T06:37:50.4660000Z"'
        $result = $output | ConvertFrom-Json
        $result.Version | Should Match '^5\.1\.'
        $result.Results.Count | Should Be 3
        foreach ($entry in $result.Results) {
            ([datetime]$entry.Result.Data.CanAttemptUpdateAfter).ToUniversalTime().ToString('o') | Should Be '2026-11-02T06:37:50.4660000Z'
            $entry.Result.Data.CanAttemptUpdateAfterRaw | Should Be '20-CE-66-AE-94-6A-DD-01'
        }
        $result.Results[0].Result.Data.SecureBootEnabled | Should Be $true
        $result.Results[1].Result.Data.SecureBootEnabled | Should BeNullOrEmpty
        $result.Results[1].Result.Data.SecureBootSource | Should Be 'UnsupportedPlatform'
        @($result.Results[1].Result.Issues | Where-Object Kind -eq 'Error').Count | Should Be 0
        @($result.Results[2].Result.Issues | Where-Object { $_.Area -eq 'SecureBoot' -and $_.Kind -eq 'Error' }).Count | Should Be 1
    }
}

Describe 'Secure Boot direct script exit code' {
    It 'writes partial outputs and exits 1 for a synthetic transport failure without network calls' {
        $csv = Join-Path $TestDrive 'cli.csv'
        "ComputerName`nserver01" | Set-Content -LiteralPath $csv
        $output = Join-Path $TestDrive 'cli-output'
        $runner = Join-Path $TestDrive 'runner.ps1'
        @"
function Invoke-Command {
    [CmdletBinding()]
    param(`$ComputerName, `$ScriptBlock, `$ArgumentList, [switch]`$AsJob, `$SessionOption)
    throw 'Synthetic transport failure; no network call'
}
& '$($scriptPath.Replace("'","''"))' -CsvPath '$($csv.Replace("'","''"))' -OutputDir '$($output.Replace("'","''"))'
exit `$LASTEXITCODE
"@ | Set-Content -LiteralPath $runner
        $PSNativeCommandUseErrorActionPreference = $false
        $null = & (Get-Process -Id $PID).Path -NoProfile -File $runner 2>&1
        $LASTEXITCODE | Should Be 1
        Test-Path -LiteralPath (Join-Path $output 'SecureBootAudit.html') | Should Be $true
    }
}

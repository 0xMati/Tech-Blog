$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Invoke-NtlmAudit.ps1'
. $scriptPath

function New-TestNtlmXml {
    param(
        [int]$Id = 4020,
        [string]$Provider = 'Microsoft-Windows-NTLM',
        [System.Collections.IDictionary]$Data = @{},
        [long]$Record = 1,
        [int]$Version = 0,
        [string]$Computer = 'source.example.test',
        [string]$Time = '2025-11-02T12:00:00Z',
        [int]$Level = 4
    )
    $channel = if ($Provider -eq 'Microsoft-Windows-Security-Auditing') { 'Security' } else { 'Microsoft-Windows-NTLM/Operational' }
    $fields = foreach ($key in $Data.Keys) {
        '<Data Name="{0}">{1}</Data>' -f [Net.WebUtility]::HtmlEncode([string]$key), [Net.WebUtility]::HtmlEncode([string]$Data[$key])
    }
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="{0}"/><EventID>{1}</EventID><Version>{2}</Version><Level>{3}</Level><TimeCreated SystemTime="{4}"/><EventRecordID>{5}</EventRecordID><Channel>{6}</Channel><Computer>{7}</Computer></System><EventData>{8}</EventData></Event>' -f
        $Provider, $Id, $Version, $Level, $Time, $Record, $channel, $Computer, ($fields -join '')
}

function New-TestNtlmRecord {
    param([string]$Xml)
    $record = [pscustomobject]@{ Xml = $Xml; TimeCreated = [datetime]'2025-11-01T00:00:00Z' }
    Add-Member -InputObject $record -MemberType ScriptMethod -Name ToXml -Value { $this.Xml }
    $record
}

Describe 'NTLM named-field normalization' {
    foreach ($id in 4020,4021) {
        It "normalizes client event $id using the installed manifest field names" {
            $xml = New-TestNtlmXml -Id $id -Data ([ordered]@{
                ProcessName = 'C:\Apps\example.exe'; ProcessPID = '0x123'; Username = 'service'
                DomainName = 'EXAMPLE'; Hostname = 'client.example.test'; TargetMachine = 'server.example.test'
                TargetDomain = 'EXAMPLE'; TargetService = 'cifs/server.example.test'; TargetIP = '192.0.2.10'
                NtlmUsageId = '7'; NtlmUsageReason = 'Target name contains an IP address.'
                NtlmVersion = 'NTLMv2'; 'Mic Status' = 'Protected'; AvlFlags = '0x2'; AvlFlagsStr = 'sample'
                UnexpectedFutureField = 'preserved'
            })
            $event = Convert-NtlmAuditEvent -Xml $xml
            $event.EventId | Should Be $id
            $event.ObservationPoint | Should Be 'Client'
            $event.InitiatingProcess | Should Be 'C:\Apps\example.exe'
            $event.ReasonId | Should Be '7'
            $event.NtlmVersion | Should Be 'NTLMv2'
            $event.AuthenticationResult | Should Be 'Attempt'
            $event.MicStatus | Should Be 'Protected'
            $event.AvFlags | Should Be '0x2'
            $event.RawFields['UnexpectedFutureField'] | Should Be 'preserved'
            $event.RawXml | Should Match 'UnexpectedFutureField'
        }
    }

    foreach ($id in 4022,4023) {
        It "keeps the resource-server process separate for event $id" {
            $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id $id -Data @{
                Username = 'user'; DomainName = 'EXAMPLE'; ProcessName = 'C:\Windows\server.exe'
                RemoteClientMachine = 'client'; ClientIP = '192.0.2.5'; TargetMachine = 'server'
                NtlmVersion = 'NTLM V2'; Status = '0xc000006d'; 'Mic Status' = 'Unprotected'
            })
            $event.ObservationPoint | Should Be 'ResourceServer'
            $event.InitiatingProcess | Should BeNullOrEmpty
            $event.LocalProcess | Should Be 'C:\Windows\server.exe'
            $event.ClientName | Should Be 'client'
            $event.AuthenticationResult | Should Be 'ProcessingFailure'
            $event.NtlmVersion | Should Be 'NTLMv2'
            $event.ReasonId | Should BeNullOrEmpty
        }
    }

    foreach ($id in 4030,4031,4032,4033) {
        It "normalizes Security-Netlogon event $id without inventing client reason or process fields" {
            $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id $id -Provider 'Microsoft-Windows-Security-Netlogon' -Data @{
                AccountName = 'user'; AccountDomain = 'EXAMPLE'; AccountMachine = 'client'
                ServerName = 'server'; ServerDomain = 'RESOURCE'; NtlmVersion = 'NTLMv1'
                ForwarderName = 'dc.resource.example.test'; ForwarderIP = '192.0.2.20'; Status = '0x0'
            })
            $event.ObservationPoint | Should Be 'DomainController'
            $event.AccountName | Should Be 'user'
            $event.TargetName | Should Be 'server'
            $event.NtlmVersion | Should Be 'NTLMv1'
            $event.ForwarderName | Should Be 'dc.resource.example.test'
            $event.AuthenticationResult | Should Be 'ProcessingSuccess'
            $event.InitiatingProcess | Should BeNullOrEmpty
            $event.ReasonId | Should BeNullOrEmpty
        }
    }

    It 'does not classify a Warning as NTLMv1 or a missing protection as insecure' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4021 -Level 3)
        $event.NtlmVersion | Should Be 'Unknown'
        $event.ChannelBindingStatus | Should BeNullOrEmpty
    }

    It 'preserves an unrecognized reason without assigning a root cause' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Data @{ NtlmUsageId = '999'; NtlmUsageReason = 'new reason' })
        $event.ReasonId | Should Be '999'
        $event.RawReason | Should Be 'new reason'
        $event.ReasonDescription | Should Be 'Not established'
    }

    It 'retains future event versions with an explicit schema warning' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Version 1)
        $event.EventVersion | Should Be 1
        $event.ParsingWarnings.Count | Should Be 1
    }

    It 'does not interpret the 4776 package name as NTLMv1' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4776 -Provider 'Microsoft-Windows-Security-Auditing' -Data @{
            PackageName = 'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0'; TargetUserName = 'user'
            Workstation = 'client'; Status = '0'
        })
        $event.NtlmVersion | Should Be 'Unknown'
        $event.TargetName | Should BeNullOrEmpty
        $event.AuthenticationResult | Should Be 'ProcessingSuccess'
    }

    It 'accepts explicit 4624 NTLM evidence but separates anonymous activity' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4624 -Provider 'Microsoft-Windows-Security-Auditing' -Data @{
            AuthenticationPackageName = 'NTLM'; LmPackageName = 'NTLM V1'
            TargetUserName = 'ANONYMOUS LOGON'; TargetUserSid = 'S-1-5-7'
        })
        $event.RawNtlmVersion | Should Be 'NTLM V1'
        $event.NtlmVersion | Should Be 'Unknown'
        $event.AuthenticationResult | Should Be 'LogonSuccess'
    }

    It 'separates enhanced null sessions from credential-bearing version evidence' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Data @{ NtlmUsageId = '11'; NtlmVersion = 'NTLMv1' })
        $event.NtlmVersion | Should Be 'Unknown'
    }

    It 'ignores Security events without an explicit NTLM authentication package' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4624 -Provider 'Microsoft-Windows-Security-Auditing' -Data @{
            AuthenticationPackageName = 'Negotiate'
        })
        $event | Should BeNullOrEmpty
    }

    It 'does not accept a recognized ID from the wrong provider' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4032)
        $event | Should BeNullOrEmpty
    }

    It 'normalizes classic domain evidence without guessing the application target' {
        $event = Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 8004 -Provider 'Microsoft-Windows-Security-Netlogon' -Data @{
            UserName = 'user'; DomainName = 'EXAMPLE'; WorkstationName = 'client'; SChannelName = 'secure-channel'
        })
        $event.ClientName | Should Be 'client'
        $event.TargetName | Should BeNullOrEmpty
        $event.NtlmVersion | Should Be 'Unknown'
    }

    It 'rejects malformed or incomplete provenance' {
        { Convert-NtlmAuditEvent -Xml '<Event><EventData/></Event>' } | Should Throw 'System'
        { Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Time 'not-a-time') } | Should Throw 'not-a-time'
    }

    It 'rejects external XML entities' {
        { Read-NtlmXml -Text '<!DOCTYPE Event [<!ENTITY x SYSTEM "file:///not-allowed">]><Event>&x;</Event>' } | Should Throw 'DTD'
    }

    It 'keeps client/server/DC observations as separate dependency groups' {
        $events = @(
            Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Data @{ Username = 'user'; TargetMachine = 'server' })
            Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Id 4022 -Record 2 -Data @{ Username = 'user'; TargetMachine = 'server' })
        )
        @(Get-NtlmDependency -Events $events).Count | Should Be 2
    }

    It 'keeps distinct IP targets separate when no machine or service name is available' {
        $events = @(
            Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Record 1 -Data @{ TargetIP = '192.0.2.1' })
            Convert-NtlmAuditEvent -Xml (New-TestNtlmXml -Record 2 -Data @{ TargetIP = '192.0.2.2' })
        )
        $dependencies = @(Get-NtlmDependency -Events $events)
        $dependencies.Count | Should Be 2
        @($dependencies.TargetIP | Sort-Object -Unique).Count | Should Be 2
    }
}

Describe 'NTLM live collection boundary' {
    BeforeEach {
        $script:queryRecords = @{}
        $script:queries = [System.Collections.Generic.List[string]]::new()
        $script:oldestDate = [datetime]'2025-11-01T00:00:00Z'
        $script:channelDisabled = $false
        $script:providerUnavailable = $false
        $script:sourceAccessDenied = $false
        Mock Get-CimInstance { [pscustomobject]@{ Caption = 'Test Windows'; BuildNumber = '26100'; DomainRole = 4 } }
        Mock Get-WinEvent {
            param($ListLog, $ListProvider, $LogName, $Oldest, $MaxEvents, $FilterXml)
            if ($ListLog) {
                if ($script:channelDisabled) { return [pscustomobject]@{ IsEnabled = $false } }
                return [pscustomobject]@{ IsEnabled = $true; RecordCount = 1; MaximumSizeInBytes = 1048576; LogMode = 'Circular' }
            }
            if ($ListProvider) {
                if ($script:providerUnavailable) { Write-Error 'Provider unavailable' -ErrorId NoMatchingProvidersFound -ErrorAction Stop }
                $ids = switch ($ListProvider) {
                    'Microsoft-Windows-NTLM' { @(4020,4021,4022,4023,8001,8002,8003) }
                    'Microsoft-Windows-Security-Netlogon' { @(4030,4031,4032,4033,8004) }
                    default { @(4624,4625,4776) }
                }
                return [pscustomobject]@{ Events = @($ids | ForEach-Object {
                    [pscustomobject]@{ Id = $_; Version = 0; Template = '<template/>' }
                }) }
            }
            if ($Oldest) { return [pscustomobject]@{ TimeCreated = $script:oldestDate } }
            if ($FilterXml) {
                if ($script:sourceAccessDenied) { throw [UnauthorizedAccessException]::new('Access denied') }
                $queryText = $FilterXml.OuterXml
                $script:queries.Add($queryText)
                $records = @()
                foreach ($name in $script:queryRecords.Keys) {
                    if ($queryText.Contains("Provider[@Name='$name']")) { $records = @($script:queryRecords[$name]) }
                }
                if ($records.Count -eq 0) { Write-Error 'No matching events.' -ErrorId NoMatchingEventsFound -ErrorAction Stop }
                return $records
            }
            throw 'Unexpected event-log request.'
        }
    }

    It 'uses the correct providers and treats only NoMatchingEventsFound as an empty result' {
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 10
        $result.Coverage.Count | Should Be 3
        @($result.Coverage | Where-Object Status -eq 'NoEvents').Count | Should Be 3
        $script:queries.Count | Should Be 3
        $script:queries[1] | Should Match 'Microsoft-Windows-Security-Netlogon'
        $script:queries[2] | Should Match 'AuthenticationPackageName'
        foreach ($query in $script:queries) { { [xml]$query } | Should Not Throw }
    }

    It 'detects truncation using a lookahead event and preserves the newest matching subset' {
        $script:queryRecords['Microsoft-Windows-NTLM'] = @(
            New-TestNtlmRecord (New-TestNtlmXml -Record 3)
            New-TestNtlmRecord (New-TestNtlmXml -Record 2)
            New-TestNtlmRecord (New-TestNtlmXml -Record 1)
        )
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        $result.Coverage[0].Truncated | Should Be $true
        $result.Coverage[0].Collected | Should Be 2
        $result.Events.Count | Should Be 2
    }

    It 'marks an observation window older than retained history as unproven' {
        $script:oldestDate = [datetime]'2025-11-02Z'
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        $result.Coverage[0].RetentionUnproven | Should Be $true
    }

    It 'surfaces access denial rather than returning an empty source' {
        $script:sourceAccessDenied = $true
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        @($result.Coverage | Where-Object Status -eq 'Error').Count | Should Be 3
        $result.Coverage[0].Error | Should Match 'Access denied'
    }

    It 'does not query disabled channels' {
        $script:channelDisabled = $true
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        @($result.Coverage | Where-Object Status -eq 'Disabled').Count | Should Be 3
        $script:queries.Count | Should Be 0
    }

    It 'reports unavailable providers as unsupported, not as successful empty collection' {
        $script:providerUnavailable = $true
        $result = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        (($result.Coverage | ForEach-Object { "$($_.Status): $($_.Error)" }) -join '; ') |
            Should Be 'Unsupported: Provider unavailable; Unsupported: Provider unavailable; Unsupported: Provider unavailable'
        $result.Coverage[0].UnsupportedIds.Count | Should Be 7
    }

    It 'constructs the time window and filters Security evidence by explicit NTLM package and provider' {
        $null = Get-NtlmSourceData -StartUtc ([datetime]'2025-11-01Z') -EndUtc ([datetime]'2025-11-03Z') -Limit 2
        [xml]$query = $script:queries[2]
        $xpath = $query.SelectSingleNode('/QueryList/Query/Select').InnerText
        $ntlm = Read-NtlmXml -Text (New-TestNtlmXml -Id 4624 -Provider 'Microsoft-Windows-Security-Auditing' -Data @{
            AuthenticationPackageName = 'NTLM'
        })
        $other = Read-NtlmXml -Text (New-TestNtlmXml -Id 4624 -Provider 'Microsoft-Windows-Security-Auditing' -Data @{
            AuthenticationPackageName = 'Negotiate'
        })
        $xpath | Should Match '2025-11-01T'
        $xpath | Should Match '2025-11-03T'
        # .NET XPath lacks the Windows Event Log datetime comparison extension.
        $packagePredicate = $xpath -replace " and TimeCreated\[[^\]]+\]", ''
        $ntlmWithoutNamespace = Read-NtlmXml -Text ($ntlm.OuterXml -replace ' xmlns="[^"]+"', '')
        $otherWithoutNamespace = Read-NtlmXml -Text ($other.OuterXml -replace ' xmlns="[^"]+"', '')
        $ntlmWithoutNamespace.CreateNavigator().Evaluate($packagePredicate) | Should Be $true
        $otherWithoutNamespace.CreateNavigator().Evaluate($packagePredicate) | Should Be $false
    }
}

Describe 'NTLM domain controller discovery' {
    function Get-ADDomainController {
        [CmdletBinding()]
        param([string]$Filter, [string]$Server, [pscredential]$Credential)
        throw 'Domain discovery must be mocked in tests.'
    }

    BeforeEach {
        $script:discoveryRunArgs = @{
            StartTime = [datetimeoffset]'2025-11-01T00:00:00Z'
            EndTime = [datetimeoffset]'2025-11-03T00:00:00Z'
            OutputDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        }
        $script:discoveredDcs = @(
            [pscustomobject]@{ HostName = 'dc02.example.test'; IsReadOnly = $true }
            [pscustomobject]@{ HostName = 'dc01.example.test'; IsReadOnly = $false }
            [pscustomobject]@{ HostName = 'DC01.example.test'; IsReadOnly = $false }
        )
        $script:moduleImports = 0
        $script:discoveryImportFails = $false
        $script:discoveryFails = $false
        $script:unreachableDc = $null
        $script:discoveryCalls = [System.Collections.Generic.List[object]]::new()
        $script:remoteCalls = [System.Collections.Generic.List[object]]::new()
        Mock Write-Host {}
        Mock Write-Warning {}
        Mock Import-Module {
            param($Name)
            if ($Name -ne 'ActiveDirectory') { throw "Unexpected module import: $Name" }
            $script:moduleImports++
            if ($script:discoveryImportFails) { throw 'ActiveDirectory module not available (RSAT).' }
        }
        Mock Get-ADDomainController {
            param($Filter, $Server, $Credential)
            $script:discoveryCalls.Add([pscustomobject]@{ Filter = $Filter; Server = $Server; Credential = $Credential })
            if ($script:discoveryFails) { throw 'Directory access denied.' }
            $script:discoveredDcs
        }
        Mock Invoke-Command {
            param($ComputerName, $Credential, $ArgumentList)
            $script:remoteCalls.Add([pscustomobject]@{ ComputerName = $ComputerName; Credential = $Credential; Arguments = $ArgumentList })
            if ($ComputerName -eq $script:unreachableDc) { throw 'WinRM unavailable.' }
            [pscustomobject]@{
                Coverage = @([pscustomobject]@{
                    Computer = $ComputerName; Channel = 'Microsoft-Windows-NTLM/Operational'
                    Provider = 'Microsoft-Windows-Security-Netlogon'; Status = 'Collected'
                    RetentionUnproven = $false; Truncated = $false
                })
                Events = @(New-TestNtlmXml -Id 4032 -Provider 'Microsoft-Windows-Security-Netlogon' -Computer $ComputerName)
                MetadataErrors = @()
            }
        }
    }

    It 'collects every unique discovered DC including RODCs in the default domain context' {
        $result = Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers
        $script:moduleImports | Should Be 1
        $script:discoveryCalls.Count | Should Be 1
        $script:discoveryCalls[0].Filter | Should Be '*'
        $script:discoveryCalls[0].Server | Should BeNullOrEmpty
        $script:discoveryCalls[0].Credential | Should BeNullOrEmpty
        $script:remoteCalls.Count | Should Be 2
        ($script:remoteCalls.ComputerName -join ',').ToLowerInvariant() | Should Be 'dc01.example.test,dc02.example.test'
        $script:remoteCalls[0].Arguments[2] | Should Be 10000
        $result.ObservationCount | Should Be 2
        $result.Status | Should Be 'Collected'
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Scope | Should Be 'AllDomainControllers'
        $report.Run.Domain | Should BeNullOrEmpty
        $report.Run.Computers.Count | Should Be 2
        $report.Coverage.Count | Should Be 2
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match 'Scope: AllDomainControllers'
        $html | Should Match 'DC-only collection'
        $html | Should Match 'Member servers and client computers were not automatically included'
    }

    It 'uses the requested domain and credential for discovery and remote collection' {
        $credential = [pscredential]::new('EXAMPLE\audit', (ConvertTo-SecureString 'synthetic-test-only' -AsPlainText -Force))
        $script:discoveredDcs = @([pscustomobject]@{ HostName = 'dc01.example.test'; IsReadOnly = $false })
        $result = Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers -Domain 'example.test' -Credential $credential -MaxEventsPerSource 25
        $script:discoveryCalls[0].Server | Should Be 'example.test'
        $script:discoveryCalls[0].Credential | Should Be $credential
        $script:remoteCalls.Count | Should Be 1
        $script:remoteCalls[0].Credential | Should Be $credential
        $script:remoteCalls[0].Arguments[2] | Should Be 25
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Domain | Should Be 'example.test'
        $report.Run.Computers.Count | Should Be 1
        $report.Run.Computers[0] | Should Be 'dc01.example.test'
    }

    It 'fails before collecting or writing reports when the AD module is missing' {
        $script:discoveryImportFails = $true
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers } | Should Throw 'ActiveDirectory module not available'
        $script:discoveryCalls.Count | Should Be 0
        $script:remoteCalls.Count | Should Be 0
        Test-Path -LiteralPath $script:discoveryRunArgs.OutputDir | Should Be $false
    }

    It 'propagates directory errors without falling back to another scope' {
        $script:discoveryFails = $true
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers -Domain 'example.test' } | Should Throw 'Directory access denied'
        $script:remoteCalls.Count | Should Be 0
        Test-Path -LiteralPath $script:discoveryRunArgs.OutputDir | Should Be $false
    }

    It 'rejects empty discovery instead of producing a clean empty report' {
        $script:discoveredDcs = @()
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers } | Should Throw 'No domain controllers were discovered'
        $script:remoteCalls.Count | Should Be 0
        Test-Path -LiteralPath $script:discoveryRunArgs.OutputDir | Should Be $false
    }

    It 'rejects a discovered DC without a usable hostname before collecting' {
        $script:discoveredDcs += [pscustomobject]@{ HostName = ' ' }
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers } | Should Throw 'empty HostName'
        $script:remoteCalls.Count | Should Be 0
    }

    It 'rejects mixed scopes, a domain without discovery and a false-only discovery switch' {
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -ComputerName 'dc01' -AllDomainControllers } | Should Throw 'choose exactly one scope'
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -EventXmlPath 'unused.xml' -AllDomainControllers } | Should Throw 'choose exactly one scope'
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -ComputerName 'dc01' -Domain 'example.test' } | Should Throw 'Domain requires AllDomainControllers'
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers:$false } | Should Throw 'choose exactly one scope'
        $script:moduleImports | Should Be 0
        $script:remoteCalls.Count | Should Be 0
    }

    It 'rejects blank domain input before discovery' {
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers -Domain ' ' } | Should Throw 'Domain'
        $script:moduleImports | Should Be 0
    }

    It 'does not import or query Active Directory for explicit targets' {
        $result = Invoke-NtlmAuditRun @script:discoveryRunArgs -ComputerName 'dc01.example.test'
        $script:moduleImports | Should Be 0
        $script:discoveryCalls.Count | Should Be 0
        $script:remoteCalls.Count | Should Be 1
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Scope | Should Be 'ComputerName'
    }

    It 'does not import or query Active Directory for offline XML' {
        $path = Join-Path $TestDrive 'discovery-offline.xml'
        Set-Content -LiteralPath $path -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:discoveryRunArgs -EventXmlPath $path
        $script:moduleImports | Should Be 0
        $script:discoveryCalls.Count | Should Be 0
        $script:remoteCalls.Count | Should Be 0
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Scope | Should Be 'EventXmlPath'
        $report.Run.Computers.Count | Should Be 0
    }

    It 'retains unreachable discovered DCs as coverage errors and continues collecting the others' {
        $script:unreachableDc = 'dc02.example.test'
        { Invoke-NtlmAuditRun @script:discoveryRunArgs -AllDomainControllers } | Should Throw 'Audit incomplete'
        $script:remoteCalls.Count | Should Be 2
        $report = Get-Content -LiteralPath (Join-Path $script:discoveryRunArgs.OutputDir 'NtlmAudit.json') -Raw | ConvertFrom-Json
        $report.Run.Status | Should Be 'Partial'
        $report.Run.Computers.Count | Should Be 2
        $report.Run.ErrorCount | Should Be 1
        $report.Events.Count | Should Be 1
        @($report.Coverage | Where-Object { $_.Computer -eq 'dc02.example.test' -and $_.Status -eq 'Error' }).Count | Should Be 1
    }

    It 'supports direct script invocation with discovery and live collection options' {
        # Direct invocation creates a separate script scope; keep these mocks self-contained.
        Mock Import-Module {
            param($Name)
            if ($Name -ne 'ActiveDirectory') { throw "Unexpected module import: $Name" }
        }
        Mock Get-ADDomainController {
            param($Filter, $Server)
            if ($Filter -ne '*' -or $Server -ne 'example.test') { throw 'Incorrect discovery arguments.' }
            [pscustomobject]@{ HostName = 'dc01.example.test' }
            [pscustomobject]@{ HostName = 'dc02.example.test' }
        }
        Mock Invoke-Command {
            param($ComputerName, $ArgumentList)
            if ($ComputerName -notin 'dc01.example.test','dc02.example.test' -or $ArgumentList[2] -ne 25) {
                throw 'Incorrect collection arguments.'
            }
            [pscustomobject]@{
                Coverage = @([pscustomobject]@{
                    Computer = $ComputerName; Channel = 'Microsoft-Windows-NTLM/Operational'
                    Provider = 'Microsoft-Windows-Security-Netlogon'; Status = 'Collected'
                    RetentionUnproven = $false; Truncated = $false
                })
                Events = @(New-TestNtlmXml -Id 4032 -Provider 'Microsoft-Windows-Security-Netlogon' -Computer $ComputerName)
                MetadataErrors = @()
            }
        }
        $result = & $scriptPath @script:discoveryRunArgs -AllDomainControllers -Domain 'example.test' -MaxEventsPerSource 25
        $result.ObservationCount | Should Be 2
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Scope | Should Be 'AllDomainControllers'
        $report.Run.Domain | Should Be 'example.test'
        $report.Run.Computers.Count | Should Be 2
        $report.Run.MaxEventsPerSource | Should Be 25
    }

    It 'rejects incompatible public parameter sets before any directory query' {
        { & $scriptPath @script:discoveryRunArgs -ComputerName 'dc01' -AllDomainControllers } | Should Throw 'Parameter set cannot be resolved'
        { & $scriptPath @script:discoveryRunArgs -EventXmlPath 'unused.xml' -AllDomainControllers } | Should Throw 'Parameter set cannot be resolved'
        { & $scriptPath @script:discoveryRunArgs -ComputerName 'dc01' -Domain 'example.test' } | Should Throw 'Parameter set cannot be resolved'
        $script:moduleImports | Should Be 0
        $script:discoveryCalls.Count | Should Be 0
    }
}

Describe 'NTLM HTML table presentation' {
    It 'shows an explicit empty state instead of an empty table' {
        $html = ConvertTo-NtlmHtmlTable -Rows @() -Columns @('Status') -Id 'empty-table'
        $html | Should Match 'No rows to display'
        $html | Should Not Match '<table'
    }

    It 'uses readable headers, scroll containers, escaped cells and UTC dates' {
        $rows = @([pscustomobject]@{ TimeUtc = '2025-11-02T14:00:00+02:00'; NtlmVersion = 'Unknown'; AccountName = '<img src=x onerror=alert(1)>' })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('TimeUtc','NtlmVersion','AccountName') -Id 'sample-table'
        $html | Should Match 'class="table-scroll"'
        $html | Should Match 'scope="col">Recorded at \(UTC\)'
        $html | Should Match 'NTLM version'
        $html | Should Match '2025-11-02 12:00:00'
        $html | Should Match 'badge warning'
        $html | Should Match '&lt;img'
        $html | Should Not Match '<img'
        $html | Should Match 'data-table="sample-table"'
        $html | Should Match '1 displayed / 1 total'
    }

    It 'caps each HTML table at exactly 500 rows and states the full count and filter scope' {
        $rows = @(1..501 | ForEach-Object { [pscustomobject]@{ Sequence = $_; Note = "record-$_" } })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('Sequence','Note') -Id 'limited-table'
        [regex]::Matches($html, '<tr>').Count | Should Be 501
        $html | Should Match 'record-500'
        $html | Should Not Match 'record-501'
        $html | Should Match 'Showing the first 500 rows of 501'
        $html | Should Match 'Filters search only these displayed rows'
        $html | Should Match '500 displayed / 501 total'
    }

    It 'requires an ID for a deferred table and keeps the empty state explicit' {
        { ConvertTo-NtlmHtmlTable -Rows @() -Columns @('Status') -Deferred } | Should Throw 'Deferred HTML tables require an ID'
        $html = ConvertTo-NtlmHtmlTable -Rows @() -Columns @('Status') -Id 'empty-details' -Deferred
        $html | Should Match 'No rows to display'
        $html | Should Not Match '<script'
    }

    It 'stores deferred cells without creating row elements and retains display and export values' {
        $row = [pscustomobject]@{
            TimeUtc = '2025-11-02T14:00:00+02:00'; NtlmVersion = 'Unknown'
            Collected = 0; Enabled = $false; Error = $null; ObservationPoint = 'ResourceServer'
        }
        $html = ConvertTo-NtlmHtmlTable -Rows @($row) -Columns @('TimeUtc','NtlmVersion','Collected','Enabled','Error','ObservationPoint') -Id 'lazy-table' -Deferred
        $html | Should Match 'data-deferred="lazy-table-data"'
        $html | Should Match '<tbody></tbody>'
        $html | Should Match '1 displayed / 1 total'
        $html | Should Match 'JavaScript required'
        $payload = [regex]::Match($html, '(?s)<script type="application/json" id="lazy-table-data">(.*?)</script>').Groups[1].Value | ConvertFrom-Json
        $payload.rows.Count | Should Be 1
        $payload.rows[0].Count | Should Be 6
        $payload.rows[0][0] | Should Be '2025-11-02 12:00:00'
        $payload.rows[0][1].text | Should Be 'Version not established'
        $payload.rows[0][1].raw | Should Be 'Unknown'
        $payload.rows[0][1].tone | Should Be 'warning'
        $payload.rows[0][2] | Should Be '0'
        $payload.rows[0][3].text | Should Be 'Disabled'
        $payload.rows[0][3].raw | Should Be 'False'
        ($null -eq $payload.rows[0][4]) | Should Be $true
        $payload.rows[0][5].text | Should Be 'Server / receiver'
        $payload.rows[0][5].raw | Should Be 'ResourceServer'
    }

    It 'prevents deferred cell content from terminating its data script without changing the value' {
        $value = '</script><img src=x onerror=alert(1)> & "quoted"'
        $html = ConvertTo-NtlmHtmlTable -Rows @([pscustomobject]@{ AccountName = $value }) -Columns @('AccountName') -Id 'safe-details' -Deferred
        $html | Should Not Match '<img'
        $payload = [regex]::Match($html, '(?s)<script type="application/json" id="safe-details-data">(.*?)</script>').Groups[1].Value | ConvertFrom-Json
        $payload.rows.Count | Should Be 1
        $payload.rows[0].Count | Should Be 1
        $payload.rows[0][0] | Should Be $value
    }

    It 'applies the same explicit 500-row cap to deferred data' {
        $rows = @(1..501 | ForEach-Object { [pscustomobject]@{ Note = "record-$_" } })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('Note') -Id 'limited-details' -Deferred
        $payload = [regex]::Match($html, '(?s)<script type="application/json" id="limited-details-data">(.*?)</script>').Groups[1].Value | ConvertFrom-Json
        $payload.rows.Count | Should Be 500
        $payload.rows[499][0] | Should Be 'record-500'
        $html | Should Not Match 'record-501'
        $html | Should Match '500 displayed / 501 total'
        $html | Should Match 'Showing the first 500 rows of 501'
        $html | Should Match 'Filters search only these displayed rows'
    }

    It 'does not describe zero or missing values as unavailable evidence interchangeably' {
        $html = ConvertTo-NtlmHtmlTable -Rows @([pscustomobject]@{ Collected = 0; Enabled = $false; Error = $null }) -Columns @('Collected','Enabled','Error')
        $html | Should Match '>0</span>'
        $html | Should Match '>Disabled</span>'
        $html | Should Match 'data-raw="False"'
        [regex]::Matches($html, 'Not recorded').Count | Should Be 1
    }

    It 'distinguishes the log computer, caller, destination and local versus initiating processes' {
        $rows = @([pscustomobject]@{
            SourceComputer = 'log.example.test'; ClientName = 'caller.example.test'; TargetName = 'resource.example.test'
            InitiatingProcess = 'C:\Apps\caller.exe'; LocalProcess = 'C:\Apps\receiver.exe'; ObservationPoint = 'ResourceServer'
        })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('SourceComputer','ClientName','TargetName','InitiatingProcess','LocalProcess','ObservationPoint')
        foreach ($label in 'Log computer','Initiating computer','Requested destination','App starting the connection','Process on log computer') {
            $html.Contains($label) | Should Be $true
        }
        $html | Should Match 'Server / receiver'
        $html | Should Match 'data-raw="ResourceServer"'
        $html | Should Match 'caller.exe'
        $html | Should Match 'receiver.exe'
    }

    It 'does not present every credential authority as a domain controller' {
        $html = ConvertTo-NtlmHtmlTable -Rows @([pscustomobject]@{ ObservationPoint = 'CredentialAuthority' }) -Columns @('ObservationPoint')
        $html | Should Match 'Account validator \(4776\)'
        $html | Should Match 'data-raw="CredentialAuthority"'
        $html | Should Not Match 'Domain controller'
    }

    It 'explains collection results while retaining original export codes for filtering' {
        $rows = @('Collected','NoEvents','Disabled','Unsupported','Error','ImportedEvidenceOnly' | ForEach-Object { [pscustomobject]@{ Status = $_ } })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('Status')
        foreach ($label in 'Events read','No matching events','Log disabled','Not supported here','Could not collect','Imported XML only') {
            $html.Contains($label) | Should Be $true
        }
        foreach ($row in $rows) {
            $html.Contains('data-raw="' + $row.Status + '"') | Should Be $true
        }
    }

    It 'distinguishes an attempted exchange, NTLM processing, Windows logon and an unknown outcome' {
        $rows = @('Attempt','ProcessingSuccess','ProcessingFailure','LogonSuccess','LogonFailure','Not established' | ForEach-Object { [pscustomobject]@{ AuthenticationResult = $_ } })
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('AuthenticationResult')
        foreach ($label in 'NTLM attempt recorded','NTLM processing succeeded','NTLM processing failed','Windows logon succeeded','Windows logon failed','Outcome not established') {
            $html.Contains($label) | Should Be $true
        }
        $html | Should Match 'data-raw="Not established"'
    }

    It 'describes retention and event limits without claiming that no flag proves complete logging' {
        $rows = @(
            [pscustomobject]@{ RetentionUnproven = $true; Truncated = $true }
            [pscustomobject]@{ RetentionUnproven = $false; Truncated = $false }
        )
        $html = ConvertTo-NtlmHtmlTable -Rows $rows -Columns @('RetentionUnproven','Truncated')
        $html | Should Match 'history may be incomplete'
        $html | Should Match 'results were capped'
        $html | Should Match 'No retention gap flagged'
        $html | Should Match 'No cap flagged'
        $html | Should Not Match 'logging complete'
    }
}

Describe 'NTLM offline reports and failure behavior' {
    BeforeEach {
        $script:runArgs = @{
            StartTime = [datetimeoffset]'2025-11-01T00:00:00Z'
            EndTime = [datetimeoffset]'2025-11-03T00:00:00Z'
            OutputDir = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        }
        $script:inputPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.xml')
        Mock Write-Host {}
        Mock Write-Warning {}
    }

    It 'writes complete outputs with escaped HTML, formula-safe CSV and original JSON values' {
        $xml = New-TestNtlmXml -Data @{
            Username = '=HYPERLINK("https://example.test")'; ProcessName = '<script>alert(1)</script>'
            TargetMachine = 'server'; Hostname = 'client'; NtlmUsageId = '7'; NtlmVersion = 'NTLMv2'
        }
        Set-Content -LiteralPath $script:inputPath -Value $xml
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $result.Status | Should Be 'Partial'
        $result.ObservationCount | Should Be 1
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Events[0].AccountName | Should Be '=HYPERLINK("https://example.test")'
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Not Match '<script>alert'
        $html | Should Match '&lt;script&gt;'
        $csv = Import-Csv -LiteralPath (Join-Path $script:runArgs.OutputDir 'Events.csv')
        $csv.AccountName.StartsWith("'=") | Should Be $true
        foreach ($name in 'NtlmAudit.html','NtlmAudit.json','Events.csv','Dependencies.csv','Coverage.csv') {
            Test-Path -LiteralPath (Join-Path $script:runArgs.OutputDir $name) | Should Be $true
        }
    }

    It 'deduplicates repeated records without merging independent observations' {
        $one = New-TestNtlmXml -Record 1
        $two = New-TestNtlmXml -Record 2
        Set-Content -LiteralPath $script:inputPath -Value "<Events>$one$one$two</Events>"
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $result.ObservationCount | Should Be 2
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.DuplicateRecords | Should Be 1
        $report.Dependencies[0].ObservationCount | Should Be 2
    }

    It 'renders a self-contained dashboard with accurate metrics, valid navigation and complete technical fields' {
        $one = New-TestNtlmXml -Record 1 -Data @{ Username = 'sample'; NtlmVersion = 'NTLMv2'; NtlmUsageId = '7'; TargetMachine = 'server' }
        $two = New-TestNtlmXml -Record 2
        Set-Content -LiteralPath $script:inputPath -Value "<Events>$one$two</Events>"
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match 'name="viewport"'
        $html | Should Match '<nav class="section-nav"'
        $html | Should Match 'Event records</span><strong class="metric-value">2'
        $html | Should Match 'Records showing NTLMv1</span><strong class="metric-value">0'
        $html | Should Match 'Records showing NTLMv2</span><strong class="metric-value">1'
        $html | Should Match 'Version not established</span><strong class="metric-value">1'
        $html | Should Match 'Computers in imported logs</span><strong class="metric-value">1'
        $html | Should Match '<details class="technical">'
        $html | Should Match 'id="events-details"'
        $html | Should Match 'Channel Binding Status'
        $html | Should Match 'Filters apply only to displayed rows'
        $html | Should Match '<noscript>'
        $html | Should Not Match '<(?:script|link)[^>]+(?:src|href)="https?://'
        $ids = @([regex]::Matches($html, ' id="([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
        @($ids | Sort-Object -Unique).Count | Should Be $ids.Count
        foreach ($anchor in [regex]::Matches($html, 'href="#([^"]+)"')) {
            $ids -contains $anchor.Groups[1].Value | Should Be $true
        }
        foreach ($export in 'Events.csv','Dependencies.csv','Coverage.csv','NtlmAudit.json') {
            $html.Contains('href="' + $export + '" download') | Should Be $true
            Test-Path -LiteralPath (Join-Path $script:runArgs.OutputDir $export) | Should Be $true
        }
        $csv = @(Import-Csv -LiteralPath (Join-Path $script:runArgs.OutputDir 'Events.csv'))
        $csv.Count | Should Be 2
        $csv[0].PSObject.Properties.Name -contains 'ChannelBindingStatus' | Should Be $true
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Events.Count | Should Be 2
        $report.Events[0].RawXml | Should Match 'NtlmUsageId'
    }

    It 'provides a reading guide and a meaning and next step for every report block' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        foreach ($heading in 'How to read this report','Were the logs collected correctly?','Which NTLM version was identified?',
            'Which role recorded the activity?','Why did a client choose NTLM?','What outcome did Windows record?',
            'Which usage groups should an owner review?','Which individual event records support the findings?','Where can I find the complete data?') {
            $html.Contains($heading) | Should Be $true
        }
        $html | Should Match 'It is not necessarily the computer that started the connection'
        $html | Should Match 'Illustration, not a reconstruction of your records'
        $html | Should Match 'Unknown does not mean NTLMv1, NTLMv2 or failed authentication'
        $html | Should Match 'not a count of applications'
        $html | Should Match 'on a receiving server it is not the remote'
        $html | Should Match 'Offline analysis: only exported XML files were read'
        $html | Should Match 'No computers were contacted'
        $html | Should Match 'Review required, even with zero errors'
        $html | Should Match 'a computer checking its own local account'
        [regex]::Matches($html, '<strong>Next step:</strong>').Count | Should Be 7
        $html | Should Match 'original field names and status/role codes remain unchanged'
    }

    It 'starts explanations collapsed while keeping collection issues outside the collapsed checks' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $html | Should Match '<details class="technical" id="reading-details">'
        $html | Should Match '<details class="technical" id="collection-details">'
        $html | Should Not Match '<details[^>]+open'
        $coverageStart = $html.IndexOf('<section class="card" id="coverage">')
        $checksStart = $html.IndexOf('<details class="technical" id="collection-details">')
        $visibleChecks = $html.Substring($coverageStart, $checksStart - $coverageStart)
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Issues.Count | Should BeGreaterThan 0
        foreach ($issue in $report.Issues) {
            $visibleChecks.Contains([Net.WebUtility]::HtmlEncode($issue)) | Should Be $true
        }
        foreach ($id in 'coverage-details','dependencies-details','events-details') {
            $html.Contains('id="' + $id + '" data-deferred="' + $id + '-data"') | Should Be $true
            $html.Contains('id="' + $id + '-data"') | Should Be $true
        }
        $html | Should Match 'Summary tables and native expandable explanations remain accessible'
        $html | Should Match 'Use the complete CSV/JSON exports'
    }

    It 'groups 54 repeated anonymous cautions once without changing original evidence or export codes' {
        $events = @(1..54 | ForEach-Object {
            New-TestNtlmXml -Id 4021 -Record $_ -Data @{ Username = 'ANONYMOUS LOGON'; NtlmVersion = 'NTLMv1'; NtlmUsageId = '5' }
        })
        Set-Content -LiteralPath $script:inputPath -Value ('<Events>' + ($events -join '') + '</Events>')
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        [regex]::Matches($html, '<article class="interpretation-note">').Count | Should Be 1
        $html | Should Match 'Note types: 1 / records affected: 54'
        $html | Should Match 'Event records affected: 54'
        $html | Should Match 'Errors: 0 / collection notes: 1'
        $html | Should Match 'not a collection failure'
        $html | Should Not Match '<li>[A-F0-9]{64}:'
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Events.Count | Should Be 54
        $report.Issues.Count | Should Be 55
        $report.Run.Status | Should Be 'Partial'
        @($report.Issues | Where-Object { $_ -match '^[A-F0-9]{64}: Anonymous/null-session' }).Count | Should Be 54
        $csv = @(Import-Csv -LiteralPath (Join-Path $script:runArgs.OutputDir 'Events.csv'))
        $csv.Count | Should Be 54
        @($csv | Where-Object { $_.RawNtlmVersion -eq 'NTLMv1' -and $_.NtlmVersion -eq 'Unknown' }).Count | Should Be 54
    }

    It 'lists each checked computer once, including empty, incomplete and failed collections' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml -Computer 'dc01.example.test')
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Coverage = @(
            foreach ($count in 2,3,5) {
                [pscustomobject]@{ Computer = 'DC01'; OS = 'Windows Server'; Status = 'Collected'; Collected = $count }
            }
            [pscustomobject]@{ Computer = 'DC02'; Status = 'NoEvents'; Collected = 0; RetentionUnproven = $true }
            [pscustomobject]@{ Computer = 'DC03.example.test'; Status = 'Error'; Collected = 0; Error = 'Access denied' }
            [pscustomobject]@{ Computer = 'DC04'; Status = 'NoEvents'; Collected = 0 }
        )
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $body = [regex]::Match($html, '(?s)<table id="computers-table".*?<tbody>(.*?)</tbody>').Groups[1].Value
        $rows = @([regex]::Matches($body, '(?s)<tr>(.*?)</tr>'))
        $rows.Count | Should Be 4
        $rows[0].Value | Should Match '>DC01</span>'
        $rows[0].Value | Should Match '>10</span>'
        $rows[0].Value | Should Match 'Queries completed'
        $rows[1].Value | Should Match '>DC02</span>'
        $rows[1].Value | Should Match 'History uncertain'
        $rows[2].Value | Should Match 'DC03.example.test'
        $rows[2].Value | Should Match 'Collection errors'
        $rows[3].Value | Should Match 'No matching events'
        $body | Should Not Match 'dc01.example.test'
        $html.IndexOf('id="computers"') | Should BeLessThan $html.IndexOf('id="reading-guide"')
        $html | Should Match '4 computers'
        $html | Should Match 'before deduplication and parsing'
    }

    It 'shows every per-computer collection limitation and escapes roster fields' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Coverage = @(
            [pscustomobject]@{ Computer = '<computer>'; OS = '<img src=x>'; Status = 'Disabled'; Collected = 0 }
            [pscustomobject]@{ Computer = '<computer>'; Status = 'Unsupported'; Collected = 0 }
            [pscustomobject]@{ Computer = '<computer>'; Status = 'Collected'; Collected = 20; RetentionUnproven = $true; Truncated = $true }
        )
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $body = [regex]::Match($html, '(?s)<table id="computers-table".*?<tbody>(.*?)</tbody>').Groups[1].Value
        [regex]::Matches($body, '<tr>').Count | Should Be 1
        $body | Should Match '&lt;computer&gt;'
        $body | Should Match '&lt;img'
        $body | Should Not Match '<img'
        $body | Should Match 'Log disabled; Unsupported source; History uncertain; Event limit reached'
        $body | Should Match '>20</span>'
    }

    It 'does not turn a missing roster count into zero usage or successful collection' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Coverage = @([pscustomobject]@{ Computer = 'server'; Status = 'Collected' })
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $body = [regex]::Match($html, '(?s)<table id="computers-table".*?<tbody>(.*?)</tbody>').Groups[1].Value
        $body | Should Match 'Not recorded'
        $body | Should Match 'Check source details'
        $body | Should Not Match 'Queries completed|No matching events'
    }

    It 'lists imported log computers and normalized counts without claiming to contact them' {
        $one = New-TestNtlmXml -Computer 'one.example.test' -Record 1
        $two = New-TestNtlmXml -Computer 'one.example.test' -Record 2
        $three = New-TestNtlmXml -Computer 'two.example.test' -Record 1
        Set-Content -LiteralPath $script:inputPath -Value "<Events>$one$two$three</Events>"
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        $body = [regex]::Match($html, '(?s)<table id="computers-table".*?<tbody>(.*?)</tbody>').Groups[1].Value
        $rows = @([regex]::Matches($body, '(?s)<tr>(.*?)</tr>'))
        $rows.Count | Should Be 2
        $rows[0].Value | Should Match 'one.example.test'
        $rows[0].Value | Should Match '>2</span>'
        $rows[1].Value | Should Match 'two.example.test'
        $rows[1].Value | Should Match '>1</span>'
        $body | Should Not Match ([regex]::Escape((Split-Path -Leaf $script:inputPath)))
        $body | Should Not Match 'Queries completed'
        $html | Should Match '<h2>Computers in imported logs</h2>'
        $html | Should Match 'These computers were not contacted'
        $body | Should Match 'Imported XML only - not contacted'
    }

    It 'counts a record with two caution types once in the affected-record total' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml -Id 4021 -Version 1 -Data @{ Username = 'ANONYMOUS LOGON'; NtlmVersion = 'NTLMv1' })
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $html = Get-Content -LiteralPath $result.HtmlPath -Raw
        [regex]::Matches($html, '<article class="interpretation-note">').Count | Should Be 2
        $html | Should Match 'Note types: 2 / records affected: 1'
        $html | Should Match 'An event format needs technical verification'
        $html | Should Match 'Anonymous activity is not proof'
    }

    It 'keeps unrecognized issues visible and escapes unknown event caution text' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $warning = 'New caution <img src=x onerror=alert(1)>'
        $report.Events[0].ParsingWarnings = @($warning)
        $report.Issues += "$($report.Events[0].EvidenceId): $warning"
        $report.Issues += ('A' * 64) + ': Unrecognized issue remains visible'
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should Match 'Event interpretation needs review'
        $html | Should Match 'New caution &lt;img'
        $html | Should Not Match '<img'
        $html | Should Match 'Unrecognized issue remains visible'
        $html | Should Match 'Errors: 0 / collection notes: 2'
    }

    It 'does not describe event interpretation notes alone as collection failures' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml -Data @{ Username = 'ANONYMOUS LOGON' })
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Run.Scope = 'ComputerName'
        $report.Issues = @($report.Issues | Where-Object { $_ -match '^[A-F0-9]{64}: ' })
        $report.Coverage = @([pscustomobject]@{ Computer = 'source'; Channel = 'Microsoft-Windows-NTLM/Operational'; Status = 'Collected'; Collected = 1 })
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should Match 'Errors: 0 / collection notes: 0'
        $html | Should Match 'No collection limitations were recorded, but some event records need interpretation notes'
        $html | Should Match 'Review required'
        $html | Should Not Match 'id="retention-table"'
    }

    It 'shows requested and retained UTC history dates and a friendly retention explanation' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Run.Scope = 'ComputerName'
        $originalIssue = 'dc01.example.test / Security: oldest retained event is newer than the requested start; retention coverage is unproven.'
        $report.Issues = @($originalIssue)
        $report.Coverage = @([pscustomobject]@{
            Computer = 'DC01'; Channel = 'Security'; Provider = 'Microsoft-Windows-Security-Auditing'
            Status = 'Collected'; Collected = 1; RetentionUnproven = $true
            RequestedStartUtc = '2025-11-01T00:00:00Z'; OldestAvailableUtc = '2025-11-01T10:00:00Z'
            RequestedEndUtc = '2025-11-03T00:00:00Z'
        })
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should Match 'History may be incomplete on dc01.example.test \(Security\)'
        $html | Should Match 'History starts later than requested'
        $html | Should Match 'id="retention-table"'
        $html | Should Match '2025-11-01 00:00:00'
        $html | Should Match '2025-11-01 10:00:00'
        $html | Should Match 'not a WinRM failure or an NTLM authentication error'
        $html | Should Not Match 'id="record-notes"'
        $saved = Get-Content -LiteralPath (Join-Path $directory 'NtlmAudit.json') -Raw | ConvertFrom-Json
        $saved.Issues[0] | Should Be $originalIssue
        $saved.Coverage[0].RetentionUnproven | Should Be $true
    }

    It 'writes header-only CSV and empty JSON arrays when no selected evidence falls in the window' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml -Time '2024-01-01T00:00:00Z')
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        @($report.Events).Count | Should Be 0
        @($report.Dependencies).Count | Should Be 0
        $report.Run.IgnoredRecords | Should Be 1
        (Get-Content -LiteralPath (Join-Path $script:runArgs.OutputDir 'Events.csv')).Count | Should Be 1
    }

    It 'counts live coverage names without adding FQDN aliases from event records' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml -Computer 'source.example.test')
        $result = Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath
        $report = Get-Content -LiteralPath $result.JsonPath -Raw | ConvertFrom-Json
        $report.Run.Mode = 'Live'
        $report.Coverage = @([pscustomobject]@{ Computer = 'SOURCE'; Channel = 'Microsoft-Windows-NTLM/Operational'; Status = 'Collected'; Collected = 1 })
        $directory = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $path = Export-NtlmReport -Report $report -Directory $directory
        $html = Get-Content -LiteralPath $path -Raw
        $html | Should Match 'Computers checked</span><strong class="metric-value">1'
        $html | Should Match 'Computers queried, including failed attempts. Not a count of clients'
        $html | Should Match 'Explicit computer list: only the computers supplied'
    }

    It 'retains partial reports and fails explicitly for malformed events' {
        Set-Content -LiteralPath $script:inputPath -Value '<Event><EventData/></Event>'
        { Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath } | Should Throw 'Audit incomplete'
        $report = Get-Content -LiteralPath (Join-Path $script:runArgs.OutputDir 'NtlmAudit.json') -Raw | ConvertFrom-Json
        $report.Run.ErrorCount | Should Be 1
        $report.Run.Status | Should Be 'Partial'
        $report.RejectedEvents.Count | Should Be 1
        $report.RejectedEvents[0].RawXml | Should Match 'EventData'
    }

    It 'does not overwrite existing output directories' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $null = New-Item -ItemType Directory -Path $script:runArgs.OutputDir
        { Invoke-NtlmAuditRun @script:runArgs -EventXmlPath $script:inputPath } | Should Throw 'already exists'
    }

    It 'rejects missing scope and reversed observation windows' {
        { Invoke-NtlmAuditRun @script:runArgs } | Should Throw 'Specify either'
        $script:runArgs.EndTime = $script:runArgs.StartTime.AddDays(-1)
        { Invoke-NtlmAuditRun @script:runArgs -ComputerName 'localhost' } | Should Throw 'StartTime'
    }

    It 'saves a failed remote computer as a coverage error and then fails' {
        Mock Invoke-Command { throw [UnauthorizedAccessException]::new('Access denied') }
        { Invoke-NtlmAuditRun @script:runArgs -ComputerName 'remote.example.test' } | Should Throw 'Audit incomplete'
        $report = Get-Content -LiteralPath (Join-Path $script:runArgs.OutputDir 'NtlmAudit.json') -Raw | ConvertFrom-Json
        $report.Coverage[0].Computer | Should Be 'remote.example.test'
        $report.Coverage[0].Status | Should Be 'Error'
        $report.Events.Count | Should Be 0
    }

    It 'rejects an empty remote response instead of reporting a clean collection' {
        Mock Invoke-Command {}
        { Invoke-NtlmAuditRun @script:runArgs -ComputerName 'remote.example.test' } | Should Throw 'Audit incomplete'
        $report = Get-Content -LiteralPath (Join-Path $script:runArgs.OutputDir 'NtlmAudit.json') -Raw | ConvertFrom-Json
        $report.Coverage[0].Status | Should Be 'Error'
    }

    It 'supports direct script invocation with explicit dates and output path' {
        Set-Content -LiteralPath $script:inputPath -Value (New-TestNtlmXml)
        $result = & $scriptPath @script:runArgs -EventXmlPath $script:inputPath
        $result.ObservationCount | Should Be 1
    }

    It 'contains no commands that alter source auditing, accounts or registry values' {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
        $parseErrors.Count | Should Be 0
        $commands = @($ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() })
        @($commands | Where-Object { $_ -match '^(Set-AD|New-AD|Remove-AD|Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Enable-WinEvent|wevtutil|auditpol)' }).Count |
            Should Be 0
    }
}

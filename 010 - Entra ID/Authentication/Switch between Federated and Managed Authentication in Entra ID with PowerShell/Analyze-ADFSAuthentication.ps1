<#
.SYNOPSIS
    Analyzes AD FS Security event log to report on authentication activity.

.DESCRIPTION
    Reads AD FS audit events from the Security event log on one or more AD FS servers
    and produces aggregated statistics on authentication activity:
      - Top users (UPNs) by token issuance count
      - Top relying parties (target apps) by token issuance count
      - Distribution by authentication protocol
      - Distribution by hour of day
      - Success vs failure counts

    Two typical use cases:
      1. BEFORE migrating from Federated to Managed authentication: identify residual
         usage of ADFS (which users / which apps still authenticate via the farm).
      2. Stand-alone: regular reporting on AD FS authentication activity.

    REQUIREMENTS:
      - AD FS auditing must be enabled on each target server:
            Set-AdfsProperties -AuditLevel Basic    (or Verbose for more detail)
      - Windows audit policy 'Application Generated' must be enabled (Success + Failure):
            auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
      - Caller must have read access to the Security log on the target server(s)
      - PowerShell remoting (WinRM) is used when targeting remote servers

.PARAMETER ComputerName
    One or more AD FS server names. Defaults to the local machine.

.PARAMETER Days
    Number of days of history to analyze. Default: 7.

.PARAMETER MaxEvents
    Cap on number of events to read per server (performance safety). Default: 50000.

.PARAMETER OutputFolder
    Folder where CSV reports will be written. Default: current directory.

.PARAMETER IncludeFailures
    Include failed token issuance events (event ID 1202) in addition to successes (1200).

.EXAMPLE
    .\Analyze-ADFSAuthentication.ps1
    Analyzes the local server for the last 7 days, success events only.

.EXAMPLE
    .\Analyze-ADFSAuthentication.ps1 -ComputerName adfs01,adfs02 -Days 30 -OutputFolder C:\reports -IncludeFailures
    Analyzes two ADFS servers over 30 days, success + failure events, writes CSVs to C:\reports.

.NOTES
    Event IDs scanned:
      - 1200 : "The Federation Service issued a valid token"          (success)
      - 1202 : "The Federation Service failed to issue a valid token" (failure, optional)

    Field extraction uses regex on the event message text. Format is stable across
    AD FS 2016 / 2019 / 2022 (AD FS 2012 R2 is not supported). If a field comes back
    consistently empty on your environment, tune the regex patterns in the
    'Parse-AdfsEvent' helper.

    The raw events are always exported in full to ADFS-Events-Raw-<timestamp>.csv so
    you can re-parse offline if needed.

    Author : Mathias Motron
#>

[CmdletBinding()]
param(
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [ValidateRange(1, 365)]
    [int]$Days = 7,

    [ValidateRange(100, 1000000)]
    [int]$MaxEvents = 50000,

    [string]$OutputFolder = (Get-Location).Path,

    [switch]$IncludeFailures
)

#region Helpers --------------------------------------------------------------

function Parse-AdfsEvent {
    param([Parameter(Mandatory)] $Event, [Parameter(Mandatory)][string]$Server)

    $msg = $Event.Message

    # Best-effort regex extraction. ADFS message format varies between versions.
    $upn   = if ($msg -match 'User\s*[:=]\s*([^\s\r\n]+)')             { $Matches[1] } else { $null }
    $rp    = if ($msg -match 'Relying Party\s*[:=]\s*([^\r\n]+)')      { $Matches[1].Trim() } else { $null }
    $ip    = if ($msg -match 'IP Address\s*[:=]\s*([^\s\r\n]+)')       { $Matches[1] } else { $null }
    $proto = if ($msg -match 'Protocol\s*[:=]\s*([^\s\r\n]+)')         { $Matches[1] } else { $null }
    $authType = if ($msg -match 'Authentication (?:Method|Type)\s*[:=]\s*([^\s\r\n]+)') { $Matches[1] } else { $null }

    [pscustomobject]@{
        Server       = $Server
        Time         = $Event.TimeCreated
        EventId      = $Event.Id
        Outcome      = if ($Event.Id -eq 1200) { 'Success' } else { 'Failure' }
        User         = $upn
        RelyingParty = $rp
        ClientIP     = $ip
        Protocol     = $proto
        AuthType     = $authType
        Hour         = $Event.TimeCreated.Hour
    }
}

#endregion -------------------------------------------------------------------

# Validate output folder
if (-not (Test-Path -Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$startTime = (Get-Date).AddDays(-$Days)
$targetIds = if ($IncludeFailures) { @(1200, 1202) } else { @(1200) }
$allEvents = [System.Collections.Generic.List[object]]::new()

foreach ($server in $ComputerName) {
    Write-Host "Reading Security log on $server ..." -ForegroundColor Cyan

    $remoteScript = {
        param($Start, $Max, $Ids)
        try {
            Get-WinEvent -FilterHashtable @{
                LogName      = 'Security'
                ProviderName = 'AD FS Auditing'
                Id           = $Ids
                StartTime    = $Start
            } -MaxEvents $Max -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match 'No events were found') { return @() }
            throw
        }
    }

    try {
        $isLocal = ($server -eq $env:COMPUTERNAME) -or ($server -eq 'localhost') -or ($server -eq '.')
        if ($isLocal) {
            $events = & $remoteScript $startTime $MaxEvents $targetIds
        } else {
            $events = Invoke-Command -ComputerName $server `
                                     -ScriptBlock $remoteScript `
                                     -ArgumentList $startTime, $MaxEvents, $targetIds `
                                     -ErrorAction Stop
        }
    }
    catch {
        Write-Warning ("Failed to read events from {0} : {1}" -f $server, $_.Exception.Message)
        continue
    }

    Write-Host ("  Retrieved {0} events" -f @($events).Count) -ForegroundColor Gray

    foreach ($evt in $events) {
        $allEvents.Add( (Parse-AdfsEvent -Event $evt -Server $server) )
    }
}

if ($allEvents.Count -eq 0) {
    Write-Warning @"
No matching events found. Possible causes:
  - AD FS auditing is disabled. Check: (Get-AdfsProperties).AuditLevel
    Enable with:  Set-AdfsProperties -AuditLevel Basic
  - Windows 'Application Generated' audit policy is disabled.
    Enable with:  auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
  - No authentication activity in the requested time window.
  - Insufficient permissions to read the Security log on the target server(s).
"@
    return
}

#region Aggregations ---------------------------------------------------------

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$rawCsv = Join-Path $OutputFolder "ADFS-Events-Raw-$stamp.csv"
$allEvents | Export-Csv -Path $rawCsv -NoTypeInformation -Encoding UTF8
Write-Host "Raw events exported: $rawCsv" -ForegroundColor Green

$topUsers = $allEvents | Where-Object User |
    Group-Object User |
    Sort-Object Count -Descending |
    Select-Object -First 20 Count, Name

$topRPs = $allEvents | Where-Object RelyingParty |
    Group-Object RelyingParty |
    Sort-Object Count -Descending |
    Select-Object -First 20 Count, Name

$byProtocol = $allEvents | Where-Object Protocol |
    Group-Object Protocol |
    Sort-Object Count -Descending |
    Select-Object Count, Name

$byAuthType = $allEvents | Where-Object AuthType |
    Group-Object AuthType |
    Sort-Object Count -Descending |
    Select-Object Count, Name

$byHour = $allEvents | Group-Object Hour |
    Sort-Object @{ Expression = { [int]$_.Name } } |
    Select-Object Name, Count

$byOutcome = $allEvents | Group-Object Outcome |
    Select-Object Name, Count

$byServer = $allEvents | Group-Object Server |
    Select-Object Name, Count

#endregion -------------------------------------------------------------------

# Console summary
Write-Host "`n========== Summary ==========" -ForegroundColor Yellow
Write-Host ("Total events : {0}" -f $allEvents.Count)
Write-Host ("Time window  : {0:s}  ->  {1:s}" -f $startTime, (Get-Date))
Write-Host ("Servers      : {0}" -f ($ComputerName -join ', '))

Write-Host "`nBy server:" -ForegroundColor Yellow
$byServer | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "By outcome:" -ForegroundColor Yellow
$byOutcome | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "Top 20 users:" -ForegroundColor Yellow
$topUsers | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "Top 20 Relying Parties (apps):" -ForegroundColor Yellow
$topRPs | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "By protocol:" -ForegroundColor Yellow
$byProtocol | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "By authentication type:" -ForegroundColor Yellow
$byAuthType | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "By hour of day:" -ForegroundColor Yellow
$byHour | Format-Table -AutoSize | Out-String | Write-Host

# Export aggregated CSVs
$topUsers   | Export-Csv -Path (Join-Path $OutputFolder "ADFS-TopUsers-$stamp.csv")    -NoTypeInformation -Encoding UTF8
$topRPs     | Export-Csv -Path (Join-Path $OutputFolder "ADFS-TopRPs-$stamp.csv")      -NoTypeInformation -Encoding UTF8
$byProtocol | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByProtocol-$stamp.csv")  -NoTypeInformation -Encoding UTF8
$byAuthType | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByAuthType-$stamp.csv")  -NoTypeInformation -Encoding UTF8
$byHour     | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByHour-$stamp.csv")      -NoTypeInformation -Encoding UTF8
$byOutcome  | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByOutcome-$stamp.csv")   -NoTypeInformation -Encoding UTF8

Write-Host "`nAll reports written to: $OutputFolder" -ForegroundColor Green

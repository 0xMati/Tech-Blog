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
      1. Operational reporting: understand who and which applications authenticate
         through the AD FS farm (usage trends, top users, top relying parties).
      2. Pre-migration assessment: when planning to move from Federated to Managed
         authentication, identify which users and apps authenticate via the farm.

    REQUIREMENTS:
      - AD FS auditing must be enabled on each target server:
            Set-AdfsProperties -AuditLevel Basic    (or Verbose for more detail)
      - Windows audit policy 'Application Generated' must be enabled (Success + Failure):
            auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
      - Caller must have read access to the Security log on the target server(s)
      - PowerShell remoting (WinRM) is used when targeting remote servers

.PARAMETER ComputerName
    One or more AD FS server names. Defaults to the local machine.

    IMPORTANT: a token event (1200/1202) is only written on the farm node that
    actually processed the request. In a multi-node farm behind a load balancer,
    querying a single node gives only a partial view. Pass *every* farm node to
    get complete coverage, e.g. -ComputerName adfs01,adfs02,adfs03.

.PARAMETER Days
    Number of days of history to analyze. Default: 7.

.PARAMETER MaxEvents
    Cap on number of events to read per server (performance safety). Default: 50000.

.PARAMETER OutputFolder
    Folder where the HTML report and CSV exports will be written. When omitted, a
    timestamped subfolder is created under 'Outputs\' next to the script.

.PARAMETER IncludeFailures
    Include failed token issuance events (event ID 1202) in addition to successes (1200).

.PARAMETER OpenReport
    Open the generated HTML report when the run completes. Alias: OpenHTMLReport.

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

    [string]$OutputFolder,

    [switch]$IncludeFailures,

    [Alias('OpenHTMLReport')]
    [switch]$OpenReport
)

#region Helpers --------------------------------------------------------------

function Get-AuditNodeText {
    param($Root, [string]$Name)
    if ($null -eq $Root) { return $null }
    $node = $Root.SelectSingleNode(".//$Name")
    if ($null -eq $node) { return $null }
    $text = [string]$node.InnerText
    if ([string]::IsNullOrWhiteSpace($text) -or $text -eq 'N/A') { return $null }
    return $text.Trim()
}

function Parse-AdfsEvent {
    param([Parameter(Mandatory)] $Event, [Parameter(Mandatory)][string]$Server)

    # AD FS carries the audit detail as an embedded XML document (the "AuditBase"
    # schema) in the second EventData property; the first property is the Activity
    # ID. The plain-text Message only says "See XML for details", so the reliable
    # source is this embedded XML. The schema is stable across AD FS 2016/2019/2022.
    $auditXmlText = $null
    if ($Event.Properties -and $Event.Properties.Count -ge 2) {
        $auditXmlText = [string]$Event.Properties[1].Value
    }
    if ([string]::IsNullOrWhiteSpace($auditXmlText) -and
        $Event.Message -match '(?s)XML:\s*(<\?xml.*?</AuditBase>)') {
        $auditXmlText = $Matches[1]
    }

    $result = $null; $user = $null; $rp = $null; $ip = $null
    $proto = $null; $authType = $null; $networkLoc = $null

    if (-not [string]::IsNullOrWhiteSpace($auditXmlText)) {
        try {
            $base = ([xml]$auditXmlText).AuditBase

            $result     = Get-AuditNodeText -Root $base -Name 'AuditResult'
            $rp         = Get-AuditNodeText -Root $base -Name 'RelyingParty'
            $user       = Get-AuditNodeText -Root $base -Name 'UserId'
            $ip         = Get-AuditNodeText -Root $base -Name 'IpAddress'
            $proto      = Get-AuditNodeText -Root $base -Name 'AuthProtocol'
            $networkLoc = Get-AuditNodeText -Root $base -Name 'NetworkLocation'

            # PrimaryAuth is a SAML authn-context URN; keep only the readable tail
            # (e.g. ...:ac:classes:PasswordProtectedTransport -> PasswordProtectedTransport).
            $primaryAuth = Get-AuditNodeText -Root $base -Name 'PrimaryAuth'
            if ($primaryAuth) {
                $authType = ($primaryAuth -split '[:/]')[-1]
            }
        }
        catch {
            Write-Verbose ("Could not parse audit XML for event {0}: {1}" -f $Event.Id, $_.Exception.Message)
        }
    }

    $outcome = if ($result) { $result }
               elseif ($Event.Id -eq 1200) { 'Success' }
               else { 'Failure' }

    [pscustomobject]@{
        Server          = $Server
        Time            = $Event.TimeCreated
        EventId         = $Event.Id
        Outcome         = $outcome
        User            = $user
        RelyingParty    = $rp
        ClientIP        = $ip
        Protocol        = $proto
        AuthType        = $authType
        NetworkLocation = $networkLoc
        Hour            = $Event.TimeCreated.Hour
    }
}

function HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function ConvertTo-CountTableRows {
    param(
        $Groups,
        [string]$LabelHeader,
        [string]$EmptyText = 'No data.'
    )
    $rows = ''
    foreach ($g in @($Groups)) {
        $label = if ([string]::IsNullOrWhiteSpace([string]$g.Name)) { '(none)' } else { [string]$g.Name }
        $rows += "<tr><td>$(HtmlEncode $label)</td><td style='font-weight:700;text-align:right;'>$($g.Count)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($rows)) {
        $rows = "<tr><td colspan='2' class='empty'>$(HtmlEncode $EmptyText)</td></tr>"
    }
    return $rows
}

function Build-AdfsHtmlReport {
    param(
        [hashtable]$Data,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $usersRows    = ConvertTo-CountTableRows -Groups $Data.TopUsers          -EmptyText 'No user data parsed.'
    $rpRows       = ConvertTo-CountTableRows -Groups $Data.TopRPs            -EmptyText 'No relying-party data parsed.'
    $protoRows    = ConvertTo-CountTableRows -Groups $Data.ByProtocol        -EmptyText 'No protocol data parsed.'
    $authRows     = ConvertTo-CountTableRows -Groups $Data.ByAuthType        -EmptyText 'No authentication-type data parsed.'
    $netRows      = ConvertTo-CountTableRows -Groups $Data.ByNetworkLocation -EmptyText 'No network-location data parsed.'
    $hourRows     = ConvertTo-CountTableRows -Groups $Data.ByHour            -EmptyText 'No hourly data.'
    $outcomeRows  = ConvertTo-CountTableRows -Groups $Data.ByOutcome         -EmptyText 'No outcome data.'
    $serverRows   = ConvertTo-CountTableRows -Groups $Data.ByServer          -EmptyText 'No server data.'

    $failureCount = 0
    foreach ($o in @($Data.ByOutcome)) {
        if ([string]$o.Name -ne 'Success') { $failureCount += [int]$o.Count }
    }

    $findings = @()
    $findings += "<div class='finding good'><strong>Events analyzed:</strong> $($Data.TotalEvents) AD FS token event(s) over the last $($Data.Days) day(s).</div>"
    $distinctUsers = @($Data.TopUsers).Count
    $distinctRPs = @($Data.TopRPs).Count
    $findings += "<div class='finding'><strong>Usage:</strong> $distinctUsers distinct user(s) and $distinctRPs relying part(y/ies) authenticating through AD FS (top 20 shown).</div>"
    if ($failureCount -gt 0) {
        $findings += "<div class='finding warn'><strong>Failures:</strong> $failureCount failed token issuance event(s) in scope.</div>"
    }

    $html = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>
<title>AD FS Authentication Analysis</title>
<style>
:root{--bg:#09111f;--bg-soft:#0f1b2d;--card:#111c30;--card-2:#16233a;--border:#28405f;--text:#dce7f7;--muted:#93a7c4;--accent:#68c3ff;--accent-2:#8ef0c9;--green:#49d17d;--red:#ff6b6b;--yellow:#f0c45c;--cyan:#52d6ff}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:radial-gradient(circle at top,#173055 0%,var(--bg) 45%,#08101c 100%);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1500px;margin:0 auto}
h1{color:#f4fbff;font-size:2.2rem;margin-bottom:.5rem;letter-spacing:-.02em}h2{color:var(--accent);font-size:1.35rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:var(--muted);font-size:.92rem;margin-bottom:0}
.hero{background:linear-gradient(135deg,rgba(104,195,255,.2),rgba(142,240,201,.1));border:1px solid rgba(104,195,255,.28);border-radius:18px;padding:1.6rem 1.8rem;margin-bottom:1.5rem;box-shadow:0 18px 50px rgba(0,0,0,.25)}.hero p{color:var(--muted);max-width:980px}.hero strong{color:var(--accent-2)}
.findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.5rem}.finding{border-radius:14px;padding:1rem 1.1rem;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text)}.finding strong{display:block;margin-bottom:.35rem}.finding.warn{border-color:rgba(240,196,92,.35);background:rgba(240,196,92,.08)}.finding.good{border-color:rgba(73,209,125,.35);background:rgba(73,209,125,.08)}
.card{background:linear-gradient(180deg,var(--card),var(--card-2));border:1px solid var(--border);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 12px 30px rgba(0,0,0,.18)}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.84rem}th{background:rgba(255,255,255,.04);color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}tr:hover{background:rgba(255,255,255,.025)}
.empty{color:var(--muted);text-align:center;padding:1rem}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}.summary-metric{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));border:1px solid var(--border);border-radius:14px;padding:1.2rem 1rem;text-align:center}.summary-metric .metric-value{font-size:2.2rem;font-weight:800;line-height:1.1}.summary-metric .metric-label{color:var(--muted);font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.6px}
.section-nav{position:sticky;top:0;background:rgba(9,17,31,.84);backdrop-filter:blur(10px);padding:.8rem 0;z-index:100;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:.8rem;font-size:.85rem;padding:.45rem .7rem;border:1px solid rgba(104,195,255,.15);border-radius:999px;background:rgba(255,255,255,.02)}
.note{color:var(--muted);font-style:italic;font-size:.85rem;margin:.5rem 0}
</style></head><body><div class='container'>
<div class='hero'><h1>AD FS Authentication Analysis</h1><p class='subtitle'>Servers: $(HtmlEncode $Data.Servers) | Generated: $timestamp | Window: last $($Data.Days) day(s)</p><p style='margin-top:.85rem;'><strong>Focus:</strong> AD FS authentication activity (who and which apps authenticate through the farm) from Security audit events 1200/1202.</p></div>
<nav class='section-nav'><a href='#summary'>Summary</a><a href='#users'>Users</a><a href='#apps'>Relying Parties</a><a href='#dist'>Distributions</a></nav>

<div id='summary'><h2>Summary</h2>
<div class='summary-grid'>
<div class='summary-metric' style='border-top:3px solid var(--accent)'><div class='metric-value' style='color:var(--accent)'>$($Data.TotalEvents)</div><div class='metric-label'>Token Events</div></div>
<div class='summary-metric' style='border-top:3px solid var(--accent-2)'><div class='metric-value' style='color:var(--accent-2)'>$(@($Data.TopUsers).Count)</div><div class='metric-label'>Distinct Users (top 20)</div></div>
<div class='summary-metric' style='border-top:3px solid var(--cyan)'><div class='metric-value' style='color:var(--cyan)'>$(@($Data.TopRPs).Count)</div><div class='metric-label'>Relying Parties (top 20)</div></div>
<div class='summary-metric' style='border-top:3px solid $(if($failureCount -gt 0){'var(--red)'}else{'var(--green)'})'><div class='metric-value' style='color:$(if($failureCount -gt 0){'var(--red)'}else{'var(--green)'})'>$failureCount</div><div class='metric-label'>Failures</div></div>
</div>
<div class='findings'>$($findings -join "`n")</div>
</div>

<div id='users'><h2>Top Users</h2><div class='card'><p class='note'>Top 20 users by token issuance count.</p><table><thead><tr><th>User</th><th style='text-align:right;'>Tokens</th></tr></thead><tbody>$usersRows</tbody></table></div></div>

<div id='apps'><h2>Top Relying Parties (apps)</h2><div class='card'><p class='note'>Top 20 relying parties by token issuance count &mdash; applications that authenticate through the AD FS farm.</p><table><thead><tr><th>Relying Party</th><th style='text-align:right;'>Tokens</th></tr></thead><tbody>$rpRows</tbody></table></div></div>

<div id='dist'><h2>Distributions</h2>
<div class='grid2'>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By protocol</h3><table><thead><tr><th>Protocol</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$protoRows</tbody></table></div>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By authentication type</h3><table><thead><tr><th>Auth type</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$authRows</tbody></table></div>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By network location</h3><table><thead><tr><th>Location</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$netRows</tbody></table></div>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By outcome</h3><table><thead><tr><th>Outcome</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$outcomeRows</tbody></table></div>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By hour of day</h3><table><thead><tr><th>Hour</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$hourRows</tbody></table></div>
<div class='card'><h3 style='color:var(--accent);margin-bottom:.8rem;'>By server</h3><table><thead><tr><th>Server</th><th style='text-align:right;'>Count</th></tr></thead><tbody>$serverRows</tbody></table></div>
</div></div>

<p class='note' style='text-align:center;margin-top:2rem;'>Generated by Analyze-ADFSAuthentication.ps1</p>
</div></body></html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

#endregion -------------------------------------------------------------------

# Resolve output folder (timestamped subfolder when not provided)
if ([string]::IsNullOrWhiteSpace($OutputFolder)) {
    $baseDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputFolder = Join-Path -Path $baseDir -ChildPath ('Outputs\ADFSAuthentication_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

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

$byNetworkLocation = $allEvents | Where-Object NetworkLocation |
    Group-Object NetworkLocation |
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

Write-Host "By network location:" -ForegroundColor Yellow
$byNetworkLocation | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "By hour of day:" -ForegroundColor Yellow
$byHour | Format-Table -AutoSize | Out-String | Write-Host

# Export aggregated CSVs
$topUsers   | Export-Csv -Path (Join-Path $OutputFolder "ADFS-TopUsers-$stamp.csv")    -NoTypeInformation -Encoding UTF8
$topRPs     | Export-Csv -Path (Join-Path $OutputFolder "ADFS-TopRPs-$stamp.csv")      -NoTypeInformation -Encoding UTF8
$byProtocol | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByProtocol-$stamp.csv")  -NoTypeInformation -Encoding UTF8
$byAuthType | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByAuthType-$stamp.csv")  -NoTypeInformation -Encoding UTF8
$byNetworkLocation | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByNetworkLocation-$stamp.csv") -NoTypeInformation -Encoding UTF8
$byHour     | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByHour-$stamp.csv")      -NoTypeInformation -Encoding UTF8
$byOutcome  | Export-Csv -Path (Join-Path $OutputFolder "ADFS-ByOutcome-$stamp.csv")   -NoTypeInformation -Encoding UTF8

# HTML report
$htmlPath = Join-Path $OutputFolder "ADFS-AuthenticationReport-$stamp.html"
Build-AdfsHtmlReport -OutputPath $htmlPath -Data @{
    Servers           = ($ComputerName -join ', ')
    Days              = $Days
    TotalEvents       = $allEvents.Count
    TopUsers          = $topUsers
    TopRPs            = $topRPs
    ByProtocol        = $byProtocol
    ByAuthType        = $byAuthType
    ByNetworkLocation = $byNetworkLocation
    ByHour            = $byHour
    ByOutcome         = $byOutcome
    ByServer          = $byServer
}
Write-Host "HTML report written: $htmlPath" -ForegroundColor Green

Write-Host "`nAll reports written to: $OutputFolder" -ForegroundColor Green

if ($OpenReport -and (Test-Path $htmlPath)) {
    Start-Process $htmlPath
}

#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only discovery of AD user accounts likely used as service accounts.

.DESCRIPTION
    Correlates AD user signals (SPN, password settings, naming patterns,
    encryption configuration, privileged membership) and optional Security
    event evidence (4624 LogonType 4/5) to produce a confidence score.

    Output artifacts:
      - AdUserServiceAccountDiscovery.html
      - AdUserServiceAccountDiscovery.csv
      - AdUserServiceAccountDiscovery.HighConfidence.csv
      - AdUserServiceAccountDiscovery.json

    No write action is performed against Active Directory.

.PARAMETER Days
    Lookback window in days for 4624 collection. Default is 7.

.PARAMETER DomainControllers
    Optional DC list for 4624 collection. Default is all DCs in the domain.

.PARAMETER MaxEventsPerDc
    Max 4624 events read per DC. Default is 20000.

.PARAMETER DcTimeoutSeconds
    Per-DC WinRM connection timeout in seconds. An unreachable DC fails fast
    and is reported under Warnings/Errors instead of blocking the run.
    Default is 15.

.PARAMETER MaxReportRows
    Max rows rendered in the HTML "All Accounts" table. Only accounts with at
    least one signal (score > 0) are listed, capped at this value to keep the
    report light on large domains. The CSV and JSON exports always contain the
    full dataset. Default is 1000.

.PARAMETER OutputDir
    Output folder path.

.PARAMETER OpenReport
    Open the generated HTML report when the run completes. Alias: OpenHTMLReport.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int]$Days = 7,

    [string[]]$DomainControllers,

    [ValidateRange(100, 500000)]
    [int]$MaxEventsPerDc = 20000,

    [ValidateRange(1, 300)]
    [int]$DcTimeoutSeconds = 15,

    [ValidateRange(50, 100000)]
    [int]$MaxReportRows = 1000,

    [string]$OutputDir,

    [Alias('OpenHTMLReport')]
    [switch]$OpenReport
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $baseDir = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputDir = Join-Path -Path $baseDir -ChildPath ('Outputs\AdUserServiceAccountDiscovery_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

function HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-ConfidenceLevel {
    param([int]$Score)
    if ($Score -ge 70) { return 'High' }
    if ($Score -ge 45) { return 'Medium' }
    return 'Low'
}

function Get-StatusBadgeClass {
    param([string]$Status)
    switch ($Status) {
        'High' { 'fail'; break }
        'Medium' { 'warn'; break }
        'Low' { 'info'; break }
        'OK' { 'pass'; break }
        'Warning' { 'warn'; break }
        'Critical' { 'fail'; break }
        default { 'info' }
    }
}

function Get-Verdict {
    param(
        [int]$Score,
        [int]$ServiceLogons,
        [int]$BatchLogons,
        [bool]$HasSpn
    )

    if ($ServiceLogons -gt 0) { return 'Observed Service Usage' }
    if ($Score -ge 80 -or ($HasSpn -and $BatchLogons -gt 0 -and $Score -ge 65)) { return 'Very Likely Service Account' }
    if ($Score -ge 65) { return 'Likely Service Account' }
    if ($Score -ge 45) { return 'Possible Service Account' }
    return 'Unlikely Service Account'
}

function Get-KeywordMatch {
    param(
        [string]$SamAccountName,
        [string]$Name,
        [string]$DisplayName,
        [string]$Description
    )

    $text = @($SamAccountName, $Name, $DisplayName, $Description) -join ' '
    return [bool]($text -match '(?i)(^svc[_\-\.]|[_\-\.]svc$|service|sql|iis|app|batch|job|task|daemon|runas|api)')
}

function Get-EncTypeFlags {
    param([Nullable[int]]$Value)

    if ($null -eq $Value -or $Value -eq 0) {
        return [PSCustomObject]@{
            EncHex = '(absent/0)'
            Flags = 'Implicit default'
            Rc4WithoutAes = $false
            IsExplicitlySet = $false
        }
    }

    $flags = @()
    if ($Value -band 0x01) { $flags += 'DES_CRC' }
    if ($Value -band 0x02) { $flags += 'DES_MD5' }
    if ($Value -band 0x04) { $flags += 'RC4' }
    if ($Value -band 0x08) { $flags += 'AES128' }
    if ($Value -band 0x10) { $flags += 'AES256' }

    $hasRc4 = (($Value -band 0x04) -ne 0)
    $hasAes = ((($Value -band 0x08) -ne 0) -or (($Value -band 0x10) -ne 0))

    return [PSCustomObject]@{
        EncHex = ('0x{0:X}' -f $Value)
        Flags = ($flags -join ', ')
        Rc4WithoutAes = ($hasRc4 -and -not $hasAes)
        IsExplicitlySet = $true
    }
}

function Get-LogonEvidence {
    param(
        [string[]]$Dcs,
        [datetime]$Since,
        [int]$MaxEvents,
        [int]$TimeoutSeconds = 15
    )

    $usage = @{}
    $errors = New-Object System.Collections.Generic.List[string]
    $collected = 0

    if (-not $Dcs -or $Dcs.Count -eq 0) {
        return [PSCustomObject]@{
            Enabled = $false
            Usage = $usage
            Errors = $errors
            CollectedEvents = 0
        }
    }

    $sessionOption = New-PSSessionOption -OpenTimeout ($TimeoutSeconds * 1000) -CancelTimeout 5000

    foreach ($dc in $Dcs) {
        try {
            Write-Host ("      - querying {0} ..." -f $dc) -ForegroundColor DarkGray
            $events = Invoke-Command -ComputerName $dc -SessionOption $sessionOption -ScriptBlock {
                param($StartTime, $Limit)

                $filter = @{
                    LogName = 'Security'
                    Id = 4624
                    StartTime = $StartTime
                }

                Get-WinEvent -FilterHashtable $filter -MaxEvents $Limit -ErrorAction Stop |
                    Where-Object {
                        $_.Properties.Count -gt 8 -and (
                            $_.Properties[8].Value -eq 4 -or
                            $_.Properties[8].Value -eq 5
                        )
                    } |
                    ForEach-Object {
                        [PSCustomObject]@{
                            TargetUserName = [string]$_.Properties[5].Value
                            TargetDomainName = [string]$_.Properties[6].Value
                            LogonType = [int]$_.Properties[8].Value
                        }
                    }
            } -ArgumentList $Since, $MaxEvents -ErrorAction Stop

            foreach ($evt in $events) {
                $collected++

                $user = [string]$evt.TargetUserName
                $domain = [string]$evt.TargetDomainName

                if ([string]::IsNullOrWhiteSpace($user)) { continue }
                if ($user -in @('ANONYMOUS LOGON', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SYSTEM')) { continue }
                if ($user.EndsWith('$')) { continue }

                $key = if ([string]::IsNullOrWhiteSpace($domain)) {
                    $user.ToUpperInvariant()
                } else {
                    ('{0}\{1}' -f $domain, $user).ToUpperInvariant()
                }

                if (-not $usage.ContainsKey($key)) {
                    $usage[$key] = [PSCustomObject]@{
                        ServiceLogons = 0
                        BatchLogons = 0
                    }
                }

                if ($evt.LogonType -eq 5) { $usage[$key].ServiceLogons++ }
                if ($evt.LogonType -eq 4) { $usage[$key].BatchLogons++ }
            }
        } catch {
            $errors.Add("${dc}: $($_.Exception.Message)") | Out-Null
        }
    }

    return [PSCustomObject]@{
        Enabled = $true
        Usage = $usage
        Errors = $errors
        CollectedEvents = $collected
    }
}

function Build-HtmlReport {
    param(
        [hashtable]$Results,
        [string]$OutputPath
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $warningCount = $Results.Warnings.Count
    $errorCount = $Results.Errors.Count

    $findings = @()
    if ($Results.HighConfidenceCount -gt 0) {
        $findings += "<div class='finding danger'><strong>High-confidence candidates:</strong> $($Results.HighConfidenceCount) account(s) scored High confidence.</div>"
    }
    if ($Results.ObservedServiceUsageCount -gt 0) {
        $findings += "<div class='finding warn'><strong>Observed service usage:</strong> $($Results.ObservedServiceUsageCount) account(s) had LogonType 5 evidence.</div>"
    }
    if ($Results.EventCollectionEnabled -and $Results.EventCollectionErrors.Count -gt 0) {
        $findings += "<div class='finding warn'><strong>Event collection partial:</strong> $($Results.EventCollectionErrors.Count) domain controller(s) returned errors, confidence can be underestimated.</div>"
    }
    if ($findings.Count -eq 0) {
        $findings += "<div class='finding good'><strong>Signal:</strong> no immediate high-risk pattern found in the current dataset.</div>"
    }

    $kpiRows = ''
    foreach ($k in $Results.Kpis) {
        $badge = Get-StatusBadgeClass -Status $k.Status
        $kpiRows += "<tr><td>$(HtmlEncode $k.Name)</td><td style='font-weight:700;'>$(HtmlEncode ([string]$k.Value))</td><td>$(HtmlEncode $k.Description)</td><td><span class='badge $badge'>$(HtmlEncode $k.Status)</span></td></tr>`n"
    }

    $allRows = ''
    $scoredRows = @($Results.AllRows | Where-Object { $_.ConfidenceScore -gt 0 })
    $scoredTotal = $scoredRows.Count
    $cap = [int]$Results.MaxReportRows
    $allRowsShown = if ($cap -gt 0 -and $scoredTotal -gt $cap) { @($scoredRows | Select-Object -First $cap) } else { $scoredRows }
    foreach ($row in $allRowsShown) {
        $confidenceBadge = Get-StatusBadgeClass -Status $row.ConfidenceLevel
        $verdictBadge = if ($row.Verdict -eq 'Observed Service Usage') { 'fail' } elseif ($row.ConfidenceLevel -eq 'High') { 'warn' } else { 'info' }
        $allRows += "<tr><td>$(HtmlEncode $row.SamAccountName)</td><td>$(HtmlEncode $row.DisplayName)</td><td><span class='badge $confidenceBadge'>$(HtmlEncode $row.ConfidenceLevel)</span></td><td style='font-weight:700;'>$($row.ConfidenceScore)</td><td><span class='badge $verdictBadge'>$(HtmlEncode $row.Verdict)</span></td><td>$($row.HasSPN)</td><td>$($row.PasswordNeverExpires)</td><td>$($row.CannotChangePassword)</td><td style='font-weight:700;'>$($row.ServiceLogons)</td><td style='font-weight:700;'>$($row.BatchLogons)</td><td>$(HtmlEncode $row.EncFlags)</td><td>$(HtmlEncode $row.ReasonSummary)</td></tr>`n"
    }
    if ([string]::IsNullOrWhiteSpace($allRows)) {
        $allRows = "<tr><td colspan='12' class='empty'>No account scored any signal.</td></tr>"
    }

    $allNote = "Sorted by confidence score (descending) &mdash; this is your triage queue. Only accounts with at least one signal (score &gt; 0) are listed: $scoredTotal of $($Results.AllRows.Count) scanned. Accounts that scored zero are intentionally hidden here. The exported CSV (<code>AdUserServiceAccountDiscovery.csv</code>) and JSON contain <strong>every scanned account</strong>, including the zero-score ones, for offline filtering and audit trails."
    if ($cap -gt 0 -and $scoredTotal -gt $cap) {
        $allNote += " Display truncated to the top $cap rows by score &mdash; open the CSV for the complete list."
    }

    $warningRows = ''
    foreach ($w in $Results.Warnings) {
        $warningRows += "<tr><td>$(HtmlEncode $w)</td></tr>`n"
    }

    $errorRows = ''
    foreach ($e in $Results.Errors) {
        $errorRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n"
    }

    $html = @"
<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1.0'>
<title>AD User Service Account Discovery</title>
<style>
:root{--bg:#09111f;--bg-soft:#0f1b2d;--card:#111c30;--card-2:#16233a;--border:#28405f;--text:#dce7f7;--muted:#93a7c4;--accent:#68c3ff;--accent-2:#8ef0c9;--green:#49d17d;--red:#ff6b6b;--yellow:#f0c45c;--cyan:#52d6ff}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:radial-gradient(circle at top,#173055 0%,var(--bg) 45%,#08101c 100%);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1500px;margin:0 auto}
h1{color:#f4fbff;font-size:2.2rem;margin-bottom:.5rem;letter-spacing:-.02em}h2{color:var(--accent);font-size:1.35rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:var(--muted);font-size:.92rem;margin-bottom:0}
.hero{background:linear-gradient(135deg,rgba(104,195,255,.2),rgba(142,240,201,.1));border:1px solid rgba(104,195,255,.28);border-radius:18px;padding:1.6rem 1.8rem;margin-bottom:1.5rem;box-shadow:0 18px 50px rgba(0,0,0,.25)}.hero p{color:var(--muted);max-width:980px}.hero strong{color:var(--accent-2)}
.findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem;margin-bottom:1.5rem}.finding{border-radius:14px;padding:1rem 1.1rem;border:1px solid var(--border);background:rgba(255,255,255,.03);color:var(--text)}.finding strong{display:block;margin-bottom:.35rem}.finding.danger{border-color:rgba(255,107,107,.35);background:rgba(255,107,107,.08)}.finding.warn{border-color:rgba(240,196,92,.35);background:rgba(240,196,92,.08)}.finding.good{border-color:rgba(73,209,125,.35);background:rgba(73,209,125,.08)}
.card{background:linear-gradient(180deg,var(--card),var(--card-2));border:1px solid var(--border);border-radius:14px;padding:1.5rem;margin-bottom:1.5rem;box-shadow:0 12px 30px rgba(0,0,0,.18)}.advisory{background:rgba(82,214,255,.08);border:1px solid rgba(82,214,255,.28);border-radius:14px;padding:1rem 1.2rem;margin-bottom:1.5rem}.advisory strong{color:var(--cyan)}
table{width:100%;border-collapse:collapse;font-size:.84rem}th{background:rgba(255,255,255,.04);color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:top}tr:hover{background:rgba(255,255,255,.025)}
.badge{padding:3px 9px;border-radius:999px;font-size:.75rem;font-weight:700;display:inline-block}.badge.pass{background:rgba(73,209,125,.14);color:var(--green)}.badge.warn{background:rgba(240,196,92,.14);color:var(--yellow)}.badge.fail{background:rgba(255,107,107,.14);color:var(--red)}.badge.info{background:rgba(82,214,255,.14);color:var(--cyan)}
.note{color:var(--muted);font-style:italic;font-size:.85rem;margin:.5rem 0}.empty{color:var(--muted);text-align:center;padding:1rem}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.5rem}.summary-metric{background:linear-gradient(180deg,rgba(255,255,255,.04),rgba(255,255,255,.02));border:1px solid var(--border);border-radius:14px;padding:1.2rem 1rem;text-align:center;backdrop-filter:blur(8px)}.summary-metric .metric-value{font-size:2.2rem;font-weight:800;line-height:1.1}.summary-metric .metric-label{color:var(--muted);font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.6px}
.section-nav{position:sticky;top:0;background:rgba(9,17,31,.84);backdrop-filter:blur(10px);padding:.8rem 0;z-index:100;border-bottom:1px solid rgba(255,255,255,.08);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:.8rem;font-size:.85rem;padding:.45rem .7rem;border:1px solid rgba(104,195,255,.15);border-radius:999px;background:rgba(255,255,255,.02)}
.warning-alert{background:rgba(240,196,92,.08);border:1px solid rgba(240,196,92,.28);border-radius:14px;padding:1rem 1.5rem;margin-bottom:1.5rem}.error-alert{background:rgba(255,107,107,.08);border:1px solid rgba(255,107,107,.28);border-radius:14px;padding:1rem 1.5rem;margin-bottom:1.5rem}
</style></head><body><div class='container'>
<div class='hero'><h1>AD User Service Account Discovery</h1><p class='subtitle'>Domain: $(HtmlEncode $Results.Domain) | Generated: $timestamp | Window: last $($Results.Days) day(s)</p><p style='margin-top:.85rem;'><strong>Focus:</strong> identify user-class AD accounts likely used as service identities with confidence scoring and optional 4624 service or batch evidence.</p></div>
<nav class='section-nav'><a href='#summary'>Summary</a><a href='#kpis'>KPIs</a><a href='#all'>Scored Accounts</a>$(if($warningCount -gt 0){"<a href='#warnings' style='color:var(--yellow);'>Warnings</a>"})$(if($errorCount -gt 0){"<a href='#errors' style='color:var(--red);'>Errors</a>"})</nav>

<div id='summary'><h2>Summary</h2>
<div class='summary-grid'>
<div class='summary-metric' style='border-top:3px solid var(--accent)'><div class='metric-value' style='color:var(--accent)'>$($Results.AllRows.Count)</div><div class='metric-label'>Users Scanned</div></div>
<div class='summary-metric' style='border-top:3px solid var(--red)'><div class='metric-value' style='color:var(--red)'>$($Results.HighConfidenceCount)</div><div class='metric-label'>High Confidence</div></div>
<div class='summary-metric' style='border-top:3px solid var(--yellow)'><div class='metric-value' style='color:var(--yellow)'>$($Results.MediumConfidenceCount)</div><div class='metric-label'>Medium Confidence</div></div>
<div class='summary-metric' style='border-top:3px solid var(--cyan)'><div class='metric-value' style='color:var(--cyan)'>$($Results.ObservedServiceUsageCount)</div><div class='metric-label'>Observed Service Usage</div></div>
<div class='summary-metric' style='border-top:3px solid $(if($Results.EventCollectionEnabled){'var(--accent-2)'}else{'var(--yellow)'})'><div class='metric-value' style='color:$(if($Results.EventCollectionEnabled){'var(--accent-2)'}else{'var(--yellow)'})'>$(if($Results.EventCollectionEnabled){'ON'}else{'OFF'})</div><div class='metric-label'>4624 Evidence</div></div>
</div>
<div class='advisory'><strong>Read me first:</strong> a high score is a prioritization signal, not proof. Validate owner and runtime dependency before remediation.</div>
<div class='findings'>$($findings -join "`n")</div>
</div>

<div id='kpis'><h2>KPIs</h2><div class='card'><table><thead><tr><th>KPI</th><th>Value</th><th>How to read it</th><th>Status</th></tr></thead><tbody>$kpiRows</tbody></table></div></div>

<div id='all'><h2>Scored Accounts</h2><div class='card'><p class='note'>$allNote</p><table><thead><tr><th>SamAccountName</th><th>DisplayName</th><th>Confidence</th><th>Score</th><th>Verdict</th><th>HasSPN</th><th>PasswordNeverExpires</th><th>CannotChangePassword</th><th>ServiceLogons</th><th>BatchLogons</th><th>EncFlags</th><th>Reason summary</th></tr></thead><tbody>$allRows</tbody></table></div></div>

$(if($warningCount -gt 0){"<div id='warnings'><h2>Warnings</h2><div class='warning-alert'><table><tbody>$warningRows</tbody></table></div></div>"})
$(if($errorCount -gt 0){"<div id='errors'><h2>Errors</h2><div class='error-alert'><table><tbody>$errorRows</tbody></table></div></div>"})

<p class='note' style='text-align:center;margin-top:2rem;'>Generated by Invoke-AdUserServiceAccountDiscovery.ps1</p>
</div></body></html>
"@

    Set-Content -Path $OutputPath -Value $html -Encoding UTF8
}

Write-Host ''
Write-Host '=== AD User Service Account Discovery ===' -ForegroundColor Cyan
Write-Host ('Window: last {0} day(s)' -f $Days) -ForegroundColor DarkGray

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path -Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
}

$domain = Get-ADDomain -ErrorAction Stop
if (-not $DomainControllers -or $DomainControllers.Count -eq 0) {
    $DomainControllers = @(Get-ADDomainController -Filter * -ErrorAction Stop | Select-Object -ExpandProperty HostName)
}

$since = (Get-Date).AddDays(-1 * $Days)

Write-Host '[1/4] Collecting optional 4624 service or batch evidence...' -ForegroundColor Yellow
$eventEvidence = Get-LogonEvidence -Dcs $DomainControllers -Since $since -MaxEvents $MaxEventsPerDc -TimeoutSeconds $DcTimeoutSeconds

Write-Host '[2/4] Enumerating AD user accounts...' -ForegroundColor Yellow
$users = @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user))' -Properties Enabled,DisplayName,Description,PasswordNeverExpires,CannotChangePassword,ServicePrincipalName,LastLogonDate,pwdLastSet,MemberOf,AdminCount,msDS-SupportedEncryptionTypes,UserPrincipalName)

$privilegedGroupDns = @(
    ('CN=Domain Admins,CN=Users,{0}' -f $domain.DistinguishedName),
    ('CN=Enterprise Admins,CN=Users,{0}' -f $domain.DistinguishedName),
    ('CN=Administrators,CN=Builtin,{0}' -f $domain.DistinguishedName)
)

$rows = New-Object System.Collections.Generic.List[object]
$now = Get-Date

foreach ($u in $users) {
    if (-not $u.Enabled) { continue }

    $spnCount = @($u.ServicePrincipalName).Count
    $hasSpn = ($spnCount -gt 0)

    $keywordHit = Get-KeywordMatch -SamAccountName $u.SamAccountName -Name $u.Name -DisplayName $u.DisplayName -Description $u.Description

    $enc = Get-EncTypeFlags -Value $u.'msDS-SupportedEncryptionTypes'

    $pwdAgeDays = $null
    if ($u.pwdLastSet -and [int64]$u.pwdLastSet -gt 0) {
        $pwdDate = [datetime]::FromFileTime([int64]$u.pwdLastSet)
        $pwdAgeDays = [int]($now - $pwdDate).TotalDays
    }

    $isPrivileged = $false
    if ($u.MemberOf) {
        foreach ($groupDn in $u.MemberOf) {
            if ($privilegedGroupDns -contains $groupDn) {
                $isPrivileged = $true
                break
            }
        }
    }

    $keys = @(
        ('{0}\{1}' -f $domain.NetBIOSName, $u.SamAccountName).ToUpperInvariant(),
        ('{0}\{1}' -f $domain.DNSRoot, $u.SamAccountName).ToUpperInvariant(),
        ([string]$u.SamAccountName).ToUpperInvariant(),
        ([string]$u.UserPrincipalName).ToUpperInvariant()
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

    $serviceLogons = 0
    $batchLogons = 0
    foreach ($k in $keys) {
        if ($eventEvidence.Usage.ContainsKey($k)) {
            $serviceLogons = [Math]::Max($serviceLogons, [int]$eventEvidence.Usage[$k].ServiceLogons)
            $batchLogons = [Math]::Max($batchLogons, [int]$eventEvidence.Usage[$k].BatchLogons)
        }
    }

    $score = 0
    $reasons = New-Object System.Collections.Generic.List[string]

    if ($hasSpn) { $score += 35; $reasons.Add("SPN present ($spnCount)") | Out-Null }
    if ($u.PasswordNeverExpires) { $score += 15; $reasons.Add('PasswordNeverExpires') | Out-Null }
    if ($u.CannotChangePassword) { $score += 8; $reasons.Add('CannotChangePassword') | Out-Null }
    if ($keywordHit) { $score += 12; $reasons.Add('Service-like naming or description') | Out-Null }
    if ($pwdAgeDays -ne $null -and $pwdAgeDays -ge 365) { $score += 8; $reasons.Add("Old password ($pwdAgeDays days)") | Out-Null }
    if ($serviceLogons -gt 0) { $score += 35; $reasons.Add("Observed service logons (type 5): $serviceLogons") | Out-Null }
    if ($batchLogons -gt 0) { $score += 12; $reasons.Add("Observed batch logons (type 4): $batchLogons") | Out-Null }
    if ($isPrivileged -or $u.AdminCount -eq 1) { $score += 10; $reasons.Add('Privileged/admin signal') | Out-Null }
    if ($enc.IsExplicitlySet) { $score += 8; $reasons.Add("msDS-SupportedEncryptionTypes explicitly set ($($enc.EncHex))") | Out-Null }
    if ($enc.Rc4WithoutAes) { $score += 10; $reasons.Add('RC4 without AES in msDS-SupportedEncryptionTypes') | Out-Null }
    if ($u.LastLogonDate -and $u.LastLogonDate -ge $since) { $score += 5; $reasons.Add('Recent logon activity') | Out-Null }

    if ($score -gt 100) { $score = 100 }

    $confidence = Get-ConfidenceLevel -Score $score
    $verdict = Get-Verdict -Score $score -ServiceLogons $serviceLogons -BatchLogons $batchLogons -HasSpn $hasSpn

    $rows.Add([PSCustomObject]@{
        SamAccountName = $u.SamAccountName
        DisplayName = $u.DisplayName
        DistinguishedName = $u.DistinguishedName
        HasSPN = $hasSpn
        SPNCount = $spnCount
        PasswordNeverExpires = [bool]$u.PasswordNeverExpires
        CannotChangePassword = [bool]$u.CannotChangePassword
        LastLogonDate = $u.LastLogonDate
        PasswordAgeDays = $pwdAgeDays
        ServiceLogons = $serviceLogons
        BatchLogons = $batchLogons
        EncHex = $enc.EncHex
        EncFlags = $enc.Flags
        ConfidenceScore = $score
        ConfidenceLevel = $confidence
        Verdict = $verdict
        ReasonSummary = ($reasons -join '; ')
    }) | Out-Null
}

Write-Host '[3/4] Building datasets and report...' -ForegroundColor Yellow
$sorted = @($rows | Sort-Object -Property @{ Expression = 'ConfidenceScore'; Descending = $true }, @{ Expression = 'SamAccountName'; Descending = $false })
$topCandidates = @($sorted | Where-Object { $_.ConfidenceLevel -in @('High', 'Medium') -or $_.Verdict -eq 'Observed Service Usage' })
$highConfidenceRows = @($sorted | Where-Object { $_.ConfidenceLevel -eq 'High' -or $_.Verdict -eq 'Observed Service Usage' })

$htmlPath = Join-Path -Path $OutputDir -ChildPath 'AdUserServiceAccountDiscovery.html'
$csvPath = Join-Path -Path $OutputDir -ChildPath 'AdUserServiceAccountDiscovery.csv'
$highCsvPath = Join-Path -Path $OutputDir -ChildPath 'AdUserServiceAccountDiscovery.HighConfidence.csv'
$jsonPath = Join-Path -Path $OutputDir -ChildPath 'AdUserServiceAccountDiscovery.json'

$warnings = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]

if ($eventEvidence.Errors.Count -gt 0) {
    $warnings.Add('Some domain controllers could not return 4624 data. Review Errors for details.') | Out-Null
    foreach ($evErr in $eventEvidence.Errors) {
        $errors.Add($evErr) | Out-Null
    }
}

if ($sorted.Count -eq 0) {
    $warnings.Add('No enabled AD user accounts were returned by the query.') | Out-Null
}

$kpis = @(
    [PSCustomObject]@{
        Name = 'User accounts scanned'
        Value = $sorted.Count
        Description = 'Enabled AD user objects analyzed in this run.'
        Status = 'OK'
    },
    [PSCustomObject]@{
        Name = 'High confidence candidates'
        Value = (@($sorted | Where-Object { $_.ConfidenceLevel -eq 'High' }).Count)
        Description = 'Accounts with score >= 70.'
        Status = if ((@($sorted | Where-Object { $_.ConfidenceLevel -eq 'High' }).Count) -gt 0) { 'Warning' } else { 'OK' }
    },
    [PSCustomObject]@{
        Name = 'Observed service usage'
        Value = (@($sorted | Where-Object { $_.Verdict -eq 'Observed Service Usage' }).Count)
        Description = 'Accounts with at least one 4624 LogonType 5 event in scope.'
        Status = if ((@($sorted | Where-Object { $_.Verdict -eq 'Observed Service Usage' }).Count) -gt 0) { 'Warning' } else { 'OK' }
    },
    [PSCustomObject]@{
        Name = 'Accounts with SPN'
        Value = (@($sorted | Where-Object { $_.HasSPN }).Count)
        Description = 'Enabled user accounts carrying one or more SPNs.'
        Status = 'OK'
    },
    [PSCustomObject]@{
        Name = 'Event evidence collection'
        Value = if ($eventEvidence.Enabled) { "Enabled ($($eventEvidence.CollectedEvents) events)" } else { 'Disabled' }
        Description = '4624 service/batch evidence from Security logs on selected DCs.'
        Status = if ($eventEvidence.Enabled -and $eventEvidence.Errors.Count -eq 0) { 'OK' } else { 'Warning' }
    }
)

$results = @{
    Domain = $domain.DNSRoot
    Days = $Days
    AllRows = $sorted
    TopCandidates = $topCandidates
    MaxReportRows = $MaxReportRows
    HighConfidenceCount = (@($sorted | Where-Object { $_.ConfidenceLevel -eq 'High' }).Count)
    MediumConfidenceCount = (@($sorted | Where-Object { $_.ConfidenceLevel -eq 'Medium' }).Count)
    ObservedServiceUsageCount = (@($sorted | Where-Object { $_.Verdict -eq 'Observed Service Usage' }).Count)
    EventCollectionEnabled = [bool]$eventEvidence.Enabled
    EventCollectionErrors = @($eventEvidence.Errors)
    Warnings = $warnings
    Errors = $errors
    Kpis = $kpis
}

Build-HtmlReport -Results $results -OutputPath $htmlPath

$sorted | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
$highConfidenceRows | Export-Csv -Path $highCsvPath -NoTypeInformation -Encoding UTF8

[PSCustomObject]@{
    Domain = $results.Domain
    Days = $results.Days
    DomainControllers = $DomainControllers
    EventCollectionEnabled = $results.EventCollectionEnabled
    EventCollectionErrors = $results.EventCollectionErrors
    Kpis = $kpis
    Data = $sorted
} | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

Write-Host '[4/4] Done.' -ForegroundColor Green
Write-Host ('HTML report: {0}' -f $htmlPath) -ForegroundColor Cyan
Write-Host ('CSV (full): {0}' -f $csvPath) -ForegroundColor Cyan
Write-Host ('CSV (high confidence): {0}' -f $highCsvPath) -ForegroundColor Cyan
Write-Host ('JSON: {0}' -f $jsonPath) -ForegroundColor Cyan

if ($OpenReport) {
    Start-Process $htmlPath
}

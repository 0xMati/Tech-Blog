# Tiering\Export-TieringPhase8Html.ps1
# Generates a rich HTML report for Phase 8 — Monitoring & Detection.

function Export-TieringPhase8Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $violCount = $Results.TieringViolations.Count
    $kpiOK     = ($Results.KPIs | Where-Object Status -eq 'OK').Count
    $kpiTotal  = $Results.KPIs.Count
    $errCount  = $Results.Errors.Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # KPI rows
    $kpiRows = ''
    foreach ($k in $Results.KPIs) {
        $badge = switch ($k.Status) { 'OK' { "<span class='badge pass'>OK</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } 'Critical' { "<span class='badge fail'>Critical</span>" } default { "<span class='badge info'>$($k.Status)</span>" } }
        $kpiRows += "<tr><td>$(HtmlEncode $k.KPI)</td><td style='font-weight:700'>$($k.Value)</td><td>$($k.Target)</td><td>$badge</td></tr>`n"
    }

    # Violation rows
    $violRows = ''
    foreach ($v in $Results.TieringViolations) {
        $violRows += "<tr><td>$($v.Timestamp)</td><td>$(HtmlEncode $v.Account)</td><td>$(HtmlEncode $v.Computer)</td><td>$($v.LogonType)</td><td><span class='badge fail'>Critical</span></td></tr>`n"
    }

    # Group audit rows
    $grpRows = ''
    foreach ($g in $Results.PrivGroupAudit) {
        $badge = switch ($g.Status) { 'OK' { "<span class='badge pass'>OK</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } 'Critical' { "<span class='badge fail'>Critical</span>" } default { "<span class='badge info'>$($g.Status)</span>" } }
        $grpRows += "<tr><td>$(HtmlEncode $g.Group)</td><td style='font-weight:700'>$($g.Count)</td><td>$($g.Target)</td><td>$badge</td></tr>`n"
    }

    # Event log rows
    $logRows = ''
    foreach ($l in $Results.EventLogAudit) {
        $badge = switch ($l.Status) { 'OK' { "<span class='badge pass'>OK</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } 'Critical' { "<span class='badge fail'>Critical</span>" } default { "<span class='badge info'>$($l.Status)</span>" } }
        $logRows += "<tr><td>$(HtmlEncode $l.DC)</td><td>$($l.LogSizeMB) MB</td><td>$badge</td></tr>`n"
    }

    $errRows = ''
    foreach ($e in $Results.Errors) { $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n" }
    $errColor = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $violColor = if ($violCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $kpiColor = if ($kpiOK -eq $kpiTotal) { 'var(--green)' } else { 'var(--yellow)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 8 Monitoring Report</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#39c5cf}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1400px;margin:0 auto}
h1{color:var(--accent);font-size:2rem;margin-bottom:.5rem}h2{color:var(--accent);font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:#8b949e;font-size:.9rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:#21262d;color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid var(--border)}tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}.badge.pass{background:#0d2818;color:var(--green)}.badge.warn{background:#2d2000;color:var(--yellow)}.badge.fail{background:#2d0000;color:var(--red)}.badge.info{background:#0a2540;color:var(--cyan)}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.summary-metric{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1rem;text-align:center}.summary-metric .metric-value{font-size:2.2rem;font-weight:700;line-height:1.1}.summary-metric .metric-label{color:#8b949e;font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
.section-nav{position:sticky;top:0;background:var(--bg);padding:.5rem 0;z-index:100;border-bottom:1px solid var(--border);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:1.5rem;font-size:.85rem}
.note{color:#8b949e;font-style:italic;font-size:.85rem;margin:.5rem 0}
.error-alert{background:#2d0000;border:1px solid var(--red);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem}.error-alert h3{color:var(--red);margin:0 0 .5rem}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.step-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start}
.step-number{background:var(--accent);color:var(--bg);width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0}.step-text{font-size:.85rem;line-height:1.5}.step-text strong{color:var(--accent)}
.section-header{display:flex;align-items:center;gap:.6rem}.section-icon{font-size:1.3rem}
@media(max-width:1000px){.summary-grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body><div class="container">
<h1>MATI — Phase 8 Monitoring Report</h1>
<p class="subtitle">Monitoring &amp; Detection | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#kpis">KPIs</a><a href="#violations">Violations</a><a href="#groups">Priv Groups</a><a href="#eventlogs">Event Logs</a>
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid $violColor"><div class="metric-value" style="color:$violColor">$violCount</div><div class="metric-label">Tiering Violations</div></div>
<div class="summary-metric" style="border-top:3px solid $kpiColor"><div class="metric-value" style="color:$kpiColor">$kpiOK/$kpiTotal</div><div class="metric-label">KPIs OK</div></div>
<div class="summary-metric" style="border-top:3px solid var(--accent)"><div class="metric-value" style="color:var(--accent)">$($Results.T0Accounts.Count)</div><div class="metric-label">T0 Accounts</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div></div>

<div id="kpis"><h2 class="section-header"><span class="section-icon">&#x1F3AF;</span> KPI Dashboard</h2>
<div class="card"><table><thead><tr><th>KPI</th><th>Value</th><th>Target</th><th>Status</th></tr></thead><tbody>$kpiRows</tbody></table></div></div>

<div id="violations"><h2 class="section-header"><span class="section-icon">&#x1F6A8;</span> Tiering Violations (T0 on non-T0)</h2>
$(if($violCount -gt 0){"<div class='card'><table><thead><tr><th>Timestamp</th><th>Account</th><th>Computer</th><th>Logon Type</th><th>Severity</th></tr></thead><tbody>$violRows</tbody></table></div>"}else{"<p class='note'>No tiering violations detected in the last 7 days.</p>"})
</div>

<div id="groups"><h2 class="section-header"><span class="section-icon">&#x1F465;</span> Privileged Group Membership</h2>
<div class="card"><table><thead><tr><th>Group</th><th>Members</th><th>Target</th><th>Status</th></tr></thead><tbody>$grpRows</tbody></table></div></div>

<div id="eventlogs"><h2 class="section-header"><span class="section-icon">&#x1F4DD;</span> Security Event Log Settings (DCs)</h2>
$(if($Results.EventLogAudit.Count -gt 0){"<div class='card'><table><thead><tr><th>Domain Controller</th><th>Max Log Size</th><th>Status</th></tr></thead><tbody>$logRows</tbody></table></div>"}else{"<p class='note'>No DCs audited.</p>"})
</div>

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Import watchlists into SIEM</strong> — Use the exported CSV files as Sentinel Watchlists or SIEM lookup tables.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Create SIEM rules</strong> — Alert on T0 logons to non-T0 machines (4624 + watchlist match).</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Deploy MDI sensors</strong> — Install Microsoft Defender for Identity on all DCs.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Increase event log size</strong> — Set Security log to 1 GB+ on all DCs via GPO.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Phase 9 — Health Check</strong> — Automate recurring compliance checks and operational procedures.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 8 — Monitoring &amp; Detection</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

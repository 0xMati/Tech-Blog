# Tiering\Export-TieringPhase9Html.ps1
# Generates a rich HTML report for Phase 9 — Health Check & Ongoing Ops.

function Export-TieringPhase9Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $hcTotal = $Results.HealthChecks.Count
    $hcOK    = ($Results.HealthChecks | Where-Object Status -eq 'OK').Count
    $issueCount = $Results.ServiceAccountIssues.Count
    $staleCount = $Results.StaleAdmins.Count
    $errCount   = $Results.Errors.Count
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Health check rows
    $hcRows = ''
    foreach ($h in $Results.HealthChecks) {
        $badge = switch ($h.Status) { 'OK' { "<span class='badge pass'>OK</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } 'Critical' { "<span class='badge fail'>Critical</span>" } default { "<span class='badge info'>$($h.Status)</span>" } }
        $hcRows += "<tr><td>$(HtmlEncode $h.Check)</td><td style='font-weight:700'>$($h.Value)</td><td>$($h.Target)</td><td>$badge</td></tr>`n"
    }

    # Priv group rows
    $grpRows = ''
    foreach ($g in $Results.PrivGroupSummary) {
        $badge = switch ($g.Status) { 'OK' { "<span class='badge pass'>OK</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } default { "<span class='badge fail'>Critical</span>" } }
        $grpRows += "<tr><td>$(HtmlEncode $g.Group)</td><td style='font-weight:700'>$($g.Count)</td><td>$($g.Target)</td><td class='mono' style='font-size:.75rem'>$(HtmlEncode $g.Members)</td><td>$badge</td></tr>`n"
    }

    # Stale admin rows
    $staleRows = ''
    foreach ($s in $Results.StaleAdmins) {
        $staleRows += "<tr><td>$(HtmlEncode $s.Account)</td><td>$(HtmlEncode $s.Group)</td><td>$($s.Enabled)</td><td>$(HtmlEncode $s.Reason)</td></tr>`n"
    }

    # Break-glass rows
    $bgRows = ''
    foreach ($b in $Results.BreakGlassStatus) {
        $badge = switch ($b.Status) { 'OK' { "<span class='badge pass'>OK</span>" } default { "<span class='badge warn'>Warning</span>" } }
        $bgRows += "<tr><td>$(HtmlEncode $b.Account)</td><td>$($b.Enabled)</td><td>$($b.PasswordAgeDays)d</td><td>$($b.InDomainAdmins)</td><td>$($b.LastLogon)</td><td>$badge</td></tr>`n"
    }

    # Service account issue rows
    $svcRows = ''
    foreach ($sv in $Results.ServiceAccountIssues) {
        $badge = switch ($sv.Severity) { 'Critical' { "<span class='badge fail'>Critical</span>" } 'Warning' { "<span class='badge warn'>Warning</span>" } default { "<span class='badge info'>Info</span>" } }
        $svcRows += "<tr><td>$(HtmlEncode $sv.Account)</td><td class='mono' style='font-size:.75rem'>$(HtmlEncode $sv.SPN)</td><td>$($sv.PasswordAgeDays)d</td><td>$($sv.InDomainAdmins)</td><td>$(HtmlEncode $sv.Issues)</td><td>$badge</td></tr>`n"
    }

    # Quarantine rows
    $qRows = ''
    foreach ($q in $Results.QuarantineObjects) {
        $qRows += "<tr><td>$(HtmlEncode $q.Name)</td><td>$($q.ObjectClass)</td><td class='mono' style='font-size:.75rem'>$(HtmlEncode $q.OU)</td><td>$($q.AgeDays)d</td></tr>`n"
    }

    $errRows = ''
    foreach ($e in $Results.Errors) { $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n" }

    $errColor   = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }
    $hcColor    = if ($hcOK -eq $hcTotal) { 'var(--green)' } elseif ($hcOK -ge ($hcTotal * 0.6)) { 'var(--yellow)' } else { 'var(--red)' }
    $staleColor = if ($staleCount -eq 0) { 'var(--green)' } else { 'var(--yellow)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 9 Health Check Report</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#39c5cf}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1400px;margin:0 auto}
h1{color:var(--accent);font-size:2rem;margin-bottom:.5rem}h2{color:var(--accent);font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:#8b949e;font-size:.9rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:#21262d;color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid var(--border)}tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}.badge.pass{background:#0d2818;color:var(--green)}.badge.warn{background:#2d2000;color:var(--yellow)}.badge.fail{background:#2d0000;color:var(--red)}.badge.info{background:#0a2540;color:var(--cyan)}
.mono{font-family:'Cascadia Code','Fira Code',monospace}
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
<h1>MATI — Phase 9 Health Check Report</h1>
<p class="subtitle">Health Check &amp; Ongoing Ops | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#health">Health Checks</a><a href="#groups">Priv Groups</a><a href="#stale">Stale Admins</a><a href="#breakglass">Break-Glass</a><a href="#svc">Service Accounts</a><a href="#quarantine">Quarantine</a>
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F3E5;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid $hcColor"><div class="metric-value" style="color:$hcColor">$hcOK/$hcTotal</div><div class="metric-label">Health Checks OK</div></div>
<div class="summary-metric" style="border-top:3px solid $staleColor"><div class="metric-value" style="color:$staleColor">$staleCount</div><div class="metric-label">Stale Admins</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($issueCount -eq 0){'var(--green)'}else{'var(--yellow)'})"><div class="metric-value" style="color:$(if($issueCount -eq 0){'var(--green)'}else{'var(--yellow)'})">$issueCount</div><div class="metric-label">SVC Issues</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div></div>

<div id="health"><h2 class="section-header"><span class="section-icon">&#x2705;</span> Health Check Dashboard</h2>
$(if($hcTotal -gt 0){"<div class='card'><table><thead><tr><th>Check</th><th>Value</th><th>Target</th><th>Status</th></tr></thead><tbody>$hcRows</tbody></table></div>"}else{"<p class='note'>No health checks were executed.</p>"})
</div>

<div id="groups"><h2 class="section-header"><span class="section-icon">&#x1F465;</span> Privileged Group Membership</h2>
$(if($Results.PrivGroupSummary.Count -gt 0){"<div class='card'><table><thead><tr><th>Group</th><th>Members</th><th>Target</th><th>Member List</th><th>Status</th></tr></thead><tbody>$grpRows</tbody></table></div>"}else{"<p class='note'>Privileged group audit was not executed.</p>"})
</div>

<div id="stale"><h2 class="section-header"><span class="section-icon">&#x23F3;</span> Stale Privileged Accounts</h2>
$(if($staleCount -gt 0){"<div class='card'><table><thead><tr><th>Account</th><th>Group</th><th>Enabled</th><th>Reason</th></tr></thead><tbody>$staleRows</tbody></table></div>"}else{"<p class='note'>No stale privileged accounts detected (90-day threshold).</p>"})
</div>

<div id="breakglass"><h2 class="section-header"><span class="section-icon">&#x1F6A8;</span> Break-Glass Accounts</h2>
$(if($Results.BreakGlassStatus.Count -gt 0){"<div class='card'><table><thead><tr><th>Account</th><th>Enabled</th><th>PW Age</th><th>In DA</th><th>Last Logon</th><th>Status</th></tr></thead><tbody>$bgRows</tbody></table></div>"}else{"<p class='note'>No break-glass accounts checked — ensure at least 2 exist.</p>"})
</div>

<div id="svc"><h2 class="section-header"><span class="section-icon">&#x2699;</span> Service Account Issues</h2>
$(if($issueCount -gt 0){"<div class='card'><table><thead><tr><th>Account</th><th>SPN</th><th>PW Age</th><th>In DA</th><th>Issues</th><th>Severity</th></tr></thead><tbody>$svcRows</tbody></table></div>"}else{"<p class='note'>No service account issues found.</p>"})
</div>

<div id="quarantine"><h2 class="section-header"><span class="section-icon">&#x1F4E6;</span> Quarantine Objects</h2>
$(if($Results.QuarantineObjects.Count -gt 0){"<div class='card'><table><thead><tr><th>Name</th><th>Class</th><th>OU</th><th>Age</th></tr></thead><tbody>$qRows</tbody></table></div>"}else{"<p class='note'>No objects in quarantine OUs.</p>"})
</div>

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Recommended Actions</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Remove stale admins</strong> — Disable or remove accounts that haven't logged in for 90+ days from privileged groups.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Rotate service account passwords</strong> — Prioritize accounts in Domain Admins with old passwords.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Process quarantine objects</strong> — Review and classify or delete objects pending in quarantine OUs.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Schedule recurring run</strong> — Run this health check monthly and track KPI trends over time.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Document break-glass procedure</strong> — Ensure the break-glass process is documented, sealed and tested periodically.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 9 — Health Check &amp; Ongoing Ops</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

# Tiering\Export-TieringPhase7Html.ps1
# Generates a rich HTML report for Phase 7 — Tier 0 Object Protection.

function Export-TieringPhase7Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $aclCount  = $Results.ACLFindings.Count
    $gpoWarn   = ($Results.GPOFindings | Where-Object Status -ne 'OK').Count
    $gpoTotal  = $Results.GPOFindings.Count
    $svcCrit   = ($Results.ServiceAccountAudit | Where-Object Risk -eq 'Critical').Count
    $svcHigh   = ($Results.ServiceAccountAudit | Where-Object Risk -eq 'High').Count
    $svcTotal  = $Results.ServiceAccountAudit.Count
    $errCount  = $Results.Errors.Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $krbtgtAge = if ($Results.KrbtgtStatus) { $Results.KrbtgtStatus.AgeDays } else { 'N/A' }
    $krbtgtSev = if ($Results.KrbtgtStatus) { $Results.KrbtgtStatus.Severity } else { 'Unknown' }
    $krbtgtColor = switch ($krbtgtSev) { 'OK' { 'var(--green)' } 'Warning' { 'var(--yellow)' } 'Critical' { 'var(--red)' } default { 'var(--accent)' } }

    # ACL rows
    $aclRows = ''
    foreach ($a in $Results.ACLFindings) {
        $sevBadge = switch ($a.Severity) { 'Critical' { "<span class='badge fail'>Critical</span>" } 'High' { "<span class='badge warn'>High</span>" } default { "<span class='badge info'>$($a.Severity)</span>" } }
        $aclRows += "<tr><td>$(HtmlEncode $a.Object)</td><td>$(HtmlEncode $a.Identity)</td><td class='mono'>$(HtmlEncode $a.Rights)</td><td>$($a.Inherited)</td><td>$sevBadge</td></tr>`n"
    }

    # GPO rows
    $gpoRows = ''
    foreach ($g in $Results.GPOFindings) {
        $statusBadge = if ($g.Status -eq 'OK') { "<span class='badge pass'>OK</span>" } else { "<span class='badge warn'>$($g.Status)</span>" }
        $gpoRows += "<tr><td>$(HtmlEncode $g.GPOName)</td><td>$(HtmlEncode $g.Owner)</td><td>$statusBadge</td></tr>`n"
    }

    # Service account rows
    $svcRows = ''
    foreach ($s in $Results.ServiceAccountAudit) {
        $riskBadge = switch ($s.Risk) { 'Critical' { "<span class='badge fail'>Critical</span>" } 'High' { "<span class='badge warn'>High</span>" } 'Medium' { "<span class='badge info'>Medium</span>" } default { "<span class='badge pass'>Low</span>" } }
        $daBadge = if ($s.InDomainAdmins) { "<span class='badge fail'>YES</span>" } else { "<span class='badge pass'>No</span>" }
        $svcRows += "<tr><td>$(HtmlEncode $s.SamAccountName)</td><td>$(HtmlEncode $s.SPNs)</td><td>$($s.PasswordAge)d</td><td>$daBadge</td><td>$riskBadge</td></tr>`n"
    }

    $errRows = ''
    foreach ($e in $Results.Errors) { $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n" }
    $errColor = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 7 Audit Report</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#39c5cf}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1400px;margin:0 auto}
h1{color:var(--accent);font-size:2rem;margin-bottom:.5rem}h2{color:var(--accent);font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:#8b949e;font-size:.9rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:#21262d;color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid var(--border)}tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}.badge.pass{background:#0d2818;color:var(--green)}.badge.warn{background:#2d2000;color:var(--yellow)}.badge.fail{background:#2d0000;color:var(--red)}.badge.info{background:#0a2540;color:var(--cyan)}
.mono{font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}
.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:1.5rem}
.summary-metric{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1rem;text-align:center}.summary-metric .metric-value{font-size:2.2rem;font-weight:700;line-height:1.1}.summary-metric .metric-label{color:#8b949e;font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
.section-nav{position:sticky;top:0;background:var(--bg);padding:.5rem 0;z-index:100;border-bottom:1px solid var(--border);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:1.5rem;font-size:.85rem}
.note{color:#8b949e;font-style:italic;font-size:.85rem;margin:.5rem 0}
.error-alert{background:#2d0000;border:1px solid var(--red);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem}.error-alert h3{color:var(--red);margin:0 0 .5rem}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.step-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start}
.step-number{background:var(--accent);color:var(--bg);width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0}.step-text{font-size:.85rem;line-height:1.5}.step-text strong{color:var(--accent)}
.section-header{display:flex;align-items:center;gap:.6rem}.section-icon{font-size:1.3rem}
@media(max-width:1200px){.summary-grid{grid-template-columns:repeat(3,1fr)}}
</style></head><body><div class="container">
<h1>MATI — Phase 7 Audit Report</h1>
<p class="subtitle">Tier 0 Object Protection | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#acl">ACLs</a><a href="#gpos">GPO Ownership</a><a href="#krbtgt">krbtgt</a><a href="#svcacct">Service Accounts</a>
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid $(if($aclCount -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($aclCount -gt 0){'var(--red)'}else{'var(--green)'})">$aclCount</div><div class="metric-label">ACL Findings</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($gpoWarn -gt 0){'var(--yellow)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($gpoWarn -gt 0){'var(--yellow)'}else{'var(--green)'})">$gpoWarn</div><div class="metric-label">GPO Ownership Issues</div></div>
<div class="summary-metric" style="border-top:3px solid $krbtgtColor"><div class="metric-value" style="color:$krbtgtColor">$krbtgtAge</div><div class="metric-label">krbtgt Age (days)</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($svcCrit -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($svcCrit -gt 0){'var(--red)'}else{'var(--green)'})">$svcCrit</div><div class="metric-label">Critical Svc Accounts</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div></div>

<div id="acl"><h2 class="section-header"><span class="section-icon">&#x1F50D;</span> ACL Audit — Critical Objects</h2>
$(if($aclCount -gt 0){"<div class='card'><table><thead><tr><th>Object</th><th>Identity</th><th>Rights</th><th>Inherited</th><th>Severity</th></tr></thead><tbody>$aclRows</tbody></table></div>"}else{"<p class='note'>No dangerous non-standard ACEs found on critical objects.</p>"})
</div>

<div id="gpos"><h2 class="section-header"><span class="section-icon">&#x1F4C4;</span> GPO Ownership Audit</h2>
<div class="card"><p class="note">Total GPOs: $gpoTotal | Non-standard ownership: $gpoWarn</p>
<table><thead><tr><th>GPO Name</th><th>Owner</th><th>Status</th></tr></thead><tbody>$gpoRows</tbody></table></div></div>

<div id="krbtgt"><h2 class="section-header"><span class="section-icon">&#x1F511;</span> krbtgt Account</h2>
<div class="card">
<p>Password last set: <strong>$(if($Results.KrbtgtStatus){$Results.KrbtgtStatus.PasswordLastSet}else{'N/A'})</strong></p>
<p>Age: <strong style="color:$krbtgtColor">$krbtgtAge days</strong> — Severity: <strong style="color:$krbtgtColor">$krbtgtSev</strong></p>
$(if($Results.KrbtgtRotated){"<p style='color:var(--green);font-weight:600;'>First rotation completed. Run second rotation after 12+ hours.</p>"})
</div></div>

<div id="svcacct"><h2 class="section-header"><span class="section-icon">&#x2699;</span> Service Account Audit (SPN Accounts)</h2>
$(if($svcTotal -gt 0){"<div class='card'><p class='note'>Total: $svcTotal | Critical (in DA): $svcCrit | High (pwd >365d): $svcHigh</p><table><thead><tr><th>Account</th><th>SPNs</th><th>Pwd Age</th><th>In DA</th><th>Risk</th></tr></thead><tbody>$svcRows</tbody></table></div>"}else{"<p class='note'>No SPN-bearing accounts found.</p>"})
</div>

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Remediate critical ACLs</strong> — Remove WriteDACL/GenericAll from non-admin identities on domain root and AdminSDHolder.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Fix GPO ownership</strong> — Set owner to Domain Admins for all T0-linked GPOs.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Rotate krbtgt</strong> — If older than 180 days, perform double rotation (12h interval).</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Migrate to gMSA</strong> — Replace service accounts in Domain Admins with gMSAs where possible.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Phase 8 — Monitoring &amp; Detection</strong> — Deploy tiering violation alerts, MDI sensors, event forwarding.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 7 — Tier 0 Object Protection</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

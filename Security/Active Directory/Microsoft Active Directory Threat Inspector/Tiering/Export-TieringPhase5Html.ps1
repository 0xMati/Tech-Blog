# Tiering\Export-TieringPhase5Html.ps1
# Generates a rich HTML report for Phase 5 — PAW Hardening GPOs.

function Export-TieringPhase5Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $gpoCreated = $Results.GPOsCreated.Count
    $gpoExisted = $Results.GPOsExisted.Count
    $linksCreated = $Results.LinksCreated.Count
    $settingsCount = $Results.SettingsApplied.Count
    $errCount = $Results.Errors.Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $gpoRows = ''
    foreach ($g in $Results.GPOsCreated) { $gpoRows += "<tr><td>$(HtmlEncode $g.Name)</td><td class='mono'>$($g.Id)</td><td><span class='badge pass'>Created</span></td></tr>`n" }
    foreach ($g in $Results.GPOsExisted) { $gpoRows += "<tr><td>$(HtmlEncode $g.Name)</td><td class='mono'>$($g.Id)</td><td><span class='badge info'>Existed</span></td></tr>`n" }

    $linkRows = ''
    foreach ($l in $Results.LinksCreated) { $linkRows += "<tr><td>$(HtmlEncode $l.GPO)</td><td class='mono'>$(HtmlEncode $l.Target)</td><td><span class='badge pass'>Linked</span></td></tr>`n" }
    foreach ($l in $Results.LinksExisted) { $linkRows += "<tr><td>$(HtmlEncode $l.GPO)</td><td class='mono'>$(HtmlEncode $l.Target)</td><td><span class='badge info'>Existed</span></td></tr>`n" }

    $settingsRows = ''
    foreach ($s in $Results.SettingsApplied) {
        $statusBadge = if ($s.Status -eq 'Applied') { "<span class='badge pass'>Applied</span>" } else { "<span class='badge warn'>$($s.Status)</span>" }
        $settingsRows += "<tr><td>$(HtmlEncode $s.GPO)</td><td>$(HtmlEncode $s.Setting)</td><td>$statusBadge</td></tr>`n"
    }

    $errRows = ''
    foreach ($e in $Results.Errors) { $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n" }
    $errColor = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 5 Deployment Report</title>
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
<h1>MATI — Phase 5 Deployment Report</h1>
<p class="subtitle">PAW Hardening GPOs | Domain: $(HtmlEncode $DomainDN) | PAW OU: $(HtmlEncode $Results.PAW_OU) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#gpos">GPOs</a><a href="#settings">Settings</a><a href="#links">Links</a>
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid var(--green)"><div class="metric-value" style="color:var(--green)">$gpoCreated</div><div class="metric-label">GPOs Created</div></div>
<div class="summary-metric" style="border-top:3px solid var(--cyan)"><div class="metric-value" style="color:var(--cyan)">$gpoExisted</div><div class="metric-label">GPOs Existed</div></div>
<div class="summary-metric" style="border-top:3px solid var(--accent)"><div class="metric-value" style="color:var(--accent)">$settingsCount</div><div class="metric-label">Settings Applied</div></div>
<div class="summary-metric" style="border-top:3px solid var(--green)"><div class="metric-value" style="color:var(--green)">$linksCreated</div><div class="metric-label">Links Created</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div></div>

<div id="gpos"><h2 class="section-header"><span class="section-icon">&#x1F6E1;</span> GPOs</h2>
<div class="card"><table><thead><tr><th>GPO Name</th><th>ID</th><th>Status</th></tr></thead><tbody>$gpoRows</tbody></table></div></div>

<div id="settings"><h2 class="section-header"><span class="section-icon">&#x2699;</span> Settings Applied</h2>
<div class="card"><table><thead><tr><th>GPO</th><th>Setting</th><th>Status</th></tr></thead><tbody>$settingsRows</tbody></table></div></div>

<div id="links"><h2 class="section-header"><span class="section-icon">&#x1F517;</span> GPO Links</h2>
<div class="card"><table><thead><tr><th>GPO</th><th>Target OU</th><th>Status</th></tr></thead><tbody>$linkRows</tbody></table></div></div>

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Configure firewall rules manually</strong> — Open GPMC, edit the Firewall GPO, add outbound allow rules for RDP to DCs/T0 servers only.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Deploy PAW hardware</strong> — Physical machines with TPM 2.0, Secure Boot, BitLocker (TPM + PIN), clean OS install.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Verify Credential Guard</strong> — Run <code>msinfo32</code> on PAW, confirm VBS: Running, Credential Guard: Running.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Test Remote Credential Guard</strong> — RDP from PAW to DC with <code>mstsc /remoteGuard</code> and verify SSO to network resources.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Phase 6 — GPO Hardening Per Tier</strong> — Apply per-tier hardening baselines to DCs, T1 servers, T2 workstations.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 5 — PAW Hardening GPOs</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

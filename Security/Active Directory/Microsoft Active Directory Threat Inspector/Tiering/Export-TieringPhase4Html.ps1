# Tiering\Export-TieringPhase4Html.ps1
# Generates a rich HTML report for Phase 4 — Create Auth Policies & Silos.

function Export-TieringPhase4Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $accAssigned  = $Results.AccountsAssigned.Count
    $compAssigned = $Results.ComputersAssigned.Count
    $errCount     = $Results.Errors.Count
    $warningCount = $Results.Warnings.Count
    $claimsReady  = [bool]$Results.ClaimsReady
    $claimsCount  = $Results.ClaimsStatus.Count
    $timestamp    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $mode         = $Results.EnforcementMode
    $modeColor    = 'var(--yellow)'
    $claimsColor  = if ($claimsReady) { 'var(--green)' } else { 'var(--red)' }

    # Account rows
    $accRows = ''
    foreach ($a in $Results.AccountsAssigned) {
        $accRows += "<tr><td>$(HtmlEncode $a.SamAccountName)</td><td>$($a.Type)</td><td>$(HtmlEncode $a.Silo)</td><td><span class='badge pass'>Assigned</span></td></tr>`n"
    }

    # Computer rows
    $compRows = ''
    foreach ($c in $Results.ComputersAssigned) {
        $compRows += "<tr><td>$(HtmlEncode $c.SamAccountName)</td><td>$($c.Type)</td><td>$(HtmlEncode $c.Silo)</td><td><span class='badge pass'>Assigned</span></td></tr>`n"
    }

    # Claims rows
    $claimsRows = ''
    foreach ($c in $Results.ClaimsStatus) {
        $statusBadge = switch ($c.Status) {
            'Supported' { "<span class='badge pass'>Supported</span>" }
            'Always provide claims' { "<span class='badge pass'>Always provide claims</span>" }
            'Not configured' { "<span class='badge fail'>Not configured</span>" }
            default { "<span class='badge warn'>$(HtmlEncode $c.Status)</span>" }
        }
        $claimsRows += "<tr><td>$(HtmlEncode $c.DCName)</td><td>$statusBadge</td><td>$(if($null -ne $c.ClaimsValue){$c.ClaimsValue}else{'—'})</td><td>$(HtmlEncode $c.Detail)</td></tr>`n"
    }

    # Warning rows
    $warningRows = ''
    foreach ($w in $Results.Warnings) { $warningRows += "<tr><td>$(HtmlEncode $w)</td></tr>`n" }

    # Error rows
    $errRows = ''
    foreach ($e in $Results.Errors) { $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n" }
    $errColor = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 4 Deployment Report</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#39c5cf}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1400px;margin:0 auto}
h1{color:var(--accent);font-size:2rem;margin-bottom:.5rem}h2{color:var(--accent);font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:#8b949e;font-size:.9rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:#21262d;color:var(--accent);padding:10px 12px;text-align:left;font-weight:600;position:sticky;top:0}td{padding:8px 12px;border-bottom:1px solid var(--border)}tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}.badge.pass{background:#0d2818;color:var(--green)}.badge.warn{background:#2d2000;color:var(--yellow)}.badge.fail{background:#2d0000;color:var(--red)}.badge.info{background:#0a2540;color:var(--cyan)}
.mono{font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}
.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:1.5rem}
.summary-metric{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1rem;text-align:center}.summary-metric .metric-value{font-size:2.2rem;font-weight:700;line-height:1.1}.summary-metric .metric-label{color:#8b949e;font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
.section-nav{position:sticky;top:0;background:var(--bg);padding:.5rem 0;z-index:100;border-bottom:1px solid var(--border);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:1.5rem;font-size:.85rem}
.note{color:#8b949e;font-style:italic;font-size:.85rem;margin:.5rem 0}
.error-alert{background:#2d0000;border:1px solid var(--red);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem}.error-alert h3{color:var(--red);margin:0 0 .5rem}
.info-banner{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--accent);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1rem;font-size:.9rem}
.info-banner strong{color:var(--accent)}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.step-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start}
.step-number{background:var(--accent);color:var(--bg);width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0}.step-text{font-size:.85rem;line-height:1.5}.step-text strong{color:var(--accent)}
.section-header{display:flex;align-items:center;gap:.6rem}.section-icon{font-size:1.3rem}
.policy-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
.policy-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;border-top:3px solid var(--red)}
.policy-card .pc-title{font-weight:600;color:var(--red);font-size:.95rem;margin-bottom:.5rem}.policy-card .pc-detail{font-size:.82rem;color:#8b949e;line-height:1.7}
.policy-card .pc-detail span{color:var(--text)}
@media(max-width:1000px){.summary-grid{grid-template-columns:repeat(2,1fr)}.policy-grid{grid-template-columns:1fr}}
</style></head><body><div class="container">
<h1>MATI — Phase 4 Deployment Report</h1>
<p class="subtitle">Authentication Policies &amp; Silos | Audit-only deployment | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#policies">Policies</a><a href="#claims">KDC Claims</a><a href="#accounts">Accounts</a><a href="#computers">Computers</a>
$(if($warningCount -gt 0){'<a href="#warnings" style="color:var(--yellow);">Warnings</a>'})
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div class="info-banner">
<span style="font-size:1.5rem;">&#x1F50D;</span>
<div><strong>Mode: $mode</strong> — Phase 4 deploys audit-only configuration. Analyze Event ID 105/106 before any later move to enforce mode.<br>
<span style="color:#8b949e;">DFL: $(HtmlEncode $Results.DomainMode) | Base DN: <code style="color:var(--cyan);">$(HtmlEncode $Results.BaseDN)</code></span></div>
</div>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid $modeColor"><div class="metric-value" style="color:$modeColor">$mode</div><div class="metric-label">Enforcement</div></div>
<div class="summary-metric" style="border-top:3px solid $claimsColor"><div class="metric-value" style="color:$claimsColor">$(if($claimsReady){'Ready'}else{'Review'})</div><div class="metric-label">KDC Claims</div></div>
<div class="summary-metric" style="border-top:3px solid var(--green)"><div class="metric-value" style="color:var(--green)">$accAssigned</div><div class="metric-label">Accounts Assigned</div></div>
<div class="summary-metric" style="border-top:3px solid var(--cyan)"><div class="metric-value" style="color:var(--cyan)">$compAssigned</div><div class="metric-label">Computers Assigned</div></div>
<div class="summary-metric" style="border-top:3px solid var(--yellow)"><div class="metric-value" style="color:var(--yellow)">$warningCount</div><div class="metric-label">Warnings</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div></div>

<div id="policies"><h2 class="section-header"><span class="section-icon">&#x1F512;</span> Policies &amp; Silo</h2>
<div class="policy-grid">
<div class="policy-card"><div class="pc-title">User Auth Policy</div><div class="pc-detail">
Name: <span>$(if($Results.PolicyCreated){HtmlEncode $Results.PolicyCreated.Name}else{'N/A'})</span><br>
Status: <span>$(if($Results.PolicyCreated){$Results.PolicyCreated.Status}else{'N/A'})</span><br>
TGT Lifetime: <span>$(if($Results.PolicyCreated){"$($Results.PolicyCreated.TGTLifetime) min"}else{'N/A'})</span>
</div></div>
<div class="policy-card"><div class="pc-title">Computer Auth Policy</div><div class="pc-detail">
Name: <span>$(if($Results.ComputerPolicyCreated){HtmlEncode $Results.ComputerPolicyCreated.Name}else{'N/A'})</span><br>
Status: <span>$(if($Results.ComputerPolicyCreated){$Results.ComputerPolicyCreated.Status}else{'N/A'})</span>
</div></div>
<div class="policy-card"><div class="pc-title">Authentication Silo</div><div class="pc-detail">
Name: <span>$(if($Results.SiloCreated){HtmlEncode $Results.SiloCreated.Name}else{'N/A'})</span><br>
Status: <span>$(if($Results.SiloCreated){$Results.SiloCreated.Status}else{'N/A'})</span>
</div></div>
</div></div>

<div id="claims"><h2 class="section-header"><span class="section-icon">&#x1F6E1;</span> KDC Claims, Compound Auth &amp; Kerberos Armoring</h2>
$(if($claimsCount -gt 0){"<div class='card'><table><thead><tr><th>Domain Controller</th><th>Status</th><th>EnableCbacAndArmor</th><th>Detail</th></tr></thead><tbody>$claimsRows</tbody></table></div>"}else{"<p class='note'>No domain controller claims status could be collected.</p>"})
</div>

<div id="accounts"><h2 class="section-header"><span class="section-icon">&#x1F464;</span> Accounts Assigned to Silo</h2>
$(if($accAssigned -gt 0){"<div class='card'><table><thead><tr><th>Account</th><th>Type</th><th>Silo</th><th>Status</th></tr></thead><tbody>$accRows</tbody></table></div>"}else{"<p class='note'>No accounts were assigned to the silo.</p>"})
</div>

<div id="computers"><h2 class="section-header"><span class="section-icon">&#x1F5A5;</span> Computers Assigned to Silo</h2>
$(if($compAssigned -gt 0){"<div class='card'><table><thead><tr><th>Computer</th><th>Type</th><th>Silo</th><th>Status</th></tr></thead><tbody>$compRows</tbody></table></div>"}else{"<p class='note'>No computers were assigned to the silo.</p>"})
</div>

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

$(if($warningCount -gt 0){@"
<div id="warnings"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Warnings</h2>
<div class="card"><table><tbody>$warningRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Monitor Event IDs 105/106</strong> — Check <code>AuthenticationPolicyFailures-DomainController</code> log on all DCs for violations.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Fix KDC claims prerequisites</strong> — Ensure every DC has <code>EnableCbacAndArmor</code> set to <code>1</code> or <code>2</code> before planning enforce mode.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Review warnings before enforce</strong> — Existing enforced policies or silos should be reviewed to avoid blocking valid Tier 0 authentication flows.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Move to Enforce later</strong> — After audit analysis and prerequisite validation, apply enforce mode through a separate controlled change.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Phase 5 — Create PAW Hardening GPOs</strong> — Harden PAW machines with Credential Guard, HVCI, BitLocker, and firewall rules, and prepare for a Microsoft-recommended WDAC / App Control rollout.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 4 — Authentication Policies &amp; Silos</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

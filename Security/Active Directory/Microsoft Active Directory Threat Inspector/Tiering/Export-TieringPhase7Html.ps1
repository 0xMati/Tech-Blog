# Tiering\Export-TieringPhase7Html.ps1
# Generates a rich HTML report for Phase 7 — Implement Tier 0 Object Protection.

function Export-TieringPhase7Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]$Results,
        [Parameter(Mandatory)] [string]$DomainDN,
        [Parameter(Mandatory)] [hashtable]$TieringConfig,
        [Parameter(Mandatory)] [string]$OutputPath
    )

    function HtmlEncode([string]$s) { if (-not $s) { return '' }; [System.Net.WebUtility]::HtmlEncode($s) }

    $objectCount = if ($null -ne $Results.AuditedObjects) { $Results.AuditedObjects.Count } else { 0 }
    $aclCount = $Results.ACLFindings.Count
    $gpoAuditCount = if ($null -ne $Results.AuditedGPOs) { $Results.AuditedGPOs.Count } else { 0 }
    $gpoIssueCount = ($Results.GPOFindings | Where-Object Status -ne 'OK').Count
    $svcCrit = ($Results.ServiceAccountAudit | Where-Object Risk -eq 'Critical').Count
    $svcHigh = ($Results.ServiceAccountAudit | Where-Object Risk -eq 'High').Count
    $svcTotal = $Results.ServiceAccountAudit.Count
    $warningCount = $Results.Warnings.Count
    $errCount = $Results.Errors.Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    $krbtgtAge = if ($Results.KrbtgtStatus) { $Results.KrbtgtStatus.AgeDays } else { 'N/A' }
    $krbtgtSev = if ($Results.KrbtgtStatus) { $Results.KrbtgtStatus.Severity } else { 'Unknown' }
    $krbtgtColor = switch ($krbtgtSev) {
        'OK' { 'var(--green)' }
        'Warning' { 'var(--yellow)' }
        'Critical' { 'var(--red)' }
        default { 'var(--accent)' }
    }

    $scopeRows = ''
    foreach ($obj in $Results.AuditedObjects) {
        $scopeRows += "<tr><td>$(HtmlEncode $obj.Name)</td><td>$(HtmlEncode $obj.Category)</td><td class='mono'>$(HtmlEncode $obj.Path)</td><td>$(HtmlEncode $obj.Notes)</td></tr>`n"
    }

    $aclRows = ''
    foreach ($a in $Results.ACLFindings) {
        $sevBadge = switch ($a.Severity) {
            'Critical' { "<span class='badge fail'>Critical</span>" }
            'High' { "<span class='badge warn'>High</span>" }
            default { "<span class='badge info'>$($a.Severity)</span>" }
        }
        $aclRows += "<tr><td>$(HtmlEncode $a.Object)</td><td>$(HtmlEncode $a.Category)</td><td>$(HtmlEncode $a.Identity)</td><td class='mono'>$(HtmlEncode $a.Rights)</td><td>$($a.Inherited)</td><td>$sevBadge</td></tr>`n"
    }

    $gpoScopeRows = ''
    foreach ($gpo in $Results.AuditedGPOs) {
        $enabledBadge = if ($gpo.Enabled) { "<span class='badge pass'>Enabled</span>" } else { "<span class='badge warn'>Disabled</span>" }
        $enforcedBadge = if ($gpo.Enforced) { "<span class='badge info'>Enforced</span>" } else { "<span class='badge pass'>No</span>" }
        $gpoScopeRows += "<tr><td>$(HtmlEncode $gpo.GPOName)</td><td class='mono'>$(HtmlEncode $gpo.GPOId)</td><td>$enabledBadge</td><td>$enforcedBadge</td><td>$($gpo.LinkOrder)</td></tr>`n"
    }

    $gpoRows = ''
    foreach ($g in $Results.GPOFindings) {
        $statusBadge = switch ($g.Status) {
            'OK' { "<span class='badge pass'>OK</span>" }
            'Warning' { "<span class='badge warn'>Warning</span>" }
            'Critical' { "<span class='badge fail'>Critical</span>" }
            default { "<span class='badge info'>$(HtmlEncode $g.Status)</span>" }
        }
        $gpoRows += "<tr><td>$(HtmlEncode $g.GPOName)</td><td>$(HtmlEncode $g.FindingType)</td><td>$(HtmlEncode $g.Principal)</td><td>$(HtmlEncode $g.Permission)</td><td>$statusBadge</td><td>$(HtmlEncode $g.Details)</td></tr>`n"
    }

    $svcRows = ''
    foreach ($s in $Results.ServiceAccountAudit) {
        $riskBadge = switch ($s.Risk) {
            'Critical' { "<span class='badge fail'>Critical</span>" }
            'High' { "<span class='badge warn'>High</span>" }
            'Medium' { "<span class='badge info'>Medium</span>" }
            default { "<span class='badge pass'>Low</span>" }
        }
        $tier0Badge = if ($s.Tier0Scoped) { "<span class='badge info'>Tier 0</span>" } else { "<span class='badge pass'>No</span>" }
        $enabledBadge = if ($s.Enabled) { "<span class='badge pass'>Enabled</span>" } else { "<span class='badge warn'>Disabled</span>" }
        $svcRows += "<tr><td>$(HtmlEncode $s.Name)</td><td>$(HtmlEncode $s.AccountType)</td><td>$enabledBadge</td><td>$(HtmlEncode $s.PasswordState)</td><td>$(HtmlEncode $s.PrivilegedGroups)</td><td>$tier0Badge</td><td>$riskBadge</td></tr>`n"
    }

    $warningRows = ''
    foreach ($warning in $Results.Warnings) {
        $warningRows += "<tr><td>$(HtmlEncode $warning)</td></tr>`n"
    }

    $errRows = ''
    foreach ($errorText in $Results.Errors) {
        $errRows += "<tr><td>$(HtmlEncode $errorText)</td></tr>`n"
    }

    $errColor = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>MATI — Phase 7 — Implement Tier 0 Object Protection</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;--green:#3fb950;--red:#f85149;--yellow:#d29922;--cyan:#39c5cf}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:2rem}.container{max-width:1440px;margin:0 auto}
h1{color:var(--accent);font-size:2rem;margin-bottom:.5rem}h2{color:var(--accent);font-size:1.4rem;margin:2rem 0 1rem;padding-bottom:.5rem;border-bottom:1px solid var(--border)}.subtitle{color:#8b949e;font-size:.9rem;margin-bottom:2rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.5rem;margin-bottom:1.5rem}
table{width:100%;border-collapse:collapse;font-size:.85rem}th{background:#21262d;color:var(--accent);padding:10px 12px;text-align:left;font-weight:600}td{padding:8px 12px;border-bottom:1px solid var(--border);vertical-align:top}tr:hover{background:#1c2128}
.badge{padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600;display:inline-block}.badge.pass{background:#0d2818;color:var(--green)}.badge.warn{background:#2d2000;color:var(--yellow)}.badge.fail{background:#2d0000;color:var(--red)}.badge.info{background:#0a2540;color:var(--cyan)}
.mono{font-family:'Cascadia Code','Consolas',monospace;font-size:.8rem}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:1.5rem}
.summary-metric{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem 1rem;text-align:center}.summary-metric .metric-value{font-size:2.2rem;font-weight:700;line-height:1.1}.summary-metric .metric-label{color:#8b949e;font-size:.78rem;margin-top:.3rem;text-transform:uppercase;letter-spacing:.5px}
.section-nav{position:sticky;top:0;background:var(--bg);padding:.5rem 0;z-index:100;border-bottom:1px solid var(--border);margin-bottom:1.5rem}.section-nav a{color:var(--accent);text-decoration:none;margin-right:1.5rem;font-size:.85rem}
.note{color:#8b949e;font-style:italic;font-size:.85rem;margin:.5rem 0}
.advisory{background:#0a2540;border:1px solid var(--cyan);border-radius:8px;padding:1rem 1.2rem;margin-bottom:1.5rem}.advisory strong{color:var(--cyan)}
.warning-alert{background:#2d2000;border:1px solid var(--yellow);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem}.warning-alert h3{color:var(--yellow);margin:0 0 .5rem}
.error-alert{background:#2d0000;border:1px solid var(--red);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem}.error-alert h3{color:var(--red);margin:0 0 .5rem}
.steps-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}.step-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem;display:flex;gap:1rem;align-items:flex-start}
.step-number{background:var(--accent);color:var(--bg);width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.85rem;flex-shrink:0}.step-text{font-size:.85rem;line-height:1.5}.step-text strong{color:var(--accent)}
.section-header{display:flex;align-items:center;gap:.6rem}.section-icon{font-size:1.3rem}
</style></head><body><div class="container">
<h1>MATI — Phase 7 — Implement Tier 0 Object Protection</h1>
<p class="subtitle">Implement Tier 0 Object Protection | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>
<nav class="section-nav">
<a href="#summary">Summary</a><a href="#scope">Audit Scope</a><a href="#acl">ACLs</a><a href="#gposcope">Tier 0 GPOs</a><a href="#gpofindings">GPO Findings</a><a href="#krbtgt">krbtgt</a><a href="#svcacct">Service Accounts</a>
$(if($warningCount -gt 0){'<a href="#warnings" style="color:var(--yellow);">Warnings</a>'})
$(if($errCount -gt 0){'<a href="#errors" style="color:var(--red);">Errors</a>'})
<a href="#nextsteps">Next Steps</a></nav>

<div id="summary"><h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Summary</h2>
<div class="summary-grid">
<div class="summary-metric" style="border-top:3px solid var(--cyan)"><div class="metric-value" style="color:var(--cyan)">$objectCount</div><div class="metric-label">Objects Audited</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($aclCount -gt 0){'var(--red)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($aclCount -gt 0){'var(--red)'}else{'var(--green)'})">$aclCount</div><div class="metric-label">ACL Findings</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($gpoIssueCount -gt 0){'var(--yellow)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($gpoIssueCount -gt 0){'var(--yellow)'}else{'var(--green)'})">$gpoIssueCount</div><div class="metric-label">Tier 0 GPO Issues</div></div>
<div class="summary-metric" style="border-top:3px solid $krbtgtColor"><div class="metric-value" style="color:$krbtgtColor">$krbtgtAge</div><div class="metric-label">krbtgt Age (days)</div></div>
<div class="summary-metric" style="border-top:3px solid $(if($svcCrit -gt 0){'var(--red)'}elseif($svcHigh -gt 0){'var(--yellow)'}else{'var(--green)'})"><div class="metric-value" style="color:$(if($svcCrit -gt 0){'var(--red)'}elseif($svcHigh -gt 0){'var(--yellow)'}else{'var(--green)'})">$svcCrit</div><div class="metric-label">Critical Svc Accounts</div></div>
<div class="summary-metric" style="border-top:3px solid var(--yellow)"><div class="metric-value" style="color:var(--yellow)">$warningCount</div><div class="metric-label">Warnings</div></div>
<div class="summary-metric" style="border-top:3px solid $errColor"><div class="metric-value" style="color:$errColor">$errCount</div><div class="metric-label">Errors</div></div>
</div>
<div class="advisory"><strong>Assessment model:</strong> this phase now consumes the exact Phase 1 OU state, limits GPO review to the Tier 0 OU scope, includes Schema and System in the ACL audit scope, and reviews SPN accounts together with sMSAs and gMSAs.</div></div>

<div id="scope"><h2 class="section-header"><span class="section-icon">&#x1F3AF;</span> Audit Scope</h2>
<div class="card"><p class="note">Phase 1 state: $(HtmlEncode $Results.Phase1StatePath) | Tier 0 OU: $(HtmlEncode $Results.Tier0OUDN)</p>
<table><thead><tr><th>Object</th><th>Category</th><th>Path</th><th>Notes</th></tr></thead><tbody>$scopeRows</tbody></table></div></div>

<div id="acl"><h2 class="section-header"><span class="section-icon">&#x1F50D;</span> ACL Audit</h2>
$(if($aclCount -gt 0){"<div class='card'><table><thead><tr><th>Object</th><th>Category</th><th>Identity</th><th>Rights</th><th>Inherited</th><th>Severity</th></tr></thead><tbody>$aclRows</tbody></table></div>"}else{"<p class='note'>No dangerous non-standard ACEs found on the audited Tier 0 objects.</p>"})
</div>

<div id="gposcope"><h2 class="section-header"><span class="section-icon">&#x1F517;</span> Tier 0-Linked GPOs</h2>
$(if($gpoAuditCount -gt 0){"<div class='card'><p class='note'>Only GPOs directly linked to the exact Tier 0 OU exported by Phase 1 are audited here.</p><table><thead><tr><th>GPO Name</th><th>ID</th><th>Link Enabled</th><th>Enforced</th><th>Link Order</th></tr></thead><tbody>$gpoScopeRows</tbody></table></div>"}else{"<p class='note'>No Tier 0-linked GPOs were found on the exact Tier 0 OU.</p>"})
</div>

<div id="gpofindings"><h2 class="section-header"><span class="section-icon">&#x1F4C4;</span> GPO Findings</h2>
$(if($Results.GPOFindings.Count -gt 0){"<div class='card'><p class='note'>Owner findings are always listed. Permission findings appear only when a non-standard principal can edit or modify security on a Tier 0-linked GPO.</p><table><thead><tr><th>GPO Name</th><th>Finding Type</th><th>Principal</th><th>Permission</th><th>Status</th><th>Details</th></tr></thead><tbody>$gpoRows</tbody></table></div>"}else{"<p class='note'>No Tier 0 GPO findings were generated.</p>"})
</div>

<div id="krbtgt"><h2 class="section-header"><span class="section-icon">&#x1F511;</span> krbtgt Account</h2>
<div class="card">
<p>Password last set: <strong>$(if($Results.KrbtgtStatus){$Results.KrbtgtStatus.PasswordLastSet}else{'N/A'})</strong></p>
<p>Age: <strong style="color:$krbtgtColor">$krbtgtAge days</strong> | Severity: <strong style="color:$krbtgtColor">$krbtgtSev</strong></p>
<p>Guidance: $(HtmlEncode $(if($Results.KrbtgtStatus){$Results.KrbtgtStatus.Guidance}else{'No krbtgt status available.'}))</p>
$(if($Results.KrbtgtRotated){"<p style='color:var(--green);font-weight:600;'>The first krbtgt reset was completed. A second reset is still required after replication convergence.</p>"})
</div></div>

<div id="svcacct"><h2 class="section-header"><span class="section-icon">&#x2699;</span> Service Account Exposure</h2>
$(if($svcTotal -gt 0){"<div class='card'><p class='note'>Total: $svcTotal | Critical: $svcCrit | High: $svcHigh | Managed service accounts are included when available.</p><table><thead><tr><th>Account</th><th>Type</th><th>Enabled</th><th>Password</th><th>Privileged Groups</th><th>Tier 0 Scope</th><th>Risk</th></tr></thead><tbody>$svcRows</tbody></table></div>"}else{"<p class='note'>No service accounts were audited.</p>"})
</div>

$(if($warningCount -gt 0){@"
<div id="warnings"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Warnings</h2>
<div class="warning-alert"><h3>$warningCount warning(s)</h3><table><tbody>$warningRows</tbody></table></div></div>
"@})

$(if($errCount -gt 0){@"
<div id="errors"><h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert"><h3>$errCount error(s)</h3><table><tbody>$errRows</tbody></table></div></div>
"@})

<div id="nextsteps"><h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>
<div class="steps-grid">
<div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Remediate critical ACLs</strong> — Remove GenericAll, WriteDacl, WriteOwner, and non-standard write rights from the flagged Tier 0 objects.</div></div>
<div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Lock down Tier 0 GPOs</strong> — Ensure ownership is Domain Admins or Enterprise Admins and remove non-standard edit permissions from Tier 0-linked GPOs.</div></div>
<div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Plan krbtgt double rotation</strong> — If the password age exceeds 180 days, complete the second reset only after replication convergence and change control validation.</div></div>
<div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Reduce service account privilege</strong> — Remove service accounts from privileged groups and migrate eligible workloads to gMSAs.</div></div>
<div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Phase 8 — Monitoring &amp; Detection</strong> — Add monitoring for Tier 0 ACL drift, GPO changes, privileged account use, and tiering violations.</div></div>
</div></div>

<p class="note" style="text-align:center;margin-top:2rem;">Generated by MATI — Phase 7 — Implement Tier 0 Object Protection</p>
</div></body></html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

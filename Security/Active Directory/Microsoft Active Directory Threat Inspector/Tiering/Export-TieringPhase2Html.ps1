# Tiering\Export-TieringPhase2Html.ps1
# Generates a rich HTML report for Phase 2 — Tiered Admin Accounts.

function Export-TieringPhase2Html {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Results,

        [Parameter(Mandatory)]
        [string]$DomainDN,

        [Parameter(Mandatory)]
        [hashtable]$TieringConfig,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    function HtmlEncode([string]$s) {
        if (-not $s) { return '' }
        [System.Net.WebUtility]::HtmlEncode($s)
    }

    # ================================================================
    # Pre-compute values
    # ================================================================
    $created   = $Results.AccountsCreated.Count
    $existed   = $Results.AccountsExisted.Count
    $skipped   = $Results.AccountsSkipped.Count
    $totalAcc  = $created + $existed + $skipped
    $hardened  = ($Results.HardeningApplied | Where-Object Status -eq 'Applied').Count
    $errCount  = $Results.Errors.Count
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $source    = $Results.Source

    # Colors
    $createdColor  = if ($created -gt 0)  { 'var(--green)' } else { 'var(--accent)' }
    $existedColor  = if ($existed -gt 0)  { 'var(--cyan)'  } else { 'var(--accent)' }
    $skippedColor  = if ($skipped -gt 0)  { 'var(--yellow)' } else { 'var(--accent)' }
    $hardenedColor = if ($hardened -gt 0) { 'var(--green)' } else { 'var(--accent)' }
    $errColor      = if ($errCount -gt 0) { 'var(--red)'   } else { 'var(--green)' }

    # ================================================================
    # Tier breakdown
    # ================================================================
    $allAccounts = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $Results.AccountsCreated) { $allAccounts.Add($a) }
    foreach ($a in $Results.AccountsExisted) { $allAccounts.Add($a) }

    $t0Total = @($allAccounts | Where-Object Tier -eq 'T0').Count
    $t1Total = @($allAccounts | Where-Object Tier -eq 'T1').Count
    $t2Total = @($allAccounts | Where-Object Tier -eq 'T2').Count
    $tierMax = [math]::Max(1, [math]::Max($t0Total, [math]::Max($t1Total, $t2Total)))

    # ================================================================
    # Account table rows
    # ================================================================
    $acctRows = ''
    foreach ($a in $Results.AccountsCreated) {
        $tierBadge = switch ($a.Tier) {
            'T0' { "<span class='tier-badge t0'>T0</span>" }
            'T1' { "<span class='tier-badge t1'>T1</span>" }
            'T2' { "<span class='tier-badge t2'>T2</span>" }
        }
        $acctRows += "<tr><td>$(HtmlEncode $a.SamAccountName)</td><td>$(HtmlEncode $a.FirstName) $(HtmlEncode $a.LastName)</td><td>$tierBadge</td><td>$(HtmlEncode $a.Source)</td><td class='mono'>$(HtmlEncode $a.TargetOU)</td><td><span class='badge pass'>Created</span></td></tr>`n"
    }
    foreach ($a in $Results.AccountsExisted) {
        $tierBadge = switch ($a.Tier) {
            'T0' { "<span class='tier-badge t0'>T0</span>" }
            'T1' { "<span class='tier-badge t1'>T1</span>" }
            'T2' { "<span class='tier-badge t2'>T2</span>" }
        }
        $acctRows += "<tr><td>$(HtmlEncode $a.SamAccountName)</td><td>$(HtmlEncode $a.FirstName) $(HtmlEncode $a.LastName)</td><td>$tierBadge</td><td>$(HtmlEncode $a.Source)</td><td class='mono'>$(HtmlEncode $a.TargetOU)</td><td><span class='badge info'>Already Existed</span></td></tr>`n"
    }
    foreach ($a in $Results.AccountsSkipped) {
        $acctRows += "<tr><td>$(HtmlEncode $a.SamAccountName)</td><td>—</td><td>$(if($a.Tier){"<span class='tier-badge t$(($a.Tier -replace 'T',''))'>$($a.Tier)</span>"}else{'—'})</td><td>—</td><td>—</td><td><span class='badge warn'>Skipped</span></td></tr>`n"
    }

    # ================================================================
    # Hardening table rows
    # ================================================================
    $hardenRows = ''
    foreach ($h in $Results.HardeningApplied) {
        $statusBadge = switch ($h.Status) {
            'Applied'         { "<span class='badge pass'>Applied</span>" }
            'Already Applied' { "<span class='badge info'>Already Applied</span>" }
            'Failed'          { "<span class='badge fail'>Failed</span>" }
        }
        $hardenRows += "<tr><td>$(HtmlEncode $h.SamAccountName)</td><td>$(HtmlEncode $h.Setting)</td><td>$statusBadge</td></tr>`n"
    }

    # ================================================================
    # Group membership rows
    # ================================================================
    $grpRows = ''
    foreach ($g in $Results.GroupMembershipsAdded) {
        $parts = $g -split ' -> '
        $grpRows += "<tr><td>$(HtmlEncode $parts[0])</td><td>&#x27A1;</td><td>$(HtmlEncode $parts[1])</td><td><span class='badge pass'>Added</span></td></tr>`n"
    }

    # ================================================================
    # Error rows
    # ================================================================
    $errRows = ''
    foreach ($e in $Results.Errors) {
        $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n"
    }

    # ================================================================
    # Mapped accounts (full list for reference)
    # ================================================================
    $mappedRows = ''
    foreach ($m in $Results.AccountsMapped) {
        $actionBadge = switch ($m.Action) {
            'Create' { "<span class='badge pass'>Create</span>" }
            'Skip'   { "<span class='badge warn'>Skip</span>" }
            default  { "<span class='badge info'>$($m.Action)</span>" }
        }
        $mappedRows += "<tr><td>$(HtmlEncode $m.Source)</td><td>$(HtmlEncode $m.CurrentAccount)</td><td>$(HtmlEncode $m.NewSamAccountName)</td><td>$(HtmlEncode $m.Tier)</td><td>$actionBadge</td></tr>`n"
    }

    # ================================================================
    # Compose HTML
    # ================================================================
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MATI — Phase 2 Deployment Report</title>
<style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --yellow: #d29922; --cyan: #39c5cf; --t0: #f85149; --t1: #d29922; --t2: #58a6ff; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    .subtitle { color: #8b949e; font-size: 0.9rem; margin-bottom: 2rem; }
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #21262d; color: var(--accent); padding: 10px 12px; text-align: left; font-weight: 600; position: sticky; top: 0; }
    td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
    tr:hover { background: #1c2128; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
    .badge.pass { background: #0d2818; color: var(--green); }
    .badge.warn { background: #2d2000; color: var(--yellow); }
    .badge.fail { background: #2d0000; color: var(--red); }
    .badge.info { background: #0a2540; color: var(--cyan); }
    .mono { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.8rem; }
    .collapsible { cursor: pointer; user-select: none; }
    .collapsible::before { content: '\25BC '; font-size: 0.7rem; }
    .collapsible.collapsed::before { content: '\25B6 '; }
    .collapsible-content { overflow: hidden; }
    .collapsible-content.hidden { display: none; }
    .section-nav { position: sticky; top: 0; background: var(--bg); padding: 0.5rem 0; z-index: 100; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
    .section-nav a { color: var(--accent); text-decoration: none; margin-right: 1.5rem; font-size: 0.85rem; }
    .section-nav a:hover { text-decoration: underline; }

    /* Summary dashboard */
    .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    .summary-metric { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem 1rem; text-align: center; position: relative; overflow: hidden; }
    .summary-metric .metric-icon { font-size: 1.5rem; margin-bottom: 0.2rem; }
    .summary-metric .metric-value { font-size: 2.2rem; font-weight: 700; line-height: 1.1; }
    .summary-metric .metric-label { color: #8b949e; font-size: 0.78rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.5px; }

    /* Tier badges */
    .tier-badge { padding: 2px 10px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.5px; }
    .tier-badge.t0 { background: rgba(248,81,73,0.15); color: var(--t0); }
    .tier-badge.t1 { background: rgba(210,153,34,0.15); color: var(--t1); }
    .tier-badge.t2 { background: rgba(88,166,255,0.15); color: var(--t2); }

    /* Tier bar */
    .tier-bar-container { display: flex; gap: 1rem; margin-bottom: 1.5rem; }
    .tier-bar-item { flex: 1; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; position: relative; overflow: hidden; }
    .tier-bar-item .tb-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem; }
    .tier-bar-item .tb-label { font-weight: 600; font-size: 0.9rem; }
    .tier-bar-item .tb-count { font-size: 1.8rem; font-weight: 700; }
    .tier-bar-item .tb-bar { height: 6px; border-radius: 3px; background: rgba(255,255,255,0.05); overflow: hidden; }
    .tier-bar-item .tb-fill { height: 100%; border-radius: 3px; transition: width 0.5s ease; }
    .tier-bar-item.t0 { border-top: 3px solid var(--t0); }
    .tier-bar-item.t0 .tb-count { color: var(--t0); }
    .tier-bar-item.t0 .tb-fill { background: var(--t0); }
    .tier-bar-item.t1 { border-top: 3px solid var(--t1); }
    .tier-bar-item.t1 .tb-count { color: var(--t1); }
    .tier-bar-item.t1 .tb-fill { background: var(--t1); }
    .tier-bar-item.t2 { border-top: 3px solid var(--t2); }
    .tier-bar-item.t2 .tb-count { color: var(--t2); }
    .tier-bar-item.t2 .tb-fill { background: var(--t2); }

    /* Source banner */
    .source-banner { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 1rem; }
    .source-banner .sb-icon { font-size: 1.5rem; }
    .source-banner .sb-text { font-size: 0.9rem; }
    .source-banner .sb-text strong { color: var(--accent); }

    /* Hardening card */
    .harden-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
    .harden-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; position: relative; overflow: hidden; border-top: 3px solid var(--t0); }
    .harden-card .hc-header { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; }
    .harden-card .hc-icon { font-size: 1.2rem; }
    .harden-card .hc-title { font-weight: 600; font-size: 0.9rem; color: var(--t0); }
    .harden-card .hc-desc { font-size: 0.82rem; color: #8b949e; margin-bottom: 0.5rem; }
    .harden-card .hc-list { list-style: none; padding: 0; font-size: 0.82rem; }
    .harden-card .hc-list li { padding: 2px 0; display: flex; align-items: center; gap: 0.4rem; }
    .harden-card .hc-list li::before { content: '\2713'; color: var(--green); font-weight: 700; }

    /* Steps */
    .steps-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
    .step-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; display: flex; gap: 1rem; align-items: flex-start; }
    .step-number { background: var(--accent); color: var(--bg); width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; flex-shrink: 0; }
    .step-text { font-size: 0.85rem; color: var(--text); line-height: 1.5; }
    .step-text strong { color: var(--accent); }

    /* Error alert */
    .error-alert { background: #2d0000; border: 1px solid var(--red); border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
    .error-alert h3 { color: var(--red); margin: 0 0 0.5rem 0; }

    .section-header { display: flex; align-items: center; gap: 0.6rem; }
    .section-icon { font-size: 1.3rem; }
    .note { color: #8b949e; font-style: italic; font-size: 0.85rem; margin: 0.5rem 0; }

    @media (max-width: 1200px) { .summary-grid { grid-template-columns: repeat(3, 1fr); } .tier-bar-container { flex-direction: column; } .harden-grid { grid-template-columns: 1fr; } }
    @media (max-width: 768px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
    @media print { body { background: #fff; color: #000; } .card { border-color: #ddd; } th { background: #f0f0f0; color: #333; } }
</style>
</head>
<body>
<div class="container">

<h1>MATI — Phase 2 Deployment Report</h1>
<p class="subtitle">Tiered Admin Accounts | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>

<nav class="section-nav">
    <a href="#summary">Summary</a>
    <a href="#source">Source</a>
    <a href="#tiers">Tier Breakdown</a>
    <a href="#accounts">Accounts</a>
    <a href="#hardening">Hardening</a>
    <a href="#groups">Group Memberships</a>
    $(if ($errCount -gt 0) { '<a href="#errors" style="color:var(--red);">Errors</a>' })
    <a href="#mapping">Full Mapping</a>
    <a href="#nextsteps">Next Steps</a>
</nav>

<!-- ================================================================ -->
<!-- SUMMARY DASHBOARD -->
<!-- ================================================================ -->
<div id="summary">
<h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Deployment Summary</h2>

<div class="summary-grid">
    <div class="summary-metric" style="border-top: 3px solid $createdColor;">
        <div class="metric-icon">&#x1F464;</div>
        <div class="metric-value" style="color:$createdColor;">$created</div>
        <div class="metric-label">Accounts Created</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $existedColor;">
        <div class="metric-icon">&#x1F504;</div>
        <div class="metric-value" style="color:$existedColor;">$existed</div>
        <div class="metric-label">Already Existed</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $skippedColor;">
        <div class="metric-icon">&#x23ED;</div>
        <div class="metric-value" style="color:$skippedColor;">$skipped</div>
        <div class="metric-label">Skipped</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $hardenedColor;">
        <div class="metric-icon">&#x1F6E1;</div>
        <div class="metric-value" style="color:$hardenedColor;">$hardened</div>
        <div class="metric-label">Hardening Applied</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $errColor;">
        <div class="metric-icon">$(if($errCount -gt 0){'&#x274C;'}else{'&#x2705;'})</div>
        <div class="metric-value" style="color:$errColor;">$errCount</div>
        <div class="metric-label">Errors</div>
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- SOURCE INFO -->
<!-- ================================================================ -->
<div id="source">
<div class="source-banner">
    <div class="sb-icon">&#x1F50D;</div>
    <div class="sb-text">
        <strong>Account Source:</strong> $(HtmlEncode $source)<br>
        <span style="color:#8b949e;">Base DN: <code style="color:var(--cyan);">$(HtmlEncode $Results.BaseDN)</code></span>
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- TIER BREAKDOWN -->
<!-- ================================================================ -->
<div id="tiers">
<h2 class="section-header"><span class="section-icon">&#x1F3AF;</span> Tier Breakdown</h2>

<div class="tier-bar-container">
    <div class="tier-bar-item t0">
        <div class="tb-header"><span class="tb-label">&#x1F534; Tier 0</span></div>
        <div class="tb-count">$t0Total</div>
        <div class="tb-bar"><div class="tb-fill" style="width: $([math]::Round($t0Total / $tierMax * 100))%;"></div></div>
    </div>
    <div class="tier-bar-item t1">
        <div class="tb-header"><span class="tb-label">&#x1F7E0; Tier 1</span></div>
        <div class="tb-count">$t1Total</div>
        <div class="tb-bar"><div class="tb-fill" style="width: $([math]::Round($t1Total / $tierMax * 100))%;"></div></div>
    </div>
    <div class="tier-bar-item t2">
        <div class="tb-header"><span class="tb-label">&#x1F535; Tier 2</span></div>
        <div class="tb-count">$t2Total</div>
        <div class="tb-bar"><div class="tb-fill" style="width: $([math]::Round($t2Total / $tierMax * 100))%;"></div></div>
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- ACCOUNTS TABLE -->
<!-- ================================================================ -->
<div id="accounts">
<h2 class="section-header"><span class="section-icon">&#x1F465;</span> Admin Accounts</h2>

<div class="card">
    <table>
        <thead>
            <tr>
                <th>SamAccountName</th>
                <th>Full Name</th>
                <th>Tier</th>
                <th>Source</th>
                <th>Target OU</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            $acctRows
        </tbody>
    </table>
</div>
</div>

<!-- ================================================================ -->
<!-- T0 HARDENING -->
<!-- ================================================================ -->
<div id="hardening">
<h2 class="section-header"><span class="section-icon">&#x1F6E1;</span> Tier 0 Hardening</h2>

$(if ($Results.HardeningApplied.Count -gt 0) {
@"
<div class="harden-grid">
    <div class="harden-card">
        <div class="hc-header"><span class="hc-icon">&#x1F512;</span><span class="hc-title">Protected Users Group</span></div>
        <div class="hc-desc">Disables NTLM, enforces Kerberos, no delegation, no credential caching, 4-hour TGT lifetime.</div>
        <ul class="hc-list">
            $(($Results.HardeningApplied | Where-Object Setting -eq 'Protected Users' | ForEach-Object { "<li>$(HtmlEncode $_.SamAccountName) — $($_.Status)</li>" }) -join "`n            ")
        </ul>
    </div>
    <div class="harden-card">
        <div class="hc-header"><span class="hc-icon">&#x1F6AB;</span><span class="hc-title">AccountNotDelegated</span></div>
        <div class="hc-desc">Prevents the account's Kerberos tickets from being forwarded (delegated) to other services.</div>
        <ul class="hc-list">
            $(($Results.HardeningApplied | Where-Object Setting -eq 'AccountNotDelegated' | ForEach-Object { "<li>$(HtmlEncode $_.SamAccountName) — $($_.Status)</li>" }) -join "`n            ")
        </ul>
    </div>
</div>
"@
} else {
    '<p class="note">No Tier 0 accounts were processed — hardening not applicable.</p>'
})
</div>

<!-- ================================================================ -->
<!-- GROUP MEMBERSHIPS -->
<!-- ================================================================ -->
<div id="groups">
<h2 class="section-header"><span class="section-icon">&#x1F517;</span> Group Memberships</h2>

$(if ($Results.GroupMembershipsAdded.Count -gt 0) {
@"
<div class="card">
    <table>
        <thead>
            <tr><th>Account</th><th></th><th>Group</th><th>Status</th></tr>
        </thead>
        <tbody>
            $grpRows
        </tbody>
    </table>
</div>
"@
} else {
    '<p class="note">No group membership changes were made.</p>'
})
</div>

<!-- ================================================================ -->
<!-- ERRORS -->
<!-- ================================================================ -->
$(if ($errCount -gt 0) {
@"
<div id="errors">
<h2 class="section-header"><span class="section-icon">&#x26A0;</span> Errors</h2>
<div class="error-alert">
    <h3>$errCount error(s) encountered</h3>
    <table>
        <tbody>
            $errRows
        </tbody>
    </table>
</div>
</div>
"@
})

<!-- ================================================================ -->
<!-- FULL MAPPING TABLE (collapsible) -->
<!-- ================================================================ -->
<div id="mapping">
<h2 class="section-header collapsible" onclick="this.classList.toggle('collapsed');this.nextElementSibling.classList.toggle('hidden');"><span class="section-icon">&#x1F5C2;</span> Full Mapping Table</h2>
<div class="collapsible-content">
<div class="card">
    <p class="note">Complete mapping of all accounts that were evaluated, including skipped entries.</p>
    <table>
        <thead>
            <tr><th>Source</th><th>Current Account</th><th>New Account Name</th><th>Tier</th><th>Action</th></tr>
        </thead>
        <tbody>
            $mappedRows
        </tbody>
    </table>
</div>
</div>
</div>

<!-- ================================================================ -->
<!-- NEXT STEPS -->
<!-- ================================================================ -->
<div id="nextsteps">
<h2 class="section-header"><span class="section-icon">&#x1F680;</span> Next Steps</h2>

<div class="steps-grid">
    <div class="step-card">
        <div class="step-number">1</div>
        <div class="step-text"><strong>Distribute credentials</strong> — Securely share temporary passwords with each admin. Ensure they change at first logon.</div>
    </div>
    <div class="step-card">
        <div class="step-number">2</div>
        <div class="step-text"><strong>Delete the password CSV</strong> — Once credentials have been distributed, securely delete the temporary password file.</div>
    </div>
    <div class="step-card">
        <div class="step-number">3</div>
        <div class="step-text"><strong>Verify account placement</strong> — Confirm all accounts are in the correct tiered OUs (Tier 0/Accounts, Tier 1/Accounts, etc.).</div>
    </div>
    <div class="step-card">
        <div class="step-number">4</div>
        <div class="step-text"><strong>Test logon</strong> — Have each admin test authentication with their new tiered account on appropriate-tier machines.</div>
    </div>
    <div class="step-card">
        <div class="step-number">5</div>
        <div class="step-text"><strong>Phase 3 — Deny Logon GPOs</strong> — Create and link the six deny-logon GPOs to enforce tier boundaries. Without this, tiered accounts are cosmetic only.</div>
    </div>
    <div class="step-card">
        <div class="step-number">6</div>
        <div class="step-text"><strong>Store secrets properly</strong> — Move all credentials into tier-separated vaults (KeePass per tier, or enterprise PAM solution).</div>
    </div>
</div>
</div>

<p class="note" style="text-align:center; margin-top: 2rem;">Generated by MATI — Microsoft Active Directory Threat Inspector | Phase 2 — Tiered Admin Accounts</p>

</div>

<script>
document.querySelectorAll('.collapsible').forEach(el => {
    el.addEventListener('click', () => {
        el.classList.toggle('collapsed');
        const content = el.nextElementSibling;
        if (content) content.classList.toggle('hidden');
    });
});
</script>

</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "    HTML : $OutputPath" -ForegroundColor Cyan
}

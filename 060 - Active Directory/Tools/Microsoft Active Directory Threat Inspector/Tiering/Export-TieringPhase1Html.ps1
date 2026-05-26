# Tiering\Export-TieringPhase1Html.ps1
# Generates a rich HTML report for Phase 1 — Create Recommended OU Structure & Group Model.

function Export-TieringPhase1Html {
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
    $ouCreated  = $Results.OUsCreated.Count
    $ouExisted  = $Results.OUsExisted.Count
    $ouTotal    = $ouCreated + $ouExisted
    $grpCreated = $Results.GroupsCreated.Count
    $grpExisted = $Results.GroupsExisted.Count
    $grpTotal   = $grpCreated + $grpExisted
    $nestDone   = $Results.NestingDone.Count
    $nestSkip   = $Results.NestingSkipped.Count
    $nestTotal  = $nestDone + $nestSkip
    $errCount   = $Results.Errors.Count
    $timestamp  = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Colors for stat cards
    $ouColor   = if ($ouCreated -gt 0) { 'var(--green)' } else { 'var(--accent)' }
    $grpColor  = if ($grpCreated -gt 0) { 'var(--green)' } else { 'var(--accent)' }
    $nestColor = if ($nestDone -gt 0) { 'var(--green)' } else { 'var(--accent)' }
    $errColor  = if ($errCount -gt 0) { 'var(--red)' } else { 'var(--green)' }

    # OU table rows
    $ouRows = ''
    foreach ($dn in $Results.OUsCreated) {
        $name = ($dn -split ',')[0] -replace '^OU='
        $ouRows += "<tr><td>$(HtmlEncode $name)</td><td class='mono'>$(HtmlEncode $dn)</td><td><span class='badge pass'>Created</span></td></tr>`n"
    }
    foreach ($dn in $Results.OUsExisted) {
        $name = ($dn -split ',')[0] -replace '^OU='
        $ouRows += "<tr><td>$(HtmlEncode $name)</td><td class='mono'>$(HtmlEncode $dn)</td><td><span class='badge info'>Already Existed</span></td></tr>`n"
    }

    # Group table rows
    $grpRows = ''
    foreach ($g in $Results.GroupsCreated) {
        $grpRows += "<tr><td>$(HtmlEncode $g)</td><td><span class='badge pass'>Created</span></td></tr>`n"
    }
    foreach ($g in $Results.GroupsExisted) {
        $grpRows += "<tr><td>$(HtmlEncode $g)</td><td><span class='badge info'>Already Existed</span></td></tr>`n"
    }

    # Nesting table rows
    $nestRows = ''
    foreach ($n in $Results.NestingDone) {
        $parts = $n -split ' -> '
        $nestRows += "<tr><td>$(HtmlEncode $parts[0])</td><td>&#x27A1;</td><td>$(HtmlEncode $parts[1])</td><td><span class='badge pass'>Configured</span></td></tr>`n"
    }
    foreach ($n in $Results.NestingSkipped) {
        $parts = $n -split ' -> '
        $nestRows += "<tr><td>$(HtmlEncode $parts[0])</td><td>&#x27A1;</td><td>$(HtmlEncode $parts[1])</td><td><span class='badge info'>Already In Place</span></td></tr>`n"
    }

    # Redirect rows
    $redirRows = ''
    $redircmpStatus = if ($Results.RedircmpDone) { '<span class="badge pass">Redirected</span>' } else { '<span class="badge warn">Skipped</span>' }
    $redircmpTarget = if ($Results.RedircmpTarget) { HtmlEncode $Results.RedircmpTarget } else { '—' }
    $redirRows += "<tr><td>Default Computers Container</td><td>redircmp</td><td>$redircmpTarget</td><td>$redircmpStatus</td></tr>`n"

    $redirusrStatus = if ($Results.RedirusrDone) { '<span class="badge pass">Redirected</span>' } else { '<span class="badge warn">Skipped</span>' }
    $redirusrTarget = if ($Results.RedirusrTarget) { HtmlEncode $Results.RedirusrTarget } else { '—' }
    $redirRows += "<tr><td>Default Users Container</td><td>redirusr</td><td>$redirusrTarget</td><td>$redirusrStatus</td></tr>`n"

    # Error rows
    $errRows = ''
    foreach ($e in $Results.Errors) {
        $errRows += "<tr><td>$(HtmlEncode $e)</td></tr>`n"
    }

    # OU tree visualization — build from created + existed lists
    $ouCfg   = $TieringConfig.OUStructure
    $baseDN  = $Results.BaseDN
    $allOUs  = [System.Collections.Generic.List[string]]::new()
    $allOUs.AddRange($Results.OUsCreated)
    $allOUs.AddRange($Results.OUsExisted)
    $createdSet = [System.Collections.Generic.HashSet[string]]::new($Results.OUsCreated, [System.StringComparer]::OrdinalIgnoreCase)

    # Build tree HTML
    $treeHtml = ''

    # Container OU if applicable
    if ($Results.ContainerOU) {
        $containerDN = if ($Results.ContainerOUDN) { $Results.ContainerOUDN } else { "OU=$($Results.ContainerOU),$DomainDN" }
        $cssBadge = if ($createdSet.Contains($containerDN)) { 'pass' } else { 'info' }
        $treeHtml += "<div class='ou-node' style='--depth:0;'><span class='ou-icon'>&#x1F4C1;</span><span class='ou-name'>$($Results.ContainerOU)</span> <span class='ou-badge $cssBadge'>$(if($cssBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
    }

    $depth0 = if ($Results.ContainerOU) { 1 } else { 0 }

    # Tier OUs
    $tierDefs = @(
        @{ Key = 'Tier0'; Icon = '&#x1F534;'; Color = '#e74c3c' }
        @{ Key = 'Tier1'; Icon = '&#x1F7E0;'; Color = '#f39c12' }
        @{ Key = 'Tier2'; Icon = '&#x1F535;'; Color = '#3498db' }
    )
    foreach ($td in $tierDefs) {
        $tierName = $ouCfg.($td.Key)
        $tierDN = "OU=$tierName,$baseDN"
        $tierBadge = if ($createdSet.Contains($tierDN)) { 'pass' } else { 'info' }
        $treeHtml += "<div class='ou-node' style='--depth:$depth0;'><span class='ou-icon'>$($td.Icon)</span><span class='ou-name' style='color:$($td.Color);'>$tierName</span> <span class='ou-badge $tierBadge'>$(if($tierBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
        $subOUs = $ouCfg.SubOUs.($td.Key)
        foreach ($sub in $subOUs) {
            $subDN = "OU=$sub,$tierDN"
            $subBadge = if ($createdSet.Contains($subDN)) { 'pass' } else { 'info' }
            $treeHtml += "<div class='ou-node' style='--depth:$($depth0 + 1);'><span class='ou-icon'>&#x1F4C2;</span><span class='ou-name'>$sub</span> <span class='ou-badge $subBadge'>$(if($subBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
        }
    }

    # Quarantine
    $qName = $ouCfg.Quarantine
    $qDN   = "OU=$qName,$baseDN"
    $qBadge = if ($createdSet.Contains($qDN)) { 'pass' } else { 'info' }
    $treeHtml += "<div class='ou-node' style='--depth:$depth0;'><span class='ou-icon'>&#x26A0;</span><span class='ou-name' style='color:var(--yellow);'>$qName</span> <span class='ou-badge $qBadge'>$(if($qBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
    foreach ($sub in $ouCfg.QuarantineSubOUs) {
        $subDN = "OU=$sub,$qDN"
        $subBadge = if ($createdSet.Contains($subDN)) { 'pass' } else { 'info' }
        $treeHtml += "<div class='ou-node' style='--depth:$($depth0 + 1);'><span class='ou-icon'>&#x1F4C2;</span><span class='ou-name'>$sub</span> <span class='ou-badge $subBadge'>$(if($subBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
    }

    # Disabled
    $dName = $ouCfg.Disabled
    $dDN   = "OU=$dName,$baseDN"
    $dBadge = if ($createdSet.Contains($dDN)) { 'pass' } else { 'info' }
    $treeHtml += "<div class='ou-node' style='--depth:$depth0;'><span class='ou-icon'>&#x1F6AB;</span><span class='ou-name'>$dName</span> <span class='ou-badge $dBadge'>$(if($dBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
    foreach ($sub in $ouCfg.DisabledSubOUs) {
        $subDN = "OU=$sub,$dDN"
        $subBadge = if ($createdSet.Contains($subDN)) { 'pass' } else { 'info' }
        $treeHtml += "<div class='ou-node' style='--depth:$($depth0 + 1);'><span class='ou-icon'>&#x1F4C2;</span><span class='ou-name'>$sub</span> <span class='ou-badge $subBadge'>$(if($subBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"
    }

    # Standard Users
    $suName = $ouCfg.StandardUsers
    $suDN   = "OU=$suName,$baseDN"
    $suBadge = if ($createdSet.Contains($suDN)) { 'pass' } else { 'info' }
    $treeHtml += "<div class='ou-node' style='--depth:$depth0;'><span class='ou-icon'>&#x1F464;</span><span class='ou-name'>$suName</span> <span class='ou-badge $suBadge'>$(if($suBadge -eq 'pass'){'NEW'}else{'EXISTS'})</span></div>`n"

    # ================================================================
    # Compose HTML
    # ================================================================
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MATI — Phase 1 — Create Recommended OU Structure & Group Model</title>
<style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9; --accent: #58a6ff; --green: #3fb950; --red: #f85149; --yellow: #d29922; --cyan: #39c5cf; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }
    .container { max-width: 1400px; margin: 0 auto; }
    h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
    h2 { color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    h3 { color: var(--text); font-size: 1.1rem; margin: 1.5rem 0 0.5rem 0; }
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
    .note { color: #8b949e; font-style: italic; font-size: 0.85rem; margin: 0.5rem 0; }
    .section-nav { position: sticky; top: 0; background: var(--bg); padding: 0.5rem 0; z-index: 100; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem; }
    .section-nav a { color: var(--accent); text-decoration: none; margin-right: 1.5rem; font-size: 0.85rem; }
    .section-nav a:hover { text-decoration: underline; }

    /* Summary dashboard */
    .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    .summary-metric { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem 1rem; text-align: center; position: relative; overflow: hidden; }
    .summary-metric .metric-icon { font-size: 1.5rem; margin-bottom: 0.2rem; }
    .summary-metric .metric-value { font-size: 2.2rem; font-weight: 700; line-height: 1.1; }
    .summary-metric .metric-label { color: #8b949e; font-size: 0.78rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.5px; }

    /* Placement banner */
    .placement-banner { background: var(--card); border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 1rem; }
    .placement-banner .pb-icon { font-size: 1.5rem; }
    .placement-banner .pb-text { font-size: 0.9rem; }
    .placement-banner .pb-text strong { color: var(--accent); }
    .placement-banner .pb-dn { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.82rem; color: var(--cyan); margin-top: 0.2rem; }

    /* OU Tree */
    .ou-tree { padding: 0.5rem 0; font-size: 0.88rem; font-family: 'Cascadia Code', 'Consolas', monospace; }
    .ou-node { display: flex; align-items: center; gap: 0.4rem; padding: 3px 0 3px calc(var(--depth) * 1.6rem + 0.5rem); border-left: 2px solid transparent; transition: background 0.15s; position: relative; }
    .ou-node:hover { background: rgba(88,166,255,0.06); border-left-color: var(--accent); }
    .ou-node::before { content: ''; position: absolute; left: calc(var(--depth) * 1.6rem - 0.6rem); top: 0; bottom: 50%; width: 0.8rem; border-left: 1px solid #30363d; border-bottom: 1px solid #30363d; }
    .ou-node[style*="--depth:0"]::before { display: none; }
    .ou-icon { font-size: 1rem; flex-shrink: 0; }
    .ou-name { color: var(--text); font-weight: 500; }
    .ou-badge { padding: 1px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; font-family: 'Segoe UI', sans-serif; letter-spacing: 0.5px; vertical-align: middle; }
    .ou-badge.pass { background: #0d2818; color: var(--green); }
    .ou-badge.info { background: #0a2540; color: var(--cyan); }

    /* Redirect status cards */
    .redir-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem; }
    .redir-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; position: relative; overflow: hidden; }
    .redir-card.done { border-top: 3px solid var(--green); }
    .redir-card.skipped { border-top: 3px solid var(--yellow); }
    .redir-card .rc-header { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.5rem; }
    .redir-card .rc-icon { font-size: 1.2rem; }
    .redir-card .rc-title { font-weight: 600; font-size: 0.9rem; }
    .redir-card .rc-target { font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 0.78rem; color: var(--cyan); margin-top: 0.3rem; word-break: break-all; }
    .redir-card .rc-status { margin-top: 0.3rem; }

    /* Section headers */
    .section-header { display: flex; align-items: center; gap: 0.6rem; }
    .section-header .section-icon { font-size: 1.3rem; }
    .section-intro { color: #8b949e; font-size: 0.85rem; margin: -0.5rem 0 1.5rem 0; }

    /* Steps */
    .steps-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
    .step-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; display: flex; gap: 1rem; align-items: flex-start; }
    .step-number { background: var(--accent); color: var(--bg); width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; flex-shrink: 0; }
    .step-text { font-size: 0.85rem; color: var(--text); line-height: 1.5; }
    .step-text strong { color: var(--accent); }

    /* Error alert */
    .error-alert { background: #2d0000; border: 1px solid var(--red); border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1.5rem; }
    .error-alert h3 { color: var(--red); margin: 0 0 0.5rem 0; }

    @media (max-width: 1200px) { .summary-grid { grid-template-columns: repeat(3, 1fr); } .redir-grid { grid-template-columns: 1fr; } }
    @media (max-width: 768px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } }
    @media print { body { background: #fff; color: #000; } .card { border-color: #ddd; } th { background: #f0f0f0; color: #333; } }
</style>
</head>
<body>
<div class="container">

<h1>MATI — Phase 1 — Create Recommended OU Structure & Group Model</h1>
<p class="subtitle">Create Recommended OU Structure &amp; Group Model | Domain: $(HtmlEncode $DomainDN) | Generated: $timestamp</p>

<nav class="section-nav">
    <a href="#summary">Summary</a>
    <a href="#placement">Placement</a>
    <a href="#ous">OU Structure</a>
    <a href="#groups">Security Groups</a>
    <a href="#nesting">Deny-Logon Nesting</a>
    <a href="#redirect">Container Redirect</a>
    $(if ($errCount -gt 0) { '<a href="#errors" style="color:var(--red);">Errors</a>' })
    <a href="#nextsteps">Next Steps</a>
</nav>

<!-- ================================================================ -->
<!-- SUMMARY DASHBOARD -->
<!-- ================================================================ -->
<div id="summary">
<h2 class="section-header"><span class="section-icon">&#x1F4CA;</span> Deployment Summary</h2>

<div class="summary-grid">
    <div class="summary-metric" style="border-top: 3px solid $ouColor;">
        <div class="metric-icon">&#x1F4C2;</div>
        <div class="metric-value" style="color:$ouColor;">$ouTotal</div>
        <div class="metric-label">OUs ($ouCreated new / $ouExisted existed)</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $grpColor;">
        <div class="metric-icon">&#x1F465;</div>
        <div class="metric-value" style="color:$grpColor;">$grpTotal</div>
        <div class="metric-label">Groups ($grpCreated new / $grpExisted existed)</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $nestColor;">
        <div class="metric-icon">&#x1F517;</div>
        <div class="metric-value" style="color:$nestColor;">$nestTotal</div>
        <div class="metric-label">Nesting ($nestDone new / $nestSkip existed)</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $(if($Results.RedircmpDone -or $Results.RedirusrDone){'var(--green)'}else{'var(--yellow)'});">
        <div class="metric-icon">&#x1F500;</div>
        <div class="metric-value" style="color:$(if($Results.RedircmpDone -or $Results.RedirusrDone){'var(--green)'}else{'var(--yellow)'});">$(([int]$Results.RedircmpDone + [int]$Results.RedirusrDone))/2</div>
        <div class="metric-label">Container Redirects</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $errColor;">
        <div class="metric-icon">$(if($errCount -gt 0){'&#x274C;'}else{'&#x2705;'})</div>
        <div class="metric-value" style="color:$errColor;">$errCount</div>
        <div class="metric-label">Errors</div>
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- PLACEMENT -->
<!-- ================================================================ -->
<div id="placement">
<h2 class="section-header"><span class="section-icon">&#x1F4CD;</span> OU Placement</h2>

<div class="placement-banner">
    <div class="pb-icon">&#x1F3E2;</div>
    <div>
        <div class="pb-text">Tiering structure placed: <strong>$(HtmlEncode $Results.Placement)</strong></div>
        <div class="pb-dn">Base DN: $(HtmlEncode $Results.BaseDN)</div>
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- OU STRUCTURE -->
<!-- ================================================================ -->
<div id="ous">
<h2 class="section-header"><span class="section-icon">&#x1F4C2;</span> OU Structure ($ouTotal OUs)</h2>
<p class="section-intro">Hierarchical view of the deployed tiering OU structure. <span class="ou-badge pass" style="display:inline;">NEW</span> = created, <span class="ou-badge info" style="display:inline;">EXISTS</span> = already existed.</p>

<div class="card">
<div class="ou-tree">
$treeHtml</div>
</div>

<div class="card">
<h3 class="collapsible" onclick="toggleSection(this)">OU Detail Table ($ouTotal)</h3>
<div class="collapsible-content">
<table>
    <thead><tr><th>Name</th><th>Distinguished Name</th><th>Status</th></tr></thead>
    <tbody>$ouRows</tbody>
</table>
</div>
</div>
</div>

<!-- ================================================================ -->
<!-- SECURITY GROUPS -->
<!-- ================================================================ -->
<div id="groups">
<h2 class="section-header"><span class="section-icon">&#x1F465;</span> Security Groups ($grpTotal)</h2>
<p class="section-intro">Tiered security groups for administration, service account isolation, and the deny-logon model that will be enforced later by Phase 3 GPOs.</p>

$(if ($grpTotal -gt 0) {
@"
<div class="card">
<h3 class="collapsible" onclick="toggleSection(this)">All Groups ($grpTotal)</h3>
<div class="collapsible-content">
<table>
    <thead><tr><th>Group Name</th><th>Status</th></tr></thead>
    <tbody>$grpRows</tbody>
</table>
</div>
</div>
"@
} else {
    '<div class="card"><p class="note" style="text-align:center; padding:1.5rem;">No groups were created or found — group creation was skipped.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- DENY-LOGON NESTING -->
<!-- ================================================================ -->
<div id="nesting">
<h2 class="section-header"><span class="section-icon">&#x1F517;</span> Deny-Logon Nesting ($nestTotal)</h2>
<p class="section-intro">Cross-tier deny-logon group membership. Tier X admin and service accounts are nested into deny-logon groups that block logon on Tier Y machines.</p>

$(if ($nestTotal -gt 0) {
@"
<div class="card">
<h3 class="collapsible" onclick="toggleSection(this)">Nesting Configuration ($nestTotal)</h3>
<div class="collapsible-content">
<table>
    <thead><tr><th>Member</th><th></th><th>Group</th><th>Status</th></tr></thead>
    <tbody>$nestRows</tbody>
</table>
</div>
</div>
"@
} else {
    '<div class="card"><p class="note" style="text-align:center; padding:1.5rem;">No nesting was configured — group creation was skipped.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- CONTAINER REDIRECT -->
<!-- ================================================================ -->
<div id="redirect">
<h2 class="section-header"><span class="section-icon">&#x1F500;</span> Default Container Redirection</h2>
<p class="section-intro">Redirecting default Computers and Users containers ensures new objects land in managed OUs with GPO support.</p>

<div class="redir-grid">
    <div class="redir-card $(if($Results.RedircmpDone){'done'}else{'skipped'})">
        <div class="rc-header">
            <span class="rc-icon">&#x1F5A5;</span>
            <span class="rc-title">Default Computers (redircmp)</span>
        </div>
        <div class="rc-status">$redircmpStatus</div>
        $(if($Results.RedircmpTarget){"<div class='rc-target'>$redircmpTarget</div>"})
    </div>
    <div class="redir-card $(if($Results.RedirusrDone){'done'}else{'skipped'})">
        <div class="rc-header">
            <span class="rc-icon">&#x1F464;</span>
            <span class="rc-title">Default Users (redirusr)</span>
        </div>
        <div class="rc-status">$redirusrStatus</div>
        $(if($Results.RedirusrTarget){"<div class='rc-target'>$redirusrTarget</div>"})
    </div>
</div>
</div>

<!-- ================================================================ -->
<!-- ERRORS -->
<!-- ================================================================ -->
$(if ($errCount -gt 0) {
@"
<div id="errors">
<h2 class="section-header"><span class="section-icon">&#x274C;</span> Errors ($errCount)</h2>
<div class="error-alert">
<h3>&#x26A0; The following errors occurred during deployment:</h3>
<table>
    <thead><tr><th>Error</th></tr></thead>
    <tbody>$errRows</tbody>
</table>
</div>
</div>
"@
})

<!-- ================================================================ -->
<!-- NEXT STEPS -->
<!-- ================================================================ -->
<div id="nextsteps">
<h2 class="section-header"><span class="section-icon">&#x1F680;</span> Recommended Next Steps</h2>
<p class="section-intro">Actions to take after Phase 1 deployment before proceeding through the next implementation phases.</p>
<div class="steps-grid">
    <div class="step-card"><div class="step-number">1</div><div class="step-text"><strong>Verify OU structure</strong> — Open Active Directory Users and Computers and confirm the OU hierarchy matches expectations.</div></div>
    <div class="step-card"><div class="step-number">2</div><div class="step-text"><strong>Validate group membership</strong> — Confirm deny-logon nesting is correct with <code>Get-ADGroupMember</code>.</div></div>
    <div class="step-card"><div class="step-number">3</div><div class="step-text"><strong>Run Phase 0 again</strong> — Re-run Discovery to see the updated OU tree with the new structure.</div></div>
    <div class="step-card"><div class="step-number">4</div><div class="step-text"><strong>Proceed to Phase 2</strong> — Create or align the tiered admin accounts that will populate the new OU and group model.</div></div>
    <div class="step-card"><div class="step-number">5</div><div class="step-text"><strong>Proceed to Phase 3</strong> — Create and link the deny-logon GPOs that enforce the cross-tier boundaries prepared in Phase 1.</div></div>
    <div class="step-card"><div class="step-number">6</div><div class="step-text"><strong>Proceed to Phase 4</strong> — Review and deploy Authentication Policies and Silos after the account and workstation/server model is stable.</div></div>
</div>
</div>

<p class="subtitle" style="margin-top:2rem; text-align:center;">Generated by MATI — Microsoft Active Directory Threat Inspector</p>

</div>

<script>
function toggleSection(el) {
    el.classList.toggle('collapsed');
    const content = el.nextElementSibling;
    content.classList.toggle('hidden');
}
</script>
</body>
</html>
"@

    $html | Set-Content -Path $OutputPath -Encoding UTF8 -Force
    Write-Host "    HTML : $OutputPath" -ForegroundColor Green
}

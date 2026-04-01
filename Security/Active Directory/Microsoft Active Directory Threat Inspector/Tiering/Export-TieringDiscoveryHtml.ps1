# Tiering\Export-TieringDiscoveryHtml.ps1
# Generates a rich HTML report for Phase 0 — Tiering Discovery.

function Export-TieringDiscoveryHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Discovery,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # ================================================================
    # Helper — HTML-encode
    # ================================================================
    function HtmlEncode([string]$s) {
        if (-not $s) { return '' }
        [System.Net.WebUtility]::HtmlEncode($s)
    }

    # ================================================================
    # Build HTML sections
    # ================================================================

    # Extract numeric values for stat cards
    $summary = Get-MATISummarySnapshot -Discovery $Discovery
    $totalComputers = $Discovery.ComputersByTier.Tier0.Count + $Discovery.ComputersByTier.Tier1.Count + $Discovery.ComputersByTier.Tier2.Count + $Discovery.ComputersByTier.Unclassified.Count
    $daCount = $summary.IdentityAccess.DomainAdmins.Count
    $eaCount = $summary.IdentityAccess.EnterpriseAdmins.Count
    $svcInDA = $summary.IdentityAccess.ServiceAccountsInDA.Count
    $gmsaCount = $summary.IdentityAccess.GMSA.Count
    $msaCount = $summary.IdentityAccess.MSA.Count
    $userCount = $summary.Environment.Users
    $groupCount = $summary.Environment.Groups
    $orphans = $summary.IdentityAccess.AdminCountOrphans.Count
    $trustCount = $summary.Trusts.TrustRelationships.Count
    $unsafeTrustCount = $summary.Trusts.UnsafeTrusts.Count
    $gpoCount = $summary.Infrastructure.GroupPolicies
    $ouCount = $summary.Infrastructure.OrganizationalUnits
    $reviewQueueCount = @($Discovery.ReviewQueue).Count
    $authPolicySummary = if ($Discovery.AuthenticationControls.Summary) { $Discovery.AuthenticationControls.Summary } else { [ordered]@{ PolicyCount = 0; EnforcedPolicies = 0; SiloCount = 0; EnforcedSilos = 0; AuditOnlySilos = 0; AssignedMembers = 0 } }
    $readinessStatus = if ($Discovery.Readiness.Status) { $Discovery.Readiness.Status } else { 'Unknown' }
    $readinessColor = switch ($readinessStatus) {
        'Ready' { 'var(--green)' }
        'ReadyWithWarnings' { 'var(--yellow)' }
        'Blocked' { 'var(--red)' }
        default { 'var(--accent)' }
    }
    $readinessBadgeClass = switch ($readinessStatus) {
        'Ready' { 'pass' }
        'ReadyWithWarnings' { 'warn' }
        'Blocked' { 'fail' }
        default { 'info' }
    }

    # Color logic
    $daColor = if ($summary.IdentityAccess.DomainAdmins.Dot -eq 'red') { 'var(--red)' } elseif ($summary.IdentityAccess.DomainAdmins.Dot -eq 'yellow') { 'var(--yellow)' } else { 'var(--green)' }
    $eaColor = if ($summary.IdentityAccess.EnterpriseAdmins.Dot -eq 'red') { 'var(--red)' } elseif ($summary.IdentityAccess.EnterpriseAdmins.Dot -eq 'yellow') { 'var(--yellow)' } else { 'var(--green)' }
    # --- Forest summary ---
    $forestInfo = $Discovery.Forest
    $domainRows = ''
    foreach ($d in $Discovery.Domains) {
        $pwdColor = if ([int]$d.MinPwdLength -lt 12) { 'var(--red)' } elseif ([int]$d.MinPwdLength -lt 14) { 'var(--yellow)' } else { 'var(--green)' }
        $lockColor = if ([int]$d.LockoutThreshold -eq 0) { 'var(--red)' } else { 'var(--green)' }
        $maqColor = if ([int]$d.MachineAccountQuota -gt 0) { 'var(--red)' } else { 'var(--green)' }
        $domainRows += "<tr><td>$(HtmlEncode $d.Name)</td><td>$(HtmlEncode $d.NetBIOSName)</td><td>$(HtmlEncode $d.DomainMode)</td>"
        $domainRows += "<td><span style='color:$pwdColor;font-weight:600;'>$($d.MinPwdLength)</span></td><td><span style='color:$lockColor;font-weight:600;'>$($d.LockoutThreshold)</span></td><td><span style='color:$maqColor;font-weight:600;'>$($d.MachineAccountQuota)</span></td></tr>`n"
    }

    # --- DCs ---
    $dcRows = ''
    foreach ($dc in $Discovery.DomainControllers) {
        $roles = if ($dc.OperationMasterRoles.Count -gt 0) { ($dc.OperationMasterRoles -join ', ') } else { '-' }
        $rodc = if ($dc.IsReadOnly) { '<span class="badge warn">RODC</span>' } else { 'RWDC' }
        $dcRows += "<tr><td>$(HtmlEncode $dc.Name)</td><td>$(HtmlEncode $dc.Domain)</td><td>$(HtmlEncode $dc.Site)</td>"
        $dcRows += "<td>$(HtmlEncode $dc.OperatingSystem)</td><td>$rodc</td><td>$(HtmlEncode $roles)</td></tr>`n"
    }

    $dcConnectivityRows = ''
    foreach ($dc in @($Discovery.DCConnectivity | Sort-Object Domain, Name)) {
        $statusClass = switch ($dc.Status) {
            'OK' { 'ok' }
            'Unreachable' { 'unreachable' }
            '' { 'warning' }
            $null { 'warning' }
            default { 'warning' }
        }
        $latency = if ($null -ne $dc.LatencyMs) { "$($dc.LatencyMs) ms" } else { '—' }
        $gc = if ($dc.IsGlobalCatalog) { 'Yes' } else { 'No' }
        $dcConnectivityRows += "<tr><td><strong>$(HtmlEncode $dc.Name)</strong></td><td>$(HtmlEncode $dc.HostName)</td><td>$(HtmlEncode $dc.Domain)</td><td>$(HtmlEncode $dc.IPv4Address)</td><td>$gc</td><td><span class='dc-status $statusClass'>$(HtmlEncode $dc.Status)</span></td><td>$latency</td></tr>`n"
    }

    # --- Computers by tier ---
    $tierSummary = @(
        @{ Tier = 'Tier 0'; Count = $Discovery.ComputersByTier.Tier0.Count; Color = '#e74c3c' }
        @{ Tier = 'Tier 1'; Count = $Discovery.ComputersByTier.Tier1.Count; Color = '#f39c12' }
        @{ Tier = 'Tier 2'; Count = $Discovery.ComputersByTier.Tier2.Count; Color = '#3498db' }
        @{ Tier = 'Unclassified'; Count = $Discovery.ComputersByTier.Unclassified.Count; Color = '#95a5a6' }
    )
    $totalComputers = ($tierSummary | Measure-Object -Property Count -Sum).Sum

    # Tier 0 detail table
    $t0Rows = ''
    foreach ($c in ($Discovery.ComputersByTier.Tier0 | Sort-Object { $_.Name })) {
        $enabled = if ($c.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $confidence = switch ($c.Confidence) { 'High' { 'pass' } 'Medium' { 'warn' } default { 'fail' } }
        $review = if ($c.ReviewRequired) { '<span class="badge warn">Review</span>' } else { '<span class="badge pass">No</span>' }
        $evidence = if ($c.Evidence.Count -gt 0) { $c.Evidence -join ' | ' } else { $c.Reason }
        $t0Rows += "<tr><td>$(HtmlEncode $c.Name)</td><td>$(HtmlEncode $c.Domain)</td><td>$(HtmlEncode $c.OperatingSystem)</td>"
        $t0Rows += "<td>$enabled</td><td><span class='badge $confidence'>$(HtmlEncode $c.Confidence)</span></td><td>$review</td><td>$(HtmlEncode $evidence)</td><td>$(HtmlEncode $c.OU)</td></tr>`n"
    }

    # Tier 1 detail table (limit to 100 for readability, count shown)
    $t1All = @($Discovery.ComputersByTier.Tier1 | Sort-Object { $_.Name })
    $t1Rows = ''
    $t1Display = if ($t1All.Count -gt 100) { $t1All | Select-Object -First 100 } else { $t1All }
    foreach ($c in $t1Display) {
        $enabled = if ($c.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $confidence = switch ($c.Confidence) { 'High' { 'pass' } 'Medium' { 'warn' } default { 'fail' } }
        $review = if ($c.ReviewRequired) { '<span class="badge warn">Review</span>' } else { '<span class="badge pass">No</span>' }
        $evidence = if ($c.Evidence.Count -gt 0) { $c.Evidence -join ' | ' } else { $c.Reason }
        $t1Rows += "<tr><td>$(HtmlEncode $c.Name)</td><td>$(HtmlEncode $c.Domain)</td><td>$(HtmlEncode $c.OperatingSystem)</td>"
        $t1Rows += "<td>$enabled</td><td><span class='badge $confidence'>$(HtmlEncode $c.Confidence)</span></td><td>$review</td><td>$(HtmlEncode $evidence)</td><td>$(HtmlEncode $c.OU)</td></tr>`n"
    }
    $t1Note = if ($t1All.Count -gt 100) { "<p class='note'>Showing first 100 of $($t1All.Count) Tier 1 computers. See JSON export for full list.</p>" } else { '' }

    # Tier 2 detail table (limit to 100)
    $t2All = @($Discovery.ComputersByTier.Tier2 | Sort-Object { $_.Name })
    $t2Rows = ''
    $t2Display = if ($t2All.Count -gt 100) { $t2All | Select-Object -First 100 } else { $t2All }
    foreach ($c in $t2Display) {
        $enabled = if ($c.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $confidence = switch ($c.Confidence) { 'High' { 'pass' } 'Medium' { 'warn' } default { 'fail' } }
        $review = if ($c.ReviewRequired) { '<span class="badge warn">Review</span>' } else { '<span class="badge pass">No</span>' }
        $evidence = if ($c.Evidence.Count -gt 0) { $c.Evidence -join ' | ' } else { $c.Reason }
        $t2Rows += "<tr><td>$(HtmlEncode $c.Name)</td><td>$(HtmlEncode $c.Domain)</td><td>$(HtmlEncode $c.OperatingSystem)</td>"
        $t2Rows += "<td>$enabled</td><td><span class='badge $confidence'>$(HtmlEncode $c.Confidence)</span></td><td>$review</td><td>$(HtmlEncode $evidence)</td><td>$(HtmlEncode $c.OU)</td></tr>`n"
    }
    $t2Note = if ($t2All.Count -gt 100) { "<p class='note'>Showing first 100 of $($t2All.Count) Tier 2 computers. See JSON export for full list.</p>" } else { '' }

    # Unclassified detail table
    $unRows = ''
    foreach ($c in ($Discovery.ComputersByTier.Unclassified | Sort-Object { $_.Name })) {
        $enabled = if ($c.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $confidence = switch ($c.Confidence) { 'High' { 'pass' } 'Medium' { 'warn' } default { 'fail' } }
        $review = if ($c.ReviewRequired) { '<span class="badge warn">Review</span>' } else { '<span class="badge pass">No</span>' }
        $evidence = if ($c.Evidence.Count -gt 0) { $c.Evidence -join ' | ' } else { $c.Reason }
        $unRows += "<tr><td>$(HtmlEncode $c.Name)</td><td>$(HtmlEncode $c.Domain)</td><td>$(HtmlEncode $c.OperatingSystem)</td>"
        $unRows += "<td>$enabled</td><td><span class='badge $confidence'>$(HtmlEncode $c.Confidence)</span></td><td>$review</td><td>$(HtmlEncode $evidence)</td><td>$(HtmlEncode $c.OU)</td></tr>`n"
    }

    $reviewQueueRows = ''
    foreach ($item in (@($Discovery.ReviewQueue) | Sort-Object { $_.Name })) {
        $confidence = switch ($item.Confidence) { 'High' { 'pass' } 'Medium' { 'warn' } default { 'fail' } }
        $evidence = if ($item.Evidence.Count -gt 0) { $item.Evidence -join ' | ' } else { '' }
        $reviewQueueRows += "<tr><td>$(HtmlEncode $item.Name)</td><td>$(HtmlEncode $item.Domain)</td><td>$(HtmlEncode $item.ProposedTier)</td><td><span class='badge $confidence'>$(HtmlEncode $item.Confidence)</span></td><td>$(HtmlEncode $item.ReviewReason)</td><td>$(HtmlEncode $evidence)</td></tr>`n"
    }

    $priorityActionCards = ''
    foreach ($action in @($Discovery.PriorityActions | Sort-Object Priority)) {
        $severityColor = switch ($action.Severity) {
            'High' { 'var(--red)' }
            'Medium' { 'var(--yellow)' }
            'Low' { 'var(--cyan)' }
            default { 'var(--accent)' }
        }
        $priorityActionCards += "<div class='step-card'><div class='step-number' style='background:$severityColor;'>$($action.Priority)</div><div class='step-text'><strong>$(HtmlEncode $action.Title)</strong> — $(HtmlEncode $action.Detail)</div></div>"
    }

    $readinessBlockerItems = ''
    foreach ($item in @($Discovery.Readiness.Blockers)) {
        $readinessBlockerItems += "<li>$(HtmlEncode $item)</li>"
    }
    $readinessWarningItems = ''
    foreach ($item in @($Discovery.Readiness.Warnings)) {
        $readinessWarningItems += "<li>$(HtmlEncode $item)</li>"
    }
    $readinessRecommendationItems = ''
    foreach ($item in @($Discovery.Readiness.Recommendations)) {
        $readinessRecommendationItems += "<li>$(HtmlEncode $item)</li>"
    }

    # --- Privileged accounts (grouped by group name) ---
    # Build per-group HTML blocks
    $privGroupBlocks = ''
    $groupOrder = @(
        'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Server Operators', 'Backup Operators', 'Print Operators',
        'DnsAdmins', 'Group Policy Creator Owners', 'Cert Publishers'
    )
    # Collect all keys and organize by group name
    $groupData = [ordered]@{}
    foreach ($key in $Discovery.PrivilegedAccounts.Keys) {
        $groupName = ($key -split '\\', 2)[1]
        $domain    = ($key -split '\\', 2)[0]
        if (-not $groupData[$groupName]) { $groupData[$groupName] = @() }
        $groupData[$groupName] += @($Discovery.PrivilegedAccounts[$key] | ForEach-Object {
            $_ + @{ _Domain = $domain }
        })
    }

    foreach ($grp in $groupOrder) {
        $members = $groupData[$grp]
        if (-not $members -or $members.Count -eq 0) { continue }

        $memberCount = $members.Count
        $collapsed = if ($grp -eq 'Domain Admins' -or $grp -eq 'Enterprise Admins') { '' } else { ' collapsed' }
        $hiddenCls = if ($collapsed) { ' hidden' } else { '' }

        $rows = ''
        foreach ($m in ($members | Sort-Object { $_.SamAccountName })) {
            $svcBadge = if ($m.IsServiceAccount) { '<span class="badge fail">SVC</span>' } elseif ($m.HasSPN) { '<span class="badge warn">SPN</span>' } else { '' }
            $enabledBadge = if ($m.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
            $pneBadge = if ($m.PasswordNeverExpires) { '<span class="badge warn">Yes</span>' } else { 'No' }
            $rows += "<tr><td>$(HtmlEncode $m.SamAccountName)</td><td>$(HtmlEncode $m._Domain)</td>"
            $rows += "<td>$enabledBadge</td><td>$svcBadge</td><td>$pneBadge</td>"
            $rows += "<td>$(HtmlEncode $m.PasswordLastSet)</td><td>$(HtmlEncode $m.LastLogon)</td></tr>`n"
        }

        $privGroupBlocks += @"
<div class="card">
<h3 class="collapsible$collapsed" onclick="toggleSection(this)">$grp ($memberCount members)</h3>
<div class="collapsible-content$hiddenCls">
<table>
    <thead><tr><th>Account</th><th>Domain</th><th>Enabled</th><th>Type</th><th>PwdNeverExpires</th><th>PwdLastSet</th><th>LastLogon</th></tr></thead>
    <tbody>$rows</tbody>
</table>
</div>
</div>

"@
    }

    # Service accounts in DA
    $svcDARows = ''
    foreach ($s in $Discovery.ServiceAccountsInDA) {
        $svcType = if ($s.ManagedServiceType) { $s.ManagedServiceType } elseif ($s.IsServiceAccount) { 'User service account' } else { 'SPN-bearing account' }
        $svcDARows += "<tr><td>$(HtmlEncode $s.SamAccountName)</td><td>$(HtmlEncode $s.Domain)</td><td>$(HtmlEncode $svcType)</td>"
        $svcDARows += "<td>$(HtmlEncode $s.Description)</td></tr>`n"
    }

    $gmsaRows = ''
    foreach ($svc in (@($Discovery.ManagedServiceAccounts.GMSA) | Sort-Object { $_.SamAccountName })) {
        $principals = if ($svc.PrincipalsAllowed.Count -gt 0) { ($svc.PrincipalsAllowed | ForEach-Object { HtmlEncode ([string]$_) }) -join '<br>' } else { '<span style="color:#8b949e;">None</span>' }
        $enabled = if ($svc.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $gmsaRows += "<tr><td>$(HtmlEncode $svc.SamAccountName)</td><td>$(HtmlEncode $svc.Domain)</td><td>$enabled</td><td>$($svc.PrincipalsCount)</td><td>$principals</td><td>$(HtmlEncode ([string]$svc.PasswordInterval))</td><td>$(HtmlEncode $svc.Description)</td></tr>`n"
    }

    $msaRows = ''
    foreach ($svc in (@($Discovery.ManagedServiceAccounts.MSA) | Sort-Object { $_.SamAccountName })) {
        $enabled = if ($svc.Enabled) { '<span class="badge pass">Yes</span>' } else { '<span class="badge fail">No</span>' }
        $msaRows += "<tr><td>$(HtmlEncode $svc.SamAccountName)</td><td>$(HtmlEncode $svc.Domain)</td><td>$enabled</td><td>$(HtmlEncode $svc.PasswordLastSet)</td><td>$(HtmlEncode $svc.Description)</td></tr>`n"
    }

    $authPolicyRows = ''
    foreach ($policy in (@($Discovery.AuthenticationControls.Policies) | Sort-Object { $_.Name })) {
        $mode = if ($policy.Enforce) { '<span class="badge fail">Enforce</span>' } else { '<span class="badge warn">Audit</span>' }
        $authPolicyRows += "<tr><td>$(HtmlEncode $policy.Name)</td><td>$mode</td><td>$(HtmlEncode $policy.Description)</td><td>$(HtmlEncode $policy.DistinguishedName)</td></tr>`n"
    }

    $authSiloRows = ''
    foreach ($silo in (@($Discovery.AuthenticationControls.Silos) | Sort-Object { $_.Name })) {
        $mode = if ($silo.Enforce) { '<span class="badge fail">Enforce</span>' } else { '<span class="badge warn">Audit</span>' }
        $policyBindings = @()
        if ($silo.UserPolicy) { $policyBindings += "User: $($silo.UserPolicy)" }
        if ($silo.ComputerPolicy) { $policyBindings += "Computer: $($silo.ComputerPolicy)" }
        if ($silo.ServicePolicy) { $policyBindings += "Service: $($silo.ServicePolicy)" }
        $bindingText = if ($policyBindings.Count -gt 0) { $policyBindings -join ' | ' } else { 'None' }
        $authSiloRows += "<tr><td>$(HtmlEncode $silo.Name)</td><td>$mode</td><td>$($silo.MemberCount)</td><td>$(HtmlEncode $bindingText)</td><td>$(HtmlEncode $silo.Description)</td></tr>`n"
    }

    # AdminCount orphans
    $orphanRows = ''
    foreach ($o in $Discovery.AdminCountOrphans) {
        $orphanRows += "<tr><td>$(HtmlEncode $o.SamAccountName)</td><td>$(HtmlEncode $o.Domain)</td></tr>`n"
    }

    # --- OUs (sorted hierarchically: parent before children) ---
    $sortedOUs = $Discovery.OUStructure | Sort-Object {
        $dnParts = @($_.DistinguishedName -split '(?<!\\),' | Where-Object { $_ -match '^(OU|DC)=' })
        [array]::Reverse($dnParts)
        $dnParts -join '/'
    }

    # Group OUs by domain for per-domain trees
    $ousByDomain = [ordered]@{}
    foreach ($ou in $sortedOUs) {
        if (-not $ousByDomain.Contains($ou.Domain)) { $ousByDomain[$ou.Domain] = @() }
        $ousByDomain[$ou.Domain] += $ou
    }

    # Build tree HTML per domain
    $ouTreeHtml = ''
    foreach ($domName in $ousByDomain.Keys) {
        $domOUs = $ousByDomain[$domName]
        $domOUCount = $domOUs.Count
        $collapsed = if ($ousByDomain.Keys.IndexOf($domName) -eq 0) { '' } else { ' collapsed' }
        $hiddenCls = if ($ousByDomain.Keys.IndexOf($domName) -eq 0) { '' } else { ' hidden' }

        $ouTreeHtml += @"
<div class="card">
<h3 class="collapsible$collapsed" onclick="toggleSection(this)">&#x1F3E2; $domName ($domOUCount OUs)</h3>
<div class="collapsible-content$hiddenCls">
<div class="ou-tree">
"@

        foreach ($ou in $domOUs) {
            $depth = [Math]::Max(0, $ou.Depth - 1)
            $gpoTag = if ($ou.HasGPOLinked) { ' <span class="ou-badge gpo">GPO</span>' } else { '' }
            $descTag = if ($ou.Description) { " <span class=`"ou-desc`">$(HtmlEncode $ou.Description)</span>" } else { '' }
            $ouTreeHtml += "<div class=`"ou-node`" style=`"--depth:$depth;`"><span class=`"ou-icon`">&#x1F4C1;</span><span class=`"ou-name`">$(HtmlEncode $ou.Name)</span>$gpoTag$descTag</div>`n"
        }

        $ouTreeHtml += @"
</div>
</div>
</div>

"@
    }

    # --- GPOs (with linked OUs) ---
    $gpoRows = ''
    foreach ($g in ($Discovery.GPOs | Sort-Object { $_.DisplayName })) {
        # Find all OUs this GPO is linked to
        $linkedOUs = @($Discovery.GPOLinks | Where-Object { $_.GPODN -eq $g.DN -and -not $_.Disabled } | ForEach-Object {
            $dn = $_.LinkedTo
            $enforced = if ($_.Enforced) { ' <span class="badge warn">Enforced</span>' } else { '' }
            "$(HtmlEncode $dn)$enforced"
        })
        $linkedToHtml = if ($linkedOUs.Count -gt 0) { $linkedOUs -join '<br>' } else { '<span style="color:#8b949e;">Not linked</span>' }
        $gpoRows += "<tr><td>$(HtmlEncode $g.DisplayName)</td><td>$(HtmlEncode $g.Domain)</td>"
        $gpoRows += "<td>$linkedToHtml</td><td>$(HtmlEncode $g.WhenCreated)</td><td>$(HtmlEncode $g.WhenChanged)</td></tr>`n"
    }

    # --- Trusts ---
    $trustRows = ''
    foreach ($t in $Discovery.Trusts) {
        $sidFilter = if ($t.SIDFilteringQuarantined) { '<span class="badge pass">Yes</span>' } else {
            if ($t.IntraForest) { '<span class="badge info">Intra-Forest</span>' } else { '<span class="badge fail">No</span>' }
        }
        $selectAuth = if ($t.SelectiveAuth) { '<span class="badge pass">Yes</span>' } else { 'No' }
        $trustRows += "<tr><td>$(HtmlEncode $t.Source)</td><td>$(HtmlEncode $t.Target)</td><td>$(HtmlEncode $t.Direction)</td>"
        $trustRows += "<td>$(HtmlEncode $t.TrustType)</td><td>$sidFilter</td><td>$selectAuth</td></tr>`n"
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
<title>MATI — Tiering Discovery Report</title>
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
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
    .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem; text-align: center; }
    .stat-card .number { font-size: 2.5rem; font-weight: bold; }
    .stat-card .label { color: #8b949e; font-size: 0.85rem; margin-top: 0.3rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th { background: #21262d; color: var(--accent); padding: 10px 12px; text-align: left; font-weight: 600; position: sticky; top: 0; }
    td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
    tr:hover { background: #1c2128; }
    .badge { padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
    .badge.pass { background: #0d2818; color: var(--green); }
    .badge.warn { background: #2d2000; color: var(--yellow); }
    .badge.fail { background: #2d0000; color: var(--red); }
    .badge.info { background: #0a2540; color: var(--cyan); }
    .progress-bar { width: 100%; height: 30px; background: #21262d; border-radius: 15px; overflow: hidden; margin: 1rem 0; }
    .progress-fill { height: 100%; border-radius: 15px; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.9rem; color: #fff;
        transition: width 0.3s; }
    .tier-bar { display: flex; height: 40px; border-radius: 8px; overflow: hidden; margin: 1rem 0; }
    .tier-segment { display: flex; align-items: center; justify-content: center; font-weight: 600; font-size: 0.85rem; color: #fff; }
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
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .summary-metric { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem 1rem; text-align: center; position: relative; overflow: hidden; }
    .summary-metric::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 10px 10px 0 0; }
    .summary-metric .metric-icon { font-size: 1.5rem; margin-bottom: 0.2rem; }
    .summary-metric .metric-value { font-size: 2.2rem; font-weight: 700; line-height: 1.1; }
    .summary-metric .metric-label { color: #8b949e; font-size: 0.78rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.5px; }
    .summary-category { margin-bottom: 1.5rem; }
    .summary-category h3 { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.8rem; border: none; }
    .summary-row { display: flex; align-items: center; justify-content: space-between; padding: 0.6rem 1rem; border-bottom: 1px solid var(--border); }
    .summary-row:last-child { border-bottom: none; }
    .summary-row .row-label { display: flex; align-items: center; gap: 0.6rem; color: var(--text); font-size: 0.88rem; }
    .summary-row .row-label .icon { font-size: 1rem; width: 1.5rem; text-align: center; }
    .summary-row .row-value { font-weight: 600; font-size: 0.88rem; display: flex; align-items: center; gap: 0.5rem; }
    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
    .dot.green { background: var(--green); box-shadow: 0 0 6px var(--green); }
    .dot.yellow { background: var(--yellow); box-shadow: 0 0 6px var(--yellow); }
    .dot.red { background: var(--red); box-shadow: 0 0 6px var(--red); }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1.5rem; }

    /* Section headers */
    .section-header { display: flex; align-items: center; gap: 0.6rem; }
    .section-header .section-icon { font-size: 1.3rem; }
    .section-intro { color: #8b949e; font-size: 0.85rem; margin: -0.5rem 0 1.5rem 0; }

    /* Enhanced stat cards */
    .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .metric-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; position: relative; overflow: hidden; }
    .metric-card .mc-icon { font-size: 1.3rem; margin-bottom: 0.3rem; }
    .metric-card .mc-value { font-size: 2rem; font-weight: 700; line-height: 1.2; }
    .metric-card .mc-label { color: #8b949e; font-size: 0.78rem; margin-top: 0.2rem; text-transform: uppercase; letter-spacing: 0.5px; }

    /* Tier-colored cards */
    .tier-card { position: relative; }
    .tier-card::after { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; border-radius: 8px 8px 0 0; }
    .tier-card.t0::after { background: #e74c3c; }
    .tier-card.t1::after { background: #f39c12; }
    .tier-card.t2::after { background: #3498db; }
    .tier-card.unclass::after { background: #6c757d; }

    /* Trust card */
    .trust-visual { display: flex; align-items: center; gap: 1rem; padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.88rem; }
    .trust-visual:last-child { border-bottom: none; }
    .trust-arrow { color: var(--accent); font-weight: 700; font-size: 1.1rem; flex-shrink: 0; }
    .trust-badges { display: flex; gap: 0.4rem; flex-wrap: wrap; }

    /* GPO card */
    .gpo-item { padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); }
    .gpo-item:last-child { border-bottom: none; }
    .gpo-item:hover { background: #1c2128; }
    .gpo-name { font-weight: 600; color: var(--text); font-size: 0.9rem; }
    .gpo-domain { color: #8b949e; font-size: 0.78rem; margin-left: 0.5rem; }
    .gpo-meta { display: flex; gap: 1.5rem; margin-top: 0.3rem; font-size: 0.78rem; color: #8b949e; }
    .gpo-links { margin-top: 0.3rem; font-size: 0.78rem; }
    .gpo-link-item { color: var(--cyan); }

    /* Next steps */
    .steps-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }
    .step-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; display: flex; gap: 1rem; align-items: flex-start; }
    .step-number { background: var(--accent); color: var(--bg); width: 28px; height: 28px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; flex-shrink: 0; }
    .step-text { font-size: 0.85rem; color: var(--text); line-height: 1.5; }
    .step-text strong { color: var(--accent); }
    .status-list { margin: 0.5rem 0 0 1.2rem; }
    .status-list li { margin-bottom: 0.35rem; }
    .dc-status { display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.25rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.02em; }
    .dc-status.ok { background: #0d2818; color: var(--green); }
    .dc-status.warning { background: #2d2000; color: var(--yellow); }
    .dc-status.unreachable { background: #2d0000; color: var(--red); }

    /* OU Tree */
    .ou-tree { padding: 0.5rem 0; font-size: 0.88rem; font-family: 'Cascadia Code', 'Consolas', monospace; }
    .ou-node { display: flex; align-items: center; gap: 0.4rem; padding: 3px 0 3px calc(var(--depth) * 1.6rem + 0.5rem); border-left: 2px solid transparent; transition: background 0.15s; position: relative; }
    .ou-node:hover { background: rgba(88,166,255,0.06); border-left-color: var(--accent); }
    .ou-node::before { content: ''; position: absolute; left: calc(var(--depth) * 1.6rem - 0.6rem); top: 0; bottom: 50%; width: 0.8rem; border-left: 1px solid #30363d; border-bottom: 1px solid #30363d; }
    .ou-node[style*="--depth:0"]::before { display: none; }
    .ou-icon { font-size: 1rem; flex-shrink: 0; }
    .ou-name { color: var(--text); font-weight: 500; }
    .ou-badge { padding: 1px 6px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; font-family: 'Segoe UI', sans-serif; letter-spacing: 0.5px; vertical-align: middle; }
    .ou-badge.gpo { background: #1a1a2e; color: #a78bfa; }
    .ou-desc { color: #6e7681; font-size: 0.78rem; font-style: italic; font-family: 'Segoe UI', sans-serif; margin-left: 0.3rem; }

    @media (max-width: 1200px) { .summary-grid { grid-template-columns: repeat(3, 1fr); } .grid-3 { grid-template-columns: 1fr; } }
    @media (max-width: 768px) { .summary-grid { grid-template-columns: repeat(2, 1fr); } .metric-grid { grid-template-columns: repeat(2, 1fr); } }

    @media print { body { background: #fff; color: #000; } .card { border-color: #ddd; } th { background: #f0f0f0; color: #333; } }
</style>
</head>
<body>
<div class="container">

<h1>MATI — Tiering Discovery Report</h1>
<p class="subtitle">Phase 0 — Read-Only Assessment | Generated: $($Discovery.Timestamp)</p>

<nav class="section-nav">
    <a href="#summary">Summary</a>
    <a href="#forest">Forest</a>
    <a href="#dcs">Domain Controllers</a>
    <a href="#computers">Computers</a>
    <a href="#review">Review Queue</a>
    <a href="#privileged">Privileged Accounts</a>
    <a href="#managed-service-accounts">Managed Service Accounts</a>
    <a href="#ous">OU Structure</a>
    <a href="#gpos">GPOs</a>
    <a href="#trusts">Trusts</a>
</nav>

<!-- ================================================================ -->
<!-- CURRENT STATE SUMMARY -->
<!-- ================================================================ -->
<div id="summary">
<h2>&#x1F4CA; Environment Snapshot</h2>

<!-- Top metric cards -->
<div class="summary-grid">
    <div class="summary-metric" style="border-top: 3px solid var(--accent);">
        <div class="metric-icon">&#x1F3E2;</div>
        <div class="metric-value" style="color:var(--accent);">$($summary.Environment.Domains)</div>
        <div class="metric-label">Domains</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid var(--accent);">
        <div class="metric-icon">&#x1F5A5;</div>
        <div class="metric-value" style="color:var(--accent);">$totalComputers</div>
        <div class="metric-label">Computers</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid var(--accent);">
        <div class="metric-icon">&#x1F464;</div>
        <div class="metric-value" style="color:var(--accent);">$($summary.Environment.Users)</div>
        <div class="metric-label">Users</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid var(--accent);">
        <div class="metric-icon">&#x1F465;</div>
        <div class="metric-value" style="color:var(--accent);">$($summary.Environment.Groups)</div>
        <div class="metric-label">Groups</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $daColor;">
        <div class="metric-icon">&#x1F6E1;</div>
        <div class="metric-value" style="color:$daColor;">$daCount</div>
        <div class="metric-label">Domain Admins</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid $eaColor;">
        <div class="metric-icon">&#x1F451;</div>
        <div class="metric-value" style="color:$eaColor;">$eaCount</div>
        <div class="metric-label">Enterprise Admins</div>
    </div>
    <div class="summary-metric" style="border-top: 3px solid var(--accent);">
        <div class="metric-icon">&#x1F517;</div>
        <div class="metric-value" style="color:var(--accent);">$trustCount</div>
        <div class="metric-label">Trusts</div>
    </div>
</div>

<!-- Tier distribution bar -->
<div class="card" style="padding: 1rem 1.5rem;">
    <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
        <span style="font-size:0.85rem; color:#8b949e;">Computer Tier Distribution</span>
        <span style="font-size:0.85rem; color:#8b949e;">$totalComputers total</span>
    </div>
    <div class="tier-bar">
        <div class="tier-segment" style="flex:$([Math]::Max($Discovery.ComputersByTier.Tier0.Count,0.01)); background:#e74c3c;" title="Tier 0: $($Discovery.ComputersByTier.Tier0.Count)">$(if($Discovery.ComputersByTier.Tier0.Count -gt 0){"T0: $($Discovery.ComputersByTier.Tier0.Count)"})</div>
        <div class="tier-segment" style="flex:$([Math]::Max($Discovery.ComputersByTier.Tier1.Count,0.01)); background:#f39c12;" title="Tier 1: $($Discovery.ComputersByTier.Tier1.Count)">$(if($Discovery.ComputersByTier.Tier1.Count -gt 0){"T1: $($Discovery.ComputersByTier.Tier1.Count)"})</div>
        <div class="tier-segment" style="flex:$([Math]::Max($Discovery.ComputersByTier.Tier2.Count,0.01)); background:#3498db;" title="Tier 2: $($Discovery.ComputersByTier.Tier2.Count)">$(if($Discovery.ComputersByTier.Tier2.Count -gt 0){"T2: $($Discovery.ComputersByTier.Tier2.Count)"})</div>
        <div class="tier-segment" style="flex:$([Math]::Max($Discovery.ComputersByTier.Unclassified.Count,0.01)); background:#6c757d;" title="Unclassified: $($Discovery.ComputersByTier.Unclassified.Count)">$(if($Discovery.ComputersByTier.Unclassified.Count -gt 0){"?: $($Discovery.ComputersByTier.Unclassified.Count)"})</div>
    </div>
</div>

<!-- 3-column detail cards -->
<div class="grid-3">

<!-- Identity & Access -->
<div class="card summary-category">
    <h3>&#x1F464; Identity & Access</h3>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F6E1;</span> Domain Admins</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.DomainAdmins.Dot)"></span> $($summary.IdentityAccess.DomainAdmins.Count) account(s)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F451;</span> Enterprise Admins</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.EnterpriseAdmins.Dot)"></span> $($summary.IdentityAccess.EnterpriseAdmins.Count) account(s)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x2699;</span> Svc Accounts in DA</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.ServiceAccountsInDA.Dot)"></span> $($summary.IdentityAccess.ServiceAccountsInDA.Count) found</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F527;</span> gMSA</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.GMSA.Dot)"></span> $($summary.IdentityAccess.GMSA.Count) account(s)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F9F0;</span> sMSA</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.MSA.Dot)"></span> $($summary.IdentityAccess.MSA.Count) account(s)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x26A0;</span> AdminCount Orphans</div>
        <div class="row-value"><span class="dot $($summary.IdentityAccess.AdminCountOrphans.Dot)"></span> $($summary.IdentityAccess.AdminCountOrphans.Count) account(s)</div>
    </div>
</div>

<!-- Infrastructure -->
<div class="card summary-category">
    <h3>&#x1F3D7; Infrastructure</h3>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F310;</span> Sites</div>
        <div class="row-value" style="color:var(--accent);">$($summary.Infrastructure.Sites)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F5A5;</span> Domain Controllers</div>
        <div class="row-value" style="color:var(--accent);">$($summary.Infrastructure.DomainControllers)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F4C2;</span> Organizational Units</div>
        <div class="row-value" style="color:var(--accent);">$($summary.Infrastructure.OrganizationalUnits)</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F4DC;</span> Group Policies</div>
        <div class="row-value" style="color:var(--accent);">$($summary.Infrastructure.GroupPolicies)</div>
    </div>
</div>

<!-- Trusts -->
<div class="card summary-category">
    <h3>&#x1F517; Trusts</h3>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F91D;</span> Trust Relationships</div>
        <div class="row-value"><span class="dot $($summary.Trusts.TrustRelationships.Dot)"></span> $($summary.Trusts.TrustRelationships.Count) total</div>
    </div>
    <div class="summary-row">
        <div class="row-label"><span class="icon">&#x1F6A8;</span> Unsafe Trusts (no SID filter)</div>
        <div class="row-value"><span class="dot $($summary.Trusts.UnsafeTrusts.Dot)"></span> $($summary.Trusts.UnsafeTrusts.Count)</div>
    </div>
</div>

</div>

<div class="card">
    <h3 style="margin-top:0;">&#x1F6A6; Tiering Readiness</h3>
    <p><span class="badge $readinessBadgeClass">$readinessStatus</span></p>
    $(if ($Discovery.Readiness.Blockers.Count -gt 0) { "<h3>Blockers</h3><ul class='status-list'>$readinessBlockerItems</ul>" })
    $(if ($Discovery.Readiness.Warnings.Count -gt 0) { "<h3>Warnings</h3><ul class='status-list'>$readinessWarningItems</ul>" })
    $(if ($Discovery.Readiness.Recommendations.Count -gt 0) { "<h3>Recommended actions</h3><ul class='status-list'>$readinessRecommendationItems</ul>" })
</div>

</div>

<!-- ================================================================ -->
<!-- FOREST & DOMAINS -->
<!-- ================================================================ -->
<div id="forest">
<h2 class="section-header"><span class="section-icon">&#x1F3E2;</span> Forest & Domains</h2>
<p class="section-intro">Forest topology overview with domain functional levels and security policies.</p>

<div class="metric-grid">
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F30D;</div><div class="mc-value" style="color:var(--accent);">$(HtmlEncode $forestInfo.Name)</div><div class="mc-label">Forest Root</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F3E2;</div><div class="mc-value" style="color:var(--accent);">$($forestInfo.DomainCount)</div><div class="mc-label">Domains</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F4CD;</div><div class="mc-value" style="color:var(--accent);">$($forestInfo.SiteCount)</div><div class="mc-label">Sites</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F4D7;</div><div class="mc-value" style="color:var(--accent);">$($forestInfo.GlobalCatalogCount)</div><div class="mc-label">Global Catalogs</div></div>
</div>

<div class="card">
    <h3 style="margin-top:0;">&#x1F512; Domain Configuration</h3>
<table>
    <thead><tr><th>Domain</th><th>NetBIOS</th><th>Functional Level</th><th>Min Pwd Length</th><th>Lockout Threshold</th><th>MachineAccountQuota</th></tr></thead>
    <tbody>$domainRows</tbody>
</table>
</div>
</div>

<!-- ================================================================ -->
<!-- DOMAIN CONTROLLERS -->
<!-- ================================================================ -->
<div id="dcs">
<h2 class="section-header"><span class="section-icon">&#x1F5A5;</span> Domain Controllers ($($Discovery.DomainControllers.Count))</h2>
<p class="section-intro">All domain controllers with FSMO roles, site assignments and operating system details.</p>
<div class="card">
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>Site</th><th>OS</th><th>Type</th><th>FSMO Roles</th></tr></thead>
    <tbody>$dcRows</tbody>
</table>
</div>

<div class="card">
    <h3 style="margin-top:0;">&#x1F6A6; Connectivity Status</h3>
    <table>
        <thead><tr><th>Name</th><th>FQDN</th><th>Domain</th><th>IP</th><th>GC</th><th>Status</th><th>Latency</th></tr></thead>
        <tbody>$dcConnectivityRows</tbody>
    </table>
</div>
</div>

<!-- ================================================================ -->
<!-- COMPUTERS BY TIER -->
<!-- ================================================================ -->
<div id="computers">
<h2 class="section-header"><span class="section-icon">&#x1F4BB;</span> Computer Classification</h2>
<p class="section-intro">Automated tier assignment based on roles, SPNs, OU location and naming patterns defined in classification rules.</p>

<div class="metric-grid">
    <div class="metric-card" style="border-top: 3px solid #e74c3c;"><div class="mc-icon">&#x1F534;</div><div class="mc-value" style="color:#e74c3c;">$($Discovery.ComputersByTier.Tier0.Count)</div><div class="mc-label">Tier 0 — Control Plane</div></div>
    <div class="metric-card" style="border-top: 3px solid #f39c12;"><div class="mc-icon">&#x1F7E0;</div><div class="mc-value" style="color:#f39c12;">$($Discovery.ComputersByTier.Tier1.Count)</div><div class="mc-label">Tier 1 — Servers</div></div>
    <div class="metric-card" style="border-top: 3px solid #3498db;"><div class="mc-icon">&#x1F535;</div><div class="mc-value" style="color:#3498db;">$($Discovery.ComputersByTier.Tier2.Count)</div><div class="mc-label">Tier 2 — Workstations</div></div>
    <div class="metric-card" style="border-top: 3px solid #6c757d;"><div class="mc-icon">&#x2753;</div><div class="mc-value" style="color:#6c757d;">$($Discovery.ComputersByTier.Unclassified.Count)</div><div class="mc-label">Unclassified</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--yellow);"><div class="mc-icon">&#x1F50D;</div><div class="mc-value" style="color:var(--yellow);">$reviewQueueCount</div><div class="mc-label">Review Queue</div></div>
</div>

<div class="card" style="padding: 1rem 1.5rem;">
    <div style="display:flex; justify-content:space-between; margin-bottom:0.5rem;">
        <span style="font-size:0.85rem; color:#8b949e;">Tier Distribution</span>
        <span style="font-size:0.85rem; color:#8b949e;">$totalComputers total</span>
    </div>
    <div class="tier-bar">
        $(foreach ($ts in $tierSummary) {
            $pct = if ($totalComputers -gt 0) { [math]::Round(($ts.Count / $totalComputers) * 100, 1) } else { 0 }
            if ($pct -gt 0) { "<div class='tier-segment' style='width:${pct}%; background:$($ts.Color);'>$($ts.Tier) ($($ts.Count))</div>" }
        })
    </div>
</div>

<div class="card tier-card t0">
<h3 class="collapsible" onclick="toggleSection(this)">&#x1F534; Tier 0 — Control Plane ($($Discovery.ComputersByTier.Tier0.Count))</h3>
<div class="collapsible-content">
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>OS</th><th>Enabled</th><th>Confidence</th><th>Review</th><th>Evidence</th><th>Current OU</th></tr></thead>
    <tbody>$t0Rows</tbody>
</table>
</div>
</div>

<div class="card tier-card t1">
<h3 class="collapsible collapsed" onclick="toggleSection(this)">&#x1F7E0; Tier 1 — Servers ($($Discovery.ComputersByTier.Tier1.Count))</h3>
<div class="collapsible-content hidden">
$t1Note
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>OS</th><th>Enabled</th><th>Confidence</th><th>Review</th><th>Evidence</th><th>Current OU</th></tr></thead>
    <tbody>$t1Rows</tbody>
</table>
</div>
</div>

<div class="card tier-card t2">
<h3 class="collapsible collapsed" onclick="toggleSection(this)">&#x1F535; Tier 2 — Workstations ($($Discovery.ComputersByTier.Tier2.Count))</h3>
<div class="collapsible-content hidden">
$t2Note
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>OS</th><th>Enabled</th><th>Confidence</th><th>Review</th><th>Evidence</th><th>Current OU</th></tr></thead>
    <tbody>$t2Rows</tbody>
</table>
</div>
</div>

$(if ($Discovery.ComputersByTier.Unclassified.Count -gt 0) {
@"
<div class="card tier-card unclass" style="border-color:var(--yellow);">
<h3 class="collapsible" onclick="toggleSection(this)">&#x2753; Unclassified Computers ($($Discovery.ComputersByTier.Unclassified.Count))</h3>
<div class="collapsible-content">
<p class="note">These computers could not be automatically classified. Review and adjust classification rules in Tiering.config.psd1.</p>
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>OS</th><th>Enabled</th><th>Confidence</th><th>Review</th><th>Evidence</th><th>Current OU</th></tr></thead>
    <tbody>$unRows</tbody>
</table>
</div>
</div>
"@
})
</div>

<div id="review">
<h2 class="section-header"><span class="section-icon">&#x1F50D;</span> Review Queue ($reviewQueueCount)</h2>
<p class="section-intro">Computers that were classified with weak or conflicting evidence and should be validated before using this output to drive tier placement.</p>
$(if ($reviewQueueCount -gt 0) {
@"
<div class="card" style="border-top: 3px solid var(--yellow);">
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>Proposed Tier</th><th>Confidence</th><th>Review Reason</th><th>Evidence</th></tr></thead>
    <tbody>$reviewQueueRows</tbody>
</table>
</div>
"@
} else {
    '<div class="card"><p style="color:#8b949e; text-align:center; padding:1rem 0;">&#x2705; No computers currently require manual review.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- ================================================================ -->
<div id="privileged">
<h2 class="section-header"><span class="section-icon">&#x1F6E1;</span> Privileged Accounts</h2>
<p class="section-intro">Members of sensitive security groups across all domains. Domain Admins and Enterprise Admins are expanded by default.</p>

$privGroupBlocks

$(if ($Discovery.ServiceAccountsInDA.Count -gt 0) {
@"
<div class="card" style="border-top: 3px solid var(--red);">
<h3 style="margin-top:0;">&#x26A0; Service Accounts in Domain Admins ($($Discovery.ServiceAccountsInDA.Count))</h3>
<p class="note">These service, gMSA, sMSA or SPN-bearing accounts are members of Domain Admins. They should be reviewed and removed from DA where possible.</p>
<table>
    <thead><tr><th>Account</th><th>Domain</th><th>Type</th><th>Description</th></tr></thead>
    <tbody>$svcDARows</tbody>
</table>
</div>
"@
})

$(if ($Discovery.AdminCountOrphans.Count -gt 0) {
@"
<div class="card" style="border-top: 3px solid var(--yellow);">
<h3 style="margin-top:0;">&#x1F4A4; AdminCount Orphans ($($Discovery.AdminCountOrphans.Count))</h3>
<p class="note">Accounts with adminCount=1 but no longer members of any privileged group. Consider clearing adminCount and resetting inherited ACLs.</p>
<table>
    <thead><tr><th>Account</th><th>Domain</th></tr></thead>
    <tbody>$orphanRows</tbody>
</table>
</div>
"@
})
</div>

<!-- ================================================================ -->
<!-- MANAGED SERVICE ACCOUNTS -->
<!-- ================================================================ -->
<div id="managed-service-accounts">
<h2 class="section-header"><span class="section-icon">&#x1F527;</span> Managed Service Accounts</h2>
<p class="section-intro">Inventory of Group Managed Service Accounts and standalone Managed Service Accounts discovered during Phase 0.</p>

<div class="metric-grid">
    <div class="metric-card" style="border-top: 3px solid var(--green);"><div class="mc-icon">&#x1F527;</div><div class="mc-value" style="color:var(--green);">$gmsaCount</div><div class="mc-label">gMSA</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--yellow);"><div class="mc-icon">&#x1F9F0;</div><div class="mc-value" style="color:var(--yellow);">$msaCount</div><div class="mc-label">sMSA</div></div>
</div>

$(if ($gmsaCount -gt 0) {
@"
<div class="card">
<h3 style="margin-top:0;">&#x1F512; Group Managed Service Accounts ($gmsaCount)</h3>
<table>
    <thead><tr><th>Account</th><th>Domain</th><th>Enabled</th><th>Allowed Principals</th><th>Principals</th><th>Password Interval</th><th>Description</th></tr></thead>
    <tbody>$gmsaRows</tbody>
</table>
</div>
"@
})

$(if ($msaCount -gt 0) {
@"
<div class="card">
<h3 style="margin-top:0;">&#x1F4A1; Standalone Managed Service Accounts ($msaCount)</h3>
<table>
    <thead><tr><th>Account</th><th>Domain</th><th>Enabled</th><th>Password Last Set</th><th>Description</th></tr></thead>
    <tbody>$msaRows</tbody>
</table>
</div>
"@
})

$(if ($gmsaCount -eq 0 -and $msaCount -eq 0) {
    '<div class="card"><p style="color:#8b949e; text-align:center; padding:1rem 0;">No managed service accounts were discovered.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- AUTHENTICATION POLICIES & SILOS -->
<!-- ================================================================ -->
<div id="auth-policies">
<h2 class="section-header"><span class="section-icon">&#x1F512;</span> Authentication Policies &amp; Silos</h2>
<p class="section-intro">Read-only inventory of Authentication Policies and Authentication Policy Silos already deployed in the forest. Phase 0 reports the current state; Phase 4 remains the deployment phase.</p>

<div class="metric-grid">
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F4CB;</div><div class="mc-value" style="color:var(--accent);">$($authPolicySummary.PolicyCount)</div><div class="mc-label">Policies</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--red);"><div class="mc-icon">&#x1F6E1;</div><div class="mc-value" style="color:var(--red);">$($authPolicySummary.EnforcedPolicies)</div><div class="mc-label">Policies Enforced</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--accent);"><div class="mc-icon">&#x1F3F0;</div><div class="mc-value" style="color:var(--accent);">$($authPolicySummary.SiloCount)</div><div class="mc-label">Silos</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--yellow);"><div class="mc-icon">&#x1F50E;</div><div class="mc-value" style="color:var(--yellow);">$($authPolicySummary.AuditOnlySilos)</div><div class="mc-label">Audit-Only Silos</div></div>
    <div class="metric-card" style="border-top: 3px solid var(--green);"><div class="mc-icon">&#x1F465;</div><div class="mc-value" style="color:var(--green);">$($authPolicySummary.AssignedMembers)</div><div class="mc-label">Assigned Members</div></div>
</div>

$(if ($authPolicySummary.PolicyCount -gt 0) {
@"
<div class="card">
<h3 style="margin-top:0;">Policies</h3>
<table>
    <thead><tr><th>Name</th><th>Mode</th><th>Description</th><th>DN</th></tr></thead>
    <tbody>$authPolicyRows</tbody>
</table>
</div>
"@
})

$(if ($authPolicySummary.SiloCount -gt 0) {
@"
<div class="card">
<h3 style="margin-top:0;">Silos</h3>
<table>
    <thead><tr><th>Name</th><th>Mode</th><th>Members</th><th>Bound Policies</th><th>Description</th></tr></thead>
    <tbody>$authSiloRows</tbody>
</table>
</div>
"@
})

$(if ($authPolicySummary.PolicyCount -eq 0 -and $authPolicySummary.SiloCount -eq 0) {
    '<div class="card"><p style="color:#8b949e; text-align:center; padding:1rem 0;">No Authentication Policies or Authentication Policy Silos were discovered in the current baseline.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- OU STRUCTURE -->
<!-- ================================================================ -->
<div id="ous">
<h2 class="section-header"><span class="section-icon">&#x1F4C2;</span> Current OU Structure ($($Discovery.OUStructure.Count) OUs)</h2>
<p class="section-intro">Hierarchical view of all Organizational Units per domain. <span class="ou-badge gpo" style="display:inline;">GPO</span> indicates a Group Policy is linked.</p>
$ouTreeHtml
</div>

<!-- ================================================================ -->
<!-- GPOs -->
<!-- ================================================================ -->
<div id="gpos">
<h2 class="section-header"><span class="section-icon">&#x1F4DC;</span> Group Policy Objects ($($Discovery.GPOs.Count))</h2>
<p class="section-intro">All GPOs with their linked OUs. Enforced links are highlighted.</p>
<div class="card">
<h3 class="collapsible" onclick="toggleSection(this)">All GPOs</h3>
<div class="collapsible-content">
<table>
    <thead><tr><th>Name</th><th>Domain</th><th>Linked To</th><th>Created</th><th>Modified</th></tr></thead>
    <tbody>$gpoRows</tbody>
</table>
</div>
</div>
</div>

<!-- ================================================================ -->
<!-- TRUSTS -->
<!-- ================================================================ -->
<div id="trusts">
<h2 class="section-header"><span class="section-icon">&#x1F517;</span> Trust Relationships ($($Discovery.Trusts.Count))</h2>
<p class="section-intro">Forest and domain trust relationships with SID filtering and selective authentication status.</p>
$(if ($Discovery.Trusts.Count -gt 0) {
@"
<div class="card">
<table>
    <thead><tr><th>Source</th><th>Target</th><th>Direction</th><th>Type</th><th>SID Filtering</th><th>Selective Auth</th></tr></thead>
    <tbody>$trustRows</tbody>
</table>
</div>
"@
} else {
    '<div class="card"><p style="color:#8b949e; text-align:center; padding:2rem 0;">&#x2705; No trust relationships found.</p></div>'
})
</div>

<!-- ================================================================ -->
<!-- NEXT STEPS -->
<!-- ================================================================ -->
<h2 class="section-header"><span class="section-icon">&#x1F680;</span> Recommended Next Steps</h2>
<p class="section-intro">Priority actions generated from the current discovery output before proceeding to Phase 1.</p>
<div class="steps-grid">
    $priorityActionCards
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

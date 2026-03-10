# Reporters\Export-MATIHtml.ps1
# MATIv2 - HTML reporter using template-based generation.

function Export-MATIHtml {
    <#
    .SYNOPSIS
        Generates a rich HTML report from the template.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$EngineContext
    )

    $htmlDir   = $EngineContext.HtmlDir
    $timestamp = $EngineContext.Timestamp
    $config    = $EngineContext.Config
    $findings  = $EngineContext.Findings
    $score     = $EngineContext.Score

    # ------------------------------------------------------------------
    # Load HTML template
    # ------------------------------------------------------------------
    $templatePath = Join-Path $EngineContext.RootPath 'Reporters\Templates\report.html.tpl'
    if (-not (Test-Path $templatePath)) {
        Write-Warning "HTML template not found at $templatePath - generating minimal report."
        $template = '<html><body><h1>MATI Report</h1><p>Template not found.</p>{{CONTENT}}</body></html>'
    } else {
        $template = Get-Content -Path $templatePath -Raw -Encoding UTF8
    }

    # ------------------------------------------------------------------
    # Build severity summary
    # ------------------------------------------------------------------
    $severityCounts = @{
        Critical      = ($findings | Where-Object Severity -eq 'Critical').Count
        High          = ($findings | Where-Object Severity -eq 'High').Count
        Medium        = ($findings | Where-Object Severity -eq 'Medium').Count
        Low           = ($findings | Where-Object Severity -eq 'Low').Count
        Informational = ($findings | Where-Object Severity -eq 'Informational').Count
    }

    # ------------------------------------------------------------------
    # Build findings table rows grouped by category (custom order)
    # ------------------------------------------------------------------
    $categoryOrder = @(
        'Config'
        'Hardening'
        'Kerberos'
        'PasswordPolicy'
        'PrivilegedAccounts'
        'StaleObjects'
        'ACL'
        'ADCS'
        'Delegation'
        'RODC'
    )
    $grouped = $findings | Group-Object Category | Sort-Object {
        $idx = $categoryOrder.IndexOf($_.Name)
        if ($idx -eq -1) { 999 } else { $idx }
    }

    $categoryBlocks = ''

    foreach ($group in $grouped) {
        $categoryBlocks += "<details class=`"category-section`" open>`n"
        $categoryBlocks += "<summary class=`"category-header`">$($group.Name) <span class=`"badge`">$($group.Count)</span></summary>`n"

        # Group findings by ID within each category, sorted by severity then ID
        $byId = $group.Group | Group-Object Id | Sort-Object @{Expression={
            $sev = $_.Group[0].Severity
            switch ($sev) { 'Critical'{0} 'High'{1} 'Medium'{2} 'Low'{3} 'Informational'{4} }
        }}, Name

        foreach ($idGroup in $byId) {
            $firstFinding = $idGroup.Group[0]
            $severityClass = $firstFinding.Severity.ToLower()
            $idCount = $idGroup.Count
            $categoryBlocks += "<details class=`"finding-section`" open>`n"
            $categoryBlocks += "<summary class=`"finding-header`"><span class=`"severity-badge $severityClass`">$($firstFinding.Severity)</span> $($idGroup.Name) &mdash; $($firstFinding.Title) <span class=`"badge`">$idCount</span></summary>`n"
            $categoryBlocks += "<table class=`"findings-table`">`n"
            $categoryBlocks += "<thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Description</th><th>Object</th><th>Domain</th><th>Remediation</th><th>Details</th><th>References</th></tr></thead>`n"
            $categoryBlocks += "<tbody>`n"

            foreach ($f in $idGroup.Group) {
                $fSevClass = $f.Severity.ToLower()
                $detailsStr = ($f.Details.GetEnumerator() | ForEach-Object { "<b>$($_.Key)</b>: $($_.Value)" }) -join '<br>'
                $escapedDesc = [System.Web.HttpUtility]::HtmlEncode($f.Description)
                $escapedRem  = [System.Web.HttpUtility]::HtmlEncode($f.Remediation)
                $escapedDN   = [System.Web.HttpUtility]::HtmlEncode($f.ObjectDN)

                $categoryBlocks += "<tr class=`"severity-$fSevClass`">"
                $categoryBlocks += "<td>$($f.Id)</td>"
                $categoryBlocks += "<td><span class=`"severity-badge $fSevClass`">$($f.Severity)</span></td>"
                $categoryBlocks += "<td>$($f.Title)</td>"
                $categoryBlocks += "<td>$escapedDesc</td>"
                $categoryBlocks += "<td class=`"object-dn`">$escapedDN</td>"
                $categoryBlocks += "<td>$($f.Domain)</td>"
                $categoryBlocks += "<td>$escapedRem</td>"
                $categoryBlocks += "<td>$detailsStr</td>"

                # References
                $refsStr = ''
                if ($f.References -and $f.References.Count -gt 0) {
                    $refsStr = ($f.References | ForEach-Object {
                        $escaped = [System.Web.HttpUtility]::HtmlEncode($_)
                        "<a href=`"$escaped`" target=`"_blank`" rel=`"noopener`">$escaped</a>"
                    }) -join '<br>'
                }
                $categoryBlocks += "<td class=`"refs-cell`">$refsStr</td>"

                $categoryBlocks += "</tr>`n"
            }

            $categoryBlocks += "</tbody></table>`n"
            $categoryBlocks += "</details>`n"
        }

        $categoryBlocks += "</details>`n"
    }

    # ------------------------------------------------------------------
    # Build DC connectivity table
    # ------------------------------------------------------------------
    $dcBlock = ''
    if ($EngineContext.DCConnectivity -and $EngineContext.DCConnectivity.Count -gt 0) {
        $reachable   = ($EngineContext.DCConnectivity | Where-Object Status -eq 'OK').Count
        $total       = $EngineContext.DCConnectivity.Count
        $unreachable = $total - $reachable

        $dcBlock += "<div class=`"dc-section`">`n"
        $dcBlock += "<h2>Domain Controllers <span class=`"badge`">$total contacted &mdash; $reachable reachable &mdash; $unreachable unreachable</span></h2>`n"
        $dcBlock += "<table class=`"dc-table`">`n"
        $dcBlock += "<thead><tr><th>Name</th><th>FQDN</th><th>Domain</th><th>IP</th><th>Site</th><th>OS</th><th>GC</th><th>RODC</th><th>Status</th><th>Latency</th></tr></thead>`n"
        $dcBlock += "<tbody>`n"

        foreach ($dc in ($EngineContext.DCConnectivity | Sort-Object Domain, Name)) {
            $statusClass = switch ($dc.Status) {
                'OK'          { 'ok' }
                'Unreachable' { 'unreachable' }
                default       { 'warning' }
            }
            $latStr = if ($null -ne $dc.LatencyMs) { "$($dc.LatencyMs) ms" } else { '—' }
            $gcStr  = if ($dc.IsGlobalCatalog) { 'Yes' } else { 'No' }
            $roStr  = if ($dc.IsReadOnly) { 'Yes' } else { 'No' }
            $osStr  = [System.Web.HttpUtility]::HtmlEncode($dc.OperatingSystem)

            $dcBlock += "<tr>"
            $dcBlock += "<td><strong>$($dc.Name)</strong></td>"
            $dcBlock += "<td>$($dc.HostName)</td>"
            $dcBlock += "<td>$($dc.Domain)</td>"
            $dcBlock += "<td>$($dc.IPv4Address)</td>"
            $dcBlock += "<td>$($dc.Site)</td>"
            $dcBlock += "<td>$osStr</td>"
            $dcBlock += "<td>$gcStr</td>"
            $dcBlock += "<td>$roStr</td>"
            $dcBlock += "<td><span class=`"dc-status $statusClass`">$($dc.Status)</span></td>"
            $dcBlock += "<td>$latStr</td>"
            $dcBlock += "</tr>`n"
        }

        $dcBlock += "</tbody></table>`n"
        $dcBlock += "</div>`n"
    }

    # ------------------------------------------------------------------
    # Build Protocol Audit section (donut charts + top-N tables)
    # ------------------------------------------------------------------
    $protoBlock = ''
    $auditData = $EngineContext.DataCache['LegacyProtocolAudit']
    if ($auditData) {
        $protoBlock += "<div class=`"protocol-audit`">`n"
        $protoBlock += "<h2>Legacy Protocol Audit <span class=`"badge`">last $($auditData.AuditHours) hours</span></h2>`n"

        # --- Helper: build SVG donut ---
        function Build-Donut {
            param([double]$Percent1, [string]$Color1, [double]$Percent2, [string]$Color2,
                  [string]$CenterBig, [string]$CenterSmall)
            $r = 60; $cx = 80; $cy = 80; $circ = [math]::Round(2 * [math]::PI * $r, 2)
            $dash1 = [math]::Round($circ * $Percent1 / 100, 2)
            $gap1  = [math]::Round($circ - $dash1, 2)
            $dash2 = [math]::Round($circ * $Percent2 / 100, 2)
            $gap2  = [math]::Round($circ - $dash2, 2)
            $offset2 = $dash1

            $svg  = "<div class=`"donut-wrapper`">`n"
            $svg += "<svg width=`"160`" height=`"160`" viewBox=`"0 0 160 160`">`n"
            # Background ring
            $svg += "<circle cx=`"$cx`" cy=`"$cy`" r=`"$r`" fill=`"none`" stroke=`"#2a2a4a`" stroke-width=`"20`"/>`n"
            # Slice 1
            if ($dash1 -gt 0) {
                $svg += "<circle cx=`"$cx`" cy=`"$cy`" r=`"$r`" fill=`"none`" stroke=`"$Color1`" stroke-width=`"20`" "
                $svg += "stroke-dasharray=`"$dash1 $gap1`" stroke-dashoffset=`"0`"/>`n"
            }
            # Slice 2
            if ($dash2 -gt 0) {
                $svg += "<circle cx=`"$cx`" cy=`"$cy`" r=`"$r`" fill=`"none`" stroke=`"$Color2`" stroke-width=`"20`" "
                $svg += "stroke-dasharray=`"$dash2 $gap2`" stroke-dashoffset=`"-$offset2`"/>`n"
            }
            $svg += "</svg>`n"
            $svg += "<div class=`"donut-center`"><span class=`"big`">$CenterBig</span><span class=`"small`">$CenterSmall</span></div>`n"
            $svg += "</div>`n"
            return $svg
        }

        # --- Helper: build top-N table ---
        function Build-TopTable {
            param([string]$Title, [string]$Col1, [array]$Items)
            if (-not $Items -or $Items.Count -eq 0) { return '' }
            $t  = "<div><h3>$Title</h3>`n"
            $t += "<table class=`"top-table`"><thead><tr><th>$Col1</th><th>Events</th></tr></thead><tbody>`n"
            foreach ($item in $Items) {
                $escaped = [System.Web.HttpUtility]::HtmlEncode($item.Name)
                $t += "<tr><td>$escaped</td><td>$($item.Count)</td></tr>`n"
            }
            $t += "</tbody></table></div>`n"
            return $t
        }

        # ========== Kerberos section ==========
        $krb = $auditData.Kerberos
        if ($krb -and $krb.TotalAll -gt 0) {
            $protoBlock += "<h3>Kerberos Ticket Encryption (4768 / 4769)</h3>`n"
            $protoBlock += "<div class=`"chart-row`">`n"

            # Donut: AES vs RC4 (global)
            $aesP = [double]$krb.AESPercent
            $rc4P = [double]$krb.RC4Percent
            $failP = if ($krb.FailedPercent) { [double]$krb.FailedPercent } else { 0 }
            $othP  = if ($krb.OtherPercent)  { [double]$krb.OtherPercent  } else { 0 }
            $protoBlock += "<div class=`"chart-card`">`n"
            $protoBlock += "<div class=`"chart-title`">All Tickets ($($krb.TotalAll))</div>`n"
            $protoBlock += (Build-Donut $aesP '#00e676' $rc4P '#ff2d55' "$($krb.RC4Percent)%" 'RC4')
            $protoBlock += "<div class=`"chart-legend`">"
            $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#00e676`"></span>AES $($krb.AESCount)</span>"
            $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#ff2d55`"></span>RC4 $($krb.RC4Count)</span>"
            if ($krb.FailedCount -gt 0) {
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#666680`"></span>Failed $($krb.FailedCount)</span>"
            }
            if ($krb.OtherCount -gt 0) {
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#2a2a4a`"></span>Other $($krb.OtherCount)</span>"
            }
            $protoBlock += "</div></div>`n"

            # Donut: TGT breakdown
            $tgtTotal = $krb.TotalTGT
            if ($tgtTotal -gt 0) {
                $tgtAes = $krb.Totals.TGT_AES256 + $krb.Totals.TGT_AES128
                $tgtRc4 = $krb.Totals.TGT_RC4
                $tgtFailed = if ($krb.Totals.TGT_Failed) { $krb.Totals.TGT_Failed } else { 0 }
                $tgtOther  = if ($krb.Totals.TGT_Other)  { $krb.Totals.TGT_Other  } else { 0 }
                $tgtAesP = [math]::Round(100 * $tgtAes / $tgtTotal, 1)
                $tgtRc4P = [math]::Round(100 * $tgtRc4 / $tgtTotal, 1)
                $protoBlock += "<div class=`"chart-card`">`n"
                $protoBlock += "<div class=`"chart-title`">TGT — 4768 ($tgtTotal)</div>`n"
                $protoBlock += (Build-Donut $tgtAesP '#00e676' $tgtRc4P '#ff6b35' "$tgtRc4P%" 'RC4')
                $protoBlock += "<div class=`"chart-legend`">"
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#00e676`"></span>AES $tgtAes</span>"
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#ff6b35`"></span>RC4 $tgtRc4</span>"
                if ($tgtFailed -gt 0) {
                    $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#666680`"></span>Failed $tgtFailed</span>"
                }
                if ($tgtOther -gt 0) {
                    $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#2a2a4a`"></span>Other $tgtOther</span>"
                }
                $protoBlock += "</div></div>`n"
            }

            # Donut: TGS breakdown
            $tgsTotal = $krb.TotalTGS
            if ($tgsTotal -gt 0) {
                $tgsAes = $krb.Totals.TGS_AES256 + $krb.Totals.TGS_AES128
                $tgsRc4 = $krb.Totals.TGS_RC4
                $tgsFailed = if ($krb.Totals.TGS_Failed) { $krb.Totals.TGS_Failed } else { 0 }
                $tgsOther  = if ($krb.Totals.TGS_Other)  { $krb.Totals.TGS_Other  } else { 0 }
                $tgsAesP = [math]::Round(100 * $tgsAes / $tgsTotal, 1)
                $tgsRc4P = [math]::Round(100 * $tgsRc4 / $tgsTotal, 1)
                $protoBlock += "<div class=`"chart-card`">`n"
                $protoBlock += "<div class=`"chart-title`">TGS — 4769 ($tgsTotal)</div>`n"
                $protoBlock += (Build-Donut $tgsAesP '#00e676' $tgsRc4P '#ff6b35' "$tgsRc4P%" 'RC4')
                $protoBlock += "<div class=`"chart-legend`">"
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#00e676`"></span>AES $tgsAes</span>"
                $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#ff6b35`"></span>RC4 $tgsRc4</span>"
                if ($tgsFailed -gt 0) {
                    $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#666680`"></span>Failed $tgsFailed</span>"
                }
                if ($tgsOther -gt 0) {
                    $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#2a2a4a`"></span>Other $tgsOther</span>"
                }
                $protoBlock += "</div></div>`n"
            }

            $protoBlock += "</div>`n"  # end chart-row

            # Top-N tables for RC4
            if ($krb.RC4Count -gt 0) {
                $protoBlock += "<div class=`"top-tables-row`">`n"
                $protoBlock += (Build-TopTable 'Top RC4 TGT Accounts (4768)' 'Account' $krb.TopRC4TGTAccounts)
                $protoBlock += (Build-TopTable 'Top RC4 Service Targets (4769)' 'Service' $krb.TopRC4TGSServices)
                $protoBlock += (Build-TopTable 'Top RC4 Client IPs' 'IP Address' $krb.TopRC4ClientIPs)
                $protoBlock += "</div>`n"
            }

            # Top-N tables for Failed auth and Unknown encryption types
            $hasFailedOrOther = ($krb.FailedCount -gt 0 -or $krb.OtherCount -gt 0)
            if ($hasFailedOrOther) {
                $protoBlock += "<div class=`"top-tables-row`">`n"
                if ($krb.TopFailedAccounts -and $krb.TopFailedAccounts.Count -gt 0) {
                    $protoBlock += (Build-TopTable 'Top Failed Kerberos Auth Accounts' 'Account' $krb.TopFailedAccounts)
                }
                if ($krb.OtherEncTypes -and $krb.OtherEncTypes.Count -gt 0) {
                    $protoBlock += (Build-TopTable 'Unknown Encryption Types (successful tickets)' 'Enc Type' $krb.OtherEncTypes)
                }
                $protoBlock += "</div>`n"
            }
        }
        elseif ($krb) {
            $protoBlock += "<p style=`"color:var(--text-secondary)`">No Kerberos 4768/4769 events found in the last $($auditData.AuditHours) hours.</p>`n"
        }

        # ========== NTLM section ==========
        $ntlm = $auditData.NTLM
        if ($ntlm -and $ntlm.TotalEvents -gt 0) {
            $protoBlock += "<h3>NTLM Authentication (4624 / NtLmSsp)</h3>`n"
            $protoBlock += "<div class=`"chart-row`">`n"

            # Donut: NTLMv1 vs NTLMv2
            $v1P = [double]$ntlm.NTLMv1Percent
            $v2P = [double]$ntlm.NTLMv2Percent
            $v1Color = if ($v1P -gt 0) { '#ff2d55' } else { '#6c757d' }
            $protoBlock += "<div class=`"chart-card`">`n"
            $protoBlock += "<div class=`"chart-title`">NTLM Logons ($($ntlm.TotalEvents))</div>`n"
            $protoBlock += (Build-Donut $v2P '#ffc107' $v1P $v1Color "$(if ($v1P -gt 0) { "$v1P%" } else { '0%' })" 'NTLMv1')
            $protoBlock += "<div class=`"chart-legend`">"
            $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:#ffc107`"></span>NTLMv2 $($ntlm.NTLMv2Count)</span>"
            $protoBlock += "<span class=`"legend-item`"><span class=`"legend-dot`" style=`"background:$v1Color`"></span>NTLMv1 $($ntlm.NTLMv1Count)</span>"
            $protoBlock += "</div></div>`n"
            $protoBlock += "</div>`n"

            # NTLMv1 Top-N tables (only if v1 events exist)
            if ($ntlm.NTLMv1Count -gt 0) {
                $protoBlock += "<h4 style=`"color:#ff2d55;margin-top:1.2em`">NTLMv1 Breakdown</h4>`n"
                $protoBlock += "<div class=`"top-tables-row`">`n"
                $protoBlock += (Build-TopTable 'Top NTLMv1 Accounts' 'Account' $ntlm.TopV1Accounts)
                $protoBlock += (Build-TopTable 'Top NTLMv1 Workstations' 'Workstation' $ntlm.TopV1Workstations)
                $protoBlock += (Build-TopTable 'Top NTLMv1 Source IPs' 'IP Address' $ntlm.TopV1IPs)
                $protoBlock += "</div>`n"
            }

            # NTLMv2 Top-N tables (only if v2 events exist)
            if ($ntlm.NTLMv2Count -gt 0) {
                $protoBlock += "<h4 style=`"color:#ffc107;margin-top:1.2em`">NTLMv2 Breakdown</h4>`n"
                $protoBlock += "<div class=`"top-tables-row`">`n"
                $protoBlock += (Build-TopTable 'Top NTLMv2 Accounts' 'Account' $ntlm.TopV2Accounts)
                $protoBlock += (Build-TopTable 'Top NTLMv2 Workstations' 'Workstation' $ntlm.TopV2Workstations)
                $protoBlock += (Build-TopTable 'Top NTLMv2 Source IPs' 'IP Address' $ntlm.TopV2IPs)
                $protoBlock += "</div>`n"
            }
        }
        elseif ($ntlm) {
            $protoBlock += "<p style=`"color:var(--text-secondary)`">No NTLM logon events found in the last $($auditData.AuditHours) hours.</p>`n"
        }

        $protoBlock += "</div>`n"  # end protocol-audit
    }

    # ------------------------------------------------------------------
    # Build scoring breakdown table
    # ------------------------------------------------------------------
    $scoreBreakdown = ''
    if ($score.CategoryDeductions -and $score.CategoryDeductions.Count -gt 0) {
        $catWeights = $config.Scoring.CategoryWeights
        $defaultWt  = if ($config.Scoring.DefaultCategoryWeight) { $config.Scoring.DefaultCategoryWeight } else { 8 }

        $scoreBreakdown += "<div class=`"score-breakdown`">`n"
        $scoreBreakdown += "<h2>Scoring Breakdown <span class=`"badge`">$($score.Score) / $($score.BaseScore)</span></h2>`n"
        $scoreBreakdown += "<table class=`"dc-table`">`n"
        $scoreBreakdown += "<thead><tr><th>Category</th><th>Budget</th><th>Deduction</th><th>Consumed</th><th>Visual</th></tr></thead>`n"
        $scoreBreakdown += "<tbody>`n"

        foreach ($cat in ($score.CategoryDeductions.GetEnumerator() | Sort-Object Value -Descending)) {
            $budget = if ($catWeights.ContainsKey($cat.Key)) { $catWeights[$cat.Key] } else { $defaultWt }
            $pct = [math]::Round(100 * $cat.Value / $budget)
            $barColor = if ($pct -ge 70) { '#ff2d55' } elseif ($pct -ge 40) { '#ff9500' } else { '#ffc107' }
            $scoreBreakdown += "<tr>"
            $scoreBreakdown += "<td><strong>$($cat.Key)</strong></td>"
            $scoreBreakdown += "<td>$budget pts</td>"
            $scoreBreakdown += "<td>-$($cat.Value) pts</td>"
            $scoreBreakdown += "<td>$pct%</td>"
            $scoreBreakdown += "<td><div style=`"background:#2a2a4a;border-radius:4px;height:16px;width:100%;position:relative`">"
            $scoreBreakdown += "<div style=`"background:$barColor;border-radius:4px;height:100%;width:$pct%`"></div>"
            $scoreBreakdown += "</div></td>"
            $scoreBreakdown += "</tr>`n"
        }
        $scoreBreakdown += "</tbody></table>`n"
        $scoreBreakdown += "</div>`n"
    }

    # ------------------------------------------------------------------
    # Determine grade
    # ------------------------------------------------------------------
    $grade = 'E'
    $grades = $config.Scoring.Grades
    foreach ($g in ($grades.GetEnumerator() | Sort-Object Value -Descending)) {
        if ($score.Score -ge $g.Value) {
            $grade = $g.Key
            break
        }
    }

    $gradeClass = switch ($grade) {
        'A' { 'grade-a' }
        'B' { 'grade-b' }
        'C' { 'grade-c' }
        'D' { 'grade-d' }
        default { 'grade-e' }
    }

    # ------------------------------------------------------------------
    # Replace placeholders in template (use literal .Replace() to avoid
    # regex $-expansion corrupting text with dollar signs, e.g. computer
    # names like MM-DC1$ whose $& sequence is a regex back-reference).
    # ------------------------------------------------------------------
    $companyName = if ($config.Report.CompanyName) { $config.Report.CompanyName } else { 'AD Security Assessment' }
    $dateStr = Get-Date -Format $config.Report.DateFormat

    $html = $template
    $html = $html.Replace('{{TOOL_NAME}}',       [string]$config.General.ToolName)
    $html = $html.Replace('{{VERSION}}',          [string]$config.General.Version)
    $html = $html.Replace('{{COMPANY_NAME}}',     [string]$companyName)
    $html = $html.Replace('{{DATE}}',             [string]$dateStr)
    $html = $html.Replace('{{SCORE}}',            [string]$score.Score)
    $html = $html.Replace('{{GRADE}}',            [string]$grade)
    $html = $html.Replace('{{GRADE_CLASS}}',      [string]$gradeClass)
    $html = $html.Replace('{{TOTAL_FINDINGS}}',   [string]$findings.Count)
    $html = $html.Replace('{{CRITICAL_COUNT}}',   [string]$severityCounts.Critical)
    $html = $html.Replace('{{HIGH_COUNT}}',       [string]$severityCounts.High)
    $html = $html.Replace('{{MEDIUM_COUNT}}',     [string]$severityCounts.Medium)
    $html = $html.Replace('{{LOW_COUNT}}',        [string]$severityCounts.Low)
    $html = $html.Replace('{{INFO_COUNT}}',       [string]$severityCounts.Informational)
    $html = $html.Replace('{{RULES_EVALUATED}}',  [string]$EngineContext.Rules.Count)
    $html = $html.Replace('{{DC_CONNECTIVITY}}',  [string]$dcBlock)
    $html = $html.Replace('{{PROTOCOL_AUDIT}}',   [string]$protoBlock)
    $html = $html.Replace('{{CATEGORY_BLOCKS}}',  [string]$categoryBlocks)
    $html = $html.Replace('{{SCORE_BREAKDOWN}}',  [string]$scoreBreakdown)

    # ------------------------------------------------------------------
    # Write HTML file
    # ------------------------------------------------------------------
    $htmlPath = Join-Path $htmlDir "MATI_Report_$timestamp.html"
    $html | Out-File -FilePath $htmlPath -Encoding UTF8
}

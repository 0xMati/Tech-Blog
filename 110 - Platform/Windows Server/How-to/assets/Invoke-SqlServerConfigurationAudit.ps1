#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$SqlInstance = 'localhost',

    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 128)]
    [string]$Database,

    [switch]$TrustServerCertificate,

    [switch]$GenerateHtml
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Data

function Invoke-ConfigurationQuery {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query,
        [string]$DatabaseName
    )

    $command = $Connection.CreateCommand()
    $command.CommandText = $Query
    $command.CommandTimeout = 30
    $parameter = $command.Parameters.Add('@DatabaseName', [System.Data.SqlDbType]::NVarChar, 128)
    $parameter.Value = if ($DatabaseName) { $DatabaseName } else { [DBNull]::Value }
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $table = New-Object System.Data.DataTable
    try {
        [void]$adapter.Fill($table)
        foreach ($row in $table.Rows) {
            $values = [ordered]@{}
            foreach ($column in $table.Columns) {
                $values[$column.ColumnName] = if ($row.IsNull($column)) { $null } else { $row[$column] }
            }
            [pscustomobject]$values
        }
    }
    finally {
        $adapter.Dispose()
        $command.Dispose()
        $table.Dispose()
    }
}

function Get-SqlConfigurationAudit {
    param([psobject]$Report)

    $ruleHelp = @{
        MEMORY_LIMIT = @('SQL memory budget', 'Without sufficient headroom, SQL Server can compete with Windows and applications for RAM. This snapshot cannot determine a safe limit for your workload.')
        MEMORY_RANGE = @('Minimum and maximum memory', 'An inconsistent range needs investigation. A consistent range alone says nothing about memory pressure or whether the chosen limits are appropriate.')
        HOST_MEMORY = @('Host memory visibility', 'Missing host RAM prevents comparing the SQL limit with physical capacity. A permission failure must not be interpreted as a healthy server.')
        SETTING_VALUE = @('Configured versus running value', 'A difference can mean a pending change or setting-specific behavior. Equality only confirms that the recorded values match, not that they are optimal.')
        PARALLELISM = @('Parallel query configuration', 'Parallelism affects CPU use and query execution. Defaults are not automatically wrong; the right choice depends on CPU topology, workload and application requirements.')
        DATABASE_VISIBILITY = @('Database inventory coverage', 'SQL metadata can be hidden by permissions. An incomplete inventory can hide problems and must not be treated as proof that a database does not exist.')
        DATABASE_STATE = @('Database availability', 'A database that is not ONLINE may be unavailable to applications. Maintenance and restore operations can explain some states; recovery failures need prompt DBA investigation.')
        DATABASE_OPTION = @('Automatic database maintenance options', 'AUTO_CLOSE can add reopen overhead. AUTO_SHRINK can cause repeated file growth and fragmentation. Exceptions need an explicit application or capacity justification.')
        PAGE_VERIFY = @('Page integrity protection', 'CHECKSUM helps detect some storage-related page corruption when pages are read. It does not prevent corruption, verify every existing page immediately, or replace backups and integrity checks.')
        FILE_VISIBILITY = @('File inventory coverage', 'Without visible file metadata, growth and tempdb layout cannot be assessed. Even a nonempty inventory may be incomplete under restricted permissions.')
        FILE_GROWTH = @('File growth predictability', 'Percentage growth changes increment size as a file grows. Disabled growth can cause allocation failures when preallocated space is exhausted, but may be intentional in a managed capacity plan.')
        TEMPDB_LAYOUT = @('tempdb data-file consistency', 'Unequal sizes or growth settings can create uneven allocation patterns. This comparison does not measure contention or determine the correct number of files.')
        CERTIFICATE_VALIDATION = @('Reporting connection identity', 'Bypassing certificate validation keeps encryption but removes certificate-based verification of the SQL endpoint. This finding concerns only this reporting connection.')
    }

    function New-AuditFinding {
        param([string]$RuleId, [string]$Severity, [string]$Target, [string]$Observed, [string]$Recommendation)
        [pscustomobject]@{
            RuleId = $RuleId
            Title = $ruleHelp[$RuleId][0]
            Severity = $Severity
            Target = $Target
            Observed = $Observed
            WhyItMatters = $ruleHelp[$RuleId][1]
            Recommendation = $Recommendation
        }
    }

    $maximum = $Report.Configuration | Where-Object Setting -eq 'max server memory (MB)'
    $minimum = $Report.Configuration | Where-Object Setting -eq 'min server memory (MB)'
    if (-not $maximum -or -not $minimum) {
        New-AuditFinding 'MEMORY_LIMIT' 'Unknown' 'Instance' 'Memory settings missing.' 'Check configuration-query results and SQL permissions.'
    }
    else {
        if ($maximum.RunningValue -eq 2147483647) {
            New-AuditFinding 'MEMORY_LIMIT' 'Warning' 'Instance' 'Max server memory uses the effectively unlimited default.' 'Define an explicit memory budget with the DBA, reserving RAM for Windows, other instances and applications. Do not apply a fixed percentage blindly.'
        }
        elseif (-not $Report.HostMemory) {
            New-AuditFinding 'MEMORY_LIMIT' 'Unknown' 'Instance' "Max memory = $($maximum.RunningValue) MB; host RAM unavailable." 'Obtain host RAM and workload requirements before judging the configured limit.'
        }
        elseif ($maximum.RunningValue -ge $Report.HostMemory.TotalPhysicalMemoryMB) {
            New-AuditFinding 'MEMORY_LIMIT' 'Warning' 'Instance' "Max memory = $($maximum.RunningValue) MB; host RAM = $($Report.HostMemory.TotalPhysicalMemoryMB) MB." 'Review a lower memory budget that leaves headroom for Windows and other consumers. SQL allocations outside this limit also need headroom.'
        }
        else {
            New-AuditFinding 'MEMORY_LIMIT' 'Review' 'Instance' "Max memory = $($maximum.RunningValue) MB; host RAM = $($Report.HostMemory.TotalPhysicalMemoryMB) MB." 'An explicit limit below host RAM is not proof of correct sizing. Validate headroom and memory pressure against representative workload measurements.'
        }
        if ($minimum.RunningValue -gt $maximum.RunningValue) {
            New-AuditFinding 'MEMORY_RANGE' 'Error' 'Instance' 'Running minimum memory exceeds running maximum memory.' 'Verify the collected values and resolve the inconsistent memory range with the DBA.'
        }
        else {
            New-AuditFinding 'MEMORY_RANGE' 'Pass' 'Instance' 'Running minimum does not exceed maximum.' 'No range inconsistency detected; minimum memory is not preallocated at startup.'
        }
    }

    if (-not $Report.HostMemory) {
        New-AuditFinding 'HOST_MEMORY' 'Unknown' 'Host' 'Host RAM query did not return data.' 'Check DMV permissions and collection notes. This audit cannot assess host memory pressure.'
    }
    foreach ($settingName in @('min server memory (MB)', 'max server memory (MB)', 'max degree of parallelism', 'cost threshold for parallelism', 'backup compression default')) {
        $setting = $Report.Configuration | Where-Object Setting -eq $settingName
        if (-not $setting) {
            New-AuditFinding 'SETTING_VALUE' 'Unknown' $settingName 'Setting not returned.' 'Check query results and metadata visibility.'
        }
        elseif ($setting.ConfiguredValue -ne $setting.RunningValue) {
            New-AuditFinding 'SETTING_VALUE' 'Review' $settingName "Configured = $($setting.ConfiguredValue); running = $($setting.RunningValue)." 'Review why the values differ and the setting-specific activation requirements. Do not assume that a restart is needed.'
        }
        else {
            New-AuditFinding 'SETTING_VALUE' 'Pass' $settingName "Configured and running = $($setting.RunningValue)." 'No configured/running mismatch detected; this does not validate the chosen value.'
        }
    }
    foreach ($settingName in @('max degree of parallelism', 'cost threshold for parallelism')) {
        $setting = $Report.Configuration | Where-Object Setting -eq $settingName
        if ($setting) {
            New-AuditFinding 'PARALLELISM' 'Review' $settingName "Running = $($setting.RunningValue)." 'Validate against CPU/NUMA topology, workload measurements and application guidance. The script cannot prescribe a universal value.'
        }
    }

    if ($Report.RequestedDatabase -and -not ($Report.Databases | Where-Object DatabaseName -eq $Report.RequestedDatabase)) {
        New-AuditFinding 'DATABASE_VISIBILITY' 'Unknown' $Report.RequestedDatabase 'Requested database not visible.' 'Verify the instance, database name and SQL permissions; absence from results does not prove absence from SQL Server.'
    }
    if (@($Report.Databases).Count -eq 0) {
        New-AuditFinding 'DATABASE_VISIBILITY' 'Unknown' 'Databases' 'No database metadata returned.' 'Check metadata visibility with the DBA.'
    }
    foreach ($databaseRow in $Report.Databases) {
        $target = $databaseRow.DatabaseName
        $severity = if ($databaseRow.State -eq 'ONLINE') { 'Pass' } elseif ($databaseRow.State -in @('SUSPECT', 'RECOVERY_PENDING', 'EMERGENCY')) { 'Error' } else { 'Review' }
        New-AuditFinding 'DATABASE_STATE' $severity $target $databaseRow.State 'If not ONLINE, verify whether the state is planned; investigate recovery errors with the DBA. Do not force recovery or repair from this report.'
        foreach ($option in @('AutoClose', 'AutoShrink')) {
            $severity = if ($databaseRow.$option) { 'Warning' } else { 'Pass' }
            New-AuditFinding 'DATABASE_OPTION' $severity "$target / $option" "$($databaseRow.$option)" 'Normally keep AUTO_CLOSE and AUTO_SHRINK disabled on production databases. If enabled, validate application requirements and plan disabling with the DBA.'
        }
        $severity = if ($databaseRow.PageVerify -eq 'CHECKSUM') { 'Pass' } else { 'Warning' }
        New-AuditFinding 'PAGE_VERIFY' $severity $target $databaseRow.PageVerify 'Prefer CHECKSUM unless a documented exception applies. Enabling it does not retroactively validate existing pages or replace DBCC CHECKDB and backups.'
    }
    if (@($Report.Files).Count -eq 0) {
        New-AuditFinding 'FILE_VISIBILITY' 'Unknown' 'Files' 'No file metadata returned.' 'Check file metadata permissions before assessing file growth or tempdb.'
    }
    foreach ($file in $Report.Files) {
        $target = "$($file.DatabaseName) / $($file.LogicalName)"
        $severity = if ($file.IsPercentGrowth -or $file.GrowthRaw -eq 0) { 'Review' } else { 'Pass' }
        New-AuditFinding 'FILE_GROWTH' $severity $target "SizeMB = $($file.SizeMB); percent growth = $($file.IsPercentGrowth); growth raw = $($file.GrowthRaw); growth MB = $($file.GrowthMB)." 'Prefer predictable fixed-MB growth with appropriate pre-sizing. Disabled growth may be intentional; verify free disk space, file limits and capacity policy before changing it. A Pass does not validate the growth increment.'
    }
    $tempdbFiles = @($Report.Files | Where-Object { $_.DatabaseName -eq 'tempdb' -and $_.FileType -eq 'ROWS' })
    if ($tempdbFiles.Count -gt 1) {
        $layouts = @($tempdbFiles | Select-Object SizeMB, IsPercentGrowth, GrowthRaw -Unique)
        $severity = if ($layouts.Count -gt 1) { 'Review' } else { 'Pass' }
        New-AuditFinding 'TEMPDB_LAYOUT' $severity 'tempdb data files' "$($tempdbFiles.Count) files; $($layouts.Count) size/growth combinations." 'Normally align data-file sizes and growth settings. Validate intended layout with the DBA; file count must be based on contention and CPU topology, not this snapshot.'
    }
    $severity = if ($Report.TrustServerCertificate) { 'Review' } else { 'Pass' }
    New-AuditFinding 'CERTIFICATE_VALIDATION' $severity 'Reporting connection' "TrustServerCertificate = $($Report.TrustServerCertificate)." 'For durable use, validate the SQL certificate chain and server name. This checks only this reporting connection, not every SQL client or server encryption policy.'
}

function Export-SqlConfigurationReport {
    param(
        [psobject]$Report,
        [string]$Directory,
        [switch]$GenerateHtml
    )

    [void][System.IO.Directory]::CreateDirectory($Directory)
    $fileName = 'SqlServerConfigurationAudit_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $jsonPath = Join-Path $Directory ($fileName + '.json')
    $Report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
    $htmlPath = $null

    if ($GenerateHtml) {
        $htmlPath = Join-Path $Directory ($fileName + '.html')
        function ConvertTo-ReportText {
            param([object]$Value)
            [System.Net.WebUtility]::HtmlEncode([string]$Value)
        }
        $severityOrder = @{ Error = 0; Warning = 1; Unknown = 2; Review = 3; Pass = 4 }
        $findingHtml = foreach ($finding in ($Report.AuditFindings | Sort-Object { $severityOrder[$_.Severity] }, RuleId, Target)) {
            $severity = if ($severityOrder.ContainsKey([string]$finding.Severity)) { [string]$finding.Severity } else { 'Unknown' }
            $title = if ($finding.Title) { $finding.Title } else { $finding.RuleId }
            $impact = if ($finding.WhyItMatters) { $finding.WhyItMatters } else { 'Review this observation with the database owner before deciding on a change.' }
            '<details class="finding" data-severity="{0}" open><summary><span class="badge {0}">{0}</span><span class="finding-name">{1}<small>{2}</small></span><span class="rule">{3}</span></summary><div class="finding-body"><dl><dt>Observed</dt><dd>{4}</dd><dt>Why it matters</dt><dd>{5}</dd><dt>Recommended next step</dt><dd>{6}</dd></dl></div></details>' -f $severity, (ConvertTo-ReportText $title), (ConvertTo-ReportText $finding.Target), (ConvertTo-ReportText $finding.RuleId), (ConvertTo-ReportText $finding.Observed), (ConvertTo-ReportText $impact), (ConvertTo-ReportText $finding.Recommendation)
        }
        $countsHtml = foreach ($severity in @('Error', 'Warning', 'Unknown', 'Review', 'Pass')) {
            $count = @($Report.AuditFindings | Where-Object Severity -eq $severity).Count
            '<div class="stat"><span class="badge {0}">{0}</span><strong>{1}</strong></div>' -f $severity, $count
        }
        $sections = [ordered]@{
            'Instance' = @($Report.Instance)
            'Host memory (MB)' = @($Report.HostMemory)
            'Instance settings' = @($Report.Configuration)
            'Databases' = @($Report.Databases)
            'Files' = @($Report.Files)
            'Review notes' = @($Report.ReviewNotes | ForEach-Object { [pscustomobject]@{ Note = $_ } })
        }
        $body = foreach ($section in $sections.GetEnumerator()) {
            '<details class="evidence"><summary>{0}</summary>' -f $section.Key
            $rows = @($section.Value | Where-Object { $null -ne $_ })
            if ($rows.Count) {
                '<div class="table-scroll">'
                $rows | ConvertTo-Html -Fragment
                '</div>'
            }
            else {
                '<p>No data available.</p>'
            }
                        '</details>'
        }
                $template = @'
<!DOCTYPE html>
<html lang="en"><head><title>SQL Server configuration audit</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* { box-sizing: border-box; } [hidden] { display: none !important; }
:root { --ink: #20292d; --muted: #58676b; --line: #d6dfe0; --accent: #086f67; }
body { margin: 0; color: var(--ink); background: #f4f6f6; font: 15px/1.55 "Segoe UI", sans-serif; letter-spacing: 0; }
header { background: #fff; border-top: 5px solid var(--accent); border-bottom: 1px solid var(--line); padding: 28px max(20px, calc((100% - 1160px)/2)); }
main { max-width: 1200px; padding: 24px 20px 48px; margin: auto; }
h1 { font-size: 26px; margin: 0 0 8px; } h2 { font-size: 20px; margin: 28px 0 12px; }
p { margin: 8px 0; } .context, .scope, small, .rule { color: var(--muted); }
.context { overflow-wrap: anywhere; } .scope { font-size: 13px; }
.stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); border: 1px solid var(--line); background: #fff; }
.stat { padding: 16px; border-right: 1px solid var(--line); } .stat:last-child { border: 0; }
.stat strong { display: block; font-size: 28px; margin-top: 8px; }
.badge { display: inline-block; font-size: 12px; font-weight: 650; padding: 2px 8px; border-radius: 4px; }
.Error { color: #9b2232; background: #fbe8eb; } .Warning { color: #815000; background: #fff0cc; }
.Unknown { color: #4a4b8b; background: #ededfa; } .Review { color: #075d88; background: #e1f1fa; } .Pass { color: #246342; background: #e4f3ea; }
.toolbar { display: flex; align-items: end; flex-wrap: wrap; gap: 16px; padding: 16px 0; border-block: 1px solid var(--line); }
label { display: grid; gap: 5px; font-size: 13px; } .search { flex: 1 1 240px; }
input[type=search], select { min-height: 40px; border: 1px solid #aab9bb; border-radius: 4px; background: #fff; padding: 8px; font: inherit; color: var(--ink); width: 100%; }
.toggle { display: flex; align-items: center; gap: 8px; min-height: 40px; } input[type=checkbox] { accent-color: var(--accent); width: 17px; height: 17px; }
:focus-visible { outline: 3px solid #329d97; outline-offset: 3px; }
#result-count { font-size: 13px; color: var(--muted); margin: 12px 0; }
.finding { background: #fff; border: 1px solid var(--line); border-radius: 6px; margin: 10px 0; }
.finding summary { display: flex; align-items: center; gap: 12px; padding: 15px; cursor: pointer; }
.finding summary::before { content: '+'; color: var(--muted); } .finding[open] summary::before { content: '-'; }
.finding-name { flex: 1; min-width: 0; font-weight: 650; overflow-wrap: anywhere; } small { display: block; font-size: 12px; font-weight: normal; }
.rule { font: 11px/1.5 Consolas, monospace; overflow-wrap: anywhere; } .finding-body { padding: 0 18px 16px; border-top: 1px solid #edf0f0; }
dl { display: grid; grid-template-columns: 170px minmax(0, 1fr); gap: 10px 18px; margin: 16px 0 0; }
dt { font-weight: 650; font-size: 13px; } dd { margin: 0; overflow-wrap: anywhere; }
.evidence { border-bottom: 1px solid var(--line); padding: 12px 0; } .evidence summary { font-weight: 650; cursor: pointer; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; margin-top: 12px; background: #fff; }
th, td { border: 1px solid var(--line); padding: 9px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #eaf0ef; } tr:nth-child(even) { background: #f8fafa; }
@media (max-width: 640px) { header { padding: 20px; } .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); } .stat { padding: 10px; border-bottom: 1px solid var(--line); } .stat strong { font-size: 22px; } .badge { padding: 2px 5px; } .finding summary { flex-wrap: wrap; } .rule { flex-basis: 100%; padding-left: 24px; } dl { grid-template-columns: 1fr; gap: 5px; } dd { margin-bottom: 12px; } }
@media print { .toolbar, #result-count { display: none; } body { background: #fff; } .finding { break-inside: avoid; } }
</style>
</head><body><header><h1>SQL Server configuration audit</h1><p class="context">__CONTEXT__</p><p class="scope">Basic configuration review. No SQL changes performed. Metadata visibility may be incomplete; this is not a health or compliance certification.</p></header>
<main><section class="stats" aria-label="Finding totals">__COUNTS__</section>
<h2>Findings and recommended actions</h2>
<div class="toolbar"><label class="search">Search findings<input id="search" type="search" placeholder="Database, setting, observation..."></label><label>Severity<select id="severity"><option value="all">All severities</option><option>Error</option><option>Warning</option><option>Unknown</option><option>Review</option><option>Pass</option></select></label><label class="toggle"><input id="show-pass" type="checkbox">Show passed checks</label></div>
<p id="result-count" role="status" aria-live="polite"></p><p class="scope">Error: investigate promptly. Warning: configuration risk. Review: context-dependent decision. Unknown: missing evidence. Pass: only the specific condition checked was satisfied.</p>
<noscript><p>Interactive filters require JavaScript. All findings are displayed below.</p></noscript>
<section id="findings" aria-label="Audit findings">__FINDINGS__</section><p id="empty" hidden>No findings match the selected filters.</p>
<h2>Collected evidence</h2>__EVIDENCE__</main>
<script>
const findings = Array.from(document.querySelectorAll('.finding'));
const search = document.getElementById('search');
const severity = document.getElementById('severity');
const showPass = document.getElementById('show-pass');
function filterFindings() {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    findings.forEach(finding => {
        const level = finding.dataset.severity;
        const matchesSeverity = severity.value === 'all' ? (showPass.checked || level !== 'Pass') : level === severity.value;
        finding.hidden = !(matchesSeverity && finding.textContent.toLowerCase().includes(query));
        if (!finding.hidden) visible++;
    });
    showPass.disabled = severity.value !== 'all';
    document.getElementById('result-count').textContent = visible + ' of ' + findings.length + ' findings shown';
    document.getElementById('empty').hidden = visible !== 0;
}
search.addEventListener('input', filterFindings);
severity.addEventListener('change', filterFindings);
showPass.addEventListener('change', filterFindings);
filterFindings();
</script></body></html>
'@
                $context = '{0} | Database: {1} | Collected: {2}' -f $Report.RequestedInstance, $(if ($Report.RequestedDatabase) { $Report.RequestedDatabase } else { 'All visible databases' }), $Report.CollectedAt
                $replacements = @{
                        '__CONTEXT__' = ConvertTo-ReportText $context
                        '__COUNTS__' = $countsHtml -join "`n"
                        '__FINDINGS__' = $findingHtml -join "`n"
                        '__EVIDENCE__' = $body -join "`n"
                }
                $html = [regex]::Replace($template, '__CONTEXT__|__COUNTS__|__FINDINGS__|__EVIDENCE__', [System.Text.RegularExpressions.MatchEvaluator]{ param($placeholder) $replacements[$placeholder.Value] })
                $html | Out-File -FilePath $htmlPath -Encoding utf8
    }

    [pscustomobject]@{ Json = $jsonPath; Html = $htmlPath }
}

$builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$builder['Data Source'] = $SqlInstance
$builder['Initial Catalog'] = 'master'
$builder['Integrated Security'] = $true
$builder['Encrypt'] = $true
$builder['TrustServerCertificate'] = $TrustServerCertificate.IsPresent
$builder['Connect Timeout'] = 15
$builder['Application Name'] = 'SQL Server configuration audit'
$connection = New-Object System.Data.SqlClient.SqlConnection $builder.ConnectionString
$notes = New-Object 'System.Collections.Generic.List[string]'

try {
    $connection.Open()
    $instance = Invoke-ConfigurationQuery -Connection $connection -Query @'
SELECT CONVERT(nvarchar(128), SERVERPROPERTY('ServerName')) AS ServerName,
       CONVERT(nvarchar(128), SERVERPROPERTY('MachineName')) AS MachineName,
       COALESCE(CONVERT(nvarchar(128), SERVERPROPERTY('InstanceName')), N'MSSQLSERVER') AS InstanceName,
       CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS ProductVersion,
       CONVERT(nvarchar(128), SERVERPROPERTY('Edition')) AS Edition;
'@
    $configuration = @(Invoke-ConfigurationQuery -Connection $connection -Query @'
SELECT name AS Setting, CONVERT(bigint, value) AS ConfiguredValue,
       CONVERT(bigint, value_in_use) AS RunningValue
FROM sys.configurations
WHERE name IN ('min server memory (MB)', 'max server memory (MB)',
               'max degree of parallelism', 'cost threshold for parallelism',
               'backup compression default')
ORDER BY name;
'@)
    $databaseStatus = @(Invoke-ConfigurationQuery -Connection $connection -DatabaseName $Database -Query @'
SELECT name AS DatabaseName, state_desc AS State, recovery_model_desc AS RecoveryModel,
       compatibility_level AS CompatibilityLevel, page_verify_option_desc AS PageVerify,
       is_auto_close_on AS AutoClose, is_auto_shrink_on AS AutoShrink
FROM sys.databases
WHERE @DatabaseName IS NULL OR name = @DatabaseName OR name = N'tempdb';
'@)
    $files = @(Invoke-ConfigurationQuery -Connection $connection -DatabaseName $Database -Query @'
SELECT DB_NAME(database_id) AS DatabaseName, name AS LogicalName, type_desc AS FileType,
       physical_name AS PhysicalPath, CONVERT(decimal(18,2), size / 128.0) AS SizeMB,
       is_percent_growth AS IsPercentGrowth, growth AS GrowthRaw,
       CASE WHEN is_percent_growth = 0 THEN CONVERT(decimal(18,2), growth / 128.0) END AS GrowthMB,
       max_size AS MaxSizePages
FROM sys.master_files
WHERE @DatabaseName IS NULL OR database_id IN (DB_ID(@DatabaseName), DB_ID(N'tempdb'))
ORDER BY database_id, file_id;
'@)
    $hostMemory = $null
    try {
        $hostMemory = Invoke-ConfigurationQuery -Connection $connection -Query @'
SELECT CONVERT(bigint, total_physical_memory_kb / 1024) AS TotalPhysicalMemoryMB,
       CONVERT(bigint, available_physical_memory_kb / 1024) AS AvailablePhysicalMemoryMB,
       system_memory_state_desc AS MemoryState
FROM sys.dm_os_sys_memory;
'@
    }
    catch {
        $notes.Add("Host memory unavailable; check DMV permissions. Details: $($_.Exception.Message)")
    }

    $maximum = $configuration | Where-Object Setting -eq 'max server memory (MB)'
    if ($maximum.RunningValue -eq 2147483647) {
        $notes.Add('Max server memory uses the default effectively unlimited value. Review the memory budget with the DBA.')
    }
    if ($hostMemory -and $maximum.RunningValue -ge $hostMemory.TotalPhysicalMemoryMB) {
        $notes.Add('Max server memory is at least the host physical RAM. Reserve memory for Windows, other SQL instances and applications.')
    }
    if (@($configuration | Where-Object { $_.ConfiguredValue -ne $_.RunningValue }).Count) {
        $notes.Add('Some configured values differ from running values. Review pending changes with the DBA.')
    }
    if ($Database -and -not ($databaseStatus | Where-Object DatabaseName -eq $Database)) {
        $notes.Add("Database '$Database' was not visible. Check the instance, database name and metadata permissions.")
    }
    foreach ($databaseRow in $databaseStatus) {
        if ($databaseRow.AutoClose -or $databaseRow.AutoShrink -or $databaseRow.PageVerify -ne 'CHECKSUM' -or $databaseRow.State -ne 'ONLINE') {
            $notes.Add("Review database '$($databaseRow.DatabaseName)': state, AUTO_CLOSE, AUTO_SHRINK or PAGE_VERIFY needs attention.")
        }
    }
    if ($files | Where-Object { $_.IsPercentGrowth -or $_.GrowthRaw -eq 0 }) {
        $notes.Add('Some visible files use percentage growth or have autogrowth disabled. Review capacity and growth settings; no change was made.')
    }
    $notes.Add('Metadata visibility depends on SQL permissions; missing rows do not prove that a database or file is absent.')
    $report = [pscustomobject]@{
        CollectedAt = (Get-Date).ToString('o')
        RequestedInstance = $SqlInstance
        RequestedDatabase = $Database
        TrustServerCertificate = $TrustServerCertificate.IsPresent
        Instance = $instance
        Configuration = $configuration
        HostMemory = $hostMemory
        Databases = $databaseStatus
        Files = $files
        ReviewNotes = $notes.ToArray()
    }
}
finally {
    $connection.Dispose()
}

$findings = @(Get-SqlConfigurationAudit -Report $report)
$summary = [pscustomobject]@{
    Scope = 'Basic configuration review only; metadata visibility may be incomplete. Not a compliance or health certification.'
    Error = @($findings | Where-Object Severity -eq 'Error').Count
    Warning = @($findings | Where-Object Severity -eq 'Warning').Count
    Review = @($findings | Where-Object Severity -eq 'Review').Count
    Unknown = @($findings | Where-Object Severity -eq 'Unknown').Count
    Pass = @($findings | Where-Object Severity -eq 'Pass').Count
}
$report | Add-Member -NotePropertyName AuditFindings -NotePropertyValue $findings
$report | Add-Member -NotePropertyName AuditSummary -NotePropertyValue $summary
$reportFiles = Export-SqlConfigurationReport -Report $report -Directory (Join-Path $PSScriptRoot 'Reports') -GenerateHtml:$GenerateHtml
$report | Add-Member -NotePropertyName ReportFiles -NotePropertyValue $reportFiles
$report
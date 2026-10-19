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

    function New-AuditFinding {
        param([string]$RuleId, [string]$Severity, [string]$Target, [string]$Observed, [string]$Recommendation)
        [pscustomobject]@{
            RuleId = $RuleId
            Severity = $Severity
            Target = $Target
            Observed = $Observed
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
    $fileName = 'SqlServerConfiguration_{0}_{1}' -f (Get-Date -Format 'yyyyMMdd_HHmmss'), ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $jsonPath = Join-Path $Directory ($fileName + '.json')
    $Report | ConvertTo-Json -Depth 8 | Out-File -FilePath $jsonPath -Encoding utf8
    $htmlPath = $null

    if ($GenerateHtml) {
        $htmlPath = Join-Path $Directory ($fileName + '.html')
        $sections = [ordered]@{
            'Collection' = @($Report | Select-Object CollectedAt, RequestedInstance, RequestedDatabase)
            'Audit summary' = @($Report.AuditSummary)
            'Audit findings and recommended actions' = @($Report.AuditFindings)
            'Instance' = @($Report.Instance)
            'Host memory (MB)' = @($Report.HostMemory)
            'Instance settings' = @($Report.Configuration)
            'Databases' = @($Report.Databases)
            'Files' = @($Report.Files)
            'Review notes' = @($Report.ReviewNotes | ForEach-Object { [pscustomobject]@{ Note = $_ } })
        }
        $body = foreach ($section in $sections.GetEnumerator()) {
            '<h2>{0}</h2>' -f $section.Key
            $rows = @($section.Value | Where-Object { $null -ne $_ })
            if ($rows.Count) {
                '<div class="table-scroll">'
                $rows | ConvertTo-Html -Fragment
                '</div>'
            }
            else {
                '<p>No data available.</p>'
            }
        }
        $head = @'
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: "Segoe UI", sans-serif; margin: 2rem; color: #202124; background: #fff; }
h1 { font-size: 1.7rem; border-bottom: 3px solid #16746b; padding-bottom: .6rem; }
h2 { font-size: 1.2rem; margin-top: 2rem; }
.table-scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { border: 1px solid #d5d9dc; padding: .5rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
th { background: #edf4f3; }
tr:nth-child(even) { background: #f7f8f9; }
</style>
'@
        ConvertTo-Html -Title 'SQL Server configuration report' -Head $head -Body (@('<h1>SQL Server configuration report</h1>') + $body -join "`n") |
            Out-File -FilePath $htmlPath -Encoding utf8
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
$builder['Application Name'] = 'SQL Server configuration report'
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
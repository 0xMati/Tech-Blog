#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$SqlInstance = 'localhost',

    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 128)]
    [string]$Database,

    [switch]$TrustServerCertificate
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

$builder = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
$builder.DataSource = $SqlInstance
$builder.InitialCatalog = 'master'
$builder.IntegratedSecurity = $true
$builder.Encrypt = $true
$builder.TrustServerCertificate = $TrustServerCertificate.IsPresent
$builder.ConnectTimeout = 15
$builder.ApplicationName = 'SQL Server configuration report'
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
    [pscustomobject]@{
        CollectedAt = (Get-Date).ToString('o')
        RequestedInstance = $SqlInstance
        RequestedDatabase = $Database
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
---
title: "Check SQL Server configuration with PowerShell"
date: 2026-10-19
---

# Check SQL Server configuration with PowerShell

A small read-only report for a SQL Server instance: memory limits, basic parallelism settings, database options and file growth. It provides a configuration snapshot, not a performance audit or an automatic tuning recommendation.

Download the [Get-SqlServerConfiguration.ps1 script](assets/Get-SqlServerConfiguration.ps1).

## Prerequisites

- Windows PowerShell 5.1 and the built-in .NET Framework SQL client. No `SqlServer` PowerShell module is required.
- Windows authentication: the script connects with the current Windows identity. Local administrator access does not automatically grant SQL access.
- A SQL login mapped to that identity with access to `master` and sufficient metadata visibility. Ask the DBA for read-only reporting permissions rather than granting `sysadmin` just for this script. Database and file results can be incomplete when permissions restrict visibility.
- For host RAM information from `sys.dm_os_sys_memory`: `VIEW SERVER STATE` on SQL Server 2019 and earlier, or `VIEW SERVER PERFORMANCE STATE` on SQL Server 2022 and later. If this optional query fails, the rest of the report is retained and a note records the failure. Failures in the other queries stop the script.
- Network access to the selected SQL instance. The script does not enable protocols, open firewall ports or discover instances.

The connection is encrypted and validates the SQL Server certificate by default. Use a server name matching the certificate and a trusted certificate chain. For an approved diagnostic exception only, `-TrustServerCertificate` keeps encryption but bypasses certificate validation; it is not a fix for certificate configuration.

## Collect and display

Run from the directory containing the script. The default target is the local default instance; without a database filter, all visible databases, including system databases, are reported.

```powershell
$report = .\Get-SqlServerConfiguration.ps1 -SqlInstance 'localhost'
$report.Instance | Format-List
$report.HostMemory | Format-List
$report.Configuration | Format-Table -AutoSize
$report.Databases | Format-Table -AutoSize
$report.Files | Format-List
$report.ReviewNotes
```

For a named instance and a specific database, use single quotes to preserve the instance name. With `-Database`, database and file sections include the selected database **and tempdb**; instance settings and RAM information remain instance-wide.

```powershell
$report = .\Get-SqlServerConfiguration.ps1 -SqlInstance 'SQL01\APP' -Database 'ApplicationDB'
```

For example, on an Entra Connect server using a full local default SQL Server instance and the `ADSync` database:

```powershell
$report = .\Get-SqlServerConfiguration.ps1 -SqlInstance 'localhost' -Database 'ADSync'
```

This example does not discover the SQL instance used by the application. Confirm the actual connection settings first; LocalDB uses a different connection name and access context.

## Export the report

The script returns one structured PowerShell object. Formatting is optional and separate from collection, so the same object can be exported without losing nested sections.

```powershell
$report | ConvertTo-Json -Depth 6 |
    Out-File -FilePath '.\SqlServerConfiguration.json' -Encoding utf8
$report.Configuration |
    Export-Csv -Path '.\SqlServerSettings.csv' -NoTypeInformation -Encoding utf8
```

Only these explicit export commands write local files; the script does not change SQL configuration or application data. Protect the reports: they contain server names, database names and physical file paths.

## Read the results

| Section | What to review |
| --- | --- |
| Instance | Server, instance, version and edition. Patch currency must be checked separately. |
| HostMemory | Total and currently available physical RAM on the SQL host, not the workstation running the script. Available RAM is a point-in-time measurement. |
| Configuration | Configured and running values for min/max memory, MAXDOP, cost threshold for parallelism and default backup compression. Differences require review, not necessarily a restart. |
| Databases | State, recovery model, compatibility level, PAGE_VERIFY, AUTO_CLOSE and AUTO_SHRINK. Recovery model must match the backup and recovery strategy. |
| Files | Data/log paths, allocated size and autogrowth. Size is allocated file size, not used space. `GrowthRaw` is a percentage when `IsPercentGrowth` is true; otherwise use `GrowthMB`. `MaxSizePages` is in 8-KB pages (`-1` means growth up to applicable limits). |
| ReviewNotes | Basic review prompts: default effectively unlimited max memory, max memory at least physical RAM, differing configured/running values, database options or file growth needing attention, and metadata visibility limitations. These are not compliance failures. |

### Memory on a shared server

The default `max server memory (MB)` value is `2147483647`. Review an explicit memory budget with the DBA, reserving RAM for Windows, other SQL instances and co-located applications. On an Entra Connect server, this includes the synchronization engine.

`max server memory` does **not** cap every allocation made by the SQL Server process, and `min server memory` is not a preallocated reservation at startup. A limit below total host RAM is not proof of correct sizing. The script deliberately does not apply a fixed percentage or recommend a value without workload measurements.

Likewise, do not automatically change MAXDOP, recovery model or tempdb layout based on this snapshot. File-growth notes can have valid explanations, particularly for deliberately pre-sized system files. Correlate findings with capacity planning, backup policy, application guidance and performance collection.

## Scope and validation

This first version does not inspect disk free space, backup history, log usage, wait statistics, query performance or all SQL security settings. Missing metadata is not proof that a database or file is absent. An empty review list is not a health certificate.

PowerShell syntax and SELECT-only query content were checked locally. Execution against a live SQL Server instance remains to be validated in the target environment.

## References

- [Server memory configuration options](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-memory-server-configuration-options).
- [sys.dm_os_sys_memory and required permissions](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-sys-memory-transact-sql).
- [Metadata visibility configuration](https://learn.microsoft.com/en-us/sql/relational-databases/security/metadata-visibility-configuration).
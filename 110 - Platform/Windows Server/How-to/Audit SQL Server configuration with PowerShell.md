---
title: "Basic SQL Server Configuration Audit with PowerShell"
date: 2026-10-19
---

# Basic SQL Server Configuration Audit with PowerShell

A basic read-only audit of standard SQL Server configuration settings: memory limits, basic parallelism settings, database options and file growth. Its purpose is to identify common configuration risks and deviations from a production baseline, explain them and recommend next steps, not just inventory values. Context-dependent settings are flagged for review rather than judged against arbitrary universal values. It is not a comprehensive security assessment, performance audit or automatic tuning tool: no SQL setting is changed.

Download the [Invoke-SqlServerConfigurationAudit.ps1 script](assets/Invoke-SqlServerConfigurationAudit.ps1).

## Prerequisites

- Windows PowerShell 5.1 and the built-in .NET Framework SQL client. No `SqlServer` PowerShell module is required.
- Windows authentication: the script connects with the current Windows identity. Local administrator access does not automatically grant SQL access.
- A SQL login mapped to that identity with access to `master` and sufficient metadata visibility. Ask the DBA for read-only reporting permissions rather than granting `sysadmin` just for this script. Database and file results can be incomplete when permissions restrict visibility.
- For host RAM information from `sys.dm_os_sys_memory`: `VIEW SERVER STATE` on SQL Server 2019 and earlier, or `VIEW SERVER PERFORMANCE STATE` on SQL Server 2022 and later. If this optional query fails, the rest of the report is retained and a note records the failure. Failures in the other queries stop the script.
- Network access to the selected SQL instance. The script does not enable protocols, open firewall ports or discover instances.
- Write permission next to the script: each successful collection creates a JSON file in a `Reports` subdirectory there.

The connection is encrypted and validates the SQL Server certificate by default. Use a server name matching the certificate and a trusted certificate chain. For an approved diagnostic exception only, `-TrustServerCertificate` keeps encryption but bypasses certificate validation; it is not a fix for certificate configuration.

## Collect and display

Run from the directory containing the script. The default target is the local default instance; without a database filter, all visible databases, including system databases, are reported.

```powershell
$report = .\Invoke-SqlServerConfigurationAudit.ps1 -SqlInstance 'localhost'
$report.Instance | Format-List
$report.HostMemory | Format-List
$report.Configuration | Format-Table -AutoSize
$report.Databases | Format-Table -AutoSize
$report.Files | Format-List
$report.ReviewNotes
```

For a named instance and a specific database, use single quotes to preserve the instance name. With `-Database`, database and file sections include the selected database **and tempdb**; instance settings and RAM information remain instance-wide.

```powershell
$report = .\Invoke-SqlServerConfigurationAudit.ps1 -SqlInstance 'SQL01\APP' -Database 'ApplicationDB'
```

For example, on an Entra Connect server using a full local default SQL Server instance and the `ADSync` database:

```powershell
$report = .\Invoke-SqlServerConfigurationAudit.ps1 -SqlInstance 'localhost' -Database 'ADSync'
```

This example does not discover the SQL instance used by the application. Confirm the actual connection settings first; LocalDB uses a different connection name and access context.

### Untrusted SQL Server certificate

If the connection fails with **"The certificate chain was issued by an authority that is not trusted"**, the SQL endpoint was reached but its certificate chain could not be validated. For an approved local diagnostic exception, run:

```powershell
$report = .\Invoke-SqlServerConfigurationAudit.ps1 -SqlInstance 'localhost' -Database 'ADSync' -TrustServerCertificate
$report.Configuration | Format-Table -AutoSize
$report.HostMemory | Format-List
$report.ReviewNotes
```

The connection remains encrypted, but **server certificate validation is bypassed**. Do not make this the default: the durable fix is a valid SQL Server certificate with a trusted certificate chain, accessed using a server name matching that certificate.

## Export the report

Every successful collection automatically creates a `Reports` directory **next to the script**, using `$PSScriptRoot`, not the shell's current working directory. A JSON snapshot is saved there with a timestamp and unique suffix, for example `SqlServerConfigurationAudit_20261019_143000_a1b2c3d4.json`. Previous reports are not overwritten.

Add `-GenerateHtml` to also create a self-contained HTML report with the same filename stem. The HTML begins with collection context, severity counters and expandable findings, followed by collapsed raw-evidence sections. It uses no external resources and can be opened directly in a browser. For the local ADSync example, including the approved certificate exception described above:

```powershell
$report = .\Invoke-SqlServerConfigurationAudit.ps1 -SqlInstance 'localhost' -Database 'ADSync' -TrustServerCertificate -GenerateHtml
$report.ReportFiles | Format-List
Invoke-Item -LiteralPath $report.ReportFiles.Html
```

Omit `-TrustServerCertificate` when the certificate can be validated. The JSON export is always enabled; HTML is optional. Both files describe the same collection, with no second SQL query pass. If the optional host-memory query fails, the report still includes its diagnostic note; a fatal collection error produces no report.

The script still returns one structured PowerShell object for console inspection or additional exports. `ReportFiles` contains the generated paths on that returned object; it is not part of the saved snapshot. For an additional CSV export:

```powershell
$report.Configuration |
    Export-Csv -Path (Join-Path (Split-Path $report.ReportFiles.Json) 'SqlServerSettings.csv') -NoTypeInformation -Encoding utf8
```

The script writes local report files but does not change SQL configuration or application data. Protect the reports: they contain server names, database names and physical file paths. No retention cleanup is performed; manage access, disk space and deletion according to your reporting policy.

### Navigate the HTML audit

- **Severity counters** show totals for the complete collection, regardless of active filters.
- **Show passed checks** is unchecked by default: successful checks are retained but hidden to prioritize work. Enable it to include Pass findings when viewing all severities.
- **Severity** selects one level. Selecting Pass explicitly displays passed checks even if the checkbox is unchecked; the checkbox only applies to All severities.
- **Search findings** filters titles, targets, observations, explanations and recommendations. Search and severity filters combine; the visible/total count and empty state reflect both.
- Findings are ordered Error, Warning, Unknown, Review, then Pass, and can be individually expanded or collapsed. Unknown appears before Review because missing evidence can block a conclusion.
- Each finding separates **Observed** (collected evidence), **Why it matters** (potential impact and interpretation limits), and **Recommended next step** (a proposed investigation or change to validate).
- **Collected evidence** contains expandable source tables. These are not filtered, so supporting data remains available for investigation.

Filtering changes only the view: the JSON and HTML still contain every finding. The HTML runs locally without a server or external library. JavaScript is required for filtering; without it, all findings remain readable. A hidden Pass is not a missing check, and the counters are not a compliance score.

## Read the results

Start with the mini-audit, then inspect the raw evidence for each finding:

```powershell
$report.AuditSummary | Format-List
$report.AuditFindings |
    Where-Object { $_.Severity -ne 'Pass' } |
    Format-List RuleId, Title, Severity, Target, Observed, WhyItMatters, Recommendation
```

| Section | What to review |
| --- | --- |
| AuditSummary | Counts of Error, Warning, Review, Unknown and Pass findings, with an explicit limited-scope statement. Counts are findings, not distinct servers or rules. There is no global compliance score. |
| AuditFindings | One row per evaluated rule and target: `RuleId`, `Title`, `Severity`, `Target`, `Observed`, `WhyItMatters` and `Recommendation`. Included in both JSON and HTML. Titles and impact explanations add context; severity still comes from the documented rules. |
| Instance | Server, instance, version and edition. Patch currency must be checked separately. |
| HostMemory | Total and currently available physical RAM on the SQL host, not the workstation running the script. Available RAM is a point-in-time measurement. |
| Configuration | Configured and running values for min/max memory, MAXDOP, cost threshold for parallelism and default backup compression. Documented default memory mappings are expected; other differences require review, not necessarily a restart. |
| Databases | State, recovery model, compatibility level, PAGE_VERIFY, AUTO_CLOSE and AUTO_SHRINK. Recovery model must match the backup and recovery strategy. |
| Files | Data/log paths, size and autogrowth from `sys.master_files`. `SizeBasis` is `Startup` for tempdb (configured startup size, not current size after growth) and `Allocated` for other databases. Neither is used space. `GrowthRaw` is a percentage when `IsPercentGrowth` is true; otherwise use `GrowthMB`. `MaxSizePages` is in 8-KB pages (`-1` means growth up to applicable limits). |
| ReviewNotes | Collection diagnostics and general review notes. Retained alongside the structured audit findings, particularly for permission and visibility limitations. |

### Severity levels

| Severity | Meaning and response |
| --- | --- |
| Error | A serious observed state or inconsistent values: investigate promptly with the DBA. This does not by itself establish root cause or business impact. |
| Warning | A known configuration risk or departure from a common production baseline. Plan a correction after validating context and documented exceptions. |
| Review | The observation is real, but whether to change it depends on workload, capacity or application guidance. Not a confirmed misconfiguration. |
| Unknown | Data required for a check is unavailable or not visible. Resolve collection gaps before drawing conclusions; this is never treated as a Pass. |
| Pass | Only the specific condition tested was satisfied. Not a guarantee that the setting, database or instance is healthy or optimally configured. |

### Rules and recommended actions

| Rule | Detection and result | Action to consider |
| --- | --- | --- |
| MEMORY_LIMIT | Warning for the effectively unlimited default, or an explicit running limit at least equal to physical host RAM. Unknown when required settings or RAM are missing. Otherwise Review, not Pass. | Agree an explicit memory budget that leaves headroom for Windows, other SQL allocations, other instances and applications. No fixed percentage is imposed. |
| MEMORY_RANGE | Error if running minimum memory exceeds running maximum; otherwise Pass for range consistency only. | Verify inconsistent collected values with the DBA. Do not mistake min memory for startup preallocation. |
| HOST_MEMORY | Unknown if the optional host-memory query returns no data. | Check collection notes and the version-specific DMV permission. No memory-pressure diagnosis is made from unavailable data. |
| SETTING_VALUE | Pass for equality or documented default memory mappings: minimum configured at 0 and running at 8 or 16 MB; maximum configured at 0 and running at 2147483647 MB. Review for other differences; Unknown if a setting is missing. Checked for min/max memory, MAXDOP, cost threshold and default backup compression. | Expected default mappings require no reconfiguration or restart; they do not validate memory sizing. Review other differences and how the setting becomes effective. |
| PARALLELISM | Review for each returned MAXDOP and cost-threshold value. | Compare with CPU/NUMA topology, measured workload and application support guidance. The audit does not guess an optimal value. |
| DATABASE_VISIBILITY | Unknown if the requested database is not returned, or no database rows are visible. | Confirm the instance, filter and metadata permissions. Missing rows do not prove that a database is absent. |
| DATABASE_STATE | Error for SUSPECT, RECOVERY_PENDING or EMERGENCY; Review for other non-ONLINE states; Pass for ONLINE. | Determine whether the state is planned and investigate errors. Never force repair or recovery solely from this report. |
| DATABASE_OPTION | Warning when AUTO_CLOSE or AUTO_SHRINK is enabled; otherwise Pass for that option. | Normally disable these options on production databases, subject to application requirements and a validated change plan. |
| PAGE_VERIFY | Warning when not CHECKSUM; otherwise Pass for the option value. | Prefer CHECKSUM unless an exception applies. This does not validate existing pages or replace integrity checks and backups. |
| FILE_VISIBILITY | Unknown when no file metadata is returned. | Check permissions before making conclusions about storage or tempdb. Partial visibility can still go undetected. |
| FILE_GROWTH | Review for percentage growth or disabled autogrowth; otherwise Pass for growth mode only. | Prefer predictable fixed-MB growth with suitable pre-sizing. Verify disk capacity and file limits first; disabled growth may be deliberate. No optimal increment is calculated. |
| TEMPDB_LAYOUT | With multiple visible tempdb data files, Review when configured startup sizes or growth settings differ; otherwise Pass for equality. | Normally align startup sizes and growth settings after DBA review. Query `tempdb.sys.database_files` for current sizes after growth. The script does not recommend a file count or diagnose contention. This rule is not evaluated with fewer than two visible data files. |
| CERTIFICATE_VALIDATION | Review when `-TrustServerCertificate` was used; otherwise Pass for this connection's validation setting. | Replace an ongoing bypass with a trusted SQL certificate and matching server name. This is not an audit of server encryption policy or other clients. |

For example, `MEMORY_LIMIT / Warning` with `2147483647` means the running instance has no practical configured memory ceiling. The recommended change is to **plan a suitable memory limit**, not blindly apply a generated number. On a shared application server such as Entra Connect, include the application engine in the RAM budget.

### Turn findings into a change plan

1. Resolve Error findings and collection gaps first; establish whether states are expected.
2. For each Warning, confirm the evidence and any documented exception with the DBA/application owner.
3. Evaluate Review findings against capacity, workload and vendor guidance before deciding to change anything.
4. Record approved changes, backups and rollback steps, then implement in a maintenance window where necessary.
5. Rerun the script and compare before/after JSON snapshots and performance measurements. The script never executes corrective SQL.

### Memory on a shared server

The default `max server memory (MB)` value is `2147483647`. Review an explicit memory budget with the DBA, reserving RAM for Windows, other SQL instances and co-located applications. On an Entra Connect server, this includes the synchronization engine.

`max server memory` does **not** cap every allocation made by the SQL Server process, and `min server memory` is not a preallocated reservation at startup. A limit below total host RAM is not proof of correct sizing. The script deliberately does not apply a fixed percentage or recommend a value without workload measurements.

SQL Server can expose a configured minimum of `0` as a running minimum of `16` MB on 64-bit systems (`8` MB on 32-bit systems). This is documented default behavior, not a pending change. The audit accepts these mappings without raising a Review finding or a pending-change note.

Likewise, do not automatically change MAXDOP, recovery model or tempdb layout based on this snapshot. File-growth notes can have valid explanations, particularly for deliberately pre-sized system files. Correlate findings with capacity planning, backup policy, application guidance and performance collection.

For tempdb, the file sizes collected from `sys.master_files` describe startup configuration. A reported size of 8 MB does not prove that the running file is still 8 MB or that the workload only needs that amount. Inspect `tempdb.sys.database_files` separately for current allocated sizes; the basic audit deliberately avoids an additional database-scoped query and its access requirements.

## Scope and validation

This first version does not inspect disk free space, backup history, log usage, wait statistics, query performance or all SQL security settings. Missing metadata is not proof that a database or file is absent. An empty review list is not a health certificate.

PowerShell syntax, SELECT-only query content, JSON round-trip and HTML export (including special-character encoding and empty sections) were checked locally. Synthetic audit scenarios covered memory limits and missing RAM, database states and options, missing settings, configured/running differences, file growth, tempdb layout and certificate-validation bypass. Collection and report generation were also confirmed by a user-provided SQL Server 2019 report. The updated rules were tested offline against that snapshot, including documented memory mappings, genuine mismatches and tempdb startup-size wording; the revised script still needs a fresh run in the target environment.

## References

- [Server memory configuration options](https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/server-memory-server-configuration-options).
- [sys.configurations and documented default memory mappings](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-configurations-transact-sql).
- [sys.master_files and tempdb startup sizes](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-master-files-transact-sql).
- [sys.dm_os_sys_memory and required permissions](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-views/sys-dm-os-sys-memory-transact-sql).
- [Metadata visibility configuration](https://learn.microsoft.com/en-us/sql/relational-databases/security/metadata-visibility-configuration).
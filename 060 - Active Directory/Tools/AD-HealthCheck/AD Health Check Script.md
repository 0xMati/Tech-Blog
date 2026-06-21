---
title: "AD Health Check Script"
date: 2026-06-21
---

# AD Health Check Script
🗓️ Published: 2026-06-21

## Introduction

Keeping an Active Directory environment healthy means catching problems *before* they turn into authentication outages, replication backlogs, or SYSVOL inconsistencies. Most of the signals you need are already exposed by native tooling — `repadmin`, `dcdiag`, `nltest`, `w32tm`, the *Directory Service* event log — but they are scattered across multiple commands and multiple servers.

`Invoke-ADHealthCheck.ps1` consolidates these checks into a single, self-contained PowerShell 5.1 script. It auto-discovers every domain controller in the domain, runs a series of health checks against each of them, and produces a colored console summary, an HTML report, a timestamped CSV log, and an optional SMTP alert email.

It is designed to run **unattended as a scheduled task** on an admin server (or a DC), and returns an exit code that monitoring systems can consume (`0` = OK, `1` = WARN, `2` = FAIL).

> 💡 The script is read-only. It queries AD and the DCs but never changes anything, so it is safe to run on a production environment.

## What the script checks

| Category | Check | Tooling |
|---|---|---|
| **Discovery** | Auto-discovery of all DCs in the domain | `Get-ADDomainController` |
| **FSMO** | Location + reachability of the 5 FSMO role holders | `Get-ADForest` / `Get-ADDomain` |
| **Replication** | Domain-wide replication summary | `repadmin /replsummary` |
| **Replication** | Per-DC outbound replication failures | `repadmin /showrepl /csv` |
| **Services** | NTDS, DNS, KDC, Netlogon, DFSR, W32Time, ADWS | `Get-Service` |
| **Connectivity** | ICMP + ports LDAP (389), Kerberos (88), SMB/SYSVOL (445) | `Test-Connection` / `Test-NetConnection` |
| **SecureChannel** | Secure channel state | `nltest /sc_query` |
| **DCDiag** | Targeted tests (Connectivity, Replications, Advertising, FsmoCheck, Services, SysVolCheck, NetLogons, KccEvent) | `dcdiag` |
| **TimeSync** | Real measured clock offset (W32Time) | `w32tm /stripchart` |
| **Storage** | Free space on `C:` and the NTDS volume + `NTDS.dit` size | CIM / remote registry |
| **EventLog** | Recent critical *Directory Service* errors (1311, 2042, lingering objects, USN rollback…) | `Get-WinEvent` |

Each check produces a status:

- 🟢 **OK** — healthy
- 🟡 **WARN** — needs attention (e.g. clock drift above threshold, low disk space)
- 🔴 **FAIL** — broken (e.g. core service stopped, replication failure, secure channel down)
- ⚪ **INFO** — informational (e.g. NTDS.dit size, DC list)

## Prerequisites

- **PowerShell 5.1**
- **RSAT AD DS Tools** installed on the machine running the script, providing:
  - The `ActiveDirectory` PowerShell module
  - `repadmin.exe`, `dcdiag.exe`, `nltest.exe`, `w32tm.exe`
- An account with:
  - Read access to AD (domain user is enough for most checks)
  - Remote admin rights on the DCs for the storage and event-log checks (Remote Registry, WMI/CIM, **Event Log Readers**)
  - Network access to the DCs (ICMP, LDAP 389, Kerberos 88, SMB 445, RPC)

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-DomainName` | `$env:USERDNSDOMAIN` | FQDN of the domain to check |
| `-OutputPath` | `.\Reports` | Output folder for HTML/CSV reports |
| `-SendEmail` | *(off)* | Enables the SMTP summary email |
| `-EmailOnlyOnIssue` | `$true` | With `-SendEmail`, only send when at least one WARN/FAIL is found |
| `-SmtpServer` | — | SMTP relay |
| `-SmtpPort` | `25` | SMTP port |
| `-From` | — | Sender address |
| `-To` | — | Recipient address(es) |
| `-UseSsl` | *(off)* | Use TLS for SMTP |
| `-DcDiagTests` | *(8 tests)* | List of dcdiag tests to run per DC |
| `-DiskFreeWarnGB` | `10` | Free-space threshold (GB) below which a WARN is raised |
| `-DiskFreeFailGB` | `3` | Free-space threshold (GB) below which a FAIL is raised |
| `-TimeOffsetWarnSec` | `5` | Clock offset (s) above which a WARN is raised |
| `-TimeOffsetFailSec` | `60` | Clock offset (s) above which a FAIL is raised |
| `-EventLookbackHours` | `24` | Directory Service event-log analysis window (hours) |

## Usage

### Manual run (test)

```powershell
cd "C:\...\060 - Active Directory\Tools\AD-HealthCheck"
.\Invoke-ADHealthCheck.ps1
```

This produces a colored console output plus an HTML and CSV report in `.\Reports`.

### Run with email alerting

```powershell
.\Invoke-ADHealthCheck.ps1 -SendEmail `
    -SmtpServer relay.contoso.com `
    -From ad-monitor@contoso.com `
    -To soc@contoso.com
```

By default the email is only sent when a WARN or FAIL is detected (`-EmailOnlyOnIssue $true`). Set it to `$false` to always receive the report.

### Custom thresholds

```powershell
.\Invoke-ADHealthCheck.ps1 `
    -DiskFreeWarnGB 20 -DiskFreeFailGB 5 `
    -TimeOffsetWarnSec 2 -TimeOffsetFailSec 30 `
    -EventLookbackHours 48
```

## Scheduled task

Run the following **as an administrator** on the admin server (or DC) that will host the monitoring task. Adjust the script path and the service account.

```powershell
$script = "C:\...\060 - Active Directory\Tools\AD-HealthCheck\Invoke-ADHealthCheck.ps1"

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$script`" -SendEmail -SmtpServer relay.contoso.com -From ad-monitor@contoso.com -To soc@contoso.com"

$trigger = New-ScheduledTaskTrigger -Daily -At 7am

$principal = New-ScheduledTaskPrincipal `
    -UserId 'CONTOSO\svc-ad-monitor' `
    -LogonType Password -RunLevel Highest

Register-ScheduledTask -TaskName 'AD-HealthCheck' `
    -Action $action -Trigger $trigger -Principal $principal
```

> ⚠️ The service account must have RSAT AD DS Tools installed locally and remote admin rights on the DCs (for the storage and event-log checks).

## Output

### Console

A per-DC, color-coded breakdown of every check, followed by a global summary line:

```
  Synthèse : OK=42  WARN=2  FAIL=0  -> WARN
```

### HTML report

A self-contained `ADHealth_<timestamp>.html` file with a summary card (OK / WARN / FAIL counts), the global status, and a sortable table of every check. WARN and FAIL rows are highlighted.

### CSV log

A `ADHealth_<timestamp>.csv` file containing one row per check (`Time, DC, Category, Check, Status, Detail`), ready to ingest into a SIEM or to keep as an audit trail.

### Email

When enabled, an HTML email is sent with the subject:

```
[AD Health][WARN] contoso.com - OK=42 WARN=2 FAIL=0
```

The CSV log is attached.

### Exit codes

| Exit code | Meaning |
|---|---|
| `0` | All checks OK |
| `1` | At least one WARN |
| `2` | At least one FAIL |

These can be consumed by the scheduled task's *Last Run Result* or by an external monitoring agent.

## Directory Service event IDs monitored

The event-log check flags the following critical IDs from the *Directory Service* log within the lookback window:

| Event ID | Meaning |
|---|---|
| `1311` | KCC could not build a fully connected replication topology |
| `2042` | Replication has not occurred within the tombstone lifetime |
| `1388` / `1988` | Lingering objects detected |
| `2103` / `467` | USN rollback / database corruption |
| `1645` | SPN / Kerberos issue |
| `1865` | KCC could not reach one or more sites |

## Conclusion

`Invoke-ADHealthCheck.ps1` gives you a single, repeatable, read-only health snapshot of your domain controllers — replication, services, connectivity, FSMO availability, time sync, storage, and critical Directory Service events — with console, HTML, CSV, and email output. Scheduled to run daily, it turns a pile of scattered native commands into an actionable health report and an exit code your monitoring can act on.

---
title: "AD Health Check Script"
date: 2026-06-21
---

# AD Health Check Script
🗓️ Published: 2026-06-21

## Introduction

Keeping an Active Directory environment healthy means catching problems *before* they turn into authentication outages, replication backlogs, or SYSVOL inconsistencies. Most of the signals you need are already exposed by native tooling — `repadmin`, `dcdiag`, `nltest`, `w32tm`, the *Directory Service* event log — but they are scattered across multiple commands and multiple servers.

`Invoke-ADHealthCheck.ps1` consolidates these checks into a single, self-contained PowerShell 5.1 script. It auto-discovers every domain controller in the domain, runs a series of health checks against each of them, and produces a colored console summary, an HTML report, a timestamped CSV log, and an optional alert email (via classic **SMTP** or **Microsoft Graph**).

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

> 💡 **Known benign false positive (DnsCache):** on Windows Server 2019+ / 2025 the `DnsCache` service runs in an *isolated* SvcHost process (`WIN32_OWN_PROCESS`), while dcdiag still expects the legacy shared process (`WIN32_SHARE_PROCESS`). This makes the dcdiag **Services** test fail with *"Invalid service type"* even though DNS is perfectly healthy. The script detects this exact pattern and downgrades it to **WARN** (never masking a real service failure). Per Microsoft, the service type should **not** be changed based on this dcdiag message.

## Prerequisites

- **PowerShell 5.1**
- **RSAT AD DS Tools** installed on the machine running the script, providing:
  - The `ActiveDirectory` PowerShell module
  - `repadmin.exe`, `dcdiag.exe`, `nltest.exe`, `w32tm.exe`
- For email delivery via **Microsoft Graph** (`-MailMethod Graph`): the `Microsoft.Graph.Authentication` and `Microsoft.Graph.Users.Actions` modules, plus an Entra ID app registration with the **`Mail.Send`** application permission (admin-consented).
- An account with:
  - Read access to AD (domain user is enough for most checks)
  - Remote admin rights on the DCs for the storage and event-log checks
  - Network access to the DCs (ICMP, LDAP 389, Kerberos 88, SMB 445, RPC)

> ℹ️ The script does **not** use PowerShell Remoting (WinRM). All remote checks rely on classic protocols: RPC (SCM / Event Log), WMI/DCOM, Remote Registry and SMB admin shares.

### Firewall rules on the domain controllers

Several checks query the DCs remotely over RPC / WMI / SMB. If the corresponding inbound rules are closed, those checks are reported as **FAIL/WARN by mistake** even though they pass when run locally on the DC. Enable the following built-in rule groups on each DC:

| Rule group (`Enable-NetFirewallRule -DisplayGroup ...`) | Protocol | Checks that need it |
|---|---|---|
| `Remote Service Management` | RPC (SCM) | `Get-Service`, dcdiag **Services** |
| `Remote Event Log Management` | RPC (Event Log) | `Get-WinEvent` (Directory Service), dcdiag **KccEvent** |
| `Windows Management Instrumentation (WMI-In)` | WMI / DCOM | Disk free space (`Get-CimInstance`) |
| `Remote Registry` (service + rule) | RPC | Locating the `NTDS.dit` path |
| `File and Printer Sharing (SMB-In)` | SMB 445 | `NTDS.dit` size via the `\\DC\C$` admin share |

```powershell
# Run on each DC (elevated)
Enable-NetFirewallRule -DisplayGroup "Remote Service Management"
Enable-NetFirewallRule -DisplayGroup "Remote Event Log Management"
Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI-In)"
```

### DNS resolution (multi-domain / `-Forest`)

When scanning a forest with `-Forest`, the machine running the script must be able to resolve the **short names** of DCs in every domain (including child domains). If short-name resolution fails, dcdiag tests such as *Advertising*, *FsmoCheck*, *SysVolCheck* and *NetLogons* return errors 53 / 1722 that look like a DC outage but are only a DNS-suffix problem. Add every domain suffix to the client search list:

```powershell
Set-DnsClientGlobalSetting -SuffixSearchList @('contoso.com','child.contoso.com')
```

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-DomainName` | `$env:USERDNSDOMAIN` | FQDN of the domain to check |
| `-Forest` | *(off)* | Scan **every domain** of the forest (all child domains) instead of a single domain |
| `-OutputPath` | `.\Reports` | Output folder for HTML/CSV reports |
| `-SendEmail` | *(off)* | Enables the summary email |
| `-EmailOnlyOnIssue` | `$true` | With `-SendEmail`, only send when at least one WARN/FAIL is found |
| `-MailMethod` | `Smtp` | Delivery method: `Smtp` or `Graph` |
| `-SmtpServer` | — | SMTP relay (`-MailMethod Smtp`) |
| `-SmtpPort` | `25` | SMTP port (`-MailMethod Smtp`) |
| `-UseSsl` | *(off)* | Use TLS for SMTP (`-MailMethod Smtp`) |
| `-TenantId` | — | Entra ID tenant ID (`-MailMethod Graph`) |
| `-ClientId` | — | App (client) ID of the app registration with `Mail.Send` (`-MailMethod Graph`) |
| `-CertThumbprint` | — | Thumbprint of the app's auth certificate — **recommended** (`-MailMethod Graph`) |
| `-ClientSecret` | — | App client secret as a `SecureString` — alternative to the certificate (`-MailMethod Graph`) |
| `-From` | — | Sender address |
| `-To` | — | Recipient address(es) |
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

### Run with email alerting (SMTP)

```powershell
.\Invoke-ADHealthCheck.ps1 -SendEmail -MailMethod Smtp `
    -SmtpServer relay.contoso.com `
    -From ad-monitor@contoso.com `
    -To soc@contoso.com
```

By default the email is only sent when a WARN or FAIL is detected (`-EmailOnlyOnIssue $true`). Set it to `$false` to always receive the report.

### Run with email alerting (Microsoft Graph)

Recommended in modern tenants where basic SMTP/relay is disabled. Authenticate with a certificate (preferred) or a client secret on an app registration that holds the `Mail.Send` application permission.

```powershell
# Certificate auth (recommended)
.\Invoke-ADHealthCheck.ps1 -SendEmail -MailMethod Graph `
    -TenantId <tenant-guid> `
    -ClientId <app-guid> `
    -CertThumbprint <cert-thumbprint> `
    -From ad-monitor@contoso.com `
    -To soc@contoso.com

# Client secret auth (store the secret encrypted, e.g. DPAPI)
$secret = Get-Content C:\Secure\graph-secret.txt | ConvertTo-SecureString
.\Invoke-ADHealthCheck.ps1 -SendEmail -MailMethod Graph `
    -TenantId <tenant-guid> `
    -ClientId <app-guid> `
    -ClientSecret $secret `
    -From ad-monitor@contoso.com `
    -To soc@contoso.com
```

> 💡 Restrict the app's `Mail.Send` scope with an **Application Access Policy** so it can only send from the monitoring mailbox.

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
  Summary : OK=42  WARN=2  FAIL=0  -> WARN
```

### HTML report

A self-contained `ADHealth_<timestamp>.html` file with a modern dark-theme design:

- a **health-score donut** (SVG) showing the overall pass percentage,
- four **KPI cards** (Passed / Warnings / Failures / Total checks),
- a **Domain Controllers overview** with one card per DC,
- a **detailed results table** grouped by DC, with color-coded status badges.

The accent color of the report adapts to the global status (green / amber / red).

### CSV log

A `ADHealth_<timestamp>.csv` file containing one row per check (`Time, DC, Category, Check, Status, Detail`), ready to ingest into a SIEM or to keep as an audit trail.

### Email

When enabled, the same HTML report is sent inline as the email body (no attachment), with the subject:

```
[AD Health][WARN] contoso.com - OK=42 WARN=2 FAIL=0
```

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

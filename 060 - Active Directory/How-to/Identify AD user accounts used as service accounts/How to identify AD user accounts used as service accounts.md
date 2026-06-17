---
title: "How to identify AD user accounts used as service accounts"
date: 2026-06-17
---

# How to identify AD user accounts used as service accounts

At some point, every AD team asks the same question:

> "Is this user account a real human identity, or a service account in disguise?"

Short answer: there is no single magical AD attribute that says "service account".
Practical answer: combine **AD signals + runtime usage evidence**, then score confidence.

This article ships with a companion script:

- [Invoke-AdUserServiceAccountDiscovery.ps1](Invoke-AdUserServiceAccountDiscovery.ps1)

The script is **read-only** (no AD write, no infrastructure changes), and generates:

- a modern, readable HTML report
- a full CSV export
- a high-confidence CSV shortlist for prioritization

## Why this matters

Identifying user accounts used as service identities helps you:

- harden security by removing unnecessary interactive usage
- modernize by migrating to gMSA where possible
- reduce risk by removing "forever-password" patterns
- make audits defensible with evidence, not assumptions

## What the script evaluates

Scoring combines AD heuristics and, when available, service/batch logon events (4624).

### AD posture signals

- `servicePrincipalName` not empty
- `PasswordNeverExpires = True`
- `CannotChangePassword = True`
- Name/description keyword hits (`svc`, `service`, `sql`, `app`, `batch`, `job`, ...)
- Old password age (`pwdLastSet`)
- Recent activity (`LastLogonDate`)
- Privileged group membership (Domain Admins, Enterprise Admins, Administrators)
- `msDS-SupportedEncryptionTypes` explicitly set (uncommon on regular user accounts, often a leftover from service hardening)
- `msDS-SupportedEncryptionTypes` with RC4 but no AES (technical debt signal)

### Runtime evidence signals

- Events 4624, `LogonType = 5` (service)
- Events 4624, `LogonType = 4` (batch / scheduled task)

If event collection is not possible (permissions, retention, WinRM), the script still runs and reports that limitation.

## Confidence score model

Score is normalized to 100 and mapped to bands:

- `High` : >= 70
- `Medium` : 45-69
- `Low` : < 45

The report also provides a readable verdict:

- `Observed Service Usage` (at least one observed type-5 logon)
- `Very Likely Service Account`
- `Likely Service Account`
- `Possible Service Account`
- `Unlikely Service Account`

## Prerequisites

- PowerShell `ActiveDirectory` module available (RSAT)
- Account with AD read permissions
- For event evidence: Security log read access on target DCs (WinRM + permissions)

## Domain controller scope

By default the script queries **every domain controller** in the domain. It resolves the list with `Get-ADDomainController -Filter *`, then connects to each one over WinRM (`Invoke-Command`) to read the `4624` events from its Security log.

Why all of them: a logon (type 5 / type 4) is only recorded on the DC that authenticated the request, so full coverage avoids missing evidence.

Things to keep in mind:

- On large domains this multiplies WinRM calls. Use `-MaxEventsPerDc` (default `20000`) to cap the volume read per DC.
- Each DC needs WinRM enabled and the running account needs Security log read rights. A DC that cannot be reached is reported under Warnings/Errors and the script keeps going.
- An unreachable DC fails fast thanks to a bounded WinRM connection timeout (`-DcTimeoutSeconds`, default `15`) instead of blocking the run. The script prints which DC it is querying so you can spot a slow target.
- You can restrict the scope with `-DomainControllers` (one or several DCs) when you do not need full coverage.

## Usage

### Standard run (7 days)

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1
```

### 14-day window + auto-open report

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 -Days 14 -OpenReport
```

### Scope to selected DCs + higher event volume

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 `
  -DomainControllers dc1.contoso.com,dc2.contoso.com `
  -MaxEventsPerDc 50000
```

### Shorter per-DC timeout (skip unreachable DCs faster)

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 -DcTimeoutSeconds 5
```

### Large domains: keep the HTML light

The HTML `Scored Accounts` table only lists accounts with at least one signal (score > 0), capped by `-MaxReportRows` (default `1000`). The CSV and JSON exports always keep the full dataset, so nothing is lost.

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 -MaxReportRows 500
```

### Custom output folder

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 -OutputDir C:\Temp\SvcAccountAudit
```

## Produced artifacts

- `AdUserServiceAccountDiscovery.html`: main dashboard
- `AdUserServiceAccountDiscovery.csv`: full dataset
- `AdUserServiceAccountDiscovery.HighConfidence.csv`: actionable shortlist
- `AdUserServiceAccountDiscovery.json`: raw export (debug/reuse)

> The HTML is a triage dashboard, not the source of truth. On large domains the `Scored Accounts` table is filtered to scored accounts and capped (`-MaxReportRows`); the CSV/JSON always hold every scanned account.

## Quick way to read the report

1. Start with **Findings** (immediate high-signal items).
2. Review KPIs (coverage and collection quality).
3. Work through the **Scored Accounts** table by descending score.
4. Validate `Observed Service Usage` accounts with application owners.
5. Plan remediation waves (gMSA, logon rights, secret rotation, etc.).

## Known limitations (expected)

- A service account can exist without SPN (for example local scheduled tasks or custom services).
- An SPN-bearing account is not always still in active use.
- `LastLogonDate` is useful but not perfect, depending on topology and replication.
- Confidence score is a **prioritization aid**, not absolute truth.

## Recommended remediation pattern

- Wave 1: `Observed Service Usage` + `High` confidence
- Wave 2: `Very Likely` and `Likely`
- Wave 3: validate `Possible` with owner mapping

This gives you a clean, defensible backlog that is practical to execute in waves.

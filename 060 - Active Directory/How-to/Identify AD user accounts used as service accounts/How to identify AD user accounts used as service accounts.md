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

- un rapport HTML moderne et lisible
- un export CSV complet
- un top "high confidence" CSV pour prioriser
- a modern, readable HTML report
- a full CSV export
- a high-confidence CSV shortlist for prioritization

## Pourquoi c est utile

Identifying user accounts used as service identities helps you:

- harden security by removing unnecessary interactive usage
- modernize by migrating to gMSA where possible
- reduce risk by removing "forever-password" patterns
- make audits defensible with evidence, not assumptions

## Ce que le script regarde

Scoring combines AD heuristics and, when available, service/batch logon events (4624).

### Signaux AD

- `servicePrincipalName` non vide
- `PasswordNeverExpires = True`
- `CannotChangePassword = True`
- Nom / description avec mots clefs (`svc`, `service`, `sql`, `app`, `batch`, `job`, ...)
- Mot de passe ancien (`pwdLastSet`)
- Activite recente (`LastLogonDate`)
- Groupes privilegies (Domain Admins, Enterprise Admins, Administrators)
- `msDS-SupportedEncryptionTypes` avec RC4 sans AES (signal de dette technique)
- `servicePrincipalName` not empty
- `PasswordNeverExpires = True`
- `CannotChangePassword = True`
- Name/description keyword hits (`svc`, `service`, `sql`, `app`, `batch`, `job`, ...)
- Old password age (`pwdLastSet`)
- Recent activity (`LastLogonDate`)
- Privileged group membership (Domain Admins, Enterprise Admins, Administrators)
- `msDS-SupportedEncryptionTypes` with RC4 but no AES (technical debt signal)

### Signaux d usage reel

- Evenements 4624, `LogonType = 5` (service)
- Evenements 4624, `LogonType = 4` (batch / tache planifiee)
- Events 4624, `LogonType = 5` (service)
- Events 4624, `LogonType = 4` (batch / scheduled task)

If event collection is not possible (permissions, retention, WinRM), the script still runs and reports that limitation.

## Score de confiance

Score is normalized to 100 and mapped to bands:

- `High` : >= 70
- `Medium` : 45-69
- `Low` : < 45

The report also provides a readable verdict:

- `Observed Service Usage` (au moins un logon type 5 observe)
- `Very Likely Service Account`
- `Likely Service Account`
- `Possible Service Account`
- `Unlikely Service Account`
- `Observed Service Usage` (at least one observed type-5 logon)
- `Very Likely Service Account`
- `Likely Service Account`
- `Possible Service Account`
- `Unlikely Service Account`

## Prerequisites

- PowerShell `ActiveDirectory` module available (RSAT)
- Account with AD read permissions
- For event evidence: Security log read access on target DCs (WinRM + permissions)

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

### Custom output folder

```powershell
.\Invoke-AdUserServiceAccountDiscovery.ps1 -OutputDir C:\Temp\SvcAccountAudit
```

## Artefacts produits

- `AdUserServiceAccountDiscovery.html` : dashboard principal
- `AdUserServiceAccountDiscovery.csv` : dataset complet
- `AdUserServiceAccountDiscovery.HighConfidence.csv` : shortlist actionnable
- `AdUserServiceAccountDiscovery.json` : dump brut (debug / re-use)
- `AdUserServiceAccountDiscovery.html`: main dashboard
- `AdUserServiceAccountDiscovery.csv`: full dataset
- `AdUserServiceAccountDiscovery.HighConfidence.csv`: actionable shortlist
- `AdUserServiceAccountDiscovery.json`: raw export (debug/reuse)

## Quick way to read the report

1. Start with **Findings** (immediate high-signal items).
2. Review KPIs (coverage and collection quality).
3. Work through **Top candidates** by descending score.
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

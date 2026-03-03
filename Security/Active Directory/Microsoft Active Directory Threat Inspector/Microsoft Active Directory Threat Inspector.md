# MATI — Microsoft Active Directory Threat Inspector

**MATI** is a PowerShell-based Active Directory security assessment tool. It collects configuration data from your forest, evaluates it against **93 detection rules** across 10 categories, and generates scored HTML / CSV / JSON reports — all from a single read-only scan.

> Think of it as an open, extensible alternative to PingCastle or ORADAD that you can customize to your environment.

---

## What it detects

| Category | Rules | Examples |
|---|:-:|---|
| **Hardening** | 30 | LDAP signing, SMB signing, NTLMv1 usage, LAPS coverage, Print Spooler, TLS config, SCRIL rotation, anonymous bind … |
| **Kerberos** | 7 | Kerberoasting, AS-REP Roasting, KRBTGT age/encryption, RC4 ticket usage, duplicate SPNs, unconstrained delegation … |
| **ACL** | 7 | DCSync, AdminSDHolder, Schema/Config/Domain root ACLs, GPO permissions, critical object owners |
| **ADCS** | 9 | ESC1–ESC8, weak CA certificate, CA cert expiry |
| **Config** | 15 | Functional levels, Recycle Bin, tombstone, trust hardening (SID Filtering, AES, selective auth, TGT delegation), DNS aging … |
| **Delegation** | 6 | Constrained/unconstrained/protocol-transition delegation targeting DCs, RBCD backdoor, Shadow Credentials |
| **Password Policy** | 3 | Default policy strength, FGPP for privileged accounts, reversible encryption |
| **Privileged Accounts** | 9 | Inactive/stale admins, non-expiring passwords, disabled accounts in groups, SIDHistory, service accounts in DA, gMSA permissions, RID-500 enabled … |
| **Stale Objects** | 3 | Inactive users, inactive computers, legacy OS |
| **RODC** | 4 | Cached passwords, allowed/denied replication groups, orphan krbtgt |

Additionally, MATI performs **live event-log auditing** on all DCs (Kerberos RC4 vs AES breakdown, NTLMv1/v2 usage) with donut-chart visualisation in the HTML report.

---

## Sample output

```
=== Phase 3: Scoring ===

  ┌────────────────────────────────┐
  │  Score: 52 / 100  (Grade: C)   │
  └────────────────────────────────┘

  Total findings : 126 (from 38 rules)
  Critical: 6 | High: 69 | Medium: 40 | Low: 3
```

Reports are generated in three formats:
- **HTML** — interactive report with collapsible sections, severity badges, donut charts for protocol usage
- **CSV** — one CSV per collector + dedicated protocol audit exports (for Excel / SIEM ingestion)
- **JSON** — full structured export (findings, scores, raw data)

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell 7+** | Required (`pwsh`). PowerShell 5.1 is **not supported** |
| **ActiveDirectory module** | `RSAT: Active Directory Domain Services` — must be installed and importable |
| **AD read access** | The running account needs standard read access to the domain (no admin required for most rules) |
| **WinRM to DCs** | Required only for the `LegacyProtocolAudit` collector (Kerberos/NTLM event-log analysis). The account needs permission to read `Security` event logs on DCs |
| **Network** | Line of sight to at least one DC per domain in the forest |

### Optional (for full coverage)

- **CertificateServices module** (`PSPKI` or `ADCSAdministration`) — for ADCS/ESC detection
- **Group Policy module** (`GroupPolicy`) — for GPO analysis
- DCs must have **Kerberos event auditing enabled** (subcategories: `Kerberos Authentication Service`, `Kerberos Service Ticket Operations`) for RC4/AES analysis
- DCs must have **Logon auditing** enabled for NTLM analysis (event 4624)

---

## Quick start

```powershell
# Clone or copy the project folder to a machine with RSAT installed
cd '.\Microsoft Active Directory Threat Inspector'

# Run the full assessment
.\Invoke-MATI.ps1

# Run only specific categories
.\Invoke-MATI.ps1 -CategoriesOnly Config, Kerberos

# Run specific rules only
.\Invoke-MATI.ps1 -RulesOnly MATI-CONFIG-001, MATI-KERB-005

# Skip report generation (quick check)
.\Invoke-MATI.ps1 -NoReport
```

Reports are saved to `Outputs\Output_<timestamp>\` with `HTML`, `CSV`, and `JSON` subdirectories.

---

## Project structure

```
Microsoft Active Directory Threat Inspector/
├── Invoke-MATI.ps1            # Entry point
├── Config/
│   └── MATI.config.psd1       # All thresholds, weights, exclusions
├── Collectors/                 # 16 data collectors (AD queries, event logs)
├── Rules/                      # 93 detection rules across 10 categories
│   ├── ACL/
│   ├── ADCS/
│   ├── Config/
│   ├── Delegation/
│   ├── Hardening/
│   ├── Kerberos/
│   ├── PasswordPolicy/
│   ├── PrivilegedAccounts/
│   ├── RODC/
│   └── StaleObjects/
├── Scoring/                    # Multiplicative-decay scoring engine
├── Engine/                     # Pipeline orchestration
├── Models/                     # MATIFinding class
├── Reporters/                  # HTML, CSV, JSON exporters
│   └── Templates/
│       └── report.html.tpl
├── History/                    # Score trend tracking (CSV)
└── Outputs/                    # Generated reports
```

---

## Configuration

All tuning is done in [`Config/MATI.config.psd1`](Config/MATI.config.psd1):

- **Scoring** — category budgets, severity impact percentages, grade thresholds
- **Thresholds** — stale account days, password age limits, LAPS coverage %, legacy OS patterns, event-log audit window …
- **Exclusions** — skip specific DNs, sAMAccountNames, rule IDs, or entire categories
- **Collectors** — AD property lists requested by `Get-ADUser` / `Get-ADComputer`

---

## Scoring model

MATI uses a **multiplicative-decay** scoring system:

1. Each category has a **point budget** (e.g., Hardening = 15, Kerberos = 12, RODC = 5 — totalling 100).
2. Each rule that fires consumes a **percentage** of the remaining budget based on severity (Critical 35%, High 20%, Medium 8%, Low 3%).
3. Diminishing returns: the first failed rule in a category hurts the most; subsequent failures impact less because the pool is already partially consumed.

| Grade | Score |
|:-:|---|
| **A** | ≥ 85 |
| **B** | ≥ 70 |
| **C** | ≥ 50 |
| **D** | ≥ 30 |
| **E** | < 30 |

---

## Extending MATI

### Add a new rule

Create a `.rule.ps1` file in the appropriate `Rules/<Category>/` folder:

```powershell
@{
    Id          = 'MATI-CAT-NNN'
    Title       = 'Short description'
    Category    = 'Category'
    Severity    = 'High'
    Description = 'What this checks'
    Remediation = 'How to fix it'
    Collectors  = @('CollectorName')
    Condition   = {
        param($Data, $Config)
        # Return findings or $null
    }
}
```

Rules are auto-discovered — no registration needed.

### Add a new collector

Create `Collectors/Get-MATI<Name>.ps1` with a function `Get-MATI<Name>`. The return value is stored in `DataCache['<Name>']` and made available to rules.

---

## License

This project is open-source and provided as-is under the [MIT License](LICENSE). Contributions and feedback are welcome.

**GitHub**: [0xMati/Tech-Blog — MATI](https://github.com/0xMati/Tech-Blog/tree/main/Security/Active%20Directory/Microsoft%20Active%20Directory%20Threat%20Inspector)
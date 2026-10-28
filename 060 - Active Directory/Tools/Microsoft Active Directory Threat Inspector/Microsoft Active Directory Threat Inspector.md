---
title: "MATI — Microsoft Active Directory Threat Inspector"
date: 2026-05-26
---

# MATI — Microsoft Active Directory Threat Inspector

**MATI** is a PowerShell-based Active Directory security assessment tool. It collects configuration data from your forest, evaluates it against **157 detection rules** across 11 categories, and generates scored HTML / CSV / JSON reports — all from a single read-only scan.

> An open, extensible PowerShell tool for Active Directory security assessment that you can customize to your environment.

MATI is dedicated to read-only security assessment. The tiering deployment
workflow is now a separate, standalone tool:
[AD Tiering Toolkit (ADTT)](../AD%20Tiering%20Toolkit/AD%20Tiering%20Toolkit.md).
Copying MATI does not require ADTT, and ADTT does not load MATI.
Security detections concerning privileged access and isolation remain in MATI.

Version **2.4.0** distinguishes complete, partial and deliberately filtered
assessments. Missing data and failed rules are no longer treated as evidence of
a clean forest. See [Assessment coverage](#assessment-coverage) and
[Offline regression tests](#offline-regression-tests).

The 2.2.1 patch fixes audit-policy collection when native `auditpol` output
contains stderr error records, and CA service permission reads on Windows
PowerShell 5.1 remoting endpoints.

The 2.2.2 patch uses `auditpol /get /category:* /r` to retrieve all audit
categories and their subcategories. This replaces the rejected
`/subcategory:*` argument that produced native exit code 87 on the tested DCs.
See [auditpol get syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get).

The 2.2.3 patch adds a shared member-link fallback when `Get-ADGroupMember`
fails. It retains readable principals, foreign SIDs and unresolved links,
traverses nested groups across domains, and prevents cycles and duplicates.
Unreadable member links remain partial rather than silently treating a failed
enumeration as an empty group. Version 2.4.0 uses these links directly for scoped
collection, without first invoking ADWS member enumeration.

The 2.2.4 patch makes HTML assessment coverage readable: status counts remain
visible, exact duplicate collection messages are grouped by collector and scope
with occurrence counts, and technical records and affected rule IDs are collapsed
by default. Selection/exclusions use human-readable labels instead of raw JSON.
All raw collection records remain unchanged in the JSON and CSV exports.

The 2.2.5 patch restores the single-hashtable `SecurityConfig` return contract
and its individual dataset CSVs without changing group-cycle detection. DNS
inventory now reads `IsDsIntegrated` and the native `SecureSecondaries` policy
instead of inferring them from unrelated properties or an empty server list.
Missing or unsupported settings remain unknown and emit collection warnings.
Trust transitivity now correctly interprets the `NON_TRANSITIVE` attribute.
These fixes do not resolve unavailable external identities or remove partial
coverage warnings.

The 2.2.6 patch adds diagnostic guidance when ADWS enumeration fails and the
member-link fallback encounters foreign principals. Console warnings and raw
collection-issue exports retained the guidance; HTML coverage originally displayed one visible
explanation with a link to
[Microsoft KB 3171600](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/get-adgroupmember-error-remote-forest-members).
Possible causes include deleted external accounts, inaccessible forests or
identities, DNS/connectivity, and trust authentication conditions; Microsoft also
documents this error with one-way trusts. Local Enterprise Admin rights do not
guarantee access to external identities. The note does not establish orphaned
SIDs or broken trusts and does not change membership completeness, findings or
grading. From version 2.4.0, this explanation belongs in the foreign-principal
finding, not in a report-front warning.

Version 2.4.0 audits principals and expands groups **inside the target forest**,
including its child domains. A trust does not place the trusted forest in scope.
Local member links and FSP objects are inventoried without requiring access to
remote account attributes. Windows SID-name translation is optional, bounded to
15 seconds per SID and cached per assessment. Only a SID belonging to a target
forest domain is eligible for directory verification and recursive expansion.
External users and groups remain opaque inventory entries: their attributes and
group members are not audited, even if they happen to be accessible.

`MATI-ADMIN-018` reports external privileged placement, preserving the local DN,
SID, any translated name and lookup evidence. Its details explain the distinction
between name translation and authenticated directory reads and link to KB 3171600.
An untranslated or timed-out external name is not proof of deletion, a broken
trust or incomplete target-forest collection. Real failures reading local FSP
objects, member links or in-forest account properties still limit coverage.

Recovered ADWS failures and guidance are diagnostic records, not automatically
collector-wide missing data. Remaining limitations are scoped to datasets:
for example an incomplete privileged-membership index limits AdminCount orphan
classification, not unrelated DNS, LAPS or machine-account-quota checks.
Unclassified errors remain conservatively collector-wide. Direct-membership
findings use the exact direct link count, while incomplete recursive counts stay
explicit lower bounds. Permanent EA/SA membership checks also use direct links,
so even an external-only member is detected without remote group expansion.
Each assessment produces one HTML report.

---

## What it detects

| Category | Rules | Examples |
|---|:-:|---|
| **Hardening** | 47 | LDAP signing, SMB signing, NTLMv1 usage, LAPS coverage, Print Spooler, TLS config, SCRIL rotation, anonymous bind, DSRM admin logon behavior … |
| **Config** | 28 | Functional levels, Recycle Bin, tombstone, trust hardening (SID Filtering, AES, selective auth, TGT delegation), DNS aging … |
| **Privileged Accounts** | 17 | Inactive/stale admins, non-expiring passwords, disabled accounts in groups, SIDHistory, service accounts in DA, gMSA permissions, RID-500 enabled … |
| **ACL** | 16 | DCSync, AdminSDHolder, Schema/Config/Domain root ACLs, GPO permissions, critical object owners |
| **ADCS** | 11 | ESC1–ESC4 and ESC6–ESC10, weak CA certificate, CA cert expiry (no ESC5 or ESC11 detection) |
| **Kerberos** | 9 | Kerberoasting, AS-REP Roasting, KRBTGT age/encryption, RC4 ticket usage, duplicate SPNs, unconstrained delegation … |
| **Delegation** | 8 | Constrained/unconstrained/protocol-transition delegation targeting DCs, RBCD backdoor, Shadow Credentials |
| **Stale Objects** | 8 | Inactive users, inactive computers, stale/cluster/MSA passwords, legacy OS, duplicate sAMAccountName |
| **RODC** | 5 | Cached passwords, allowed/denied replication groups, orphan krbtgt, SYSVOL write |
| **GPO** | 4 | WSUS over HTTP, AlwaysInstallElevated, GPP cpassword (MS14-025), dangerous user-rights assignment |
| **Password Policy** | 4 | Default policy strength, FGPP for privileged accounts, reversible encryption, account lockout policy |

Additionally, MATI performs **live event-log auditing** on all DCs (Kerberos RC4 vs AES breakdown, NTLMv1/v2/unknown-version usage) with donut-chart visualisation in the HTML report. Failed Kerberos requests are not counted as issued tickets.

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
- **CSV** — assessment coverage and per-rule outcomes, collection errors when present, collector datasets and dedicated protocol audit exports (for Excel / SIEM ingestion)
- **JSON** — findings, scores, coverage, execution metadata and protocol-audit aggregates; not the entire raw collector cache. The findings-only file is always a JSON array, including `[]` for zero findings

## Assessment coverage

HTML, JSON and CSV expose the same assessment status:

- **Complete**: every selected rule was fully evaluated without known collection failures.
- **Partial**: a collector, domain, remote read or rule failed, data is incomplete, or AD ran through Windows PowerShell compatibility mode. Known findings are retained.
- **Filtered**: evaluation succeeded but categories, rules or objects were deliberately restricted. A partial and filtered assessment is labelled Partial, with both flags preserved.

These statuses describe the target forest. Excluding trusted-forest account
attributes and external group expansion is the standard audit boundary, not a
failed collection or a user-filtered scan. JSON metadata and the assessment CSV
record `PrincipalAuditScope` as `TargetForest` (camel case in JSON).

Selected, evaluated and fully assessed rule counts are distinct. Rules using
partial data are not counted as fully assessed. Errors and reasons are included
in the reports, including when there are no findings.

Partial assessments retain the calculated **A–E grade**, labelled
**Provisional grade - partial assessment** in a small report note.
`GradeIsProvisional` is true in JSON and the assessment CSV; status, rule coverage
and collection diagnostics remain unchanged. A provisional grade reflects known
findings, not an assurance of complete coverage. Deliberately filtered assessments
retain a scope-limited numeric score and **N/A** for the global grade; **N/A** also
applies when no rules could be evaluated. Unknown or empty rule selections fail
explicitly rather than producing 100/A. A Complete status means no known execution
gaps, not proof that every AD attack path has been tested. This presentation policy
applies from version 2.3.1.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| **PowerShell 7+** | Required (`pwsh`). PowerShell 5.1 is **not supported** |
| **Elevated PowerShell session** | Recommended. Launch PowerShell with `Run as Administrator` for full collector coverage |
| **ActiveDirectory module** | `RSAT: Active Directory Domain Services` — must be installed and importable |
| **AD read access** | The running account needs standard read access to the domain (no admin required for most rules) |
| **WinRM to DCs** | Used by `DCInfo`, `ProtocolConfig` and `LegacyProtocolAudit`; CIM service checks in `SecurityConfig` also require remote access. Event auditing needs permission to read DC Security and System logs; registry and audit-policy reads need corresponding permissions |
| **WinRM to CAs** | Required for CA policy-module settings and CA service security descriptor reads. LDAP read access alone does not provide this coverage |
| **Network** | AD/ADWS access per domain, SYSVOL/SMB access for GPO parsing, and remote access to all DCs/CAs needed by the selected checks |

Launch MATI with **PowerShell 7** (`pwsh`), not Windows PowerShell 5.1. This
requirement concerns the launcher: a DC or CA's default WinRM endpoint can still
run collector scriptblocks under Windows PowerShell 5.1. Native command errors
and nonzero `auditpol` exit codes are reported as collection failures, not empty
successful audit-policy results.

### Optional (for full coverage)

- **Group Policy module** (`GroupPolicy`) — used by `GPOInfo` when available; LDAP fallback is supported. `GPOSettings` parses SYSVOL directly
- ADCS collection uses LDAP and remote registry reads; `PSPKI` / `ADCSAdministration` are not required by the current collector
- DCs must have **Kerberos event auditing enabled** (subcategories: `Kerberos Authentication Service`, `Kerberos Service Ticket Operations`) for RC4/AES analysis
- DCs must have **Logon auditing** enabled for NTLM analysis (event 4624)

---

## Quick start

```powershell
# Clone or copy the project folder to a machine with RSAT installed
cd '.\Microsoft Active Directory Threat Inspector'

# Run the full assessment
.\Invoke-MATI.ps1

# Target a specific forest instead of the current logon context
.\Invoke-MATI.ps1 -TargetForest corp.contoso.com

# Run only specific categories
.\Invoke-MATI.ps1 -CategoriesOnly Config, Kerberos

# Run specific rules only
.\Invoke-MATI.ps1 -RulesOnly MATI-CONFIG-001, MATI-KERB-005

# Skip report generation (quick check)
.\Invoke-MATI.ps1 -NoReport
```

Reports are saved to `Outputs\ThreatDetection\Output_<timestamp>\` with `HTML`, `CSV`, and `JSON` subdirectories.

The interactive menu offers Threat Detection & Security Analysis and Quit.
Tiering deployment is no longer available from this launcher. Previous
tiering reports and state under `Outputs\Tiering` are preserved; see the ADTT
documentation before resuming a deployment in the standalone tool.

When running interactively from the menu, MATI now prompts for the forest DNS name to analyze. Press Enter to keep the current logon forest or the previously selected target.

Each Threat Detection run also saves a PowerShell transcript named `MATI.transcript.txt` in the execution output folder.

At startup, MATI also displays the execution context of the operator and launch host: user domain, `sAMAccountName`, UPN, computer name, FQDN, and machine domain. The same context is included in the JSON metadata export.

---

## Project structure

```
Microsoft Active Directory Threat Inspector/
├── Invoke-MATI.ps1            # Entry point
├── Config/
│   └── MATI.config.psd1       # All thresholds, weights, exclusions
├── Collectors/                 # 18 data collectors (AD queries, event logs)
├── Rules/                      # 157 detection rules across 11 categories
│   ├── ACL/
│   ├── ADCS/
│   ├── Config/
│   ├── Delegation/
│   ├── GPO/
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

1. Each category has a **point budget** (e.g., Hardening = 15, Kerberos = 12, RODC = 5). Configured budgets total **116**, including the reserved Governance budget; they are not a percentage split of 100. Existing weights are preserved.
2. Each rule that fires consumes a **percentage** of the remaining budget based on severity (Critical 35%, High 20%, Medium 8%, Low 3%).
3. Diminishing returns: the first failed rule in a category hurts the most; subsequent failures impact less because the pool is already partially consumed.
4. The final score is the base score minus deductions, floored at zero. Unfiltered Partial assessments display the calculated A–E grade as provisional when at least one rule was evaluated. Complete assessments display the same grade without that qualification.

| Grade | Score |
|:-:|---|
| **A** | ≥ 85 |
| **B** | ≥ 70 |
| **C** | ≥ 50 |
| **D** | ≥ 30 |
| **E** | < 30 |

Score history is appended to `History\MATI_ScoreHistory_v2.csv`, with forest,
tool version, selection/exclusions, status and coverage counts. The legacy
`MATI_ScoreHistory.csv` is left untouched. Compare runs only when forest, scope,
version and coverage are comparable.

---

## Detection boundaries and effective settings

- **Localized privileged groups** are identified by their domain SID and RID, not only by English names. Privileged FGPP coverage uses the DC-calculated `msDS-ResultantPSO` per enabled user rather than the mere existence of a policy.
- **Scoped group membership** reads local `Members` links and individual in-forest objects directly, with cycle and duplicate guards. `DirectMembershipComplete` describes direct link inventory; `RecursiveMembershipComplete` and `MembershipComplete` describe target-forest traversal, independently of optional name translation (`IdentityResolutionComplete`). `ExternalPrincipalCount` and `ExternalMembers` retain out-of-scope entries. `MemberCount` stays null if local traversal is incomplete or external entries prevent a total expanded count; `KnownMemberCount` counts confirmed in-forest principals only. Direct-member findings use the exact `DirectMemberCount`. AdminCount findings require a complete in-forest index and make no claim about paths through external forests; review those before changing account protection. RODC deny-list SID checks require complete local object/link reads, not access to trusted-forest attributes.
- **Rule coverage** uses concrete collector datasets where access is statically identifiable. Rules using aliases, dynamic lookup or ambiguous access remain conservatively collector-wide unless they declare `CollectorDatasets`. Explicit requirements can distinguish direct group inventory, recursive membership of specific groups and account properties. Unknown read failures are never reclassified as harmless diagnostics.
- **Constrained delegation** includes Kerberos-only accounts with `msDS-AllowedToDelegateTo`, even without protocol transition. RC4 service-account correlation uses SID or domain/account observations, not full SPN strings or truncated report Top-N lists. No observed usage is not proof that an account cannot use RC4.
- **GPO settings are linked configuration, not RSoP.** Domain/DC OU link order, enforcement, inheritance blocking and disabled computer settings are handled. Security/WMI filters, site policy, nested DC OUs and local policy are not evaluated. Verify actual client RSoP before concluding applicability or exploitability.
- **ESC6** reads `EditFlags` from the CA policy module, not the CA root key. Exploitability still depends on templates, enrollment rights, approval/signatures and certificate mapping.
- **ESC7** reads the CA service security descriptor, not the AD enrollment object's ACL. It reports broad low-privilege allow ACEs for Manage CA / Issue and Manage Certificates, accounting for same-SID deny bits. It is not a full effective-access calculation for every nested/custom group, role-separation setting or deny combination.
- **Certificate binding and KDC RC4 defaults** use OS build/revision baselines, not the date a hotfix happened to be installed. Supported baselines cover Server 2016/2019/2022/2025, including the distinct February/September 2025 hotpatch revisions. September 2025 certificate-binding enforcement overrides residual compatibility registry values. January/April/July 2026 RC4 phase changes and explicit `DefaultDomainSupportedEncTypes` overrides are distinguished.
- **Unknown is not absent.** Unsupported or missing OS revisions, unreadable critical registry values and inaccessible logs/settings are reported for manual verification. Older Windows builds are not assigned guessed patch-dependent defaults.

Baseline references:
[KB5014754 — certificate-based authentication](https://support.microsoft.com/help/5014754),
[KB5073381 — RC4 phase changes](https://support.microsoft.com/help/5073381),
[Windows Server release history](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info).

---

## Offline regression tests

From the MATI directory, with Pester 3.4 or 4.x (legacy assertion syntax):

```powershell
Invoke-Pester -Script .\Tests
```

[Detection-only tests](Tests/DetectionOnly.Tests.ps1) verify launcher separation
and output paths. [Regression tests](Tests/Regression.Tests.ps1) exercise
coverage/scoring, exports/history, localized groups, member-link recovery with
foreign/unreadable principals, nested cross-domain groups and cycles, resultant PSO, delegation,
patch baselines, CA settings/permissions, protocol events and GPO precedence.
[Membership coverage tests](Tests/MembershipCoverage.Tests.ps1) cover scoped
coverage, foreign lookup caching and a real timeout/cleanup check using a
synthetic sleeping job (no AD access).
They use synthetic data, mocked AD/remoting/registry/event calls and local
SYSVOL fixtures. They do not perform a live AD assessment or change AD.
Real-forest validation with representative permissions and patch levels remains
necessary before production use.

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

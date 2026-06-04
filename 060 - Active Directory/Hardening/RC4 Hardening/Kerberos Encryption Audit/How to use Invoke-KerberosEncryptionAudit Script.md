# `Invoke-KerberosEncryptionAudit.ps1`

Read-only PowerShell audit script that automates the inventory phase of the **RC4 Hardening** series. It correlates KDC-side configuration, account capability, KDC-flagged events and live Kerberos traffic into a unified HTML / JSON / CSV report, and produces the prioritized remediation backlog described in [Article 2 §0](../2.%20Legacy%20Dependency%20Mapping%20and%20Technical%20Inventory.md).

> **Read-only by design.** No `Set-AD*`, no registry writes, no password rotation, no GPO change. The script lives in the inventory phase — never in the remediation phase.

---

## What it does, mapped to Article 2

| Script function | Covers |
| --- | --- |
| `Get-KdcDefaultAudit` | Reads `DefaultDomainSupportedEncTypes` on every DC in scope — DC-side KDC posture (Article 2 §2 Source 0a, required by §8 Definition of Done). |
| `Get-Rc4DisablementPhaseAudit` | Reads `RC4DefaultDisablementPhase` (KB5073381 / Jan 2026) on every DC — the per-DC valve that controls whether Kdcsvc 201-209 are produced (Article 2 §2 Source 0b). |
| `Get-AccountKerberosAudit` | LDAP inventory of `msDS-SupportedEncryptionTypes` on users, computers and managed service accounts (Article 2 §2 Source 2 + §5 Pattern D capability evidence). |
| `Get-KerberosEventAudit` | Collects 4768 + 4769 over a configurable window, leveraging the post-KB5021131 (Nov 2022) enriched fields `Ticket Encryption Type`, `Available Keys`, `Advertised Etypes`, `Pre-Authentication EncryptionType` and `Session Encryption Type` (Article 2 §2 Source 1 + §5 Patterns A, B, C). |
| `Get-KdcsvcEventAudit` | Collects Kdcsvc System-log events 201-209 from each DC at Phase ≥ 1, mapped to Patterns B / D / Hygiene per Article 1 §6 (Article 2 §2 Source 0c). |
| `Invoke-TrustEncryptionAudit` | Self-contained TDO inventory via `Get-ADTrust` (no external script dependency since v1.1.6). Reads `msDS-SupportedEncryptionTypes` + `trustAttributes` on every Trusted Domain Object visible from the local domain, classifies each one (AES-only / Mixed / RC4-only / Legacy-DES / Unset) and folds the rows into the report when `-IncludeTrusts` is set (Article 2 §2 Source 3, §5 Pattern C). |
| `Build-Rc4Backlog` | Produces the §0 deliverable: one row per dependency with deterministic Blast-radius / Exposure / Fix-cost scoring (1–9), owner from `-OwnerMappingPath`, and a recommended action. |
| Report builder (HTML / JSON / CSV) | Renders the unified report and exports `Backlog.csv` plus per-section CSVs. |

---

## Prerequisites

**On the workstation running the script:**

- **PowerShell 7.2+** (the script declares `#Requires -Version 7.2` and uses `ForEach-Object -Parallel` for cross-DC collection — Windows PowerShell 5.1 is **not** supported).
- **RSAT — Active Directory module** (`Get-ADUser`, `Get-ADComputer`, `Get-ADDomainController`, `Get-ADTrust`, `Get-ADRootDSE`).
- Network reachability to all DCs in scope (LDAP 389 / 636, RPC for `Get-WinEvent -ComputerName`, remote registry).

**Permissions:**

- **Domain Users** is sufficient to read `msDS-SupportedEncryptionTypes` on accounts and `DefaultDomainSupportedEncTypes` on the domain object (default ACL).
- **Event Log Readers** group membership (or equivalent) on every DC in scope — required to read Security log (4768/4769) and System log (Kdcsvc 201-209) remotely.
- **Remote registry** read access on every DC — required for `RC4DefaultDisablementPhase`.
- No write permissions are needed and none are requested. If the running account has Domain Admin rights the script does not exercise them.

**On every DC in scope:**

- **Audit policy `Account Logon → Kerberos Authentication Service`** = Success (4768 generation). Verify with `auditpol /get /category:"Account Logon"`.
- **Audit policy `Account Logon → Kerberos Service Ticket Operations`** = Success (4769 generation).
- **Security log size ≥ 1 GB** so 4768/4769 events are not rotated out of the observation window.
- For Kdcsvc 201-209 visibility: **`RC4DefaultDisablementPhase = 1` (or `2`)** in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters` (KB5073381, January 2026 cumulative or later). Phase 0 / absent registry → no Kdcsvc events; the audit will report this gap as a finding. *Note: do not confuse this hive with `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`, which holds the unrelated `DefaultDomainSupportedEncTypes` value.*

---

## Parameters

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-Days` | `int` | `1` | Observation window for 4768/4769/Kdcsvc collection, in days. Common values: 1 (smoke test), 7 (1 week), 14 (2 weeks — recommended baseline). Range 1-365. |
| `-DomainControllers` | `string[]` | All DCs in current domain | Optional subset. Use FQDNs. Useful for piloting on one DC before domain-wide collection. The default uses `Get-ADDomainController -Filter *` and therefore covers the **current domain only** — to audit other domains in the same forest, run the script once per domain. |
| `-MaxEventsPerDc` | `int` | `5000` | Per-DC cap on collected Kerberos events to avoid runaway runs in large environments. Increase if the report shows a "truncated" warning on hot DCs. |
| `-ExportCsv` | `switch` | off | Emit per-section CSVs alongside HTML/JSON (accounts, tickets, Kdcsvc, trusts, backlog). `Backlog.csv` is *always* written when the backlog has rows — independent of this switch. |
| `-OpenReport` | `switch` | off | Open the generated HTML report in the default browser when the run finishes. |
| `-IncludeTrusts` | `switch` | off | Inventory Trusted Domain Objects via `Get-ADTrust` and fold TDO classification into the report. Required to satisfy the Article 2 §0 deliverable end-to-end. |
| `-OwnerMappingPath` | `string` | `$null` | Path to a CSV file mapping account/SPN patterns to owners (see *Owner mapping* below). When omitted, every backlog row gets `Owner = TBD`. |
| `-OutputDir` | `string` | `Outputs\KerberosEncryptionAudit_<timestamp>` | Override the output directory. The default places one timestamped folder per run next to the script. |

---

## Quick start

```powershell
# Default: 1-day window, all DCs in current domain, HTML + JSON reports
.\Invoke-KerberosEncryptionAudit.ps1

# 7-day window, open the report when done
.\Invoke-KerberosEncryptionAudit.ps1 -Days 7 -OpenReport

# 14-day window with all CSVs (spreadsheet work)
.\Invoke-KerberosEncryptionAudit.ps1 -Days 14 -ExportCsv

# Full Article 2 §0 deliverable: include trust audit + load owner mapping
.\Invoke-KerberosEncryptionAudit.ps1 -Days 7 -IncludeTrusts -OwnerMappingPath .\owners.csv -ExportCsv -OpenReport

# Targeted DC subset (pilot run)
.\Invoke-KerberosEncryptionAudit.ps1 -DomainControllers DC01.contoso.com,DC02.contoso.com -Days 7
```

### Owner mapping CSV format

```csv
Pattern,Owner
SQL-*,Database team
WEB-*,Web platform team
*-DC*,AD operations
fileserver-*,Storage team
svc_iis_*,Web platform team
```

Pattern matching uses PowerShell `-like` semantics (so `*` is a wildcard). The first matching pattern wins; rows with no match get `Owner = TBD`.

---

## Output structure

Each run creates `Outputs\KerberosEncryptionAudit_<yyyyMMdd_HHmmss>\` (or the directory passed via `-OutputDir`) containing:

| File | When produced | Content |
| --- | --- | --- |
| `KerberosEncryptionAudit.html` | Always | Unified human-readable report (DC posture, accounts, tickets, Kdcsvc, trusts, backlog). |
| `KerberosEncryptionAudit.json` | Always | Same data as HTML, machine-readable — feed into a SIEM or downstream automation. |
| `Backlog.csv` | When ≥ 1 backlog row was scored | **The Article 2 §0 deliverable** — prioritized remediation backlog, one row per RC4 dependency, with deterministic scoring (BlastRadius / Exposure / FixCost / Score 1–9), Source (which detection produced the row: account capability, RC4 ticket, RC4 client ≥ 50 events, non-AES TDO, etc.), RecommendedAction, and Owner (from `-OwnerMappingPath`). Always written when the backlog has rows, **independent of `-ExportCsv`** — the HTML report only displays the first 200 rows, so the CSV is the canonical full-dataset artefact you hand to remediation owners. |
| `KdcsvcEvents.csv`, `KdcsvcSummary.csv`, `PriorityAccounts.csv`, `TicketBreakdownByType.csv`, `TicketBreakdownGlobal.csv`, `Rc4RequestorAccounts.csv`, `Rc4TargetServices.csv`, `Trusts.csv`, `AllTicketEvents.csv` | `-ExportCsv` only | Per-section dumps for spreadsheet triage. `AllTicketEvents.csv` is the unfiltered 4768/4769 dataset; `PriorityAccounts.csv` is the curated short-list used by the HTML report; the two `TicketBreakdown*` CSVs are pivot-friendly aggregates by ticket type and globally. |

---

## Reading the report — four operational questions

The HTML output is structured around four questions, in this order:

1. **Is the DC posture already locked to AES-only?** — *KDC Default* + *Phase* sections. DCs that still allow mixed or implicit behavior are flagged, and DCs at Phase 0 / absent registry are explicitly called out as inventory blind spots.
2. **Which identities still block AES-only enforcement?** — *Accounts* + *Trusts* sections, with emphasis on SPN-bearing service identities and trust objects whose attribute is anything but AES-only.
3. **Is RC4 still present in live Kerberos traffic?** — *Kdcsvc* (KDC-side flagged events 201-209) + *Tickets* + *RC4 Hotspots* sections. The Kdcsvc table is usually the cheapest entry point because the KDC has already extracted the offending account name.
4. **What is the prioritized remediation backlog?** — the *Backlog* section materializes the Article 2 §0 deliverable with deterministic scoring. Rows at score ≥ 8 are immediate-wave; 6-7 are next wave; below 6 are after quick wins or decommission candidates.

Move from control plane (what is allowed) to KDC-flagged events (what the KDC actually rejects) to data plane (what the KDC actually issues), then read the backlog rows top-down by score, and assign each row to an Article 2 §4 wave + owner.

---

## Known limitations

The tool is read-only and domain-local by design (one run per domain — see `-DomainControllers` note above). Its remaining honest limitations are:

- **Single-side trust view.** `Invoke-TrustEncryptionAudit` inventories only the LOCAL side of each trust via `Get-ADTrust`. Each TDO has a twin on the remote side with its own `msDS-SupportedEncryptionTypes`. Run the same audit there to compare.
- **Attribute-only trust classification.** AES-only at the attribute level does not guarantee AES referrals — the trust password must have been rotated *after* the attribute change for AES keys to be materialized in `supplementalCredentials`. The tool flags this caveat but cannot read `supplementalCredentials`.
- **Phase 0 and absent-registry blind spot.** Until every DC is at `RC4DefaultDisablementPhase ≥ 1`, the Kdcsvc table is incomplete. The tool quantifies the gap ("DCs at Phase ≥ 1" KPI) but cannot fix it.
- **Passive Kerberos consumers (keytab-only services) stay invisible at the device level.** A non-Windows appliance with a static keytab consumes TGS without ever authenticating against the DC, so no 4768 is generated for the appliance host. The AD account behind the SPN remains visible (4769 ServiceName, msDS-SET, pwdLastSet), but mapping the SPN to a physical host requires a complementary field inventory (`klist -k /etc/krb5.keytab` on each Linux host, or a CMDB attribute). See Article 2 §2 Source 1a deep dive.
- **No SIEM correlation.** KQL / Splunk searches over historical 4768 / 4769 / Kdcsvc data live in the *RC4 telemetry & inventory reporting* annex, not in this tool.
- **Heuristic scoring.** Blast radius / Exposure / Fix cost are rule-of-thumb classifications. Adjust the thresholds in `Build-Rc4Backlog` for environments where SPN-bearing accounts are not always Critical, or where event counts have a different operational meaning.

---

## Common mistakes the tool helps you avoid

- Looking at `msDS-SupportedEncryptionTypes` only and ignoring 4768 / 4769 — capability ≠ runtime.
- Treating absent values as fully remediated just because KB5021131 improved the implicit default.
- Confusing `0x1C` (RC4 + AES) with "AES-only" — the RC4 bit is still set.
- Using `lastLogonTimestamp` as a "this account is unused" filter — passive SPN consumers do not bump it (Article 2 §2 Source 1a deep dive).
- Enforcing AES-only on the KDC before the priority accounts list is empty.

---

## Validation coverage matrix

This section is a **coverage matrix**, not a runnable test suite. Each row describes a real-world AD/DC condition the script must detect, and the signal it must surface (JSON field, HTML section, KPI). Use it as the acceptance criteria for the script: if a row's expected detection does not appear in the output when the condition is present in the audited domain, that is a script bug. *How* you reproduce each condition in a lab is left to the operator — see Article 2 §6 for setup patterns.

Conditions are organised by layer: account inventory, KDC infrastructure (Default + Phase), trusts, live 4768/4769 events, Kdcsvc 201-209, backlog scoring, robustness, concurrency and output format. **Several conditions (DC registry values, account `msDS-SupportedEncryptionTypes`, Trusted Domain Objects) would impact real authentication if reproduced in production — only reproduce in an isolated lab.**

### Coverage matrix

| ID  | Category | Condition in the audited domain | Expected detection in the script output |
| --- | --- | --- | --- |
| **T01** | Baseline | Healthy domain, nothing unusual | Run completes with `Errors.Count = 0` and `Warnings.Count = 0` (apart from collection warnings such as empty event window). |
| **T02** | Inventory | User account with `msDS-SupportedEncryptionTypes` unset (null) and no SPN | Account classified `Info (Unset/0, non-service inherits KDC default)` in `AccountStatusSummary`. Not in `PriorityAccounts`. |
| **T03** | Inventory | User account with RC4-only (`msDS-SET = 0x4`) | Account classified `Failed (RC4-only/No AES)`. Listed in `PriorityAccounts`. |
| **T04** | Inventory | User account with DES-only (`msDS-SET = 0x3`) | Account classified `Failed (DES-only/No AES)`. Listed in `PriorityAccounts`. |
| **T05** | Inventory | User account with AES-only (`msDS-SET = 0x18`) | Account classified `Compliant (AES present)`. |
| **T06** | Inventory | Service account (SPN present) with AES + RC4 allowed (`msDS-SET = 0x1C`) | Account classified `Warning (AES present + RC4 allowed)`. Listed in `PriorityAccounts`. |
| **T07** | Inventory | Account with a value containing no AES/RC4/DES enc-type bit (e.g. `0x40` only) | Account classified `Failed (No AES)`. Hex flags rendered with the unknown bit. |
| **T08** | Inventory | Account with AES256-SK only (`msDS-SET = 0x20`, post-CVE-2022-37966 hardening bit) | Account classified `Compliant (AES present)`. Flags rendered as `0x20 [AES256-SK]`. |
| **T09** | Inventory | Account with capability-only bits set (e.g. `0x50000` = FAST + Claims, krbtgt-style) | Account classified `Info (Unset/0, ...)` — script masks `0x3F` to ignore non-enc-type capability bits. Flags rendered as `0x50000 [FAST-Supported, Claims-Supported]`. |
| **T10** | Inventory | Service account (SPN present) with `msDS-SET` unset | Account classified `Warning (Unset/0, service relies on KDC default)`. Listed in `PriorityAccounts`. |
| **T11** | Inventory | `krbtgt` account is present (always true) | `PriorityAccounts` does NOT contain `krbtgt` (explicitly filtered — it is special-cased and audited by KB5021131 logic). |
| **T12** | Inventory | Computer account at `msDS-SET = 0x1C` (very common after KB5021131 self-update) | NOT listed in `PriorityAccounts` when status is `Info*` — filter keeps large fleets readable. Still counted in `AccountStatusSummary`. |
| **T13** | KDC default | `DefaultDomainSupportedEncTypes` registry absent on a DC | DC classified `Warning (AES default, not enforced)` in the *KDC Default* section. |
| **T14** | KDC default | DC with `DefaultDomainSupportedEncTypes = 0x18` (AES-only) | DC classified `Compliant (AES-only default)`. KPI `DCs with AES-only KDC default` incremented. |
| **T15** | KDC default | DC with `DefaultDomainSupportedEncTypes = 0x1C` (mixed AES+RC4) | DC classified `Warning (Mixed or RC4 allowed)`. |
| **T16** | KDC default | 100% of DCs in the domain at `0x18` | KPI `DCs with AES-only KDC default` shows full coverage and Status = `OK`. |
| **T17** | Phase | `RC4DefaultDisablementPhase` registry absent on every DC | Every DC line in *Rc4DisablementPhase* shows `Status = 'Info (registry absent)'`. KPI `DCs at Phase >= 1` = 0. |
| **T18** | Phase | DC with `RC4DefaultDisablementPhase = 0` (silent) | DC classified `Warning (silent)` — the explicit 0 is reported separately from "registry absent". |
| **T19** | Phase | DC with `RC4DefaultDisablementPhase = 1` (audit) | DC classified `Compliant (Phase 1 audit)`. Counted in KPI `DCs at Phase >= 1`. |
| **T20** | Phase | DC with `RC4DefaultDisablementPhase = 2` (enforce) | DC classified `Compliant (Phase 2 enforce)`. Counted in KPI `DCs at Phase >= 1`. |
| **T21** | Trust | TDO with AES-only encryption | Listed in `Trusts` with `Classification = 'AES-only'`. |
| **T22** | Trust | TDO with `msDS-SupportedEncryptionTypes` unset | Listed in `Trusts` with `Classification = 'Unset'`. |
| **T23** | Trust | TDO with RC4-only (`msDS-SET = 0x4`) | `Classification = 'RC4-only'`. Backlog row with `Source = TDO`, `Score = 8`. |
| **T24** | Trust | TDO with mixed AES+RC4 (`msDS-SET = 0x1C`) | `Classification = 'Mixed'`. |
| **T25** | Trust | TDO with DES (`msDS-SET = 0x1`) | `Classification = 'Legacy-DES'`. Backlog row with `FixCost = High`. |
| **T26** | 4768/4769 | 4769 (TGS) issued for a RC4-only service in the lookback window | `TotalRc4Events >= 1`. Service listed in `Rc4TargetServices`. `AvoidableRc4Tgs = 0` (service is not AES-capable). |
| **T27** | 4768/4769 | 4768 (AS-REQ) from a RC4-only requestor (Pattern B) | Requestor listed in `Rc4RequestorAccounts`. Account `Status = 'Failed (RC4-only/No AES)'`. |
| **T28** | 4768/4769 | TGT (4768) encrypted with RC4 visible | `TicketBreakdownByType` contains line `TGT / RC4-HMAC` with `Events >= 1`. |
| **T29** | 4768/4769 | TGS (4769) encrypted with RC4 visible | `TicketBreakdownByType` contains line `TGS / RC4-HMAC` with `Events >= 1`. |
| **T30** | 4768/4769 | TGS issued in RC4 to an AES-capable service from an AES-capable client (RC4 forced client-side) | `AvoidableRc4Tgs >= 1` — script flags as avoidable because the service has AES bits. |
| **T31** | 4768/4769 | Service has AES bits in `msDS-SET` but its key material is still RC4 (password not rotated after the AES bit was added — Pattern D / stale key) | Inventory shows `Compliant (AES present)` BUT a RC4 4769 for the same service is visible in the window. Demonstrates the documented limitation of attribute-based classification. |
| **T32** | 4768/4769 | Same service as T31 after a password reset | Subsequent 4769 events for that service now in AES (e.g. `0x12` = AES256). No new RC4 event. |
| **T33** | 4768/4769 | 4769 where client advertised AES but service ticket was returned in RC4 (T31 reproduces it naturally) | `MisconfiguredClientSignal = True` on the event (visible in `AllTicketEvents.csv` when `-ExportCsv`). |
| **T34** | Kdcsvc | Kdcsvc 201 emitted by a DC at Phase 1 (Pattern B audit, no explicit GPO) | `KdcsvcEvents` contains entry with `EventId = 201`, `Pattern = B`, `Severity = Audit`. |
| **T35** | Kdcsvc | Kdcsvc 206 emitted (Pattern B audit with explicit insecure default) | Entry with `EventId = 206`, `Pattern = B`, `Severity = Audit`. |
| **T36** | Kdcsvc | Kdcsvc 202 emitted (Pattern D audit — stale RC4 key after AES bit set) | Entry with `EventId = 202`, `Pattern = D`. |
| **T37** | Kdcsvc | Kdcsvc 205 emitted at service start because DC default is insecure | Entry with `EventId = 205` (1 per Kdcsvc start). KPI `Kdcsvc 205 hygiene findings >= 1`. |
| **T38** | Kdcsvc | Kdcsvc 203 emitted by a DC at Phase 2 (Pattern B enforce — authentication actually rejected) | Entry with `EventId = 203`, `Pattern = B`, `Severity = Enforce`. |
| **T39** | Backlog | RC4-using service with >5 events in the window | Backlog row with `Source = Account`, `Type = Service account`, `Score >= 5`. |
| **T40** | Backlog | Non-AES trust (RC4-only, Mixed or DES) | Backlog row `Trust: <name>` with `Source = TDO`, `Score = 8` (Critical + Frequent + Medium). |
| **T41** | Backlog | RC4-only client account with >= 50 events in the window (Pattern B at scale) | Backlog row with `Source = Account`, `Type = Client account (Pattern B)`. |
| **T42** | Backlog | Same account triggers both source 1 (RC4 service) and source 3 (RC4 client) | Single backlog row (deduplicated — source 1 wins). |
| **T43** | Backlog | `-OwnerMappingPath` provided with a CSV mapping `usr.*` to `Team-A` | Backlog rows whose `Dependency` matches `usr.*` have `Owner = Team-A`. |
| **T44** | Robustness | DC list contains an unreachable host | DC line in *KDC Default* with `Status = 'Failed'`. `Errors.Count >= 1`. Other DCs still collected. |
| **T45** | Robustness | Script invoked with `-Days 0` | Parameter validation error from `[ValidateRange(1, 365)]` (since v1.2.0). |
| **T46** | Robustness | Script invoked with `-MaxEventsPerDc -1` | Parameter validation error. |
| **T47** | Robustness | `-OwnerMappingPath` points to a non-existent file | `Warnings` contains `"Owner mapping file not found"`. Run continues without owner enrichment. |
| **T48** | Robustness | Audited window contains zero 4768/4769 events | `Warnings` contains `"No 4768/4769 events were collected"`. Run completes; sections that depend on events are empty. |
| **T49** | Robustness | RSAT-AD-PowerShell module not present on the host | Fatal error at startup: `Active Directory discovery failed`. |
| **T50** | Robustness | Account name contains LDAP metacharacters | No crash; value is displayed verbatim (v1.1.9 helpers `ConvertTo-LdapFilterSafe` / `ConvertTo-LdapRfc4515Safe` escape correctly). |
| **T51** | Robustness | Domain has zero trusts, run with `-IncludeTrusts` | `Trusts.Count = 0`. No error. Log line `Trusts inventoried = 0`. |
| **T52** | Robustness | Run without `-IncludeTrusts` | `Trusts.Count = 0`. Log line `Skipped (use -IncludeTrusts...)`. *Trusts* HTML section absent. |
| **T53** | Robustness | Run with `-ExportCsv -IncludeTrusts` | 10 `*.csv` files created in OutputDir (`KdcsvcEvents`, `KdcsvcSummary`, `PriorityAccounts`, `TicketBreakdownByType`, `TicketBreakdownGlobal`, `Rc4RequestorAccounts`, `Rc4TargetServices`, `Trusts`, `Backlog`, `AllTicketEvents`). |
| **T54** | Robustness | Run without `-ExportCsv`, but `Backlog.Count > 0` | `Backlog.csv` still produced (always exported when non-empty). |
| **T55** | Robustness | Run with `-OpenReport` | Default browser opens on `KerberosEncryptionAudit.html` at the end of the run. |
| **T56** | Concurrency | Domain with >= 5 DCs | DC collection runs in parallel with throttle at 4 (`ForEach-Object -Parallel -ThrottleLimit 4`). |
| **T57** | Concurrency | One DC becomes unreachable mid-run | Failure isolated to that DC's entry in `Errors`. Other DCs collected and reported normally. |
| **T58** | JSON format | Run completed | `KerberosEncryptionAudit.json` parses successfully with `ConvertFrom-Json` — no exception. |
| **T59** | HTML format | Run completed | `KerberosEncryptionAudit.html` renders in a browser. All navigation anchors (*Summary, Backlog, KDC Default, Phase, Kdcsvc, Accounts, Trusts, Tickets, RC4 Hotspots, Artifacts*) resolve. |
| **T60** | Idempotence | Two consecutive runs against an unchanged domain | JSON outputs differ only on `StartedAt` (timestamp). `AccountStatusSummary`, `KdcDefaults`, `Trusts`, `Backlog` are identical between runs. |

### Recommended subset for client validation

If time is short, here is the minimum surface to sign off production quality. Pick the rows from the matrix above:

| Priority | IDs |
| --- | --- |
| **P0 — must verify** | T01, T03, T05, T08, T09, T11, T12, T26, T58, T59, T60 |
| **P1 — strongly recommended** | T13, T14, T17, T19, T21, T27, T44, T47, T48, T52 |
| **P2 — nice to have** | T15, T22, T23, T30, T31, T34, T36, T39, T40, T43, T53 |
| **P3 — lab only / destructive** | T20, T24, T25, T35, T37, T38, T41, T49, T57 |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Empty *Tickets* section even though Kerberos is heavily used | Audit policy off on DCs (no 4768/4769 generated) | `auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable` and the same for `Kerberos Service Ticket Operations`. Wait for the next observation window before re-running. |
| `Get-WinEvent` errors on one or more DCs | Account lacks Event Log Readers, or RPC blocked | Add the running account to the Event Log Readers group on the DC, or open `RPC Endpoint Mapper` + dynamic RPC ports. |
| *Tickets* section shows "truncated" warning on a hot DC | `MaxEventsPerDc` cap reached | Increase `-MaxEventsPerDc`, or split the run by `-DomainControllers` per DC, or shorten `-Days`. |
| Kdcsvc section completely empty on a recent OS | DC at Phase 0 or KB5073381 not yet deployed | Verify `RC4DefaultDisablementPhase` (the script reports this in *DC posture*). Set to `1` once you are ready to surface the events. |
| Backlog rows all show `Owner = TBD` | No `-OwnerMappingPath` or no patterns matched | Provide an `owners.csv` with account/SPN wildcard patterns. |
| `KerberosEncryptionAudit.html` looks broken / missing sections | Run interrupted mid-collection | Re-run with the same parameters; each run writes a new timestamped folder. |

---

## Related references

- [Article 1 — RC4 Fundamentals, Obsolescence, and Risks of Continued Use](../1.%20RC4%20Fundamentals%2C%20Obsolescence%2C%20and%20Risks%20of%20Continued%20Use.md)
- [Article 2 — Legacy Dependency Mapping and Technical Inventory](../2.%20Legacy%20Dependency%20Mapping%20and%20Technical%20Inventory.md) — the methodology this tool automates.
- [Article 3 — Remediation, AES Migration, Cutover, and RC4 Extinction](../3.%20Remediation%2C%20AES%20Migration%2C%20Cutover%2C%20and%20RC4%20Extinction.md)
- [Hardening Kerberos Encryption on AD Trusts](../Hardening%20Kerberos%20Encryption%20on%20AD%20Trusts/Hardening%20Kerberos%20Encryption%20on%20AD%20Trusts.md) — sister article and home of `Get-TrustEncryptionAudit.ps1`.
- [Weak supported encryption algorithms on DCs](../Weak%20supported%20encryption%20algorithms%20on%20DCs.md)

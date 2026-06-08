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
- **Passive Kerberos consumers (keytab-only services) stay invisible at the device level.** A non-Windows appliance with a static keytab consumes TGS without ever authenticating against the DC, so no 4768 is generated for the appliance host. The AD account behind the SPN remains visible (4769 ServiceName, msDS-SupportedEncryptionTypes, pwdLastSet), but mapping the SPN to a physical host requires a complementary field inventory (`klist -k /etc/krb5.keytab` on each Linux host, or a CMDB attribute). See Article 2 §2 Source 1a deep dive.
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

## Validation lab playbook

This section is a **lab playbook**: for every detection path of the script, it gives a reproducible PowerShell recipe to simulate the condition in an isolated lab, the signal you should then see in the script output, and the cleanup to bring the lab back to its previous state. Use it to validate that every detection actually fires, end to end. **Run only in an isolated lab** — several rows mutate DC registry values, account `msDS-SupportedEncryptionTypes`, or Trusted Domain Objects, and would impact real authentication if applied to production.

**Reading conventions:**

- Each row is self-contained: the `Setup commands` cell creates the condition from scratch, the `Cleanup` cell rolls it back. Tests do not depend on each other.
- Placeholders to replace with your lab values: `dc01.lab.local` (a writable DC), `client01.lab.local` (a domain-joined workstation separate from any DC, used to trigger Kerberos requests), `lab.local` (your domain DNS root), `LAB` (your domain NetBIOS name), `P@ssw0rd!2026` (lab password literal — change to satisfy your password policy).
- Each test uses a unique account named `usr.tNN` / `svc.tNN` so cleanups never collide.
- **After running the `Setup commands`, execute the audit script and verify the `Expected detection`** in the resulting JSON / HTML / CSV:
  ```powershell
  .\Invoke-KerberosEncryptionAudit.ps1 -IncludeTrusts -ExportCsv -OutputDir .\Outputs\T<NN>
  ```
  For rows that depend on freshly generated 4768/4769 events, wait ~30 seconds between Setup and the audit, and use `-Days 1` (default). For Kdcsvc rows, the DC must have been restarted after the registry change (the Setup commands handle this).
- All `Invoke-Command -ComputerName` calls require PowerShell Remoting (enabled by default on DCs and on Windows servers; on client workstations enable it with `Enable-PSRemoting -Force`).

### Test matrix

| ID  | Category | Condition | Setup commands | Expected detection | Cleanup |
| --- | --- | --- | --- | --- | --- |
| **T01** | Baseline | Healthy domain, nothing unusual | None — run the audit on the lab as-is. | `Errors.Count = 0`, `Warnings.Count = 0` (apart from collection warnings such as empty event window). Capture as baseline for diffs. | None. |
| **T02** | Inventory | User with `msDS-SupportedEncryptionTypes` unset and no SPN | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t02 -AccountPassword $pw -Enabled $true` | Account classified `Info (Unset/0, non-service inherits KDC default)` in `AccountStatusSummary`. Not in `PriorityAccounts`. | `Remove-ADUser usr.t02 -Confirm:$false` |
| **T03** | Inventory | User RC4-only (`msDS-SupportedEncryptionTypes = 0x4`) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t03 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4` | Account classified `Failed (RC4-only/No AES)`. Listed in `PriorityAccounts`. | `Remove-ADUser usr.t03 -Confirm:$false` |
| **T04** | Inventory | User DES-only (`msDS-SupportedEncryptionTypes = 0x3`) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t04 -AccountPassword $pw -Enabled $true`<br>`Set-ADUser usr.t04 -Replace @{'msDS-SupportedEncryptionTypes'=3}` | Account classified `Failed (DES-only/No AES)`. Listed in `PriorityAccounts`. | `Remove-ADUser usr.t04 -Confirm:$false` |
| **T05** | Inventory | User AES-only (`msDS-SupportedEncryptionTypes = 0x18`) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t05 -AccountPassword $pw -Enabled $true -KerberosEncryptionType AES128,AES256` | Account classified `Compliant (AES present)`. | `Remove-ADUser usr.t05 -Confirm:$false` |
| **T06** | Inventory | Service account with AES + RC4 allowed (`msDS-SupportedEncryptionTypes = 0x1C`) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t06 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4,AES128,AES256 -ServicePrincipalNames 'HTTP/usr.t06.lab.local'` | Account classified `Warning (AES present + RC4 allowed)`. Listed in `PriorityAccounts`. | `Remove-ADUser usr.t06 -Confirm:$false` |
| **T07** | Inventory | Value with no AES/RC4/DES enc-type bit (e.g. `0x40` only) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t07 -AccountPassword $pw -Enabled $true`<br>`Set-ADUser usr.t07 -Replace @{'msDS-SupportedEncryptionTypes'=64}` | Account classified `Failed (No AES)`. Hex flags rendered with the unknown bit. | `Remove-ADUser usr.t07 -Confirm:$false` |
| **T08** | Inventory | AES256-SK only (`msDS-SupportedEncryptionTypes = 0x20`, CVE-2022-37966 hardening bit) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t08 -AccountPassword $pw -Enabled $true`<br>`Set-ADUser usr.t08 -Replace @{'msDS-SupportedEncryptionTypes'=32}` | Account classified `Compliant (AES present)`. Flags rendered as `0x20 [AES256-SK]`. | `Remove-ADUser usr.t08 -Confirm:$false` |
| **T09** | Inventory | Capability-only bits set (e.g. `0x50000` = FAST + Claims, krbtgt-style) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t09 -AccountPassword $pw -Enabled $true`<br>`Set-ADUser usr.t09 -Replace @{'msDS-SupportedEncryptionTypes'=327680}` | Account classified `Info (Unset/0, ...)` — script masks `0x3F` to ignore non-enc-type capability bits. Flags rendered as `0x50000 [FAST-Supported, Claims-Supported]`. | `Remove-ADUser usr.t09 -Confirm:$false` |
| **T10** | Inventory | Service account (SPN) with `msDS-SupportedEncryptionTypes` unset | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t10 -AccountPassword $pw -Enabled $true -ServicePrincipalNames 'HTTP/usr.t10.lab.local'` | Account classified `Warning (Unset/0, service relies on KDC default)`. Listed in `PriorityAccounts`. | `Remove-ADUser usr.t10 -Confirm:$false` |
| **T11** | Inventory | `krbtgt` is always present | None. | `PriorityAccounts` does NOT contain `krbtgt` (special-cased — audited by KB5021131 logic). | None. |
| **T12** | Inventory | Computer accounts at `msDS-SupportedEncryptionTypes = 0x1C` (KB5021131 self-update) | None. Most lab DCs and member servers naturally reach `0x1C` after KB5021131. | Computer accounts with status `Info*` are NOT listed in `PriorityAccounts` (filter keeps large fleets readable). Still counted in `AccountStatusSummary`. | None. |
| **T13** | KDC default | `DefaultDomainSupportedEncTypes` absent on a DC | None — initial state on most labs. To force on a DC where it exists:<br>`Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc }` | DC classified `Warning (AES default, not enforced)` in *KDC Default*. | If you forced the absence above and want to restore the original value:<br>`Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x18 /f; Restart-Service kdc }` *(use `0x18` for AES-only or `0x1C` for mixed — match your pre-test value)* |
| **T14** | KDC default | DC with `DefaultDomainSupportedEncTypes = 0x18` (AES-only) | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x18 /f; Restart-Service kdc }` | DC classified `Compliant (AES-only default)`. KPI `DCs with AES-only KDC default` incremented. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc }` |
| **T15** | KDC default | DC with `DefaultDomainSupportedEncTypes = 0x1C` (mixed AES+RC4) | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x1C /f; Restart-Service kdc }` | DC classified `Warning (Mixed or RC4 allowed)`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc }` |
| **T16** | KDC default | 100% of DCs at `0x18` | `Get-ADDomainController -Filter * \| ForEach-Object { Invoke-Command -ComputerName $_.HostName -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x18 /f; Restart-Service kdc } }` | KPI `DCs with AES-only KDC default` Status = `OK`, full coverage. | `Get-ADDomainController -Filter * \| ForEach-Object { Invoke-Command -ComputerName $_.HostName -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc } }` |
| **T17** | Phase | `RC4DefaultDisablementPhase` absent on every DC | None — pre-KB5073381 state. | Every DC line in *Rc4DisablementPhase* shows `Status = 'Info (registry absent)'`. KPI `DCs at Phase >= 1` = 0. | None. |
| **T18** | Phase | DC at Phase 0 (silent) | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 0 /f; Restart-Service kdc }` | DC classified `Warning (silent)` — explicit 0 is reported separately from registry absent. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }` |
| **T19** | Phase | DC at Phase 1 (audit) | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 1 /f; Restart-Service kdc }` | DC classified `Compliant (Phase 1 audit)`. Counted in KPI `DCs at Phase >= 1`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }` |
| **T20** | Phase | DC at Phase 2 (enforce) — ⚠️ **destructive** | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 2 /f; Restart-Service kdc }` — **RC4-only authentications on that DC now fail.** | DC classified `Compliant (Phase 2 enforce)`. Counted in KPI `DCs at Phase >= 1`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }` |
| **T21** | Trust | Pre-existing AES-only TDO | Requires an existing AES-only trust in the lab. To create one: configure a forest/external trust to a partner domain and ensure both sides set `msDS-SupportedEncryptionTypes = 0x18` on their TDO. | Listed in `Trusts` with `Classification = 'AES-only'`. | If you created a new trust for this test, remove it: `Remove-ADTrust -Identity 'partner.lab.local'`. |
| **T22** | Trust | Pre-existing TDO with `msDS-SupportedEncryptionTypes` unset | Most new trusts are created Unset. | Listed in `Trusts` with `Classification = 'Unset'`. | None. |
| **T23** | Trust | TDO RC4-only (`msDS-SupportedEncryptionTypes = 0x4`) — ⚠️ **lab only** | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Replace @{'msDS-SupportedEncryptionTypes'=4}` *(replace DN with an actual lab TDO)* | `Classification = 'RC4-only'`. Backlog row with `Source = TDO`, `Score = 8`. | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Clear msDS-SupportedEncryptionTypes` |
| **T24** | Trust | TDO Mixed (`msDS-SupportedEncryptionTypes = 0x1C`) | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Replace @{'msDS-SupportedEncryptionTypes'=28}` *(replace DN with an actual lab TDO)* | `Classification = 'Mixed'`. | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Clear msDS-SupportedEncryptionTypes` |
| **T25** | Trust | TDO DES (`msDS-SupportedEncryptionTypes = 0x1`) | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Replace @{'msDS-SupportedEncryptionTypes'=1}` *(replace DN with an actual lab TDO)* | `Classification = 'Legacy-DES'`. Backlog row with `FixCost = High`. | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Clear msDS-SupportedEncryptionTypes` |
| **T26** | 4768/4769 | 4769 (TGS) issued for a RC4-only service | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t26 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t26.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t26.lab.local') }`<br>`Start-Sleep -Seconds 30` | `TotalRc4Events >= 1`. Service listed in `Rc4TargetServices`. `AvoidableRc4Tgs = 0`. | `Remove-ADUser svc.t26 -Confirm:$false` |
| **T27** | 4768/4769 | 4768 (AS-REQ) from a RC4-only requestor (Pattern B) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t27 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t27',$pw)`<br>`Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist } \| Out-Null`<br>`Start-Sleep -Seconds 30` | Requestor listed in `Rc4RequestorAccounts`. Account `Status = 'Failed (RC4-only/No AES)'`. | `Remove-ADUser usr.t27 -Confirm:$false` |
| **T28** | 4768/4769 | TGT (4768) encrypted with RC4 visible in breakdown | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t28 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t28',$pw)`<br>`Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist } \| Out-Null`<br>`Start-Sleep -Seconds 30` — the AS-REQ generates a 4768 with `Ticket Encryption Type = 0x17`. | `TicketBreakdownByType` contains `TGT / RC4-HMAC` with `Events >= 1`. | `Remove-ADUser usr.t28 -Confirm:$false` |
| **T29** | 4768/4769 | TGS (4769) encrypted with RC4 visible in breakdown | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t29 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t29.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t29.lab.local') }`<br>`Start-Sleep -Seconds 30` | `TicketBreakdownByType` contains `TGS / RC4-HMAC` with `Events >= 1`. | `Remove-ADUser svc.t29 -Confirm:$false` |
| **T30** | 4768/4769 | TGS in RC4 to an AES-capable service from an AES-capable client (RC4 forced client-side) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t30 -AccountPassword $pw -Enabled $true -KerberosEncryptionType AES128,AES256 -ServicePrincipalNames 'HTTP/svc.t30.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' /v SupportedEncryptionTypes /t REG_DWORD /d 0x4 /f; gpupdate /force \| Out-Null; klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t30.lab.local') }`<br>`Start-Sleep -Seconds 30` | `AvoidableRc4Tgs >= 1` — service is AES-capable but RC4 was chosen. | `Invoke-Command client01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' /v SupportedEncryptionTypes /f; gpupdate /force \| Out-Null }`<br>`Remove-ADUser svc.t30 -Confirm:$false` |
| **T31** | 4768/4769 | Pattern D — service has AES bits but key material still RC4 | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t31 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t31.lab.local'`<br>`Set-ADAccountPassword svc.t31 -Reset -NewPassword $pw  # generate RC4 key`<br>`Set-ADUser svc.t31 -KerberosEncryptionType AES128,AES256  # add AES bits WITHOUT rotation`<br>`Invoke-Command client01.lab.local -ScriptBlock { klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t31.lab.local') }`<br>`Start-Sleep -Seconds 30` | Inventory shows `Compliant (AES present)` BUT a RC4 4769 for `svc.t31` is visible — documented limitation of attribute-based classification. | `Remove-ADUser svc.t31 -Confirm:$false` |
| **T32** | 4768/4769 | Same service after rotation — RC4 stops | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t32 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t32.lab.local'`<br>`Set-ADAccountPassword svc.t32 -Reset -NewPassword $pw  # generate RC4 key`<br>`Set-ADUser svc.t32 -KerberosEncryptionType AES128,AES256  # add AES bits WITHOUT rotation`<br>`Invoke-Command client01.lab.local -ScriptBlock { klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t32.lab.local') }`<br>`Start-Sleep -Seconds 30  # first audit run should show a RC4 4769`<br>`Set-ADAccountPassword svc.t32 -Reset -NewPassword $pw  # rotate, AES key generated`<br>`Invoke-Command client01.lab.local -ScriptBlock { klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t32.lab.local') }`<br>`Start-Sleep -Seconds 30` | Subsequent 4769 events for `svc.t32` now AES (typically `0x12` = AES256). No new RC4 event. | `Remove-ADUser svc.t32 -Confirm:$false` |
| **T33** | 4768/4769 | `MisconfiguredClientSignal` (client AES, ticket RC4) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t33 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t33.lab.local'`<br>`Set-ADAccountPassword svc.t33 -Reset -NewPassword $pw  # generate RC4 key`<br>`Set-ADUser svc.t33 -KerberosEncryptionType AES128,AES256  # add AES bits WITHOUT rotation`<br>`Invoke-Command client01.lab.local -ScriptBlock { klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t33.lab.local') }`<br>`Start-Sleep -Seconds 30` — the user pre-authenticates in AES but the service ticket is returned in RC4. | `RawEvents` show `MisconfiguredClientSignal = True` (visible in `AllTicketEvents.csv` when `-ExportCsv`). | `Remove-ADUser svc.t33 -Confirm:$false` |
| **T34** | Kdcsvc | Kdcsvc 201 — Pattern B audit, no GPO | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 1 /f; Restart-Service kdc }`<br>`$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t34 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t34',$pw)`<br>`Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist } \| Out-Null`<br>`Start-Sleep -Seconds 30` | `KdcsvcEvents` contains entry `EventId = 201`, `Pattern = B`, `Severity = Audit`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }`<br>`Remove-ADUser usr.t34 -Confirm:$false` |
| **T35** | Kdcsvc | Kdcsvc 206 — audit with explicit insecure default | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x1C /f; reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 1 /f; Restart-Service kdc }`<br>`$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t35 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t35',$pw)`<br>`Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist } \| Out-Null`<br>`Start-Sleep -Seconds 30` | Entry `EventId = 206`, `Pattern = B`, `Severity = Audit`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }`<br>`Remove-ADUser usr.t35 -Confirm:$false` |
| **T36** | Kdcsvc | Kdcsvc 202 — Pattern D audit | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 1 /f; Restart-Service kdc }`<br>`$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t36 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t36.lab.local'`<br>`Set-ADAccountPassword svc.t36 -Reset -NewPassword $pw`<br>`Set-ADUser svc.t36 -KerberosEncryptionType AES128,AES256`<br>`Invoke-Command client01.lab.local -ScriptBlock { klist purge \| Out-Null; Add-Type -AssemblyName System.IdentityModel; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t36.lab.local') }`<br>`Start-Sleep -Seconds 30` | Entry `EventId = 202`, `Pattern = D`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }`<br>`Remove-ADUser svc.t36 -Confirm:$false` |
| **T37** | Kdcsvc | Kdcsvc 205 — DC default insecure at service start | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x1C /f; Restart-Service kdc }` | Entry `EventId = 205` (1 per Kdcsvc start). KPI `Kdcsvc 205 hygiene findings >= 1`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc }` |
| **T38** | Kdcsvc | Kdcsvc 203 — Phase 2 Pattern B enforce — ⚠️ **destructive** | `Invoke-Command dc01.lab.local -ScriptBlock { reg add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /t REG_DWORD /d 2 /f; Restart-Service kdc }`<br>`$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t38 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t38',$pw)`<br>`Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist } \| Out-Null  # this will FAIL — Phase 2 rejects RC4-only auth`<br>`Start-Sleep -Seconds 30` | Entry `EventId = 203`, `Pattern = B`, `Severity = Enforce`. | `Invoke-Command dc01.lab.local -ScriptBlock { reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f; Restart-Service kdc }`<br>`Remove-ADUser usr.t38 -Confirm:$false` |
| **T39** | Backlog | Backlog source 1 — RC4 service with > 5 events | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t39 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t39.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; 1..6 \| ForEach-Object { klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t39.lab.local') } }`<br>`Start-Sleep -Seconds 30` | Backlog row with `Source = Account`, `Type = Service account`, `Score >= 5`. | `Remove-ADUser svc.t39 -Confirm:$false` |
| **T40** | Backlog | Backlog source 2 — non-AES trust | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Replace @{'msDS-SupportedEncryptionTypes'=4}` *(replace DN with an actual lab TDO; any non-AES value — 4, 28, 1 — produces a backlog row)* | Backlog row `Trust: <name>` with `Source = TDO`, `Score = 8` (Critical + Frequent + Medium). | `Set-ADObject -Identity 'CN=partner.lab.local,CN=System,DC=lab,DC=local' -Clear msDS-SupportedEncryptionTypes` |
| **T41** | Backlog | Backlog source 3 — RC4 client with >= 50 events (Pattern B at scale) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t41 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4`<br>`$cred=[pscredential]::new('LAB\usr.t41',$pw)`<br>`1..55 \| ForEach-Object { Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist purge \| Out-Null } \| Out-Null }`<br>`Start-Sleep -Seconds 30` | Backlog row with `Source = Account`, `Type = Client account (Pattern B)`. | `Remove-ADUser usr.t41 -Confirm:$false` |
| **T42** | Backlog | Same account triggers source 1 AND source 3 (dedup) | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser usr.t42 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/usr.t42.lab.local'`<br>`$cred=[pscredential]::new('LAB\usr.t42',$pw)`<br>`1..55 \| ForEach-Object { Invoke-Command client01.lab.local -Credential $cred -ScriptBlock { klist purge \| Out-Null } \| Out-Null }`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; 1..6 \| ForEach-Object { klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/usr.t42.lab.local') } }`<br>`Start-Sleep -Seconds 30` | Single backlog row for `usr.t42` (deduplicated — source 1 wins). | `Remove-ADUser usr.t42 -Confirm:$false` |
| **T43** | Backlog | `-OwnerMappingPath` enriches Backlog with Owner column | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t43 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t43.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; 1..6 \| ForEach-Object { klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t43.lab.local') } }`<br>`Start-Sleep -Seconds 30`<br>Then create the mapping CSV:<br>`@"`<br>`Pattern,Owner`<br>`svc.*,Team-A`<br>`*,TBD`<br>`"@ \| Out-File .\owners.csv -Encoding UTF8`<br>Then run:<br>`.\Invoke-KerberosEncryptionAudit.ps1 -IncludeTrusts -ExportCsv -OwnerMappingPath .\owners.csv -OutputDir .\Outputs\T43` | In `Backlog.csv`, the row for `svc.t43` has `Owner = Team-A`. | `Remove-Item .\owners.csv`<br>`Remove-ADUser svc.t43 -Confirm:$false` |
| **T44** | Robustness | DC list contains an unreachable host | `.\Invoke-KerberosEncryptionAudit.ps1 -DomainControllers dc01.lab.local,nope.invalid.local -OutputDir .\Outputs\T44` | DC line in *KDC Default* with `Status = 'Failed'` for `nope.invalid.local`. `Errors.Count >= 1`. Other DCs still collected. | None. |
| **T45** | Robustness | `-Days 0` rejected | `.\Invoke-KerberosEncryptionAudit.ps1 -Days 0` | Parameter validation error from `[ValidateRange(1, 365)]` (since v1.2.0). | None. |
| **T46** | Robustness | `-MaxEventsPerDc -1` rejected | `.\Invoke-KerberosEncryptionAudit.ps1 -MaxEventsPerDc -1` | Parameter validation error. | None. |
| **T47** | Robustness | `-OwnerMappingPath` points to a non-existent file | `.\Invoke-KerberosEncryptionAudit.ps1 -OwnerMappingPath C:\nope.csv -OutputDir .\Outputs\T47` | `Warnings` contains `"Owner mapping file not found"`. Run completes without owner enrichment. | None. |
| **T48** | Robustness | Audited window contains zero 4768/4769 events | Idle lab + short window: `.\Invoke-KerberosEncryptionAudit.ps1 -Days 1 -OutputDir .\Outputs\T48` | `Warnings` contains `"No 4768/4769 events were collected"`. Sections that depend on events are empty. | None. |
| **T49** | Robustness | RSAT-AD-PowerShell missing on the host | `Remove-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'`<br>`.\Invoke-KerberosEncryptionAudit.ps1` | Fatal error at startup: `Active Directory discovery failed`. | `Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'` |
| **T50** | Robustness | Account name contains LDAP metacharacters | AD natively forbids most LDAP metacharacters in `SamAccountName`. The case is covered by v1.1.9 helpers `ConvertTo-LdapFilterSafe` and `ConvertTo-LdapRfc4515Safe` — exercised on every account resolution. No specific setup. | No crash on resolve. Values containing parentheses, asterisks or backslashes are displayed verbatim. | None. |
| **T51** | Robustness | Domain has zero trusts | Lab with no configured trusts: `.\Invoke-KerberosEncryptionAudit.ps1 -IncludeTrusts -OutputDir .\Outputs\T51` | `Trusts.Count = 0`. No error. Log line `Trusts inventoried = 0`. | None. |
| **T52** | Robustness | Run without `-IncludeTrusts` | `.\Invoke-KerberosEncryptionAudit.ps1 -OutputDir .\Outputs\T52` | `Trusts.Count = 0`. Log line `Skipped (use -IncludeTrusts...)`. *Trusts* HTML section absent. | None. |
| **T53** | Robustness | `-ExportCsv -IncludeTrusts` produces all CSVs | `.\Invoke-KerberosEncryptionAudit.ps1 -ExportCsv -IncludeTrusts -OutputDir .\Outputs\T53` | 10 `*.csv` files created (`KdcsvcEvents`, `KdcsvcSummary`, `PriorityAccounts`, `TicketBreakdownByType`, `TicketBreakdownGlobal`, `Rc4RequestorAccounts`, `Rc4TargetServices`, `Trusts`, `Backlog`, `AllTicketEvents`). | None. |
| **T54** | Robustness | `Backlog.csv` always exported when non-empty | `$pw=ConvertTo-SecureString 'P@ssw0rd!2026' -AsPlainText -Force`<br>`New-ADUser svc.t54 -AccountPassword $pw -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.t54.lab.local'`<br>`Invoke-Command client01.lab.local -ScriptBlock { Add-Type -AssemblyName System.IdentityModel; 1..6 \| ForEach-Object { klist purge \| Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/svc.t54.lab.local') } }`<br>`Start-Sleep -Seconds 30`<br>Then:<br>`.\Invoke-KerberosEncryptionAudit.ps1 -OutputDir .\Outputs\T54` *(no `-ExportCsv`)* | `Backlog.csv` present in `.\Outputs\T54\`. | `Remove-ADUser svc.t54 -Confirm:$false` |
| **T55** | Robustness | `-OpenReport` opens the HTML | `.\Invoke-KerberosEncryptionAudit.ps1 -OpenReport -OutputDir .\Outputs\T55` | Default browser opens on `KerberosEncryptionAudit.html` at the end of the run. | Close the browser tab. |
| **T56** | Concurrency | Throttle at 4 DCs in parallel | Run on a domain with >= 5 DCs: `.\Invoke-KerberosEncryptionAudit.ps1 -OutputDir .\Outputs\T56` | DC collection runs in parallel with throttle 4 (`ForEach-Object -Parallel -ThrottleLimit 4`). Visible in verbose logs. | None. |
| **T57** | Concurrency | One DC becomes unreachable mid-run | Start the audit, then immediately cut network on one DC (block the host firewall): `Invoke-Command dc02.lab.local -ScriptBlock { Set-NetFirewallProfile -All -Enabled True; New-NetFirewallRule -DisplayName 'Block-All' -Direction Inbound -Action Block }` | Failure isolated to that DC in `Errors`. Other DCs collected and reported normally. | `Invoke-Command dc02.lab.local -ScriptBlock { Remove-NetFirewallRule -DisplayName 'Block-All' }` |
| **T58** | JSON format | `KerberosEncryptionAudit.json` parses cleanly | `Get-Content .\Outputs\T01\KerberosEncryptionAudit.json -Raw \| ConvertFrom-Json` | No exception. Object hierarchy navigable. | None. |
| **T59** | HTML format | `KerberosEncryptionAudit.html` renders | `Invoke-Item .\Outputs\T01\KerberosEncryptionAudit.html` | Page renders. Navigation anchors (*Summary, Backlog, KDC Default, Phase, Kdcsvc, Accounts, Trusts, Tickets, RC4 Hotspots, Artifacts*) all resolve. | Close the browser tab. |
| **T60** | Idempotence | Two consecutive runs against an unchanged domain match | `.\Invoke-KerberosEncryptionAudit.ps1 -OutputDir .\Outputs\T60a`<br>`.\Invoke-KerberosEncryptionAudit.ps1 -OutputDir .\Outputs\T60b`<br>`Compare-Object (Get-Content .\Outputs\T60a\KerberosEncryptionAudit.json -Raw \| ConvertFrom-Json).AccountStatusSummary (Get-Content .\Outputs\T60b\KerberosEncryptionAudit.json -Raw \| ConvertFrom-Json).AccountStatusSummary` | No diff on `AccountStatusSummary`, `KdcDefaults`, `Trusts`, `Backlog`. Only `StartedAt` timestamp differs. | `Remove-Item .\Outputs\T60a, .\Outputs\T60b -Recurse` |

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

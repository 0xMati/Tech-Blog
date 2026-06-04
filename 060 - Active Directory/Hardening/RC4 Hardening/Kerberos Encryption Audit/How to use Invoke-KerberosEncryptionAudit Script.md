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

## Validation test plan

The scenarios below let you verify each detection path of the script against a live lab. They are organised by the layer they exercise: account inventory, KDC infrastructure (Default + Phase), trusts, live 4768/4769 events, Kdcsvc 201-209, backlog scoring, robustness, concurrency and output format. Every test that mutates state ships with its own cleanup column (read-only tests show `—`). **Use a non-production lab** — several scenarios touch DC registry values, account `msDS-SupportedEncryptionTypes`, or Trusted Domain Objects, and would impact real authentication if applied to production.

### Common test session prelude

On the host where you run the script (typically a member server or jump box with RSAT and PowerShell 7):

```powershell
$labPwd    = ConvertTo-SecureString 'Temp!Audit2026Long!' -AsPlainText -Force
$dc        = (Get-ADDomain).PDCEmulator
$lab       = (Get-ADDomain).DNSRoot
$scriptDir = 'C:\Temp\KerberosAudit'   # adjust to your local copy
$out       = Join-Path $scriptDir 'Outputs'
function Run-Audit {
    param([string]$Tag, [int]$Days = 1, [string[]]$Dcs)
    $args = @{ Days = $Days; IncludeTrusts = $true; OutputDir = (Join-Path $out $Tag) }
    if ($Dcs) { $args['DomainControllers'] = $Dcs }
    & "$scriptDir\Invoke-KerberosEncryptionAudit.ps1" @args
}
function Show-Json { param($Tag) Get-Content (Join-Path $out "$Tag\KerberosEncryptionAudit.json") -Raw | ConvertFrom-Json }
```

> The password literal above is renamed to `$labPwd` (the built-in PowerShell variable `$pwd` holds your current location — do not shadow it). When the test rows below say `$pwd`, substitute `$labPwd`.

On the **client of test** (any domain-joined workstation, distinct from a DC):

```powershell
Add-Type -AssemblyName System.IdentityModel
function Trigger-Tgs { param($Spn) klist purge | Out-Null; [void](New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $Spn) }
```

> Several rows reference `klist purge` and `runas` on the test client. The client must be reachable from your session and joined to the same domain as the DC under test.

### Test matrix

| ID | Category | Scenario | Actions | Expected detection (JSON / HTML) | Cleanup |
| --- | --- | --- | --- | --- | --- |
| **T01** | Baseline | Nominal run, nothing changed | 1. `Run-Audit baseline-pre`<br>2. `(Show-Json baseline-pre).AccountStatusSummary` | `Errors=0`, `Warnings=0`. Capture baseline for diff. | — |
| **T02** | Inventory | User unset (null) | 1. `New-ADUser usr.unset -SamAccountName usr.unset -AccountPassword $pwd -Enabled $true`<br>2. `Run-Audit T02` | `usr.unset` → `User/Service / Info (Unset/0, non-service inherits KDC default)` | `Remove-ADUser usr.unset -Confirm:$false` |
| **T03** | Inventory | User RC4-only | 1. `New-ADUser usr.rc4 -SamAccountName usr.rc4 -AccountPassword $pwd -Enabled $true -KerberosEncryptionType RC4`<br>2. `Run-Audit T03` | `User/Service / Failed (RC4-only/No AES)` count +1 | `Remove-ADUser usr.rc4 -Confirm:$false` |
| **T04** | Inventory | User DES-only | 1. `New-ADUser usr.des -SamAccountName usr.des -AccountPassword $pwd -Enabled $true`<br>2. `Set-ADUser usr.des -Replace @{'msDS-SupportedEncryptionTypes'=3}`<br>3. `Run-Audit T04` | `Failed (DES-only/No AES) = 1` | `Remove-ADUser usr.des -Confirm:$false` |
| **T05** | Inventory | User AES-only (0x18) | 1. `New-ADUser usr.aes -SamAccountName usr.aes -AccountPassword $pwd -Enabled $true -KerberosEncryptionType AES128,AES256`<br>2. `Run-Audit T05` | `Compliant (AES present)` count +1 | `Remove-ADUser usr.aes -Confirm:$false` |
| **T06** | Inventory | User AES+RC4 with SPN | 1. `New-ADUser usr.mix -SamAccountName usr.mix -AccountPassword $pwd -Enabled $true -KerberosEncryptionType RC4,AES128,AES256 -ServicePrincipalNames 'HTTP/usr.mix.test'`<br>2. `Run-Audit T06` | `Warning (AES present + RC4 allowed)`, present in `PriorityAccounts` | `Remove-ADUser usr.mix -Confirm:$false` |
| **T07** | Inventory | Value with no AES/RC4/DES bit (0x40) | 1. `New-ADUser usr.bogus -SamAccountName usr.bogus -AccountPassword $pwd -Enabled $true`<br>2. `Set-ADUser usr.bogus -Replace @{'msDS-SupportedEncryptionTypes'=64}`<br>3. `Run-Audit T07` | `Failed (No AES) = 1` | `Remove-ADUser usr.bogus -Confirm:$false` |
| **T08** | Inventory | AES256-SK only (0x20) | 1. `New-ADUser usr.sk -SamAccountName usr.sk -AccountPassword $pwd -Enabled $true`<br>2. `Set-ADUser usr.sk -Replace @{'msDS-SupportedEncryptionTypes'=32}`<br>3. `Run-Audit T08` | `Compliant (AES present)`, Flags = `0x20 [AES256-SK]` (post-CVE-2022-37966 hardening bit) | `Remove-ADUser usr.sk -Confirm:$false` |
| **T09** | Inventory | Capability-only (0x50000, krbtgt-style) | 1. `New-ADUser usr.cap -SamAccountName usr.cap -AccountPassword $pwd -Enabled $true`<br>2. `Set-ADUser usr.cap -Replace @{'msDS-SupportedEncryptionTypes'=327680}`<br>3. `Run-Audit T09` | `Info (Unset/0...)` (script masks 0x3F to ignore non-enc-type capability bits), Flags = `0x50000 [FAST-Supported, Claims-Supported]` | `Remove-ADUser usr.cap -Confirm:$false` |
| **T10** | Inventory | SPN account with no enc-type | 1. `New-ADUser usr.spn -SamAccountName usr.spn -AccountPassword $pwd -Enabled $true -ServicePrincipalNames 'HTTP/usr.spn.test'`<br>2. `Run-Audit T10` | `Warning (Unset/0, service relies on KDC default)`, present in `PriorityAccounts` | `Remove-ADUser usr.spn -Confirm:$false` |
| **T11** | Inventory | krbtgt excluded from PriorityAccounts | 1. `Run-Audit T11`<br>2. `(Show-Json T11).PriorityAccounts.Name -contains 'krbtgt'` | Returns `False` (krbtgt explicitly filtered). | — |
| **T12** | Inventory | Computer at 0x1C excluded from PriorityAccounts | 1. `Run-Audit T12`<br>2. `(Show-Json T12).PriorityAccounts \| ? Category -eq 'Computer' \| ? EncHex -eq '0x1C'` | Returns empty (status `Info*` is filtered to keep large fleets readable). | — |
| **T13** | KDC default | Default registry absent | 1. (initial state on most labs)<br>2. `Run-Audit T13` | `Status = 'Warning (AES default, not enforced)'` on every DC. | — |
| **T14** | KDC default | Default = 0x18 (AES-only) | **On one DC:**<br>1. `reg add HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v DefaultDomainSupportedEncTypes /t REG_DWORD /d 0x18 /f`<br>2. `Restart-Service kdc`<br>3. `Run-Audit T14` | `Compliant (AES-only default)` on that DC, KPI `DCs with AES-only KDC default = 1/N`. | `reg delete HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v DefaultDomainSupportedEncTypes /f; Restart-Service kdc` |
| **T15** | KDC default | Default = 0x1C (mixed) | Same as T14 with `/d 0x1C` | `Warning (Mixed or RC4 allowed)`. | Same as T14 |
| **T16** | KDC default | KPI `Compliant` when 100% of DCs at 0x18 | T14 on **every** DC of the domain | KPI `DCs with AES-only KDC default` Status=`OK`. | Reset T14 on every DC. |
| **T17** | Phase | Phase registry absent | (initial state, Phase 0 implicit) `Run-Audit T17` | `Rc4DisablementPhase[*].Status = 'Info (registry absent)'`. | — |
| **T18** | Phase | Phase = 0 (silent) | **On one DC:**<br>1. `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters /v RC4DefaultDisablementPhase /t REG_DWORD /d 0 /f`<br>2. `Restart-Service kdc`<br>3. `Run-Audit T18` | `Warning (silent)`. | `reg delete ... /v RC4DefaultDisablementPhase /f; Restart-Service kdc` |
| **T19** | Phase | Phase = 1 (audit) | Same as T18 with `/d 1` | `Compliant (Phase 1 audit)`. | Same as T18 |
| **T20** | Phase | Phase = 2 (enforce) | ⚠️ **Lab only.** Same as T18 with `/d 2` | `Compliant (Phase 2 enforce)` — RC4-only authentications now fail. | Same as T18 |
| **T21** | Trust | TDO AES-only | (existing AES-only TDO) `Run-Audit T21` | `Trusts \| ? Classification -eq 'AES-only'` non-empty. | — |
| **T22** | Trust | TDO Unset | (existing Unset TDO) | `Trusts \| ? Classification -eq 'Unset'` non-empty. | — |
| **T23** | Trust | TDO RC4-only | ⚠️ Lab only.<br>1. `$tdo = Get-ADTrust -Filter * \| Select -First 1; Set-ADObject $tdo.DistinguishedName -Replace @{'msDS-SupportedEncryptionTypes'=4}`<br>2. `Run-Audit T23` | `Classification = 'RC4-only'`, Backlog row Type=TDO Score=8. | `Set-ADObject $tdo.DistinguishedName -Replace @{'msDS-SupportedEncryptionTypes'=0}` |
| **T24** | Trust | TDO Mixed (0x1C) | Same as T23 with `=28` | `Classification = 'Mixed'`. | Same as T23 |
| **T25** | Trust | TDO Legacy-DES (0x1) | Same as T23 with `=1` | `Classification = 'Legacy-DES'`, Backlog FixCost=High. | Same as T23 |
| **T26** | 4768/4769 | RC4 TGS for RC4-only service | 1. T03 setup<br>2. `Set-ADUser usr.rc4 -ServicePrincipalNames @{Add='HTTP/usr.rc4.test'}`<br>3. `Set-ADAccountPassword usr.rc4 -Reset -NewPassword $pwd`<br>4. **On client:** `Trigger-Tgs 'HTTP/usr.rc4.test'`<br>5. wait 30s, `Run-Audit T26` | `TotalRc4Events ≥ 1`, `Rc4TargetServices` contains `HTTP/usr.rc4.test`, `AvoidableRc4Tgs = 0`. | T03 cleanup |
| **T27** | 4768/4769 | RC4 AS-REQ from RC4-only client (Pattern B) | 1. T03 setup<br>2. **On client:** `runas /user:$lab\usr.rc4 cmd`<br>3. in the new shell: `klist purge`, `klist get krbtgt`, `net use \\$dc\sysvol`<br>4. `Run-Audit T27` | `Rc4RequestorAccounts` contains `usr.rc4`, ≥ 2 events (1 TGT + 1 TGS), Status=`Failed (RC4-only/No AES)`. | T03 cleanup |
| **T28** | 4768/4769 | TGT 4768 RC4 visible in breakdown | T27 (the `klist get krbtgt` step) | `TicketBreakdownByType` line `TGT / RC4-HMAC` Events ≥ 1. | T27 cleanup |
| **T29** | 4768/4769 | TGS 4769 RC4 visible in breakdown | T26 or T27 (`net use`) | `TicketBreakdownByType` line `TGS / RC4-HMAC` Events ≥ 1. | — |
| **T30** | 4768/4769 | Avoidable RC4 (client AES, service AES, DC AES, RC4 forced client-side) | 1. T05 setup + `Set-ADUser usr.aes -ServicePrincipalNames @{Add='HTTP/usr.aes.test'}` + `Set-ADAccountPassword usr.aes -Reset -NewPassword $pwd`<br>2. **On client:** `reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters /v SupportedEncryptionTypes /t REG_DWORD /d 0x4 /f; gpupdate /force; klist purge`<br>3. `Trigger-Tgs 'HTTP/usr.aes.test'`<br>4. `Run-Audit T30` | `AvoidableRc4Tgs ≥ 1` (service is AES-capable but RC4 was chosen). | Client: `reg delete HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters /v SupportedEncryptionTypes /f; gpupdate /force` + T05 cleanup |
| **T31** | 4768/4769 | Stale-key trap (Pattern D) | 1. `New-ADUser svc.stale -SamAccountName svc.stale -AccountPassword $pwd -Enabled $true -KerberosEncryptionType RC4 -ServicePrincipalNames 'HTTP/svc.stale.test'`<br>2. `Set-ADAccountPassword svc.stale -Reset -NewPassword $pwd`<br>3. `Set-ADUser svc.stale -KerberosEncryptionType AES128,AES256` (no password reset)<br>4. **On client:** `Trigger-Tgs 'HTTP/svc.stale.test'`<br>5. `Run-Audit T31` | Inventory shows `Compliant (AES present)` but 4769 still RC4 → 1 RC4 TGS visible. Demonstrates the documented limitation of attribute-based classification. | `Remove-ADUser svc.stale -Confirm:$false` |
| **T32** | 4768/4769 | Fix stale-key (rotate password) | After T31:<br>1. `Set-ADAccountPassword svc.stale -Reset -NewPassword $pwd`<br>2. **On client:** `Trigger-Tgs 'HTTP/svc.stale.test'`<br>3. `Run-Audit T32` | 4769 now AES256 (0x12), no new RC4 event. | T31 cleanup |
| **T33** | 4768/4769 | MisconfiguredClientSignal | T31 reproduces it naturally (user pre-auth in AES, service ticket forced to RC4) | `RawEvents` (visible in `AllTicketEvents.csv`) shows `MisconfiguredClientSignal=True`. | — |
| **T34** | Kdcsvc | Pattern B audit, no GPO | T19 + T27. `Run-Audit T34` | `KdcsvcEvents` contains EventId=201, Pattern=B, Severity=Audit. | Reset T19 + T27 cleanup |
| **T35** | Kdcsvc | Pattern B audit with insecure default | T15 + T19 + T27 | EventId=206 (audit with explicit default). | Reset T15+T19 + T27 cleanup |
| **T36** | Kdcsvc | Pattern D audit | T19 + T31 | EventId=202, Pattern=D. | Reset T19 + T31 cleanup |
| **T37** | Kdcsvc | Hygiene 205 (DC default insecure) | T15 + `Restart-Service kdc` + `Run-Audit T37` | EventId=205 (1 per Kdcsvc start), KPI `Kdcsvc 205 hygiene findings ≥ 1`. | Reset T15 |
| **T38** | Kdcsvc | Phase 2 Pattern B enforce (⚠️ destructive) | T20 + T27. `usr.rc4` authentication fails. | EventId=203, Pattern=B, Severity=Enforce. | Reset T20 + T27 cleanup |
| **T39** | Backlog | Source 1 (RC4 service) | T26 repeated 5× (loop for >5 events) | `Backlog` contains `usr.rc4` Type=`Service account` Score ≥ 5. | T26 cleanup |
| **T40** | Backlog | Source 2 (non-AES trust) | T23 or T24 or T25 | `Backlog` contains line `Trust: <name>` Type=TDO Score=8 (Critical+Frequent+Medium). | T23 cleanup |
| **T41** | Backlog | Source 3 (RC4 client ≥ 50 events) | 1. T03 setup<br>2. **On client:** `runas /user:$lab\usr.rc4 cmd` then in the shell: `1..60 \| % { net use \\$dc\sysvol /persistent:no \| Out-Null; net use \\$dc\sysvol /delete \| Out-Null }`<br>3. `Run-Audit T41` | `Backlog` contains `usr.rc4` Type=`Client account (Pattern B)`. | T03 cleanup |
| **T42** | Backlog | Dedup (account in source 1 AND 3) | T26 (≥1) + T41 (≥50) on the same account | One single backlog line (source 1 wins). | Cleanup |
| **T43** | Backlog | Owner mapping CSV | 1. `"Pattern,Owner`n`usr.*,Team-A`n`*$,Team-Infra`n`*,TBD" \| Out-File owners.csv`<br>2. T39 setup<br>3. `& script.ps1 -Days 1 -IncludeTrusts -OwnerMappingPath owners.csv -OutputDir .\Outputs\T43` | `Backlog \| ? Dependency -eq 'usr.rc4' \| Select Owner` = `Team-A`. | `Remove-Item owners.csv` + T39 cleanup |
| **T44** | Robustness | Unreachable DC | `& script.ps1 -Days 1 -DomainControllers $dc,'nope.invalid.local' -OutputDir .\Outputs\T44` | `KdcDefaults` contains line `Computer=nope.invalid.local` Status=`Failed`, `Errors` ≥ 1 entry. | — |
| **T45** | Robustness | `-Days 0` rejection | `& script.ps1 -Days 0` | Parameter validation error (`[ValidateRange(1,365)]` since v1.2.0). | — |
| **T46** | Robustness | `-MaxEventsPerDc -1` rejection | `& script.ps1 -MaxEventsPerDc -1` | Parameter validation error. | — |
| **T47** | Robustness | Missing OwnerMappingPath | `& script.ps1 -OwnerMappingPath C:\nope.csv -OutputDir .\Outputs\T47` | `Warnings` contains `"Owner mapping file not found"`. | — |
| **T48** | Robustness | No 4768/4769 events in window | Short window on idle lab | `Warnings` contains `"No 4768/4769 events were collected"`. | — |
| **T49** | Robustness | RSAT-AD-PowerShell missing (lab) | `Remove-WindowsFeature RSAT-AD-PowerShell` then `Run-Audit T49` | Fatal error at startup: `Active Directory discovery failed`. | `Add-WindowsFeature RSAT-AD-PowerShell` |
| **T50** | Robustness | LDAP injection (apostrophe in SamAccountName) | AD normally forbids apostrophes in `SamAccountName`. The case is covered by v1.1.9 helpers `ConvertTo-LdapFilterSafe` and `ConvertTo-LdapRfc4515Safe`. | No crash on resolve, value displayed verbatim. | — |
| **T51** | Robustness | Trust audit with no trusts | Domain with 0 trusts: `& script.ps1 -IncludeTrusts -OutputDir .\Outputs\T51` | `Trusts.Count = 0`, no error, log line `Trusts inventoried = 0`. | — |
| **T52** | Robustness | Run without `-IncludeTrusts` | `& script.ps1 -OutputDir .\Outputs\T52` | `Trusts.Count = 0`, log line `Skipped (use -IncludeTrusts...)`. | — |
| **T53** | Robustness | CSV export | `& script.ps1 -ExportCsv -IncludeTrusts -OutputDir .\Outputs\T53` | 12 `*.csv` files created in OutputDir. | — |
| **T54** | Robustness | Backlog CSV always exported | `& script.ps1 -OutputDir .\Outputs\T54` (without `-ExportCsv`) | `Backlog.csv` present when `Backlog.Count > 0`. | — |
| **T55** | Robustness | OpenReport | `& script.ps1 -OpenReport -OutputDir .\Outputs\T55` | Browser opens on `KerberosEncryptionAudit.html`. | Close the browser tab. |
| **T56** | Concurrency | Parallel limit at 4 DCs | Lab with ≥ 5 DCs | Throttle at 4 visible in logs (`-ThrottleLimit 4`). | — |
| **T57** | Concurrency | Resilience if 1 DC parallel run fails | Cut network on 1 DC during the run | Isolated error in `Errors`, other DCs collect OK. | Restore network. |
| **T58** | JSON format | Valid JSON | `Get-Content .\Outputs\T01\KerberosEncryptionAudit.json -Raw \| ConvertFrom-Json` | No exception. | — |
| **T59** | HTML format | Valid HTML | `Test-Path .\Outputs\T01\KerberosEncryptionAudit.html` then open | Page renders, sections navigable. | — |
| **T60** | Idempotence | Two consecutive runs identical | `Run-Audit idem1; Run-Audit idem2; Compare-Object (Show-Json idem1).AccountStatusSummary (Show-Json idem2).AccountStatusSummary` | No diff (except `StartedAt` and `Days`). | — |

### Recommended subset for client validation

If time is short, here is the minimum surface to sign off production quality:

| Priority | Tests |
| --- | --- |
| **P0 — must run** | T01, T03, T05, T08, T09, T11, T12, T26, T58, T59, T60 |
| **P1 — strongly recommended** | T13, T14, T17, T19, T21, T27, T44, T47, T48, T52 |
| **P2 — nice to have** | T15, T22, T23, T30, T31, T34, T36, T39, T40, T43, T53 |
| **P3 — lab only / destructive** | T20, T24, T25, T35, T37, T38, T41, T49, T57 |

### Global cleanup at the end of the campaign

```powershell
# Test accounts
Get-ADUser -Filter "SamAccountName -like 'usr.*' -or SamAccountName -like 'svc.audittest' -or SamAccountName -like 'svc.stale*'" |
  Remove-ADUser -Confirm:$false

# DC registry rollbacks (run on every DC you modified)
Invoke-Command -ComputerName (Get-ADDomainController -Filter *).HostName -ScriptBlock {
    reg delete 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc' /v DefaultDomainSupportedEncTypes /f 2>$null
    reg delete 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' /v RC4DefaultDisablementPhase /f 2>$null
    Restart-Service kdc
}

# Test client rollback
Invoke-Command -ComputerName <client1>,<client2> -ScriptBlock {
    reg delete 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' /v SupportedEncryptionTypes /f 2>$null
    gpupdate /force
    klist purge
}

# TDOs (T23-T25): roll back any modified msDS-SupportedEncryptionTypes manually.
```

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

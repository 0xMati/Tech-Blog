---
title: "How to check firewall state on DCs with PowerShell"
date: 2026-06-04
---

# How to check firewall state on DCs with PowerShell

The Windows Firewall state on a Domain Controller is harder to assess than it looks. The same DC can show **"Enabled"** in `wf.msc`, **"Off"** in the legacy registry, **"managed by your administrator"** in `firewall.cpl`, and a different rule set than its peers — all at the same time, all without breaking AD. The usual culprits are:

- A hardening **GPO** that forces the firewall on while the local config still says off (the most common false alarm).
- A **legacy GPO or script** that writes directly under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` instead of going through WFAS — modern WFAS ignores it, but old audit tooling still reads it.
- A **required inbound rule group** (AD DS, KDC, SMB, DFSR…) silently disabled by a misfired baseline.
- A **NIC stuck in Public/Private** because NLA failed at boot — the wrong rule set is applied.

This page comes with two PowerShell companion scripts that target every DC of the domain in parallel via WinRM, and that together answer the two questions that come up after every firewall change:

| Question | Script |
|---|---|
| *"Is my DC firewall sane right now?"* | [Audit-DCFirewall.ps1](Audit-DCFirewall.ps1) — cross-checks WFAS Effective vs Local, the legacy registry, the WSC view, the firewall services, and the required rule groups. Verdict per DC: `OK` or `DIVERGENCE` with detailed notes. |
| *"What changed after my last GPO push?"* | [Export-DCFirewallRules.ps1](Export-DCFirewallRules.ps1) — dumps the full effective rule set + profile settings of every DC to CSV/JSON, and produces a per-DC CSV diff between two snapshot folders. |

Both scripts are read-only.

## Prerequisites

- Run from a workstation or a DC with the **ActiveDirectory** PowerShell module installed (RSAT).
- The account running the script needs **WinRM remote PowerShell** access on every DC (typically a Tier 0 admin).
- WinRM (`Enable-PSRemoting`) must be enabled on each DC. On a properly-managed forest it is, by default.

---

# Part 1 — `Audit-DCFirewall.ps1` (diagnostic)

## What `Audit-DCFirewall.ps1` checks

For each DC, on each of the three firewall profiles (**Domain / Private / Public**):

| Source | What it tells you |
|---|---|
| **WFAS Effective** (`Get-NetFirewallProfile -PolicyStore ActiveStore`) | The *authoritative* state — what actually filters traffic (local config + GPO + MDM merged) |
| **WFAS Local** (`Get-NetFirewallProfile -PolicyStore PersistentStore`) | The DC's local config only — what `wf.msc` shows when not viewing GPO data. If it differs from Effective, a GPO or MDM is overriding the local config |
| **DefaultInboundAction / DefaultOutboundAction** | `Enabled=True` is meaningless if inbound default is `Allow` — the firewall is on but does not filter |
| **Legacy registry** (`SharedAccess\...\FirewallPolicy\<Profile>\EnableFirewall`) | What old GPOs / scripts wrote directly, bypassing WFAS |
| **WSC** (`root\SecurityCenter2`) | What `firewall.cpl` sees on workstations (normally absent on Server SKUs) |
| **Services** `MpsSvc`, `BFE`, `wscsvc` | If `MpsSvc` or `BFE` is not running, the firewall is not filtering at all |
| **Active network profile** per NIC | A NIC stuck in Public/Private on a DC = wrong rule set applied |
| **Required rule groups on the Domain profile** | The built-in firewall rule groups needed for the DC role must exist **and** have at least one enabled inbound rule on the Domain profile |

### Required firewall rule groups checked on the Domain profile

For each DC, the script verifies that each of the following built-in groups (queried via `Get-NetFirewallRule -DisplayGroup`) has at least one **inbound** rule with `Enabled=True` whose profile includes `Domain` (or `Any`):

| `DisplayGroup` | Why a DC needs it |
|---|---|
| `Active Directory Domain Services` | LDAP 389/636, GC 3268/3269, RPC endpoint mapper, RPC dynamic, Netlogon RPC |
| `Kerberos Key Distribution Center` | Kerberos 88 (TCP/UDP) |
| `DNS Service` | DNS 53 TCP/UDP (most DCs are also DNS servers) |
| `File and Printer Sharing` | SMB 445 — SYSVOL / NETLOGON shares |
| `DFS Replication` | SYSVOL replication (DFSR) |
| `Windows Management Instrumentation (WMI)` | Remote audits / monitoring |
| `Core Networking` | ICMPv6, DHCPv6, base networking |

> 💡 **Why no `Netlogon Service` and no `Remote Event Log Management`?**
> Both groups are **disabled by default** on Windows Server, and neither is actually required for the DC role:
> - The `Netlogon Service` group only holds a Named-Pipe rule (`Netlogon Service (NP-In)`). The real Netlogon RPC traffic (secure channel, replication) rides on the RPC endpoint mapper + dynamic RPC rules of the `Active Directory Domain Services` group. The `Netlogon Service` group is therefore redundant and is intentionally left out.
> - `Remote Event Log Management` is purely optional — only useful if you actively read remote Event Logs (e.g. central log collection without WEF).
>
> If your baseline requires either of them, add them via `-RequiredRuleGroups` (see [Audit usage](#audit-usage)).

The list is overridable via the `-RequiredRuleGroups` parameter (see [Audit usage](#audit-usage)). A group classifies as:

- **`MISSING`** — no rule at all is registered for the group on the host (typical of a DC where the AD-DS rule set was never installed, or where someone deleted the rules).
- **`DISABLED`** — rules exist but none is `Enabled=True` and inbound on the Domain profile (often the result of a hardening GPO that disabled them by mistake).
- **`OK`** — at least one matching rule is active.

The script then issues a verdict per DC:

- **`OK`** — no issue detected
- **`DIVERGENCE`** — at least one of: service not running, WFAS ≠ registry, **WFAS Effective ≠ WFAS Local** (GPO/MDM override), profile disabled, `Enabled=True` but `DefaultInboundAction=Allow`, WSC reports non-Defender or multiple firewall products, **a required rule group is missing or disabled on the Domain profile**

> ℹ️ **A `DIVERGENCE` is not necessarily a problem.** A GPO that *forces the firewall ON* on every DC will trigger `Effective != Local` divergence on every DC where the local baseline was different — that is **good practice**, not an outage. Always read the `Notes` and the `Hint` before acting. See [A real-world example](#a-real-world-example--gpo-override-on-every-dc) below.

The full column legend is printed at the end of the console output and also dumped to a `*_legend.txt` companion file when you export to CSV.

## Audit usage

### Audit all DCs of the current domain

```powershell
.\Audit-DCFirewall.ps1
```

### Audit a specific list of DCs

```powershell
.\Audit-DCFirewall.ps1 -ComputerName DC01.contoso.com, DC02.contoso.com
```

### With alternate credentials

```powershell
$cred = Get-Credential CONTOSO\t0-jdoe
.\Audit-DCFirewall.ps1 -Credential $cred
```

### Override the list of required rule groups

For example, to also require RDP (typical when admins reach DCs over RDP from a Tier 0 PAW), or to enforce `Remote Event Log Management` if your baseline mandates it:

```powershell
.\Audit-DCFirewall.ps1 -RequiredRuleGroups @(
    'Active Directory Domain Services',
    'Kerberos Key Distribution Center',
    'DNS Service',
    'File and Printer Sharing',
    'DFS Replication',
    'Windows Management Instrumentation (WMI)',
    'Core Networking',
    'Remote Desktop',
    'Remote Event Log Management'
)
```

Note: the parameter takes the **localized `DisplayGroup`** as shown in `wf.msc` on the target DC. On a non-English Windows, supply the localized strings.

### Show the individual rules tested per group

The `-ShowRules` switch adds, under each group in the *Rule Groups Detail* block, the list of enabled inbound rules that were found:

```powershell
.\Audit-DCFirewall.ps1 -ShowRules
```

### Show the symbol legend and full column reference

By default the console output is kept compact. Add `-ShowLegend` to print the symbol legend above the summary table and the full column reference at the bottom:

```powershell
.\Audit-DCFirewall.ps1 -ShowLegend
```

The CSV companion file (`*_legend.txt`) is always produced when `-ExportCsv` is used, regardless of `-ShowLegend`.

### Export the result to CSV (with the legend file alongside)

```powershell
.\Audit-DCFirewall.ps1 -ExportCsv C:\Temp\DCFirewallAudit.csv
# Produces:
#   C:\Temp\DCFirewallAudit.csv          <- the data
#   C:\Temp\DCFirewallAudit_legend.txt   <- the column legend
```

### Capture the full console output to a transcript

The `-Transcript` switch starts `Start-Transcript` at the beginning and stops it at the end. The log file is written to the **current working directory** with a timestamped name:

```powershell
.\Audit-DCFirewall.ps1 -Transcript
# Produces:
#   .\Audit-DCFirewall_<HOSTNAME>_<yyyyMMdd-HHmmss>.log
```

Combine with `-ShowLegend -ExportCsv` for a fully archivable run:

```powershell
.\Audit-DCFirewall.ps1 -Transcript -ShowLegend -ExportCsv .\dc-fw.csv
```

> 💡 If the system already has a transcript active (via the GPO *Turn on PowerShell Transcription*), `Start-Transcript` may fail silently — the script catches that and prints a warning, but does not abort the audit.

## Reading the audit output

The console output is in four blocks:

1. **Summary table** — one **compact symbolic** line per DC. Each `(D/P/Pu)` triplet holds the values for the Domain / Private / Public profile, in that order. Symbols used:
   - `Firewall` : `✓` enabled, `✗` disabled
   - `Inbound` / `Outbound` default action : `B` Block, `A` Allow, `―` NotConfigured
   - `Registry` (legacy `EnableFirewall`) : `1` enabled, `0` disabled, `―` NotSet
   - `MpsSvc` : `✓` Running, `✗` not running
   - `Rules` / `Status` : `OK`, `DISABLED`, `MISSING`, `DIVERGENCE`, ...

2. **Rule groups detail** — for **every DC** (not only divergent ones), one line per required group with its individual verdict (`OK` green, `DISABLED` yellow, `MISSING` red). With `-ShowRules`, each `OK` group also lists the matching enabled inbound rules.

3. **Divergence details** — for each DC flagged `DIVERGENCE`, the `Notes` field details the issues and the relevant raw values.

4. **Totals** — `X OK / Y DIVERGENCE`, followed by the column legend in dark gray.

### Example output

```text
=== FIREWALL AUDIT - SUMMARY TABLE ===
  Each (D/P/Pu) triplet is the value for the Domain / Private / Public profile
  Firewall : ✓=enabled ✗=disabled
  Inbound / Outbound default action : B=Block A=Allow ―=NotConfigured
  Registry EnableFirewall : 1=enabled 0=disabled ―=NotSet

ComputerName ActiveProfile                  Firewall(D/P/Pu) Inbound(D/P/Pu) Outbound(D/P/Pu) Registry(D/P/Pu) MpsSvc Rules    Status
------------ -----------------------------  ---------------- --------------- ---------------- ---------------- ------ -------- ----------
MM-DC1       Ethernet=DomainAuthenticated   ✗ / ✗ / ✗        ― / ― / ―       ― / ― / ―        0 / 0 / 0        ✓      DISABLED DIVERGENCE
MM-DC3       Ethernet 3=DomainAuthenticated ✓ / ✓ / ✓        B / B / B       A / A / A        1 / 1 / 1        ✓      OK       OK
MM-DC2       Ethernet 6=Private             ✗ / ✓ / ✓        B / B / B       A / A / A        0 / 1 / 1        ✓      OK       DIVERGENCE

=== RULE GROUPS DETAIL ===

[MM-DC1]
  ✗ Active Directory Domain Services         OK
  ✗ Kerberos Key Distribution Center         OK
  ✗ DNS Service                              OK
  ✗ File and Printer Sharing                 DISABLED
  ✓ DFS Replication                          OK
  ✓ Windows Management Instrumentation (WMI) OK
  ✓ Core Networking                          OK

[MM-DC3]
  ✓ Active Directory Domain Services         OK
  ✓ Kerberos Key Distribution Center         OK
  ...
```

A typical "all good" DC shows:

- `ActiveProfile` → `DomainAuthenticated` on every NIC
- `Firewall(D/P/Pu)` → `✓ / ✓ / ✓`
- `Inbound(D/P/Pu)` → `B / B / B` — `Outbound(D/P/Pu)` → `A / A / A`
- `Registry(D/P/Pu)` → `1 / 1 / 1` or `― / ― / ―`
- `MpsSvc` → `✓`
- `Rules` → `OK`
- `Status` → `OK`

A typical drift case looks like:

```
WFAS_Public = True   but Reg_Public = 0
=> DIVERGENCE: Public: WFAS=True but Registry=0
```

That tells you a legacy mechanism wrote `EnableFirewall=0` directly in the registry, but WFAS overrode it — meaning the firewall *is* on, but `firewall.cpl` and any tool that reads the registry value will be misleading. Time to find and remove that legacy GPO/script.

Another common drift, this time on the rule set:

```
Rules_Status   = DISABLED
Rules_Disabled = Windows Management Instrumentation (WMI) | DFS Replication
=> DIVERGENCE: Required rule groups DISABLED on Domain: Windows Management
   Instrumentation (WMI), DFS Replication
```

The rules exist but a hardening GPO has flipped them off on the Domain profile, breaking remote monitoring (WMI) and SYSVOL replication (DFSR) inbound on this DC.

## A real-world example — GPO override on every DC

Below is a real run on two DCs of the same domain. Both report `DIVERGENCE`, **but neither is broken** — the firewall is actually fully on and filtering. This is the most common false-alarm pattern.

```text
=== FIREWALL AUDIT - SUMMARY TABLE ===

ComputerName  ActiveProfile                 Firewall(D/P/Pu) Inbound(D/P/Pu) Outbound(D/P/Pu) Registry(D/P/Pu) MpsSvc Rules Status
------------  -------------                 ---------------- --------------- ---------------- ---------------- ------ ----- ----------
DC1           Ethernet0=DomainAuthenticated ✓ / ✓ / ✓        B / A / B       A / A / A        0 / 0 / 0        ✓      OK    DIVERGENCE
DC2           Ethernet0=DomainAuthenticated ✓ / ✓ / ✓        B / A / B       A / A / A        1 / 0 / 0        ✓      OK    DIVERGENCE

=== DIVERGENCE DETAILS ===

[DC1] -> DIVERGENCE
  ActiveProfile       : Ethernet0=DomainAuthenticated
  Notes               : Domain: WFAS=True but Registry=0 ; Private: WFAS=True but Registry=0 ;
                        Private: Enabled=True but DefaultInboundAction=Allow (no filtering) ;
                        Public: WFAS=True but Registry=0 ;
                        Domain: Effective=True but Local=False (overridden by GPO/MDM) ;
                        Private: Effective=True but Local=False (overridden by GPO/MDM) ;
                        Public: Effective=True but Local=False (overridden by GPO/MDM)
  Firewall Effective  : ✓ / ✓ / ✓  (ActiveStore - what actually applies)
  Firewall Local      : ✗ / ✗ / ✗  (PersistentStore - what wf.msc shows)
  Hint                : Local config differs from effective state -> a GPO or MDM policy
                        is overriding this DC's firewall settings.
```

**How to read this:**

| Finding | Severity | Why |
|---|---|---|
| `Firewall Effective = ✓ / ✓ / ✓` | ✅ Good | The firewall **is** running on all three profiles at runtime. |
| `Firewall Local = ✗ / ✗ / ✗` | ✅ Good | The local config has it off, but a **GPO is forcing it on**. That is exactly what a hardening GPO is supposed to do. |
| `Reg = 0 / 0 / 0` | ⚠️ Cosmetic | The legacy registry value is stale. Anything reading the registry directly (old audit scripts, `firewall.cpl`) will lie. Not an outage, but worth cleaning. |
| `Private: Inbound=Allow` | ⚠️ Cosmetic on a DC with all NICs `DomainAuthenticated` | The Private profile's inbound default is left at `Allow` (Windows default). Because no NIC is on Private, no traffic is matched against this profile. Microsoft Security Baseline still recommends `Block`. |
| `ActiveProfile = DomainAuthenticated` on every NIC | ✅ Good | Only the Domain profile rules apply at runtime. |
| All required `Rule Groups = OK` | ✅ Good | Every group needed for the DC role has at least one enabled inbound rule on Domain. |

**Verdict:** these DCs are healthy. The action items are:

1. **Identify the GPO** that enforces the firewall: `gpresult /h gpresult.html /scope:computer` on the DC, or `Get-GPResultantSetOfPolicy`.
2. **Decide whether to align the local baseline** with the GPO (so `wf.msc` stops being misleading) by deploying `netsh advfirewall set <profile>state on` once locally — or just leave the GPO doing its job and accept the cosmetic divergence.
3. **Fix the Private inbound default**: extend the GPO to set `DefaultInboundAction = Block` on Private and Public too (Microsoft Security Baseline recommendation).
4. **Clean up the legacy registry value** if any old audit tooling consumes it directly.

> 💡 The script's contextual `Hint` line tells you when a divergence is *runtime-fine* (Domain profile ON + all NICs `DomainAuthenticated` + only Private/Public off in WFAS) vs *critical* (Domain profile OFF). Read it before reaching for the panic button.

---

# Part 2 — Cross-checking with the built-in firewall consoles

Once the script flags a divergence, admins typically open one of the two built-in firewall consoles to confirm. **Both consoles can show different things** — and neither is wrong, they just answer different questions. Here is how to read them next to the script's output.

### `firewall.cpl` — the Control Panel view

Opened via *Control Panel → Windows Defender Firewall* (or `firewall.cpl`). This is a **user-facing summary**:

- Shows the **`ActiveStore`** state (i.e. effective: local + GPO + MDM merged).
- Lists which profiles are **`Connected`** (i.e. matched by at least one NIC) — the others are folded.
- Surfaces a yellow banner *"For your security, some settings are managed by your system administrator"* when a GPO is involved.

What you can conclude from it:

| What you see | What it means |
|---|---|
| 🟢 *Domain networks — Connected, On, Block all incoming...* | The Domain profile is the one filtering traffic right now, and it is configured per the security baseline. |
| 🔴 *Private networks — Not connected* (or 🟢/🟡 same wording) | Private profile exists in config but no NIC matches it. Whatever it says about Inbound/Outbound is **inert** until a NIC drops to Private. |
| 🟢 *Guest or public networks — Not connected* | Same logic for Public. |
| 🟡 *"some settings are managed by your system administrator"* | A GPO (or MDM) is overriding part of the local config. **Same signal as the script's `Effective ≠ Local` divergence**. |

`firewall.cpl` does **not** show the per-rule view, the GPO branch, or the inbound/outbound default actions in detail. For that, use `wf.msc`.

### `wf.msc` — the Advanced Security console

Opened via *Run → wf.msc* (or `Get-NetFirewallProfile` in PowerShell). Same data source as `firewall.cpl` but **much more granular**:

- Marks the active profile as `<Profile> Profile is Active` in the *Overview* pane.
- Shows the **three default actions** (firewall on/off, inbound default, outbound default) per profile, even for profiles that are not currently connected.
- Surfaces the same yellow banner *"For your security, some settings are controlled by Group Policy"* when a GPO is involved.
- Lets you switch to the *Group Policy Objects* view (right-click the root node → *View → Group Policy Objects*) to see **what the GPO actually pushes** — i.e. the `RSOP` store. That is the cleanest way to confirm a GPO override identified by the script.

What you can conclude from it that `firewall.cpl` does not surface:

| What you see in `wf.msc` Overview | What it tells you |
|---|---|
| `Domain Profile is Active` (top of the list) | Confirms what `ActiveProfile` reports in the script. The non-active profiles' inbound/outbound defaults are inert until a NIC matches them. |
| Per-profile `Inbound connections that do not match a rule are ...` | The script's `InAction_*` column. **Should be `blocked` on all three profiles** per Microsoft Security Baseline. `allowed` on a non-active profile is harmless today but a time-bomb if a NIC ever drops to that profile. |
| Per-profile `Outbound connections that do not match a rule are ...` | The script's `OutAction_*` column. **Should be `allowed`** on all three (a DC must reach replication partners, KDCs, time servers, etc.). |
| Yellow GPO banner | Same as above — confirms the `Effective ≠ Local` divergence. |

### Why `firewall.cpl`, `wf.msc` and `Get-NetFirewallProfile` can each show different things

It boils down to **which store** each tool reads, and **how it merges** the various sources:

| Tool / view | Store read | What "Enabled" really means there |
|---|---|---|
| `firewall.cpl` (Control Panel) | `ActiveStore` | Effective state = local + GPO + MDM merged. What actually filters traffic. |
| `wf.msc` root node | `ActiveStore` | Same as above. |
| `wf.msc` → *Group Policy Objects* view | `RSOP` | What the GPO/MDM pushes. Empty if no policy applies. |
| `Get-NetFirewallProfile` (default) | `ActiveStore` | Same as `firewall.cpl` / `wf.msc` root. |
| `Get-NetFirewallProfile -PolicyStore PersistentStore` | `PersistentStore` | **Local config only** — what `wf.msc` would show if no GPO existed. The script reports this as `WFAS_Local_*`. |
| Legacy registry (`HKLM\...\FirewallPolicy\<Profile>\EnableFirewall`) | Old per-profile DWORDs | What pre-Vista tooling and a few old GPOs still read. **Ignored at runtime by modern WFAS** but can mislead audits. The script reports this as `Reg_*`. |

The frequent confusions:

- **"`wf.msc` says Enabled but `firewall.cpl` says Off (or vice versa)"** — almost always a **stale `firewall.cpl`** instance. Both read the `ActiveStore`. Close and reopen `firewall.cpl` after a `gpupdate /force`.
- **"`wf.msc` shows the right thing, the registry says `0`, the script says `DIVERGENCE`"** — legacy GPO/script wrote to the registry, modern WFAS ignores it. Cosmetic finding, but real audit tooling that reads the registry will lie. **Clean up the offending GPO/script.**
- **"The script says `Effective=True / Local=False`"** — a GPO is forcing the firewall on while the local config has it off. The yellow banner in both consoles confirms it. **Healthy if your hardening baseline is doing its job**, just align the local config (or accept the cosmetic divergence).

> 💡 The simplest mental model:
> - `Effective` = what filters traffic right now (`firewall.cpl`, `wf.msc` root, `Get-NetFirewallProfile`).
> - `Local` = what an admin set on this DC (`PersistentStore`).
> - `RSOP` = what the GPO/MDM pushes (`wf.msc → Group Policy Objects view`).
> - `Effective = Local ∪ RSOP ∪ <other stores>` — and any of those can disagree, which is normal as long as you understand which one drives traffic.

---

# Part 3 — `Export-DCFirewallRules.ps1` (snapshot / diff)

`Audit-DCFirewall.ps1` answers *"is the firewall sane?"*. When you also need to answer *"what changed after my last GPO push?"*, use the companion script [Export-DCFirewallRules.ps1](Export-DCFirewallRules.ps1).

The script has **two mutually-exclusive modes** (PowerShell parameter sets — you cannot mix them):

| Mode | Mandatory params | What it does |
|---|---|---|
| **Snapshot** (default) | `-OutputFolder` | Queries every DC in parallel via WinRM, dumps the **effective** rule set (`ActiveStore`) and profile settings as CSV + JSON. |
| **Compare** | `-Compare <before>,<after>` and `-OutputCompareFolder` | No DC is queried. Reads the CSV exports of two existing snapshot folders and produces a per-DC diff CSV. |

In Snapshot mode, files are written **directly** in `-OutputFolder` (no sub-folder is created — name the folder however you want, typically by date or change ID). They are sorted by rule `Name` so successive snapshots stay stable and `git diff`-friendly.

For each DC, Snapshot mode produces:

- `<DC>_rules.csv` and `<DC>_rules.json` — every rule with its key, display name, group, direction, action, profile, ports, addresses, program, service, and `PolicyStoreSourceType` (Local / GroupPolicy / …)
- `<DC>_profiles.csv` and `<DC>_profiles.json` — `Enabled`, `DefaultInboundAction`, `DefaultOutboundAction`, logging settings per profile

### Take a snapshot

```powershell
# Snapshot every DC of the current domain into the given folder
.\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\before-gpo
```

Produces, for each DC:

```
C:\Temp\FW\before-gpo\DC01_rules.csv
C:\Temp\FW\before-gpo\DC01_rules.json
C:\Temp\FW\before-gpo\DC01_profiles.csv
C:\Temp\FW\before-gpo\DC01_profiles.json
```

To target only specific DCs:

```powershell
.\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\dc01-baseline -ComputerName DC01
```

### Compare two snapshots

After pushing a GPO and running `gpupdate /force` on the DCs, take an "after" snapshot and run the script again in **Compare mode**:

```powershell
# 1) Snapshot after the GPO push
.\Export-DCFirewallRules.ps1 -OutputFolder C:\Temp\FW\after-gpo

# 2) Compare before vs after (no DC is queried — pure file-to-file diff)
.\Export-DCFirewallRules.ps1 `
    -Compare C:\Temp\FW\before-gpo, C:\Temp\FW\after-gpo `
    -OutputCompareFolder C:\Temp\FW\diff-gpo
```

> The two folders passed to `-Compare` are PowerShell array values, separated by a **comma**: `-Compare A, B` (not `-Compare A B`).

For each DC found in the "after" folder, Compare mode:

1. Looks for the matching `<DC>_rules.csv` and `<DC>_profiles.csv` in the "before" folder. If absent, that DC is skipped with a `no matching snapshot` notice.
2. Builds the field-level diff (added / removed / modified rules + profile setting changes).
3. Prints a console summary:

   ```text
   [DC01] C:\Temp\FW\before-gpo\DC01_rules.csv  vs  C:\Temp\FW\after-gpo\DC01_rules.csv
     + 3 rule(s) added
     ~ 5 rule(s) modified
     ! 1 profile setting(s) changed
   [DC02] C:\Temp\FW\before-gpo\DC02_rules.csv  vs  C:\Temp\FW\after-gpo\DC02_rules.csv
     No changes detected.
   ```

4. Writes one CSV per DC in `-OutputCompareFolder`: `<DC>_diff.csv`. The file is **always written** (header alone if no change) so its absence really means "comparison not run for that DC", not "no change".

### Diff CSV format

Each row is one change. Columns:

| Column | Filled for | Meaning |
|---|---|---|
| `ChangeType` | all | `Added`, `Removed`, `Modified`, `ProfileChanged` |
| `Name` | rules | The stable rule key (`Get-NetFirewallRule -Name`); empty for `ProfileChanged` |
| `DisplayName` | all | Human-readable rule name; for `ProfileChanged` it's the profile name (`Domain` / `Private` / `Public`) |
| `Direction`, `Action`, `Profile`, `Source` | `Added` / `Removed` only | Inventory of the rule that appeared / disappeared |
| `Field` | `Modified` / `ProfileChanged` only | Name of the changed field (e.g. `Action`, `Enabled`, `RemoteAddress`, `DefaultInboundAction`) |
| `OldValue` / `NewValue` | `Modified` / `ProfileChanged` only | Before / after values |

Examples:

```csv
ChangeType,Name,DisplayName,Direction,Action,Profile,Source,Field,OldValue,NewValue
Added,{76648D33-...},# TEST,Inbound,Allow,Domain,Local,,,
Modified,MyRule,My rule,,,,,Action,Allow,Block
Modified,MyRule,My rule,,,,,Enabled,True,False
ProfileChanged,,Domain,,,,,DefaultInboundAction,Allow,Block
Removed,OldRule,Old rule,Inbound,Allow,Any,GroupPolicy,,,
```

Open the file in Excel and filter on `ChangeType` to get a clean view per category. A single rule with N modified fields produces N rows so you can pivot on `Field` (e.g. *"how many rules had their `Action` changed?"*).

### Why two separate scripts

`Audit-DCFirewall.ps1` and `Export-DCFirewallRules.ps1` are kept separate because they answer different questions and have different data shapes:

- The audit gives you a one-line verdict per DC and is meant to be re-run frequently.
- The export produces a full rule dump (~600 rows per DC) and is meant to be archived in git or compared point-to-point.

Trying to merge them would either bloat the audit output or make the export too lossy to be diff-friendly.

### Fields exported per rule

| Field | Why |
|---|---|
| `Name` (key) | Stable rule ID (does **not** change across reboots / language packs) |
| `DisplayName`, `DisplayGroup`, `Group` | Human-readable identification |
| `Enabled`, `Direction`, `Action`, `Profile` | Core rule semantics |
| `EdgeTraversalPolicy` | Edge handling for IPSec / NAT-T |
| `PolicyStoreSourceType`, `PolicyStoreSource` | **Where the rule comes from** (`Local` vs `GroupPolicy`, plus the GPO GUID) — the gold field after a GPO push |
| `Protocol`, `LocalPort`, `RemotePort`, `IcmpType` | From `Get-NetFirewallPortFilter` |
| `LocalAddress`, `RemoteAddress` | From `Get-NetFirewallAddressFilter` |
| `Program`, `Package` | From `Get-NetFirewallApplicationFilter` |
| `Service` | From `Get-NetFirewallServiceFilter` |

### Typical workflow

1. **Take a baseline** before changing anything: `-OutputFolder C:\Temp\FW\baseline`.
2. **Snapshot before each change** you make to the firewall GPO: `-OutputFolder C:\Temp\FW\before-fix-rdp`.
3. **Push the GPO**, run `gpupdate /force` on the DCs, **snapshot again**: `-OutputFolder C:\Temp\FW\after-fix-rdp`.
4. **Diff the two snapshots**: `-Compare C:\Temp\FW\before-fix-rdp, C:\Temp\FW\after-fix-rdp -OutputCompareFolder C:\Temp\FW\diff-fix-rdp`.
5. **Commit the snapshot folders to Git** if you want a long-term audit trail (CSV+JSON are text and diff cleanly).

### Notes

- The script reads the **`ActiveStore` only**. To compare local vs effective on the same DC, run `Audit-DCFirewall.ps1` (its `WFAS_Local_*` columns surface that delta).
- On DCs with many rules (~600), the join with port/address/application/service filters can take 30–60 seconds per DC. They run **in parallel** across all DCs (one WinRM session each), so the wall-clock cost is roughly that of the slowest DC.
- The diff is **field-level**, so reordering of multi-valued fields (e.g. address lists) shows up. If your GPO admin reorders `RemoteAddress` entries without functional change, expect spurious `Modified` rows.
- The `-Transcript` switch is also available on this script (same behaviour as on `Audit-DCFirewall.ps1`).

---

# Appendix — Column reference for `Audit-DCFirewall.ps1`

The `-ShowLegend` switch prints a colored version of this reference at the end of the run. Below is the same content, organized by section.

### IDENTITY — where you are

| Column | What it means | What a healthy DC shows |
|---|---|---|
| `ComputerName` | DC hostname | — |
| `OSCaption` | Installed OS caption | Windows Server 2019+ ideally |
| `ActiveProfile` | Active network profile per NIC | **`DomainAuthenticated`** on **every** NIC. If a NIC is `Private` or `Public`, it failed to authenticate against the domain at boot — ⚠️ the **wrong rule set** is being applied (Private/Public rules instead of Domain rules). |

### WFAS — the real firewall state

This is the **technical truth**: what `wf.msc` shows and what actually filters traffic.

| Column | What it means | Expected value |
|---|---|---|
| `WFAS_Domain/Private/Public` | Is the firewall **on** for this profile (**Effective** = local + GPO + MDM merged)? | `✓` (True) on all three |
| `WFAS_Local_Domain/Private/Public` | Same, but **local config only** (`PersistentStore`) — what `wf.msc` shows when not viewing GPO data | Should match `WFAS_*` above. If it doesn't, a **GPO or MDM is overriding** the local config. |
| `InAction_*` | Default action for **inbound** traffic | **`Block`** on all three. `Allow` means the firewall is technically on but **does not filter** — effectively a sieve. |
| `OutAction_*` | Default action for **outbound** traffic | **`Allow`** on all three. `Block` would break AD replication and Internet access for the DC. |

> 💡 **Effective vs Local — why two readings?**
> `Get-NetFirewallProfile` defaults to the *ActiveStore* (effective state). On a DC where a Group Policy enforces firewall settings, **the local config can say "off" while the firewall is actually on at runtime** (or vice-versa). `wf.msc` users routinely get confused by this. The script reads both stores and flags the divergence as a `DIVERGENCE` so you immediately know whether the discrepancy is a **GPO override** (often desired — your baseline is doing its job) or a **real config drift**.

### LEGACY REGISTRY — what old GPOs wrote

| Column | What it means | Expected value |
|---|---|---|
| `Reg_Domain/Private/Public` | `EnableFirewall` value under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\<Profile>\` | `1` or `―` (NotSet) |

**Why is this here?** Before Vista / Server 2008, the firewall was driven by this key. Today WFAS takes precedence — but old GPOs or scripts sometimes still write here directly. If `WFAS=✓` but `Reg=0` (or vice-versa), you have a **legacy GPO that lies**, and any tool still reading the registry (old audits, `firewall.cpl`) will show a wrong state.

> 💡 In the registry, the `Private` profile is historically named `StandardProfile`.

### WINDOWS SECURITY CENTER — workstations only

| Column | What it means | Expected value on a DC |
|---|---|---|
| `WSC_Available` | Does the `SecurityCenter2` WMI namespace exist? | `False` (normal on Server SKUs) |
| `WSC_FirewallProducts` | Firewall products registered with WSC (consumed by `firewall.cpl` on workstations) | `N/A` |

WSC does **not** exist on Windows Server. Seeing `True` here is abnormal (workstation masquerading as a DC?). On Windows 10/11 it lets you spot a third-party firewall (CrowdStrike, Sophos, etc.) that has replaced Defender Firewall.

### SERVICES — without these, the firewall doesn't run

| Column | What it means | Expected value |
|---|---|---|
| `Svc_MpsSvc` | "Windows Defender Firewall" service (the firewall itself) | **`Running/Automatic`** — otherwise **nothing is filtered**, regardless of what the other columns say. |
| `Svc_BFE` | "Base Filtering Engine" — low-level engine `MpsSvc` depends on | `Running/Automatic` — if stopped, `MpsSvc` cannot start. |
| `Svc_Wscsvc` | "Security Center" service (workstations) | `NotInstalled` on a DC (normal). |

### REQUIRED RULE GROUPS — the inbound rules AD needs

The script also verifies that **inbound rules** required by the DC role are **present and enabled** on the Domain profile.

| Column | What it means |
|---|---|
| `Rules_Status` | Overall verdict: `OK` / `MISSING` / `DISABLED` |
| `Rules_Missing` | Groups for which **no rule exists** on the host (entirely absent — abnormal) |
| `Rules_Disabled` | Groups that **exist** but have **no enabled rule** on the Domain profile (typically a hardening GPO that turned them off by mistake) |
| `RuleGroups_Detail` | Flat compact summary: `AD-DS=OK | KDC=OK | DNS=OK | ...`. CSV-friendly mirror of the per-group breakdown. |

Default groups checked: AD DS, KDC, DNS, File and Printer Sharing (SMB for SYSVOL), DFS Replication, WMI, Core Networking. See [Required firewall rule groups checked on the Domain profile](#required-firewall-rule-groups-checked-on-the-domain-profile).

### OVERALL VERDICT — the bottom line

| Value | Meaning |
|---|---|
| `OK` | Everything is compliant, nothing to do. |
| `DIVERGENCE` | At least **one** anomaly was detected. The `Notes` column tells you which. |

`Status` flips to `DIVERGENCE` as soon as **any** check above fails (service stopped, profile disabled, registry mismatch, required rule missing, etc.).

### Where to look first

1. **`Status`** — if `OK` everywhere, you're done.
2. **`MpsSvc` / `BFE`** — if not running, everything else is meaningless.
3. **`Firewall(D/P/Pu)`** — must be `✓ / ✓ / ✓` (Effective state). If `✗` somewhere, check the `Hint` line for runtime impact.
4. **`Firewall Effective` vs `Firewall Local`** in DIVERGENCE DETAILS — if they differ, a GPO/MDM is overriding. Usually that's intended (your hardening baseline doing its job). Run `gpresult /h gpresult.html` to identify the GPO.
5. **`Inbound(D/P/Pu)`** — must be `B / B / B`. `Allow` = sieve (only critical on profiles where NICs actually live).
6. **`Registry`** vs **`Firewall`** — divergence = legacy GPO to clean up.
7. **`Rules`** — if `DISABLED` or `MISSING`, drill into the *Rule Groups Detail* block.
8. **`ActiveProfile`** — every NIC must be `DomainAuthenticated`.

## Notes

- **Both scripts are read-only.** They do not change any setting on any DC.
- Microsoft Security Baseline recommends **all three profiles enabled** on every server, including DCs. `Audit-DCFirewall.ps1` flags any disabled profile as a divergence accordingly.
- On Server SKUs the WSC (Security Center) namespace is absent — that is normal and reported as `N/A`, not as a divergence.
- All comparisons in `Audit-DCFirewall.ps1` are done against the **`ActiveStore`** (effective state). The `WFAS_Local_*` columns add a second reading from the **`PersistentStore`** so you can detect GPO/MDM overrides without mistaking them for outages.
- `Export-DCFirewallRules.ps1` reads the **`ActiveStore` only**. To compare local vs effective on the same DC, use `Audit-DCFirewall.ps1`.

## References

- [Windows Firewall — Best practices for configuring](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/best-practices) — official guidance: keep the firewall **enabled on all three profiles**, with **Inbound = Block** and **Outbound = Allow** as defaults.
- [Securing domain controllers against attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack) — recommends the host-based firewall on every DC and lists the ports the DC role requires.
- [Best practices for securing Active Directory — *Use host-based firewalls to control and secure communications*](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory#security-measure-summary-table) — listed as a tactical preventative measure in the official AD security summary table.
- [Windows Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) — canonical source for the per-profile settings (`Domain/Private/Public = Enabled`, `DefaultInboundAction = Block`, `DefaultOutboundAction = Allow`). Downloadable as GPO backups via the **Security Compliance Toolkit**.
- [How to configure RPC dynamic port allocation to work with firewalls](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation-with-firewalls) — useful when you also need to restrict the DC's RPC dynamic port range.
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile) — cmdlet reference used as the script's authoritative source.

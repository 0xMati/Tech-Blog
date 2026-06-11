---
title: "How to check firewall state on DCs with PowerShell"
date: 2026-06-04
---

# How to check firewall state on DCs with PowerShell

A common drift on Domain Controllers is the Windows Firewall ending up in an inconsistent state: `wf.msc` says **enabled**, the legacy `firewall.cpl` says **disabled** (on the rare workstation-style DC), and the registry tells yet another story. This usually happens when an old GPO or a hand-written script writes directly under `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` instead of going through WFAS.

The companion script [Audit-DCFirewall.ps1](Audit-DCFirewall.ps1) queries **every DC of the current domain in parallel** and cross-checks the three sources of truth so you can spot the divergence in one look.

## What the script checks

For each DC, on each of the three firewall profiles (**Domain / Private / Public**):

| Source | What it tells you |
|---|---|
| **WFAS** (`Get-NetFirewallProfile`) | The *authoritative* state — what `wf.msc` shows, and what actually filters traffic |
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
> If your baseline requires either of them, add them via `-RequiredRuleGroups` (see [Usage](#usage)).

The list is overridable via the `-RequiredRuleGroups` parameter (see [Usage](#usage)). A group classifies as:

- **`MISSING`** — no rule at all is registered for the group on the host (typical of a DC where the AD-DS rule set was never installed, or where someone deleted the rules).
- **`DISABLED`** — rules exist but none is `Enabled=True` and inbound on the Domain profile (often the result of a hardening GPO that disabled them by mistake).
- **`OK`** — at least one matching rule is active.

The script then issues a verdict per DC:

- **`OK`** — no issue detected
- **`DIVERGENCE`** — at least one of: service not running, WFAS ≠ registry, profile disabled, `Enabled=True` but `DefaultInboundAction=Allow`, WSC reports non-Defender or multiple firewall products, **a required rule group is missing or disabled on the Domain profile**

The full column legend is printed at the end of the console output and also dumped to a `*_legend.txt` companion file when you export to CSV.

## Prerequisites

- Run from a workstation or a DC with the **ActiveDirectory** PowerShell module installed (RSAT).
- The account running the script needs **WinRM remote PowerShell** access on every DC (typically a Tier 0 admin).
- WinRM (`Enable-PSRemoting`) must be enabled on each DC. On a properly-managed forest it is, by default.

## Usage

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

## Reading the output

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

## Column reference — what each column means and why you look at it

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
| `WFAS_Domain/Private/Public` | Is the firewall **on** for this profile? | `✓` (True) on all three |
| `InAction_*` | Default action for **inbound** traffic | **`Block`** on all three. `Allow` means the firewall is technically on but **does not filter** — effectively a sieve. |
| `OutAction_*` | Default action for **outbound** traffic | **`Allow`** on all three. `Block` would break AD replication and Internet access for the DC. |

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
3. **`Firewall(D/P/Pu)`** — must be `✓ / ✓ / ✓`.
4. **`Inbound(D/P/Pu)`** — must be `B / B / B`. `Allow` = sieve.
5. **`Registry`** vs **`Firewall`** — divergence = legacy GPO to clean up.
6. **`Rules`** — if `DISABLED` or `MISSING`, drill into the *Rule Groups Detail* block.
7. **`ActiveProfile`** — every NIC must be `DomainAuthenticated`.

## Notes

- The script is read-only. It does not change any setting on any DC.
- Microsoft Security Baseline recommends **all three profiles enabled** on every server, including DCs. The script flags any disabled profile as a divergence accordingly.
- On Server SKUs the WSC (Security Center) namespace is absent — that is normal and reported as `N/A`, not as a divergence.

## References

- [Windows Firewall — Best practices for configuring](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/best-practices) — official guidance: keep the firewall **enabled on all three profiles**, with **Inbound = Block** and **Outbound = Allow** as defaults.
- [Securing domain controllers against attack](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/securing-domain-controllers-against-attack) — recommends the host-based firewall on every DC and lists the ports the DC role requires.
- [Best practices for securing Active Directory — *Use host-based firewalls to control and secure communications*](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory#security-measure-summary-table) — listed as a tactical preventative measure in the official AD security summary table.
- [Windows Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines) — canonical source for the per-profile settings (`Domain/Private/Public = Enabled`, `DefaultInboundAction = Block`, `DefaultOutboundAction = Allow`). Downloadable as GPO backups via the **Security Compliance Toolkit**.
- [How to configure RPC dynamic port allocation to work with firewalls](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-rpc-dynamic-port-allocation-with-firewalls) — useful when you also need to restrict the DC's RPC dynamic port range.
- [Get-NetFirewallProfile](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile) — cmdlet reference used as the script's authoritative source.

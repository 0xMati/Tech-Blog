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

The script then issues a verdict per DC:

- **`OK`** — no issue detected
- **`DIVERGENCE`** — at least one of: service not running, WFAS ≠ registry, profile disabled, `Enabled=True` but `DefaultInboundAction=Allow`, WSC reports non-Defender or multiple firewall products

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

### Export the result to CSV (with the legend file alongside)

```powershell
.\Audit-DCFirewall.ps1 -ExportCsv C:\Temp\DCFirewallAudit.csv
# Produces:
#   C:\Temp\DCFirewallAudit.csv          <- the data
#   C:\Temp\DCFirewallAudit_legend.txt   <- the column legend
```

## Reading the output

The console output is in three blocks:

1. **Summary table** — one line per DC with the key columns (active profile, WFAS state per profile, inbound default action, registry state, `MpsSvc` status, verdict).
2. **Divergence details** — for each DC flagged `DIVERGENCE`, the `Notes` field details the issues and the relevant raw values.
3. **Totals** — `X OK / Y DIVERGENCE`.
4. **Legend** — printed in dark gray at the bottom.

A typical "all good" DC shows:

- `ActiveProfile` → `DomainAuthenticated` on every NIC
- `WFAS_Domain` / `WFAS_Private` / `WFAS_Public` → `True`
- `InAction_*` → `Block` (inbound) / `Allow` (outbound)
- `Reg_*` → `1` or `NotSet`
- `Svc_MpsSvc` → `Running/Automatic`
- `Status` → `OK`

A typical drift case looks like:

```
WFAS_Public = True   but Reg_Public = 0
=> DIVERGENCE: Public: WFAS=True but Registry=0
```

That tells you a legacy mechanism wrote `EnableFirewall=0` directly in the registry, but WFAS overrode it — meaning the firewall *is* on, but `firewall.cpl` and any tool that reads the registry value will be misleading. Time to find and remove that legacy GPO/script.

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

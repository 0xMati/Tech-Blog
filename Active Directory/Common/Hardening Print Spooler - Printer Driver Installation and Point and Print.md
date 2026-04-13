# Hardening Print Spooler — Printer Driver Installation and Point and Print
🗓️ Published: 2026-04-13

## Introduction

After the PrintNightmare vulnerabilities (CVE-2021-34527, CVE-2021-1675), Microsoft fundamentally changed the default behavior of printer driver installation on Windows.

Two distinct security controls now govern who can install printer drivers:

1. **GPO "Devices: Prevent users from installing printer drivers"** — blocks manual/local driver installation by non-admins.

2. **Registry key `RestrictDriverInstallationToAdministrators`** — blocks automatic driver installation via **Point and Print** (network printers from a print server).

> 🔑 These are **two independent controls**. Enabling one does not configure the other. For full hardening, **both must be set**.

## 🔧 The two controls explained

### Control 1 — GPO: Devices: Prevent users from installing printer drivers

| Setting | Detail |
|---|---|
| **GPO Path** | `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options` |
| **Policy name** | Devices: Prevent users from installing printer drivers |
| **Registry backing** | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers` → `AddPrinterDrivers` (DWORD) |
| **Enabled (1)** | Only administrators can install printer drivers (local install, USB, INF, EXE) |
| **Disabled (0)** | Standard users can install certain drivers |

**Scope:** controls "classic" driver installation — when a user manually installs a driver from a local source (USB device, downloaded installer, INF file).

---

### Control 2 — RestrictDriverInstallationToAdministrators

| Setting | Detail |
|---|---|
| **Registry path** | `HKLM\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint` |
| **Value name** | `RestrictDriverInstallationToAdministrators` (DWORD) |
| **1** | Only administrators can install drivers via Point and Print |
| **0** | Standard users can install drivers from a print server |
| **Absent** | Since the PrintNightmare patches, Windows treats absent as **1** (secure by default) |

**Scope:** controls **Point and Print** specifically — the automatic driver download that happens when a user connects to a shared printer on a print server (e.g. `\\PrintSrv\HP-Finance`).

> ⚠️ Some organizations historically set this to **0** to avoid helpdesk tickets about printers. This **re-opens the PrintNightmare attack surface**.

## 📊 Behavior matrix (standard user)

| GPO "Prevent users from installing printer drivers" | RestrictDriverInstallationToAdministrators | Manual driver install (USB / EXE / INF) | Point and Print (network printer from print server) |
|---|---|---|---|
| Disabled | 0 | ✅ Allowed | ✅ Allowed |
| Disabled | 1 | ✅ Allowed | ❌ Blocked |
| **Enabled** | 0 | ❌ Blocked | ✅ Allowed |
| **Enabled** | **1** | ❌ Blocked | ❌ Blocked |

**Target state:** both Enabled / 1 → standard users cannot install drivers by any method.

---

## 🖨️ How to deploy printers securely with full hardening

With both controls active, standard users cannot install drivers.

The question becomes: **how do users get their printers?**

### ❌ Common misconception — GPO Preferences (User Configuration)

Many guides suggest deploying printers via:

```
User Configuration > Preferences > Control Panel Settings > Printers
```

This runs **in the user's security context**. If the driver is not already present on the workstation and `RestrictDriverInstallationToAdministrators = 1`, the printer mapping **will fail** because the user context cannot install the driver.

---

### ✅ Correct method — Per-Machine deployment (Computer Configuration)

The supported method that works with full hardening:

1. Open the **Print Management** console (`printmanagement.msc`) on your print server.
2. Right-click a shared printer → **Deploy with Group Policy**.
3. Select a GPO and choose **Per Machine** (Computer Configuration).
4. This creates an entry under `Computer Configuration > Windows Settings > Deployed Printers`.

> 💡 **Why this works:** the printer connection is processed by `PushPrinterConnections.exe` running as **SYSTEM** during machine startup. The SYSTEM context has full rights to install drivers regardless of user-level restrictions.

| Deployment method | Execution context | Works with RestrictDriverInstallationToAdministrators = 1? |
|---|---|---|
| GPO Preferences > User Config > Printers | User | ❌ No (unless driver is pre-staged) |
| Deploy with Group Policy > **Per Machine** | SYSTEM | ✅ Yes |
| Deploy with Group Policy > Per User | User | ❌ No (unless driver is pre-staged) |

---

### 🔄 Alternative — Pre-stage drivers then use per-user deployment

If you prefer per-user GPO Preferences (e.g. for targeting by security group), you can **pre-stage** the driver so it's already present when the user mapping runs:

1. **Image-based:** include the driver in your SOE/golden image (MDT, SCCM task sequence).
2. **pnputil:** deploy via a script running as SYSTEM:
   ```powershell
   pnputil.exe /add-driver "\\FileServer\Drivers\HP-UPD\hpbuio2l.inf" /install
   ```
3. **SCCM / Intune:** deploy the driver package to machines before mapping printers.

Once the driver is present on the workstation, per-user GPO Preferences will succeed because no driver installation is needed — only a printer connection.

---

## ✅ Recommendations

### Workstations

| Setting | Recommended value | Notes |
|---|---|---|
| GPO "Devices: Prevent users from installing printer drivers" | **Enabled** | Blocks manual driver installation by non-admins |
| `RestrictDriverInstallationToAdministrators` | **1** (or absent — defaults to 1 post-patch) | Blocks Point and Print driver installation by non-admins |
| Printer deployment method | **Per-Machine** via Print Management console | Runs as SYSTEM, not affected by user restrictions |

### Print Servers


| Action | Why |
|---|---|
| Dedicate the print server role — never use a Domain Controller as a print server | A compromised Print Spooler on a DC = domain compromise |
| Restrict who can install drivers on the print server | Only designated print admins should modify drivers |
| Use signed drivers only | Unsigned drivers are an unnecessary risk |
| Prefer Type 4 (v4) drivers over Type 3 (v3) | Type 4 drivers run in user-mode, are package-aware, and reduce kernel attack surface |
| Disable the Print Spooler service on servers that don't need it (especially DCs) | Reduces attack surface — `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled` |
| Monitor driver changes on print servers | A compromised print server can push malicious drivers to every client |

### ⚠️ Remaining risks (even with full hardening)

The per-machine deployment model shifts trust to the **print server**. If the print server is compromised, an attacker can replace a legitimate driver with a malicious one, and it will be deployed to all clients via SYSTEM context. Therefore:

- Harden the print server as a **Tier 1 asset**.
- Restrict RDP and admin access.
- Monitor for unexpected driver changes (Event ID 316 in `Microsoft-Windows-PrintService/Admin`).

---

## 📚 References

- [CVE-2021-34527 — Windows Print Spooler Remote Code Execution (PrintNightmare)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527)
- [KB5005010 — Restricting installation of new printer drivers after applying July 2021 updates](https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7)
- [Managing Point and Print restrictions](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/point-and-print-restrictions)
- [Deploy printers by using Group Policy](https://learn.microsoft.com/en-us/windows-server/administration/print-management/deploy-printers-by-using-group-policy)

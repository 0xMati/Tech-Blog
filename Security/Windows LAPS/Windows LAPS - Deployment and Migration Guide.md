# Windows LAPS – Deployment and Migration Guide
🗓️ Published: 2026-03-23

Hey everyone!

If you're still managing local admin passwords with spreadsheets, GPO preferences, or the good old Legacy LAPS (Microsoft LAPS), it's time to level up. **Windows LAPS** (Local Administrator Password Solution) is the built-in, modern successor that ships natively with Windows and stores passwords directly in Active Directory or Entra ID — no more MSI installs, no more `AdmPwd.dll` side-loading.

In this post we'll cover what Windows LAPS is, why you need it, how to deploy it from scratch, and how to migrate smoothly from Legacy LAPS.

---

## 📖 What Is Windows LAPS?

Windows LAPS is a **native Windows feature** (built into the OS since April 2023 updates) that automatically manages and rotates the password of a local administrator account on domain-joined or Entra ID-joined devices.

Key characteristics:

- **No agent to install** — the LAPS client is part of the Windows OS (Windows 10 20H2+, Windows 11, Windows Server 2019+, after the April 2023 cumulative update).
- **Passwords stored in AD or Entra ID** — encrypted attribute in Active Directory (`msLAPS-Password`, `msLAPS-EncryptedPassword`) or in Microsoft Entra ID.
- **Password encryption** — supports encrypting passwords using a designated principal (user/group), leveraging CNG/DPAPI-NG. Only authorized identities can decrypt.
- **Password history** — Active Directory can retain encrypted password history.
- **DSRM account support** — can manage the Directory Services Restore Mode password on Domain Controllers.
- **Entra ID backup** — hybrid-joined devices can back up their passwords to Entra ID.
- **Auditing** — dedicated Windows event log: `Microsoft-Windows-LAPS/Operational`.

🔗 https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview

---

## 🎯 Why Use Windows LAPS?

Without LAPS, organizations typically fall into one of these traps:

| Problem | Risk |
|---|---|
| Same local admin password on every machine | One compromised machine = lateral movement everywhere |
| Passwords stored in GPO Preferences (cpassword) | Trivially decryptable by any domain user — MS14-025 |
| No rotation policy | Stale passwords that never expire |
| Manual password management | Doesn't scale, prone to human error |

Windows LAPS solves all of this by:

- **Randomizing** each machine's local admin password on a defined schedule
- **Storing** the password securely in AD/Entra ID with access control
- **Encrypting** the password so only authorized principals can read it
- **Rotating** automatically based on policy (default: 30 days)

---

## 🛠️ Prerequisites

Before deploying, make sure you meet these requirements:

### Operating System
- **Windows 10** 21H2 or later with the April 11, 2023 update (KB5025221) or later
- **Windows 11** 21H2 or later with the April 11, 2023 update (KB5025224) or later
- **Windows Server 2019** with the April 11, 2023 update or later
- **Windows Server 2022** with the April 11, 2023 update or later
- **Windows Server 2025** (built-in)

### Active Directory
- **Schema update** required to add the new LAPS attributes
- **Domain functional level**: Windows Server 2016 or later (required for password encryption)
- **Permissions**: delegated write access for machines, delegated read access for admins

### Entra ID (optional)
- Entra ID-joined or hybrid-joined devices
- **Intune** license for policy deployment via Endpoint Security

---

## 🚀 Deployment – Step by Step (Active Directory)

### Step 1 — Update the AD Schema

The schema update adds the new `msLAPS-*` attributes. Run this from a machine with the AD PowerShell module, as **Schema Admin**:

```powershell
Import-Module LAPS
Update-LapsADSchema
```

You can verify the new attributes exist:

```powershell
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter { name -like "msLAPS*" } -Properties name | Select-Object name
```

Expected attributes:
- `msLAPS-PasswordExpirationTime`
- `msLAPS-Password`
- `msLAPS-EncryptedPassword`
- `msLAPS-EncryptedPasswordHistory`
- `msLAPS-EncryptedDSRMPassword`
- `msLAPS-EncryptedDSRMPasswordHistory`

---

### Step 2 — Set Permissions on the OU

Grant the **computer accounts** (SELF) the right to write their own LAPS password attributes:

```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=contoso,DC=com"
```

Then, grant read/reset permissions to your **admin group**:

```powershell
# Allow a group to read LAPS passwords
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers"

# Allow a group to force password rotation
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers"
```

> 💡 **Tip**: Use `Find-LapsADExtendedRights` to audit who currently has extended rights on an OU — this helps you spot unwanted permission inheritance.

```powershell
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=contoso,DC=com"
```

---

### Step 3 — Configure the LAPS Policy via GPO

Create a new GPO (or edit an existing one) and navigate to:

**Computer Configuration → Administrative Templates → System → LAPS**

Configure the following settings:

| Setting | Recommended Value | Notes |
|---|---|---|
| **Configure password backup directory** | Active Directory | Or Azure Active Directory for cloud-only |
| **Password Settings** | Complexity: Large letters + small letters + numbers + specials, Length: 20+, Age: 30 days | Adjust to your security baseline |
| **Name of administrator account to manage** | *(leave blank for built-in admin, or specify a custom account name)* | If you renamed the built-in admin, specify the name |
| **Enable password encryption** | Enabled | Requires 2016 DFL. Highly recommended |
| **Configure authorized password decryptors** | `CONTOSO\LAPS-Password-Readers` | Group authorized to decrypt passwords |
| **Enable password backup for DSRM accounts** | Enabled | Only applies to DCs |
| **Post-authentication actions** | Reset password and logoff | After admin usage, rotate and kill sessions |
| **Post-authentication reset delay** | 8 hours | Grace period after password retrieval |

Link the GPO to the target OU(s).

---

### Step 4 — Verify Deployment

After group policy has refreshed on a client, check the event log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 20
```

Retrieve the LAPS password for a specific computer:

```powershell
Get-LapsADPassword -Identity "YOURPC01" -AsPlainText
```

Or from the **Active Directory Users and Computers** console → computer object → **LAPS** tab.

---

## ☁️ Deployment – Entra ID & Intune

For Entra ID-joined (or hybrid-joined) devices managed by Intune:

1. **Enable LAPS in Entra ID**:
   - Go to **Entra ID Portal** → **Devices** → **Device settings** → **Enable Microsoft Entra Local Administrator Password Solution (LAPS)** → **Yes**

2. **Create an Endpoint Security policy in Intune**:
   - **Intune Admin Center** → **Endpoint Security** → **Account Protection** → **Create Policy**
   - Platform: **Windows 10 and later**
   - Profile: **Local admin password solution (Windows LAPS)**

3. **Configure the policy settings** (similar to GPO):
   - Backup directory: Azure AD or Azure AD and Active Directory (hybrid)
   - Password complexity, length, age
   - Post-authentication actions
   - Administrator account name

4. **Assign the policy** to the appropriate device groups.

5. **Retrieve passwords** from the **Entra ID Portal** → **Devices** → select device → **Local administrator password** tab, or through the **Intune Admin Center**.

🔗 https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords

---

## 🔄 Migrating from Legacy LAPS to Windows LAPS

If you already have **Legacy LAPS** (the MSI-based version using `ms-Mcs-AdmPwd`) deployed, the good news is: **Windows LAPS and Legacy LAPS can coexist** — but Legacy LAPS **must be in emulation mode** during transition.

### Migration Strategy Overview

```
Legacy LAPS only
      ↓
Enable Windows LAPS in Legacy emulation mode
      ↓
Validate on pilot group
      ↓
Switch to Windows LAPS native mode
      ↓
Remove Legacy LAPS components
```

---

### Step 1 — Verify Current Legacy LAPS Deployment

Confirm Legacy LAPS is working and identify the OUs it manages:

```powershell
# Check the Legacy LAPS attributes in AD
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=contoso,DC=com" `
    -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime |
    Select-Object Name, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
```

Check which machines have the Legacy LAPS CSE installed:

```powershell
Get-ChildItem "\\contoso.com\SYSVOL\contoso.com\Policies" -Recurse -Filter "AdmPwd.dll" -ErrorAction SilentlyContinue
```

---

### Step 2 — Update the AD Schema for Windows LAPS

If not already done:

```powershell
Import-Module LAPS
Update-LapsADSchema
```

This adds the new `msLAPS-*` attributes alongside the existing `ms-Mcs-*` attributes. **No impact on Legacy LAPS**.

---

### Step 3 — Configure Windows LAPS in Legacy Emulation Mode

Create a new GPO targeting your **pilot OU** with the following settings:

| Setting | Value |
|---|---|
| **Configure password backup directory** | Active Directory |
| **Enable password encryption** | Disabled *(initially, to match Legacy LAPS behavior)* |
| **Configure size of encrypted password history** | 0 |

> ⚠️ **Important**: When Windows LAPS detects that Legacy LAPS is also installed and configured, it operates in **emulation mode** by default. In this mode, Windows LAPS processes the Legacy LAPS GPO settings and writes passwords to the Legacy `ms-Mcs-AdmPwd` attribute.

This allows you to validate Windows LAPS behavior without any disruption.

---

### Step 4 — Pilot and Validate

On your pilot machines:

1. Ensure the April 2023 (or later) cumulative update is installed
2. Apply the new GPO
3. Run `gpupdate /force`
4. Check the LAPS event log:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 10 |
    Format-Table TimeCreated, Id, Message -Wrap
```

5. Verify the password is updated in AD:

```powershell
Get-LapsADPassword -Identity "PILOTPC01" -AsPlainText
```

---

### Step 5 — Switch to Windows LAPS Native Mode

Once you're confident the pilot is working, update the GPO to use **native Windows LAPS mode** with full features:

| Setting | New Value |
|---|---|
| **Configure password backup directory** | Active Directory |
| **Enable password encryption** | **Enabled** |
| **Configure authorized password decryptors** | `CONTOSO\LAPS-Password-Readers` |
| **Password Settings** | Complexity: Large + small + numbers + specials, Length: 20+, Age: 30 days |
| **Post-authentication actions** | Reset password and logoff |
| **Post-authentication reset delay** | 8 hours |

Set permissions on the OU:

```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=contoso,DC=com"
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers"
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers"
```

> 💡 Once Windows LAPS native mode is active, passwords are stored in the new `msLAPS-EncryptedPassword` attribute (encrypted). The Legacy `ms-Mcs-AdmPwd` attribute will no longer be updated.

---

### Step 6 — Clean Up Legacy LAPS

After all machines have transitioned:

1. **Remove the Legacy LAPS GPO** (or unlink it)
2. **Uninstall the Legacy LAPS CSE** (MSI) from all clients:

```powershell
# Find and uninstall Legacy LAPS MSI (example)
$laps = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Local Administrator Password Solution*" }
if ($laps) { $laps.Uninstall() }
```

Or via your software deployment tool (SCCM, Intune, etc.).

3. **Remove the Legacy LAPS PowerShell module** (if installed separately):

```powershell
Uninstall-Module -Name AdmPwd.PS -Force -ErrorAction SilentlyContinue
```

4. **(Optional) Clean up Legacy attributes**: The `ms-Mcs-AdmPwd` and `ms-Mcs-AdmPwdExpirationTime` attributes will remain in the schema (schema attributes cannot be deleted), but you can clear the values:

```powershell
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=contoso,DC=com" `
    -Properties ms-Mcs-AdmPwd |
    Where-Object { $_.'ms-Mcs-AdmPwd' -ne $null } |
    Set-ADComputer -Clear 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'
```

5. **Remove Legacy LAPS permissions** on OUs (the extended rights for `ms-Mcs-AdmPwd`).

---

## 🔍 Useful Commands Reference

| Command | Description |
|---|---|
| `Get-LapsADPassword -Identity "PC01" -AsPlainText` | Retrieve the LAPS password for a computer |
| `Reset-LapsPassword` | Force immediate password rotation (run locally) |
| `Get-LapsDiagnostics` | Collect LAPS diagnostic logs |
| `Set-LapsADComputerSelfPermission -Identity "OU=..."` | Grant SELF write permissions |
| `Set-LapsADReadPasswordPermission -Identity "OU=..."` | Delegate read permissions |
| `Set-LapsADResetPasswordPermission -Identity "OU=..."` | Delegate reset permissions |
| `Find-LapsADExtendedRights -Identity "OU=..."` | Audit extended rights on an OU |
| `Update-LapsADSchema` | Extend AD schema for Windows LAPS |

---

## ⚠️ Common Pitfalls

- **Missing April 2023 update**: Windows LAPS won't work without the KB. Ensure all target machines are patched.
- **Schema update forgotten**: The `Update-LapsADSchema` must be run before any policy can work against AD.
- **DFL too low for encryption**: Password encryption requires **Windows Server 2016 domain functional level**. Without it, passwords are stored in clear text in the `msLAPS-Password` attribute.
- **Conflicting GPOs**: If both Legacy LAPS GPO and Windows LAPS GPO are applied, Windows LAPS enters emulation mode. Make sure to clean up Legacy GPO after migration.
- **Post-authentication actions not configured**: Without this, a retrieved password stays valid indefinitely until the next scheduled rotation. Always configure post-authentication reset.
- **Wrong OU permissions**: If `Set-LapsADComputerSelfPermission` was not run, computers cannot write their password back to AD and you'll see errors in the event log.

---

## 🧰 Automation Toolkit

Three PowerShell tools are available in this repository to automate the LAPS lifecycle:

| Tool | Purpose |
|---|---|
| **`Invoke-LAPSAssessment.ps1`** | Full audit of your environment: schema, GPOs, OU permissions, computer inventory, password status, OS eligibility, migration readiness |
| **`Deploy-WindowsLAPS.ps1`** | Automated deployment: schema update, OU permissions, GPO creation with best-practice settings, validation |
| **`Invoke-LAPSMigration.ps1`** | Guided migration from Legacy LAPS in 5 phases: PreCheck → SchemaAndEmulation → ValidatePilot → SwitchToNative → CleanupLegacy |

### Quick start examples

```powershell
# 1. Assess current state
.\Invoke-LAPSAssessment.ps1 -ExportCSV

# 2a. Fresh deployment (no Legacy LAPS)
.\Deploy-WindowsLAPS.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers"

# 2b. Migration from Legacy LAPS
.\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase PreCheck
.\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase SchemaAndEmulation
.\Invoke-LAPSMigration.ps1 -TargetOU "OU=Pilot,OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase ValidatePilot
.\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -ReadGroup "CONTOSO\LAPS-Readers" -Phase SwitchToNative
.\Invoke-LAPSMigration.ps1 -TargetOU "OU=Workstations,DC=contoso,DC=com" -Phase CleanupLegacy
```

---

## 📚 References

🔗 [Windows LAPS Overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
🔗 [Get Started with Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
🔗 [Windows LAPS with Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords)
🔗 [Migrate from Legacy LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy)
🔗 [Windows LAPS CSP (Intune)](https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp)
🔗 [Windows LAPS Troubleshooting](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-troubleshooting)

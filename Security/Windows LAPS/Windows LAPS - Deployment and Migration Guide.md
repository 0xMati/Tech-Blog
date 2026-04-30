# Windows LAPS – Deployment and Migration Guide
🗓️ Published: 2026-03-23

Hey everyone!

If you're still managing local admin passwords with spreadsheets, GPO preferences, or the good old Legacy LAPS (Microsoft LAPS), it's time to level up. **Windows LAPS** (Local Administrator Password Solution) is the built-in, modern successor that ships natively with Windows and stores passwords directly in Active Directory or Entra ID — no more MSI installs, no more `AdmPwd.dll` side-loading.

In this post we'll cover what Windows LAPS is, why you need it, how to deploy it from scratch, and how to migrate smoothly from Legacy LAPS.

---

## Table of Contents

- [📖 What Is Windows LAPS?](#-what-is-windows-laps)
- [🎯 Why Use Windows LAPS?](#-why-use-windows-laps)
- [🛠️ Prerequisites](#️-prerequisites)
- [🚀 Deployment – Step by Step (Active Directory)](#-deployment--step-by-step-active-directory)
    - [Step 1 — Update the AD Schema](#step-1--update-the-ad-schema)
    - [Step 2 — Set Permissions on the OU](#step-2--set-permissions-on-the-ou)
    - [Step 3 — Configure the LAPS Policy via GPO](#step-3--configure-the-laps-policy-via-gpo)
    - [Step 4 — Verify Deployment](#step-4--verify-deployment)
    - [Step 5 — Manage DSRM Password on Domain Controllers](#step-5--manage-dsrm-password-on-domain-controllers)
- [☁️ Deployment – Entra ID & Intune](#️-deployment--entra-id--intune)
- [🔄 Migrating from Legacy LAPS to Windows LAPS](#-migrating-from-legacy-laps-to-windows-laps)
  - [Step 1 — Verify Current Legacy LAPS Deployment](#step-1--verify-current-legacy-laps-deployment)
  - [Step 2 — Update the AD Schema for Windows LAPS](#step-2--update-the-ad-schema-for-windows-laps)
  - [Step 3 — Uninstall Legacy LAPS CSE on Pilot Machines](#step-3--uninstall-legacy-laps-cse-on-pilot-machines)
  - [Step 4 — Pilot and Validate](#step-4--pilot-and-validate)
  - [Step 5 — Switch to Windows LAPS Native Mode](#step-5--switch-to-windows-laps-native-mode)
  - [Step 6 — Clean Up Legacy LAPS](#step-6--clean-up-legacy-laps)
- [🔍 Useful Commands Reference](#-useful-commands-reference)
- [⚠️ Common Pitfalls](#️-common-pitfalls)
- [🧰 Automation Toolkit](#-automation-toolkit)
- [📚 References](#-references)

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
Update-LapsADSchema -Verbose
```

You can verify the new attributes exist:

```powershell
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter { name -like "ms-LAPS*" } -Properties name | Select-Object name
```

Expected attributes:
- `ms-LAPS-PasswordExpirationTime`
- `ms-LAPS-Password`
- `ms-LAPS-EncryptedPassword`
- `ms-LAPS-EncryptedPasswordHistory`
- `ms-LAPS-EncryptedDSRMPassword`
- `ms-LAPS-EncryptedDSRMPasswordHistory`

---

### Step 2 — Set Permissions on the OU

Grant the **computer accounts** (SELF) the right to write their own LAPS password attributes:

```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,DC=contoso,DC=com" -verbose
```

Then, grant read/reset permissions to your **admin group**:

```powershell
# Allow a group to read LAPS passwords
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers" -Verbose

# Allow a group to force password rotation
Set-LapsADResetPasswordPermission -Identity "OU=Workstations,DC=contoso,DC=com" `
    -AllowedPrincipals "CONTOSO\LAPS-Password-Readers" -Verbose
```

> 💡 **Tip**: Use `Find-LapsADExtendedRights` to audit who currently has extended rights on an OU — this helps you spot unwanted permission inheritance.

```powershell
Find-LapsADExtendedRights -Identity "OU=Workstations,DC=contoso,DC=com" -Verbose
```

---

### Step 3 — Configure the LAPS Policy via GPO

Create a new GPO (or edit an existing one) and navigate to:

**Computer Configuration → Administrative Templates → System → LAPS**

Configure the following settings:

| Setting | Recommended Value | Description | Notes |
|---|---|---|---|
| **Configure password backup directory** | Active Directory | Defines where the LAPS password is stored (AD, Entra ID, or disabled). This is the master switch — if disabled, LAPS does nothing. | Or Azure Active Directory for cloud-only |
| **Password Settings** | Complexity: Large letters + small letters + numbers + specials, Length: 20+, Age: 30 days | Controls password complexity, length, and rotation frequency. A longer, more complex password reduces brute-force risk. Age defines how often the password is automatically rotated. | Adjust to your security baseline |
| **Name of administrator account to manage** | *(leave blank for built-in admin, or specify a custom account name)* | Specifies which local account LAPS manages. If left blank, LAPS targets the built-in Administrator (RID 500) regardless of its display name. | If you renamed the built-in admin, specify the name |
| **Enable password encryption** | Enabled | Encrypts the password stored in AD using CNG/DPAPI-NG so that only authorized principals can decrypt it. Without this, the password is stored in clear text in the `msLAPS-Password` attribute. | Requires 2016 DFL. Highly recommended |
| **Configure authorized password decryptors** | `CONTOSO\LAPS-Password-Readers` | Defines which AD principal (user or group) can decrypt encrypted passwords. This setting has effect only when encryption is enabled. If disabled or not configured, encrypted passwords are decryptable by Domain Admins. | Use a domain-qualified name, UPN, or SID string. Do not use quotes or parentheses. The principal must be resolvable by managed devices. Ignored for DSRM backup on DCs (Domain Admins apply by design). |
| **Configure automatic account management** | Enabled | When enabled, LAPS automatically creates and manages a local admin account with a random name. This avoids relying on the built-in Administrator (RID 500) which is a well-known target. The account name is randomly generated and rotated. | New in recent updates. Alternative to built-in admin |
| **Enable password backup for DSRM accounts** | Depends on scope: Enabled for DC GPO, Disabled/Not Configured for member GPO | Allows LAPS to also manage and rotate the Directory Services Restore Mode (DSRM) password on Domain Controllers. Useful for securing DC recovery credentials. | Only applies to DCs |
| **Configure size of encrypted password history** | 0 | Number of previously encrypted passwords to retain in AD. Useful for disaster recovery scenarios where you may need an older password. Set to 0 if you don't need history. | Requires encryption enabled |
| **Do not allow password expiration time longer than required by policy** | Enabled | Prevents the password expiration time from being extended beyond the configured maximum age. Ensures that passwords are always rotated within the policy-defined interval, even if someone manually sets a later expiry. | Enforces consistent rotation |
| **Post-authentication actions** | Reset password and logoff | Defines what happens after the LAPS password has been retrieved and used. Options: do nothing, reset password only, reset + logoff, or reset + reboot. Prevents stale admin sessions from lingering. | After admin usage, rotate and kill sessions |
| **Post-authentication reset delay** | 8 hours | Grace period (in hours) after a password is retrieved before the post-authentication action kicks in. Gives the admin time to finish their work before the password is rotated and sessions are terminated. | Grace period after password retrieval |

Recommended deployment model: use two GPOs.

1. One GPO for member devices (workstations and member servers)
2. One dedicated GPO for Domain Controllers (DSRM scenario)

#### Recommended GPO Parameters - Members (Workstations/Member Servers)

Link this GPO to your member-device OUs (for example `OU=Workstations` and `OU=Servers`).

| Setting | Recommended Value |
|---|---|
| **Configure password backup directory** | Active Directory (or Azure AD for cloud-managed devices) |
| **Password Settings** | Complexity: Large + small + numbers + specials, Length: 20+, Age: 30 days |
| **Name of administrator account to manage** | Blank (RID 500) or your managed local admin name |
| **Enable password encryption** | Enabled |
| **Configure authorized password decryptors** | Dedicated group, for example `CONTOSO\LAPS-Password-Readers` |
| **Configure automatic account management** | Optional, based on security baseline |
| **Configure size of encrypted password history** | 0 (or >0 if your recovery process requires history) |
| **Do not allow password expiration time longer than required by policy** | Enabled |
| **Post-authentication actions** | Reset password and logoff |
| **Post-authentication reset delay** | 8 hours |
| **Enable password backup for DSRM accounts** | Disabled or Not Configured |

#### Recommended GPO Parameters - Domain Controllers (DSRM)

Link this dedicated GPO only to `OU=Domain Controllers`.

| Setting | Recommended Value |
|---|---|
| **Configure password backup directory** | Active Directory |
| **Password Settings** | Complexity: Large + small + numbers + specials, Length: 20+, Age aligned with Tier-0 policy |
| **Enable password encryption** | Enabled |
| **Enable password backup for DSRM accounts** | Enabled |
| **Configure size of encrypted password history** | 0 (or according to recovery policy) |
| **Do not allow password expiration time longer than required by policy** | Enabled |
| **Post-authentication actions** | Reset password and logoff |
| **Post-authentication reset delay** | Shorter delay may be required for Tier-0 posture |

Note for DCs: **Configure authorized password decryptors** does not control DSRM secret decryption. For DSRM on DCs, decryption defaults to Domain Admins by design.

#### Quick Matrix - Members vs Domain Controllers

Use this as a practical checklist during design and deployment reviews.

| Parameter | Members (Workstations/Member Servers) | Domain Controllers (DSRM) | Why it matters |
|---|---|---|---|
| **Configure password backup directory** | Active Directory (or Azure AD for cloud-managed devices) | Active Directory | Defines where the secret is stored. For DSRM on DCs, AD is the operational model. |
| **Password Settings** | Strong baseline (20+ chars, full complexity, periodic rotation) | Tier-0 baseline, often stricter rotation window | Aligns password strength and rotation with risk level. |
| **Name of administrator account to manage** | Built-in admin (RID 500) or managed custom local admin | Not typically the main control for DSRM scenario | Clarifies target account scope to avoid policy drift. |
| **Enable password encryption** | Enabled | Enabled | Prevents clear-text exposure in directory attributes. |
| **Configure authorized password decryptors** | Dedicated reader group (or SID/UPN), resolvable by devices | Ignored for DSRM secret decryption | Critical distinction: valid for non-DSRM local admin secrets, not for DSRM on DCs. |
| **Enable password backup for DSRM accounts** | Disabled or Not Configured | Enabled | Avoids unnecessary DSRM behavior on members and activates DSRM management on DCs. |
| **Configure size of encrypted password history** | 0 by default (increase only with recovery need) | 0 or per recovery policy | Balances forensic/recovery needs with data minimization. |
| **Do not allow password expiration time longer than required by policy** | Enabled | Enabled | Enforces maximum age and prevents accidental extension. |
| **Post-authentication actions** | Reset password and logoff | Reset password and logoff | Reduces residual privileged session risk after password retrieval. |
| **Post-authentication reset delay** | Typically 8 hours | Usually shorter for Tier-0 posture | Defines the exposure window after password use. |

> 💡 **Remember**: for DSRM on Domain Controllers, decryption defaults to Domain Admins by design, even if a custom decryptor is configured.

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

### Step 5 — Manage DSRM Password on Domain Controllers

Yes, for DSRM you should apply a GPO to Domain Controllers, not only to workstations.

Important behavior by design:

- The **Configure authorized password decryptors** setting is ignored for DSRM password backup on Domain Controllers.
- In DSRM scenario, decryption defaults to the Domain Admins group of the DC domain.
- So a non-Domain Admin account being unable to decrypt DSRM is expected behavior.
- Delegating DSRM password decryption to non-Domain-Admin accounts isn't supported by design.

Recommended approach:

1. Create a dedicated GPO for DCs (for example `GPO-LAPS-DC-DSRM`)
2. Link it to `OU=Domain Controllers,DC=contoso,DC=com`
3. In that GPO, configure at least:
    - **Configure password backup directory** = Active Directory
    - **Password Settings** = complexity/length/age aligned with Tier-0 standard
    - **Enable password encryption** = Enabled
    - **Enable password backup for DSRM accounts** = Enabled
    - **Do not allow password expiration time longer than required by policy** = Enabled
    - **Post-authentication actions** = Reset password and logoff

For non-DSRM local admin passwords, if you configure **Configure authorized password decryptors**, use one of these formats and do not add quotes or parentheses:

- `contoso\LAPSAdmins`
- `lapsadmins@contoso.com`
- `S-1-5-21-2127521184-1604012920-1887927527-35197`

Then delegate permissions on the Domain Controllers OU:

```powershell
Set-LapsADComputerSelfPermission -Identity "OU=Domain Controllers,DC=contoso,DC=com" -Verbose

Find-LapsADExtendedRights -Identity "OU=Domain Controllers,DC=contoso,DC=com" -Verbose
```

Validation checklist:

1. On a DC, confirm policy application (`gpresult /h`) and verify the LAPS policy values.
2. Trigger policy refresh (`gpupdate /force`) and check `Microsoft-Windows-LAPS/Operational`.
3. Test retrieval and expected access model:

    - DSRM secret decryption: validate with a Domain Admin account
    - Non-DA decryptor groups are valid for non-DSRM local admin password scenarios, not for DSRM on DCs

```powershell
Get-LapsADPassword -Identity "DC01" -AsPlainText
```

Reference: https://go.microsoft.com/fwlink/?linkid=2188435

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

If you already have **Legacy LAPS** (the MSI-based version using `ms-Mcs-AdmPwd`) deployed, here's an important thing to understand: **the Legacy LAPS CSE and Windows LAPS cannot both be active on the same machine at the same time**. If Windows LAPS detects the Legacy CSE (`AdmPwd.dll`) is installed, it **will not manage the password** and defers to the Legacy CSE.

The migration strategy relies on **Windows LAPS emulation mode**: once you **uninstall the Legacy LAPS CSE**, Windows LAPS takes over and — if only a Legacy LAPS GPO is present (no Windows LAPS GPO yet) — it enters **emulation mode**. In this mode, Windows LAPS reads the Legacy GPO settings and writes passwords to the Legacy `ms-Mcs-AdmPwd` attribute, effectively replacing the Legacy CSE with zero disruption.

### Migration Strategy Overview

The migration follows 6 phases. Each phase is designed to be non-disruptive — you can pause, validate, and roll back at each step.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 1: CURRENT STATE                                                │
│  Legacy LAPS CSE (AdmPwd.dll MSI) installed on all machines            │
│  Legacy LAPS GPO active → writes passwords to ms-Mcs-AdmPwd           │
│  Everything works as before — no change yet                            │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 2: PREPARE AD                                                   │
│  Run Update-LapsADSchema → adds ms-LAPS-* attributes to the schema    │
│  Set SELF write permissions on target OUs                              │
│  No impact on machines — Legacy LAPS keeps running normally            │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 3: UNINSTALL LEGACY CSE ON PILOT MACHINES                       │
│  Remove the Legacy LAPS MSI (AdmPwd.dll) from a small group           │
│  Windows LAPS (built into the OS) detects Legacy GPO → enters          │
│  EMULATION MODE: reads Legacy GPO settings, writes to ms-Mcs-AdmPwd   │
│  Same attribute, same permissions, same tools — zero disruption        │
│  ⚠ If CSE is still installed, Windows LAPS will NOT activate!          │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 4: VALIDATE PILOT                                               │
│  Check LAPS event log on pilot machines (Microsoft-Windows-LAPS)       │
│  Verify passwords are being rotated in ms-Mcs-AdmPwd                   │
│  Confirm Get-LapsADPassword works on pilot machines                    │
│  If something is wrong → reinstall Legacy CSE to roll back             │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 5: SWITCH TO NATIVE MODE                                        │
│  Create & link a Windows LAPS GPO (with encryption, post-auth, etc.)   │
│  Grant read/reset permissions to admin group                           │
│  Windows LAPS now uses its OWN GPO → stores passwords in               │
│  msLAPS-EncryptedPassword (encrypted!) instead of ms-Mcs-AdmPwd       │
│  Uninstall Legacy CSE on all remaining machines                        │
│                                                                         │
│  ℹ GPO priority: if BOTH Legacy and Windows LAPS GPOs are applied,     │
│  Windows LAPS ignores the Legacy GPO entirely and uses only its own.   │
│  No conflict — you can safely deploy the Windows LAPS GPO BEFORE       │
│  removing the Legacy GPO.                                              │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  Phase 6: CLEANUP                                                      │
│  Unlink/remove the Legacy LAPS GPO                                     │
│  Clear stale ms-Mcs-AdmPwd values on computer objects                  │
│  (Legacy schema attributes stay — AD schema attributes can't           │
│  be deleted, but values are wiped clean)                               │
│  ✅ Migration complete — fully on Windows LAPS native                  │
└─────────────────────────────────────────────────────────────────────────┘
```

> 💡 **Rollback at any point**: During phases 3-4 (emulation mode), if anything goes wrong, simply reinstall the Legacy LAPS CSE MSI on the affected machines — Legacy LAPS takes back control immediately. During phase 5, if the Windows LAPS GPO causes issues, remove the GPO link and the machines will fall back to emulation mode.

---

### Step 1 — Verify Current Legacy LAPS Deployment

Confirm Legacy LAPS is working and identify the OUs it manages:

```powershell
# Check the Legacy LAPS attributes in AD
Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=contoso,DC=com" `
    -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime, DistinguishedName |
    Select-Object Name,
        @{ Name = 'OU'; Expression = { $_.DistinguishedName -replace '^CN=[^,]+,' } },
        @{ Name = 'Password'; Expression = { if ($_.'ms-Mcs-AdmPwd') { '********' } else { '(none)' } } },
        @{ Name = 'Expiration'; Expression = {
            if ($_.'ms-Mcs-AdmPwdExpirationTime') {
                [datetime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime').ToString('yyyy-MM-dd HH:mm')
            } else { '(never)' }
        }} |
    Sort-Object OU, Name |
    Format-Table -AutoSize
```

Check which machines have the Legacy LAPS CSE installed (the CSE is installed **locally** on each machine, not in SYSVOL):

```powershell
# Local check — run on a single machine
Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"

# Remote check — query multiple machines via PSRemoting
# ⚠ Requires: WinRM/PSRemoting enabled on target machines (Enable-PSRemoting -Force)
# Note: -SearchBase searches recursively (sub-OUs included) by default.
# Excludes Domain Controllers (they don't run the Legacy LAPS CSE)
# Machines that are offline or unreachable will show CSEInstalled = '⚠ Unreachable'
$dcList     = (Get-ADDomainController -Filter *).Name
$adComputers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=contoso,DC=com" `
    -Properties DistinguishedName |
    Where-Object { $_.Name -notin $dcList }
$computers  = $adComputers.Name

# Build OU lookup table (Computer → OU)
$ouLookup = @{}
$adComputers | ForEach-Object {
    $ouLookup[$_.Name] = $_.DistinguishedName -replace '^CN=[^,]+,'
}

$results = Invoke-Command -ComputerName $computers -ScriptBlock {
    [PSCustomObject]@{
        Computer          = $env:COMPUTERNAME
        LegacyCSEInstalled = Test-Path "$env:ProgramFiles\LAPS\CSE\AdmPwd.dll"
    }
} -ErrorAction SilentlyContinue | Select-Object Computer, LegacyCSEInstalled

# Show unreachable machines (offline, no PSRemoting, firewall, etc.)
$reached     = $results.Computer
$unreachable = $computers | Where-Object { $_ -notin $reached }
$unreachable | ForEach-Object {
    $results += [PSCustomObject]@{ Computer = $_; LegacyCSEInstalled = '⚠ Unreachable' }
}

$results |
    Select-Object Computer,
        @{ Name = 'OU'; Expression = { $ouLookup[$_.Computer] } },
        LegacyCSEInstalled |
    Sort-Object OU, Computer |
    ForEach-Object {
        $color = switch ($_.LegacyCSEInstalled) {
            'True'            { '32' }  # Green  — CSE found
            'False'           { '33' }  # Yellow — CSE not found
            '⚠ Unreachable'  { '31' }  # Red    — machine unreachable
            default           { '0'  }
        }
        Write-Host ("{0,-20} {1,-60} " -f $_.Computer, $_.OU) -NoNewline
        Write-Host $_.LegacyCSEInstalled -ForegroundColor ([ConsoleColor]@{
            '32' = 'Green'; '33' = 'Yellow'; '31' = 'Red'; '0' = 'White'
        }[$color])
    }
```

> 💡 **Machines showing "⚠ Unreachable"?** They are either offline, have WinRM/PSRemoting disabled, or are blocked by a firewall. You can alternatively use your software inventory tool (SCCM, Intune, etc.) to report on installed programs matching `*Local Administrator Password Solution*`.

---

### Step 2 — Update the AD Schema for Windows LAPS

If not already done:

```powershell
Import-Module LAPS
Update-LapsADSchema -Verbose
```

This adds the new `msLAPS-*` attributes alongside the existing `ms-Mcs-*` attributes. **No impact on Legacy LAPS**.

---

### Step 3 — Uninstall Legacy LAPS CSE on Pilot Machines

On your pilot machines, **uninstall the Legacy LAPS CSE** (the MSI). This is what triggers emulation mode:

```powershell
# Uninstall Legacy LAPS MSI on a pilot machine (avoid Win32_Product)
$app = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", `
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Local Administrator Password Solution*" } |
    Select-Object -First 1

if ($app -and $app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
    Start-Process msiexec.exe -ArgumentList "/x $($app.PSChildName) /qn" -Wait
    Write-Host "Legacy LAPS CSE uninstalled."
} else {
    Write-Host "Legacy LAPS CSE not found (or non-MSI uninstall metadata)."
}
```

Or use your software deployment tool (SCCM, Intune) to remove it from pilot machines.

> ⚠️ **Important**: Once the Legacy LAPS CSE is **uninstalled**, Windows LAPS (built into the OS since the April 2023 update) automatically takes over. Since no Windows LAPS GPO is configured yet, it enters **emulation mode**: it reads the existing Legacy LAPS GPO settings and writes passwords to the Legacy `ms-Mcs-AdmPwd` attribute. No configuration change is needed — just remove the CSE.

> 💡 **Key point**: If the Legacy CSE is still installed, Windows LAPS will NOT activate. The CSE must be removed first.

---

### Step 4 — Pilot and Validate

On your pilot machines:

1. Ensure the April 2023 (or later) cumulative update is installed
2. Apply the existing Legacy LAPS GPO for emulation validation (or a dedicated pilot native Windows LAPS GPO if you are validating native mode)
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

| Setting | New Value | Description |
|---|---|---|
| **Configure password backup directory** | Active Directory | Switches password storage to AD using the native Windows LAPS attributes (`msLAPS-EncryptedPassword`) instead of the Legacy `ms-Mcs-AdmPwd`. This is the key setting that exits emulation mode. |
| **Enable password encryption** | **Enabled** | Encrypts the stored password with CNG/DPAPI-NG. Only the principal defined in "authorized password decryptors" can read it. Without this, passwords are stored in clear text — strongly recommended. |
| **Configure authorized password decryptors** | `CONTOSO\LAPS-Password-Readers` | Specifies which AD group or user can decrypt the encrypted password. Must match the group that has `Set-LapsADReadPasswordPermission` on the OU. |
| **Password Settings** | Complexity: Large + small + numbers + specials, Length: 20+, Age: 30 days | Defines the password complexity, length, and rotation frequency. Age = how often the password is automatically rotated. A 20+ character password with all character classes is a good baseline. |
| **Configure size of encrypted password history** | 0 | Number of previously encrypted passwords to keep in AD. Useful for disaster recovery. Set to 0 if not needed. |
| **Do not allow password expiration time longer than required by policy** | Enabled | Prevents password expiry from being extended beyond the configured max age. Ensures consistent rotation even if someone manually modifies the expiration. |
| **Post-authentication actions** | Reset password and logoff | What happens after the LAPS password is retrieved and used: reset only, reset + logoff, or reset + reboot. "Reset + logoff" ensures no stale admin session remains after password retrieval. |
| **Post-authentication reset delay** | 8 hours | Grace period (in hours) after a password is retrieved before the post-authentication action triggers. Gives the admin time to finish their work before being logged off and the password rotated. |

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
# Find and uninstall Legacy LAPS MSI (example, avoid Win32_Product)
$app = Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", `
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -like "*Local Administrator Password Solution*" } |
    Select-Object -First 1

if ($app -and $app.PSChildName -match '^\{[0-9A-Fa-f-]+\}$') {
    Start-Process msiexec.exe -ArgumentList "/x $($app.PSChildName) /qn" -Wait
}
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

5. **Remove Legacy LAPS permissions** on OUs (the extended rights for `ms-Mcs-AdmPwd`):

Legacy LAPS delegates two types of permissions via ACEs on the OU: **SELF write** (so computers can update their own password) and **read extended rights** (so admins can read the password). These are standard AD ACEs that must be removed manually.

```powershell
# Target OU (will also scan all sub-OUs recursively)
$rootOU = "DC=contoso,DC=com"
$dryRun = $true   # Set to $false to actually remove the ACEs

# Get the schema GUIDs for Legacy LAPS attributes
$schemaNC   = (Get-ADRootDSE).schemaNamingContext
$guidAdmPwd = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwd" } `
    -Properties schemaIDGUID).schemaIDGUID
$guidExpiry = (Get-ADObject -SearchBase $schemaNC -Filter { name -eq "ms-Mcs-AdmPwdExpirationTime" } `
    -Properties schemaIDGUID).schemaIDGUID

$guidAdmPwdGuid = [Guid]$guidAdmPwd
$guidExpiryGuid = [Guid]$guidExpiry

# Get all OUs under the root (including the root itself)
$allOUs = @($rootOU)
$allOUs += (Get-ADOrganizationalUnit -SearchBase $rootOU -Filter * -SearchScope Subtree).DistinguishedName

$totalDirect = 0; $totalInherited = 0
foreach ($ouDN in $allOUs) {
    $acl = Get-Acl -Path "AD:\$ouDN"

    $legacyACEs = $acl.Access | Where-Object {
        $_.ObjectType -eq $guidAdmPwdGuid -or $_.ObjectType -eq $guidExpiryGuid
    }

    if ($legacyACEs.Count -eq 0) { continue }

    # Separate direct (removable) ACEs from inherited (can only be removed at the source)
    $directACEs    = $legacyACEs | Where-Object { -not $_.IsInherited }
    $inheritedACEs = $legacyACEs | Where-Object { $_.IsInherited }

    if ($directACEs.Count -gt 0) {
        Write-Host "`n [$($directACEs.Count) DIRECT] $ouDN" -ForegroundColor Yellow
        $directACEs |
            Select-Object IdentityReference, AccessControlType, ActiveDirectoryRights,
                @{ Name = 'Attribute'; Expression = {
                    if ($_.ObjectType -eq $guidAdmPwdGuid) { 'ms-Mcs-AdmPwd' }
                    elseif ($_.ObjectType -eq $guidExpiryGuid) { 'ms-Mcs-AdmPwdExpirationTime' }
                    else { $_.ObjectType }
                }} |
            Format-Table -AutoSize

        if (-not $dryRun) {
            $directACEs | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            Set-Acl -Path "AD:\$ouDN" -AclObject $acl
            Write-Host " Removed $($directACEs.Count) ACE(s)" -ForegroundColor Green
        }
        $totalDirect += $directACEs.Count
    }

    if ($inheritedACEs.Count -gt 0) {
        Write-Host "`n [$($inheritedACEs.Count) INHERITED] $ouDN" -ForegroundColor DarkGray
        $totalInherited += $inheritedACEs.Count
    }
}

Write-Host "`n--- Summary ---" -ForegroundColor White
Write-Host "  Direct ACEs (removable):   $totalDirect" -ForegroundColor Yellow
Write-Host "  Inherited ACEs (from parent): $totalInherited" -ForegroundColor DarkGray
if ($totalInherited -gt 0) {
    Write-Host "  Inherited ACEs will disappear automatically once the direct ACEs on the parent OU are removed." -ForegroundColor DarkGray
}

if ($totalDirect -eq 0) {
    Write-Host "`nNo direct Legacy LAPS ACEs found — nothing to remove." -ForegroundColor Green
} elseif ($dryRun) {
    Write-Host "`n[DRY RUN] $totalDirect direct ACE(s) to remove. Set `$dryRun = `$false to apply." -ForegroundColor Cyan
} else {
    Write-Host "`nDone — removed $totalDirect direct Legacy LAPS ACE(s)." -ForegroundColor Green
}
```

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
- **LAPS settings not visible in GPMC**: The `LAPS.admx`/`LAPS.adml` templates are **NOT included** in the standard Microsoft ADMX download. They are delivered only with the April 2023+ update, at `C:\Windows\PolicyDefinitions\LAPS.admx` and `C:\Windows\PolicyDefinitions\en-US\LAPS.adml`. If you use a **Central Store**, you must manually copy these files to `\\domain\SYSVOL\domain\Policies\PolicyDefinitions\`. After copying, reopen GPMC and the settings will appear under **Computer Configuration → Administrative Templates → System → LAPS**.
- **Schema update forgotten**: The `Update-LapsADSchema` must be run before any policy can work against AD.
- **DFL too low for encryption**: Password encryption requires **Windows Server 2016 domain functional level**. Without it, passwords are stored in clear text in the `msLAPS-Password` attribute.
- **Conflicting GPOs**: If both Legacy LAPS GPO and Windows LAPS GPO are applied on a machine **without the Legacy CSE**, there is **no conflict** — Windows LAPS ignores the Legacy GPO and uses only its own. However, you should still clean up the Legacy GPO after migration to avoid confusion. Note: on machines where the **Legacy CSE is still installed**, the CSE processes the Legacy GPO independently, and Windows LAPS won't activate at all.
- **Post-authentication actions not configured**: Without this, a retrieved password stays valid indefinitely until the next scheduled rotation. Always configure post-authentication reset.
- **Wrong OU permissions**: If `Set-LapsADComputerSelfPermission` was not run, computers cannot write their password back to AD and you'll see errors in the event log.

---

## 🧰 Automation Toolkit

An all-in-one interactive PowerShell tool is available in this repository: **`Invoke-LAPSToolkit.ps1`**

Just run it and navigate through the menu:

```powershell
.\Invoke-LAPSToolkit.ps1
```

```
  ┌──────────────────────────────────────────────────────────┐
  │  Main Menu                                               │
  └──────────────────────────────────────────────────────────┘

   [1] Assessment — Full audit of current LAPS state
   [2] Deployment — Deploy Windows LAPS from scratch
   [3] Migration  — Legacy LAPS → Windows LAPS (guided)
   [4] Quick Tools — Password retrieval, rotation, diagnostics
   [5] Exit
```

**Features:**

| Module | What it does |
|---|---|
| **Assessment** | Schema analysis, DFL check, GPO detection, OU permissions audit, full computer inventory with LAPS status, CSV export |
| **Deployment** | Interactive wizard: schema update, OU permissions (SELF + read/reset), GPO creation with best-practice settings, link & validation |
| **Migration** | 5-phase guided migration: Pre-check → Schema & emulation mode → Pilot validation → Switch to native → Legacy cleanup |
| **Quick Tools** | Retrieve passwords, force rotation (local/remote), check LAPS event logs, collect diagnostics, audit OU rights |

The tool detects your current environment state automatically (schema, DFL, LAPS module availability) and displays it on the main screen.

---

## 📚 References

🔗 [Windows LAPS Overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
🔗 [Get Started with Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-windows-server-active-directory)
🔗 [Windows LAPS with Entra ID](https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords)
🔗 [Migrate from Legacy LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-scenarios-legacy)
🔗 [Windows LAPS CSP (Intune)](https://learn.microsoft.com/en-us/windows/client-management/mdm/laps-csp)
🔗 [Windows LAPS Troubleshooting](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-troubleshooting)

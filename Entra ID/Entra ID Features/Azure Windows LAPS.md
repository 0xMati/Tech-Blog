# Windows LAPS: Modern Local Administrator Password Solution
🗓️ Published: 2024-06-11

---

## 1. Introduction

**Windows Local Administrator Password Solution (LAPS)** is the new generation of Microsoft’s LAPS, built directly into Windows. It replaces the older **Legacy LAPS** (separate MSI) and offers extended capabilities to protect local admin accounts and, optionally, the DSRM password on domain controllers.

> **Context**:  
> - Avoid pass-the-hash and reduce lateral movement  
> - Enforce unique, periodically refreshed admin passwords  
> - Manage hybrid environments (AD or Azure AD) under a single approach

---

## 2. New Features and Improvements

![](Azure%20Windows%20LAPS/2025-04-08-13-35-55.png)


### 2.1 AD or Azure AD Storage
- Passwords can be stored in **on-prem AD** (domain-joined), **Azure AD** (Azure AD-joined), or **both** for hybrid-joined devices.  
- Support for the **DSRM password** on domain controllers (optional).

### 2.2 Enhanced Password Security
- **DPAPI encryption** (no longer plain text).  
- **Password history** helps retrieve older passwords (useful when restoring a machine to a previous state).  
- **Managed via GPO or MDM**— Windows-native policy settings.

### 2.3 Post-Authentication Actions
- Option to **auto-reset** the local admin password after it’s used.  
- **Auto-reboot** the device to clear traces if needed.

### 2.4 Built-In Integration
- **Windows LAPS** is shipped with Windows (April 2023 updates and onward).  
- No separate MSI install required (unlike Legacy LAPS).

---

## 3. Configuration and Deployment

### 3.1 Requirements
- **Windows 10/11**, **Windows Server 2019/2022**  
- **Domain Functional Level** at least Windows Server 2016  
- For Azure AD storage, ensure you have a **proper Azure AD** environment in place.

### 3.2 Configuring via Group Policy
1. **Enable** Windows LAPS through GPO  
   - Path: `Computer Configuration > Administrative Templates > System > LAPS`
2. **Set** password rotation interval, encryption, history, and so on.
3. **Apply** the GPO to target OUs or devices.

(_Here you can insert your screenshots, e.g._ `![GPO Settings - Windows LAPS](path/to/laps-gpo.png)`)

### 3.3 New AD Schema Attributes
- `msLAPS-Password` (plain text password)  
- `msLAPS-EncryptedPassword`, `msLAPS-EncryptedPasswordHistory`  
- `msLAPS-EncryptedDSRMPassword`, and more

> **Important**: An **AD schema update** is required to add these attributes.

### 3.4 Monitoring and Management
- **Dedicated event log**: `Applications and Services > Microsoft > Windows > LAPS > Operational`  
- **New ADUC tab** to view or reset the password on a computer account.  
- **PowerShell module** (`LAPS`) for scripting and automation (read, reset, configure policies).

---

## 4. Migration from Legacy LAPS

1. **Update the AD schema** for Windows LAPS attributes.  
2. **Run** Windows LAPS in **emulation mode**:
   - It manages the old attributes (`ms-Mcs-AdmPwd…`) **if Legacy LAPS is not installed**.
   - You won’t get new Windows LAPS features (encryption, DSRM, etc.) in emulation mode.
3. **Uninstall Legacy LAPS** and gradually enable Windows LAPS policies.
4. **Move** test machines to the full Windows LAPS approach (with the appropriate GPO).
5. **Roll out** to production OUs.

(_Include a detailed step-by-step plan if needed._)

---

## 5. Key Points and Best Practices

- **Avoid mixing** full Windows LAPS and Legacy LAPS on the same machine.  
- **Rotate** local admin passwords at reasonable intervals (e.g., 30 days).  
- **Restrict** read/write permissions on LAPS attributes in AD (proper ACLs).  
- **Monitor** the LAPS event log for errors or suspicious activity.

---

## 6. References and Useful Links

1. [“By popular demand: Windows LAPS available now!”](https://aka.ms/WindowsLAPSAnnouncement)  
2. [Windows LAPS setup in Windows Server AD](https://aka.ms/WindowsLAPS-ADSetup)  
3. [Windows LAPS setup in Azure AD](https://aka.ms/WindowsLAPS-AzureSetup)  
4. [Migrating from Legacy LAPS to Windows LAPS](https://aka.ms/WindowsLAPS-LegacyMigration)

(Feel free to add internal links or additional resources as needed.)

---

## 7. Conclusion

**Windows LAPS** provides stronger security and richer functionality compared to Legacy LAPS, and it’s natively built into Windows for **on-prem** or **hybrid/cloud** use. Overall, it’s a step forward in **hardening** your servers and endpoints.

---

### Special Thanks

A special thank-you to **Didier Gautier** for his support and contributions to this presentation.

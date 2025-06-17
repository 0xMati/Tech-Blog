## Enable auditing of LDAP binds and queries via the Windows Registry
🗓️ Published: 2025-06-17

To diagnose and secure your Active Directory infrastructure, you can enable on the Domain Controller side detailed logging of **all** LDAP connections (binds) and LDAP operations (SearchRequest, Add/Modify/Delete, etc.) using registry keys. Here's how:

---

### 1. NTDS Diagnostics settings location

All LDAP diagnostics are configured under the following registry key:

```
HKEY_LOCAL_MACHINE
 └─ SYSTEM
    └─ CurrentControlSet
       └─ Services
          └─ NTDS
             └─ Diagnostics
```

In this key, two DWORD values are of particular interest:

| Value name                        | Category number | Description                                                                           |
|-----------------------------------|-----------------|---------------------------------------------------------------------------------------|
| **15 Field Engineering Events**   | 15              | Field Engineering events (advanced configuration and troubleshooting logs)           |
| **16 LDAP Interface Events**      | 16              | Detailed logs of **all** LDAP operations (bind, search, controls, etc.)               |

---

### 2. Enable Field Engineering (Category 15)

1. Open **Regedit** (Start → `regedit.exe`).  
2. Navigate to `HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`.  
3. Create or modify the DWORD named `15 Field Engineering Events`:  
   - **Type**: `REG_DWORD`  
   - **Value data**:  
     - `0` → Off (default)  
     - `1` → Errors only  
     - `2` → Warnings  
     - **`5` → Verbose (log everything)**  
4. Restart the **Active Directory Domain Services** service (or reboot the DC).

> **Use case**: Category 15 is enabled to capture configuration events, referrals, redirections, or internal AD engine errors, without detailing each LDAP request.

---

### 3. Enable LDAP Interface Logging (Category 16)

1. In the same `NTDS\Diagnostics` key, create or modify the DWORD `16 LDAP Interface Events`:  
   - **Type**: `REG_DWORD`  
   - **Value data**:  
     - `0` → Off  
     - `1` → Errors only  
     - `2` → Warnings  
     - **`5` → Verbose (log everything)**  
2. Also restart the **Active Directory Domain Services** service.

> **Use case**: Category 16 in verbose mode logs every LDAP operation on ports 389/636 – SearchRequest, Bind (simple or SASL), Add/Modify/Delete, including filters, returned attributes, and controls (DirSync, paged-results, etc.).

---

### 4. Where to view the logs?

- **Event Viewer** → **Applications and Services Logs** → **Directory Service**  
- Event IDs:  
  - **1644** → `LDAP Bind`  
  - **1645–1649** → `SearchRequest`, `ModifyRequest`, `AddRequest`, etc.  
  - At verbose level, you'll see additional detail.

![](assets/Audit%20LDAP%20Binds%20and%20Queries%20with%20Regedit/2025-06-17-15-04-21.png)
---

### 5. Difference between Category 15 and Category 16

| Criterion                        | Category 15 (Field Engineering)         | Category 16 (LDAP Interface)                              |
|----------------------------------|-----------------------------------------|------------------------------------------------------------|
| **Purpose**                      | Internal diagnostics & advanced errors  | Exhaustive logging of all LDAP operations                  |
| **Event types**                  | Referrals, redirections, engine errors  | Query, Bind, Add/Modify/Delete, controls, filters, etc.   |
| **Data volume**                  | Moderate                                | Very high (potentially thousands of events/hour)           |
| **Recommended usage**            | Bug troubleshooting, Microsoft support  | Audit, troubleshooting, compliance, and forensic analysis  |

---

#### Example PowerShell script for GPO startup to deploy these values

```powershell
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
  -Name '15 Field Engineering Events'    -PropertyType DWord -Value 5 -Force
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
  -Name '16 LDAP Interface Events'       -PropertyType DWord -Value 5 -Force

Restart-Service ntds -Force
```

---

> **Caution**:  
> - In verbose mode, the **Directory Service** log can grow very quickly. Plan for log rotation or forward to a SIEM.  
> - To distinguish LDAP simple binds vs LDAPS, filter by port or monitor **Event ID 1641** (SSL bind).

---

With this configuration, you will have a complete record of all LDAP connections and queries to your domain controllers.

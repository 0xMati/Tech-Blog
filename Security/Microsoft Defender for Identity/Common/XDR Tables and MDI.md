# Microsoft Defender for Identity and the XDR Advanced Hunting tables
🗓️ Published: 2025-12-04

When you deploy **Microsoft Defender for Identity (MDI)**, it doesn’t just raise alerts in the portal.  
It also feeds several **Advanced Hunting** tables in Microsoft Defender XDR, and optionally Microsoft Sentinel.

This document provides:

- A **complete list of XDR tables** populated by MDI  
- What each table contains  
- Example KQL queries  
- A clear section on **data retention** across XDR and Sentinel  

---

# 🔥 Complete list of XDR tables populated by Microsoft Defender for Identity

| Table | Description | Populated by MDI |
|-------|-------------|------------------|
| **IdentityLogonEvents** | Authentication activity (Kerberos, NTLM, logon failures, etc.) | ✅ Yes |
| **IdentityDirectoryEvents** | Directory changes (password updates, UPN changes, group changes, DC system events) | ✅ Yes |
| **IdentityQueryEvents** | LDAP queries and AD reconnaissance | ✅ Yes |
| **IdentitySensitiveGroupMembershipEvents** | Privileged group membership events | ⚠️ Yes (subset) |
| **IdentityInfo** | Unified identity inventory (MDI + Entra ID + Sentinel UEBA) | ⚠️ Partially |
| **IdentityEvents** (Preview) | Third‑party IdP events (Okta, etc.) via MDI | ⚠️ If configured |
| **AlertInfo** | Alerts from all Defender products, including MDI | ⚠️ Indirect |
| **AlertEvidence** | Entities involved in alerts | ⚠️ Indirect |
| **IdentityRecommendation** | Identity hygiene and posture findings | ⚠️ Yes |
| **AlertsInfo** (Sentinel variant) | Same concept as AlertInfo | ⚠️ Indirect |

---

# 📘 Table details

## IdentityLogonEvents

Authentication telemetry observed on domain controllers.

**What you see**
- Kerberos & NTLM authentications  
- Logon types & results  
- Authentication failures (bad password, disabled account, etc.)

**Example KQL**
```kql
IdentityLogonEvents
| where Timestamp > ago(1d)
| where FailureReason has "Bad password"
| summarize Attempts = count() by AccountUpn, IPAddress
```

---

## IdentityDirectoryEvents

Directory operations and selected DC system activity.

**What you see**
- Password or UPN changes  
- Account creation / modification  
- Group membership changes  
- Scheduled tasks, PowerShell, and system activities on DCs  

**Example KQL**
```kql
IdentityDirectoryEvents
| where ActionType in ("GroupMembershipChange", "UserAccountCreated")
| project Timestamp, ActionType, TargetAccountUpn, TargetGroupName
```

---

## IdentityQueryEvents

LDAP reconnaissance detection.

**What you see**
- Who queried AD  
- Which objects were queried  
- Indicators of enumeration and lateral movement  

**Example KQL**
```kql
IdentityQueryEvents
| where ActionType startswith "LDAP"
| where QueryTarget has_any ("Domain Admins","Enterprise Admins")
```

---

## IdentitySensitiveGroupMembershipEvents

Tracks membership operations in privileged groups such as:
- Domain Admins  
- Enterprise Admins  
- Schema Admins  
- Administrators  

**Example KQL**
```kql
IdentitySensitiveGroupMembershipEvents
| where Timestamp > ago(7d)
| project Timestamp, TargetGroupName, TargetAccountUpn, ActionType
```

---

## IdentityInfo

A unified identity inventory combining:
- On‑prem accounts via MDI  
- Cloud accounts via Entra ID  
- Behavioral insights via Sentinel UEBA  

**Example KQL**
```kql
IdentityInfo
| where AccountType == "User"
| project Identity, AccountSid, IdentityEnvironment, RiskLevel
```

---

## IdentityEvents (Preview)

Populated only when MDI ingests events from **third‑party IdPs** such as Okta.

---

## AlertInfo & AlertEvidence

All alerts raised by MDI (and other Defender products) appear in:
- `AlertInfo` (alert metadata)
- `AlertEvidence` (users, devices, IPs associated with alerts)

**Example KQL**
```kql
AlertInfo
| where ServiceSource == "Microsoft Defender for Identity"
| project Timestamp, AlertId, Title, Severity, Category
```

---

## IdentityRecommendation

Identity hygiene & posture findings, including:
- Weak configurations  
- Misconfigurations in AD  
- Risky accounts  
- Outdated domain controller settings  

---

# 🕒 Data Retention

## Defender XDR / Advanced Hunting

| Scope                                                 | Retention Period      | Configurable | Where Data Is Accessible                   | Explanation                                                                                                                            | Practical Example                                                                                                         |
| ----------------------------------------------------- | --------------------- | ------------ | ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **MDI / Microsoft Defender XDR Console**              | **30 days (fixed)**   | ❌ No         | MDI portal, Defender XDR, Advanced Hunting | MDI signals are retained for 30 days only inside the Defender platform. This retention is hard-coded and cannot be extended.           | An attacker performed lateral movement 45 days ago → the activity is **no longer visible** in the MDI or Defender portal. |
| **Microsoft Sentinel (Analytics / Hot tier)**         | **90 days (default)** | ✅ Yes        | Sentinel (Log Analytics, KQL)              | When MDI is connected to Sentinel, its signals are ingested into Log Analytics. By default, Sentinel keeps analytics data for 90 days. | An NTLM relay detected by MDI 60 days ago → no longer visible in MDI, but **still queryable in Sentinel**.                |
| **Microsoft Sentinel (Extended Analytics Retention)** | **Up to 730 days**    | ✅ Yes (paid) | Sentinel (Log Analytics)                   | Analytics retention can be extended beyond 90 days to support long-term investigations, at additional cost.                            | A security team investigates a compromise from 6 months ago → data is **still available in Sentinel KQL**.                |
| **Microsoft Sentinel Archive / Data Lake**            | **Years**             | ✅ Yes        | Archive tier / Data Lake                   | Data can be archived for multi-year retention at lower cost. Queries require restore or archive search, and are not real-time.         | A compliance audit requires identity activity from 2 years ago → data is **retrieved from archive storage**.              |

All Identity\* tables follow this retention window.  
**MDI does not control retention — XDR does.**



---

## Microsoft Sentinel (Log Analytics Workspace)

If XDR data is also forwarded into Sentinel:

- Workspace retention: **30 to 730+ days**
- Per‑table retention: **customizable**
- Controlled entirely by **your Sentinel workspace settings**

This means:
> A table like `IdentityLogonEvents` may have **30 days in XDR** but **1 year in Sentinel**.

---

# ✅ Summary

MDI populates the following XDR tables:

### **Telemetry**
- `IdentityLogonEvents`  
- `IdentityDirectoryEvents`  
- `IdentityQueryEvents`  
- `IdentitySensitiveGroupMembershipEvents`  
- `IdentityEvents` (when enabled)

### **Context**
- `IdentityInfo`

### **Alerts**
- `AlertInfo`  
- `AlertEvidence`

### **Hygiene**
- `IdentityRecommendation`

Together, these provide the core dataset for identity threat hunting across hybrid AD environments.

---

_Last updated: December 2025_

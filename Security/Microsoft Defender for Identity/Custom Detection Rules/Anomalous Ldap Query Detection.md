# MDI Custom Detection – Anomalous LDAP Query Detection  
🗓️ Published: 2024-03-22  

---

## 💍 Rule Description

Adversaries can use LDAP to collect environment information. This detection aims to highlight **anomalous volumes of LDAP queries** originating from a single device.

The detection establishes a **baseline** of LDAP activity per device and identifies anomalies that deviate from that norm. It helps surface devices performing unexpected LDAP queries — a potential sign of reconnaissance.

Key parameters:
- `starttime`: Start of the time window (default: 30d)
- `endtime`: End of the time window (default: 1d)
- `timeframe`: Query grouping interval (default: 1h)
- `TotalEventsThreshold`: Minimum number of events for a device to be included

> ℹ️ Only **workstations** are included by default. Remove the filtering line to include **servers** as well.

---

## ⚠️ Risk Analysis

- **Reconnaissance Activity**  
  An attacker may use LDAP to gather information about users and systems.  
- **Stealthy Lateral Movement Prep**  
  This often precedes lateral movement or privilege escalation.  
- **Baseline Evasion**  
  By slowly querying over time, attackers hope to avoid detection — baselining helps spot that.

---

## ⚙️ Detection Logic (KQL Query)

```sql
let starttime = 30d;
let endtime = 1d;
let timeframe = 1h;
let TotalEventsThreshold = 1;

let Workstations = DeviceInfo
    | where Timestamp > ago(30d)
    | where DeviceType == "Workstation"
    | distinct DeviceName;

let TimeSeriesData = IdentityQueryEvents
    | where ActionType == "LDAP query"
    | where DeviceName in~ (Workstations)
    | make-series PerHourCount=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(endtime)) step timeframe by DeviceName;

let TimeSeriesAlerts = TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit')
    | mv-expand
        PerHourCount to typeof(double),
        Timestamp to typeof(datetime),
        anomalies to typeof(double),
        score to typeof(double),
        baseline to typeof(long);

TimeSeriesAlerts
| where anomalies > 0
| project DeviceName, Timestamp, PerHourCount, baseline, anomalies, score
| where PerHourCount > TotalEventsThreshold
```

---

## 🛠️ Recommended Actions

### 🔍 1. Investigate high-volume LDAP sources  
Look for workstations or devices issuing large volumes of LDAP queries.

### 🧪 2. Run targeted queries on suspicious devices  
Use follow-up queries such as:
```kusto
// Replace with actual device name
IdentityQueryEvents
| where DeviceName == "suspicious-device"
| where ActionType == "LDAP query"
```

### 🔐 3. Harden and monitor LDAP access  
- Restrict LDAP access where possible
- Monitor for enumeration patterns
- Combine with behavioral analytics for broader visibility

---

## 💎 References

- [Original detection rule](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/AnomalousLDAPTraffic.md)  
- [MITRE ATT&CK T1087.002 – Account Discovery](https://attack.mitre.org/techniques/T1087/002/)  
- [Microsoft blog – Nobelium toolset](https://www.microsoft.com/en-us/security/blog/2021/05/28/breaking-down-nobeliums-latest-early-stage-toolset/)

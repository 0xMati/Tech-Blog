# MDI Custom Detection Rule – Anomalous Group Policy Discovery
🗓️ Published: 2025-02-20

---

**Time:** 1:42 PM  
**MITRE Technique:** [T1615 – Group Policy Discovery](https://attack.mitre.org/techniques/T1615)

---

## 💍 Rule Description

Adversaries may gather information on Group Policy settings to:
- Identify paths for privilege escalation
- Analyze security measures within a domain
- Detect patterns in domain objects that can be manipulated or help blend into the environment

Group policies may contain **valuable information** for an attacker.  
This query detects when a device performs **Group Policy Discovery** for the first time in **30 days**.

> ⚠️ **False Positive**: A new administrator or freshly rebuilt machine may also trigger this detection.

---

## ⚠️ Risk Analysis

- **Reconnaissance Activity**  
  An attacker queries Group Policy objects to map out security controls, access restrictions, and escalation paths.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
let PreviousActivity = materialize (
    IdentityQueryEvents
    | where Timestamp > ago(30d)
    | where QueryType == "AllGroupPolicies"
    | summarize make_set(DeviceName)
);

IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType == "AllGroupPolicies"
| where not(DeviceName has_any(PreviousActivity))
```

---

## 🛠️ Recommended Actions

1. **Verify the Device & User**
   - Has this system recently been deployed or rebuilt?
   - Is the user performing expected IT operations?

2. **Check for Lateral Movement or Initial Access**
   - Was this action preceded by unusual authentications?

3. **Correlate with Group Modification Events**
   - If combined with GPO changes or privilege assignment, treat as high risk.

4. **Triage the Context**
   - Investigate whether this device has performed this action before.

---

## 💎 References

- [MITRE T1615 – Group Policy Discovery](https://attack.mitre.org/techniques/T1615)
- [Original Detection Rule](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/AnomalousGroupPolicyDiscovery.md)

---

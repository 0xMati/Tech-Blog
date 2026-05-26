---
title: "Suspicious Actions on Entra ID Connect"
date: 2025-04-24
categories: ["Suspicious activity"]
---

## Suspicious Actions on Entra ID Connect

This custom query helps identify potentially suspicious behavior originating from Entra ID Connect servers. These servers are often privileged and represent a critical point of trust in hybrid identity environments, making them a high-value target for attackers.

---

### Detection Logic (KQL Query)

```kql
IdentityDirectoryEvents 
| where DeviceName in~ ('entraIDConnectServer.contoso.com', 'entraIDConnectServerStaging.contoso.com')
| where ActionType in (
    "Entra Connect password writeback failed",
    "PowerShell execution",
    "Service creation",
    "Task scheduling",
    "Wmi execution"
)
```

---

### ⚠️ Risk Analysis

- **Credential compromise attempts**: The `"Entra Connect password writeback failed"` may indicate a failed attempt to change a password, potentially as part of an account takeover.
- **Remote execution risks**: The presence of `Remote PowerShell`, `Remote WMI`, `Remote Service creation`, or `Remote Task scheduling` actions on a sensitive identity infrastructure server may indicate:
  - Malicious lateral movement
  - Persistence mechanisms being deployed
  - Initial steps in a broader compromise

---

### Recommended Actions

1. **Investigate all triggering events** on Entra ID Connect Servers to verify if the activities are legitimate or suspicious.
2. **Correlate with other logs**, such as DeviceProcessEvents or network logs, to look for indicators of compromise.
3. **Harden Entra ID Connect servers** by:
   - Enforcing just-in-time access
   - Enabling audit logging
   - Restricting interactive logons

---

### 📚 References

- [Monitoring Entra ID activity](https://learn.microsoft.com/en-us/entra/identity/monitoring-health)


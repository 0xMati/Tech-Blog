# MDI Custom Detection Rule – PowerShell Execution
🗓️ Published: 2024-04-09

---

## 💍 Rule Description

This custom detection rule identifies **PowerShell execution events** in your environment. It focuses on **suspicious or unauthorized usage** of PowerShell, which is often a vector for lateral movement, credential dumping, or malicious scripts.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == @"PowerShell execution"
| extend Command = todynamic(AdditionalFields)["PowerShell execution"]
| project Timestamp, ReportId, DeviceName, IPAddress, DestinationDeviceName, AccountName, AccountDomain, Command
```

### 🔖 Remarks on Filtering
- You can **add filters** to exclude legitimate traffic (e.g., known admin scripts, DC-to-DC traffic).
- Correlate the **source machine/IP** with your asset inventory to confirm if it’s managed and legitimate.
- Review the actual **PowerShell command** in `Command`; look for signs of credential dumping, suspicious script blocks, etc.
- If a specific user is identified, confirm with them whether the activity is legitimate or unexpected.

Add any other filters in the query to reduce false positives based on your environment needs.

---

## ⚠️ Risk Analysis

- **Privilege Escalation & Lateral Movement**
  Attackers frequently use PowerShell to run malicious scripts, exfiltrate data, or pivot across servers.

- **Credential Theft**
  Malicious PowerShell commands can harvest stored credentials from memory or run Mimikatz modules.

- **Persistence**
  Advanced scripts can create scheduled tasks, WMI events, or manipulate registry keys to maintain footholds.

---

## 🛠️ Recommended Actions

1. **Review the Command**
   Check if the command lines are legitimate admin scripts or suspicious.
2. **Investigate the Source Host**
   - Is it a managed server or workstation?
   - Cross-check the IP address or device name in your CMDB (Configuration Management Database).
3. **Validate the User**
   Confirm if the user account belongs to an authorized admin. If unclear, perform a thorough review of user activity.
4. **Implement Script Block Logging**
   Use advanced logging or AMSI integration to see the full script content, not just the execution event.
5. **Contain or Block**
   If suspicious, isolate the machine and reset the account passwords.
6. **Add KQL Filters**
   Exclude known hosts or legitimate service accounts to reduce noise.

---

## 💎 References

- [Microsoft Documentation – Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/)
- [PowerShell Security Best Practices](https://learn.microsoft.com/en-us/powershell/scripting/security/)
- [Common Attack Techniques with PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

### Source

```
From the original document:
https://github.com/DanielpFR/MDI
```

> _Use this detection as part of a broader security strategy, combining identity detection, endpoint monitoring, and access control policies._

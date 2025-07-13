# MDI Custom Detection – Suspicious SMB File Copy  
🗓️ Published: 2025-04-08  

---

## Description

This custom detection rule helps identify **SMB file copies** performed by accounts that are **not whitelisted**.  
Adversaries may abuse SMB to transfer tools, payloads, or staging files to remote machines as part of lateral movement or post-exploitation steps.

This detection is inspired by real-world attack techniques such as **T1021.002 – Remote Services: SMB/Windows Admin Shares** ([MITRE link](https://attack.mitre.org/techniques/T1021/002)).

> A common technique is to upload malicious files to remote hosts using SMB. In most environments, such behavior is rare and should be audited when it originates from unexpected sources.

---

## ⚠️ Risk Analysis

- **Malware Propagation**  
  Malicious actors may use SMB shares to distribute malware to other systems.

- **Data Exfiltration**  
  Files copied to or from sensitive systems (like domain controllers) may indicate data theft or reconnaissance.

- **Legitimate Admin Activity**  
  False positives can occur if IT administrators regularly transfer files — these accounts should be added to the whitelist.

---

## Detection Logic (KQL Query)

```kql
let WhitelistedAccounts = dynamic(['account1', 'account2']);
IdentityDirectoryEvents
| where ActionType == 'SMB file copy'
| where not(AccountName has_any (WhitelistedAccounts))
| extend 
     SMBFileCopyCount = parse_json(AdditionalFields).Count,
     FilePath = parse_json(AdditionalFields).FilePath,
     FileName = parse_json(AdditionalFields).FileName
| project-rename SourceDeviceName = DeviceName
| project-reorder
     Timestamp,
     ActionType,
     SourceDeviceName,
     DestinationDeviceName,
     FilePath,
     FileName,
     SMBFileCopyCount
```

---

## Recommended Actions

- **Audit the source device and user** to determine if the file transfer was legitimate.
- **Correlate with login activity** to check for unexpected locations or times.
- **Update your whitelist** to include known admin or backup service accounts.
- **Consider alerting or blocking** untrusted accounts attempting SMB file transfers to critical infrastructure.

---

## 📎 References

- [Original Detection Rule](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/SMBFileCopy.md)
- [MITRE T1021.002 – Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)
- [Microsoft Defender for Identity documentation](https://learn.microsoft.com/en-us/defender-for-identity/)

---

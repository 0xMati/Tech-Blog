# MDI Custom Detection – Suspicious SMB File Copy to Domain Controllers  
🗓️ Published: 2024-03-22  

---

## 💍 Rule Description

It is generally **not recommended** to use **Domain Controllers as file servers**. Therefore, **file copies over SMB** from workstations or member servers to DCs should be rare and suspicious.

This detection identifies SMB file copy activity where the destination is a domain controller. It looks specifically for **"Write" operations**, which indicate that a file has been copied.

This type of behavior may signal **credential theft**, **lateral movement**, or **payload staging** by an adversary.

> ℹ️ This rule assumes DCs are not acting as file servers. If they are, adjust or suppress known safe flows accordingly.

---

## ⚠️ Risk Analysis

- **Unauthorized file transfers to sensitive systems**  
- **Potential exfiltration or staging on DCs**  
- **Abuse of SMB protocol for lateral movement or persistence**

---

## ⚙️ Detection Logic (KQL Query)

```sql
IdentityDirectoryEvents
| where ActionType == @"SMB file copy"
| extend ParsedFields = parse_json(AdditionalFields)
| project
    Timestamp,
    ReportId,
    ActionType,
    DeviceName,
    IPAddress,
    AccountDisplayName,
    DestinationDeviceName,
    DestinationPort,
    FileName = tostring(ParsedFields.FileName),
    FilePath = tostring(ParsedFields.FilePath),
    Method = tostring(ParsedFields.Method)
| where Method == @"Write"
```

---

## 🚫 With Whitelist (Optional)

To suppress known safe accounts from alerting:

```kusto
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

## 🛠️ Recommended Actions

- Investigate any SMB file copy activity to DCs
- Confirm if the action was legitimate or part of an attack sequence
- Review account privileges and access history
- Harden DC shares and disable SMB write access where not needed

---

## 💎 References

- MITRE ATT&CK reference: [T1021.002 – SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/)  
- [Microsoft security guidance on DC hardening](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/ad-security-best-practices)
- Original Source, thanks to : https://github.com/DanielpFR/MDI
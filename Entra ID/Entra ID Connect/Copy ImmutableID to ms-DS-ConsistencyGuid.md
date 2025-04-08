# Azure AD Connect – Copy ImmutableID to On-Prem ConsistencyGuid  
🗓️ Published: 2021-02-05  

---

## 💍 Description

This script is used to **synchronize the Azure AD `ImmutableID`** value into the **on-prem Active Directory `ms-DS-ConsistencyGuid`** attribute. It is typically executed **when changing the anchor** used by Azure AD Connect from `ObjectGUID` to `ms-DS-ConsistencyGuid`.

This is often required during **AAD Connect migrations**, or when aligning existing objects for hybrid join scenarios.

The script covers:
- User accounts across multiple OUs (EN, FR, US, NC)
- Azure AD Groups (Office 365 groups)
- Logging for trace, errors, updates, backups
- Alert email generation

---

## ⚙️ Features

- Reads on-prem accounts from various OUs
- Converts ObjectGUID to base64 (ImmutableID format)
- Writes value into `ms-DS-ConsistencyGuid` if empty or mismatched
- Logs:
  - Trace file
  - Error file
  - Update log
  - Backup file
  - System error log
- Email alert with logs as attachments

---

## ✅ Verification Points

- The script properly checks whether `ms-DS-ConsistencyGuid` is already set
- If the existing value matches, no changes are made
- If the value differs, it is flagged as inconsistent (and not overwritten automatically)
- Errors are logged and counted
- SMTP config and mail alert logic are working and customizable

---

## 📎 Script Entry Points

- Loop through predefined OUs: `EN`, `FR`, `US`, `NC`
- For each user:
  - Fetch `ObjectGUID`
  - Convert to base64 as ImmutableID
  - Compare with existing `ms-DS-ConsistencyGuid`
  - Update if null, log otherwise
- Same process applied to Office 365 groups

---

## 📬 Email Alert Behavior

If any errors are detected during processing:
- The email subject includes **KO** status
- Else, subject indicates **OK** status

Logs are attached to help admins review the processing status.

---

## 🛠️ Recommendations

- Test on a sample OU before applying to all environments
- Ensure `ms-DS-ConsistencyGuid` is not in use before script runs
- Backup AD objects or log snapshots before write operations
- Adapt SMTP and OU paths to your environment

---

## 💡 Notes

- Script assumes PowerShell modules `ActiveDirectory` and `AzureAD` are available
- The logic is defensive: it doesn't overwrite mismatched GUIDs automatically — logs instead
- Logging and alerting can be centralized with a monitoring system (e.g., SCOM, Splunk)

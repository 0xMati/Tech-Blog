# MDI Custom Detection Rule – Account with Password Never Expires  
🗓️ Published: 2024-03-22  

---

## 💍 Rule Description

In Windows, an account password can be set to **never expire**, which is generally **not recommended**.  
Best practices require periodic password changes to reduce the risk of credential compromise.

This rule detects when a user account is modified so that **"Account Password Never Expires"** is enabled.

---

## ⚠️ Risk Analysis

- **Weak Security Posture**  
  Accounts with non-expiring passwords are attractive targets for attackers.  
- **Increased Brute Force Risk**  
  If the password is weak and never changes, brute-force attacks become more effective.  
- **Compliance Issues**  
  Many security frameworks (ISO 27001, NIST, CIS) recommend password expiration policies.

---

## ⚙️ Detection Logic (KQL Query)

```sql
IdentityDirectoryEvents
| where ActionType == "Account Password Never Expires changed"
| extend AdditionalInfo = parse_json(AdditionalFields)
| extend OriginalValue = AdditionalInfo.['FROM Account Password Never Expires']
| extend NewValue = AdditionalInfo.['TO Account Password Never Expires']
| where NewValue == true
| project
     Timestamp,
     TargetAccountUpn,
     AccountDomain,
     OriginalValue,
     NewValue,
     ReportId,
     DeviceName
```

---

## 🛠️ Recommended Actions

### 🔎 1. Audit all accounts with non-expiring passwords  
Run the following PowerShell command to list accounts where the **"Password Never Expires"** setting is enabled:  

```powershell
Get-ADUser -Filter * | Where-Object { $_.PasswordNeverExpires }
```

### 🚫 2. Enforce password expiration policies  
- **Active Directory (on-premises)**: Configure Group Policy (GPO) to set a **maximum password age**.  
- **Azure AD**: Use **Conditional Access** policies to enforce periodic password changes.

### 🔒 3. Use Multi-Factor Authentication (MFA) and strong password policies  
- Require **MFA** for high-privilege accounts.  
- Enforce **password length and complexity rules** to reduce brute force risks.  

---

## 💎 References

- [Original detection rule](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/AccountWithPasswordNeverExpiresEnabled.md)  
- [Microsoft Security Best Practices](https://learn.microsoft.com/en-us/security/)  
- [Azure AD Conditional Access Policies](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/overview)  
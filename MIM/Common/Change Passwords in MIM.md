# Rotating All Service Account Passwords in Microsoft Identity Manager (MIM)
🗓️ Published: 2025-05-06

Rotating service account passwords in a Microsoft Identity Manager (MIM) 2016 environment is a sensitive yet essential maintenance task. This article provides a step-by-step guide to perform the rotation and outlines the potential impacts to anticipate.

---

## ⚙️ Step-by-Step Procedure

### Identify All Service Accounts
Start by identifying all service accounts used in the MIM infrastructure:

| Component                          | Typical Account Name             |
|-----------------------------------|----------------------------------|
| MIM Sync Service                  | `DOMAIN\MIMSync`                 |
| MIM Service (FIMService)          | `DOMAIN\MIMService`              |
| MIM Portal (IIS App Pool)         | `DOMAIN\MIMSPortal` |
| SQL Server (if using Windows Auth)| `DOMAIN\SQLServiceAccount`       |
| Management Agents (MAs)           | Depends on connector (e.g. AD)   |
| SharePoint Farm Account           | `DOMAIN\SPFarm`                  |

> ⚠️ Use the Synchronization Service Manager (`miisclient.exe`) to inspect each Management Agent (MA) and verify the account credentials.

> You cand find MIM Sync and MIM Service Account with powershell :

```powershell
Get-WmiObject -Class Win32_Service -Filter "Name='FIMSynchronizationService' or Name='FIMService'" | Select-Object DisplayName, Name, StartName
```

> You can find the MIM Portal App Pool Account here in IIS Manager :

![](assets/Change%20Passwords%20in%20MIM/2025-05-07-14-47-35.png)

> You find all related SQL Account with this powershell command:

```powershell
Get-WmiObject -Class Win32_Service | Where-Object { $_.DisplayName -like "SQL Server*" } | Select DisplayName, StartName
```

---

### Generate New Passwords
- Use a secure password manager or vault.
- Ensure passwords meet security and complexity requirements.
- Store them securely (e.g., Azure Key Vault, KeePass).

---

### Plan a Maintenance Window
- Communicate expected downtime to stakeholders.
- Ensure no synchronization cycles or workflows are active during the change.

---

### Update Passwords in Active Directory

Update each service account password using Active Directory Users and Computers (ADUC) or PowerShell.

> ⚠️ **Important:** Do not change the SharePoint Farm account password directly in Active Directory unless you plan to synchronize it manually in SharePoint afterward. SharePoint managed accounts should preferably be updated through Central Administration or PowerShell to avoid configuration issues.

You can use the following PowerShell command for other service accounts:

```powershell
Set-ADAccountPassword -Identity "DOMAIN\MIMService" -NewPassword (ConvertTo-SecureString "NewPassword!" -AsPlainText -Force)
```

---

## Synchronization Engine (MIM Sync Service)

### Update Windows Service Logon Account
- Open `services.msc`
- Locate **Forefront Identity Manager Synchronization Service**
- Right-click > **Properties** > **Log On** tab
- Update the account credentials
- Click OK and restart the service

---

## Management Agents (MAs)

### Update MA Credentials in Sync Engine
- Open `miisclient.exe`
- Go to **Management Agents**
- For each MA that uses a service account:
  - Right-click > **Properties** > **Connect to...**
  - Enter the updated credentials
- Run a test **Full Import** to validate each MA

---

## FIM Service

### Update the Forefront Identity Manager Service
- Open `services.msc`
- Locate **Forefront Identity Manager Service**
- Right-click > **Properties** > **Log On** tab
- Update the logon credentials
- Restart the service

---

## SharePoint & IIS (MIM Portal)

### SharePoint Services
- Open `services.msc`
- Locate services such as **SharePoint Timer Service**, **SharePoint Administration**, etc.
- Right-click > **Properties** > **Log On** tab
- Update the credentials for each relevant SharePoint service

### IIS Application Pools
- Open **Internet Information Services (IIS) Manager**
- Navigate to the **Application Pools** section
- Locate the pools associated with your SharePoint web applications (e.g., MIM Portal)
- Right-click each pool > **Advanced Settings** > **Identity** > Update credentials

### Updating the SharePoint Farm Account Password

The **SharePoint Farm account** is a critical managed account used to:
- Run the SharePoint Timer Service
- Act as the identity for the Central Administration application pool
- Connect to the SQL Server databases
- Manage core farm-level services

Changing its password requires careful handling to avoid service interruptions.

#### Scenario 1: The Password Has Already Been Changed in Active Directory

**Option 1: Central Administration UI**
1. Open **SharePoint Central Administration**
2. Navigate to **Security** > **Configure Managed Accounts**
3. Click the **Edit** icon next to the farm account
4. Check **Change password now**
5. Select **Use existing password**
6. Enter the new password that was already set in AD
7. Click **OK** to apply

**Option 2: PowerShell**
```powershell
$FarmAccount = Read-Host "Enter the Farm Account in DOMAIN\User format:"
$Password = Read-Host "Enter the updated password" -AsSecureString
Set-SPManagedAccount -Identity $FarmAccount -ExistingPassword $Password -UseExistingPassword $true
```

#### Scenario 2: You Want to Change the Password from SharePoint Itself

**Option 1: Central Administration UI**
1. Open **SharePoint Central Administration**
2. Go to **Security** > **Configure Managed Accounts**
3. Click **Edit** on the farm account
4. Check **Change password now**
5. Select **Set account password to new value**
6. Provide and confirm the new password
7. Click **OK** — SharePoint will change the password in AD and update its own config

**Option 2: PowerShell**
```powershell
$FarmAccount = Read-Host "Enter the Farm Account in DOMAIN\User format:"
$Password = Read-Host "Enter the new password for the Farm Account" -AsSecureString
Set-SPManagedAccount -Identity $FarmAccount -NewPassword $Password -ConfirmPassword $Password
```

> ⚠️ Avoid enabling automatic password change for the Farm account to ensure credentials remain accessible and controlled manually.

### Other Considerations
- Check and update credentials for:
  - **User Profile Synchronization Service**
  - **Workflow Manager**
  - **Secure Store Service**
  - Any scheduled tasks or third-party integrations using the Farm account

---

## SQL Server Access

### Change SQL Service Account Password
- If SQL Server is using a domain account for the database engine service:
  - Open **SQL Server Configuration Manager**
  - Go to **SQL Server Services**
  - Right-click the SQL Server instance > **Properties** > **Log On** tab
  - Update the password for the domain service account
  - Restart the SQL Server service

- If SQL Agent is used, update its account in the same manner

### Verify Access to MIM Databases
- Ensure service accounts still have required roles (e.g., `db_owner`) on MIM databases
- If using SQL authentication, validate stored credentials in connection strings (if any)
- No changes needed if SQL authentication is not used

---

## ✅ Post-Rotation Checks
- Restart all updated services
- Monitor the Event Viewer for any errors (especially under **Application** and **Forefront Identity Manager** logs)
- Run test import/export/sync cycles on key Management Agents
- Validate access to MIM Portal and Service

---

## ⚠️ Anticipated Impacts

| Affected Area              | Potential Issue                         | Mitigation                                      |
|---------------------------|------------------------------------------|-------------------------------------------------|
| Management Agents (MAs)   | Sync errors due to invalid credentials   | Test each MA manually after update              |
| MIM Portal (IIS)          | Downtime if App Pool fails               | Restart app pool, ensure credentials updated    |
| MIM Service (FIMService)  | Workflows fail silently                  | Check FIMService logs                           |
| SQL Database Access       | Denied access if SQL permissions fail    | Validate account permissions                    |
| Kerberos Authentication   | Broken SPNs if passwords reset incorrectly | Review and re-register SPNs if necessary     |

---

Keeping service accounts up-to-date with secure passwords is a best practice for any MIM deployment. This guide ensures minimal disruption while maintaining security compliance.

> Do not forget to document the change and store credentials securely!

---

Sources:
https://www.sharepointdiary.com/2017/08/change-farm-account-password-in-sharepoint-using-powershell.html
https://learn.microsoft.com/en-us/answers/questions/1695987/change-sharepoint-2019-service-account-password

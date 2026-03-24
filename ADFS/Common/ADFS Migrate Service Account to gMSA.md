# ADFS — Migrate from a Standard Service Account to a Group Managed Service Account (gMSA)

> This article covers how to migrate your AD FS farm from a traditional domain service account to a **Group Managed Service Account (gMSA)**, for both **WID (Windows Internal Database)** and **SQL Server** deployment topologies.

🗓️ Published: 2026-03-24

---

## 🗂️ Table of Contents

- [1. Why Migrate to a gMSA?](#1-why-migrate-to-a-gmsa)
- [2. Prerequisites](#2-prerequisites)
- [3. Prepare the gMSA Account](#3-prepare-the-gmsa-account)
- [4. Migration — ADFS with WID](#4-migration--adfs-with-wid)
  - [4.1. Identify the Primary Node](#41-identify-the-primary-node)
  - [4.2. Change the Service Account on the Primary Node](#42-change-the-service-account-on-the-primary-node)
  - [4.3. Update Secondary Nodes](#43-update-secondary-nodes)
  - [4.4. Validate the WID Farm](#44-validate-the-wid-farm)
- [5. Migration — ADFS with SQL Server](#5-migration--adfs-with-sql-server)
  - [5.1. Grant SQL Permissions to the gMSA](#51-grant-sql-permissions-to-the-gmsa)
  - [5.2. Change the Service Account](#52-change-the-service-account)
  - [5.3. Validate the SQL Farm](#53-validate-the-sql-farm)
- [6. Post-Migration Steps](#6-post-migration-steps)
- [7. Rollback Plan](#7-rollback-plan)
- [8. Common Errors and Troubleshooting](#8-common-errors-and-troubleshooting)

---

## 1. Why Migrate to a gMSA?

| Feature | Standard Service Account | gMSA |
|---|---|---|
| Password management | Manual rotation required | Automatic (managed by AD, 30-day cycle) |
| Password exposure risk | Stored/known by admins | Never exposed — managed by the OS |
| SPN management | Manual | Automatic |
| Multi-server support | Yes | Yes (gMSA can be shared across servers) |
| Compliance / Security | ⚠️ Weaker | ✅ Stronger — no human-known password |

> ✅ **Microsoft recommends using gMSA** for AD FS farms. It removes the operational burden of manual password rotation and reduces the attack surface.

---

## 2. Prerequisites

Before starting the migration, ensure the following:

- **Domain functional level**: Windows Server 2012 or higher
- **KDS Root Key** must be created and effective (see step 3)
- The account performing the migration must be:
  - A **local administrator** on all AD FS servers
  - A **Domain Admin** (or have rights to create gMSA accounts)
  - An **AD FS administrator**
- All AD FS nodes must be able to retrieve the gMSA password (they must be in the `PrincipalsAllowedToRetrieveManagedPassword` group/list)
- For SQL topology: access to the SQL Server instance to grant permissions

> ⚠️ **Plan a maintenance window.** The AD FS service will be restarted on each node during the migration — expect a brief authentication outage.

---

## 3. Prepare the gMSA Account

### 3.1. Verify or Create the KDS Root Key

The **Key Distribution Services (KDS) Root Key** is required for gMSA password generation. Check if one already exists:

```powershell
Get-KdsRootKey
```

If no key exists, create one. In **production**, use the following (effective after 10 hours of DC replication):

```powershell
Add-KdsRootKey -EffectiveImmediately
```

> ⚠️ Despite the parameter name, `Add-KdsRootKey -EffectiveImmediately` actually sets the effective time to **10 hours in the future** to allow replication. In a **lab environment only**, you can force immediate availability:
>
> ```powershell
> Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
> ```

### 3.2. Create a Security Group for ADFS Servers

Create an AD security group containing all your ADFS servers. This group will be granted permission to retrieve the gMSA password.

```powershell
# Create the group
New-ADGroup -Name "grp-ADFS-Servers" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,DC=contoso,DC=com"

# Add all ADFS servers to the group
Add-ADGroupMember -Identity "grp-ADFS-Servers" `
    -Members (Get-ADComputer -Identity "ADFS01"), `
             (Get-ADComputer -Identity "ADFS02")
```

> ⚠️ **Important:** After adding computer accounts to the group, **reboot all ADFS servers** (or wait for Kerberos ticket refresh) so they pick up the new group membership.

### 3.3. Create the gMSA Account

```powershell
New-ADServiceAccount -Name "svc-ADFS-gMSA" `
    -DNSHostName "svc-ADFS-gMSA.contoso.com" `
    -PrincipalsAllowedToRetrieveManagedPassword "grp-ADFS-Servers" `
    -KerberosEncryptionType AES128, AES256 `
    -ServicePrincipalNames "http/adfs.contoso.com"
```

### 3.4. Validate gMSA on Each ADFS Server

On **each** AD FS server, install the gMSA and test it:

```powershell
Install-ADServiceAccount -Identity "svc-ADFS-gMSA"
Test-ADServiceAccount -Identity "svc-ADFS-gMSA"
```

✅ Expected result: `True`

If it returns `False`, verify:
- The server's computer account is in the `grp-ADFS-Servers` group
- The server has been rebooted since group membership was changed
- The KDS Root Key is effective

---

## 4. Migration — ADFS with WID

In a WID farm, there is one **primary node** and one or more **secondary (read-only) nodes**. The migration must start on the primary node.

### 4.1. Identify the Primary Node

Run the following on any AD FS node:

```powershell
Get-AdfsSyncProperties
```

The primary node will show:

```
Role : PrimaryComputer
```

### 4.2. Change the Service Account on the Primary Node

On the **primary AD FS node**, run the following PowerShell commands **as Administrator**:

> ⚠️ Before proceeding, **export your current AD FS configuration** as a backup:
>
> ```powershell
> # Backup current ADFS configuration
> Export-AdfsFarmConfiguration -Path "C:\ADFS-Backup\adfs-config-backup.xml"
> ```

```powershell
# Stop the ADFS service
Stop-Service adfssrv

# Change the service account to gMSA
# Note: the trailing $ is required for gMSA accounts
Set-AdfsFarmInformation -ServiceAccountCredential (New-Object System.Management.Automation.PSCredential("CONTOSO\svc-ADFS-gMSA$", (New-Object System.Security.SecureString)))
```

> 💡 Alternatively, you can use the **AD FS Management Console** approach:
>
> ```powershell
> # This cmdlet handles everything in one step
> Set-AdfsFarmInformation -ServiceAccountCredential $null -ServiceAccount "CONTOSO\svc-ADFS-gMSA$"
> ```

If your farm uses **SSL certificate bindings** tied to the old service account, update the permissions:

```powershell
# Grant the gMSA read access to the ADFS SSL certificate private key
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*adfs*" }
$keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$fullPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyPath"
$acl = Get-Acl $fullPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("CONTOSO\svc-ADFS-gMSA$", "Read", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $fullPath $acl
```

Start the service:

```powershell
Start-Service adfssrv
```

### 4.3. Update Secondary Nodes

On **each secondary node**, run:

```powershell
# Stop the service
Stop-Service adfssrv

# Update the service account
Set-AdfsFarmInformation -ServiceAccountCredential (New-Object System.Management.Automation.PSCredential("CONTOSO\svc-ADFS-gMSA$", (New-Object System.Security.SecureString)))

# Grant certificate private key access (same as primary)
# ... (repeat the certificate ACL commands from section 4.2)

# Start the service
Start-Service adfssrv
```

### 4.4. Validate the WID Farm

```powershell
# Verify the service account
Get-WmiObject Win32_Service -Filter "Name='adfssrv'" | Select-Object Name, StartName

# Check ADFS health
Get-AdfsProperties | Select-Object HostName, ActiveEndpoints

# Check sync status on secondary nodes
Get-AdfsSyncProperties

# Test a token issuance
Test-AdfsServerHealth
```

✅ The `StartName` should display `CONTOSO\svc-ADFS-gMSA$`

---

## 5. Migration — ADFS with SQL Server

When AD FS uses a SQL Server backend, additional steps are required to grant the gMSA access to the databases.

### 5.1. Grant SQL Permissions to the gMSA

Connect to the SQL Server instance and run the following T-SQL:

```sql
-- Create a login for the gMSA
USE [master]
GO
CREATE LOGIN [CONTOSO\svc-ADFS-gMSA$] FROM WINDOWS
GO

-- Grant permissions on the ADFS configuration database
USE [AdfsConfigurationV4]
GO
CREATE USER [CONTOSO\svc-ADFS-gMSA$] FOR LOGIN [CONTOSO\svc-ADFS-gMSA$]
GO
ALTER ROLE [db_owner] ADD MEMBER [CONTOSO\svc-ADFS-gMSA$]
GO

-- Grant permissions on the ADFS artifact database
USE [AdfsArtifactStore]
GO
CREATE USER [CONTOSO\svc-ADFS-gMSA$] FOR LOGIN [CONTOSO\svc-ADFS-gMSA$]
GO
ALTER ROLE [db_owner] ADD MEMBER [CONTOSO\svc-ADFS-gMSA$]
GO
```

> ⚠️ Database names may vary depending on your ADFS version and configuration. Common names include:
> - `AdfsConfigurationV4` (ADFS 2016+)
> - `AdfsConfiguration` (older versions)
> - `AdfsArtifactStore`
>
> Verify your database names in SQL Server Management Studio before running the script.

### 5.2. Change the Service Account

On **each AD FS node** (there is no primary/secondary distinction in SQL mode — all nodes are equal):

```powershell
# Stop the ADFS service
Stop-Service adfssrv

# Change the service account
Set-AdfsFarmInformation -ServiceAccountCredential (New-Object System.Management.Automation.PSCredential("CONTOSO\svc-ADFS-gMSA$", (New-Object System.Security.SecureString)))

# Grant certificate private key access
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*adfs*" }
$keyPath = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
$fullPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyPath"
$acl = Get-Acl $fullPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("CONTOSO\svc-ADFS-gMSA$", "Read", "Allow")
$acl.AddAccessRule($rule)
Set-Acl $fullPath $acl

# Start the service
Start-Service adfssrv
```

> 💡 In a SQL farm, you can update nodes **one at a time** to maintain availability — the remaining nodes continue to serve requests while one is being updated.

### 5.3. Validate the SQL Farm

```powershell
# Verify the service account on each node
Get-WmiObject Win32_Service -Filter "Name='adfssrv'" | Select-Object Name, StartName

# Verify ADFS is operational
Get-AdfsProperties | Select-Object HostName

# Full health check
Test-AdfsServerHealth
```

---

## 6. Post-Migration Steps

Once all nodes are successfully running with the gMSA:

1. **Remove SQL permissions for the old service account** (SQL topology only):

    ```sql
    USE [AdfsConfigurationV4]
    GO
    DROP USER [CONTOSO\svc-adfs-old]
    GO
    USE [AdfsArtifactStore]
    GO
    DROP USER [CONTOSO\svc-adfs-old]
    GO
    USE [master]
    GO
    DROP LOGIN [CONTOSO\svc-adfs-old]
    GO
    ```

2. **Disable the old service account** in Active Directory (don't delete it immediately in case rollback is needed):

    ```powershell
    Disable-ADAccount -Identity "svc-adfs-old"
    ```

3. **Update monitoring** — if you have monitoring on the AD FS service account, update it to reference the gMSA.

4. **Update documentation** — record the new service account name and the migration date.

5. **Delete the old service account** after a validation period (e.g., 30 days).

---

## 7. Rollback Plan

If something goes wrong, you can revert to the old service account:

```powershell
# Stop the service
Stop-Service adfssrv

# Revert to the old service account
$cred = Get-Credential -Message "Enter the old service account credentials (CONTOSO\svc-adfs-old)"
Set-AdfsFarmInformation -ServiceAccountCredential $cred

# Start the service
Start-Service adfssrv
```

For SQL topology, ensure the old account still has SQL permissions before reverting.

---

## 8. Common Errors and Troubleshooting

| Error | Cause | Solution |
|---|---|---|
| `Test-ADServiceAccount` returns `False` | Server not in gMSA's allowed principals | Add the computer account to `grp-ADFS-Servers` and **reboot** |
| ADFS service fails to start (Event 364) | gMSA cannot read the SSL certificate private key | Grant Read permission on the certificate private key (see section 4.2) |
| SQL connection error after migration | gMSA has no SQL login/permissions | Run the SQL permission script from section 5.1 |
| `Set-AdfsFarmInformation` fails with access denied | Not running as local admin or missing AD FS admin role | Run PowerShell as Administrator and verify AD FS admin rights |
| Secondary node not syncing (WID) | Service account mismatch between nodes | Ensure all nodes use the same gMSA — check with `Get-WmiObject Win32_Service` |
| KDS Root Key not effective | Key was created less than 10 hours ago | Wait for replication or recreate with `-EffectiveTime` in lab only |
| Event 1021: "Encountered error during federation passive request" | Certificate binding still referencing old account | Re-run the certificate private key ACL commands on the affected node |

---

> 📚 **References:**
> - [Configure AD FS to use a gMSA — Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/configure-a-federation-server#configure-ad-fs-to-use-a-group-managed-service-account)
> - [Group Managed Service Accounts Overview](https://learn.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
> - [AD FS Troubleshooting](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-overview)

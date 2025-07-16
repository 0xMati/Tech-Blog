# Microsoft Defender for Identity on AD FS
🗓️ Published: 2025-07-14

## 1. Server Specifications

| OS Version            | Desktop Experience | Server Core | Nano Server |
|-----------------------|--------------------|-------------|-------------|
| Windows Server 2016   | ✔                  | ✔           | ❌          |
| Windows Server 2019+  | ✔                  | ✔           | ❌          |

For detailed hardware requirements, see the Defender for Identity server specifications.

---

## 2. Network Requirements

On each AD FS host, allow outbound **TCP 443** to your Defender for Identity endpoint:

https://<your-instance>-sensorapi.atp.azure.com


No other ports are required for cloud connectivity.  

---

## 3. AD FS Audit Configuration

Run this PowerShell on each AD FS server to turn on verbose auditing:

```powershell
Set-AdfsProperties –AuditLevel Verbose
Restart-Service adfssrv
```

> Make sure you’re tracking these Security events in your GPO or advanced audit policy:

1202 – Federation Service validated a new credential
1203 – Federation Service failed to validate a new credential
4624 – An account was successfully logged on
4625 – An account failed to log on

---

### 4. Grant AD FS Database Permissions
Your sensor’s gMSA (e.g. CONTOSO\MDI-DSA$) needs read access to the AD FS configuration database (WID or SQL). Run once per instance (adjust names as needed).

1. T-SQL Method

```sql
USE [master];
CREATE LOGIN [CONTOSO\MDI-DSA$] FROM WINDOWS WITH DEFAULT_DATABASE=[master];
GO
USE [AdfsConfigurationV4];
CREATE USER [CONTOSO\MDI-DSA$] FOR LOGIN [CONTOSO\MDI-DSA$];
ALTER ROLE [db_datareader] ADD MEMBER [CONTOSO\MDI-DSA$];
GRANT CONNECT TO [CONTOSO\MDI-DSA$];
GRANT SELECT TO [CONTOSO\MDI-DSA$];
GO
```

2. PowerShell Method

```powershell
# Connection string for Windows Internal Database (WID)
$cs = 'Server=\\.\pipe\MICROSOFT##WID\tsql\query;Database=master;Trusted_Connection=True;'
$cn = New-Object System.Data.SqlClient.SqlConnection($cs)
$cn.Open()
$cmd = $cn.CreateCommand()
$cmd.CommandText = @"
USE [master];
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N'CONTOSO\MDI-DSA$')
  CREATE LOGIN [CONTOSO\MDI-DSA$] FROM WINDOWS;
USE [AdfsConfigurationV4];
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'CONTOSO\MDI-DSA$')
  CREATE USER [CONTOSO\MDI-DSA$] FOR LOGIN [CONTOSO\MDI-DSA$];
ALTER ROLE [db_datareader] ADD MEMBER [CONTOSO\MDI-DSA$];
GRANT CONNECT TO [CONTOSO\MDI-DSA$];
GRANT SELECT TO [CONTOSO\MDI-DSA$];
"@
$cmd.ExecuteNonQuery()
$cn.Close()
Write-Host "AD FS DB permissions granted to CONTOSO\MDI-DSA$"
```

---

### 5. Install the Sensor on AD FS

Prerequisite: your gMSA (CONTOSO\MDI-DSA$) already has “Log on as a service” and event-log ACL rights via your Config GPO.

1. Download the sensor from the Defender portal (Settings → Identities → Sensors → Add sensor).
2. Extract the ZIP and run Azure ATP Sensor Setup.exe.
3. Paste your access key, accept defaults, and click Install.
4. In the portal, under Sensors, select your new ADFS1.contoso.com entry, click Manage sensor, give it a name, then Save.

Wait for status to move from Not configured → Syncing → Up to date.

---

### 6. Post-Installation Steps

1. In Microsoft 365 Defender, go to Settings → Identities → Sensors.
2. Select your AD FS sensor and in the pane’s Domain Controller (FQDN) field, add one or more DC FQDNs, then Save.
3. Give the sensor a minute to initialize—its service will change from stopped to running.

---

### 7. FAQ

Q: Do I need both the MDI sensor and an Endpoint sensor on my AD FS servers?
A: Yes—Defender for Identity covers identity abuse, and Endpoint covers file/process telemetry. Install both for full coverage.

Q: My AD FS database is on WID—how do I find the pipe name?
A: Run Get-ChildItem "HKLM:\SOFTWARE\Microsoft\ADFS\Parameters" | Format-List to see the WID instance name.

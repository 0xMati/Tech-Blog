# Configuring Permissions for Entra Id Connect (ADSync) Database
🗓️ Published: 2025-07-14

**Note:** Only needed if your Entra Connect database lives on a separate SQL Server instance.

You faced this issue ? 

![](assets/Configuring%20MDI%20Permissions%20for%20Entra%20ID%20Connect%20Database/2025-07-14-10-47-28.png)

When you run an MDI sensor on an Entra Connect host, that sensor needs:

1. **A Windows login** for the computer account (e.g. `CONTOSO\ENCTR-SRV1$`)  
2. **A database user** in your ADSync database  
3. **Execute rights** on the two key stored procedures (`mms_get_globalsettings` & `mms_get_connectors`)

Below is a PowerShell snippet you can run **on each** Entra Connect server to automate this:

```powershell
# Read ADSync settings from the registry
$domain    = $env:USERDOMAIN
$computer  = $env:COMPUTERNAME
$dbName    = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters' -Name DBName).DBName
$sqlServer = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters' -Name Server).Server
$sqlInst   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters' -Name SQLInstance).SQLInstance

# Build a trusted connection string
$connectionString = "Server=$sqlServer\$sqlInst;Database=master;Trusted_Connection=True;"

# Connect and run the SQL statements
$cn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
$cn.Open()
$cmd = $cn.CreateCommand()

$loginName = "$domain\$computer`$"   # note the trailing $ for machine account
$cmd.CommandText = @"
USE [master];

-- Create a Windows login for the computer account
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N'$loginName')
  CREATE LOGIN [$loginName] FROM WINDOWS WITH DEFAULT_DATABASE=[master];

USE [$dbName];

-- Create a user in the ADSync database
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'$loginName')
  CREATE USER [$loginName] FOR LOGIN [$loginName];

-- Grant minimal rights
GRANT CONNECT     TO [$loginName];
GRANT SELECT      TO [$loginName];
GRANT EXECUTE ON OBJECT::[$dbName].dbo.mms_get_globalsettings TO [$loginName];
GRANT EXECUTE ON OBJECT::[$dbName].dbo.mms_get_connectors     TO [$loginName];
"@

$cmd.ExecuteNonQuery()
$cn.Close()
Write-Host "ADSync DB permissions granted for $loginName in $dbName"
```


## 18/09/2025 - Updated Script

What’s new vs. the original script
- LocalDB awareness. Detects (LocalDB) and builds the correct data source ((localdb)\.\ADSync) instead of assuming a remote/named instance.
- Instance detection. Handles named, default (MSSQLSERVER), and empty SQLInstance values cleanly (falls back to Server=$sqlServer when appropriate).
- Right principal, right place. Lets you choose the correct security principal via a single $Principal:
    - Local DB scenario → typically NT AUTHORITY\SYSTEM (or NT SERVICE\ADSync).
    - Remote SQL/Express → the computer account DOMAIN\<ServerName>$.
- Idempotent & minimal grants (kept, but generalized). Still creates login/user only if missing and grants only what’s needed:
    - CONNECT, SELECT, and EXECUTE on dbo.mms_get_globalsettings & dbo.mms_get_connectors.
    - Safer connection string logic. Always uses trusted (integrated) auth; no hard-coded server strings.
- Drop-in on any Connect host. Reads ADSync location from the registry, but now works regardless of whether ADSync is local or on a separate SQL instance.

Operational tip: after running the new script, restart AATPSensorUpdater and check the updater log to confirm the “EXECUTE permission was denied” errors are gone.

```powershell
# === Paramètres à ajuster si besoin ===
# Principal cible des droits SQL :
# - LocalDB/SQL local : 'NT AUTHORITY\SYSTEM'  (ou 'NT SERVICE\ADSync' si c’est lui qui accède)
# - SQL/Express externe : "$env:USERDOMAIN\$($env:COMPUTERNAME)$"
$Principal = 'NT AUTHORITY\SYSTEM'

# === Lecture config ADSync dans le registre ===
$regPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\ADSync\Parameters'
$dbName    = (Get-ItemProperty $regPath -Name DBName     -ErrorAction Stop).DBName
$sqlServer = (Get-ItemProperty $regPath -Name Server     -ErrorAction Stop).Server
$sqlInst   = (Get-ItemProperty $regPath -Name SQLInstance -ErrorAction SilentlyContinue).SQLInstance

# Construction connection string
if ($sqlServer -match '^\(localdb\)$') {
  # LocalDB : attention au \.\Instance
  $dataSource = "(localdb)\.\$sqlInst"
} elseif ([string]::IsNullOrEmpty($sqlInst) -or $sqlInst -eq 'MSSQLSERVER') {
  $dataSource = $sqlServer                  # instance par défaut
} else {
  $dataSource = "$sqlServer\$sqlInst"       # instance nommée
}
$connectionString = "Server=$dataSource;Database=master;Trusted_Connection=True;"

# SQL : créer login + user + droits minimaux
$tsql = @"
USE [master];
IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N'$Principal')
  CREATE LOGIN [$Principal] FROM WINDOWS WITH DEFAULT_DATABASE=[master];

USE [$dbName];
IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N'$Principal')
  CREATE USER [$Principal] FOR LOGIN [$Principal];

GRANT CONNECT TO [$Principal];
GRANT SELECT  TO [$Principal];
GRANT EXECUTE ON OBJECT::dbo.mms_get_globalsettings TO [$Principal];
GRANT EXECUTE ON OBJECT::dbo.mms_get_connectors     TO [$Principal];
"@

# Exécution
$cn = New-Object System.Data.SqlClient.SqlConnection($connectionString)
$cn.Open()
$cmd = $cn.CreateCommand()
$cmd.CommandText = $tsql
$null = $cmd.ExecuteNonQuery()
$cn.Close()
Write-Host "ADSync DB permissions granted for [$Principal] on [$dbName] via [$dataSource]"
```

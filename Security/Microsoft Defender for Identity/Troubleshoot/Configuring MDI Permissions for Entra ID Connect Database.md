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


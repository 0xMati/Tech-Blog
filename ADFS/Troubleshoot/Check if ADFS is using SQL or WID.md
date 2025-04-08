---
title: "How to Check if your ADFS Server is Using SQL or WID"
date: 2025-04-08
---

## How to Check if your Server ADFS environment is using SQL or WID

To determine whether your Active Directory Federation Services (AD FS) environment is using a Windows Internal Database (WID) or a full SQL Server backend, you can use the following PowerShell command:

```powershell
Get-WmiObject -class SecurityTokenService -namespace root/ADFS | select-object ConfigurationDatabaseConnectionString
```

![](assets/Check%20if%20ADFS%20is%20using%20SQL%20or%20WID/2025-04-08-15-56-41.png)

### Output Interpretation

#### ✅ If your ADFS is using WID, you will see:
```
ConfigurationDatabaseConnectionString
-------------------------------------
Data Source=np:\\.\pipe\microsoft##WID\tsql\query;Initial Catalog=AdfsConfiguration;Integrated Security=True
```

#### ✅ If your ADFS is using SQL Server, you will see:
```
ConfigurationDatabaseConnectionString
-------------------------------------
data source=<SQL SERVER>\<INSTANCE>; initial catalog=AdfsConfiguration;integrated security=true
```

This quick check can help you validate the underlying database configuration of your ADFS farm.


# ADFS Migrate from WID to SQL
🗓️ Published: 2025-09-09

> **Goal**: Move an AD FS farm from **WID** to **SQL Server** with minimal downtime, one node at a time.

## Before you start (once)
- **SQL ready**: Have a reachable SQL instance (fixed port or listener) and a place to store DB files.
- **Service account**: Know your AD FS service account (gMSA recommended).
- **Backups**: Export an AD FS config snapshot and/or copy the WID DB files before changes.
- **Primary node**: Identify it with:
  ```powershell
  Get-AdfsSyncProperties
  ```

![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-49-44.png>)

## A. Primary AD FS node (drain first)
1. **Stop AD FS service** on the primary:
   ```cmd
   net stop adfssrv
   ```

 ![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-50-09.png>)

2. **Detach WID databases** (run on the AD FS server, local WID named pipe):
   ```cmd
   sqlcmd -S np:\\.\pipe\MICROSOFT##WID\tsql\query -E -Q "USE master; EXEC sp_detach_db 'AdfsArtifactStore'; EXEC sp_detach_db 'AdfsConfigurationV3';"
   ```
![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-51-42.png>)


3. **Copy DB files** from the AD FS server to the SQL data folder:
   - From: `C:\Windows\WID\Data\`
     - `AdfsConfigurationV3.mdf`, `AdfsConfigurationV3_log.ldf`
     - `AdfsArtifactStore.mdf`, `AdfsArtifactStore_log.ldf`
   - To: e.g., `C:\Program Files\Microsoft SQL Server\MSSQL\Data\` (on the SQL Server).

![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-51-13.png>)

## B. SQL Server (once)
4. **Attach the databases** and **enable Service Broker** for the configuration DB:
   ```sql
   USE master;
   GO
   CREATE DATABASE [AdfsConfigurationV3] ON 
     (FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL\Data\AdfsConfigurationV3.mdf'),
     (FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL\Data\AdfsConfigurationV3_log.ldf')
   FOR ATTACH;
   GO

   CREATE DATABASE [AdfsArtifactStore] ON 
     (FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL\Data\AdfsArtifactStore.mdf'),
     (FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL\Data\AdfsArtifactStore_log.ldf')
   FOR ATTACH;
   GO

   ALTER DATABASE [AdfsConfigurationV3] SET ENABLE_BROKER WITH ROLLBACK IMMEDIATE;
   GO
   ```

![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-52-33.png>)


5. **Grant rights** to the AD FS service account (replace `DOMAIN\gmsa-adfs$` as needed):
   ```sql
   CREATE LOGIN [DOMAIN\gmsa-adfs$] FROM WINDOWS;
   GO
   USE [AdfsConfigurationV3]; EXEC sp_addrolemember 'db_owner', 'DOMAIN\gmsa-adfs$'; GO
   USE [AdfsArtifactStore];   EXEC sp_addrolemember 'db_owner', 'DOMAIN\gmsa-adfs$'; GO
   ```

## C. Point the **primary** AD FS to SQL (order matters)
6. With the **service still stopped**, set the **Configuration DB** connection (WMI):
   ```powershell
   $Sql = "SQLSERVER\INSTANCE"
   $Cfg = "AdfsConfigurationV3"
   $adfs = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
   $adfs.ConfigurationDatabaseConnectionString = "Data Source=$Sql;Initial Catalog=$Cfg;Integrated Security=True;Min Pool Size=20"
   $adfs.Put() | Out-Null
   ```
![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-53-28.png>)

7. **Start AD FS service**:
   ```powershell
   Start-Service adfssrv
   ```

8. Set the **Artifact DB** connection (cmdlet, service running):
   ```powershell
   $Art = "AdfsArtifactStore"
   Set-AdfsProperties -ArtifactDbConnection "Data Source=$Sql;Initial Catalog=$Art;Integrated Security=True;Min Pool Size=20"
   ```
![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-53-51.png>)

9. **Validate** and return to the load balancer:
   ```powershell
   Get-AdfsProperties | Select ConfigurationDatabaseConnectionString, ArtifactDbConnection
   ```
   - Event Viewer → **AD FS/Admin**: Event **100** on startup.
   - Optional: test `/adfs/ls/IdpInitiatedSignon.aspx`.

![](<./assets/ADFS Migrate from WID to SQL/2025-09-09-11-54-26.png>)

## D. Each **secondary** AD FS node (repeat)
10. Drain from LB, then **stop AD FS**:
    ```powershell
    Stop-Service adfssrv
    ```
11. Set **Configuration DB** (service stopped → WMI), **start service**, set **Artifact DB** (cmdlet), **validate**, and re-add to LB:
    ```powershell
    $Sql = "SQLSERVER\INSTANCE"
    $Cfg = "AdfsConfigurationV3"
    $Art = "AdfsArtifactStore"

    $adfs = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
    $adfs.ConfigurationDatabaseConnectionString = "Data Source=$Sql;Initial Catalog=$Cfg;Integrated Security=True;Min Pool Size=20"
    $adfs.Put() | Out-Null

    Start-Service adfssrv
    Set-AdfsProperties -ArtifactDbConnection "Data Source=$Sql;Initial Catalog=$Art;Integrated Security=True;Min Pool Size=20"
    Get-AdfsProperties | Select ConfigurationDatabaseConnectionString, ArtifactDbConnection
    ```

## E. Post-migration
12. Configure **regular SQL backups** for both DBs. Monitor AD FS/Admin logs and SQL latency.
13. Optional: uninstall **Windows Internal Database** from AD FS servers and remove old MDF/LDF after a steady period.

## Rollback (quick)
- Stop AD FS, point back to WID named pipe for **Configuration DB**, reattach DBs to WID if needed, start service, validate.
  ```powershell
  # Example connection string back to WID
  $wid = "np:\\.\pipe\MICROSOFT##WID\tsql\query"
  $cfg = "AdfsConfigurationV3"
  $adfs = Get-WmiObject -Namespace root/ADFS -Class SecurityTokenService
  $adfs.ConfigurationDatabaseConnectionString = "Data Source=$wid;Initial Catalog=$cfg;Integrated Security=True"
  $adfs.Put() | Out-Null
  Start-Service adfssrv
  ```

---

### One-page summary
1) Drain primary → stop service → detach WID → copy files → attach on SQL → enable broker → grant rights.  
2) Primary: set **Config (WMI)** → start service → set **Artifact (cmdlet)** → validate → back to LB.  
3) Repeat **Config/Start/Artifact/Validate** on each secondary → back to LB.  
4) Backups, monitoring, optional WID removal.


---
title: "Moving the AD FS WID Database: Procedure and Version Limits"
date: 2026-09-29
---

# Moving the AD FS WID Database: Procedure and Version Limits

**A local data-file move, a WID-to-SQL migration and a farm restore are three different operations.**

This note preserves a **Windows Server 2012 R2 lab procedure** for relocating AD FS database files within the local Windows Internal Database (WID) instance. It is not a newly tested procedure for Server 2016/2019/2022/2025. No current AD FS-specific Microsoft procedure confirming this local-file relocation was identified during this review; generic SQL file-movement documentation does not establish that support boundary.

Use the historical sequence below to understand an existing configuration or plan a version-specific operation, not as an unattended production script. Before a real move, establish the supported method for the installed versions, a restorable backup and the exact local database/file inventory.

## What is being moved?

| Operation | What changes |
|---|---|
| Local WID file relocation | Physical data/log paths in that node's existing local instance |
| WID to SQL Server | Database engine/location and AD FS connection/configuration; separate migration |
| Farm restore or replacement node | Service/configuration recovery under the chosen version-compatible process |

WID is not SQL Server Express. Installing management tools does not replace the WID instance, and the old lab's SQL Server 2014 download/.NET 3.5 steps are not prerequisites to impose on a current server. Use a compatible management client without installing an unnecessary database engine.

Every WID node owns local files. AD FS configuration replication does **not** copy a changed physical disk path from the primary to all secondaries. Do not run a farm-wide move blindly, and do not make a secondary writable merely because the primary holds the writable AD FS configuration copy.

## Inventory before changing anything

On the affected, confirmed WID-based AD FS server, record version, role, service identity and paths. These are read-only observations in Windows PowerShell 5.1:

```powershell
Import-Module ADFS -ErrorAction Stop
Get-AdfsSyncProperties -ErrorAction Stop

Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
    Where-Object { $_.Name -eq 'MSSQL$MICROSOFT##WID' } |
    Select-Object Name, StartName, State, PathName
```

The usual local connection is `np:\\.\pipe\MICROSOFT##WID\tsql\query`, using Windows authentication from an elevated local management session with database permissions. Microsoft documents this WID connection in other role-specific procedures, including WSUS; that documents the connection mechanism, **not** approval to apply the WSUS migration to AD FS.

![Historical management client connecting to the local WID named pipe with Windows authentication](./assets/Moving%20the%20AD%20FS%20WID%20Database%20-%20Procedure%20and%20Version%20Limits/historical-wid-local-connection.png)

*Historical lab capture, cropped with the account name masked. The SQL Server 2014 branding belongs to the management client, not proof that WID has been replaced by SQL Server 2014.*

With a compatible **ODBC sqlcmd** installed, this query lists the local AD FS-named databases and files. It does not detach, alter or copy them:

```powershell
$inventoryQuery = @'
SELECT SERVERPROPERTY('ServerName') AS InstanceName,
       SERVERPROPERTY('ProductVersion') AS EngineVersion;

SELECT databases.name AS DatabaseName,
       files.file_id AS FileId,
       files.name AS LogicalName,
       files.type_desc AS FileType,
       files.physical_name AS PhysicalPath,
       files.state_desc AS FileState
FROM sys.master_files AS files
INNER JOIN sys.databases AS databases
    ON databases.database_id = files.database_id
WHERE databases.name LIKE N'Adfs%'
ORDER BY databases.name, files.file_id;
'@

& sqlcmd.exe -S 'np:\\.\pipe\MICROSOFT##WID\tsql\query' `
    -E -d master -Q $inventoryQuery -b -l 15 -t 30
if ($LASTEXITCODE -ne 0) {
    throw 'WID file inventory failed; do not proceed from an incomplete result.'
}
```

Confirm the actual instance, database names, **all** data/log files and permissions. Names such as `AdfsConfiguration` or version-suffixed variants must come from the server, not be guessed from an article. No returned rows could indicate the wrong instance, insufficient metadata visibility or a different configuration; it does not mean there are no files to protect.

## Historical detach/copy/attach sequence

The source lab used the following order. For a new operation, stop here unless the installed-version procedure and recovery plan have been validated.

1. **Retain the full recovery state.** Back up the AD FS configuration and required key/certificate material with the appropriate supported method. Record database/file names, service identities, ACLs, configuration roles and known-good authentication/replication behavior. A copy of an online MDF file is not that backup.
2. **Drain the affected node and stop dependent services.** The lab stopped AD FS and the applicable Device Registration service. Identify actual consumers; do not stop the entire WID instance just to clear a lock without considering other databases or roles.
3. **Detach the identified AD FS databases from that local instance.** The historical SSMS dialog used **Drop Connections**. That is a disruptive operation, not an observational step; do not force-disconnect transactions before understanding them. The instance must be running for SQL detach/attach operations.
4. **Copy the detached data and log files to the reviewed local location.** Preserve the old files for recovery and include every file reported by the inventory, not only the primary MDF. Verify paths, storage properties and the database-engine service identity's access before attaching.
5. **Attach to the same intended WID instance using the new paths.** Confirm the data/log pairing and database options. Do not attach the files to an accidentally installed SQL Express instance or change AD FS connection strings as though this were a WID-to-SQL migration.
6. **Verify database state, then resume service and test.** Re-run the file inventory, review database/AD FS errors, confirm WID synchronization and perform fresh internal/external authentication through the normal load-balanced path. Keep the old files until the recovery window is closed.

![Historical AD FS configuration and artifact-store data and log files in the lab target directory](./assets/Moving%20the%20AD%20FS%20WID%20Database%20-%20Procedure%20and%20Version%20Limits/historical-wid-data-log-files.png)

*Historical lab capture, cropped. These four files and the E: drive are that lab's inventory, not a fixed file list or required destination for another version.*

**Permissions:** determine the database-engine identity actually running WID, commonly `NT SERVICE\MSSQL$MICROSOFT##WID`. Its file access is separate from the AD FS domain service account's database access. Give the intended engine the required access to the reviewed data directory under the supported design; do not grant broad rights on an entire drive.

## What not to infer from the old screenshots

- **Read-only is not a single diagnosis.** A WID secondary's AD FS configuration role, a database `READ_ONLY` option, a file attribute and an NTFS permission problem are different things. Do not force `READ_ONLY = false` simply because a screenshot did so.
- **Service Broker is not a generic synchronization repair.** The old note proposed `ENABLE_BROKER WITH ROLLBACK IMMEDIATE` after a replication issue. This can terminate work and changes database behavior; it is not justified merely by moving files. Investigate the actual database/version/replication error instead.
- **A service starting is not full recovery.** Check the newly opened file paths, replicated configuration, WAP trust and actual RP authentication. The next restart must not reveal that the service still depended on an old directory.
- **Do not mix two writable copies.** If rolling back, stop consumers and restore the recorded attachment/file arrangement or the tested backup. Never merge old/new MDF/LDF files after they have diverged or overwrite a database while it is in use.

## When the requirement is really migration or recovery

Use the [WID-to-SQL article](ADFS%20Migrate%20from%20WID%20to%20SQL.md) for that distinct operation, or the [parallel Rapid Restore workflow](ADFS%20Migrate%20from%20WID%20to%20SQL%20via%20Rapid%20Restore%20Tool%20-%20Parallel%20deployment.md) where applicable. Microsoft's Rapid Restore documentation covers AD FS 2016 and later, requires matching backup/restore AD FS versions and places WID backup on the primary. Those requirements are not evidence that a local file move must be performed only on the primary, nor a backup prescription for the 2012 R2 lab.

## References

- [Microsoft Learn: sys.master_files inventory](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-master-files-transact-sql?view=sql-server-ver17)
- [Microsoft Learn: sqlcmd usage](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-use-utility?view=sql-server-ver17)
- [Microsoft Learn: SQL Server user-database file movement](https://learn.microsoft.com/en-us/sql/relational-databases/databases/move-user-databases?view=sql-server-ver17), generic engine procedures, not an AD FS WID certification.
- [Microsoft Learn: WID connection example in WSUS migration](https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/wid-to-sql-migration), another Windows role; do not apply its database/login changes to AD FS.
- [Microsoft Learn: AD FS Rapid Restore requirements](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/ad-fs-rapid-restore-tool)
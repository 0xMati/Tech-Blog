---
title: "AD FS WID Errors 28005 and 15517: Ownership, Permissions and File Checks"
date: 2026-10-01
---

# AD FS WID Errors 28005 and 15517: Ownership, Permissions and File Checks

**Read the inner SQL error before changing the database owner.**

Windows Internal Database (WID) uses SQL Server database-engine components. An Application-log event from the WID instance is not automatically an AD FS authentication error, even when AD FS depends on that instance.

## 1. Separate the outer error from its cause

| Evidence | Meaning |
|---|---|
| **28005** | An exception occurred while enqueueing a message in a Service Broker target queue; inspect the embedded error number, state and text |
| **15517** | SQL cannot execute as the specified database principal: it may not exist, may not be impersonatable, or the caller may lack permission |
| `dbo` named in the inner error | Investigate the database-owner execution context, including stored SIDs and the instance's valid principals |
| File-open, access-denied or compressed-file error | Investigate the identified file and engine service identity; this is a different branch |

An event 28005 **containing error 15517** is a reason to investigate execution context. Event 28005 alone is not proof of a broken owner SID. Likewise, NTFS compression does not explain every 15517.

Retain the full message, timestamp, event provider/instance, database name and recent restore, migration or service-account changes. Compare the failure with AD FS Admin events from the same node and interval. Do not apply a fix intended for another application using WID.

## 2. Read the correct database's metadata

Use an existing SQL administration tool with Windows authentication and sufficient metadata access. For WID, connect locally using the instance and connection details actually configured on that AD FS node; do not enable remote SQL access for this check. Old `MICROSOFT##SSEE` and later `MICROSOFT##WID` instructions are not interchangeable. AD FS database names also vary by version.

Select the affected database explicitly. Replace the placeholder below with its exact name. The guard prevents silently diagnosing `master` or another database. These are catalog reads, not an AD FS database repair script:

```sql
DECLARE @ExpectedDatabase sysname = N'REPLACE_WITH_ACTUAL_ADFS_DATABASE';
IF DB_NAME() <> @ExpectedDatabase
    THROW 51000, 'Select the exact affected AD FS database before querying.', 1;

SELECT SERVERPROPERTY('ServerName') AS InstanceName,
       DB_NAME() AS DatabaseName,
       SUSER_SNAME() AS ConnectedLogin;

SELECT name AS DatabaseName, state_desc, is_read_only,
       owner_sid, SUSER_SNAME(owner_sid) AS ResolvedOwner
FROM sys.databases
WHERE database_id = DB_ID();

SELECT name AS DatabasePrincipal, type_desc, sid,
       SUSER_SNAME(sid) AS ResolvedLogin
FROM sys.database_principals
WHERE name = N'dbo';

SELECT name AS LogicalFileName, type_desc, physical_name, state_desc
FROM sys.database_files;
```

**Verify:** The instance and database match the error, and the query returned the expected rows. Compare the database `owner_sid` with the `dbo` SID and whether each resolves to a valid login. A restore can leave an execution-context SID that is invalid on the destination instance, as Microsoft's 15517 example demonstrates.

A NULL name or missing row needs investigation of principal validity **and the reader's metadata visibility**. It is not an instruction to grant the AD FS service account `sysadmin`. If the error names a principal other than `dbo`, investigate that specific execution context instead of assuming the owner is the cause.

## 3. Check file-system compression separately

Microsoft does not support read/write SQL data filegroups or transaction-log files on an NTFS-compressed file system. This is **file-system compression**, not SQL row/page compression or backup compression. The SQL documentation's read-only exceptions are not a reason to mark an AD FS operational database read-only.

On the database host, replace these example paths with **all the actual file paths** returned above. This Windows PowerShell 5.1 check reads attributes only:

```powershell
$databaseFiles = @(
    'D:\DatabaseFiles\ActualDataFile.mdf',
    'D:\DatabaseFiles\ActualLogFile.ldf'
)
foreach ($databaseFile in $databaseFiles) {
    $file = Get-Item -LiteralPath $databaseFile -Force -ErrorAction Stop
    if ($file.PSIsContainer) { throw 'Expected a database file, not a directory.' }
    [pscustomobject]@{
        Path = $file.FullName
        NtfsCompressed = [bool]([int]$file.Attributes -band [int][IO.FileAttributes]::Compressed)
        FileReadOnly = [bool]([int]$file.Attributes -band [int][IO.FileAttributes]::ReadOnly)
    }
}
```

Inspect the containing directory's compression policy too; an inherited policy can affect newly created files. `FileReadOnly` is a file attribute, not the SQL database's `is_read_only` setting. A readable file for an administrator does not prove that the WID service identity has the necessary access. Check the exact path, effective ACLs, free space and related engine/OS errors without applying broad ACL resets.

## 4. Choose a repair only after identifying the cause

- **Invalid execution-context principal:** establish the intended principal for this AD FS version, its permissions and the restore history. The generic SQL 15517 article describes ownership/impersonation remedies, but does not define a universal AD FS owner.
- **File attribute or permission problem:** plan the specific correction with database/service availability and recovery requirements. Do not decompress or move active database files as a blind online fix.
- **Different embedded error:** follow that error's evidence. Do not force Service Broker, replace its identity or toggle database read-only state merely because 28005 mentions a queue.

Take a recoverable, AD FS-appropriate backup before any repair. Preserve the initial metadata and settings, then verify database access, AD FS service health, relevant WID synchronization behavior and the original sign-in test afterward. Silencing one event is not the success criterion.

The [WID file-move guide](../How-to/Moving%20the%20AD%20FS%20WID%20Database%20-%20Procedure%20and%20Version%20Limits.md) is explicitly a historical, version-limited procedure. A [side-by-side WID farm upgrade](../How-to/Upgrading%20an%20AD%20FS%20WID%20Farm%20-%20Mixed%20Mode,%20Farm%20Behavior%20Level%20and%20WAP.md) is a different operation from editing local SQL ownership or permissions.

## References

- [Microsoft Learn: SQL Server error 15517](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/mssqlserver-15517-database-engine-error)
- [Microsoft Learn: SQL Server error catalog, including 28005](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors-28000-to-30999)
- [Microsoft Learn: Database files, filegroups and file-system support](https://learn.microsoft.com/en-us/sql/relational-databases/databases/database-files-and-filegroups)
- [Microsoft Learn: Metadata visibility configuration](https://learn.microsoft.com/en-us/sql/relational-databases/security/metadata-visibility-configuration)
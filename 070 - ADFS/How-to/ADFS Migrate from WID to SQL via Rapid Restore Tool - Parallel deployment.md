# ADFS Migrate WID to SQL via Rapid Restore Tool (Parallel deployment)
🗓️ Published: 2025-09-09

> **When to use this method?**  
> You want a *clean rebuild* of the farm on SQL Server (not an in-place DB attach) with a short, controlled cutover window.

## Introduction
- **Version parity**: restore must target the **same Windows/ADFS version** as the backup.
- **Primary WID node**: On WID farms, run the backup on the **primary** ADFS server:
  ```powershell
  Get-AdfsSyncProperties
  ```
- **SQL ready**: reachable instance (fixed port or listener). Service account (gMSA or classic) will be reused.
- **Certificates**: SSL + token signing/decrypting certs **exportable**. Keep password handy.
- **Limitations**: This tool **does not support** SQL **Merge Replication** or **Always On AG** for the restore step. Use classic SQL backups in those cases.

---

## 1. Back up the current WID farm (on the primary)
```powershell
# Install module (after MSI install of the tool)
Import-Module 'C:\Program Files (x86)\ADFS Rapid Recreation Tool\ADFSRapidRecreationTool.dll'

# File system backup including DKM (keys) – run as Domain Admin or pass service account creds
$Export = 'C:\AdfsBackup'
$Pwd    = 'StrongPassw0rd!'   # choose a secure temporary passphrase

Backup-ADFS -StorageType FileSystem `
            -StoragePath  $Export `
            -EncryptionPassword $Pwd `
            -BackupComment "Pre-migration WID backup" `
            -BackupDKM
```

> Result: a folder like `adfsBackup_<ID>_<Date-Time>` containing encrypted artifacts.

---

## 2. Build a **new first** ADFS server on SQL (parallel)
> Use a **fresh Windows Server** joined to the **same domain** (or repurpose a former node after uninstalling ADFS).

```powershell
# Restore the farm and point it to SQL with DBConnectionString
$Export = 'C:\AdfsBackup'      # path copied from step 1
$Pwd    = 'StrongPassw0rd!'    # same passphrase
$Sql    = 'SQLHOST\INSTANCE'   # or listener; Windows auth is recommended
$gMSA   = 'CONTOSO\adfsgmsa$'  # or use -ServiceAccountCredential

Restore-ADFS -StorageType FileSystem `
             -StoragePath  $Export `
             -DecryptionPassword $Pwd `
             -DBConnectionString "Data Source=$Sql;Integrated Security=True" `
             -GroupServiceAccountIdentifier $gMSA `
             -RestoreDKM
```

What the command does:
- Installs the **ADFS role**, creates a **new farm** on **SQL**, and **restores** configuration/certificates.  
- Uses your existing **service account** and **keys** (via `-RestoreDKM`).

Validate:
```powershell
Get-AdfsProperties | Select FederationServiceName,ArtifactDbConnection,ConfigurationDatabaseConnectionString
```

> Optional test (from a test client, without impacting prod) by overriding DNS to the new server in the client’s `hosts` file and visiting:  
> `https://<fs-name>/adfs/ls/IdpInitiatedSignon.aspx`

---

## 3. Join extra ADFS servers to the new SQL farm
> Repeat on each additional server you want in the new farm.

```powershell
# Add server as additional node (SQL-backed farm)
Add-AdfsFarmNode -GroupServiceAccountIdentifier $gMSA `
                 -SQLConnectionString "Data Source=$Sql;Integrated Security=True"
```

Check health on each node and in the ADFS/Admin event log.

---

## 4. Web Application Proxies (WAP)
If the federation service name and certificates are unchanged, you can usually **re-provision WAP** to trust the rebuilt farm:
```powershell
# On each WAP (run elevated), re-establish trust with the new farm
$fscred = Get-Credential   # enter the ADFS service account (or admin) used for trust establishment
Install-WebApplicationProxy `
   -FederationServiceName "<fs-name.yourdomain>" `
   -FederationServiceTrustCredential $fscred `
   -CertificateThumbprint "<SSL-cert-thumbprint>"
```
Validate external sign-in flows after each proxy.

---

## 5. Cutover
1. **Switch DNS / load balancer** to point at the new ADFS nodes.
2. Verify SSO flows (internal + external via WAP).
3. Remove old ADFS servers from rotation.

---

## 6. Post-cutover
- Configure **SQL backups** for `AdfsConfiguration*` and `AdfsArtifactStore`.
- Monitor ADFS/Admin logs.
- Retire old WID components after a steady period.

---

## Rollback plan
- Keep the old WID farm intact until you validate the new farm.  
- In case of issues, revert DNS/LB to the original farm; troubleshoot offline.

---

### Common commands reference

**Back up (with DKM):**
```powershell
Backup-ADFS -StorageType FileSystem -StoragePath C:\AdfsBackup -EncryptionPassword "<pwd>" -BackupDKM
```

**Restore to WID (if ever needed):**
```powershell
Restore-ADFS -StorageType FileSystem -StoragePath C:\AdfsBackup -DecryptionPassword "<pwd>" -DBConnectionString "WID"
```

**Restore to SQL (typical for this migration):**
```powershell
Restore-ADFS -StorageType FileSystem -StoragePath C:\AdfsBackup -DecryptionPassword "<pwd>" -DBConnectionString "Data Source=SQLHOST;Integrated Security=True"
```

**Join extra nodes to SQL farm:**
```powershell
Add-AdfsFarmNode -GroupServiceAccountIdentifier "CONTOSO\adfsgmsa$" -SQLConnectionString "Data Source=SQLHOST;Integrated Security=True"
```

---

## ⚠️ Attention for side-by-side with the **same Federation Service Name (FSN)**

### SPN of the Federation Service (Kerberos)
- Keep a **single SPN** `host/<fsn>` on **one** account (ideally the **same gMSA** for both farms).
- If you must switch accounts, **move** the SPN **at cutover** (no duplicates before then):
  ```cmd
  setspn -D host/fs.contoso.com CONTOSO\OldAcct
  setspn -S host/fs.contoso.com CONTOSO\NewAcct
  ```

### DKM keys (AD)
- Rapid Restore restores/uses the **DKM container** in AD; both farms can **read the same keys** safely.
- Do not modify or delete DKM until after the cutover and decommission of the old farm.

### Device Registration Service (DRS) / SCP
- If you use **Workplace Join**, only **one farm** should have **DRS active** at a time.
- Keep DRS **disabled** on the new farm until cutover; after cutover, **enable** it and ensure the **SCP** points to the live farm.

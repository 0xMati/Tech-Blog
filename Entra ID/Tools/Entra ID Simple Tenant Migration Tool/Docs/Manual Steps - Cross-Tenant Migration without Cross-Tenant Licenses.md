# Manual Steps — Cross-Tenant Migration WITHOUT Cross-Tenant Licenses

> This document describes how to perform a full tenant-to-tenant migration **without** the Cross-Tenant User Data Migration license. This is the "old school" approach — **PST exports** for mailboxes, **manual file copy** for OneDrive, and no trust relationship between the tenants.
>
> This method is slower, more labor-intensive, and requires more downtime, but it works in any scenario and doesn't need any special licensing beyond basic Microsoft 365.

---

## Table of Contents

- [Overview — What's Different?](#overview--whats-different)
- [Before You Start — Prerequisites](#before-you-start--prerequisites)
- [Phase 1 — Inventory the Source Tenant](#phase-1--inventory-the-source-tenant)
- [Phase 2 — Provision Identities in the Target Tenant](#phase-2--provision-identities-in-the-target-tenant)
- [Phase 3 — Migrate Exchange Mailboxes (PST Method)](#phase-3--migrate-exchange-mailboxes-pst-method)
- [Phase 4 — Migrate OneDrive Data (Manual Copy)](#phase-4--migrate-onedrive-data-manual-copy)
- [Phase 5 — Migrate SharePoint Sites (Manual)](#phase-5--migrate-sharepoint-sites-manual)
- [Phase 6 — Post-Migration Cleanup & DNS Cutover](#phase-6--post-migration-cleanup--dns-cutover)
- [Quick Reference](#quick-reference)

---

## Overview — What's Different?

With the **Cross-Tenant User Data Migration** license, Microsoft provides built-in cmdlets that move mailboxes and OneDrive content directly between tenants through their backend infrastructure. **Without** that license, none of those cmdlets are available, so you must:

| Workload | With Cross-Tenant License | Without (this guide) |
|----------|---------------------------|----------------------|
| **Mailboxes** | `New-MigrationBatch` moves mailboxes server-side | Export to PST, upload to target |
| **OneDrive** | `Start-SPOCrossTenantUserContentMove` moves content server-side | Download files, upload to target (sync client, browser, or SharePoint Migration Tool) |
| **SharePoint** | `Start-SPOCrossTenantGroupContentMove` (preview) | SharePoint Migration Tool (SPMT) or manual download/upload |
| **Trust setup** | Org relationships, migration endpoint, app registration | None needed — tenants are completely independent |
| **Downtime** | Near-zero (mailbox cutover takes minutes) | Hours to days (depends on data volume and bandwidth) |
| **Complexity** | High setup, low execution | Low setup, high execution |

**When to use this approach**:
- You don't have (or can't get) Cross-Tenant User Data Migration licenses
- The source tenant is being decommissioned soon and you need a quick-and-dirty approach
- You're migrating a small number of users (< 20) and PST/manual copy is acceptable
- You're migrating from a tenant that doesn't support cross-tenant migration (e.g., GCC, older plans)

---

## Before You Start — Prerequisites

### Tools You'll Need

| Tool | Purpose | Download |
|------|---------|----------|
| **PowerShell 5.1** | Scripting, module management | Built into Windows |
| **Microsoft Graph PowerShell** | Create users, groups, assign licenses | `Install-Module Microsoft.Graph` |
| **Exchange Online PowerShell** | Compliance search, mailbox export, mail contacts | `Install-Module ExchangeOnlineManagement` |
| **OneDrive Sync Client** | Download/upload OneDrive files | Built into Windows 10/11 |
| **SharePoint Migration Tool (SPMT)** | Bulk copy SharePoint/OneDrive data | [Download from Microsoft](https://learn.microsoft.com/en-us/sharepointmigration/introducing-the-sharepoint-migration-tool) |
| **Azure Storage Explorer** (optional) | Manage PST files in Azure blob storage | [Download](https://azure.microsoft.com/en-us/products/storage/storage-explorer/) |

### Install PowerShell Modules

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Users.Actions -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### Permissions Required

| Service | Source Tenant | Target Tenant |
|---------|--------------|---------------|
| **Entra ID** | Global Reader | Global Administrator |
| **Exchange Online** | Compliance Administrator + Export role | Exchange Administrator |
| **SharePoint/OneDrive** | SharePoint Administrator | SharePoint Administrator |
| **On-premises AD** | — | Domain Admin (if AD-synced users) |

> **Important**: For the PST export method, you need the **Mailbox Import Export** role in Exchange Online on the SOURCE tenant. This role is NOT assigned by default, not even to Global Admins.

### Prepare Storage

You'll need temporary storage for PST files and OneDrive data:

- [ ] **For PST exports**: An Azure Storage Account with a blob container (Microsoft's Content Search export puts PST files in Azure blob storage), OR local disk space (if using Outlook export)
- [ ] **For OneDrive**: Enough local disk space to download all users' OneDrive content (check your Phase 1 inventory for total size)
- [ ] **Estimate**: Budget 1.5x the total data size for temporary storage (original + copy in transit)

---

## Phase 1 — Inventory the Source Tenant

> This phase is **identical** to the licensed approach. You still need a complete inventory.

Refer to [Phase 1 of the licensed manual steps](./Manual%20Steps%20-%20Cross-Tenant%20Migration.md#phase-1--inventory-the-source-tenant) for the full inventory process. The key exports are:

- [ ] `EntraUsers_SOURCE.csv` — All users with UPN, type (synced/cloud/guest), licenses
- [ ] `EntraGroups_SOURCE.csv` — All groups
- [ ] `EntraGroupMembers_SOURCE.csv` — All group memberships
- [ ] `EXO-Mailboxes_SOURCE.csv` — All mailboxes with size and ExchangeGuid
- [ ] `EXO-MailContacts_SOURCE.csv` — All mail contacts
- [ ] `SPO-OneDriveSites_SOURCE.csv` — All OneDrive sites with storage used
- [ ] `SPO-Sites_SOURCE.csv` — All SharePoint sites

**Pay special attention to mailbox sizes** — they determine how long PST export/import will take and how much temporary storage you need.

---

## Phase 2 — Provision Identities in the Target Tenant

> This phase is also **largely identical** to the licensed approach, with one key difference: you do NOT need to set mail-related attributes on AD users, because there's no cross-tenant migration endpoint to route traffic through.

Refer to [Phase 2 of the licensed manual steps](./Manual%20Steps%20-%20Cross-Tenant%20Migration.md#phase-2--provision-identities-in-the-target-tenant) for the full process. Summary:

- [ ] Create AD-synced users in the target AD forest (Step 2.2 — but skip the `targetAddress`/`proxyAddresses` mail attributes)
- [ ] Create cloud-only users in target Entra ID (Step 2.3)
- [ ] Invite guest users to the target tenant (Step 2.4)
- [ ] Create groups in target AD and/or Entra ID (Steps 2.5-2.6)
- [ ] Configure Entra Connect sync scope (Step 2.7)
- [ ] Recreate mail contacts in target Exchange Online (Step 2.8)
- [ ] **Assign full Microsoft 365 licenses immediately** (Exchange + OneDrive + SharePoint) — since we're creating real mailboxes, not MailUsers

> **Key difference**: In the licensed approach, target users are created as **MailUser** objects (no mailbox) and the migration creates the mailbox. Here, you assign licenses **upfront** so users get a **full mailbox** immediately, and you import data into it via PST.

```powershell
# On TARGET — assign licenses to all migrated users immediately
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "User.ReadWrite.All"

$skuId = (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "SPE_E3" }).SkuId

# For each user:
Set-MgUserLicense -UserId "john.doe@target.onmicrosoft.com" `
    -AddLicenses @(@{SkuId = $skuId}) `
    -RemoveLicenses @()
```

---

## Phase 3 — Migrate Exchange Mailboxes (PST Method)

> **Goal**: Export each user's mailbox from the SOURCE tenant as a PST file, then import it into the TARGET tenant.

There are **three methods** to export/import mailboxes as PST. Choose based on your situation:

| Method | Best for | Pros | Cons |
|--------|----------|------|------|
| **A. Compliance Content Search + eDiscovery Export** | Large-scale (50+ users), server-side | No Outlook needed, handles large mailboxes, can export multiple at once | Requires eDiscovery permissions, uses Azure blob storage, slower for single mailboxes |
| **B. Outlook PST Export** | Small-scale (< 20 users), simple | Simple, well-known process | Requires Outlook installed, limited by client memory for large mailboxes, one-by-one |
| **C. Third-party tool** | Enterprise migrations | Feature-rich, fast, delta sync | Costs money (BitTitan MigrationWiz, Quest, etc.) |

---

### Method A — Compliance Content Search Export (Recommended for 20+ users)

#### A.1 — Assign the Mailbox Import Export Role

**Why**: This role is required to export search results as PST. It's NOT included in any default admin role, not even Global Admin.

```powershell
# On SOURCE Exchange Online — assign the role to yourself
Connect-ExchangeOnline  # (source tenant)

# Check if the role group exists  
Get-ManagementRoleAssignment -Role "Mailbox Import Export" -GetEffectiveUsers

# Add yourself to the role (or create an assignment)
New-ManagementRoleAssignment -Role "Mailbox Import Export" -User "admin@source.onmicrosoft.com"

# IMPORTANT: You must disconnect and reconnect for the role to take effect
Disconnect-ExchangeOnline -Confirm:$false
# Wait 15-30 minutes, then reconnect
Connect-ExchangeOnline
```

> **Warning**: It can take **up to 60 minutes** for the role assignment to propagate. If the export option is grayed out in the Compliance Portal, wait and try again.

#### A.2 — Create a Content Search for Each User (or All Users)

- [ ] Go to the **Microsoft Purview Compliance Portal**: https://compliance.microsoft.com
- [ ] Navigate to **Content search** (or **eDiscovery > Standard**)
- [ ] Click **New search**
- [ ] Name: e.g., `Migration - John Doe`
- [ ] In **Locations**, select **Exchange mailboxes** > Choose specific mailboxes > Add the user
- [ ] In **Conditions**, leave empty (to export everything) or add date filters if needed
- [ ] Click **Submit** and wait for the search to complete

Or via PowerShell:

```powershell
# Connect to Security & Compliance PowerShell
Connect-IPPSSession

# Create a search for one user
New-ComplianceSearch `
    -Name "Migration-JohnDoe" `
    -ExchangeLocation "john.doe@contoso.com" `
    -Description "Full mailbox export for migration"

# Start the search
Start-ComplianceSearch -Identity "Migration-JohnDoe"

# Check status (wait for Completed)
Get-ComplianceSearch -Identity "Migration-JohnDoe" | Select-Object Name, Status, Items, Size
```

> **Tip**: You can create one search per user, or one search with multiple mailboxes. For large migrations, one search per user gives you more granular control.

#### A.3 — Export Search Results as PST

**Via the Compliance Portal (recommended)**:

- [ ] After the search completes, click on it and choose **Actions > Export results**
- [ ] Export settings:
  - Output options: **All items, excluding ones that have unrecognized format**
  - Export Exchange content as: **One PST file for each mailbox**
- [ ] Click **Export**
- [ ] Go to the **Exports** tab, click on your export, click **Download results**
- [ ] The **eDiscovery Export Tool** opens — enter the export key and choose a download folder
- [ ] Files are downloaded as `.pst` files

Or via PowerShell:

```powershell
# Create the export action
New-ComplianceSearchAction -SearchName "Migration-JohnDoe" -Export -Format FxStream -ExchangeArchiveFormat PerUserPst

# Check export status
Get-ComplianceSearchAction -Identity "Migration-JohnDoe_Export" | Select-Object Name, Status, Results
```

> **Note**: The PST download requires the **eDiscovery Export Tool** (a ClickOnce application that runs in Internet Explorer/Edge Legacy). It only works on Windows and may require IE mode in Edge.

> 📖 [Export Content Search results](https://learn.microsoft.com/en-us/purview/ediscovery-export-search-results)

#### A.4 — Import PST into Target Mailbox

**Via the Microsoft Purview Compliance Portal (TARGET tenant)**:

- [ ] Go to https://compliance.microsoft.com (logged into the **TARGET** tenant)
- [ ] Navigate to **Data lifecycle management > Microsoft 365 > Import**
- [ ] Click **New import job**
- [ ] Choose **Upload your data**
- [ ] The portal generates an **Azure blob storage SAS URL** — use it to upload the PST files via `AzCopy` or Azure Storage Explorer

```powershell
# Download AzCopy if you don't have it: https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10

# Upload PST files to the Azure blob storage
# The SAS URL is provided by the import job wizard
azcopy copy "C:\PSTExports\*.pst" "https://<blob-url>/<container>?<sas-token>" --recursive
```

- [ ] Create a **CSV mapping file** that tells the import service which PST goes to which mailbox:

```csv
Workload,FilePath,Name,Mailbox,IsArchive,TargetRootFolder,ContentCodePage,SPFileContainer,SPManifestContainer,SPSiteUrl
Exchange,,john_doe.pst,john.doe@target.onmicrosoft.com,FALSE,/,,,,
Exchange,,jane_smith.pst,jane.smith@target.onmicrosoft.com,FALSE,/,,,,
```

- [ ] Upload the CSV mapping file in the import wizard
- [ ] Validate the mapping — the portal checks if PST files exist in blob storage and if target mailboxes exist
- [ ] Click **Import** to start the import job
- [ ] Monitor progress in the Import page

> **Important**: 
> - The `TargetRootFolder` of `/` imports into the root of the mailbox (preserving folder structure from the PST)
> - To import into a subfolder (e.g., `Migrated Mail`), set `TargetRootFolder` to `/Migrated Mail`
> - The import can take hours to days depending on PST size

> 📖 [Import PST files to Microsoft 365](https://learn.microsoft.com/en-us/purview/importing-pst-files-to-office-365)
>
> 📖 [Use network upload to import PST files](https://learn.microsoft.com/en-us/purview/use-network-upload-to-import-pst-files)

---

### Method B — Outlook PST Export (Small scale, < 20 users)

#### B.1 — Export from Outlook (Source)

For each user, or using an admin account with Full Access to the mailboxes:

- [ ] Open **Outlook** (desktop app, not new Outlook) connected to the **SOURCE** tenant
- [ ] Go to **File > Open & Export > Import/Export**
- [ ] Choose **Export to a file** > **Outlook Data File (.pst)**
- [ ] Select the mailbox root (include subfolders)
- [ ] Choose a save location, e.g., `C:\PSTExports\john_doe.pst`
- [ ] Set a password if desired (or leave blank)
- [ ] Click **Finish** and wait for the export to complete

> **Alternative via PowerShell (if you have Full Access)**:
> ```powershell
> # Grant yourself Full Access to a user's mailbox on SOURCE
> Connect-ExchangeOnline  # (source tenant)
> Add-MailboxPermission -Identity "john.doe@contoso.com" -User "admin@source.onmicrosoft.com" -AccessRights FullAccess -AutoMapping $false
> ```
> Then add the mailbox as an additional account in Outlook and export it.

#### B.2 — Import into Outlook (Target)

- [ ] Open **Outlook** connected to the **TARGET** tenant (the user's new mailbox)
- [ ] Go to **File > Open & Export > Import/Export**
- [ ] Choose **Import from another program or file** > **Outlook Data File (.pst)**
- [ ] Browse to the PST file
- [ ] Options:
  - **Replace duplicates with items imported** — Overwrites if same item exists
  - **Allow duplicates to be created** — Safer, but may create duplicates
  - **Do not import duplicates** — Skips existing items
- [ ] Select to import into the current mailbox
- [ ] Click **Finish** and wait

> **Tip**: For shared mailboxes, room mailboxes, or equipment mailboxes, you can grant yourself Full Access on both sides and use Outlook to export/import.

---

### Method C — Third-Party Tools

If you have budget, tools like **BitTitan MigrationWiz**, **Quest On Demand Migration**, or **AvePoint** can:

- Migrate mailboxes directly between tenants (tenant-to-tenant) without PST
- Handle delta sync (migrate changes that happened after the initial copy)
- Migrate calendars, contacts, rules, and permissions
- Provide a web-based dashboard with progress tracking

These tools work by using EWS (Exchange Web Services) or Graph API to read from the source and write to the target.

> 📖 [BitTitan MigrationWiz](https://www.bittitan.com/migrationwiz/)
>
> 📖 [Quest On Demand Migration](https://www.quest.com/products/on-demand-migration/)

---

## Phase 4 — Migrate OneDrive Data (Manual Copy)

> **Goal**: Copy each user's OneDrive files from the source tenant to the target tenant.

There are **three methods**:

| Method | Best for | Pros | Cons |
|--------|----------|------|------|
| **A. SharePoint Migration Tool (SPMT)** | Medium/large scale, bulk copy | Preserves metadata, handles permissions, batch mode | Requires Windows, setup time |
| **B. OneDrive Sync Client** | Small scale, simple | Built in, familiar | Manual per-user, no metadata preservation |
| **C. Browser download/upload** | Very small scale (< 5 users) | Zero tools needed | Slow, no metadata, 250 file limit per download |

---

### Method A — SharePoint Migration Tool (SPMT) — Recommended

**Why SPMT**: It can copy OneDrive content from one tenant to another while preserving file metadata (modified dates, author info). It supports bulk migration and retry logic.

#### A.1 — Install SPMT

- [ ] Download from: https://learn.microsoft.com/en-us/sharepointmigration/introducing-the-sharepoint-migration-tool
- [ ] Install on a Windows machine with good network connectivity
- [ ] Sign in with a **SharePoint Administrator** account on the **TARGET** tenant

#### A.2 — Grant Access to Source OneDrive Sites

**Why**: You need read access to each user's OneDrive on the SOURCE tenant.

```powershell
# On SOURCE SharePoint — grant yourself (or a service account) access to each user's OneDrive
Connect-SPOService -Url "https://source-admin.sharepoint.com"

# For each user:
$siteUrl = "https://source-my.sharepoint.com/personal/john_doe_contoso_com"
Set-SPOUser -Site $siteUrl -LoginName "admin@source.onmicrosoft.com" -IsSiteCollectionAdmin $true
```

> **Note**: OneDrive site URLs follow the pattern: `https://{tenant}-my.sharepoint.com/personal/{upn_with_underscores}` where dots and `@` are replaced with underscores.

#### A.3 — Run SPMT Migration

In the SPMT interface:

- [ ] Choose **SharePoint** as migration source type (OneDrive is treated as SharePoint)
- [ ] Sign in to the source tenant when prompted
- [ ] Source URL: the user's OneDrive URL (e.g., `https://source-my.sharepoint.com/personal/john_doe_contoso_com`)
- [ ] Source document library: `Documents`
- [ ] Sign in to the target tenant
- [ ] Target URL: the user's OneDrive URL on the TARGET (e.g., `https://target-my.sharepoint.com/personal/john_doe_target_onmicrosoft_com`)
- [ ] Target document library: `Documents`
- [ ] Click **Migrate**

You can add multiple users in a single migration task using a **bulk JSON or CSV file**.

**SPMT bulk CSV format**:

```csv
Source,SourceDocLib,SourceSubFolder,TargetWeb,TargetDocLib,TargetSubFolder
https://source-my.sharepoint.com/personal/john_doe_contoso_com,Documents,,https://target-my.sharepoint.com/personal/john_doe_target_onmicrosoft_com,Documents,
https://source-my.sharepoint.com/personal/jane_smith_contoso_com,Documents,,https://target-my.sharepoint.com/personal/jane_smith_target_onmicrosoft_com,Documents,
```

> 📖 [SharePoint Migration Tool overview](https://learn.microsoft.com/en-us/sharepointmigration/introducing-the-sharepoint-migration-tool)
>
> 📖 [Migrate to OneDrive using SPMT](https://learn.microsoft.com/en-us/sharepointmigration/migrating-content-to-onedrive-for-business)

#### A.4 — Verify Migration

After SPMT completes:

- [ ] Check the SPMT reports for errors or skipped files
- [ ] Have users log into their target OneDrive and verify files are present
- [ ] Check file counts match between source and target

---

### Method B — OneDrive Sync Client (Small scale)

#### B.1 — Sync Source OneDrive Locally

On the user's PC (or an admin workstation):

- [ ] Open a browser, sign into `https://source-my.sharepoint.com` with the SOURCE account
- [ ] Click **Sync** — this opens the OneDrive sync client and syncs all files to a local folder (e.g., `C:\Users\john\OneDrive - Source Company\`)
- [ ] Wait for sync to complete (green checkmarks on all files)

#### B.2 — Copy Files to Target OneDrive

- [ ] Sign into the TARGET tenant's OneDrive: `https://target-my.sharepoint.com`
- [ ] Click **Sync** to set up sync for the target OneDrive (syncs to `C:\Users\john\OneDrive - Target Company\`)
- [ ] **Copy** all files from the source sync folder to the target sync folder:

```powershell
# Copy all files preserving folder structure
$source = "C:\Users\john\OneDrive - Source Company"
$target = "C:\Users\john\OneDrive - Target Company"

Copy-Item -Path "$source\*" -Destination $target -Recurse -Force
```

- [ ] Wait for the OneDrive sync client to upload everything (watch the sync icon in the system tray)

> **Warning:**
> - This does **not preserve file metadata** (modified dates will be set to the copy date)
> - Files shared with other users will lose their sharing links
> - Large syncs can take hours on slow connections

---

### Method C — Browser Download/Upload (Very small scale)

For a handful of users with very little data:

- [ ] Sign into source OneDrive in a browser
- [ ] Select all files > **Download** (creates a ZIP file)
- [ ] Sign into target OneDrive in a browser
- [ ] Click **Upload > Folder** and upload the extracted contents

> **Limitations**:
> - Browser download has a **250 file / 10 GB** limit per download
> - No metadata preservation
> - Very slow for large volumes
> - Manual and error-prone

---

## Phase 5 — Migrate SharePoint Sites (Manual)

> SharePoint sites are more complex than OneDrive because they include lists, libraries, pages, web parts, permissions, workflows, and site settings.

### Option A — SharePoint Migration Tool (SPMT)

SPMT can also migrate SharePoint site content:

- [ ] Source: `https://source.sharepoint.com/sites/TeamSite`
- [ ] Target: Create the same site structure first on the target
- [ ] SPMT copies document libraries, lists, and list items

```powershell
# Create the target site first (on TARGET SharePoint)
Connect-SPOService -Url "https://target-admin.sharepoint.com"

New-SPOSite `
    -Url "https://target.sharepoint.com/sites/TeamSite" `
    -Title "Team Site" `
    -Owner "admin@target.onmicrosoft.com" `
    -Template "STS#3" `
    -StorageQuota 26214400
```

Then use SPMT to copy content from source site to target site.

> **SPMT limitations for SharePoint**:
> - Does NOT migrate site pages, web parts, or site settings
> - Does NOT migrate workflows (Power Automate flows)
> - Does NOT migrate permissions (sets everything to inherited)
> - Custom columns and content types may need manual recreation

### Option B — Manual Download/Upload

For small sites:

- [ ] Download document libraries as ZIP (SharePoint > Library > Download)
- [ ] Upload to the target site
- [ ] Manually recreate lists, views, and permissions

### Option C — Third-Party Tools (ShareGate, AvePoint)

For enterprise SharePoint migrations without cross-tenant licenses, tools like **ShareGate** or **AvePoint** are the most reliable option:

- Copy documents, lists, sites, pages, web parts
- Preserve permissions and metadata
- Handle site templates and content types
- Support incremental/delta migration

> 📖 [ShareGate](https://www.sharegate.com/)
>
> 📖 [AvePoint Cloud Migration](https://www.avepoint.com/products/cloud/cloud-migration)

---

## Phase 6 — Post-Migration Cleanup & DNS Cutover

### 6.1 — Verify All Data

- [ ] **Mailboxes**: Have users check that all emails, calendar items, and contacts are present in the target mailbox
  - Check folder structure
  - Check sent items
  - Check calendar entries
  - Check contacts (personal contacts in the mailbox, not mail contacts)
- [ ] **OneDrive**: Have users verify all files are present in target OneDrive
  - Check file counts
  - Check important files can be opened
  - Check sharing links (they will be broken — users need to re-share)
- [ ] **Groups**: All group memberships are correct
- [ ] **Contacts**: Mail contacts appear in the GAL

### 6.2 — Set Up Mail Forwarding (Transition Period)

**Why**: During the transition period, mail sent to the source addresses should be forwarded to the target mailboxes so nothing is lost.

```powershell
# On SOURCE Exchange Online
Connect-ExchangeOnline  # (source tenant)

# For each migrated user — set up forwarding to the target address
Set-Mailbox -Identity "john.doe@contoso.com" `
    -ForwardingSmtpAddress "john.doe@target.onmicrosoft.com" `
    -DeliverToMailboxAndForward $false  # $false = only forward, $true = keep a copy in source too
```

> **Tip**: Set `-DeliverToMailboxAndForward $true` initially so you have a safety net. Switch to `$false` once you're confident the target is working correctly.

### 6.3 — Handle Distribution Groups

**Why**: If you had distribution groups sending to the source addresses, you need to recreate them in the target.

```powershell
# On TARGET Exchange Online
Connect-ExchangeOnline  # (target tenant)

# Create distribution group
New-DistributionGroup `
    -Name "Sales Team" `
    -Alias "salesteam" `
    -PrimarySmtpAddress "salesteam@target.onmicrosoft.com" `
    -MemberJoinRestriction Closed

# Add members
Add-DistributionGroupMember -Identity "salesteam" -Member "john.doe@target.onmicrosoft.com"
Add-DistributionGroupMember -Identity "salesteam" -Member "jane.smith@target.onmicrosoft.com"
```

### 6.4 — DNS Cutover (if changing domains)

If you're moving the custom domain from SOURCE to TARGET:

- [ ] **Reduce TTL** on all DNS records to 300 seconds (5 minutes) — do this 48 hours before cutover

- [ ] **Remove the domain from the SOURCE tenant**:
  - Remove all user UPN references to the domain (switch users to `@source.onmicrosoft.com`)
  - Remove the domain from Exchange accepted domains
  - Remove the domain from Entra ID > Settings > Domains

```powershell
# On SOURCE — Switch users to onmicrosoft.com UPN before removing the domain
Connect-MgGraph -TenantId "source.onmicrosoft.com" -Scopes "User.ReadWrite.All"

# For each user:
Update-MgUser -UserId "john.doe@contoso.com" -UserPrincipalName "john.doe@source.onmicrosoft.com"
```

- [ ] **Add and verify the domain on the TARGET tenant**:
  - Entra admin center > Settings > Domains > Add domain
  - Add the required DNS TXT record for verification
  - Wait for verification to complete

- [ ] **Update DNS records** to point to the TARGET tenant:

| Record | Type | Value |
|--------|------|-------|
| **MX** | MX | `target-com.mail.protection.outlook.com` (check Exchange admin center for exact value) |
| **autodiscover** | CNAME | `autodiscover.outlook.com` |
| **SPF** | TXT | `v=spf1 include:spf.protection.outlook.com -all` |
| **DKIM** | CNAME | Two CNAME records (get from Exchange admin center > Authentication > DKIM) |
| **DMARC** | TXT | `v=DMARC1; p=quarantine; rua=mailto:dmarc@contoso.com` |

- [ ] **Update user UPNs on the TARGET** to use the custom domain:

```powershell
# On TARGET
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "User.ReadWrite.All"

# For each user:
Update-MgUser -UserId "john.doe@target.onmicrosoft.com" -UserPrincipalName "john.doe@contoso.com"
```

- [ ] **Update Exchange proxy addresses** on the TARGET:

```powershell
# On TARGET Exchange Online
Connect-ExchangeOnline  # (target tenant)

# Set the custom domain as primary SMTP for each user
Set-Mailbox -Identity "john.doe@target.onmicrosoft.com" `
    -PrimarySmtpAddress "john.doe@contoso.com" `
    -EmailAddresses @{Add="smtp:john.doe@target.onmicrosoft.com"}
```

### 6.5 — Remove Source Forwarding

Once DNS has propagated and all mail flows to the target:

```powershell
# On SOURCE — remove forwarding
Connect-ExchangeOnline  # (source tenant)
Set-Mailbox -Identity "john.doe@source.onmicrosoft.com" -ForwardingSmtpAddress $null
```

### 6.6 — Clean Up Compliance Search Exports

```powershell
# On SOURCE — clean up eDiscovery searches and exports
Connect-IPPSSession

# Remove export actions
Get-ComplianceSearchAction | Where-Object { $_.Name -like "Migration*" } | Remove-ComplianceSearchAction -Confirm:$false

# Remove searches
Get-ComplianceSearch | Where-Object { $_.Name -like "Migration*" } | Remove-ComplianceSearch -Confirm:$false
```

### 6.7 — Communicate to End Users

Send a migration completion email with:

- [ ] New Outlook profile setup instructions (users may need to recreate their Outlook profile)
- [ ] New password (if applicable)
- [ ] Reminder that shared links to OneDrive/SharePoint files are broken and need to be re-shared
- [ ] IT support contact for issues
- [ ] Timeline: when the old tenant will be decommissioned

> **Outlook profile note**: After a domain move, users' Outlook may not auto-discover the new mailbox. They may need to:
> 1. Close Outlook
> 2. Go to **Control Panel > Mail > Show Profiles**
> 3. Remove the old profile
> 4. Create a new one
> 5. Outlook auto-discovers the new mailbox

---

## Quick Reference

### Estimated Timelines

| Task | Time Estimate |
|------|--------------|
| Phase 1 (Inventory) | 1-2 hours |
| Phase 2 (Identity provisioning) | 2-4 hours (depending on user count) |
| Phase 3 (Mailbox PST export) | 1-2 hours per 10 GB of mailbox data |
| Phase 3 (PST upload + import) | 1-3 hours per 10 GB |
| Phase 4 (OneDrive via SPMT) | 1-2 hours per 10 GB |
| Phase 4 (OneDrive via sync client) | Highly variable — depends on connection speed |
| Phase 6 (DNS cutover) | 30 min setup + 24-48 hours propagation |

### Comparison: Licensed vs. Non-Licensed Migration

| Aspect | With Cross-Tenant License | Without (PST/Manual) |
|--------|---------------------------|----------------------|
| **Mailbox downtime** | Minutes (cutover) | Hours to days |
| **Data fidelity** | 100% (server-side copy) | 95%+ (PST preserves most data, some rules/permissions may be lost) |
| **OneDrive metadata** | Preserved | Lost (unless using SPMT) |
| **Sharing links** | Broken (both methods) | Broken (both methods) |
| **Effort per user** | ~15 min setup once, then automated | ~30-60 min per user (export + import) |
| **Cost** | License cost (~$0/user with E5, or add-on) | Free (built-in tools) or third-party tool cost |
| **Automation** | High (batch operations) | Low (mostly manual) |

### Key Microsoft Documentation

| Topic | Link |
|-------|------|
| Export Content Search results (PST) | https://learn.microsoft.com/en-us/purview/ediscovery-export-search-results |
| Import PST files to Microsoft 365 | https://learn.microsoft.com/en-us/purview/importing-pst-files-to-office-365 |
| Network upload for PST import | https://learn.microsoft.com/en-us/purview/use-network-upload-to-import-pst-files |
| SharePoint Migration Tool (SPMT) | https://learn.microsoft.com/en-us/sharepointmigration/introducing-the-sharepoint-migration-tool |
| Migrate to OneDrive with SPMT | https://learn.microsoft.com/en-us/sharepointmigration/migrating-content-to-onedrive-for-business |
| AzCopy download | https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10 |
| Create users in Entra ID | https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-users |
| Assign M365 licenses | https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users?view=o365-worldwide |
| Manage mail contacts in EXO | https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-mail-contacts |

### Admin Portals

| Portal | URL |
|--------|-----|
| **Entra admin center** | https://entra.microsoft.com |
| **Microsoft Purview Compliance** | https://compliance.microsoft.com |
| **Microsoft 365 admin center** | https://admin.microsoft.com |
| **Exchange admin center** | https://admin.exchange.microsoft.com |
| **SharePoint admin center** | https://{tenant}-admin.sharepoint.com |

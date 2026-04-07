# Entra ID Simple Tenant Migration Tool

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [How the Tool Works](#how-the-tool-works)
- [Phase 1 - Discovery](#phase-1---discovery)
- [Phase 2 - Identity Preparation](#phase-2---identity-preparation)
- [Phase 3 - Exchange Migration Plan](#phase-3---exchange-migration-plan)
- [Phase 4 - Exchange Migration Execution](#phase-4---exchange-migration-execution)
- [Phase 5 - OneDrive Migration Plan](#phase-5---onedrive-migration-plan)
- [Phase 6 - OneDrive Migration Execution](#phase-6---onedrive-migration-execution)
- [Phase 7 - SharePoint Migration Plan](#phase-7---sharepoint-migration-plan)
- [Phase 8 - SharePoint Migration Execution](#phase-8---sharepoint-migration-execution)
- [Configuration Reference](#configuration-reference)
- [Run Management & Resumability](#run-management--resumability)
- [Troubleshooting](#troubleshooting)
- [Useful Links](#useful-links)

---

## Introduction

The **Entra ID Simple Tenant Migration Tool** is an interactive PowerShell orchestrator that migrates an entire Microsoft 365 tenant (the **SOURCE**) into another tenant (the **TARGET**). It covers three core workloads:

| Workload | Status |
|----------|--------|
| **User identity provisioning** (AD-synced, cloud-only, guests, groups, contacts) | Available |
| **Exchange Online mailbox migration** (cross-tenant) | Available |
| **OneDrive for Business content migration** (cross-tenant) | Available |
| **SharePoint Online site migration** | Available |

The tool is designed around a **step engine** that records progress after every step. If something fails or needs manual intervention, you can fix the issue and **resume exactly where you left off** — no need to re-run completed steps.

Every step produces **CSV files** that serve as both audit trail and data pipeline between phases. Before any destructive action, the tool opens the CSV in Notepad so the operator can review and edit the plan.

### Why use this tool instead of doing it manually?

A cross-tenant migration involves dozens of interconnected operations across multiple admin portals (Entra ID, Exchange Online, SharePoint Online, on-premises Active Directory). Each operation must be performed in a specific order and depends on data from previous steps. This tool:

- **Eliminates manual errors** by automating each step with proper validation
- **Provides full auditability** through CSV exports at every stage
- **Enables safe operator review** before any write operation
- **Handles resumability** so a multi-day migration can be paused and continued
- **Manages connections** to six different endpoints (Graph + EXO + SPO, each for Source and Target)

---

## Prerequisites

### PowerShell Version

- **PowerShell 5.1** (Windows PowerShell) — required. The tool uses `#requires -Version 5.1`.

### PowerShell Modules

The tool automatically checks and installs these modules on first run via `Ensure-EIDMPrerequisites`:

| Module | Purpose |
|--------|---------|
| `Microsoft.Graph.Authentication` | Authenticate to Microsoft Graph API |
| `Microsoft.Graph.Identity.DirectoryManagement` | Read domains, organization info |
| `Microsoft.Graph.Users` | Read/create users |
| `Microsoft.Graph.Users.Actions` | Assign licenses |
| `Microsoft.Graph.Groups` | Read/create groups |
| `Microsoft.Graph.Identity.SignIns` | Sign-in configuration |
| `Microsoft.Graph.Applications` | Register apps, manage service principals |
| `ExchangeOnlineManagement` | Exchange Online PowerShell cmdlets |
| `Microsoft.Online.SharePoint.PowerShell` | SharePoint Online administration |

### On-Premises Active Directory (optional)

If the **IdentityPreparation** workload is enabled (for migrating AD-synced users), you also need:

- **RSAT Active Directory module** — Install via Windows Features: *RSAT > Active Directory Domain Services and LDAP Tools*
- **Network connectivity** to a Domain Controller
- **Permissions** to create users, groups, and modify AD forest UPN suffixes

> **Manual equivalent**: Open *Server Manager > Add Roles and Features > RSAT > AD DS and Lightweight Directory Tools*, or run:
> ```powershell
> Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
> ```

### Admin Permissions Required

| Service | Permission Level |
|---------|-----------------|
| **Entra ID (Source)** | Global Reader (for Discovery) |
| **Entra ID (Target)** | Global Administrator (to create users, apps, assign licenses) |
| **Exchange Online (Source)** | Exchange Administrator (for org relationships, scoping groups) |
| **Exchange Online (Target)** | Exchange Administrator (for migration endpoints, batches) |
| **SharePoint Online (Source & Target)** | SharePoint Administrator (for cross-tenant trust, OneDrive moves) |
| **On-premises AD (Target forest)** | Domain Admin or delegated OU admin |

### Licensing Requirements

- **Cross-Tenant User Data Migration** license (or equivalent, e.g. included in some E5 plans) -- required on **both** tenants for Exchange and OneDrive migration
- **Cross-Tenant Shared Data Migration** license -- required for SharePoint site migration (separate from the User Data Migration license). Sold per 100 GB of data moved. Must be assigned to at least one user on either SOURCE or TARGET tenant. Only available to Enterprise Agreement (EA) customers.
- **Exchange Online** licenses in the TARGET tenant -- needed post-migration so users can access their mailboxes
- **OneDrive/SharePoint** licenses in the TARGET tenant -- needed before OneDrive migration so personal sites can be provisioned

> See: [Microsoft 365 cross-tenant mailbox migration prerequisites](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret)

---

## Getting Started

### 1. Clone or copy the tool

Copy the entire folder to a working directory (e.g., `C:\Temp\Entra ID Simple Tenant Migration Tool\`).

### 2. Create the configuration

Run the entry point:

```powershell
.\Start-EIDMigrationTool.ps1
```

On first run, the tool detects that no `config\config.psd1` exists and launches the **Configuration Wizard**. It asks for:

- **Source tenant** domain (e.g., `contoso.onmicrosoft.com`)
- **Target tenant** domain (e.g., `fabrikam.onmicrosoft.com`)
- **Which workloads** to enable (Discovery, Identity Preparation, Exchange Migration, OneDrive Migration, SharePoint Migration)
- **Output root** path for run data (default: `.\output\runs`)

On subsequent runs, you see a configuration lifecycle menu:

| Option | Description |
|--------|-------------|
| **Use** | Load existing config and continue |
| **View** | Display current config without modifying |
| **Edit** | Modify specific settings |
| **Recreate** | Start the config wizard from scratch |

### 3. Start or resume a run

From the main menu:

| Option | Description |
|--------|-------------|
| **1 - Start a new run** | Creates a timestamped folder (e.g., `output/runs/2025-01-15_143022/`) with subfolders for each phase |
| **2 - Resume an existing run** | Lists previous run folders and lets you pick one to continue |
| **3 - View run status** | Shows a table of all steps and their current status (Completed, Failed, InProgress, WaitingUser) |
| **4 - Execute a phase** | Opens the phase selection menu to run a specific migration phase |
| **5 - Exit** | Quit the tool |

### 4. Execute phases in order

The recommended order is:

1. **Discovery** — Read-only inventory of the source tenant
2. **Identity Preparation** — Create users, groups, guests, and contacts in the target
3. **Exchange Migration Plan** — Set up cross-tenant mailbox migration infrastructure
4. **Exchange Migration Execution** — Run and monitor migration batches
5. **OneDrive Migration Plan** — Set up cross-tenant OneDrive trust and mappings
6. **OneDrive Migration Execution** — Run and monitor OneDrive content moves
7. **SharePoint Migration Plan** — Discover sites, build mapping, verify trust and compatibility
8. **SharePoint Migration Execution** — Run and monitor SharePoint site moves

---

## How the Tool Works

### Step Engine

Every phase is composed of **steps** defined as PowerShell hashtables:

```powershell
@{
    Id       = "Discovery-ExportUsers-Source"
    Phase    = "01-Discovery"
    Handler  = { param($Ctx) Invoke-DiscoveryExportUsersSource -Ctx $Ctx }
    Requires = @("GraphSource")
}
```

The step engine (`Invoke-EIDMPhase` / `Invoke-EIDMStep` in `lib/00-Core.Functions.ps1`):

1. Checks whether the step was already **Completed** in the run state file — if so, skips it
2. Resolves **dependencies** (e.g., `GraphSource` → authenticates to Microsoft Graph on the source tenant)
3. Records **InProgress** in the state file
4. Runs the handler function
5. Records **Completed** or **Failed**
6. On failure, stops the phase so you can investigate and resume later

### Connection Management

The tool manages six independent connections:

| Connection | How it authenticates | Validation |
|------------|---------------------|------------|
| **GraphSource** | `Connect-MgGraph -TenantId <source>` with interactive login | Checks `Get-MgContext` tenant ID |
| **GraphTarget** | `Connect-MgGraph -TenantId <target>` with interactive login | Checks `Get-MgContext` tenant ID |
| **ExchangeSource** | `Connect-ExchangeOnline` | `Get-OrganizationConfig` |
| **ExchangeTarget** | `Connect-ExchangeOnline` | `Get-OrganizationConfig` |
| **SharePointSource** | `Connect-SPOService -Url <source-admin-url>` | `Get-SPOTenant` |
| **SharePointTarget** | `Connect-SPOService -Url <target-admin-url>` | `Get-SPOTenant` |

> **Important**: Only one Graph/EXO/SPO connection can be active at a time. When a step requires switching sides (e.g., from Source to Target), the tool disconnects and reconnects automatically.

### CSV-Based Workflow

All data flows between phases through CSV files stored in the run folder. This design:

- Makes every intermediate result **inspectable and editable**
- Allows the operator to **modify plans** before execution (e.g., change a user's target UPN)
- Provides a **complete audit trail** of what was discovered, planned, and executed
- Enables **Plan → Review → Execute** triads where the operator validates each CSV before the tool acts on it

---

## Phase 1 — Discovery

**Purpose**: Build a complete, read-only inventory of the SOURCE tenant. No modifications are made to either tenant.

**Why**: Before migrating anything, you need to know exactly what exists — users, groups, mailboxes, OneDrive sites, mail contacts, etc. This inventory becomes the foundation for all subsequent planning steps.

**Output folder**: `<RunRoot>/01-Discovery/`

### Steps

#### 1.1 — Export Entra ID Users

| | |
|-|-|
| **Step ID** | `Discovery-ExportUsers-Source` |
| **Connection** | Microsoft Graph (Source) |
| **Output** | `EntraUsers_SOURCE.csv` |

Exports all Entra ID users from the source tenant using `Get-MgUser -All` with 25+ properties: UserPrincipalName, DisplayName, Mail, ProxyAddresses, OnPremisesSyncEnabled, AssignedLicenses, Department, JobTitle, etc.

> **Manual equivalent**: Go to [Entra admin center](https://entra.microsoft.com) > Users > All Users > Download Users, or run:
> ```powershell
> Connect-MgGraph -TenantId "source.onmicrosoft.com" -Scopes "User.Read.All"
> Get-MgUser -All -Property Id,UserPrincipalName,DisplayName,Mail,ProxyAddresses,OnPremisesSyncEnabled,AccountEnabled,AssignedLicenses | Export-Csv .\users.csv -NoTypeInformation
> ```

#### 1.2 — Export Domains

| | |
|-|-|
| **Step ID** | `Discovery-ExportDomains-Source` |
| **Connection** | Microsoft Graph (Source) |
| **Output** | `EntraDomains_SOURCE.csv` |

Exports all verified and unverified domains via `Get-MgDomain -All`.

> **Why**: You need the domain list to plan UPN suffix mapping. If users in the source are `user@contoso.com`, you need to decide what their UPN will be in the target tenant.

> **Manual equivalent**: Entra admin center > Settings > Domain names

#### 1.3 — Export Groups

| | |
|-|-|
| **Step ID** | `Discovery-ExportGroups-Source` |
| **Connection** | Microsoft Graph (Source) |
| **Output** | `EntraGroups_SOURCE.csv` |

Exports all groups (Security, Microsoft 365, Distribution, Dynamic, Mail-enabled Security) via `Get-MgGroup -All`.

> **Manual equivalent**: Entra admin center > Groups > All groups > Download groups

#### 1.4 — Export Group Members

| | |
|-|-|
| **Step ID** | `Discovery-ExportGroupMembers-Source` |
| **Connection** | Microsoft Graph (Source) |
| **Output** | `EntraGroupMembers_SOURCE.csv` |

For each non-dynamic group, exports all members via `Get-MgGroupMember`. Dynamic groups are skipped because their membership is calculated from rules, not static assignments.

> **Why**: When recreating groups in the target, you need to know who belongs to which group so you can repopulate memberships.

#### 1.5 — Export Exchange Mailboxes

| | |
|-|-|
| **Step ID** | `Discovery-EXO-ExportMailboxes-Source` |
| **Connection** | Exchange Online (Source) |
| **Output** | `EXO-Mailboxes_SOURCE.csv` |

Exports all User, Shared, Room, and Equipment mailboxes with statistics (size, item count) via `Get-EXOMailbox` + `Get-EXOMailboxStatistics`.

> **Why**: This data is used later to identify which users need mailbox migration, determine the scope of the migration, and stamp target mail users with the source `ExchangeGuid`.

> **Manual equivalent**: Exchange admin center > Recipients > Mailboxes, or:
> ```powershell
> Connect-ExchangeOnline
> Get-EXOMailbox -ResultSize Unlimited | Select-Object UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, ExchangeGuid | Export-Csv .\mailboxes.csv -NoTypeInformation
> ```

#### 1.6 — Export Exchange Recipients

| | |
|-|-|
| **Step ID** | `Discovery-EXO-ExportRecipients-Source` |
| **Connection** | Exchange Online (Source) |
| **Output** | `EXO-Recipients_SOURCE.csv` |

Exports all mail-enabled recipients (excluding system mailboxes like DiscoveryMailbox) via `Get-EXORecipient`. This includes mailboxes, mail users, mail contacts, distribution groups, etc.

> **Why**: Provides a complete picture of all mail-enabled objects, which helps plan the Exchange migration and identify objects that might conflict in the target.

#### 1.7 — Export Mail Contacts

| | |
|-|-|
| **Step ID** | `Discovery-EXO-ExportMailContacts-Source` |
| **Connection** | Exchange Online (Source) |
| **Output** | `EXO-MailContacts_SOURCE.csv` |

Exports all mail contacts via `Get-MailContact -ResultSize Unlimited`. Mail contacts are external email addresses that appear in the Global Address List (GAL).

> **Why**: Mail contacts need to be recreated in the target tenant so the GAL remains complete after migration. Users expect to find external contacts (vendors, partners, etc.) in the address book.

> **Manual equivalent**: Exchange admin center > Recipients > Contacts, or:
> ```powershell
> Get-MailContact -ResultSize Unlimited | Select-Object DisplayName, Alias, ExternalEmailAddress, PrimarySmtpAddress | Export-Csv .\contacts.csv -NoTypeInformation
> ```

#### 1.8 — Export OneDrive Sites

| | |
|-|-|
| **Step ID** | `Discovery-SPO-ExportOneDriveSites-Source` |
| **Connection** | SharePoint Online (Source) |
| **Output** | `SPO-OneDriveSites_SOURCE.csv` |

Exports all OneDrive personal sites (URL, owner, quota, storage used) via `Get-SPOSite -IncludePersonalSite $true -Filter "Url -like '-my.sharepoint.com/personal'"`.

> **Why**: Identifies which users have OneDrive data and how much, so you can plan the OneDrive migration scope and estimate timelines.

#### 1.9 — Export SharePoint Sites

| | |
|-|-|
| **Step ID** | `Discovery-SPO-ExportSites-Source` |
| **Connection** | SharePoint Online (Source) |
| **Output** | `SPO-Sites_SOURCE.csv` |

Exports all SharePoint sites (excluding OneDrive personal sites) with hub association awareness via `Get-SPOSite -Limit All`.

> **Why**: Provides inventory for future SharePoint site migration planning.

---

## Phase 2 — Identity Preparation

**Purpose**: Create all user identities, groups, guests, and mail contacts in the TARGET tenant so they are ready to receive migrated data.

**Why**: Before you can migrate mailboxes or OneDrive content, the user accounts must already exist in the target tenant. Exchange cross-tenant migration requires target users to be **MailUser** objects (not full mailboxes), and OneDrive migration requires provisioned OneDrive sites.

**Output folder**: `<RunRoot>/02-IdentityPreparation/`

This phase uses a **Plan → Review → Execute** pattern for every object type:
1. **Plan**: The tool reads Discovery CSVs and builds a provisioning plan CSV
2. **Review**: The plan CSV opens in Notepad — the operator can edit it (change UPNs, mark rows as Skip, etc.)
3. **Execute**: The tool reads the reviewed plan and creates the objects

### On-Premises AD Users (Steps 02-01 to 02-03)

For users that are **synced from on-premises AD** (identified by `OnPremisesSyncEnabled = True` in the Discovery export).

#### 02-01 — Build Users On-Prem Provisioning Plan

Reads `EntraUsers_SOURCE.csv`, filters for synced users, and builds a provisioning plan. The tool:

- **Prompts for a target OU** where new users will be created
- **Maps UPN suffixes**: If source users have `@contoso.com` but the target forest doesn't have that UPN suffix, the tool offers to register it via `Set-ADForest -UPNSuffixes @{Add="contoso.com"}`
- **Cross-references with mailbox data** to detect which users have Exchange mailboxes (important for mail-enabling the AD account)

> **Manual equivalent**: You would need to manually list all synced users, decide their target UPN, verify the UPN suffix exists in the target AD forest, and prepare a spreadsheet with all the attribute mappings.

#### 02-02 — Confirm Users On-Prem Provisioning Plan Review

Opens the plan CSV in Notepad. The operator reviews each user and can:
- Change the `TargetUPN` or `TargetSAM`
- Set `ProvisioningAction` to `Skip` for users that shouldn't be migrated
- Verify attribute mappings (DisplayName, Department, etc.)

#### 02-03 — Create Users On-Prem

Creates AD users via `New-ADUser` with all mapped attributes (GivenName, Surname, Department, JobTitle, etc.). For users with mailboxes, sets mail-related attributes so Entra Connect will sync them as **MailUser** objects. Generates temporary passwords.

Outputs: `Users_OnPrem_ProvisioningPlan.csv`, `Users_OnPrem_CreationResults.csv`

> **Manual equivalent**: For each user, open Active Directory Users and Computers, create a new user in the target OU, fill in all attributes, and enable the account. For mail-enabled users, use ADSI Edit or PowerShell to set `mail`, `proxyAddresses`, `targetAddress` attributes.
>
> See: [Plan your Entra Connect sync](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)

### Cloud-Only Users (Steps 02-04 to 02-06)

For users that exist **only in Entra ID** (not synced from AD). Created directly in the target tenant via Microsoft Graph.

#### 02-04 — Build Cloud-Only Users Provisioning Plan

Filters `EntraUsers_SOURCE.csv` for non-synced, non-guest users. Builds plan with target UPN mapping.

#### 02-05 — Confirm Cloud-Only Users Provisioning Plan Review

Opens plan in Notepad for operator review.

#### 02-06 — Create Cloud-Only Users

Creates users in the target Entra ID via `New-MgUser` with a temporary password and `ForceChangePasswordNextSignIn = $true`.

Outputs: `Users_CloudOnly_ProvisioningPlan.csv`, `Users_CloudOnly_CreationResults.csv`

> **Manual equivalent**: Entra admin center > Users > New user > Create new user. Fill in all fields for each user.
>
> See: [Create a user in Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-users)

### Guest Users (Steps 02-07 to 02-09)

For **B2B guest** users (`#EXT#` accounts) from the source tenant.

#### 02-07 — Build Guests Provisioning Plan

Filters for guest users and builds an invitation plan.

#### 02-08 — Confirm Guests Provisioning Plan Review

Opens plan in Notepad for operator review.

#### 02-09 — Create Guests

Invites guest users to the target tenant via `New-MgInvitation`.

> **Manual equivalent**: Entra admin center > Users > New user > Invite external user.
>
> See: [Invite B2B collaboration users](https://learn.microsoft.com/en-us/entra/external-id/add-users-administrator)

### On-Premises AD Groups (Steps 02-10 to 02-15)

For security and distribution groups that are synced from AD.

#### 02-10 / 02-11 / 02-12 — Plan, Review, Create Groups

Creates AD groups via `New-ADGroup` in the target AD forest.

#### 02-13 / 02-14 / 02-15 — Plan, Review, Apply Membership

Populates group memberships via `Add-ADGroupMember`, cross-referencing the source group membership data with the newly created target users.

### Cloud-Only Groups (Steps 02-16 to 02-21)

For groups that exist only in Entra ID (not synced from AD).

#### 02-16 / 02-17 / 02-18 — Plan, Review, Create Cloud Groups

Creates groups in the target Entra ID via `New-MgGroup`.

#### 02-19 / 02-20 / 02-21 — Plan, Review, Apply Cloud Membership

Populates cloud group memberships via `New-MgGroupMember`.

> **Manual equivalent**: Entra admin center > Groups > New group. Then add members manually.

### Entra Connect Scope Assessment (Step 02-22)

#### 02-22 — AAD Connect Scope Assessment

An interactive assessment that walks through the Entra Connect configuration checklist:

1. **Entra Connect installation**: Is Entra Connect (or Cloud Sync) installed and running?
2. **OU filtering**: Are the newly created OUs included in the Entra Connect sync scope?
3. **Sync cycle**: Has a sync cycle been triggered and confirmed? (`Start-ADSyncSyncCycle -PolicyType Delta`)
4. **Synchronization verification**: Has the operator verified that the synced objects appear correctly in the target Entra ID tenant?

The tool provides a **verdict** (OK / Action needed) based on the answers.

> **Why**: If the new OUs aren't in the Entra Connect scope, the on-prem users and groups will never sync to the target Entra ID. This is a critical checkpoint.
>
> **Manual equivalent**: Open **Entra Connect** > Configure > Customize synchronization options > Domain and OU filtering. Ensure new OUs are checked. Then run `Start-ADSyncSyncCycle -PolicyType Delta` and verify in the Entra admin center.
>
> See: [Configure Entra Connect sync filtering](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering)

### Mail Contacts (Steps 02-23 to 02-25)

For **mail contacts** (external email addresses in the Global Address List).

#### 02-23 — Build Contacts Provisioning Plan

Reads `EXO-MailContacts_SOURCE.csv` from Discovery. For each contact, checks whether it already exists in the target Exchange Online by matching on `ExternalEmailAddress`. Builds a plan with `ProvisioningAction = CreateInTarget` or `Skip`.

The tool normalizes aliases (removes invalid characters, ensures uniqueness) using the `Normalize-EIDMAlias` helper.

#### 02-24 — Confirm Contacts Provisioning Plan Review

Opens the plan in Notepad. The operator can change aliases, mark contacts as Skip, or adjust display names.

#### 02-25 — Recreate Contacts

Creates mail contacts in the target Exchange Online via `New-MailContact` with:
- DisplayName, Name, Alias
- ExternalEmailAddress (the external address that appears in the GAL)
- HiddenFromAddressListsEnabled (preserved from source)

Outputs: `Contacts_ProvisioningPlan.csv`, `Contacts_Provisioning_Results.csv`

> **Manual equivalent**: Exchange admin center > Recipients > Contacts > Add a mail contact. Fill in Name, Display name, Alias, and External email address for each contact.
>
> Or via PowerShell:
> ```powershell
> Connect-ExchangeOnline
> New-MailContact -Name "John Doe (External)" -DisplayName "John Doe" -ExternalEmailAddress "john@external.com" -Alias "johndoe"
> ```
>
> See: [Manage mail contacts in Exchange Online](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-mail-contacts)

---

## Phase 3 — Exchange Migration Plan

**Purpose**: Set up all the infrastructure needed for cross-tenant mailbox migration. This is the most complex setup phase, involving app registrations, organization relationships, and migration endpoints.

**Why**: Microsoft's cross-tenant mailbox migration requires a trust relationship between the two tenants, established through an Entra ID application, organization relationships, and migration endpoints. This phase automates all of that.

**Output folder**: `<RunRoot>/03-ExchangeMigrationPlan/`

> See: [Cross-tenant mailbox migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide)

### Step 03-01 — Exchange Migration Prerequisites

An interactive questionnaire that validates readiness:

| Question | What it checks |
|----------|---------------|
| Cross-Tenant User Data Migration licenses | Available on both tenants? |
| Admin permissions | Exchange Admin on both sides? |
| Mail-enabled security group for scoping | Exists on SOURCE? (If not, the tool offers to create one, e.g., `MAILBOXMIGRATION`) |
| Source Tenant ID | GUID of the source tenant |
| Target Tenant ID | GUID of the target tenant |
| Exchange Online licenses on TARGET | Available to assign post-migration? |

Answers are saved to `config.psd1` and to `ExchangeMigration_Prerequisites_Assessment.csv`.

> **Why**: If any prerequisite is missing, the subsequent steps will fail. Better to discover issues now.
>
> **Manual equivalent**: Check the [official prerequisites list](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret) and verify each item manually.

### Step 03-02 — Create Target Application

Creates the migration application in the **TARGET** Entra ID:

1. **App registration** — `New-MgApplication` with multi-tenant sign-in
2. **Service principal** — `New-MgServicePrincipal`
3. **Client secret** — `Add-MgApplicationPassword` (saved to config)
4. **Mailbox Migration app role** — Assigns the `Mailbox.Migration` permission from the Exchange Online service principal (`00000002-0000-0ff1-ce00-000000000000`)

> **Manual equivalent**: Entra admin center > App registrations > New registration:
> - Name: `Cross-Tenant Mailbox Migration`
> - Supported account types: Multitenant
> - Create a client secret
> - Go to API permissions > Add a permission > APIs my organization uses > Office 365 Exchange Online > Application permissions > `Mailbox.Migration`
> - Grant admin consent
>
> See: [Create the migration application](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret)

### Step 03-03 — Endpoint & Organization Relationships

Sets up the migration infrastructure on both sides:

**On the TARGET tenant**:
1. Creates a **Migration Endpoint** (`New-MigrationEndpoint -ExchangeRemoteMove`) pointing to the source tenant
2. Creates an **Inbound Organization Relationship** allowing the source to push mail data

**Admin consent**:
- Opens a browser URL for the SOURCE tenant admin to consent to the TARGET application

**On the SOURCE tenant**:
1. Runs `Enable-OrganizationCustomization` if not already enabled
2. Creates or verifies the **mail-enabled security group** for scoping (determines which mailboxes are allowed to migrate)
3. Creates an **Outbound Organization Relationship** with the `OAuthApplicationId` and `MailboxMovePublishedScopes` pointing to the scope group

> **Manual equivalent**: This involves running about 10 different Exchange PowerShell commands in a specific order on both tenants, plus navigating to an admin consent URL. See the [step-by-step instructions](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-tenant).

### Step 03-04 — Build Mailbox Migration CSV

Cross-references Phase 2 creation results with Discovery mailbox data to build the migration roster:

- Loads users created in Phase 2 (both on-prem and cloud-only)
- Matches with `EXO-Mailboxes_SOURCE.csv` to find which users have mailboxes
- Applies skip rules (e.g., users that failed creation, users without mailboxes)
- Produces a CSV with `ExoStatus = READY` or `SKIPPED` for each user

### Step 03-05 — Check Target Recipients

For each `READY` user, queries the TARGET Exchange Online via `Get-Recipient` to verify the user exists and is in the correct state:

| State | Meaning |
|-------|---------|
| **MailUser** | Ready for migration (expected state) |
| **UserMailbox** | Already has a mailbox — unexpected, investigate |
| **SoftDeletedMailbox** | Previous mailbox needs cleanup |
| **NotFound** | User doesn't exist in TARGET EXO — needs fixing |

### Step 03-06 — Prepare Mail Users

Two operations to prepare the target MailUsers for migration:

**Part A — Clear soft-deleted mailboxes**: For users with `SoftDeletedMailbox` status, runs `Set-User -PermanentlyClearPreviousMailboxInfo` to remove the ghost mailbox.

**Part B — Stamp target MailUsers**: For each user, retrieves the source mailbox properties and stamps the target MailUser with:
- `ExchangeGuid` — Links the target user to the source mailbox
- `ExternalEmailAddress` — Sets the routing address
- `LegacyExchangeDN` as an X500 proxy address — Ensures reply-ability to old emails

> **Why**: Without the `ExchangeGuid` stamp, Exchange won't know which source mailbox to migrate to which target user. Without the X500 address, replies to old emails will bounce.
>
> **Manual equivalent**:
> ```powershell
> # On SOURCE:
> $mbx = Get-Mailbox user@source.com
> # On TARGET:
> Set-MailUser user@target.com -ExchangeGuid $mbx.ExchangeGuid -ExternalEmailAddress $mbx.PrimarySmtpAddress
> ```
>
> See: [Prepare target user objects](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-target-user-objects-for-migration)

---

## Phase 4 — Exchange Migration Execution

**Purpose**: Execute, monitor, and complete the actual mailbox migrations.

**Note**: Unlike other phases, these steps can be run **individually and repeatedly** (e.g., check status multiple times). Each step has `AllowRerun = $true`.

**Output folder**: `<RunRoot>/04-ExchangeMigrationExecution/`

### Step 04-01 — Start Migration Batch

1. Adds source mailbox users to the **scoping security group** on SOURCE via `Add-DistributionGroupMember`
2. Generates a batch CSV file (format required by Exchange: `EmailAddress` column with target UPNs)
3. Creates a `New-MigrationBatch` on the TARGET tenant with configurable `AutoStart` and `AutoComplete`
4. The operator chooses the batch name and confirmation

> **Why**: The scoping group controls which mailboxes the migration endpoint is allowed to move. Without adding users to this group, the migration will be rejected.
>
> **Manual equivalent**:
> ```powershell
> # SOURCE: Add to scope group
> Add-DistributionGroupMember -Identity "MAILBOXMIGRATION" -Member user@source.com
> # TARGET: Start batch
> New-MigrationBatch -Name "Batch1" -SourceEndpoint "MigrationEndpoint" -CSVData ([System.IO.File]::ReadAllBytes(".\batch.csv")) -TargetDeliveryDomain "target.mail.onmicrosoft.com" -AutoStart -AutoComplete
> ```
>
> See: [Initiate cross-tenant mailbox migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#initiate-cross-tenant-moves)

### Step 04-02 — Check Migration Batches

Queries `Get-MigrationBatch` and `Get-MigrationUser` on the TARGET tenant. Displays per-batch and per-user status with aggregated counts (Synced, Syncing, Failed, Completed, etc.). Exports status CSVs.

> **Tip**: Run this step repeatedly to track migration progress. Mailbox migrations can take hours or days depending on size.

### Step 04-03 — Stop / Complete / Remove Batches

Interactive step to manage batch lifecycle:

| Action | Command | When to use |
|--------|---------|-------------|
| **Complete** | `Complete-MigrationBatch` | All users synced, ready for cutover |
| **Stop** | `Stop-MigrationBatch` | Need to pause/cancel |
| **Remove** | `Remove-MigrationBatch` | Cleanup after completion |

> **Why**: `Complete-MigrationBatch` triggers the final cutover — the source mailbox becomes a MailUser (forwarding), and the target MailUser becomes a full mailbox. This is the point of no easy return.

### Step 04-04 — Assign Licenses

After mailbox migration completes, users need an **Exchange Online license** in the target tenant to access their mailbox:

1. Lists available SKUs via `Get-MgSubscribedSku`
2. Operator selects which SKU to assign
3. Assigns licenses via `Set-MgUserLicense`

> **Manual equivalent**: Microsoft 365 admin center > Users > Active users > Select user > Licenses and apps > Assign license.
>
> See: [Assign licenses to users](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users?view=o365-worldwide)

### Step 04-05 -- Cleanup Migration Config

Removes the cross-tenant mailbox migration infrastructure created in Phase 3:

1. **Migration endpoint** on TARGET (`Remove-MigrationEndpoint`)
2. **Organization relationships** on both SOURCE and TARGET
3. **Scoping security group** on SOURCE (the mail-enabled group used to control which mailboxes can migrate)
4. **Application registration** in TARGET Entra ID

> **Why**: After all mailbox migrations are complete, the migration infrastructure should be cleaned up for security. The app registration and org relationships grant cross-tenant access that is no longer needed.
>
> **Warning**: Only run this after ALL mailbox migrations are finalized. This cannot be easily undone.

---

## Phase 5 — OneDrive Migration Plan

**Purpose**: Set up cross-tenant trust and identity mapping for OneDrive content migration using Microsoft's Mergers & Acquisitions (MnA) framework.

**Output folder**: `<RunRoot>/05-OneDriveMigrationPlan/`

> See: [Cross-tenant OneDrive migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration?view=o365-worldwide)

### Step 05-01 — Build Users Mapping

Loads Phase 2 creation results (both on-prem and cloud-only) and builds a **SourceUPN → TargetUPN** mapping file. Each row gets a status:

- `OK` — User was created successfully, ready for OneDrive migration
- `FAILED` — User creation failed, excluded from migration

### Step 05-02 — Setup Cross-Tenant Trust

Establishes the MnA trust between both SharePoint Online tenants:

1. Verifies Cross-Tenant User Data Migration licenses
2. Retrieves `CrossTenantHostUrl` from both tenants via `Get-SPOCrossTenantHostUrl`
3. Establishes trust via `Set-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source|Target`
4. Verifies trust status via `Verify-SPOCrossTenantRelationship` — must return `GoodToProceed`

> **Why**: Without this trust, SharePoint Online won't allow content to move between tenants.
>
> **Manual equivalent**:
> ```powershell
> # On TARGET:
> $sourceUrl = Get-SPOCrossTenantHostUrl
> Set-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceUrl
> # On SOURCE:
> $targetUrl = Get-SPOCrossTenantHostUrl
> Set-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetUrl
> # Verify on both:
> Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source|Target -PartnerCrossTenantHostUrl $url
> ```
>
> See: [Set up cross-tenant OneDrive migration trust](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step2?view=o365-worldwide)

### Step 05-03 — Build CTIM Mapping

Generates the **Cross-Tenant Identity Map** (CTIM) file — a headerless CSV in the specific format required by SharePoint:

```
User,<SourceTenantGUID>,source@contoso.com,target@fabrikam.com,target@fabrikam.com,RegularUser
```

The operator is prompted for the source tenant GUID.

> **Why**: The CTIM file tells SharePoint which source user's OneDrive should be moved to which target user.
>
> See: [Create the identity mapping file](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step3?view=o365-worldwide)

### Step 05-04 -- Assign Licenses

Assigns OneDrive/SharePoint licenses to target users so their OneDrive sites can be provisioned:

1. **Assign licenses** -- Same flow as Phase 4 (choose SKU, assign via `Set-MgUserLicense`)

> **Why**: Target users need an active license that includes OneDrive before content can be migrated to them. OneDrive sites are automatically provisioned when a licensed user first accesses OneDrive or through background provisioning.
>
> **Note**: The tool no longer calls `Request-SPOPersonalSite` for pre-provisioning, as this can create target sites that conflict with the cross-tenant move process.
>
> **Manual equivalent**: Microsoft 365 admin center > Users > Active users > Select user > Licenses and apps > Assign license.

---

## Phase 6 — OneDrive Migration Execution

**Purpose**: Execute, monitor, and clean up OneDrive content migrations. Steps can be run individually and repeatedly.

**Output folder**: `<RunRoot>/06-OneDriveMigrationExecution/`

### Step 06-01 — Start OneDrive Migrations

1. **Uploads the CTIM identity map** to the TARGET tenant via `Add-SPOTenantIdentityMap`
2. **Retrieves CrossTenantHostUrl** from TARGET
3. **Starts per-user content moves** on the SOURCE via `Start-SPOCrossTenantUserContentMove` for each user in the mapping

Requires typing **YES** in uppercase to confirm (safety measure — this initiates actual data movement).

> **Manual equivalent**:
> ```powershell
> # On TARGET:
> Add-SPOTenantIdentityMap -IdentityMapPath ".\ctim.csv"
> # On SOURCE (for each user):
> Start-SPOCrossTenantUserContentMove -CrossTenantHostUrl $targetHostUrl -TargetUserEmail user@target.com
> ```
>
> See: [Start cross-tenant OneDrive migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step5?view=o365-worldwide)

### Step 06-02 — Check Migration Status

Queries `Get-SPOCrossTenantUserContentMoveState` on **both** tenants and combines the results. Shows status for each user (NotStarted, InProgress, Completed, Failed).

> **Tip**: Run this step repeatedly until all moves show `Completed`. OneDrive migrations can take several hours depending on data volume.

### Step 06-03 — Reset Cross-Tenant Trust

After all migrations are complete, removes the MnA trust from both tenants:

1. `Remove-SPOCrossTenantRelationship -Scenario MnA` on both sides
2. Verifies removal via `Verify-SPOCrossTenantRelationship`

> **Why**: The cross-tenant trust should be removed after migration for security. Leaving it open would allow future content moves between the tenants.

---

## Phase 7 -- SharePoint Migration Plan

**Purpose**: Discover SharePoint sites on the SOURCE tenant, build a migration mapping, verify cross-tenant trust, upload identity mappings, and check compatibility before migration.

**Output folder**: `<RunRoot>/07-SharePointMigrationPlan/`

> **Important**: SharePoint site migration requires a separate **Cross-Tenant Shared Data Migration** license (per 100 GB of data), different from the Cross-Tenant User Data Migration license used for OneDrive/mailbox moves. Only available to Enterprise Agreement (EA) customers.
>
> See: [Cross-tenant SharePoint migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration?view=o365-worldwide)

### Step 07-01 -- Discover & Build Sites Mapping

1. Connects to SOURCE SharePoint Admin
2. Enumerates all SharePoint sites via `Get-SPOSite -Limit All` (excluding OneDrive personal sites, search centers, and app catalogs)
3. Detects GROUP#0 template sites as M365 Group-connected
4. Auto-generates target URLs based on the target tenant domain
5. Exports a mapping CSV with columns: SourceSiteUrl, TargetSiteUrl, Template, Owner, StorageGB, IsGroupConnected, **Migrate** (YES/NO)
6. Opens the CSV for operator review

The operator can:
- Set `Migrate=NO` for sites that should not be migrated
- Adjust `TargetSiteUrl` if the auto-generated URL is incorrect
- For Group-connected sites, ensure the target M365 Group exists beforehand

> **Important (from Microsoft docs)**:
> - Do NOT create target SharePoint sites before migration -- the migration creates them automatically
> - Each site must be < 5 TB and < 1 million items
> - Source sites must be in Read/Write mode (not Read-only)

> **Manual equivalent**:
> ```powershell
> Connect-SPOService -Url https://source-admin.sharepoint.com
> Get-SPOSite -Limit All | Select-Object Url, Template, Owner, StorageUsageCurrent | Export-Csv .\sites.csv -NoTypeInformation
> ```

### Step 07-02 -- Verify Cross-Tenant Trust

Verifies the MnA cross-tenant trust on both SOURCE and TARGET tenants using `Verify-SPOCrossTenantRelationship` (or `Test-SPOCrossTenantRelationship` on newer SPO module versions). The trust must return **GoodToProceed** on both sides.

> **Note**: This trust is the same one established in Phase 5 (OneDrive). If you already completed Phase 5, the trust is already in place. If not, run Phase 5 step 05-02 first.
>
> **Manual equivalent**:
> ```powershell
> # On SOURCE:
> Connect-SPOService -Url https://source-admin.sharepoint.com
> $targetHostUrl = Get-SPOCrossTenantHostUrl
> Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl
>
> # On TARGET:
> Connect-SPOService -Url https://target-admin.sharepoint.com
> $sourceHostUrl = Get-SPOCrossTenantHostUrl
> Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl
> ```
> Both should return `GoodToProceed`.
>
> See: [Verify trust](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step3?view=o365-worldwide)

### Step 07-03 -- Build & Upload Identity Map

Builds a cross-tenant identity mapping CSV for SharePoint (users + groups) and uploads it to the TARGET tenant via `Add-SPOTenantIdentityMap`.

**User mappings**: Reuses the OneDrive CTIM file from Phase 5 if available. Otherwise, builds user mappings from Discovery data with domain-based UPN mapping.

**Group mappings** (optional): Two modes available:
- **Auto-discover** (recommended): Connects to Microsoft Graph on both tenants, lists all groups via `Get-MgGroup`, and automatically matches them by DisplayName. Shows matched/unmatched groups for confirmation.
- **Manual**: Enter source/target group ObjectId pairs manually.

The identity map CSV uses Microsoft's required 6-column format with NO headers:
```
User,<SourceTenantId>,source@contoso.com,target@fabrikam.com,target@fabrikam.com,RegularUser
Group,<SourceTenantId>,<SourceGroupObjectId>,<TargetGroupObjectId>,GroupName,SecurityGroup
```

> **Why**: The identity map ensures file/folder permissions are preserved after migration. Without it, users lose access to shared content.
>
> **Manual equivalent**:
> ```powershell
> # Build a headerless CSV with 6 columns per line:
> # User,<SourceTenantId>,<SourceUPN>,<TargetUPN>,<TargetEmail>,RegularUser
> # Group,<SourceTenantId>,<SourceGroupObjId>,<TargetGroupObjId>,<GroupName>,SecurityGroup
> #
> # Example:
> # User,12345678-abcd-1234-abcd-123456789abc,user1@source.com,user1@target.com,user1@target.com,RegularUser
> # Group,12345678-abcd-1234-abcd-123456789abc,aaa-bbb-ccc,ddd-eee-fff,MySecurityGroup,SecurityGroup
>
> # Upload to TARGET:
> Connect-SPOService -Url https://target-admin.sharepoint.com
> Add-SPOTenantIdentityMap -IdentityMapPath .\identitymap.csv
> ```
> To find group ObjectIds, use `Get-MgGroup -All | Select-Object Id, DisplayName` on each tenant.
>
> See: [Prepare identity mapping](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step5?view=o365-worldwide)

### Step 07-04 -- Verify Compatibility

Runs `Get-SPOCrossTenantCompatibilityStatus` from the SOURCE tenant to check whether the tenants are compatible for migration. Expected result: **Compatible**.

> **Manual equivalent**:
> ```powershell
> Connect-SPOService -Url https://source-admin.sharepoint.com
> $targetHostUrl = Get-SPOCrossTenantHostUrl  # from TARGET
> Get-SPOCrossTenantCompatibilityStatus -PartnerCrossTenantHostUrl $targetHostUrl
> ```
> Should return `Compatible`. If it returns `Incompatible`, check that both tenants meet all prerequisites (no Customer Key, correct SPO module version, etc.).
>
> See: [Prepare identity mapping - Compatibility check](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step5?view=o365-worldwide)

---

## Phase 8 -- SharePoint Migration Execution

**Purpose**: Execute, monitor, cancel, and clean up SharePoint site migrations. Steps can be run individually and repeatedly.

**Output folder**: `<RunRoot>/08-SharePointMigrationExecution/`

> **Important**: This is a **MOVE**, not a copy. Content is moved from SOURCE to TARGET. A redirect link is left on SOURCE. Incremental/delta migrations are not possible.

### Step 08-01 -- Start SharePoint Site Migrations

1. Checks that the operator has the **Cross-Tenant Shared Data Migration** license
2. Loads the sites mapping CSV from step 07-01 (only rows with `Migrate=YES`)
3. Retrieves `CrossTenantHostUrl` from the TARGET tenant
4. Starts site moves from the SOURCE tenant:
   - **Standard sites**: `Start-SPOCrossTenantSiteContentMove -SourceSiteUrl <url> -TargetSiteUrl <url> -TargetCrossTenantHostUrl <url>`
   - **Group-connected sites**: `Start-SPOCrossTenantGroupContentMove -SourceGroupAlias <alias> -TargetGroupAlias <alias> -TargetCrossTenantHostUrl <url>`
5. Exports a results CSV with per-site OK/FAILED status

> **Manual equivalent**:
> ```powershell
> # Standard site:
> Start-SPOCrossTenantSiteContentMove -SourceSiteUrl "https://source.sharepoint.com/sites/MySite" -TargetSiteUrl "https://target.sharepoint.com/sites/MySite" -TargetCrossTenantHostUrl $targetHostUrl
> # Group-connected site:
> Start-SPOCrossTenantGroupContentMove -SourceGroupAlias "MyGroup" -TargetGroupAlias "MyGroup" -TargetCrossTenantHostUrl $targetHostUrl
> ```
>
> See: [Start a cross-tenant SharePoint migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step6?view=o365-worldwide)

### Step 08-02 -- Check Migration Status

Queries `Get-SPOCrossTenantUserContentMoveState` on both SOURCE and TARGET tenants (same cmdlet as OneDrive). Filters results to show only SharePoint sites (excludes OneDrive personal sites). Displays color-coded status per site and exports status CSVs.

| State | Meaning |
|-------|---------|
| `NotStarted` | Move is queued but hasn't begun |
| `Scheduled` | Move is scheduled |
| `ReadytoTrigger` | Move is ready to start |
| `InProgress` | Move is actively running |
| `Success` | Move completed successfully |
| `Rescheduled` | Move was rescheduled (temporary issue) |
| `Failed` | Move failed -- check error details |

> **Tip**: Run this step repeatedly until all moves show `Success`. SharePoint site migrations can take hours or days depending on data volume.
>
> **Manual equivalent**:
> ```powershell
> # From SOURCE (query moves to TARGET):
> Connect-SPOService -Url https://source-admin.sharepoint.com
> Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $targetHostUrl
>
> # From TARGET (query moves from SOURCE):
> Connect-SPOService -Url https://target-admin.sharepoint.com
> Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $sourceHostUrl
> ```
> Filter out OneDrive personal sites (URLs containing `-my.sharepoint.com/personal/`) to see only SharePoint site moves.
>
> See: [Start a cross-tenant SharePoint migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step6?view=o365-worldwide)

### Step 08-03 -- Stop/Cancel Migrations

Interactive step to cancel pending or queued migrations:
- **Standard sites**: `Stop-SPOCrossTenantSiteContentMove -SourceSiteUrl <url>`
- **Group-connected sites**: `Stop-SPOCrossTenantGroupContentMove -SourceGroupAlias <alias>`

> **Note**: Migrations that are `InProgress` or `Success` cannot be cancelled.
>
> **Manual equivalent**:
> ```powershell
> Connect-SPOService -Url https://source-admin.sharepoint.com
> # Cancel a standard site:
> Stop-SPOCrossTenantSiteContentMove -SourceSiteUrl "https://source.sharepoint.com/sites/MySite"
> # Cancel a Group-connected site:
> Stop-SPOCrossTenantGroupContentMove -SourceGroupAlias "MyGroup"
> ```

### Step 08-04 -- Cleanup (Post-Migration)

Two cleanup operations, each requiring confirmation:

**1. Remove cross-tenant trust**:
- `Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target` on SOURCE
- `Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source` on TARGET

**2. Remove redirect sites** on SOURCE:
- Lists all redirect sites via `Get-SPOSite -Template RedirectSite#0 -Limit All`
- Optionally removes them via `Remove-SPOSite`

> **Warning**: Only run this after ALL migrations (OneDrive + SharePoint) are complete. Removing the trust will prevent any future cross-tenant moves.
>
> **Manual equivalent**:
> ```powershell
> # Remove trust on SOURCE:
> Connect-SPOService -Url https://source-admin.sharepoint.com
> Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl
>
> # Remove trust on TARGET:
> Connect-SPOService -Url https://target-admin.sharepoint.com
> Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl
>
> # List and remove redirect sites on SOURCE:
> Connect-SPOService -Url https://source-admin.sharepoint.com
> Get-SPOSite -Template RedirectSite#0 -Limit All | ForEach-Object { Remove-SPOSite -Identity $_.Url -NoWait -Confirm:$false }
> ```
>
> See: [Post-migration steps](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration-step7?view=o365-worldwide)

---

## Configuration Reference

The configuration file `config/config.psd1` is a PowerShell Data File with this structure:

```powershell
@{
    Run = @{
        OutputRoot = '.\output\runs'    # Where run folders are created
    }
    Tenants = @{
        Source = @{
            TenantIdOrDomain = 'source.onmicrosoft.com'
        }
        Target = @{
            TenantIdOrDomain = 'target.onmicrosoft.com'
        }
    }
    Workloads = @{
        Discovery           = $true    # Phase 1
        IdentityPreparation = $true    # Phase 2
        ExchangeMigration   = $true    # Phases 3-4
        OneDriveMigration   = $true    # Phases 5-6
        SharePointMigration = $true     # Phases 7-8
    }
    OnPremIdentity = @{
        LastUsedTargetOU = ''           # Remembered from last Phase 2 run
    }
}
```

Additional keys are added dynamically at runtime:

```powershell
ExchangeMigration = @{
    TargetAppId       = '<GUID>'        # App created in Step 03-02
    TargetAppSecret   = '<secret>'      # Client secret
    SourceTenantId    = '<GUID>'        # Source tenant GUID
    TargetTenantId    = '<GUID>'        # Target tenant GUID
    EndpointName      = '<name>'        # Migration endpoint name
    ScopeGroupName    = 'MAILBOXMIGRATION'  # Scoping security group
}
```

---

## Run Management & Resumability

### Run Folder Structure

Each run creates a timestamped folder:

```
output/runs/2025-01-15_143022/
├── run_state.csv                    # Step execution log
├── logs/                            # Transcript logs
├── 01-Discovery/                    # Discovery outputs
│   ├── EntraUsers_SOURCE.csv
│   ├── EntraDomains_SOURCE.csv
│   ├── EntraGroups_SOURCE.csv
│   ├── EntraGroupMembers_SOURCE.csv
│   ├── EXO-Mailboxes_SOURCE.csv
│   ├── EXO-Recipients_SOURCE.csv
│   ├── EXO-MailContacts_SOURCE.csv
│   ├── SPO-OneDriveSites_SOURCE.csv
│   └── SPO-Sites_SOURCE.csv
├── 02-IdentityPreparation/          # Identity outputs
│   ├── Users_OnPrem_ProvisioningPlan.csv
│   ├── Users_OnPrem_CreationResults.csv
│   ├── Users_CloudOnly_ProvisioningPlan.csv
│   ├── Users_CloudOnly_CreationResults.csv
│   ├── Guests_ProvisioningPlan.csv
│   ├── Guests_CreationResults.csv
│   ├── Groups_OnPrem_ProvisioningPlan.csv
│   ├── Groups_OnPrem_CreationResults.csv
│   ├── Groups_OnPrem_MembershipPlan.csv
│   ├── Groups_CloudOnly_ProvisioningPlan.csv
│   ├── Groups_CloudOnly_CreationResults.csv
│   ├── Groups_CloudOnly_MembershipPlan.csv
│   ├── Contacts_ProvisioningPlan.csv
│   ├── Contacts_Provisioning_Results.csv
│   └── AADConnect_Assessment.csv
├── 03-ExchangeMigrationPlan/        # Exchange plan outputs
├── 04-ExchangeMigrationExecution/   # Exchange execution outputs
├── 05-OneDriveMigrationPlan/        # OneDrive plan outputs
├── 06-OneDriveMigrationExecution/   # OneDrive execution outputs
├── 07-SharePointMigrationPlan/      # SharePoint plan outputs
│   ├── SharePoint_SitesMapping_*.csv
│   └── SharePoint_IdentityMap_*.csv
└── 08-SharePointMigrationExecution/ # SharePoint execution outputs
    ├── SharePoint_StartResults_*.csv
    ├── SharePoint_Status_Source_*.csv
    └── SharePoint_Status_Target_*.csv
```

### State File (`run_state.csv`)

Tracks every step execution:

```csv
Timestamp,Phase,Step,Status,Message
2025-01-15 14:31:00,01-Discovery,Discovery-ExportUsers-Source,InProgress,Starting...
2025-01-15 14:31:45,01-Discovery,Discovery-ExportUsers-Source,Completed,Exported 150 users
2025-01-15 14:31:46,01-Discovery,Discovery-ExportDomains-Source,InProgress,Starting...
```

| Status | Meaning |
|--------|---------|
| `InProgress` | Step is currently running |
| `Completed` | Step finished successfully — will be **skipped** on resume |
| `Failed` | Step encountered an error — phase stops, fix and resume |
| `WaitingUser` | Step paused for operator input |

### Resuming a Run

1. Select **option 2** (Resume existing run) from the main menu
2. Pick the run folder
3. Execute the phase again — completed steps are automatically skipped
4. The tool picks up at the first non-completed step

---

## Troubleshooting

### Common Issues

| Problem | Cause | Solution |
|---------|-------|----------|
| `ActiveDirectory module not found` | RSAT not installed | Install RSAT AD tools via Windows Features |
| `Connect-MgGraph` fails | No admin consent or wrong tenant | Check tenant ID in config, ensure Global Admin consent |
| `Get-Mailbox` returns nothing | Connected to wrong tenant | Verify Exchange connection with `Get-OrganizationConfig` |
| Migration batch fails with `MapiExceptionUnknownUser` | Target MailUser not stamped with ExchangeGuid | Re-run Step 03-06 (Prepare Mail Users) |
| OneDrive migration stuck at `NotStarted` | Cross-tenant trust not `GoodToProceed` | Run `Verify-SPOCrossTenantRelationship` on both sides |
| `Verify-SPOCrossTenantRelationship` returns `NotEstablished` | Trust takes time to propagate | Wait 5-15 minutes and try again |
| SharePoint migration: `MnASiteMove feature is not enabled` | Missing Cross-Tenant Shared Data Migration license | Purchase from M365 admin center > Billing > Purchase services. Different from the User Data Migration license used for OneDrive |
| `.Count` errors on filtered results | PowerShell single-object issue | Wrap `Where-Object` in `@()` -- already handled in the tool |
| Step shows `Completed` but needs to be re-run | State file marks it done | Edit `run_state.csv` and remove the Completed row for that step |

### Connection Issues

If authentication fails mid-session:

1. The tool will detect the stale connection on the next step
2. It will attempt to reconnect automatically
3. If that fails, close and reopen the tool — PowerShell modules sometimes cache stale tokens

### Forcing a Step to Re-Run

If a step needs to be repeated (e.g., new data was added):

1. Open `run_state.csv` in the run folder
2. Delete the `Completed` row for the step you want to re-run
3. Resume the run — the tool will execute that step again

---

## Useful Links

### Microsoft Documentation

| Topic | Link |
|-------|------|
| **Cross-tenant mailbox migration** | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide) |
| **Cross-tenant OneDrive migration** | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration?view=o365-worldwide) |
| **Cross-tenant SharePoint migration** | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration?view=o365-worldwide) |
| **Cross-Tenant Shared Data Migration licensing** | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration?view=o365-worldwide#how-to-participate) |
| **Entra Connect sync setup** | [learn.microsoft.com](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites) |
| **Entra Connect OU filtering** | [learn.microsoft.com](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering) |
| **Pre-provision OneDrive sites** | [learn.microsoft.com](https://learn.microsoft.com/en-us/sharepoint/pre-provision-accounts) |
| **Manage mail contacts in EXO** | [learn.microsoft.com](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-mail-contacts) |
| **Create users in Entra ID** | [learn.microsoft.com](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-users) |
| **Invite B2B guest users** | [learn.microsoft.com](https://learn.microsoft.com/en-us/entra/external-id/add-users-administrator) |
| **Assign M365 licenses** | [learn.microsoft.com](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users?view=o365-worldwide) |

### PowerShell Module References

| Module | Documentation |
|--------|--------------|
| **Microsoft Graph PowerShell** | [learn.microsoft.com](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview) |
| **Exchange Online PowerShell** | [learn.microsoft.com](https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell) |
| **SharePoint Online PowerShell** | [learn.microsoft.com](https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell) |

### Entra Admin Portals

| Portal | URL |
|--------|-----|
| **Entra admin center** | [entra.microsoft.com](https://entra.microsoft.com) |
| **Microsoft 365 admin center** | [admin.microsoft.com](https://admin.microsoft.com) |
| **Exchange admin center** | [admin.exchange.microsoft.com](https://admin.exchange.microsoft.com) |
| **SharePoint admin center** | [admin.microsoft.com/sharepoint](https://admin.microsoft.com/sharepoint) |

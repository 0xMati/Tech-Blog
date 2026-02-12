# Entra ID Migration - A Simple Home Made tool
🗓️ Published: 2026-02-07 - VVersion 1

## Introduction

Migrating identities to a new Microsoft Entra ID tenant is **never a trivial task**.  
Even for small environments, the number of prerequisites, dependencies, edge cases, and sequencing constraints can quickly become overwhelming.

This project deliberately focuses on the **core identity and collaboration workloads** required for most migrations:
**users, groups, mailboxes, and OneDrive**.

It does **not aim to migrate complex or highly customized configurations**, such as:
- Advanced mailbox permissions (Send As, Send on Behalf, Full Access edge cases)
- Delegations and shared mailbox-specific workflows
- Existing OneDrive sharing links or external sharing relationships
- Other tenant-specific customizations that usually require dedicated tooling or manual remediation

The objective is to provide a **clean, predictable baseline migration**, covering what matters for the majority of users, while intentionally leaving out scenarios that introduce disproportionate complexity.

This project was born from a simple observation:  
while **large-scale tenant-to-tenant migrations** usually rely on industrial tools, vendors, and heavy project governance, **small to medium migrations** are often left with little more than manual steps, scripts scattered across machines, and undocumented processes.

The goal of this home-made toolset is **not to replace enterprise migration platforms**, nor to claim universal applicability.  
Instead, it aims to:

- Automate **repeatable and error-prone tasks**
- Provide **clear visibility** into each migration phase
- Enforce **structured inputs and outputs**
- Reduce manual intervention where it makes sense

This documentation describes the scripts and processes used throughout the migration lifecycle.  
They are **most suitable for small to medium-sized Entra ID migrations**, where flexibility, transparency, and control matter more than scale.

## How to Use the Tool

All scripts required for the migration are located in a single root folder:

```
Entra-ID-Simple-Tenant-Migration-Tool
```

This folder contains all phases, helpers, and runners needed to execute the migration end-to-end.

The migration is orchestrated through a **single entry point script**:

```
00-Run-MigrationTenant-All.ps1
```

To start the migration process:

1. Open a PowerShell session (PowerShell 5.1 is required).
2. Navigate to the `Entra-ID-Simple-Tenant-Migration-Tool` directory.
3. Execute the main runner script:
   ```powershell
   .\00-Run-MigrationTenant-All.ps1
   ```
4. Follow the interactive prompts displayed in the console.

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-15-34-00.png)

The runner script is responsible for:
- Executing each migration phase in the correct order
- Loading the appropriate input files
- Ensuring required prerequisites are met before continuing
- Guiding the operator through decisions that cannot be fully automated

All scripts are designed to be **interactive by default**, favoring control and visibility over silent execution.

## Prerequisites and Required Permissions

Before running any migration script, the following permissions are **mandatory**.

### Active Directory (On-Premises)

- **Domain Admins** membership is required.
- These rights are needed to:
  - Create and modify Active Directory objects
  - Prepare and validate target identities
  - Handle OU placement and attribute updates

### Microsoft Entra ID (Source and Target Tenants)

- **Global Administrator** rights are required on **both the source and target tenants**.
- These permissions are necessary to manage all involved workloads, including:
  - Entra ID (users, groups, identities)
  - Exchange Online
  - OneDrive and SharePoint Online
  - Cross-tenant trust and migration configuration

### Azure AD Connect

- Administrative rights on **Azure AD Connect** are required.
- These permissions are needed to:
  - Adjust or validate synchronization rules
  - Control attribute flow during the migration
  - Ensure consistency between on-premises Active Directory and Entra ID

Failure to meet these prerequisites may result in partial migrations, blocked steps, or inconsistent states across tenants.

## Check & Install Modules

Before executing any migration phase, the environment must be prepared with all required PowerShell modules.
This step is handled by the script:

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-16-03-26.png)

```
00-CheckAndInstall-Modules.ps1
```

This script is automatically proposed by the main runner and acts as a **mandatory environment pre-check**.

Its purpose is to ensure that the workstation used for the migration is technically capable of running all phases without interruption.

### What This Script Does

The script performs the following actions:

- Verifies that **Windows PowerShell 5.1** is being used
- Checks the presence of all required **cloud PowerShell modules**
- Installs missing modules from the PowerShell Gallery using the **AllUsers** scope
- Validates that critical modules can be successfully imported
- Confirms the availability of required Graph cmdlets (such as `New-MgInvitation`)
- Verifies whether the **ActiveDirectory (RSAT)** module is available for on-prem AD operations

### Covered Migration Phases

This module preparation step is required for:

- **Phase 1 – Discovery (Cloud)**  
  Uses Microsoft Graph modules to inventory users, groups, and tenant configuration.

- **Phase 2 – AD Preparation**  
  Requires the `ActiveDirectory` module to create and validate on-premises objects.

- **Phase 4 – Data Migration**  
  Uses Graph, Exchange Online, and SharePoint Online modules to handle:
  - Mailbox preparation and migration
  - OneDrive migration
  - Cross-tenant access and permissions

### Required Modules

The script ensures the availability of the following modules:

**Cloud / Microsoft 365**
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Users
- Microsoft.Graph.Users.Actions
- Microsoft.Graph.Groups
- Microsoft.Graph.Identity.SignIns
- Microsoft.Graph.Applications
- ExchangeOnlineManagement
- Microsoft.Online.SharePoint.PowerShell

**On-Premises**
- ActiveDirectory (RSAT AD PowerShell)

> Note: The ActiveDirectory module is not installed via `Install-Module`.  
> It must be installed through Windows Features (RSAT), depending on the operating system.

### Why This Step Is Critical

Without this pre-check:
- Scripts may fail midway due to missing dependencies
- Authentication or Graph calls may silently fail
- AD preparation steps may not be executable

Running this script **once per workstation** ensures a stable and predictable execution environment for the entire migration process.

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-16-04-30.png)

## 2. Phase 1 – Discovery

**Objective:**  
Tenant inventory, identity assessment, mappings and prerequisites.

Phase 1 is dedicated to **understanding the source tenant** before any transformation or migration action is taken.

During this phase, the tool focuses on:
- Inventorying identities and core objects
- Assessing the current state of users and groups
- Collecting the information required for identity mapping
- Identifying prerequisites and potential blockers for later phases

This phase is intentionally **read-only** and does not perform any modification in the source tenant.

Detailed execution steps, inputs, and outputs are documented separately for each sub-step of the Discovery phase.

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-16-08-50.png)

### 2.1 Set Context

Before running any discovery step, the tool requires a minimal context for the source tenant:

- **CompanyName** – Friendly label for the source tenant (used in folder structure and filenames).
- **SPOAdminTenantName** – Short tenant name used for the SharePoint admin URL  
  (e.g. `mySourceTenantName` for `mySourceTenantName-admin.sharepoint.com`).
- **TenantDomain** – Primary or main UPN / routing domain of the tenant  
  (e.g. `source_domain.com`, used to force the Graph context).

This context is stored in the current PowerShell session and reused by all Phase 1 scripts to ensure consistent naming and output locations.

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-34-32.png)

### 2.2 Connect (Graph / Exchange Online / SharePoint Online)

Script: `01-Auth.ps1`

This step establishes all required admin connections to the source tenant:

- Microsoft Graph (for Entra ID / identity / directory data)
- Exchange Online (for mailbox and messaging inventory)
- SharePoint Online (for SharePoint and OneDrive inventory)

It uses the previously defined context values and writes connection traces and logs under the Phase 1 output folder.  
No configuration change is performed; this step is **authentication and connectivity only**.

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-36-01.png)

The output folder will have the name of the Company Name that has been choose :

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-39-10.png)

### 2.3 Export Tenant Settings, Domains and Federation

Script: `02-Export-TenantSettings.ps1`

This step captures the **high-level configuration** of the source tenant, including:

- Entra ID tenant properties and organization settings
- Verified domains and routing / UPN domains
- Federation / authentication model information (where applicable)

The goal is to provide a **baseline snapshot** of the tenant, useful both for migration planning and for documentation / rollback references.

The "Export" folder will contain all information regarding the source tenant : Domain names settings, Tenant settings, etc.
Is will be used later for Local UPN suffixe that will be needed to be created

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-44-22.png)

### 2.4 Export Entra Users

Script: `03-Export-EntraUsers.ps1`

This step exports the **user inventory** from the source tenant, including:

- Enabled / disabled accounts
- User types (member vs guest)
- Core attributes needed for mapping (UPN, mail, objectId, etc.)
- Basic license / workload-related information where relevant to the migration

The exported data is used later for **identity mapping**, **target AD preparation**, and **migration scope definition** (who is in / who is out).

You can review or edit the "user_inventory.csv" file to remove Users that don't need to to fall under the migration scope:

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-46-47.png)

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-47-40.png)

### 2.5 Export Groups, Owners and Membership

Script: `04-Export-Groups.ps1`

This step focuses on **group-based collaboration and access control**, and exports:

- Groups (security groups and M365 groups, depending on scope)
- Group metadata (type, mail-enabled or not, visibility, etc.)
- Owners and membership lists

The output is used to prepare **group migration strategy** (recreation, mapping, or consolidation) and to understand dependencies between users and groups.

You can review or edit the "groups_inventory.csv" file to remove Groups that don't need to to fall under the migration scope:

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-50-35.png)

![](assets/Entra%20ID%20Migration%20-%20A%20Simple%20Home%20Made%20tool/2026-02-07-17-51-23.png)

### 2.6 Export Exchange Inventory

Script: `05-Export-Exchange.ps1`

This step collects the **mailbox-related inventory**, such as:

- User mailboxes, shared mailboxes and other mailbox types in scope
- Primary addresses and aliases (proxy addresses)
- Basic mailbox characteristics relevant to migration tooling and batching

The aim is not to capture every advanced setting, but to build a **clean, actionable view of mailboxes** to be used later in Phase 4 (Data Migration).


### 2.7 Export SharePoint and OneDrive Inventory

Script: `06-Export-SharePointOneDrive.ps1`

This step inventories:

- SharePoint Online site collections relevant to the migration
- OneDrive sites associated with user accounts
- Technical identifiers and URLs required to drive later OneDrive migration steps

It does **not** attempt to export permissions or sharing links at this stage.  
The focus is on building a **reliable inventory of what exists**, so that OneDrive and SharePoint migration can be scoped properly in Phase 4.


### 2.8 Open Output Folder

Menu option: `8. Open Output folder`

For convenience, the orchestrator can open the **current Phase 1 output folder** for the selected CompanyName and date.

This folder follows a consistent structure:

- One root per **CompanyName**
- One subfolder per **execution date** (`yyyy-MM-dd`)
- Inside it, CSV and JSON exports for each discovery step

This standardized layout makes it easier to track multiple runs, compare inventories over time, and feed later phases with the right input files.




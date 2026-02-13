# Entra ID Simple Tenant Migration Tool

## Project Master Status & Architectural Reference  
Last updated: 2026-02-13 06:55 (America/Los_Angeles)

-----------------------------------------------------------------------

# 1. Executive Overview

This project is a Windows PowerShell 5.1–based interactive framework designed to perform structured, controlled tenant‑to‑tenant migrations between Microsoft Entra ID environments.

The tool is designed with:

- Single entry point
- Interactive operator-driven execution
- Run-oriented architecture (one RunId per execution context)
- CSV-only state and data model (no JSON)
- Step-based execution engine
- Resume capability via run_state.csv
- Dependency-aware authentication layer
- Hybrid + Cloud scenario compatibility (Synced + Cloud-only)
- StrictMode enforcement for robustness

The architecture is intentionally modular and extensible.

-----------------------------------------------------------------------

# 2. Architecture Principles (LOCKED)

- PowerShell 5.1 compatibility only
- StrictMode -Version Latest always enabled
- No secrets stored in config.psd1
- Interactive execution only (no full automation mode)
- Operator-controlled phase execution
- Fail-fast behavior between steps
- CSV-only tracking and export model
- Clear separation between:
  - Core engine
  - Authentication
  - Workloads
  - State tracking

-----------------------------------------------------------------------

# 3. Repository Structure

Entra ID Simple Tenant Migration Tool
│
├── Start-EIDMigrationTool.ps1
│
├── config
│   ├── config.sample.psd1
│   └── config.psd1 (local, gitignored)
│
├── lib
│   ├── 00-Core.Functions.ps1                 (Step engine + run orchestration)
│   ├── 00-Auth.Functions.ps1                 (Graph + EXO + SPO auth implemented)
│   ├── 01-Discovery.Functions.ps1            (Implemented)
│   ├── 02-IdentityPreparation.Functions.ps1  (Partially implemented)
│   ├── 03-ExchangeMigration.Functions.ps1    (Stub)
│   ├── 04-OneDriveMigration.Functions.ps1    (Stub)
│   └── 05-SharePointMigration.Functions.ps1  (Stub)
│
└── output
    └── runs
        └── <RunId>
            ├── logs
            ├── run_state.csv
            ├── 01-Discovery
            ├── 02-IdentityPreparation
            ├── 03-ExchangeMigration
            ├── 04-OneDriveMigration
            └── 05-SharePointMigration

-----------------------------------------------------------------------

# 4. Core Engine (Implemented)

## 4.1 Runner

- Interactive configuration lifecycle
- New run creation
- Resume existing run
- View run state
- Execute selected phase
- Active run context displayed in UI

## 4.2 Run State Model

File: run_state.csv

Header:
Timestamp,Phase,Step,Status,Message

Supported Status Values:
- InProgress
- Completed
- Failed
- WaitingUser

Behavior:
- Completed steps auto-skip
- Failed step stops phase
- WaitingUser pauses execution
- Resume supported via CSV inspection

## 4.3 Run Context (Ctx)

A run context object is passed to all phases/steps. It includes, among others:
- RunId
- RunRoot
- RepoRoot
- Config
- ConfigPath (added to support config persistence inside steps)

-----------------------------------------------------------------------

# 5. Authentication Layer

## 5.1 Microsoft Graph

Interactive authentication per tenant.

Supported:
- Graph SOURCE connection
- Graph TARGET connection
- Separate admin accounts allowed
- Token handled per session
- No token persistence

Modules validated at startup:
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.DirectoryManagement
- Microsoft.Graph.Users
- Microsoft.Graph.Users.Actions
- Microsoft.Graph.Groups
- Microsoft.Graph.Identity.SignIns
- Microsoft.Graph.Applications

## 5.2 Exchange Online

Interactive authentication implemented.

Module required:
- ExchangeOnlineManagement

State tracked per session.

## 5.3 SharePoint Online

Module required:
- Microsoft.Online.SharePoint.PowerShell

Interactive Connect-SPOService implemented (admin URL derived from SPO admin tenant name logic currently in auth layer).

-----------------------------------------------------------------------

# 6. Discovery Phase (Operational)

## 6.1 Entra Users (SOURCE)

Output: EntraUsers_SOURCE.csv

Includes:
- Identity attributes
- Account state
- Hybrid attributes
- ProxyAddresses
- AssignedLicenses (GUID)
- AssignedPlans (GUID)
- Department / JobTitle / CompanyName
- OnPremises attributes

Supports:
- Cloud-only users
- Hybrid synchronized users

## 6.2 Entra Groups (SOURCE)

Output: EntraGroups_SOURCE.csv

Includes:
- Core group metadata
- MailEnabled / SecurityEnabled
- GroupTypes
- MembershipRule
- Dynamic group support

## 6.3 Group Membership (SOURCE)

Output: EntraGroupMembers_SOURCE.csv

Includes:
- GroupId
- GroupDisplayName
- MemberId
- MemberType
- MemberUserPrincipalName
- MemberDisplayName

Dynamic groups excluded (rule-based membership).

## 6.4 Entra Domains (SOURCE)

Output: EntraDomains_SOURCE.csv

Includes:
- DomainName
- IsVerified
- IsDefault
- IsInitial
- AuthenticationType
- State

Purpose:
- UPN suffix planning
- Federated vs Managed detection
- Target AD preparation

## 6.5 Exchange Online Discovery (SOURCE)

### Mailboxes

Output: EXO-Mailboxes_SOURCE.csv

Includes:
- Identity
- DisplayName
- PrimarySmtpAddress
- RecipientTypeDetails
- ExchangeGuid
- ArchiveGuid
- TotalItemSize
- ItemCount
- LastLogonTime

### Recipients (Mail-enabled objects)

Output: EXO-Recipients_SOURCE.csv

Includes:
- ExternalDirectoryObjectId
- RecipientTypeDetails
- DisplayName
- Alias
- PrimarySmtpAddress
- EmailAddresses
- HiddenFromAddressListsEnabled

System mailboxes excluded.

## 6.6 OneDrive Discovery (SOURCE)

Output: SPO-OneDriveSites_SOURCE.csv

Includes:
- Url
- Owner
- StorageQuotaMB
- StorageUsageCurrentMB
- LastContentModifiedDate
- Status
- LockState
- IsHubSite
- HubSiteId

Personal sites detected via:
Contains("/personal/")

Hub awareness enabled.

-----------------------------------------------------------------------

# 7. Identity Preparation Phase (In Progress)

Goal: prepare target identity layer prior to migration. This phase transitions from read-only discovery to controlled on-prem and tenant write operations.

## 7.1 Prerequisites (New)

If Workloads.IdentityPreparation = $true, the tool enforces an Active Directory prerequisite check at startup:

- RSAT ActiveDirectory module must be present (Get-Module -ListAvailable ActiveDirectory)
- Import-Module ActiveDirectory must succeed
- Get-ADForest must succeed (connectivity + permissions)

Failure stops the tool early (fail-fast).

## 7.2 Users - On-Prem Provisioning Plan (Implemented)

Step:
- 02-01-BuildUsersOnPremProvisioningPlan

Inputs:
- output\runs\<RunId>\01-Discovery\EntraUsers_SOURCE.csv

Behavior:
- Filters users with OnPremisesSyncEnabled = True (Synced users)
- Prompts operator for Target OU (interactive)
  - Persists last used OU in config.psd1 as OnPremIdentity.LastUsedTargetOU
- Extracts distinct Source UPN suffixes for synced users
  - For each suffix, operator chooses:
    - Use the same suffix in target AD (Y/N)
    - If N: provide an alternate suffix
  - Validates suffix presence in target AD forest
    - If missing: offers to create it using:
      - Set-ADForest -Identity <ForestName> -UPNSuffixes @{Add=<suffix>}
- Generates a single plan file:
  - output\runs\<RunId>\02-IdentityPreparation\Users_OnPrem_ProvisioningPlan.csv
- Returns WaitingUser to enforce operator validation before execution

Plan file intent:
- This plan is the single source of truth for subsequent on-prem user creation (execution step to be implemented).
- If OnPremisesSamAccountName is missing, the user is marked Blocked (no guessing).

## 7.3 Naming Convention Decision (Confirmed)

- Identity plan file name explicitly indicates on-prem provisioning intent:
  - Users_OnPrem_ProvisioningPlan.csv

## 7.4 Known UX Hardening (Planned)

- Enforce strict Y/N validation for suffix prompts to prevent accidental free-text inputs.

-----------------------------------------------------------------------

# 8. Design Decisions (Confirmed)

- Two-file model for groups (metadata + membership)
- Single enriched CSV for users
- Two-file model for EXO (Mailboxes + Recipients)
- Single CSV per workload entity
- No over-engineering
- Discovery remains read-only
- Minimal but architecture-aware data capture
- IdentityPreparation starts with planning gates (WaitingUser) before any write operations

-----------------------------------------------------------------------

# 9. What Is NOT Implemented Yet

- IdentityPreparation execution step(s):
  - Review/Approve provisioning plan step
  - Create AD users step (idempotent; conflict handling)
  - Cloud-only user creation in target tenant
  - Group recreation logic (synced vs cloud)
- ImmutableId strategy finalization (hybrid handling)
- License reassignment engine
- Exchange migration logic
- OneDrive migration execution
- SharePoint migration execution
- Advanced resume policies
- Token refresh optimization
- Cross-tenant mapping engine

-----------------------------------------------------------------------

# 10. Current Stability

Runner: Stable  
Config lifecycle: Stable (now supports OnPremIdentity.LastUsedTargetOU persistence)  
Step engine: Stable  
Dependency resolver: Stable  
Graph auth: Stable  
Exchange auth: Stable  
SharePoint auth: Working (current implementation)  
Discovery phase: Operational & Production-test ready  
IdentityPreparation: Planning step for Synced users operational (WaitingUser gate)  
Write operations: Not implemented

Architecture maturity: High  
Business logic maturity: Medium (Discovery complete; IdentityPreparation planning started)

-----------------------------------------------------------------------

# 11. Strategic Next Phase

1. IdentityPreparation:
   - Step 02-02: Review/Approve Users_OnPrem_ProvisioningPlan.csv (operator gate -> Completed)
   - Step 02-03: Create AD users from approved plan (idempotent; conflict handling)
2. Identity mapping design (synced vs cloud-only; UPN strategy)
3. ImmutableId / Hybrid handling strategy finalization
4. License reassignment engine
5. Controlled write operations testing

-----------------------------------------------------------------------

# 12. Summary

The project now has:

- Interactive runner
- Modular architecture
- Step-based execution engine
- Resume capability via run_state.csv
- Dependency-aware authentication
- Full Discovery for:
  - Entra Users
  - Entra Groups
  - Group Membership
  - Entra Domains
  - Exchange Mailboxes
  - Exchange Recipients
  - OneDrive Sites (Hub-aware)
- IdentityPreparation started:
  - AD prerequisites enforced (fail-fast)
  - Synced Users on-prem provisioning plan generation implemented
  - Operator gate enforced (WaitingUser)

Next milestone transitions from read-only discovery to controlled write operations, starting with plan validation and AD provisioning.

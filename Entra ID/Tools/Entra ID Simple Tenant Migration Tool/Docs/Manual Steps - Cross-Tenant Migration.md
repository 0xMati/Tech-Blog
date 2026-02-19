# Manual Steps — Cross-Tenant Microsoft 365 Migration

> This document lists **every manual task** required to perform a full tenant-to-tenant migration (Entra ID identities, Exchange Online mailboxes, OneDrive for Business content) without using the automated tool. Follow the steps in order. Each section explains **what to do**, **why**, and provides **PowerShell examples**.

---

## Table of Contents

- [Before You Start — Prerequisites](#before-you-start--prerequisites)
- [Phase 1 — Inventory the Source Tenant](#phase-1--inventory-the-source-tenant)
- [Phase 2 — Provision Identities in the Target Tenant](#phase-2--provision-identities-in-the-target-tenant)
- [Phase 3 — Set Up Exchange Cross-Tenant Migration](#phase-3--set-up-exchange-cross-tenant-migration)
- [Phase 4 — Execute Exchange Mailbox Migration](#phase-4--execute-exchange-mailbox-migration)
- [Phase 5 — Set Up OneDrive Cross-Tenant Migration](#phase-5--set-up-onedrive-cross-tenant-migration)
- [Phase 6 — Execute OneDrive Content Migration](#phase-6--execute-onedrive-content-migration)
- [Phase 7 — Post-Migration Cleanup](#phase-7--post-migration-cleanup)

---

## Before You Start — Prerequisites

### Install Required PowerShell Modules

Open an elevated PowerShell 5.1 window and install all modules you'll need:

```powershell
# Microsoft Graph modules (for Entra ID user/group/app management)
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Users.Actions -Scope CurrentUser
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Applications -Scope CurrentUser

# Exchange Online module (for mailbox migration)
Install-Module ExchangeOnlineManagement -Scope CurrentUser

# SharePoint Online module (for OneDrive migration)
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

### Install RSAT Active Directory Tools (if migrating AD-synced users)

```powershell
# Windows 10/11 — run as Administrator
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

Or via GUI: **Settings > Apps > Optional features > Add a feature > RSAT: Active Directory DS-LDS Tools**

### Verify Admin Permissions

Before starting, make sure you have:

- [ ] **Global Reader** on the source tenant (for inventory — or Global Admin if you also need to modify the source)
- [ ] **Global Administrator** on the target tenant (to create users, register apps, assign licenses)
- [ ] **Exchange Administrator** on **both** tenants (for organization relationships, migration batches)
- [ ] **SharePoint Administrator** on **both** tenants (for cross-tenant trust, OneDrive moves)
- [ ] **Domain Admin** or delegated OU admin on the target Active Directory forest (if using AD-synced users)

### Verify Licensing

- [ ] **Cross-Tenant User Data Migration** add-on license (or equivalent) — must be assigned on **both** tenants
  - Check in M365 Admin Center > Billing > Licenses
  - Without this, cross-tenant Exchange and OneDrive migrations will fail
- [ ] Enough **Exchange Online** licenses available on the target (to assign to migrated users)
- [ ] Enough **OneDrive/SharePoint** licenses available on the target (users need them before OneDrive migration)

> 📖 [Cross-tenant mailbox migration prerequisites](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide)

---

## Phase 1 — Inventory the Source Tenant

> **Goal**: Export everything from the source tenant so you know exactly what needs to be migrated.

### 1.1 — Export All Entra ID Users

**Why**: You need to know every user account — their UPN, display name, department, whether they're synced from AD, what licenses they have, their proxy addresses, etc.

```powershell
# Connect to the SOURCE tenant via Microsoft Graph
Connect-MgGraph -TenantId "source.onmicrosoft.com" -Scopes "User.Read.All","Directory.Read.All"

# Export all users with key properties
$users = Get-MgUser -All -Property `
    Id, UserPrincipalName, DisplayName, GivenName, Surname, Mail, `
    ProxyAddresses, OnPremisesSyncEnabled, OnPremisesSamAccountName, `
    OnPremisesDistinguishedName, OnPremisesImmutableId, `
    AccountEnabled, UserType, Department, JobTitle, CompanyName, `
    OfficeLocation, City, Country, UsageLocation, `
    AssignedLicenses, LicenseAssignmentStates

$users | Select-Object Id, UserPrincipalName, DisplayName, GivenName, Surname, Mail,
    @{N='ProxyAddresses';E={$_.ProxyAddresses -join ';'}},
    OnPremisesSyncEnabled, OnPremisesSamAccountName,
    OnPremisesDistinguishedName, OnPremisesImmutableId,
    AccountEnabled, UserType, Department, JobTitle, CompanyName,
    OfficeLocation, City, Country, UsageLocation,
    @{N='AssignedLicenses';E={($_.AssignedLicenses | ForEach-Object { $_.SkuId }) -join ';'}} |
    Export-Csv ".\EntraUsers_SOURCE.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($users.Count) users"
```

**What to look for in the export**:
- `OnPremisesSyncEnabled = True` → These users are synced from AD, they need to be recreated in the **target AD** first
- `OnPremisesSyncEnabled = (empty)` and `UserType = Member` → Cloud-only users, create directly in target Entra ID
- `UserType = Guest` → Guest users, re-invite in target tenant
- `AccountEnabled = False` → Disabled accounts — decide if you want to migrate them

### 1.2 — Export All Domains

**Why**: You need to know what domains are configured on the source so you can plan UPN suffix mapping for the target.

```powershell
Get-MgDomain -All | Select-Object Id, AuthenticationType, IsDefault, IsVerified |
    Export-Csv ".\EntraDomains_SOURCE.csv" -NoTypeInformation -Encoding UTF8
```

**What to look for**:
- Each verified domain in the source will need to either be added to the target, or you'll need to map users to a different UPN suffix
- Remember: a domain can only be verified on **one tenant at a time** — you may need to use temporary UPNs during migration

### 1.3 — Export All Groups

**Why**: Groups need to be recreated in the target with the same memberships.

```powershell
$groups = Get-MgGroup -All -Property `
    Id, DisplayName, Description, GroupTypes, SecurityEnabled, MailEnabled, `
    MailNickname, Mail, ProxyAddresses, OnPremisesSyncEnabled, MembershipRule

$groups | Select-Object Id, DisplayName, Description,
    @{N='GroupTypes';E={$_.GroupTypes -join ';'}},
    SecurityEnabled, MailEnabled, MailNickname, Mail,
    @{N='ProxyAddresses';E={$_.ProxyAddresses -join ';'}},
    OnPremisesSyncEnabled, MembershipRule |
    Export-Csv ".\EntraGroups_SOURCE.csv" -NoTypeInformation -Encoding UTF8

Write-Host "Exported $($groups.Count) groups"
```

### 1.4 — Export Group Memberships

**Why**: After recreating groups in the target, you'll need to repopulate them with the correct members.

```powershell
$memberships = @()
$staticGroups = $groups | Where-Object { $_.GroupTypes -notcontains "DynamicMembership" }

foreach ($group in $staticGroups) {
    Write-Host "Exporting members for: $($group.DisplayName)"
    $members = Get-MgGroupMember -GroupId $group.Id -All

    foreach ($member in $members) {
        $memberships += [PSCustomObject]@{
            GroupId          = $group.Id
            GroupDisplayName = $group.DisplayName
            MemberId         = $member.Id
            MemberUPN        = $member.AdditionalProperties.userPrincipalName
            MemberType       = $member.AdditionalProperties.'@odata.type'
        }
    }
}

$memberships | Export-Csv ".\EntraGroupMembers_SOURCE.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($memberships.Count) membership entries"
```

> **Note**: Dynamic groups don't need member export — their membership is calculated from rules that you'll recreate.

### 1.5 — Export All Exchange Mailboxes

**Why**: You need to know which users have mailboxes, their type (User, Shared, Room, Equipment), their size, their ExchangeGuid, and their proxy addresses.

```powershell
# Connect to source Exchange Online
Connect-ExchangeOnline

# Export all mailboxes
$mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets All

$result = foreach ($mbx in $mailboxes) {
    $stats = Get-EXOMailboxStatistics -Identity $mbx.UserPrincipalName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        UserPrincipalName       = $mbx.UserPrincipalName
        DisplayName             = $mbx.DisplayName
        PrimarySmtpAddress      = $mbx.PrimarySmtpAddress
        RecipientTypeDetails    = $mbx.RecipientTypeDetails
        ExchangeGuid            = $mbx.ExchangeGuid
        ArchiveGuid             = $mbx.ArchiveGuid
        LegacyExchangeDN        = $mbx.LegacyExchangeDN
        EmailAddresses          = ($mbx.EmailAddresses -join ';')
        TotalItemSize           = if ($stats) { $stats.TotalItemSize } else { '' }
        ItemCount               = if ($stats) { $stats.ItemCount } else { '' }
    }
}

$result | Export-Csv ".\EXO-Mailboxes_SOURCE.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($result.Count) mailboxes"
```

**Key properties to note**:
- `ExchangeGuid` — You'll need this later to stamp the target MailUser
- `LegacyExchangeDN` — Needed as an X500 proxy address on the target to preserve reply-ability
- `RecipientTypeDetails` — Tells you if it's a User, Shared, Room, or Equipment mailbox

### 1.6 — Export All Exchange Recipients

**Why**: This gives you the full picture of all mail-enabled objects (mailboxes, mail users, mail contacts, distribution groups, etc.).

```powershell
Get-EXORecipient -ResultSize Unlimited |
    Where-Object { $_.DisplayName -ne "DiscoverySearchMailbox" } |
    Select-Object DisplayName, PrimarySmtpAddress, RecipientType, RecipientTypeDetails,
        ExternalDirectoryObjectId |
    Export-Csv ".\EXO-Recipients_SOURCE.csv" -NoTypeInformation -Encoding UTF8
```

### 1.7 — Export All Mail Contacts

**Why**: Mail contacts (external email addresses in the GAL) need to be recreated in the target so the address book is complete.

```powershell
Get-MailContact -ResultSize Unlimited |
    Select-Object ExternalDirectoryObjectId, DisplayName, Name, Alias,
        ExternalEmailAddress, PrimarySmtpAddress,
        @{N='EmailAddresses';E={$_.EmailAddresses -join ';'}},
        HiddenFromAddressListsEnabled, WhenCreated, WhenChanged |
    Export-Csv ".\EXO-MailContacts_SOURCE.csv" -NoTypeInformation -Encoding UTF8
```

### 1.8 — Export All OneDrive Sites

**Why**: Identifies which users have OneDrive data and how much storage they use.

```powershell
# Disconnect Exchange, connect to SharePoint
Disconnect-ExchangeOnline -Confirm:$false
Connect-SPOService -Url "https://source-admin.sharepoint.com"

Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal'" |
    Select-Object Url, Owner, StorageQuota, StorageUsageCurrent, LastContentModifiedDate, Status |
    Export-Csv ".\SPO-OneDriveSites_SOURCE.csv" -NoTypeInformation -Encoding UTF8
```

### 1.9 — Export All SharePoint Sites

**Why**: Inventory for future SharePoint migration or just to have a complete picture.

```powershell
Get-SPOSite -Limit All |
    Where-Object { $_.Url -notlike '*-my.sharepoint.com/personal/*' } |
    Select-Object Url, Title, Template, StorageQuota, StorageUsageCurrent, Owner,
        SharingCapability, HubSiteId, IsHubSite, LastContentModifiedDate |
    Export-Csv ".\SPO-Sites_SOURCE.csv" -NoTypeInformation -Encoding UTF8
```

---

## Phase 2 — Provision Identities in the Target Tenant

> **Goal**: Create all user accounts, groups, guests, and contacts in the target tenant **before** migrating any data.

### 2.1 — Plan UPN Suffix Mapping

**Why**: Users in the source have UPNs like `user@contoso.com`. In the target, you need to decide what their UPN will be. If you're keeping the same domain, you'll need to remove it from the source first (since a domain can only be verified on one tenant at a time). Most migrations use a temporary UPN first, then switch later.

- [ ] Review the domains export from Phase 1
- [ ] Decide: will target users keep the same UPN suffix, or use a temporary one (e.g. `@target.onmicrosoft.com`)?
- [ ] If using the same domain: plan the DNS cutover timing carefully

### 2.2 — Create AD-Synced Users in Target Active Directory

**Why**: If the source tenant has users synced from on-premises AD, you need to create matching users in the **target** AD forest so that Entra Connect can sync them to the target Entra ID.

**Step-by-step**:

- [ ] **Choose or create a target OU** for the migrated users

```powershell
# Example: Create a dedicated OU
New-ADOrganizationalUnit -Name "MigratedUsers" -Path "OU=Company,DC=target,DC=local"
```

- [ ] **Verify UPN suffixes** in the target AD forest

```powershell
# List current UPN suffixes
(Get-ADForest).UPNSuffixes

# Add a new UPN suffix if needed (e.g., the source domain)
Set-ADForest -UPNSuffixes @{Add="contoso.com"}
```

- [ ] **Create each user** in Active Directory

```powershell
# Example for one user
$password = ConvertTo-SecureString "TempP@ss2025!" -AsPlainText -Force

New-ADUser `
    -Name "John Doe" `
    -SamAccountName "john.doe" `
    -UserPrincipalName "john.doe@contoso.com" `
    -GivenName "John" `
    -Surname "Doe" `
    -DisplayName "John Doe" `
    -Department "Engineering" `
    -Title "Senior Engineer" `
    -Office "Building A" `
    -City "Paris" `
    -Country "FR" `
    -Path "OU=MigratedUsers,OU=Company,DC=target,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -ChangePasswordAtLogon $true
```

- [ ] **For users with mailboxes**: Set mail-related attributes so Entra Connect syncs them as **MailUser** objects (not just regular users)

```powershell
# These attributes tell Entra Connect to create a MailUser in Exchange Online
Set-ADUser "john.doe" -Replace @{
    mail            = "john.doe@contoso.com"
    targetAddress   = "SMTP:john.doe@source.mail.onmicrosoft.com"
    proxyAddresses  = @("SMTP:john.doe@contoso.com", "smtp:john.doe@target.onmicrosoft.com")
}
```

> **Important**: The `targetAddress` must point to the **source** mailbox routing address (usually `user@source.mail.onmicrosoft.com`). This is what makes the user a MailUser instead of creating a new empty mailbox.

> 📖 [Plan Entra Connect sync prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)

### 2.3 — Create Cloud-Only Users in Target Entra ID

**Why**: Users that exist only in Entra ID (not synced from AD) need to be created directly in the target tenant via Microsoft Graph.

```powershell
# Connect to the TARGET tenant
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "User.ReadWrite.All"

# Example: Create one cloud-only user
$passwordProfile = @{
    Password                      = "TempP@ss2025!"
    ForceChangePasswordNextSignIn = $true
}

New-MgUser `
    -UserPrincipalName "clouduser@target.onmicrosoft.com" `
    -DisplayName "Cloud User" `
    -GivenName "Cloud" `
    -Surname "User" `
    -MailNickname "clouduser" `
    -PasswordProfile $passwordProfile `
    -AccountEnabled:$true `
    -UsageLocation "FR" `
    -Department "Marketing" `
    -JobTitle "Marketing Manager"
```

Repeat for every cloud-only user from your inventory.

> 📖 [Create a user in Entra ID](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-users)

### 2.4 — Invite Guest Users to Target Tenant

**Why**: B2B guest accounts from the source tenant need to be re-invited in the target tenant.

```powershell
# Invite a guest
New-MgInvitation `
    -InvitedUserEmailAddress "partner@external.com" `
    -InvitedUserDisplayName "Partner User" `
    -InviteRedirectUrl "https://myapps.microsoft.com" `
    -SendInvitationMessage:$false
```

> **Note**: Setting `-SendInvitationMessage:$false` prevents sending the invitation email. The guest account is created immediately and can be used for permissions/group memberships. You can send the invitation later if needed.

> 📖 [Invite B2B collaboration users](https://learn.microsoft.com/en-us/entra/external-id/add-users-administrator)

### 2.5 — Create Groups in Target

#### A. AD-Synced Security Groups (in target AD)

```powershell
# Create each group in the target AD
New-ADGroup `
    -Name "Engineering Team" `
    -SamAccountName "EngineeringTeam" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=MigratedGroups,OU=Company,DC=target,DC=local" `
    -Description "Engineering team security group"
```

#### B. Cloud-Only Groups (in target Entra ID)

```powershell
# Security group
New-MgGroup `
    -DisplayName "Marketing Team" `
    -MailEnabled:$false `
    -MailNickname "MarketingTeam" `
    -SecurityEnabled:$true `
    -Description "Marketing team security group"

# Microsoft 365 group
New-MgGroup `
    -DisplayName "Project Alpha" `
    -MailEnabled:$true `
    -MailNickname "ProjectAlpha" `
    -SecurityEnabled:$false `
    -GroupTypes @("Unified") `
    -Description "Project Alpha collaboration group"
```

### 2.6 — Populate Group Memberships

**Why**: Groups are empty after creation — you need to add the newly created target users to the corresponding groups.

#### A. AD Groups

```powershell
# Use the source group membership export to repopulate
# For each group, add the corresponding target users
Add-ADGroupMember -Identity "EngineeringTeam" -Members "john.doe","jane.smith"
```

#### B. Cloud Groups

```powershell
# Get the group ID
$group = Get-MgGroup -Filter "DisplayName eq 'Marketing Team'"

# Get the user ID
$user = Get-MgUser -Filter "UserPrincipalName eq 'clouduser@target.onmicrosoft.com'"

# Add member
New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id
```

### 2.7 — Configure Entra Connect Sync Scope

**Why**: If you created users and groups in the target AD, Entra Connect needs to include those OUs in its sync scope, otherwise the objects will never appear in the target Entra ID.

- [ ] Open **Entra Connect** on the sync server
- [ ] Go to **Configure > Customize synchronization options**
- [ ] In **Domain and OU filtering**, check the new OUs (e.g., `MigratedUsers`, `MigratedGroups`)
- [ ] Click through to finish

Then force a sync cycle:

```powershell
# Run on the Entra Connect server
Start-ADSyncSyncCycle -PolicyType Delta
```

- [ ] **Verify in the Entra admin center** that the users appear under Users > All Users
- [ ] **Verify** that they show as "MailUser" type in Exchange Online (if they had mail attributes set)

```powershell
# Check in Exchange Online (target)
Connect-ExchangeOnline
Get-Recipient "john.doe@contoso.com" | Select-Object RecipientTypeDetails
# Should return: MailUser
```

> 📖 [Configure Entra Connect OU filtering](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering)

### 2.8 — Recreate Mail Contacts in Target

**Why**: Mail contacts represent external email addresses (vendors, partners, etc.) that appear in the Global Address List. Users expect to find these in the target tenant's address book.

```powershell
# Connect to target Exchange Online
Connect-ExchangeOnline

# For each contact from the source export:
New-MailContact `
    -Name "John External" `
    -DisplayName "John External" `
    -ExternalEmailAddress "john@externalcompany.com" `
    -Alias "johnexternal"

# If the contact was hidden from the address list in the source:
Set-MailContact -Identity "johnexternal" -HiddenFromAddressListsEnabled $true
```

Repeat for every mail contact from your Phase 1 export.

> **Tip**: Normalize aliases — remove special characters, spaces, accents. Exchange requires aliases to be alphanumeric with dots, hyphens, and underscores only.

> 📖 [Manage mail contacts in Exchange Online](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-mail-contacts)

---

## Phase 3 — Set Up Exchange Cross-Tenant Migration

> **Goal**: Build the trust infrastructure between the two tenants so mailboxes can move from SOURCE to TARGET.

> 📖 [Full Microsoft documentation — Cross-tenant mailbox migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide)

### 3.1 — Verify Prerequisites

Before proceeding, confirm:

- [ ] **Cross-Tenant User Data Migration** license is assigned on both tenants
- [ ] You have **Exchange Administrator** role on both tenants
- [ ] You know the **Tenant ID (GUID)** for both tenants

```powershell
# Get tenant ID via Graph
Connect-MgGraph -TenantId "source.onmicrosoft.com"
(Get-MgContext).TenantId  # e.g., "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

Connect-MgGraph -TenantId "target.onmicrosoft.com"
(Get-MgContext).TenantId  # e.g., "11111111-2222-3333-4444-555555555555"
```

### 3.2 — Create the Migration Application in the Target Tenant

**Why**: Microsoft's cross-tenant migration uses an Entra ID application to establish trust. The TARGET tenant creates the app, then the SOURCE tenant consents to it.

```powershell
# Connect to TARGET tenant with elevated permissions
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All"

# 1) Create the application registration
$appParams = @{
    DisplayName    = "Cross-Tenant Mailbox Migration"
    SignInAudience = "AzureADMultipleOrgs"
}
$app = New-MgApplication @appParams
Write-Host "Application ID: $($app.AppId)"

# 2) Create the service principal
$sp = New-MgServicePrincipal -AppId $app.AppId
Write-Host "Service Principal ID: $($sp.Id)"

# 3) Create a client secret (note the expiry — max 2 years recommended)
$secretParams = @{
    PasswordCredential = @{
        DisplayName = "Migration Secret"
        EndDateTime = (Get-Date).AddYears(1)
    }
}
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -BodyParameter $secretParams
Write-Host "Client Secret: $($secret.SecretText)"  # SAVE THIS — you won't see it again!

# 4) Assign the Mailbox.Migration app role from Exchange Online
# Exchange Online service principal ID is always: 00000002-0000-0ff1-ce00-000000000000
$exoSp = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"

# Find the Mailbox.Migration role
$migrationRole = $exoSp.AppRoles | Where-Object { $_.Value -eq "Mailbox.Migration" }

# Assign the role to our app's service principal
$roleAssignment = @{
    PrincipalId = $sp.Id
    ResourceId  = $exoSp.Id
    AppRoleId   = $migrationRole.Id
}
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -BodyParameter $roleAssignment
```

**Save these values** — you'll need them in the next steps:
- Application (client) ID: `$app.AppId`
- Client secret: `$secret.SecretText`
- Target tenant ID

> 📖 [Create the migration application](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-the-target-destination-tenant-by-creating-the-migration-application-and-secret)

### 3.3 — Create Migration Endpoint on Target

**Why**: The migration endpoint tells Exchange Online TARGET where to pull mailbox data from.

```powershell
# Connect to TARGET Exchange Online
Connect-ExchangeOnline  # (target tenant)

$endpointParams = @{
    Name                       = "CrossTenantMigrationEndpoint"
    RemoteServer               = "outlook.office.com"
    ExchangeRemoteMove         = $true
    ApplicationId              = "<Target App ID from step 3.2>"
    AppSecretKeyVaultUrl       = "<Client Secret from step 3.2>"  # or use -Credential
    SourceMailboxMovePublishedScopes = "<Source Tenant ID>"
}

# The exact syntax depends on your EXO version — use the documented approach:
$endpoint = New-MigrationEndpoint `
    -Name "CrossTenantMigrationEndpoint" `
    -RemoteServer "outlook.office.com" `
    -ExchangeRemoteMove:$true `
    -ApplicationId "<AppId>" `
    -AppSecretKeyVaultUrl "<ClientSecret>"

Write-Host "Endpoint created: $($endpoint.Identity)"
```

### 3.4 — Create Organization Relationship on Target (Inbound)

**Why**: The organization relationship allows the source tenant to push migration data to the target.

```powershell
# Still on TARGET Exchange Online
$orgRelParams = @{
    Name              = "SourceToTarget_Inbound"
    DomainNames       = @("source.onmicrosoft.com")
    MailboxMoveEnabled = $true
    MailboxMoveCapability = "Inbound"
}

New-OrganizationRelationship @orgRelParams
```

### 3.5 — Admin Consent on Source Tenant

**Why**: The SOURCE tenant admin must consent to the TARGET application so it can access source mailboxes.

- [ ] Open a browser and navigate to:

```
https://login.microsoftonline.com/<SOURCE_TENANT_ID>/adminconsent?client_id=<TARGET_APP_ID>
```

Replace `<SOURCE_TENANT_ID>` with the source tenant GUID and `<TARGET_APP_ID>` with the application ID from step 3.2.

- [ ] Sign in with a **Global Administrator** account on the SOURCE tenant
- [ ] Click **Accept** to grant consent

### 3.6 — Create Scoping Security Group on Source

**Why**: The scoping group controls which mailboxes are allowed to migrate. Only mailboxes whose owners are members of this group can be moved by the cross-tenant migration.

```powershell
# Connect to SOURCE Exchange Online
Connect-ExchangeOnline  # (source tenant)

# Enable organization customization (required for creating groups with certain types)
Enable-OrganizationCustomization -ErrorAction SilentlyContinue

# Create a mail-enabled security group
New-DistributionGroup `
    -Name "MAILBOXMIGRATION" `
    -Type Security `
    -Description "Users approved for cross-tenant mailbox migration"
```

### 3.7 — Create Organization Relationship on Source (Outbound)

**Why**: The organization relationship on the source side authorizes the migration and specifies which users are in scope.

```powershell
# Still on SOURCE Exchange Online
$orgRelParams = @{
    Name                         = "TargetFromSource_Outbound"
    DomainNames                  = @("target.onmicrosoft.com")
    MailboxMoveEnabled           = $true
    MailboxMoveCapability        = "RemoteOutbound"
    OAuthApplicationId           = "<Target App ID from step 3.2>"
    MailboxMovePublishedScopes   = @("MAILBOXMIGRATION")
}

New-OrganizationRelationship @orgRelParams
```

### 3.8 — Stamp Target MailUsers with Source Mailbox Data

**Why**: For each mailbox you want to migrate, the corresponding MailUser in the target needs to be "stamped" with the source mailbox's `ExchangeGuid` and `LegacyExchangeDN`. Without this, Exchange doesn't know which source mailbox maps to which target user.

```powershell
# For EACH user with a mailbox:

# 1) Get source mailbox properties (on SOURCE)
Connect-ExchangeOnline  # (source tenant)
$sourceMbx = Get-Mailbox "john.doe@contoso.com"
$sourceGuid = $sourceMbx.ExchangeGuid
$sourceLegacyDN = $sourceMbx.LegacyExchangeDN
$sourceAddress = $sourceMbx.PrimarySmtpAddress
Disconnect-ExchangeOnline -Confirm:$false

# 2) Stamp the target MailUser (on TARGET)
Connect-ExchangeOnline  # (target tenant)
Set-MailUser "john.doe@target.onmicrosoft.com" `
    -ExchangeGuid $sourceGuid `
    -ExternalEmailAddress "SMTP:$sourceAddress"

# 3) Add LegacyExchangeDN as X500 proxy address (for reply-ability)
$x500 = "X500:$sourceLegacyDN"
Set-MailUser "john.doe@target.onmicrosoft.com" -EmailAddresses @{Add=$x500}
```

**Repeat for every user being migrated.**

> **Why X500?**: When someone replies to an old email sent from the source mailbox, Outlook uses the `LegacyExchangeDN` to route the reply. Without the X500 address, those replies bounce with "user not found".

> 📖 [Prepare target user objects for migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide#prepare-target-user-objects-for-migration)

### 3.9 — Handle Soft-Deleted Mailboxes (if any)

**Why**: If a target user previously had a mailbox that was deleted, a "soft-deleted" ghost remains for 30 days. This blocks the migration. You must clear it.

```powershell
# On TARGET Exchange Online
# Check if a user has a soft-deleted mailbox:
Get-Recipient "john.doe@target.onmicrosoft.com" | Select-Object RecipientTypeDetails
# If it returns "SoftDeletedMailbox" or similar:

Set-User "john.doe@target.onmicrosoft.com" -PermanentlyClearPreviousMailboxInfo
# Wait a few minutes for Exchange to process this
```

---

## Phase 4 — Execute Exchange Mailbox Migration

> **Goal**: Move mailboxes from SOURCE to TARGET, monitor progress, and finalize.

### 4.1 — Add Users to the Scoping Group

**Why**: Only users in the scoping security group are authorized for migration.

```powershell
# On SOURCE Exchange Online
Connect-ExchangeOnline  # (source tenant)

# Add each user to the migration scope group
Add-DistributionGroupMember -Identity "MAILBOXMIGRATION" -Member "john.doe@contoso.com"
Add-DistributionGroupMember -Identity "MAILBOXMIGRATION" -Member "jane.smith@contoso.com"
# ... repeat for all users
```

### 4.2 — Create and Start the Migration Batch

**Why**: A migration batch tells Exchange Online to start moving the specified mailboxes.

```powershell
# 1) Prepare the batch CSV file (required format)
# Create a CSV with one column: EmailAddress (= target UPN)
@"
EmailAddress
john.doe@target.onmicrosoft.com
jane.smith@target.onmicrosoft.com
"@ | Out-File ".\migration_batch.csv" -Encoding UTF8

# 2) Connect to TARGET Exchange Online
Connect-ExchangeOnline  # (target tenant)

# 3) Create and start the migration batch
$csvData = [System.IO.File]::ReadAllBytes(".\migration_batch.csv")

New-MigrationBatch `
    -Name "Batch1-Engineers" `
    -SourceEndpoint "CrossTenantMigrationEndpoint" `
    -CSVData $csvData `
    -TargetDeliveryDomain "target.mail.onmicrosoft.com" `
    -AutoStart `
    -AutoComplete
```

> **Options**:
> - `-AutoStart` — Starts the initial sync immediately (otherwise you must run `Start-MigrationBatch` manually)
> - `-AutoComplete` — Automatically finalizes the migration once initial sync is done (otherwise you must run `Complete-MigrationBatch` manually)
> - Without `-AutoComplete`, the batch pauses in a "Synced" state, letting you choose when to do the final cutover

### 4.3 — Monitor Migration Progress

**Why**: Mailbox migrations can take hours or days depending on mailbox size. You need to monitor progress to detect failures early.

```powershell
# On TARGET Exchange Online

# Check batch status
Get-MigrationBatch | Format-Table Identity, Status, TotalCount, SyncedCount, FinalizedCount, FailedCount

# Check individual user status
Get-MigrationUser | Format-Table Identity, Status, StatusSummary, ErrorSummary

# For detailed error info on a failed user:
Get-MigrationUser "john.doe@target.onmicrosoft.com" | Format-List *
```

**Status values**:
| Status | Meaning |
|--------|---------|
| `Syncing` | Initial data copy in progress |
| `Synced` | Initial copy done, waiting for completion (if no `-AutoComplete`) |
| `Completing` | Final cutover in progress |
| `Completed` | Migration finished successfully |
| `Failed` | Something went wrong — check `ErrorSummary` |

> **Tip**: Run the `Get-MigrationBatch` / `Get-MigrationUser` commands repeatedly (every 15-30 minutes) to track progress.

### 4.4 — Complete (Finalize) the Migration Batch

**Why**: Completing the batch triggers the final cutover. The source mailbox becomes a MailUser (with forwarding), and the target MailUser becomes a full UserMailbox. **This is irreversible without significant effort.**

```powershell
# Only if you did NOT use -AutoComplete:
Complete-MigrationBatch -Identity "Batch1-Engineers"
```

### 4.5 — Clean Up Migration Batch

```powershell
# After the batch is fully completed, remove it
Remove-MigrationBatch -Identity "Batch1-Engineers" -Confirm:$false
```

### 4.6 — Assign Exchange Licenses to Migrated Users

**Why**: After migration, the target users need an **Exchange Online license** to actually access their mailbox. Without a license, the mailbox will eventually be soft-deleted.

```powershell
# Connect to TARGET Graph
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "User.ReadWrite.All"

# List available license SKUs
Get-MgSubscribedSku | Select-Object SkuPartNumber, SkuId, ConsumedUnits,
    @{N='Available';E={$_.PrepaidUnits.Enabled - $_.ConsumedUnits}}

# Assign a license (e.g., Microsoft 365 E3 = "SPE_E3")
$skuId = (Get-MgSubscribedSku | Where-Object { $_.SkuPartNumber -eq "SPE_E3" }).SkuId

# For each migrated user:
Set-MgUserLicense -UserId "john.doe@target.onmicrosoft.com" `
    -AddLicenses @(@{SkuId = $skuId}) `
    -RemoveLicenses @()
```

> 📖 [Assign licenses to users](https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users?view=o365-worldwide)

---

## Phase 5 — Set Up OneDrive Cross-Tenant Migration

> **Goal**: Establish a cross-tenant trust between the two SharePoint Online tenants and prepare identity mappings for OneDrive content moves.
>
> Microsoft calls this the **Mergers & Acquisitions (MnA) framework**.

> 📖 [Full Microsoft documentation — Cross-tenant OneDrive migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration?view=o365-worldwide)

### 5.1 — Verify OneDrive Migration Prerequisites

- [ ] **Cross-Tenant User Data Migration** license is assigned on both tenants
- [ ] **SharePoint Administrator** role on both tenants
- [ ] Target users are created and have **OneDrive/SharePoint licenses** assigned
- [ ] Target users' OneDrive sites are **pre-provisioned** (see step 5.4)

### 5.2 — Build the Source-to-Target User Mapping

**Why**: You need a mapping of who in the SOURCE corresponds to who in the TARGET, so OneDrive knows where to move each user's files.

Create a spreadsheet or CSV with at minimum:

| SourceUPN | TargetUPN | Status |
|-----------|-----------|--------|
| john.doe@contoso.com | john.doe@target.onmicrosoft.com | OK |
| jane.smith@contoso.com | jane.smith@target.onmicrosoft.com | OK |

Use your Phase 2 creation results to build this mapping.

### 5.3 — Establish Cross-Tenant Trust (MnA)

**Why**: SharePoint requires a trust relationship between the two tenants before it will allow content to move between them.

```powershell
# ============================
# Step A: Get CrossTenantHostUrl from BOTH tenants
# ============================

# On TARGET:
Connect-SPOService -Url "https://target-admin.sharepoint.com"
$targetHostUrl = Get-SPOCrossTenantHostUrl
Write-Host "Target CrossTenantHostUrl: $targetHostUrl"
Disconnect-SPOService

# On SOURCE:
Connect-SPOService -Url "https://source-admin.sharepoint.com"
$sourceHostUrl = Get-SPOCrossTenantHostUrl
Write-Host "Source CrossTenantHostUrl: $sourceHostUrl"
Disconnect-SPOService

# ============================
# Step B: Set up the trust on TARGET (partner = SOURCE)
# ============================
Connect-SPOService -Url "https://target-admin.sharepoint.com"

Set-SPOCrossTenantRelationship `
    -Scenario MnA `
    -PartnerRole Source `
    -PartnerCrossTenantHostUrl $sourceHostUrl

Disconnect-SPOService

# ============================
# Step C: Set up the trust on SOURCE (partner = TARGET)
# ============================
Connect-SPOService -Url "https://source-admin.sharepoint.com"

Set-SPOCrossTenantRelationship `
    -Scenario MnA `
    -PartnerRole Target `
    -PartnerCrossTenantHostUrl $targetHostUrl

Disconnect-SPOService

# ============================
# Step D: Verify trust on BOTH sides (wait 5-15 min if needed)
# ============================
Connect-SPOService -Url "https://target-admin.sharepoint.com"
Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl
# Should return: GoodToProceed
Disconnect-SPOService

Connect-SPOService -Url "https://source-admin.sharepoint.com"
Verify-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl
# Should return: GoodToProceed
Disconnect-SPOService
```

> **Important**: If `Verify-SPOCrossTenantRelationship` returns `NotEstablished`, wait 5-15 minutes and try again. DNS propagation and internal processes can cause a delay.

> 📖 [Set up cross-tenant OneDrive trust](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step2?view=o365-worldwide)

### 5.4 — Pre-Provision OneDrive Sites on Target

**Why**: OneDrive content can only be migrated into an **existing** OneDrive site. If the target user hasn't signed in yet, their OneDrive doesn't exist. You must pre-provision it.

```powershell
# Connect to TARGET SharePoint
Connect-SPOService -Url "https://target-admin.sharepoint.com"

# Pre-provision OneDrive for all target users
$targetUsers = @(
    "john.doe@target.onmicrosoft.com",
    "jane.smith@target.onmicrosoft.com"
    # ... add all users
)

Request-SPOPersonalSite -UserEmails $targetUsers

# This is asynchronous — it can take up to 24 hours for all sites to be created
# Check if a user's OneDrive exists:
Get-SPOSite -Identity "https://target-my.sharepoint.com/personal/john_doe_target_onmicrosoft_com" -ErrorAction SilentlyContinue
```

> **Tip**: `Request-SPOPersonalSite` queues site creation — it doesn't happen instantly. For large batches, submit early and wait overnight.

> 📖 [Pre-provision OneDrive](https://learn.microsoft.com/en-us/sharepoint/pre-provision-accounts)

### 5.5 — Build the CTIM Identity Map File

**Why**: SharePoint uses a specific file format called **CTIM** (Cross-Tenant Identity Map) to know which source user maps to which target user. This file has **no header row** and uses a specific column format.

```powershell
# Format: User,<SourceTenantGUID>,<SourceUPN>,<TargetUPN>,<TargetEmail>,RegularUser

$sourceTenantGuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # Your source tenant GUID

$lines = @(
    "User,$sourceTenantGuid,john.doe@contoso.com,john.doe@target.onmicrosoft.com,john.doe@target.onmicrosoft.com,RegularUser",
    "User,$sourceTenantGuid,jane.smith@contoso.com,jane.smith@target.onmicrosoft.com,jane.smith@target.onmicrosoft.com,RegularUser"
)

$lines | Out-File ".\ctim_mapping.csv" -Encoding UTF8
```

> **Important**: No header row! The file must start directly with data rows.

> 📖 [Create the identity mapping file](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step3?view=o365-worldwide)

---

## Phase 6 — Execute OneDrive Content Migration

> **Goal**: Move OneDrive content from SOURCE to TARGET, monitor progress, then clean up the trust.

### 6.1 — Upload the Identity Map to Target

```powershell
# Connect to TARGET SharePoint
Connect-SPOService -Url "https://target-admin.sharepoint.com"

# Upload the CTIM file
Add-SPOTenantIdentityMap -IdentityMapPath ".\ctim_mapping.csv"
```

### 6.2 — Start OneDrive Migrations

**Why**: You start the content move from the **SOURCE** tenant, telling it where to push the data.

```powershell
# Get the TARGET CrossTenantHostUrl (needed to tell SOURCE where to send data)
Connect-SPOService -Url "https://target-admin.sharepoint.com"
$targetHostUrl = Get-SPOCrossTenantHostUrl
Disconnect-SPOService

# Connect to SOURCE SharePoint
Connect-SPOService -Url "https://source-admin.sharepoint.com"

# Start migration for each user
Start-SPOCrossTenantUserContentMove `
    -CrossTenantHostUrl $targetHostUrl `
    -TargetUserEmail "john.doe@target.onmicrosoft.com"

Start-SPOCrossTenantUserContentMove `
    -CrossTenantHostUrl $targetHostUrl `
    -TargetUserEmail "jane.smith@target.onmicrosoft.com"

# ... repeat for all users
```

> **Warning**: This initiates **actual data movement**. Make sure you've verified the trust is `GoodToProceed` before starting.

> 📖 [Start cross-tenant OneDrive migration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration-step5?view=o365-worldwide)

### 6.3 — Monitor OneDrive Migration Status

```powershell
# Check from SOURCE:
Connect-SPOService -Url "https://source-admin.sharepoint.com"
Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $targetHostUrl |
    Format-Table MoveDirection, SourceUserPrincipalName, MoveState, StatusDescription

# Check from TARGET:
Connect-SPOService -Url "https://target-admin.sharepoint.com"
Get-SPOCrossTenantUserContentMoveState -PartnerCrossTenantHostUrl $sourceHostUrl |
    Format-Table MoveDirection, SourceUserPrincipalName, MoveState, StatusDescription
```

**Status values**:
| Status | Meaning |
|--------|---------|
| `NotStarted` | Move is queued but hasn't begun |
| `InProgress` | Data is being copied |
| `Completed` | Migration finished successfully |
| `Failed` | Something went wrong — check `StatusDescription` |

> **Tip**: Run these commands every 30-60 minutes. OneDrive migrations can take several hours depending on the amount of data.

### 6.4 — Remove Cross-Tenant Trust (after all migrations are done)

**Why**: The MnA trust should be removed after migration for security — leaving it open would allow anyone with the right permissions to start new content moves between the tenants.

```powershell
# Remove trust on SOURCE
Connect-SPOService -Url "https://source-admin.sharepoint.com"
Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Target -PartnerCrossTenantHostUrl $targetHostUrl
Disconnect-SPOService

# Remove trust on TARGET
Connect-SPOService -Url "https://target-admin.sharepoint.com"
Remove-SPOCrossTenantRelationship -Scenario MnA -PartnerRole Source -PartnerCrossTenantHostUrl $sourceHostUrl
Disconnect-SPOService

# Verify removal on both sides (should return NotEstablished or error)
```

> **Do NOT remove the trust until all OneDrive migrations are `Completed`.**

---

## Phase 7 — Post-Migration Cleanup

> **Goal**: Finalize everything, clean up temporary objects, and verify the migration.

### 7.1 — Verify All Migrations

- [ ] **Exchange**: Run `Get-MigrationBatch` on TARGET — all batches should be `Completed`
- [ ] **OneDrive**: Run `Get-SPOCrossTenantUserContentMoveState` — all moves should be `Completed`
- [ ] **User accounts**: Verify all users can sign in to the TARGET tenant
- [ ] **Mailboxes**: Users can access their email in Outlook / OWA on the target tenant
- [ ] **OneDrive**: Users can access their OneDrive files on the target tenant
- [ ] **Groups**: All group memberships are correct in the target
- [ ] **Contacts**: All mail contacts appear in the TARGET Global Address List

### 7.2 — Clean Up Source Scoping Group

```powershell
# If you no longer need the migration scope group on SOURCE:
Connect-ExchangeOnline  # (source tenant)
Remove-DistributionGroup -Identity "MAILBOXMIGRATION" -Confirm:$false
```

### 7.3 — Clean Up Migration Application

```powershell
# Remove the migration app from TARGET Entra ID (when no longer needed)
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "Application.ReadWrite.All"
$app = Get-MgApplication -Filter "DisplayName eq 'Cross-Tenant Mailbox Migration'"
Remove-MgApplication -ApplicationId $app.Id
```

### 7.4 — Clean Up Organization Relationships

```powershell
# Remove org relationships when no longer needed
# On TARGET:
Connect-ExchangeOnline  # (target tenant)
Remove-OrganizationRelationship -Identity "SourceToTarget_Inbound" -Confirm:$false

# On SOURCE:
Connect-ExchangeOnline  # (source tenant)
Remove-OrganizationRelationship -Identity "TargetFromSource_Outbound" -Confirm:$false
```

### 7.5 — Remove Migration Endpoint

```powershell
# On TARGET Exchange:
Connect-ExchangeOnline  # (target tenant)
Remove-MigrationEndpoint -Identity "CrossTenantMigrationEndpoint" -Confirm:$false
```

### 7.6 — Update DNS (if switching domains)

If you're moving a custom domain from the source to the target tenant:

- [ ] **Remove the domain** from the source tenant (Entra admin center > Settings > Domain names)
- [ ] **Add and verify the domain** on the target tenant
- [ ] **Update MX, AUTODISCOVER, SPF, DKIM, DMARC** DNS records to point to the target tenant
- [ ] **Update user UPNs** on the target to use the custom domain

```powershell
# On TARGET Graph:
Connect-MgGraph -TenantId "target.onmicrosoft.com" -Scopes "User.ReadWrite.All"

# Update each user's UPN to the custom domain
Update-MgUser -UserId "john.doe@target.onmicrosoft.com" -UserPrincipalName "john.doe@contoso.com"
```

### 7.7 — Communicate to End Users

- [ ] Send migration completion email with:
  - New sign-in instructions (if UPN changed)
  - New Outlook/OWA URL
  - New OneDrive URL
  - Temporary password (if applicable)
  - How to set up Outlook profile (if needed)
  - IT support contact for issues

---

## Quick Reference — Admin Portals

| Portal | URL |
|--------|-----|
| **Entra admin center** | https://entra.microsoft.com |
| **Microsoft 365 admin center** | https://admin.microsoft.com |
| **Exchange admin center** | https://admin.exchange.microsoft.com |
| **SharePoint admin center** | https://{tenant}-admin.sharepoint.com |

## Quick Reference — Key Microsoft Documentation

| Topic | Link |
|-------|------|
| Cross-tenant mailbox migration | https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-mailbox-migration?view=o365-worldwide |
| Cross-tenant OneDrive migration | https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-onedrive-migration?view=o365-worldwide |
| Cross-tenant SharePoint migration | https://learn.microsoft.com/en-us/microsoft-365/enterprise/cross-tenant-sharepoint-migration?view=o365-worldwide |
| Entra Connect OU filtering | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering |
| Pre-provision OneDrive sites | https://learn.microsoft.com/en-us/sharepoint/pre-provision-accounts |
| Manage mail contacts in EXO | https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-mail-contacts |
| Create users in Entra ID | https://learn.microsoft.com/en-us/entra/fundamentals/how-to-create-delete-users |
| Assign M365 licenses | https://learn.microsoft.com/en-us/microsoft-365/admin/manage/assign-licenses-to-users?view=o365-worldwide |
| Microsoft Graph PowerShell | https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview |
| Exchange Online PowerShell | https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell |
| SharePoint Online PowerShell | https://learn.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell |

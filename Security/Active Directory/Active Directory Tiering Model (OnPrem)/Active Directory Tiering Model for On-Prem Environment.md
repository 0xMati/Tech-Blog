# Active Directory Tiering Model for On-Premises Environments

## Introduction

The **Active Directory Tiering Model** (also known as the **Enterprise Access Model**) is a security architecture designed to contain credential theft and lateral movement within an Active Directory environment. It replaces the legacy ESAE (Enhanced Security Admin Environment) / Red Forest model with a more practical, layered approach.

The core principle is simple: **never expose a higher-tier credential on a lower-tier system**. A Domain Admin logging into a workstation leaves cached credentials that an attacker can harvest. Tiering eliminates this by enforcing strict isolation between administrative boundaries.

### The Three Tiers

| Tier | Name | Scope | Examples |
|------|------|-------|----------|
| **Tier 0** | Control Plane | Identity infrastructure — anything that can directly control Active Directory | Domain Controllers, AD CS (PKI), AD FS, Entra ID Connect, DNS (AD-integrated), Schema/Configuration partition, DHCP on DCs |
| **Tier 1** | Management Plane | Server infrastructure — anything that runs business applications and services | Application servers, file servers, SQL servers, Exchange, SCCM/MECM, Hyper-V/VMware hosts, print servers |
| **Tier 2** | User Access | End-user devices — where users perform day-to-day work | Workstations, laptops, kiosks, thin clients |

### Key Rule: Credentials Never Flow Downward

```
Tier 0 credentials → ONLY on Tier 0 systems
Tier 1 credentials → ONLY on Tier 1 systems (and Tier 1 PAWs)
Tier 2 credentials → ONLY on Tier 2 systems

❌ A Tier 0 admin logging into a workstation = catastrophic violation
❌ A Tier 1 admin logging into a workstation = serious violation
❌ A Tier 2 admin logging into a Domain Controller = access denied (enforced)
```

### Why This Matters

Without tiering, a single compromised workstation can lead to full domain compromise in minutes:

1. Attacker compromises a workstation (phishing, exploit, etc.)
2. Attacker harvests cached credentials (Mimikatz, LSASS dump)
3. If a Domain Admin ever logged into that workstation, the attacker now has Domain Admin credentials
4. Attacker performs DCSync, Golden Ticket, or direct DC access → **game over**

Tiering breaks this chain by ensuring that **Domain Admin credentials are never present on workstations**.

---

## Phase 0 — Prerequisites and Scoping

Before touching Active Directory, you need a thorough understanding of your current environment and executive support for the project. This phase is about discovery, classification, and getting organizational buy-in.

### 0.1 — Obtain Executive Sponsorship

Tiering impacts **every IT administrator** in the organization. Without executive sponsorship, the project will stall when teams resist the changes.

**What you need:**
- A formal mandate from the CISO or CIO
- A RACI matrix defining responsibilities across teams (AD, server, network, security, helpdesk)
- Agreed-upon timeline with phases and milestones
- Communication plan for IT staff explaining the "why" — this is not optional, resistance will be significant
- Budget allocation for PAW hardware, potential tooling (MDI, SIEM), and dedicated project time

### 0.2 — Inventory and Classify All Assets

Every computer object, server, and infrastructure component must be mapped to a tier. This is the most labor-intensive step and the foundation of everything that follows.

#### Tier 0 Assets — The Crown Jewels

These are systems that can **directly control Active Directory**. If compromised, the entire domain is compromised.

| Asset | Why It's Tier 0 |
|-------|-----------------|
| Domain Controllers | They ARE Active Directory |
| AD CS servers (Certificate Authority) | Can issue certificates that grant Domain Admin-equivalent access (ESC1-ESC8 attacks) |
| AD FS servers | Control federated authentication; a compromised AD FS server = Golden SAML |
| Entra ID Connect server | Syncs password hashes to the cloud; can modify cloud identities |
| DNS servers (AD-integrated) | Can redirect authentication traffic; DNS is part of the DC role in most deployments |
| SCCM/MECM Site Server (if it manages DCs) | Can deploy code to Domain Controllers = full domain compromise |
| Hyper-V / VMware hosts running DCs | Can snapshot/clone a DC, extract NTDS.dit offline |
| Backup servers that back up DCs | Can restore a DC and extract NTDS.dit |
| PAM/Vault servers (CyberArk, etc.) | Store credentials for Tier 0 accounts |
| RADIUS/NPS servers authenticating DC access | Control who can authenticate to Tier 0 |

> **Critical:** Any system that can **deploy code to**, **restore**, or **manage** a Tier 0 asset is itself Tier 0. This is the transitive trust principle.

#### Tier 1 Assets — Servers and Applications

| Asset | Why It's Tier 1 |
|-------|-----------------|
| File servers | Store sensitive business data, but cannot directly control AD |
| SQL servers | Host application databases |
| Application servers (ERP, CRM, LOB) | Run business logic |
| Exchange servers (if not Tier 0) | Exchange has historically had DCSync-capable permissions — verify! |
| SCCM/MECM (if it does NOT manage DCs) | Can deploy code to Tier 1/Tier 2 only |
| Print servers | Infrastructure but no AD control |
| Hyper-V / VMware hosts (not hosting DCs) | Can control VMs at the Tier 1 level |
| WSUS servers | Can push updates to servers |

> **Warning about Exchange:** In many environments, the `Exchange Windows Permissions` group has `WriteDACL` on the domain root, which is effectively DCSync. If this is the case, **Exchange is Tier 0**. Audit this with: `Get-ADPermission` or BloodHound.

> **Warning about SCCM/MECM:** If SCCM has a client installed on Domain Controllers, or if SCCM administrators can push software to DCs, then SCCM is Tier 0. This is one of the most common misclassifications.

#### Tier 2 Assets — End-User Devices

| Asset | Notes |
|-------|-------|
| Workstations | All employee desktops and laptops |
| Kiosks | Shared-use terminals |
| Conference room PCs | Often unmanaged — still Tier 2 |

#### How to Perform the Inventory

```powershell
# Export all computer objects with their OS and OU location
Get-ADComputer -Filter * -Properties OperatingSystem, DistinguishedName, Description, LastLogonTimestamp |
    Select-Object Name, OperatingSystem, DistinguishedName, Description,
        @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}} |
    Export-Csv -Path "C:\Tiering\AllComputers.csv" -NoTypeInformation

# Identify Domain Controllers
Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, Site

# Identify servers in privileged groups or with privileged SPNs
Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Properties OperatingSystem, ServicePrincipalName |
    Select-Object Name, OperatingSystem, @{N='SPNs';E={$_.ServicePrincipalName -join '; '}} |
    Export-Csv -Path "C:\Tiering\Servers.csv" -NoTypeInformation
```

### 0.3 — Inventory All Privileged Accounts

You cannot enforce tiering without knowing who holds privileges and at what level.

#### Enumerate Privileged Group Members

```powershell
# Built-in privileged groups to audit
$PrivilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Backup Operators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "DnsAdmins",
    "Group Policy Creator Owners",
    "Cert Publishers"
)

foreach ($Group in $PrivilegedGroups) {
    Write-Host "`n=== $Group ===" -ForegroundColor Cyan
    try {
        Get-ADGroupMember -Identity $Group -Recursive |
            Select-Object Name, SamAccountName, ObjectClass |
            Format-Table -AutoSize
    } catch {
        Write-Warning "Group '$Group' not found or error: $_"
    }
}
```

#### Identify Service Accounts with Excessive Privileges

```powershell
# Find service accounts that are members of Domain Admins (common bad practice)
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Where-Object { $_.Name -match "svc|service|sql|app|batch|task" } |
    Select-Object Name, SamAccountName

# Find accounts with adminCount=1 (have been in a privileged group at some point)
Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount, MemberOf, LastLogonTimestamp, PasswordLastSet |
    Select-Object Name, SamAccountName, Enabled, PasswordLastSet,
        @{N='LastLogon';E={[DateTime]::FromFileTime($_.LastLogonTimestamp)}},
        @{N='GroupCount';E={$_.MemberOf.Count}} |
    Export-Csv -Path "C:\Tiering\AdminCountUsers.csv" -NoTypeInformation
```

#### Detect Tiering Violations (Who Is Logging Where They Shouldn't)

Use Security Event Logs on Domain Controllers to find T0 accounts logging into non-T0 machines:

```powershell
# On Domain Controllers, look for 4624 events (successful logon) from privileged accounts on non-DC machines
# This requires centralized log collection (SIEM) or running on each DC

$DomainAdmins = (Get-ADGroupMember -Identity "Domain Admins" -Recursive).SamAccountName
$DCs = (Get-ADDomainController -Filter *).Name

# Example: Query Security log on a DC for interactive logons
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddDays(-30)
} -MaxEvents 50000 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $TargetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
    $WorkstationName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
    $LogonType = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonType' }).'#text'

    if ($TargetUser -in $DomainAdmins -and $WorkstationName -notin $DCs) {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            User = $TargetUser
            Workstation = $WorkstationName
            LogonType = $LogonType
        }
    }
} | Export-Csv -Path "C:\Tiering\TieringViolations.csv" -NoTypeInformation
```

### 0.4 — Assess the Current OU Structure and GPOs

Understanding the existing structure is critical before designing the tiering OUs.

```powershell
# Export the current OU structure
Get-ADOrganizationalUnit -Filter * -Properties Description |
    Select-Object Name, DistinguishedName, Description |
    Sort-Object DistinguishedName |
    Export-Csv -Path "C:\Tiering\OUStructure.csv" -NoTypeInformation

# Export all GPOs and their links
Get-GPO -All | ForEach-Object {
    $GPO = $_
    $Links = (Get-GPOReport -Guid $GPO.Id -ReportType XML | Select-Xml -XPath '//gpo:LinksTo' -Namespace @{gpo='http://www.microsoft.com/GroupPolicy/Settings'}).Node
    [PSCustomObject]@{
        GPOName = $GPO.DisplayName
        GPOId = $GPO.Id
        Status = $GPO.GpoStatus
        CreationTime = $GPO.CreationTime
        ModificationTime = $GPO.ModificationTime
        Owner = $GPO.Owner
    }
} | Export-Csv -Path "C:\Tiering\GPOInventory.csv" -NoTypeInformation

# Find GPOs linked to Domain Controllers OU
Get-ADOrganizationalUnit -Identity "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)" |
    Select-Object -ExpandProperty LinkedGroupPolicyObjects |
    ForEach-Object {
        $guid = $_ -replace '.*\{(.*?)\}.*', '$1'
        Get-GPO -Guid $guid | Select-Object DisplayName, Id, GpoStatus
    }
```

### 0.5 — Assess Attack Paths

Run these tools **before** implementing tiering to establish a baseline:

| Tool | Purpose | What To Look For |
|------|---------|-----------------|
| **BloodHound / SharpHound** | Visualize attack paths from any user to Domain Admins | Shortest paths to DA, Kerberoastable accounts with paths to T0, delegation abuse |
| **PingCastle** | AD security health check with a score | Privileged group hygiene, stale accounts, dangerous trusts, Kerberos weaknesses |
| **Purple Knight** | AD security assessment | Similar to PingCastle, different detection engine |
| **Invoke-TrimarcADChecks** | Open-source AD security checks | Focused on common misconfigurations |

```powershell
# Run PingCastle (example)
.\PingCastle.exe --healthcheck --server domain.local

# Run SharpHound collector
.\SharpHound.exe -c All --domaincontroller dc01.domain.local
```

Save the reports — you will compare them after tiering is implemented to measure improvement.

### Phase 0 Checklist

- [ ] Executive sponsorship obtained (CISO/CIO mandate)
- [ ] RACI matrix created and communicated to all teams
- [ ] Communication plan shared with IT staff
- [ ] Budget allocated (PAW hardware, tooling, project time)
- [ ] All computer objects exported and classified (T0/T1/T2)
- [ ] All Domain Controllers identified
- [ ] All Tier 0 assets identified (AD CS, AD FS, Entra ID Connect, hypervisors hosting DCs, backup servers, SCCM, PAM)
- [ ] Exchange permissions audited — `Exchange Windows Permissions` WriteDACL checked
- [ ] SCCM scope audited — does it manage Domain Controllers?
- [ ] Hypervisor scope audited — which hosts run DC VMs?
- [ ] All privileged group members enumerated
- [ ] Service accounts in privileged groups identified
- [ ] Accounts with `adminCount=1` reviewed
- [ ] Tiering violations detected (T0 accounts logging into T2 machines)
- [ ] Current OU structure documented
- [ ] All GPOs and their links documented
- [ ] GPO owners verified (no non-admin GPO owners for sensitive GPOs)
- [ ] BloodHound/PingCastle/Purple Knight baseline reports generated and saved
- [ ] Attack paths from Tier 2 to Tier 0 documented

---

## Phase 1 — OU Structure and Group Model Design

This phase defines the organizational backbone of the tiering model. The OU structure determines where objects live, how GPOs are applied, and how delegation works. The group model determines who has access to what.

### 1.1 — Design the Tiering OU Structure

The goal is a clear, unambiguous structure where every object lives in the correct tier. GPOs are linked at the tier level and inherit downward.

#### Recommended OU Structure

```
domain.local
│
├── Tier 0
│   ├── Accounts          ← T0 admin user accounts (t0-john.doe)
│   ├── Groups            ← T0 security groups (T0-Admins, T0-LogonRestriction, etc.)
│   ├── Service Accounts  ← T0 service accounts and gMSAs
│   ├── Servers           ← T0 servers (AD CS, AD FS, Entra ID Connect, etc.)
│   │                        NOTE: DCs stay in the default "Domain Controllers" OU
│   └── PAW               ← Tier 0 Privileged Access Workstations
│
├── Tier 1
│   ├── Accounts          ← T1 admin user accounts (t1-john.doe)
│   ├── Groups            ← T1 security groups
│   ├── Service Accounts  ← T1 service accounts and gMSAs
│   ├── Servers           ← All Tier 1 servers
│   │   ├── File Servers
│   │   ├── SQL Servers
│   │   ├── Application Servers
│   │   └── ...           ← Sub-OUs by role or business unit (optional)
│   └── PAW               ← Tier 1 Privileged Access Workstations (optional)
│
├── Tier 2
│   ├── Accounts          ← T2 admin user accounts (t2-helpdesk, etc.)
│   ├── Groups            ← T2 security groups
│   ├── Service Accounts  ← T2 service accounts
│   └── Workstations      ← All end-user devices
│       ├── Desktops
│       ├── Laptops
│       └── Kiosks
│
├── Quarantine            ← Staging OU for new/unclassified objects
│   └── Computers         ← Default computer container redirected here (redircmp)
│
├── Standard Users        ← Non-admin user accounts
│   ├── Department A
│   ├── Department B
│   └── ...
│
└── Disabled              ← Disabled accounts and computers awaiting deletion
    ├── Users
    └── Computers
```

#### Implementation Script

```powershell
# Define domain DN
$DomainDN = (Get-ADDomain).DistinguishedName

# === Tier 0 ===
$T0 = New-ADOrganizationalUnit -Name "Tier 0" -Path $DomainDN -Description "Tier 0 - Control Plane (Identity Infrastructure)" -PassThru
New-ADOrganizationalUnit -Name "Accounts"         -Path $T0.DistinguishedName -Description "Tier 0 admin user accounts"
New-ADOrganizationalUnit -Name "Groups"            -Path $T0.DistinguishedName -Description "Tier 0 security groups"
New-ADOrganizationalUnit -Name "Service Accounts"  -Path $T0.DistinguishedName -Description "Tier 0 service accounts and gMSAs"
New-ADOrganizationalUnit -Name "Servers"           -Path $T0.DistinguishedName -Description "Tier 0 servers (AD CS, AD FS, AADConnect, etc.)"
New-ADOrganizationalUnit -Name "PAW"               -Path $T0.DistinguishedName -Description "Tier 0 Privileged Access Workstations"

# === Tier 1 ===
$T1 = New-ADOrganizationalUnit -Name "Tier 1" -Path $DomainDN -Description "Tier 1 - Management Plane (Servers and Applications)" -PassThru
New-ADOrganizationalUnit -Name "Accounts"         -Path $T1.DistinguishedName -Description "Tier 1 admin user accounts"
New-ADOrganizationalUnit -Name "Groups"            -Path $T1.DistinguishedName -Description "Tier 1 security groups"
New-ADOrganizationalUnit -Name "Service Accounts"  -Path $T1.DistinguishedName -Description "Tier 1 service accounts and gMSAs"
$T1Servers = New-ADOrganizationalUnit -Name "Servers" -Path $T1.DistinguishedName -Description "Tier 1 servers" -PassThru
New-ADOrganizationalUnit -Name "File Servers"      -Path $T1Servers.DistinguishedName
New-ADOrganizationalUnit -Name "SQL Servers"       -Path $T1Servers.DistinguishedName
New-ADOrganizationalUnit -Name "Application Servers" -Path $T1Servers.DistinguishedName
New-ADOrganizationalUnit -Name "PAW"               -Path $T1.DistinguishedName -Description "Tier 1 Privileged Access Workstations (optional)"

# === Tier 2 ===
$T2 = New-ADOrganizationalUnit -Name "Tier 2" -Path $DomainDN -Description "Tier 2 - User Access (Workstations)" -PassThru
New-ADOrganizationalUnit -Name "Accounts"         -Path $T2.DistinguishedName -Description "Tier 2 admin user accounts (helpdesk)"
New-ADOrganizationalUnit -Name "Groups"            -Path $T2.DistinguishedName -Description "Tier 2 security groups"
New-ADOrganizationalUnit -Name "Service Accounts"  -Path $T2.DistinguishedName -Description "Tier 2 service accounts"
$T2WS = New-ADOrganizationalUnit -Name "Workstations" -Path $T2.DistinguishedName -Description "End-user devices" -PassThru
New-ADOrganizationalUnit -Name "Desktops"          -Path $T2WS.DistinguishedName
New-ADOrganizationalUnit -Name "Laptops"           -Path $T2WS.DistinguishedName

# === Quarantine ===
$Quarantine = New-ADOrganizationalUnit -Name "Quarantine" -Path $DomainDN -Description "Staging OU for new/unclassified objects" -PassThru
$QuarantineComputers = New-ADOrganizationalUnit -Name "Computers" -Path $Quarantine.DistinguishedName -Description "Default computer landing OU" -PassThru

# Redirect default computer container to Quarantine\Computers
redircmp $QuarantineComputers.DistinguishedName

# === Standard Users ===
New-ADOrganizationalUnit -Name "Standard Users" -Path $DomainDN -Description "Non-admin user accounts"

# === Disabled Objects ===
$Disabled = New-ADOrganizationalUnit -Name "Disabled" -Path $DomainDN -Description "Disabled accounts awaiting deletion" -PassThru
New-ADOrganizationalUnit -Name "Users"     -Path $Disabled.DistinguishedName
New-ADOrganizationalUnit -Name "Computers" -Path $Disabled.DistinguishedName
```

> **Important:** Do NOT move Domain Controllers out of the default `Domain Controllers` OU. The `Default Domain Controllers Policy` GPO is linked there and is required for proper DC operation.

#### Why Redirect the Default Computer Container?

When a computer joins the domain, it lands in `CN=Computers` by default. This container:
- Cannot have GPOs linked to it (it is a container, not an OU)
- Has no tiering restrictions applied
- Is a security gap

By running `redircmp` to point to `Quarantine\Computers`, new machines land in a staging OU where you can:
- Apply a restrictive baseline GPO
- Review and classify the machine before moving it to the correct tier OU

### 1.2 — Design the Group Model

Groups are the mechanism that ties accounts to permissions and restrictions. Use the **AGDLP model** (Account → Global Group → Domain Local Group → Permission).

#### Tier 0 Groups

| Group Name | Type | Purpose |
|------------|------|---------|
| `T0-Admins` | Global | All Tier 0 admin accounts |
| `T0-PAW-Computers` | Global | All Tier 0 PAW computer objects |
| `T0-Servers` | Global | All Tier 0 server computer objects (excluding DCs) |
| `T0-ServiceAccounts` | Global | All Tier 0 service accounts |
| `T0-DenyLogon-T1` | Domain Local | Used in GPO to deny T0 accounts on T1 machines |
| `T0-DenyLogon-T2` | Domain Local | Used in GPO to deny T0 accounts on T2 machines |

#### Tier 1 Groups

| Group Name | Type | Purpose |
|------------|------|---------|
| `T1-Admins` | Global | All Tier 1 admin accounts |
| `T1-PAW-Computers` | Global | All Tier 1 PAW computer objects |
| `T1-Servers` | Global | All Tier 1 server computer objects |
| `T1-ServiceAccounts` | Global | All Tier 1 service accounts |
| `T1-DenyLogon-T0` | Domain Local | Used in GPO to deny T1 accounts on T0 machines |
| `T1-DenyLogon-T2` | Domain Local | Used in GPO to deny T1 accounts on T2 machines |

#### Tier 2 Groups

| Group Name | Type | Purpose |
|------------|------|---------|
| `T2-Admins` | Global | All Tier 2 admin accounts (helpdesk, desktop support) |
| `T2-Workstations` | Global | All Tier 2 workstation computer objects |
| `T2-ServiceAccounts` | Global | All Tier 2 service accounts |
| `T2-DenyLogon-T0` | Domain Local | Used in GPO to deny T2 accounts on T0 machines |
| `T2-DenyLogon-T1` | Domain Local | Used in GPO to deny T2 accounts on T1 machines |

#### Implementation Script

```powershell
$DomainDN = (Get-ADDomain).DistinguishedName

# --- Tier 0 Groups ---
$T0GroupsOU = "OU=Groups,OU=Tier 0,$DomainDN"
New-ADGroup -Name "T0-Admins"           -GroupScope Global      -GroupCategory Security -Path $T0GroupsOU -Description "All Tier 0 admin accounts"
New-ADGroup -Name "T0-PAW-Computers"    -GroupScope Global      -GroupCategory Security -Path $T0GroupsOU -Description "All Tier 0 PAW computer objects"
New-ADGroup -Name "T0-Servers"          -GroupScope Global      -GroupCategory Security -Path $T0GroupsOU -Description "All Tier 0 server objects (excl. DCs)"
New-ADGroup -Name "T0-ServiceAccounts"  -GroupScope Global      -GroupCategory Security -Path $T0GroupsOU -Description "All Tier 0 service accounts"
New-ADGroup -Name "T0-DenyLogon-T1"     -GroupScope DomainLocal -GroupCategory Security -Path $T0GroupsOU -Description "Deny T0 accounts logon on T1 machines"
New-ADGroup -Name "T0-DenyLogon-T2"     -GroupScope DomainLocal -GroupCategory Security -Path $T0GroupsOU -Description "Deny T0 accounts logon on T2 machines"

# --- Tier 1 Groups ---
$T1GroupsOU = "OU=Groups,OU=Tier 1,$DomainDN"
New-ADGroup -Name "T1-Admins"           -GroupScope Global      -GroupCategory Security -Path $T1GroupsOU -Description "All Tier 1 admin accounts"
New-ADGroup -Name "T1-PAW-Computers"    -GroupScope Global      -GroupCategory Security -Path $T1GroupsOU -Description "All Tier 1 PAW computer objects"
New-ADGroup -Name "T1-Servers"          -GroupScope Global      -GroupCategory Security -Path $T1GroupsOU -Description "All Tier 1 server objects"
New-ADGroup -Name "T1-ServiceAccounts"  -GroupScope Global      -GroupCategory Security -Path $T1GroupsOU -Description "All Tier 1 service accounts"
New-ADGroup -Name "T1-DenyLogon-T0"     -GroupScope DomainLocal -GroupCategory Security -Path $T1GroupsOU -Description "Deny T1 accounts logon on T0 machines"
New-ADGroup -Name "T1-DenyLogon-T2"     -GroupScope DomainLocal -GroupCategory Security -Path $T1GroupsOU -Description "Deny T1 accounts logon on T2 machines"

# --- Tier 2 Groups ---
$T2GroupsOU = "OU=Groups,OU=Tier 2,$DomainDN"
New-ADGroup -Name "T2-Admins"           -GroupScope Global      -GroupCategory Security -Path $T2GroupsOU -Description "All Tier 2 admin accounts (helpdesk)"
New-ADGroup -Name "T2-Workstations"     -GroupScope Global      -GroupCategory Security -Path $T2GroupsOU -Description "All Tier 2 workstation objects"
New-ADGroup -Name "T2-ServiceAccounts"  -GroupScope Global      -GroupCategory Security -Path $T2GroupsOU -Description "All Tier 2 service accounts"
New-ADGroup -Name "T2-DenyLogon-T0"     -GroupScope DomainLocal -GroupCategory Security -Path $T2GroupsOU -Description "Deny T2 accounts logon on T0 machines"
New-ADGroup -Name "T2-DenyLogon-T1"     -GroupScope DomainLocal -GroupCategory Security -Path $T2GroupsOU -Description "Deny T2 accounts logon on T1 machines"

# --- Nest Global Groups into Domain Local Deny Groups ---
# T0 accounts denied on T1 and T2
Add-ADGroupMember -Identity "T0-DenyLogon-T1" -Members "T0-Admins","T0-ServiceAccounts"
Add-ADGroupMember -Identity "T0-DenyLogon-T2" -Members "T0-Admins","T0-ServiceAccounts"

# T1 accounts denied on T0 and T2
Add-ADGroupMember -Identity "T1-DenyLogon-T0" -Members "T1-Admins","T1-ServiceAccounts"
Add-ADGroupMember -Identity "T1-DenyLogon-T2" -Members "T1-Admins","T1-ServiceAccounts"

# T2 accounts denied on T0 and T1
Add-ADGroupMember -Identity "T2-DenyLogon-T0" -Members "T2-Admins","T2-ServiceAccounts"
Add-ADGroupMember -Identity "T2-DenyLogon-T1" -Members "T2-Admins","T2-ServiceAccounts"
```

### 1.3 — Move Existing Objects to the Correct OUs

Now move servers, workstations, and accounts to the correct tier OUs. **Do this in a maintenance window** and test GPO application afterward.

```powershell
# Example: Move a Tier 0 server to the T0 Servers OU
Move-ADObject -Identity "CN=ADCS01,CN=Computers,DC=domain,DC=local" `
              -TargetPath "OU=Servers,OU=Tier 0,DC=domain,DC=local"

# Example: Move workstations from Quarantine to Tier 2
Get-ADComputer -Filter * -SearchBase "OU=Computers,OU=Quarantine,DC=domain,DC=local" |
    Where-Object { $_.OperatingSystem -notlike "*Server*" } |
    Move-ADObject -TargetPath "OU=Desktops,OU=Workstations,OU=Tier 2,DC=domain,DC=local"
```

> **Caution:** Moving objects changes which GPOs are applied. Verify GPO inheritance with `gpresult /r` on key systems after the move.

### Phase 1 Checklist

- [ ] Tiering OU structure created (Tier 0, Tier 1, Tier 2, Quarantine, Standard Users, Disabled)
- [ ] Sub-OUs created for Accounts, Groups, Service Accounts, Servers/Workstations, PAW per tier
- [ ] Default computer container redirected to Quarantine (`redircmp`)
- [ ] Domain Controllers confirmed in default `Domain Controllers` OU (not moved)
- [ ] All tiering groups created with correct scope (Global vs. Domain Local)
- [ ] Deny logon groups nested correctly (Global → Domain Local)
- [ ] Existing Tier 0 servers moved to `Tier 0\Servers`
- [ ] Existing Tier 1 servers moved to `Tier 1\Servers`
- [ ] Existing workstations moved to `Tier 2\Workstations`
- [ ] GPO application verified on moved objects (`gpresult /r`)
- [ ] No objects left in default `CN=Computers` container
- [ ] OU protections enabled (Protect object from accidental deletion)

---

## Phase 2 — Account Isolation and Logon Restrictions

This is the phase that actually enforces tiering. Without logon restrictions, the OU structure is just cosmetic.

### 2.1 — Create Dedicated Admin Accounts Per Tier

Every administrator receives **one account per tier** they manage. Their standard user account is never granted admin privileges.

#### Naming Convention

| Account Type | Naming Convention | Example | Tier |
|--------------|-------------------|---------|------|
| Standard user | `firstname.lastname` | `john.doe` | N/A (Standard Users OU) |
| Tier 0 admin | `t0-firstname.lastname` | `t0-john.doe` | Tier 0 |
| Tier 1 admin | `t1-firstname.lastname` | `t1-john.doe` | Tier 1 |
| Tier 2 admin (helpdesk) | `t2-firstname.lastname` | `t2-john.doe` | Tier 2 |

#### Account Creation Script

```powershell
function New-TieredAdminAccount {
    param(
        [Parameter(Mandatory)][ValidateSet("T0","T1","T2")]
        [string]$Tier,

        [Parameter(Mandatory)]
        [string]$FirstName,

        [Parameter(Mandatory)]
        [string]$LastName,

        [Parameter(Mandatory)]
        [securestring]$Password
    )

    $DomainDN = (Get-ADDomain).DistinguishedName
    $SamAccountName = "$Tier-$FirstName.$LastName".ToLower()
    $TargetOU = "OU=Accounts,OU=$($Tier -replace 'T','Tier '), $DomainDN"
    $GroupName = "$Tier-Admins"

    $UserParams = @{
        Name              = $SamAccountName
        SamAccountName    = $SamAccountName
        UserPrincipalName = "$SamAccountName@$((Get-ADDomain).DNSRoot)"
        GivenName         = $FirstName
        Surname           = $LastName
        DisplayName       = "$FirstName $LastName ($Tier Admin)"
        Description       = "$Tier administrative account for $FirstName $LastName"
        Path              = $TargetOU
        AccountPassword   = $Password
        Enabled           = $true
        ChangePasswordAtLogon = $true
        PasswordNeverExpires  = $false
    }

    New-ADUser @UserParams
    Add-ADGroupMember -Identity $GroupName -Members $SamAccountName
    Write-Host "Created $SamAccountName in $TargetOU and added to $GroupName" -ForegroundColor Green
}

# Usage
$pw = Read-Host "Enter password" -AsSecureString
New-TieredAdminAccount -Tier "T0" -FirstName "John" -LastName "Doe" -Password $pw
```

#### Account Hardening for Tier 0 Accounts

Tier 0 accounts require additional hardening:

```powershell
# For each T0 admin account, apply these settings:
$T0Accounts = Get-ADGroupMember -Identity "T0-Admins" | Where-Object { $_.objectClass -eq 'user' }

foreach ($Account in $T0Accounts) {
    Set-ADUser -Identity $Account.SamAccountName -SmartcardLogonRequired $false  # Set to $true if using smartcards
    
    # Add to "Protected Users" group (disables NTLM, enforces Kerberos, no delegation, no caching)
    Add-ADGroupMember -Identity "Protected Users" -Members $Account.SamAccountName

    # Set "Account is sensitive and cannot be delegated"
    $user = Get-ADUser -Identity $Account.SamAccountName -Properties AccountNotDelegated
    Set-ADUser -Identity $Account.SamAccountName -AccountNotDelegated $true
}
```

> **Protected Users group** (Windows Server 2012 R2+): Members cannot authenticate with NTLM, cannot be delegated, have a 4-hour TGT lifetime, and credentials are never cached. This is the single most impactful protection for Tier 0 accounts.

### 2.2 — Enforce Logon Restrictions via GPO

This is the core enforcement mechanism. You need **six GPOs** (or a consolidated approach):

#### GPO Design

| GPO Name | Linked To | Purpose |
|----------|-----------|---------|
| `Tiering - Deny T0 Logon on T1` | `Tier 1` OU (all sub-OUs) | Prevents T0 accounts from logging into T1 machines |
| `Tiering - Deny T0 Logon on T2` | `Tier 2` OU (all sub-OUs) | Prevents T0 accounts from logging into T2 machines |
| `Tiering - Deny T1 Logon on T0` | `Tier 0` OU + Domain Controllers OU | Prevents T1 accounts from logging into T0 machines |
| `Tiering - Deny T1 Logon on T2` | `Tier 2` OU (all sub-OUs) | Prevents T1 accounts from logging into T2 machines |
| `Tiering - Deny T2 Logon on T0` | `Tier 0` OU + Domain Controllers OU | Prevents T2 accounts from logging into T0 machines |
| `Tiering - Deny T2 Logon on T1` | `Tier 1` OU (all sub-OUs) | Prevents T2 accounts from logging into T1 machines |

#### GPO Settings — User Rights Assignment

For each deny GPO, configure these settings under:

**Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → User Rights Assignment**

| Setting | Value |
|---------|-------|
| **Deny log on locally** | The deny group for that tier combination |
| **Deny log on through Remote Desktop Services** | Same deny group |
| **Deny access to this computer from the network** | Same deny group |
| **Deny log on as a batch job** | Same deny group |
| **Deny log on as a service** | Same deny group |

**Example for "Tiering - Deny T0 Logon on T2"** (linked to Tier 2 OU):

| Setting | Value |
|---------|-------|
| Deny log on locally | `DOMAIN\T0-DenyLogon-T2` |
| Deny log on through Remote Desktop Services | `DOMAIN\T0-DenyLogon-T2` |
| Deny access to this computer from the network | `DOMAIN\T0-DenyLogon-T2` |
| Deny log on as a batch job | `DOMAIN\T0-DenyLogon-T2` |
| Deny log on as a service | `DOMAIN\T0-DenyLogon-T2` |

> **Warning:** "Deny" rights always override "Allow" rights. A user in both a deny and an allow group will be denied. Test carefully before applying broadly.

> **Warning:** Do NOT add `Domain Admins` or `Enterprise Admins` to deny groups on DCs. This will lock you out.

#### Testing Strategy

1. **Start in audit mode:** Before enforcing, use the scripts from Phase 0.3 to identify current violations. Every violation is a logon that **will break** when you enforce the GPO.
2. **Apply to a test OU first:** Create a `Test` sub-OU in each tier and link the GPO there. Move one test machine to validate.
3. **Use `gpresult /r`** to verify the GPO is applied correctly.
4. **Test all logon types:** Interactive, RDP, network (SMB), service, batch.

```powershell
# Verify GPO application on a target machine
Invoke-Command -ComputerName "TESTSERVER01" -ScriptBlock {
    gpresult /r /scope:computer | Select-String -Pattern "Tiering"
}
```

### 2.3 — Authentication Policies and Silos (Advanced — Optional but Recommended)

**Requires:** Windows Server 2012 R2 Domain Functional Level and Kerberos Armoring (FAST).

Authentication Policies and Silos provide **Kerberos-level enforcement** that is stronger than GPO-based deny logon rights. GPO deny rights can be bypassed in certain scenarios (e.g., a compromised machine not applying GPO). Authentication Policies enforce restrictions **at the DC level** during TGT issuance.

#### How It Works

- An **Authentication Policy** defines conditions under which a TGT will be issued (e.g., "only on Tier 0 machines")
- An **Authentication Silo** groups accounts and policies together
- When an account in a silo requests a TGT, the DC checks whether the request comes from an allowed machine. If not, the TGT is denied.

#### Implementation

```powershell
# Step 1: Ensure domain functional level is 2012 R2+
(Get-ADDomain).DomainMode  # Should be Windows2012R2Domain or higher

# Step 2: Create Authentication Policy for Tier 0
New-ADAuthenticationPolicy -Name "T0-AuthPolicy" `
    -Description "Restricts Tier 0 accounts to Tier 0 machines only" `
    -UserTGTLifetimeMins 240 `
    -Enforce  # Remove -Enforce for audit mode first
    -UserAllowedToAuthenticateFrom (
        New-ADAuthenticationPolicyCriteria -AllowedToAuthenticateFrom `
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"T0-Silo`"))"
    )

# Step 3: Create Authentication Policy for Tier 0 Computers
# This restricts which accounts can get service tickets to T0 machines
New-ADAuthenticationPolicy -Name "T0-ComputerAuthPolicy" `
    -Description "Only T0 accounts can get service tickets to T0 machines" `
    -ComputerTGTLifetimeMins 240 `
    -ServiceAllowedToAuthenticateFrom (
        New-ADAuthenticationPolicyCriteria -AllowedToAuthenticateFrom `
            "O:SYG:SYD:(XA;OICI;CR;;;WD;(Member_of_any {SID($T0AdminsSID)}))"
    )

# Step 4: Create Authentication Silo for Tier 0
New-ADAuthenticationPolicySilo -Name "T0-Silo" `
    -Description "Tier 0 Authentication Silo" `
    -UserAuthenticationPolicy "T0-AuthPolicy" `
    -ComputerAuthenticationPolicy "T0-ComputerAuthPolicy" `
    -ServiceAuthenticationPolicy "T0-AuthPolicy" `
    -Enforce  # Remove -Enforce for audit mode first

# Step 5: Assign accounts to the silo
$T0Accounts = Get-ADGroupMember -Identity "T0-Admins"
foreach ($acct in $T0Accounts) {
    Set-ADUser -Identity $acct -AuthenticationPolicySilo "T0-Silo"
    Grant-ADAuthenticationPolicySiloAccess -Identity "T0-Silo" -Account $acct
}

# Step 6: Assign T0 computers to the silo
$T0Computers = Get-ADComputer -Filter * -SearchBase "OU=Servers,OU=Tier 0,$((Get-ADDomain).DistinguishedName)"
foreach ($comp in $T0Computers) {
    Set-ADComputer -Identity $comp -AuthenticationPolicySilo "T0-Silo"
    Grant-ADAuthenticationPolicySiloAccess -Identity "T0-Silo" -Account $comp
}
```

> **Recommendation:** Deploy Authentication Policies in **audit mode** first. Monitor Event ID **105** (Authentication Policy) and **106** (Authentication Silo) in the `AuthenticationPolicyFailures-DomainController` event log on DCs.

### Phase 2 Checklist

- [ ] Naming convention for tiered admin accounts defined and documented
- [ ] All Tier 0 admin accounts created and placed in `Tier 0\Accounts`
- [ ] All Tier 1 admin accounts created and placed in `Tier 1\Accounts`
- [ ] All Tier 2 admin accounts created and placed in `Tier 2\Accounts`
- [ ] Tier 0 accounts added to the `Protected Users` group
- [ ] Tier 0 accounts set to "Account is sensitive and cannot be delegated"
- [ ] All tiered admin accounts added to their respective `Tx-Admins` groups
- [ ] Six logon restriction GPOs created (or consolidated equivalent)
- [ ] Deny logon rights configured for all five logon types in each GPO
- [ ] GPOs linked to the correct OUs (including Domain Controllers OU for T0 protection)
- [ ] GPOs tested on a pilot machine per tier before broad deployment
- [ ] `gpresult /r` validated on pilot machines
- [ ] All logon types tested (interactive, RDP, network, service, batch)
- [ ] Current tiering violations resolved (accounts logging into wrong tiers)
- [ ] Authentication Policies/Silos created in audit mode (if DFL 2012 R2+)
- [ ] Authentication Policy audit events monitored (Event ID 105/106)
- [ ] Authentication Policies switched to enforce mode after validation
- [ ] Break-glass procedure documented (in case of lockout)
- [ ] Old admin accounts disabled (not deleted — keep for attribution in logs) or migrated

---

## Phase 3 — Privileged Access Workstations (PAW)

PAWs are dedicated, hardened machines from which administrators perform privileged tasks. They ensure that Tier 0 credentials are only ever exposed on Tier 0-trusted hardware.

### 3.1 — PAW Tier 0 — Hardware Requirements

Tier 0 PAWs must be **physical machines** — never VMs on a Tier 1 hypervisor (the hypervisor admin could extract credentials from memory).

| Requirement | Specification |
|-------------|---------------|
| **Hardware** | Dedicated laptop or desktop — not shared, not dual-purpose |
| **TPM** | TPM 2.0 required for BitLocker, Credential Guard, Measured Boot |
| **Secure Boot** | Enabled, UEFI firmware only (no legacy BIOS) |
| **CPU** | Modern CPU with VBS (Virtualization-Based Security) support |
| **Memory** | 16 GB minimum (Credential Guard uses VBS) |
| **Storage** | SSD, encrypted with BitLocker (TPM + PIN) |
| **Network** | Wired connection preferred; Wi-Fi disabled or restricted to admin VLAN |
| **Peripherals** | No USB storage devices; USB ports restricted via GPO |
| **Firmware** | Latest UEFI firmware, password-protected BIOS |

### 3.2 — PAW Tier 0 — Operating System Hardening

Install a **clean** Windows 11 Enterprise (or Windows 10 Enterprise LTSC) from trusted media. Do NOT image from a standard workstation template.

#### OS Configuration

| Setting | Configuration |
|---------|---------------|
| **OS** | Windows 11 Enterprise (latest build) or Windows 10 Enterprise LTSC |
| **Internet access** | **BLOCKED** — no web browsing, no email, no Teams |
| **Office applications** | **NOT installed** |
| **Credential Guard** | Enabled (via GPO or Intune) |
| **Device Guard / WDAC** | Enabled — only allow signed, trusted applications |
| **BitLocker** | Full disk encryption, TPM + PIN |
| **Windows Firewall** | All inbound blocked except RDP from authorized jump servers |
| **Remote Desktop** | Outbound RDP allowed (to connect to DCs/T0 servers only) |
| **AppLocker / WDAC Policy** | Whitelist: MMC, PowerShell (constrained), RSAT tools, RDP client only |
| **Windows Update** | Direct from Microsoft Update or a dedicated T0 WSUS |
| **Antimalware** | Microsoft Defender for Endpoint (if available) or Defender AV with latest definitions |
| **Local admin** | Only the T0 PAW admin group — no Domain Admins |

#### GPO for Tier 0 PAWs

Create a GPO named `PAW - Tier 0 Hardening` and link it to the `Tier 0\PAW` OU.

Key settings:

```
Computer Configuration → Policies → Administrative Templates:
├── Network
│   ├── DNS Client
│   │   └── Turn off multicast name resolution = Enabled
│   ├── Microsoft Peer-to-Peer Networking Services
│   │   └── Turn off Microsoft Peer-to-Peer Networking Services = Enabled
│   └── WPAD: disable via registry (no GPO native setting)
│
├── Windows Components
│   ├── Internet Explorer → Deny all
│   ├── Microsoft Edge → Deny all
│   ├── Windows Store → Turn off the Store application = Enabled
│   ├── Credential User Interface
│   │   └── Enumerate administrator accounts on elevation = Disabled
│   ├── Remote Desktop Services
│   │   └── Remote Desktop Session Host
│   │       └── Security
│   │           ├── Require use of specific security layer = SSL
│   │           ├── Require Network Level Authentication = Enabled
│   │           └── Set client connection encryption level = High
│   └── Windows Remote Management (WinRM)
│       └── WinRM Service
│           └── Allow remote server management = Disabled (inbound)
│
├── System
│   ├── Credential Delegation
│   │   └── Restrict delegation of credentials to remote servers = Enabled (Require Remote Credential Guard)
│   ├── Device Guard
│   │   └── Turn on Virtualization Based Security = Enabled
│   │       ├── Platform Security Level = Secure Boot and DMA Protection
│   │       ├── Credential Guard = Enabled with UEFI lock
│   │       └── Secure Launch = Enabled
│   └── Device Installation
│       └── Device Installation Restrictions
│           └── Prevent installation of removable devices = Enabled

Computer Configuration → Policies → Windows Settings → Security Settings:
├── Local Policies → User Rights Assignment
│   ├── Deny log on locally = T1-DenyLogon-T0, T2-DenyLogon-T0
│   └── Deny access from network = T1-DenyLogon-T0, T2-DenyLogon-T0
├── Windows Firewall with Advanced Security
│   ├── Inbound: Block all except required (Kerberos, LDAP, DNS to DCs)
│   └── Outbound: Allow RDP to T0 servers/DCs only, block internet
└── Restricted Groups / Preferences
    └── Local Administrators = T0-Admins only (remove all others)
```

#### Network Segmentation for PAWs

PAWs should be on a **dedicated VLAN** with strict firewall rules:

| Source | Destination | Ports | Allow/Deny |
|--------|-------------|-------|------------|
| T0 PAW VLAN | Domain Controllers | 53, 88, 135, 389, 445, 636, 3268, 3269, 3389, 5985, 9389 | Allow |
| T0 PAW VLAN | T0 Servers (AD CS, etc.) | 135, 445, 3389, 5985 | Allow |
| T0 PAW VLAN | Internet | ALL | **Deny** |
| T0 PAW VLAN | T1 Servers | ALL | **Deny** |
| T0 PAW VLAN | T2 Workstations | ALL | **Deny** |
| T0 PAW VLAN | Windows Update (if direct) | 443 | Allow (to Microsoft Update only) |
| Any | T0 PAW VLAN | ALL | **Deny** (no inbound from non-T0) |

### 3.3 — PAW Tier 0 — Management Model

Tier 0 PAWs cannot be managed by Tier 1 tools (SCCM, Intune). They must be self-managed or managed by Tier 0 infrastructure.

| Aspect | Approach |
|--------|----------|
| **Software deployment** | Manual or via T0-only GPO; no SCCM/Intune |
| **Patching** | Dedicated T0 WSUS or manual Windows Update to Microsoft directly |
| **Monitoring** | Forwarded event logs to SIEM via Windows Event Forwarding (WEF) |
| **Backup** | T0 backup infrastructure only; or manual BitLocker recovery key storage |
| **Inventory** | Manual inventory or a T0-only management tool |
| **Incident response** | PAW is rebuilt from scratch (not reimaged from T1 infrastructure) |

### 3.4 — PAW Tier 1 (Optional but Recommended)

For Tier 1, you have two options:

**Option A: Dedicated PAW machines** — Same concept as T0 PAWs but for server administration. Can have internet access through a web proxy, but no email or personal use.

**Option B: Hardened jump servers** — Centralized servers that Tier 1 admins RDP into to manage Tier 1 infrastructure. Cheaper to deploy, easier to manage, but less secure than dedicated hardware.

| Tier 1 PAW Feature | Option A (Dedicated) | Option B (Jump Server) |
|---------------------|---------------------|----------------------|
| Hardware isolation | Yes (physical) | No (shared server) |
| Credential protection | Credential Guard + Remote Credential Guard | Restricted Admin Mode or Remote Credential Guard |
| Cost | Higher (one per admin) | Lower (shared infrastructure) |
| Management | Same as T0 PAW model | Can use T1 management tools |
| Internet access | Proxy-filtered only | None (RDP only) |

If using jump servers:

```powershell
# Enable Restricted Admin Mode on the jump server (prevents credential caching on the target)
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
    -Name "DisableRestrictedAdmin" -Value 0 -PropertyType DWORD -Force

# Connect using Restricted Admin Mode (credentials NOT cached on remote machine)
mstsc /restrictedadmin /v:jumpserver01.domain.local
```

### 3.5 — Remote Credential Guard vs. Restricted Admin Mode

Both prevent credential caching on the remote machine, but they work differently:

| Feature | Remote Credential Guard | Restricted Admin Mode |
|---------|------------------------|----------------------|
| Credential caching on target | No | No |
| Single Sign-On from target | Yes (credentials redirected to source) | No (logs in as local admin) |
| Network resource access | Yes (using source credentials) | No (cannot access network resources) |
| Requirements | Windows 10 1607+ / Server 2016+ | Windows 8.1+ / Server 2012 R2+ |
| Recommended for | PAW → DC/T0 server connections | Fallback when RCG is not available |

**Recommended:** Use Remote Credential Guard for PAW → DC connections.

```
# GPO: Computer Configuration → Administrative Templates → System → Credential Delegation
# "Restrict delegation of credentials to remote servers" = Enabled
# Use mode: Require Remote Credential Guard
```

### Phase 3 Checklist

- [ ] Tier 0 PAW hardware procured (physical machines, TPM 2.0, Secure Boot, VBS-capable)
- [ ] Clean OS installed from trusted media (not from standard workstation image)
- [ ] BitLocker enabled with TPM + PIN
- [ ] Credential Guard enabled and verified (`msinfo32` → Virtualization-Based Security: Running)
- [ ] WDAC / AppLocker policy applied (whitelist only admin tools)
- [ ] Internet access blocked (firewall or proxy)
- [ ] Email, Office apps, web browsers NOT installed
- [ ] USB storage devices blocked via GPO
- [ ] PAW hardening GPO created and linked to `Tier 0\PAW` OU
- [ ] Dedicated admin VLAN configured for PAWs
- [ ] Firewall rules: PAW → DCs/T0 servers only; all other traffic denied
- [ ] Inbound connections to PAWs blocked from non-T0 sources
- [ ] Remote Credential Guard configured for outbound RDP connections
- [ ] Local administrators group on PAW contains only `T0-Admins` (no Domain Admins)
- [ ] PAW management model defined (no SCCM/Intune; T0-only WSUS or direct Microsoft Update)
- [ ] Event log forwarding configured (WEF to SIEM)
- [ ] Tier 1 PAW or jump server strategy decided (dedicated hardware or shared jump servers)
- [ ] Jump servers hardened if using Option B (Restricted Admin Mode or RCG enabled)
- [ ] PAW rebuild procedure documented (how to rebuild from scratch if compromised)
- [ ] BitLocker recovery keys stored securely in T0 infrastructure

---

## Phase 4 — GPO Hardening Per Tier

Each tier receives a set of security GPOs that harden the machines within that tier. These GPOs are in addition to the logon restriction GPOs from Phase 2.

### 4.1 — Tier 0 Hardening (Domain Controllers and T0 Servers)

#### GPO: `Hardening - Tier 0 - Domain Controllers`

Link to: `Domain Controllers` OU

**Credential Protection:**

| Setting | Value | Path |
|---------|-------|------|
| Credential Guard | Enabled with UEFI lock | Computer → Admin Templates → System → Device Guard |
| WDigest Authentication | Disabled | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0` |
| LSASS Protected Mode | Enabled | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` |
| Net Logon: Require strong session key | Enabled | Computer → Windows Settings → Security → Local Policies → Security Options |

**Protocol Hardening:**

| Setting | Value | Why |
|---------|-------|-----|
| LDAP signing | Required | Prevents LDAP relay attacks |
| LDAP channel binding | Required | Prevents LDAP relay over TLS |
| SMB signing | Required (both client and server) | Prevents SMB relay attacks |
| NTLMv2 only | Send NTLMv2 / Refuse LM & NTLM | Prevents downgrade attacks |
| Kerberos encryption | AES256-SHA1 minimum | Prevents RC4 (effectively NTLMv1 equivalent) |

```
Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options:

- Domain controller: LDAP server signing requirements = Require signing
- Microsoft network server: Digitally sign communications (always) = Enabled
- Microsoft network client: Digitally sign communications (always) = Enabled
- Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM
- Network security: Minimum session security for NTLM SSP = Require NTLMv2 AND 128-bit encryption
- Network security: Configure encryption types allowed for Kerberos = AES128, AES256 (disable RC4, DES)
```

**Disable Unnecessary Services:**

```powershell
# Services to disable on Domain Controllers via GPO (Computer Config → Preferences → Services)
$ServicesToDisable = @(
    "Spooler",           # Print Spooler — PrintNightmare attack vector
    "WebClient",         # WebDAV — NTLM relay attack vector
    "RemoteRegistry",    # Remote Registry — enumeration vector
    "WinHttpAutoProxySvc" # WPAD — MITM attack vector
)
```

Configure in GPO under:
`Computer Configuration → Preferences → Control Panel Settings → Services`

For each service: Startup type = Disabled, Service action = Stop

**Auditing Configuration:**

Enable **Advanced Audit Policy** on DCs to capture security-relevant events:

```
Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration:

Account Logon:
  ├── Audit Credential Validation = Success and Failure
  ├── Audit Kerberos Authentication Service = Success and Failure
  └── Audit Kerberos Service Ticket Operations = Success and Failure

Account Management:
  ├── Audit Computer Account Management = Success and Failure
  ├── Audit Security Group Management = Success and Failure
  └── Audit User Account Management = Success and Failure

Detailed Tracking:
  └── Audit Process Creation = Success

DS Access:
  ├── Audit Directory Service Access = Success and Failure
  └── Audit Directory Service Changes = Success and Failure

Logon/Logoff:
  ├── Audit Logon = Success and Failure
  ├── Audit Logoff = Success
  ├── Audit Special Logon = Success
  └── Audit Other Logon/Logoff Events = Success and Failure

Object Access:
  └── Audit SAM = Success and Failure

Policy Change:
  ├── Audit Audit Policy Change = Success and Failure
  └── Audit Authentication Policy Change = Success and Failure

Privilege Use:
  └── Audit Sensitive Privilege Use = Success and Failure

System:
  ├── Audit Security State Change = Success and Failure
  └── Audit Security System Extension = Success and Failure
```

> **Important:** Also force Advanced Audit Policy to override legacy audit policy:
> `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
> `Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings = Enabled`

> **Important:** Increase the Security Event Log size (default 20 MB is far too small):
> `Computer Configuration → Policies → Windows Settings → Security Settings → Event Log`
> `Maximum Security Log size = 1048576 KB (1 GB)` or more

**Enable command-line auditing in process creation events:**

```
Computer Configuration → Administrative Templates → System → Audit Process Creation
  → Include command line in process creation events = Enabled
```

#### GPO: `Hardening - Tier 0 - Servers`

Link to: `Tier 0\Servers` OU (for AD CS, AD FS, Entra ID Connect, etc.)

Apply the same settings as the DC GPO, plus:

| Additional Setting | Value |
|-------------------|-------|
| Windows Remote Management | Restricted to T0 PAW VLAN source IPs |
| Windows Firewall | Block all inbound except required service ports from T0 sources |
| LAPS | Enabled for local admin password management |
| Local admin group | Only `T0-Admins` via Restricted Groups or GPO Preferences |

### 4.2 — Tier 1 Hardening (Servers)

#### GPO: `Hardening - Tier 1 - Servers`

Link to: `Tier 1\Servers` OU

**Credential Protection:**

| Setting | Value |
|---------|-------|
| LAPS (Windows LAPS or Legacy LAPS) | Enabled — unique local admin password per server, rotated every 30 days |
| Credential Guard | Enabled (if compatible with applications; test first) |
| WDigest | Disabled |
| LSASS Protected Mode | Enabled |

```powershell
# Deploy Windows LAPS via GPO
# Computer Configuration → Policies → Administrative Templates → System → LAPS
# - Enable local admin password management = Enabled
# - Password Settings: length 20+, age 30 days, complexity: large + small + numbers + specials
# - Configure authorized password decryptors = T1-Admins
```

**Local Admin Restriction:**

```
Computer Configuration → Preferences → Control Panel Settings → Local Users and Groups
Action: Replace
Group: Administrators (built-in)
Members:
  - DOMAIN\T1-Admins     (Add)
  - Ensure Domain Admins is NOT in this group on T1 servers
```

> **Why remove Domain Admins from local admins on T1?** Because Domain Admins are Tier 0. If a Domain Admin's credential is cached on a Tier 1 server, that server becomes a path to Tier 0 compromise.

**Application Control:**

| Setting | Value |
|---------|-------|
| AppLocker or WDAC | Restrict executable and script execution to trusted publishers and paths |
| PowerShell | Constrained Language Mode for non-admins; Script Block Logging enabled |

```
Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell:
- Turn on Module Logging = Enabled (log all modules: *)
- Turn on PowerShell Script Block Logging = Enabled
- Turn on Script Execution = Enabled, Allow only signed scripts (if feasible)
```

**Network Protection:**

| Setting | Value |
|---------|-------|
| Windows Firewall | Block inbound from T2 workstations on management ports (5985, 5986, 3389) |
| SMB signing | Required |
| Disable LLMNR | `Computer → Admin Templates → Network → DNS Client → Turn off multicast name resolution = Enabled` |
| Disable NetBIOS | Via DHCP scope options (NetBIOS setting = Disable) or NIC GPO |

### 4.3 — Tier 2 Hardening (Workstations)

#### GPO: `Hardening - Tier 2 - Workstations`

Link to: `Tier 2\Workstations` OU

**Credential Protection:**

| Setting | Value |
|---------|-------|
| LAPS | Enabled — unique local admin password per workstation |
| Credential Guard | Enabled (standard on Windows 11 Enterprise) |
| WDigest | Disabled |

**Lateral Movement Prevention:**

This is critical. Workstations should **not** be able to communicate with each other on management ports:

```
Computer Configuration → Policies → Windows Settings → Security Settings → 
  Windows Firewall with Advanced Security → Inbound Rules:

Block Inbound:
  - SMB (TCP 445) from any workstation subnet → Block
  - RDP (TCP 3389) from any workstation subnet → Block
  - WinRM (TCP 5985, 5986) from any workstation subnet → Block
  - RPC (TCP 135) from any workstation subnet → Block
  
Allow Inbound:
  - SCCM Client (TCP 10123, etc.) from SCCM servers → Allow
  - Windows Remote Management from T2 admin subnet → Allow (for helpdesk)
```

> **Why block workstation-to-workstation SMB?** This is the primary lateral movement vector. An attacker who compromises one workstation uses `psexec`, `wmiexec`, or SMB shares to move to the next one. Blocking port 445 between workstations makes lateral movement significantly harder.

**Application Control:**

| Setting | Value |
|---------|-------|
| AppLocker or WDAC | Recommended: Block execution from user-writable paths (`%TEMP%`, `%APPDATA%`, `Downloads`) |
| PowerShell | Constrained Language Mode for standard users |
| Script execution | Restrict `.vbs`, `.js`, `.wsf`, `.ps1` execution for non-admins |

**Network Protection:**

| Setting | Value |
|---------|-------|
| LLMNR | Disabled |
| NetBIOS over TCP/IP | Disabled |
| WPAD | Disabled (via registry or DHCP) |
| mDNS | Disabled |
| SMB signing | Required (client and server) |

### 4.4 — LAPS Deployment Across All Tiers

LAPS (Local Administrator Password Solution) ensures every machine has a **unique, randomly generated** local administrator password that is stored securely in Active Directory.

#### Windows LAPS (Built-in, Windows 11 / Server 2025+)

```powershell
# Update AD schema for Windows LAPS (run as Schema Admin)
Update-LapsADSchema

# Set permissions: allow the machine to write its own password
Set-LapsADComputerSelfPermission -Identity "OU=Workstations,OU=Tier 2,$((Get-ADDomain).DistinguishedName)"
Set-LapsADComputerSelfPermission -Identity "OU=Servers,OU=Tier 1,$((Get-ADDomain).DistinguishedName)"
Set-LapsADComputerSelfPermission -Identity "OU=Servers,OU=Tier 0,$((Get-ADDomain).DistinguishedName)"

# Grant read permissions to the correct admin tier group
Set-LapsADReadPasswordPermission -Identity "OU=Workstations,OU=Tier 2,$((Get-ADDomain).DistinguishedName)" -AllowedPrincipals "T2-Admins"
Set-LapsADReadPasswordPermission -Identity "OU=Servers,OU=Tier 1,$((Get-ADDomain).DistinguishedName)" -AllowedPrincipals "T1-Admins"
Set-LapsADReadPasswordPermission -Identity "OU=Servers,OU=Tier 0,$((Get-ADDomain).DistinguishedName)" -AllowedPrincipals "T0-Admins"
```

#### LAPS GPO Settings

```
Computer Configuration → Policies → Administrative Templates → System → LAPS:
- Configure password backup directory = Active Directory
- Password Settings:
    - Password Complexity: Large letters + small letters + numbers + specials
    - Password Length: 24
    - Password Age (days): 30
- Name of administrator account to manage: (leave default or specify custom local admin name)
- Enable password encryption: Enabled (Windows LAPS only, recommended)
- Configure authorized password decryptors: <Tier-specific admin group>
```

> **Critical:** LAPS read permissions must follow tiering. T2-Admins can read T2 LAPS passwords. T1-Admins can read T1 LAPS passwords. T0-Admins can read T0 LAPS passwords. **Never** grant cross-tier LAPS read access.

### Phase 4 Checklist

- [ ] DC hardening GPO created and linked to Domain Controllers OU
- [ ] Credential Guard enabled on DCs (verified with `msinfo32`)
- [ ] LSASS Protected Mode (RunAsPPL) enabled on DCs
- [ ] WDigest disabled on all tiers
- [ ] LDAP signing set to Required on DCs
- [ ] LDAP channel binding set to Required on DCs
- [ ] SMB signing required on all tiers (client and server)
- [ ] NTLMv2 only enforced; LM and NTLMv1 refused
- [ ] Kerberos encryption restricted to AES (RC4 and DES disabled)
- [ ] Print Spooler disabled on DCs
- [ ] WebClient service disabled on DCs
- [ ] Advanced Audit Policy configured on DCs
- [ ] Command-line auditing enabled for process creation events
- [ ] Security Event Log size increased to 1 GB+ on DCs
- [ ] Tier 0 server hardening GPO created and linked
- [ ] Tier 1 server hardening GPO created and linked
- [ ] LAPS deployed on all Tier 1 servers
- [ ] Credential Guard deployed on Tier 1 servers (where compatible)
- [ ] Domain Admins removed from local admin group on Tier 1 servers
- [ ] AppLocker or WDAC deployed on Tier 1 servers
- [ ] PowerShell Script Block Logging enabled on all tiers
- [ ] Tier 2 workstation hardening GPO created and linked
- [ ] LAPS deployed on all Tier 2 workstations
- [ ] Workstation-to-workstation firewall rules blocking management ports (445, 3389, 5985)
- [ ] LLMNR, NetBIOS, WPAD, mDNS disabled on all tiers
- [ ] LAPS read permissions verified per tier (no cross-tier access)
- [ ] All GPOs tested on pilot machines before broad deployment
- [ ] Basline `gpresult` captured for compliance verification

---

## Phase 5 — Tier 0 Object Protection

Even with logon restrictions and PAWs, Active Directory objects must be protected against unauthorized modification. An attacker with write access to a Tier 0 object can escalate privileges without ever logging into a DC.

### 5.1 — Audit and Clean ACLs on Critical Objects

#### Objects to Audit

| Object | DN Path | What to Check |
|--------|---------|---------------|
| Domain root | `DC=domain,DC=local` | Who has `WriteDACL`, `WriteOwner`, `GenericAll` |
| AdminSDHolder | `CN=AdminSDHolder,CN=System,DC=domain,DC=local` | Template ACL applied to all protected objects |
| Schema partition | `CN=Schema,CN=Configuration,DC=domain,DC=local` | Schema Admins only |
| Configuration partition | `CN=Configuration,DC=domain,DC=local` | Enterprise Admins / Domain Admins only |
| Domain Controllers OU | `OU=Domain Controllers,DC=domain,DC=local` | Who can link GPOs, create objects |
| GPOs linked to T0 OUs | By GUID in SYSVOL | Who owns them, who can edit |
| `dSHeuristics` | `CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=domain,DC=local` | Should only be writeable by Schema/Enterprise Admins |

#### Auditing ACLs with PowerShell

```powershell
# Check ACLs on the domain root
$DomainDN = (Get-ADDomain).DistinguishedName
(Get-Acl "AD:\$DomainDN").Access |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericAll|WriteDacl|WriteOwner|GenericWrite" -and
        $_.IdentityReference -notmatch "S-1-5-18|NT AUTHORITY|BUILTIN\\Administrators|Domain Admins|Enterprise Admins"
    } | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType, InheritanceType -AutoSize

# Check ACLs on AdminSDHolder
(Get-Acl "AD:\CN=AdminSDHolder,CN=System,$DomainDN").Access |
    Where-Object {
        $_.IdentityReference -notmatch "S-1-5-18|NT AUTHORITY|BUILTIN\\Administrators|Domain Admins|Enterprise Admins|Account Operators|Cert Publishers"
    } | Format-Table IdentityReference, ActiveDirectoryRights, AccessControlType -AutoSize

# Check GPO owners and permissions
Get-GPO -All | ForEach-Object {
    $GPO = $_
    $Path = "\\$((Get-ADDomain).DNSRoot)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{$($GPO.Id)}"
    [PSCustomObject]@{
        GPOName = $GPO.DisplayName
        Owner = $GPO.Owner
        Path = $Path
    }
} | Where-Object { $_.Owner -notmatch "Domain Admins|Enterprise Admins" } |
    Format-Table -AutoSize
```

> **Key finding to look for:** Non-admin identities with `WriteDACL` or `GenericAll` on the domain root, AdminSDHolder, or Configuration partition. The most common offender is `Exchange Windows Permissions` with `WriteDACL` on the domain root (which allows DCSync).

#### Remediate Dangerous ACLs

```powershell
# Example: Remove WriteDACL from Exchange Windows Permissions on the domain root
$DomainDN = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:\$DomainDN"
$exchangeGroup = New-Object System.Security.Principal.NTAccount("DOMAIN","Exchange Windows Permissions")

$acl.Access | Where-Object {
    $_.IdentityReference -eq $exchangeGroup -and
    $_.ActiveDirectoryRights -match "WriteDacl"
} | ForEach-Object {
    $acl.RemoveAccessRule($_) | Out-Null
}
Set-Acl "AD:\$DomainDN" $acl
```

> **Caution:** Test ACL changes in a lab environment first. Removing the wrong ACE can break Exchange or other services.

### 5.2 — Protect GPOs Linked to Tier 0

GPOs linked to the `Domain Controllers` OU or `Tier 0` OU are effectively Tier 0 objects. If an attacker can edit these GPOs, they can deploy scripts or configuration changes that execute on DCs.

**Actions:**

1. **Verify GPO ownership:** All T0 GPOs must be owned by `Domain Admins` or `Enterprise Admins`
2. **Remove edit permissions for non-T0 accounts:** Only `T0-Admins` and `Domain Admins` should have Edit/Delete permissions
3. **Block inheritance on T0 OUs from above:** If there are GPOs at the domain root that could be modified by non-T0 accounts, use Block Inheritance on the Tier 0 OU (then re-link essential GPOs directly)

```powershell
# List all GPOs linked to Domain Controllers OU and check permissions
$DCsOU = "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"
$LinkedGPOs = (Get-ADOrganizationalUnit -Identity $DCsOU).LinkedGroupPolicyObjects

foreach ($link in $LinkedGPOs) {
    $guid = $link -replace '.*\{(.*?)\}.*', '$1'
    $gpo = Get-GPO -Guid $guid
    Write-Host "`n=== $($gpo.DisplayName) ===" -ForegroundColor Cyan
    Write-Host "Owner: $($gpo.Owner)"

    # Check SYSVOL permissions
    $sysvolPath = "\\$((Get-ADDomain).DNSRoot)\SYSVOL\$((Get-ADDomain).DNSRoot)\Policies\{$guid}"
    (Get-Acl $sysvolPath).Access |
        Where-Object { $_.FileSystemRights -match "Modify|FullControl|Write" } |
        Format-Table IdentityReference, FileSystemRights, AccessControlType -AutoSize
}
```

### 5.3 — Secure the krbtgt Account

The `krbtgt` account is the most sensitive account in Active Directory. Its password hash is used to sign every Kerberos TGT. If compromised, an attacker can forge Golden Tickets.

#### Rotate the krbtgt Password

```powershell
# Use the official Microsoft krbtgt reset script
# Download from: https://github.com/microsoft/New-KrbtgtKeys.ps1
# Or use the built-in method:

# Step 1: Reset krbtgt password (first rotation)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (
    ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(64,16)) -AsPlainText -Force
)
Write-Host "First krbtgt password rotation complete at $(Get-Date)" -ForegroundColor Green

# Step 2: WAIT at least 12 hours (must be longer than the maximum TGT lifetime, default 10 hours)
# This allows all existing TGTs signed with the old password to expire

# Step 3: Reset krbtgt password again (second rotation)
Set-ADAccountPassword -Identity "krbtgt" -Reset -NewPassword (
    ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(64,16)) -AsPlainText -Force
)
Write-Host "Second krbtgt password rotation complete at $(Get-Date)" -ForegroundColor Green
```

> **Why twice?** Active Directory keeps the current and previous krbtgt password hashes. The first rotation pushes the old hash to "previous." The second rotation pushes the compromise hash completely out. You **must** wait between rotations to avoid breaking all existing Kerberos tickets.

> **Recommendation:** Rotate krbtgt every **180 days** at minimum. Some organizations rotate every 90 days.

#### Monitor for Golden Ticket Attacks

| Event ID | Source | Meaning |
|----------|--------|---------|
| 4769 | Security | TGS request — look for tickets with anomalous lifetimes (>10 hours) |
| 4768 | Security | TGT request — baseline normal patterns |
| Alert | MDI | "Suspected Golden Ticket usage" |

### 5.4 — Secure Service Accounts

Service accounts are one of the weakest links in most environments. They often have:
- Passwords that haven't changed in years
- Membership in Domain Admins
- SPNs that make them Kerberoastable
- Interactive logon rights (should be denied)

#### Migrate to Group Managed Service Accounts (gMSA)

gMSAs have 240-character randomly generated passwords that rotate automatically every 30 days. They cannot be Kerberoasted (password is too complex) and cannot be used interactively.

```powershell
# Step 1: Create the KDS root key (one-time, domain-wide)
# In production, use -EffectiveTime (Get-Date).AddHours(-10) to make it available immediately
# In production environments, this should replicate to all DCs first (wait 10 hours normally)
Add-KdsRootKey -EffectiveTime (Get-Date).AddHours(-10)

# Step 2: Create a gMSA
New-ADServiceAccount -Name "gMSA-SQL-T1" `
    -DNSHostName "gMSA-SQL-T1.domain.local" `
    -Description "Tier 1 gMSA for SQL Server service" `
    -PrincipalsAllowedToRetrieveManagedPassword "T1-SQL-Servers" `
    -Path "OU=Service Accounts,OU=Tier 1,$((Get-ADDomain).DistinguishedName)" `
    -KerberosEncryptionType AES256

# Step 3: Install the gMSA on the target server (run on the server)
Install-ADServiceAccount -Identity "gMSA-SQL-T1"

# Step 4: Test the gMSA
Test-ADServiceAccount -Identity "gMSA-SQL-T1"  # Should return True

# Step 5: Configure the service to use the gMSA
# In services.msc: Set "Log on as" to DOMAIN\gMSA-SQL-T1$ (note the $ suffix)
# Password field: leave blank (managed automatically)
```

#### For Service Accounts That Cannot Use gMSA

Some legacy applications don't support gMSA. For those:

| Mitigation | How |
|------------|-----|
| Long, complex password | 25+ characters, randomly generated |
| Automated rotation | Use a PAM tool (CyberArk, etc.) or scheduled task |
| Remove from Domain Admins | Create a dedicated group with minimum required permissions |
| Deny interactive logon | GPO: Deny log on locally for service accounts |
| Set "Account is sensitive and cannot be delegated" | Prevents Kerberos delegation abuse |
| Monitor Kerberoasting | Alert on Event 4769 with RC4 encryption for SPN accounts |

```powershell
# Deny interactive logon for all service accounts across all tiers
# Add T0-ServiceAccounts, T1-ServiceAccounts, T2-ServiceAccounts to:
# "Deny log on locally" in each tier's GPO

# Identify service accounts with SPNs (Kerberoastable)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName, PasswordLastSet, MemberOf |
    Select-Object Name, SamAccountName, PasswordLastSet,
        @{N='SPNs';E={$_.ServicePrincipalName -join '; '}},
        @{N='MemberOf';E={($_.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join '; '}} |
    Export-Csv -Path "C:\Tiering\KerberoastableAccounts.csv" -NoTypeInformation
```

### 5.5 — Secure AD CS (PKI) as Tier 0

AD CS is one of the most commonly exploited Tier 0 components. Certificate-based attacks (ESC1 through ESC13) can grant domain admin access.

**Key hardening actions:**

| Action | Detail |
|--------|--------|
| Audit certificate templates | Look for templates that allow SAN (Subject Alternative Name) specification by the requester → ESC1 |
| Remove `ENROLLEE_SUPPLIES_SUBJECT` | Unless absolutely required, no template should let the enrollee specify the SAN |
| Restrict enrollment permissions | Only authorized groups should be allowed to enroll for each template |
| Remove unnecessary templates | Disable or delete templates that are not in use |
| Audit CA permissions | Only T0 admins should have CA manager/admin roles |
| Place CA servers in T0 OU | They are Tier 0 — treat them accordingly |
| Disable web enrollment if not needed | The web enrollment page is a frequent attack vector |
| Enable CA auditing | Log all certificate requests, issuances, and revocations |

```powershell
# Audit certificate templates for dangerous configurations
# Requires PSPKI module: Install-Module -Name PSPKI
Import-Module PSPKI

Get-CertificateTemplate | ForEach-Object {
    $template = $_
    [PSCustomObject]@{
        Name = $template.Name
        DisplayName = $template.DisplayName
        EnrolleeSuppliesSubject = ($template.Settings.SubjectName -band 1) -eq 1  # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        ClientAuth = $template.Settings.EnhancedKeyUsage -contains "1.3.6.1.5.5.7.3.2"
        AutoEnroll = $template.Settings.EnrollmentFlags -band 0x20
    }
} | Where-Object { $_.EnrolleeSuppliesSubject -and $_.ClientAuth } |
    Format-Table -AutoSize
```

### Phase 5 Checklist

- [ ] ACLs on domain root object audited — no non-admin `WriteDACL`/`GenericAll`
- [ ] ACLs on AdminSDHolder audited and cleaned
- [ ] ACLs on Configuration partition audited
- [ ] ACLs on Schema partition audited
- [ ] Exchange Windows Permissions `WriteDACL` removed from domain root (if applicable)
- [ ] All GPOs linked to Domain Controllers OU verified (owner = Domain Admins)
- [ ] All GPOs linked to Tier 0 OU verified (no non-T0 edit permissions)
- [ ] Dangerous GPO permissions remediated
- [ ] krbtgt password rotated (two rotations with appropriate interval)
- [ ] krbtgt rotation schedule established (every 90-180 days)
- [ ] Golden Ticket monitoring in place (MDI or Event 4769 alerting)
- [ ] Service accounts inventoried with SPNs, group memberships, and password age
- [ ] Service accounts removed from Domain Admins
- [ ] gMSAs created for all compatible services
- [ ] Legacy service accounts hardened (long passwords, rotation, deny interactive logon)
- [ ] Kerberoasting monitoring configured (Event 4769 with RC4)
- [ ] AD CS servers placed in Tier 0 OU
- [ ] Certificate templates audited for ESC1-ESC8 vulnerabilities
- [ ] `ENROLLEE_SUPPLIES_SUBJECT` removed from templates where not required
- [ ] CA permissions restricted to T0 admins only
- [ ] Web enrollment disabled or hardened
- [ ] CA auditing enabled
- [ ] `dSHeuristics` attribute permissions verified

---

## Phase 6 — Monitoring and Detection

Tiering is only effective if you can **detect** and **respond** to violations and attacks. This phase deploys the detection layer.

### 6.1 — Tiering Violation Detection

The most critical alert in a tiered environment: **a Tier 0 account logging into a non-Tier 0 machine.**

#### SIEM Detection Rule Logic

```
// Pseudo-rule for SIEM (Sentinel KQL example)
SecurityEvent
| where EventID == 4624
| where AccountType == "User"
| where Account in (T0_Accounts_Watchlist)
| where Computer !in (T0_Computers_Watchlist)
| project TimeGenerated, Account, Computer, LogonType, IpAddress
| extend Alert = "CRITICAL: Tier 0 account logged into non-Tier 0 machine"
```

```kql
// Microsoft Sentinel KQL — Tier 0 accounts on non-T0 machines
let T0Accounts = dynamic(["t0-john.doe", "t0-jane.smith"]);  // Or use a Watchlist
let T0Computers = dynamic(["DC01", "DC02", "ADCS01", "ADFS01"]);
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 3, 7, 10)  // Interactive, Network, Unlock, RDP
| where TargetUserName in~ (T0Accounts)
| where Computer !in~ (T0Computers)
| project TimeGenerated, TargetUserName, Computer, LogonTypeName, IpAddress, WorkstationName
```

#### Event Log-Based Detection (Without SIEM)

If you don't have a SIEM, use **Windows Event Forwarding (WEF)** to collect events centrally and **Task Scheduler** to alert:

```powershell
# Create a scheduled task on a collector that triggers on tiering violation events
# This monitors forwarded events for T0 accounts on non-T0 machines

$XPath = @"
<QueryList>
  <Query Id="0" Path="ForwardedEvents">
    <Select Path="ForwardedEvents">
      *[System[(EventID=4624)]]
      and
      *[EventData[Data[@Name='TargetUserName'] and (Data='t0-john.doe' or Data='t0-jane.smith')]]
    </Select>
  </Query>
</QueryList>
"@

# Use this XPath filter in Event Viewer subscriptions or Task Scheduler triggers
```

### 6.2 — Deploy Microsoft Defender for Identity (MDI)

MDI is the most effective tool for detecting Active Directory attacks in real time. If budget allows, it should be deployed as part of the tiering project.

**Key MDI detections relevant to tiering:**

| Detection | Relevance |
|-----------|-----------|
| Pass-the-Hash | Detects credential reuse — indicates tiering violation |
| Pass-the-Ticket | Detects Kerberos ticket theft — lateral movement |
| Golden Ticket usage | Detects forged TGTs — krbtgt compromise |
| DCSync | Detects directory replication from non-DC — Tier 0 attack |
| Lateral movement path | Shows attack paths across tiers |
| Suspicious service creation | Detects remote code execution on DCs |
| Reconnaissance (LDAP, SAM-R) | Early warning of an attacker in the network |
| Brute force | Credential attacks against AD accounts |
| Account enumeration | Attacker mapping privileged accounts |

**MDI Deployment:**
1. Deploy an MDI sensor on **every** Domain Controller
2. Configure the MDI sensor to monitor ADFS servers (if applicable)
3. Tag all T0 accounts as "Sensitive" in the MDI portal → Enables "Lateral Movement Path to Sensitive User" alerts
4. Configure entity tags for T0/T1/T2 in MDI

### 6.3 — Windows Event Forwarding (WEF) Architecture

Centralize security events from all tiers to a dedicated collector:

```
Tier 0 machines → WEF Collector (Tier 0) → SIEM
Tier 1 machines → WEF Collector (Tier 1) → SIEM
Tier 2 machines → WEF Collector (Tier 2) → SIEM
```

> **Important:** If you use a single WEF collector for all tiers, it must be Tier 0 (because it receives Tier 0 events and credentials from Tier 0 machines).

**Key events to collect and alert on:**

| Event ID | Source | What It Detects |
|----------|--------|----------------|
| 4624 | Security | Successful logon — track by tier |
| 4625 | Security | Failed logon — brute force detection |
| 4672 | Security | Special privileges assigned — T0 privilege use |
| 4728/4732/4756 | Security | Member added to security group — privilege escalation |
| 4768 | Security | Kerberos TGT request — authentication patterns |
| 4769 | Security | Kerberos TGS request — Kerberoasting detection |
| 4776 | Security | NTLM authentication — should be rare in a tiered environment |
| 5136 | Security | Directory object modified — ACL/attribute changes |
| 5141 | Security | Directory object deleted |
| 4688 | Security | Process creation (with command line) — malicious tool execution |
| 7045 | System | New service installed — persistence detection |
| 1102 | Security | Audit log cleared — anti-forensics |

### 6.4 — Dashboards and KPIs

Track these metrics monthly to measure tiering health:

| KPI | Target | How to Measure |
|-----|--------|---------------|
| Tiering violations (T0 on non-T0) | 0 | SIEM alert count |
| Tiering violations (T1 on T2) | 0 | SIEM alert count |
| % of servers with LAPS enabled | 100% | LAPS reporting / AD attribute audit |
| % of workstations with LAPS enabled | 100% | LAPS reporting |
| Members in Domain Admins | Minimum needed | Monthly group review |
| Members in Enterprise Admins | 0 (only populated during use) | Monthly group review |
| Service accounts in Domain Admins | 0 | Monthly audit |
| T0 accounts in Protected Users group | 100% | AD query |
| Kerberoastable accounts with weak passwords | 0 | Regular Kerberoast simulation |
| stale T0 accounts (>90 days inactive) | 0 | AD query on lastLogonTimestamp |
| krbtgt password age | <180 days | `(Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet` |
| BloodHound: paths from T2 to T0 | 0 | Quarterly BloodHound assessment |

### Phase 6 Checklist

- [ ] Tiering violation SIEM rule deployed (T0 account on non-T0 machine)
- [ ] Tiering violation SIEM rule deployed (T1 account on T2 machine)
- [ ] Alert severity set to CRITICAL for T0 violations
- [ ] MDI deployed on all Domain Controllers (if budget allows)
- [ ] T0 accounts tagged as "Sensitive" in MDI
- [ ] Windows Event Forwarding configured for all tiers
- [ ] WEF collector tiered appropriately (T0 collector for T0 events)
- [ ] Key event IDs collected (4624, 4625, 4672, 4728, 4768, 4769, 4776, 5136, 4688, 7045, 1102)
- [ ] Security Event Log retention increased (1 GB+ on DCs, 512 MB on servers)
- [ ] SIEM dashboards created for tiering KPIs
- [ ] Monthly tiering compliance review scheduled
- [ ] Kerberoasting simulation tool scheduled quarterly
- [ ] BloodHound assessment scheduled quarterly
- [ ] Incident response playbook for tiering violations documented
- [ ] Alerting for audit log clearing (Event 1102) configured
- [ ] Alerting for new service installation on DCs (Event 7045) configured

---

## Phase 7 — Operational Procedures and Continuous Improvement

Tiering is not a one-time project. Without ongoing maintenance, the model degrades over time as exceptions accumulate and new systems are deployed without classification.

### 7.1 — Onboarding and Offboarding Procedures

#### New Administrator Onboarding

1. Determine which tiers the admin needs to manage
2. Create tiered admin accounts (`t0-`, `t1-`, `t2-` prefix) using the script from Phase 2.1
3. Add accounts to the correct `Tx-Admins` groups
4. For T0 admins: add to `Protected Users`, issue a PAW, schedule PAW training
5. Brief the admin on the tiering model and acceptable use policy
6. Document the accounts in the admin register

#### Administrator Offboarding

1. Disable all tiered admin accounts immediately (do not delete — retain for log correlation)
2. Remove from all privileged groups
3. Remove from Authentication Silos
4. Rotate any shared credentials the admin had access to
5. Review recent activity of the admin's accounts for anomalies
6. Recover the PAW hardware
7. Move disabled accounts to the `Disabled\Users` OU
8. Schedule account deletion after retention period (90-365 days, per policy)

#### New Server / Workstation Onboarding

1. New computer object lands in `Quarantine\Computers` (via `redircmp`)
2. System administrator classifies the machine (T0/T1/T2)
3. Machine is moved to the correct tier OU
4. GPO application is verified (`gpresult /r`)
5. LAPS is confirmed operational
6. Machine is added to the correct `Tx-Servers` or `T2-Workstations` group
7. For T0 servers: added to Authentication Silo

### 7.2 — Periodic Reviews

| Review | Frequency | Actions |
|--------|-----------|---------|
| **Privileged group membership** | Monthly | Review all T0 groups; remove unnecessary members; verify `Enterprise Admins` is empty |
| **Service account audit** | Quarterly | Check password age, group memberships, SPN exposure; migrate to gMSA where possible |
| **ACL audit** | Quarterly | Re-run ACL audit scripts from Phase 5.1; check for new dangerous delegations |
| **Tiering violation review** | Weekly | Review SIEM alerts; investigate and remediate every violation |
| **GPO review** | Quarterly | Verify GPO links, ownership, and permissions; check for GPO drift |
| **LAPS compliance** | Monthly | Verify all machines have LAPS passwords set and within age policy |
| **BloodHound assessment** | Quarterly | Run SharpHound collector; analyze attack paths; compare with baseline |
| **PingCastle score** | Quarterly | Run health check; compare with baseline; address new findings |
| **krbtgt rotation** | Every 90-180 days | Rotate password (twice with interval) |
| **PAW health check** | Monthly | Verify OS patching, Credential Guard status, policy compliance |
| **Authentication Policy audit** | Quarterly | Review silo membership; check for accounts that should be in silos but aren't |

#### Automated Review Script (Monthly)

```powershell
function Invoke-TieringHealthCheck {
    $DomainDN = (Get-ADDomain).DistinguishedName
    $Report = @()

    # Check 1: Domain Admins member count
    $DAMembers = Get-ADGroupMember -Identity "Domain Admins" -Recursive
    $Report += [PSCustomObject]@{
        Check       = "Domain Admins count"
        Value       = $DAMembers.Count
        Status      = if ($DAMembers.Count -le 5) { "OK" } else { "WARNING" }
        Detail      = ($DAMembers.Name -join ", ")
    }

    # Check 2: Enterprise Admins should be empty
    $EAMembers = Get-ADGroupMember -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue
    $Report += [PSCustomObject]@{
        Check       = "Enterprise Admins count"
        Value       = ($EAMembers | Measure-Object).Count
        Status      = if (($EAMembers | Measure-Object).Count -eq 0) { "OK" } else { "CRITICAL" }
        Detail      = if ($EAMembers) { ($EAMembers.Name -join ", ") } else { "Empty (correct)" }
    }

    # Check 3: krbtgt password age
    $krbtgt = Get-ADUser "krbtgt" -Properties PasswordLastSet
    $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
    $Report += [PSCustomObject]@{
        Check       = "krbtgt password age (days)"
        Value       = $krbtgtAge
        Status      = if ($krbtgtAge -le 180) { "OK" } elseif ($krbtgtAge -le 365) { "WARNING" } else { "CRITICAL" }
        Detail      = "Last set: $($krbtgt.PasswordLastSet)"
    }

    # Check 4: T0 accounts in Protected Users
    $T0Admins = Get-ADGroupMember -Identity "T0-Admins" -Recursive | Where-Object { $_.objectClass -eq 'user' }
    $ProtectedUsers = Get-ADGroupMember -Identity "Protected Users" -Recursive
    $T0NotProtected = $T0Admins | Where-Object { $_.SID -notin $ProtectedUsers.SID }
    $Report += [PSCustomObject]@{
        Check       = "T0 accounts NOT in Protected Users"
        Value       = ($T0NotProtected | Measure-Object).Count
        Status      = if (($T0NotProtected | Measure-Object).Count -eq 0) { "OK" } else { "CRITICAL" }
        Detail      = if ($T0NotProtected) { ($T0NotProtected.Name -join ", ") } else { "All protected" }
    }

    # Check 5: Service accounts in Domain Admins
    $SvcInDA = $DAMembers | Where-Object { $_.Name -match "svc|service|sql|app|batch|task|gMSA" }
    $Report += [PSCustomObject]@{
        Check       = "Service accounts in Domain Admins"
        Value       = ($SvcInDA | Measure-Object).Count
        Status      = if (($SvcInDA | Measure-Object).Count -eq 0) { "OK" } else { "CRITICAL" }
        Detail      = if ($SvcInDA) { ($SvcInDA.Name -join ", ") } else { "None (correct)" }
    }

    # Check 6: Objects in Quarantine OU (unclassified)
    $Quarantine = Get-ADComputer -Filter * -SearchBase "OU=Quarantine,$DomainDN" -ErrorAction SilentlyContinue
    $Report += [PSCustomObject]@{
        Check       = "Unclassified computers in Quarantine"
        Value       = ($Quarantine | Measure-Object).Count
        Status      = if (($Quarantine | Measure-Object).Count -eq 0) { "OK" } else { "WARNING" }
        Detail      = if ($Quarantine) { ($Quarantine.Name -join ", ") } else { "None" }
    }

    # Output report
    $Report | Format-Table Check, Value, Status, Detail -AutoSize -Wrap

    # Export to CSV
    $Report | Export-Csv -Path "C:\Tiering\MonthlyHealthCheck_$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
}

Invoke-TieringHealthCheck
```

### 7.3 — Break-Glass Procedure

A break-glass (emergency access) procedure is essential. If all T0 admin accounts are locked out (e.g., due to a misconfigured Authentication Policy), you need a way back in.

#### Break-Glass Account Setup

1. Create **two** break-glass accounts: `BreakGlass-01`, `BreakGlass-02`
2. Set extremely long, randomly generated passwords (30+ characters)
3. Store passwords in **two** separate physical safes (not digital — not in a password manager that depends on AD)
4. Place accounts in `Tier 0\Accounts` OU
5. Add to `Domain Admins` and `T0-Admins`
6. Add to `Protected Users` group
7. **Do NOT** add to Authentication Silos (must be able to log in even if silos are misconfigured)
8. Set `Account is sensitive and cannot be delegated`
9. Set logon hours restriction (optional — deny all hours, unlock only during emergencies)
10. Monitor for **any** use of these accounts — every logon should trigger a CRITICAL alert

```powershell
# Create break-glass accounts
$BG1Password = ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(32,8)) -AsPlainText -Force
$BG2Password = ConvertTo-SecureString -String ([System.Web.Security.Membership]::GeneratePassword(32,8)) -AsPlainText -Force

New-ADUser -Name "BreakGlass-01" -SamAccountName "BreakGlass-01" `
    -UserPrincipalName "BreakGlass-01@$((Get-ADDomain).DNSRoot)" `
    -Description "Emergency break-glass account - DO NOT USE except in documented emergencies" `
    -Path "OU=Accounts,OU=Tier 0,$((Get-ADDomain).DistinguishedName)" `
    -AccountPassword $BG1Password -Enabled $true `
    -PasswordNeverExpires $true `
    -AccountNotDelegated $true

New-ADUser -Name "BreakGlass-02" -SamAccountName "BreakGlass-02" `
    -UserPrincipalName "BreakGlass-02@$((Get-ADDomain).DNSRoot)" `
    -Description "Emergency break-glass account - DO NOT USE except in documented emergencies" `
    -Path "OU=Accounts,OU=Tier 0,$((Get-ADDomain).DistinguishedName)" `
    -AccountPassword $BG2Password -Enabled $true `
    -PasswordNeverExpires $true `
    -AccountNotDelegated $true

# Add to groups
Add-ADGroupMember -Identity "Domain Admins" -Members "BreakGlass-01","BreakGlass-02"
Add-ADGroupMember -Identity "T0-Admins" -Members "BreakGlass-01","BreakGlass-02"
Add-ADGroupMember -Identity "Protected Users" -Members "BreakGlass-01","BreakGlass-02"

# PRINT PASSWORDS - store in separate physical safes, then clear from screen
Write-Host "BreakGlass-01 password: $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($BG1Password)))" -ForegroundColor Red
Write-Host "BreakGlass-02 password: $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($BG2Password)))" -ForegroundColor Red
Write-Host "`nSTORE THESE PASSWORDS IN SEPARATE PHYSICAL SAFES. CLEAR THIS SCREEN NOW." -ForegroundColor Yellow
```

#### Break-Glass Usage Process

1. Two authorized persons must be present (dual control)
2. Retrieve password from physical safe
3. Log the emergency in the incident management system
4. Use the break-glass account to resolve the issue
5. After resolution: **rotate the break-glass password immediately**
6. Store new password in the safe
7. Conduct a post-incident review

### 7.4 — Training and Change Management

| Audience | Training Content |
|----------|-----------------|
| **All IT administrators** | What tiering is, why it exists, the naming convention, which account to use for what, what happens if they violate it (alerts fire) |
| **T0 administrators** | PAW usage, Authentication Silos, break-glass procedure, krbtgt rotation procedure |
| **T1 administrators** | PAW or jump server usage, LAPS password retrieval, service account management |
| **T2 administrators (helpdesk)** | LAPS password retrieval, workstation admin procedures, when to escalate to T1/T0 |
| **Security team** | Tiering violation response, monitoring dashboards, quarterly review procedures, BloodHound analysis |
| **Management** | High-level briefing on risk reduction, KPIs, compliance posture improvement |

**Key messaging points:**
- "This is not about making your job harder — it's about making the attacker's job impossible"
- "If a Domain Admin credential is stolen from your workstation, the entire company is compromised. Tiering prevents this."
- "Yes, you need multiple accounts. Yes, the PAW is restrictive. This is the cost of protecting 10,000+ users and all company data."

### 7.5 — Evolution Toward Hybrid (If Applicable)

If the organization uses or plans to use Entra ID:

| Hybrid Extension | Detail |
|-----------------|--------|
| **Entra ID PIM** | Use Privileged Identity Management for just-in-time access to Entra roles and Azure resources |
| **Conditional Access** | Require PAW device compliance for accessing PIM / Azure Portal / Entra admin center |
| **Device compliance** | Register PAWs in Entra, enforce compliance (BitLocker, Credential Guard, OS version) |
| **Entra ID Connect as T0** | Already classified; ensure the connect server is in T0 OU with T0 hardening |
| **Passwordless for T0** | FIDO2 security keys + Entra for phishing-resistant MFA on PAWs |

### Phase 7 Checklist

- [ ] Administrator onboarding procedure documented (account creation, group assignment, PAW issuance)
- [ ] Administrator offboarding procedure documented (disable accounts, remove from groups, recover PAW)
- [ ] New server/workstation onboarding procedure documented (Quarantine → classification → tier OU)
- [ ] Monthly privileged group review scheduled and assigned
- [ ] Quarterly service account audit scheduled
- [ ] Quarterly ACL audit scheduled
- [ ] Weekly tiering violation review scheduled
- [ ] Quarterly BloodHound and PingCastle assessments scheduled
- [ ] Automated monthly health check script deployed
- [ ] krbtgt rotation schedule configured (every 90-180 days)
- [ ] Break-glass accounts created (two accounts, separate physical safes)
- [ ] Break-glass procedure documented (dual control, password rotation after use)
- [ ] Break-glass account monitoring configured (CRITICAL alert on any logon)
- [ ] Training delivered to all IT administrators
- [ ] Training delivered to security team (monitoring and response)
- [ ] Training materials documented and accessible
- [ ] Acceptable use policy updated to reflect tiering requirements
- [ ] Hybrid extensions planned (Entra PIM, Conditional Access, device compliance) if applicable

---

## Summary — Prioritized Implementation Order

| Priority | Phase | Actions | Impact |
|----------|-------|---------|--------|
| **P0 — Quick Wins** | Phase 0 | Asset classification, privileged account inventory, krbtgt rotation, LAPS | Immediately reduces attack surface |
| **P1 — Foundations** | Phases 1 + 2 | OU structure, tiering groups, dedicated admin accounts, logon restriction GPOs | Establishes the tiering framework |
| **P2 — Strong Isolation** | Phases 2 + 3 | PAW deployment, Authentication Policies/Silos, Protected Users group | Effective Tier 0 isolation |
| **P3 — Hardening** | Phases 4 + 5 | GPO hardening per tier, gMSA migration, AD CS hardening, ACL cleanup, firewall segmentation | Reduces attack vectors |
| **P4 — Detection** | Phase 6 | MDI, SIEM rules, tiering violation alerts, Windows Event Forwarding | Visibility and response capability |
| **P5 — Maturity** | Phase 7 | Periodic reviews, health check automation, training, break-glass, hybrid extensions | Long-term sustainability |

---

## Common Pitfalls and Lessons Learned

| Pitfall | Explanation | Mitigation |
|---------|-------------|------------|
| **Starting with PAWs** | Without logon restrictions and OU structure, PAWs provide no real protection | Always implement Phases 1 and 2 before Phase 3 |
| **Forgetting hypervisors** | A Hyper-V/VMware admin who hosts DCs is de facto Tier 0 | Classify hypervisors hosting T0 VMs as T0 |
| **SCCM/MECM misclassification** | If SCCM can push code to DCs, it's Tier 0 | Audit SCCM boundaries and client deployment scope |
| **Exchange as Tier 1** | `Exchange Windows Permissions` often has DCSync-equivalent rights | Audit and remediate; classify as T0 if WriteDACL exists |
| **Backup operators ignored** | Anyone who can restore a DC has Tier 0 access | Classify backup infrastructure as T0 |
| **Forgotten service accounts** | Service accounts in Domain Admins since 2009 | Quarterly audit; migrate to gMSA |
| **Not blocking lateral movement** | Workstations can freely communicate on port 445 | Deploy workstation firewall GPO blocking SMB/RDP/WinRM between workstations |
| **Single break-glass account** | If it's compromised or passwords lost, no recovery | Two accounts, two safes, dual control |
| **No monitoring** | Tiering without detection = security theater | Deploy violation alerts before or alongside enforcement |
| **Culture resistance** | Admins don't want to use PAWs and multiple accounts | Executive mandate, clear communication, training, no exceptions |
| **Scope creep in T0** | Being too conservative — putting everything in T0 | Only things that can **directly control AD** are T0. A file server is NOT T0. |
| **Scope creep in T1** | Putting dev/test servers in T1 with production | Consider sub-tiers (T1-Prod, T1-Dev) or separate OUs with different GPOs |
| **No maintenance** | Tiering degrades as new systems are added without classification | Quarantine OU + onboarding procedure + quarterly reviews |
| **GPO conflicts** | Existing GPOs override or conflict with tiering GPOs | Audit all GPOs and their precedence before deploying; use `gpresult /h` |
| **Not testing before enforcement** | Enforcing deny logon GPOs without testing = mass lockout | Always pilot on test OUs first; always have break-glass accounts ready |

---

## References

- [Microsoft: Securing Privileged Access](https://aka.ms/SPA)
- [Microsoft: Privileged Access Workstations](https://aka.ms/PAW)
- [Microsoft: Enterprise Access Model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- [Microsoft: Authentication Policies and Silos](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos)
- [Microsoft: Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [Microsoft: Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard)
- [Microsoft: Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Microsoft: Active Directory Administrative Tier Model](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models)
- [BloodHound](https://github.com/SpecterOps/BloodHound)
- [PingCastle](https://www.pingcastle.com/)

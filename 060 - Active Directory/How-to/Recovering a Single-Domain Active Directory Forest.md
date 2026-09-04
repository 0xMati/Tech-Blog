# Recovering a Single-Domain Active Directory Forest — A Practical Step-by-Step Runbook
🗓️ Published: 2026-09-02

## Introduction

Your forest is down, every domain controller is suspect, and *"let's just start all the old VMs"* suddenly sounds like a terrible idea.

Good instinct. 😅

An Active Directory forest recovery is **not** about bringing every DC back. It is about recovering **one trusted writable DC**, making it the new source of truth, removing the dead replication topology, validating the directory, and rebuilding clean DCs from there.

This article turns that process into a practical runbook for the simplest topology:

- One forest.
- One domain.
- One or more DCs before the incident.
- DFSR-replicated SYSVOL.
- A trusted, AD-aware backup of at least one writable DC.

> 🔴 **This is a disaster-recovery procedure, not routine maintenance.** Several steps intentionally break replication with every pre-recovery DC. Rehearse the complete workflow in an isolated lab and adapt it to your backup product, topology, applications, and incident-response process.

> 🔵 **Single-domain does not mean single-DC.** We restore only one DC from backup. The other DCs are removed from the recovered directory and redeployed later.

---

## ⚡ TL;DR

1. Declare the recovery point and isolate the environment.
2. Prevent every old DC from reaching the recovery network.
3. Restore **one writable DC** from a trusted backup.
4. Make its SYSVOL authoritative.
5. Seize all five FSMO roles.
6. Remove the metadata and DNS records of every other DC.
7. Raise the domain RID pool, then invalidate the restored DC's local RID pool.
8. Reset the restored DC's machine-account password twice.
9. Reset `krbtgt` twice, with the correct waiting period between resets.
10. Configure authoritative time, then validate AD DS, DNS, SYSVOL, Kerberos, and RID issuance.
11. Take a fresh backup.
12. Rebuild additional DCs — never reconnect their old copies.
13. Reconnect dependent services carefully, especially Microsoft Entra Connect.

The golden rule is simple:

> **Restore one DC. Rebuild the others. Never resurrect the old replication topology.** 🧟

---

## 🎨 Reading Legend

- 🔴 **Critical** — getting this wrong can invalidate the recovery or reintroduce the incident.
- 🟡 **Warning** — high risk of outage, data loss, or authentication failure.
- 🔵 **Important** — sequencing or design constraint.
- 🟢 **Checkpoint** — do not continue until the expected result is confirmed.
- 💡 **Tip** — practical shortcut or useful context.

---

## 1 — Understand the Recovery Model

The failed forest might have contained five, fifty, or five hundred DCs. The first recovery stage deliberately reduces it to this:

```mermaid
flowchart LR
    A["Failed forest<br/>All old DCs untrusted"] --> B["Isolated recovery network"]
    B --> C["Restore one trusted DC"]
    C --> D["Make it authoritative"]
    D --> E["Validate the domain"]
    E --> F["Reconnect carefully"]
    F --> G["Build clean additional DCs"]

    style A fill:#7f1d1d,stroke:#ef4444,color:#fff
    style B fill:#78350f,stroke:#f59e0b,color:#fff
    style C fill:#1e3a8a,stroke:#60a5fa,color:#fff
    style D fill:#1e3a8a,stroke:#60a5fa,color:#fff
    style E fill:#14532d,stroke:#4ade80,color:#fff
    style F fill:#14532d,stroke:#4ade80,color:#fff
    style G fill:#14532d,stroke:#4ade80,color:#fff
```

### What gets restored, removed, and rebuilt?

| Component | Action | Why |
|---|---|---|
| First writable DC | **Restore from trusted backup** | Provides the recovered AD database and SYSVOL baseline |
| SYSVOL on the first DC | **Make authoritative** | All future DCs must receive the selected recovered copy |
| FSMO roles | **Seize on the first DC** | Their previous holders will not return |
| Other pre-incident DCs | **Remove metadata** | Their databases and invocation state belong to the old topology |
| Additional DCs | **Rebuild or clone later** | They receive clean replicas from the recovered DC |
| Entra Connect | **Keep exports stopped initially** | A rollback of AD can otherwise trigger unexpected cloud changes |

### What this article does not cover

- Multidomain recovery or parent/child trust recovery.
- RODC recovery.
- Legacy FRS-replicated SYSVOL.
- Product-specific backup console steps.
- A complete privileged-account rotation plan after a breach.
- Rebuilding dependent Tier 0 systems such as AD CS, AD FS, MIM, or PAM.

Those components must be added to the organization's own forest recovery plan.

---

## 2 — Before the Incident: Build a Recovery Package

A forest recovery plan first opened during the incident is not a plan. It is a surprise document. 🎁

At minimum, maintain an offline recovery package containing:

| Item | What to record |
|---|---|
| Forest and domain | DNS name, NetBIOS name, forest/domain functional levels |
| Domain controllers | Hostname, site, IP, OS, DNS/GC roles, backup coverage |
| Preferred recovery DC | Writable DC with current, regularly tested backups |
| FSMO roles | Current owners before the incident |
| DSRM | Valid credentials for the recovery DC |
| Network | Recovery VLAN, firewall rules, DNS, gateway, NTP source |
| Backup | Product, backup ID, timestamp, restore procedure, integrity test |
| SYSVOL | DFSR state and expected GPO count |
| Trusts | External and forest trusts, owners, reset procedure |
| Hybrid identity | Entra Connect servers, staging mode, configuration export, deletion threshold |
| Tier 0 dependencies | AD CS, AD FS, MIM, gMSA, PAM, backup agents, security tooling |

Also keep:

- A current export of the Microsoft Entra Connect configuration.
- Copies of critical GPO backups.
- Break-glass credentials stored outside the forest.
- Installation media, drivers, backup agents, and required licenses.
- A tested method to prevent old DCs from booting or reaching the network.

> 💡 A backup is only trusted after a restore test. A green check mark in a backup console proves that a job completed — not that the forest can be recovered from it.

---

## 3 — Phase 0: Stop the Bleeding

### 3.1 Declare the recovery point

Before touching a DC, record:

- Why a forest recovery is required.
- The selected backup timestamp.
- What data will be lost between the backup and the incident.
- Which DC is the recovery source.
- Who is authorized to approve each irreversible step.

If the failure might be malicious, the backup must predate the earliest known compromise — not merely the final outage.

> 🔴 **Do not restore malware, persistence, or stolen Tier 0 secrets into a clean network.** A compromise-driven recovery needs incident-response evidence, credential rotation, gMSA review, certificate review, and potentially a broader rebuild strategy.

### 3.2 Isolate all old DCs

Shut down or network-isolate every DC. Then prevent them from returning accidentally:

- Disconnect virtual NICs.
- Quarantine hypervisor port groups.
- Block recovery VLAN access at the firewall.
- Disable automated VM restart and failover.
- Stop backup or orchestration jobs that might boot an old replica.

Only the selected recovery DC is allowed into the recovery network.

> 🔴 Once the recovered DC's machine password is reset and the old DC metadata is removed, an old DC must **never** reconnect. Label the old VMs clearly and keep them offline only for forensic or rollback purposes.

### 3.3 Freeze directory synchronization

If Microsoft Entra Connect is still reachable, stop scheduled synchronization before rolling AD back:

```powershell
Import-Module ADSync

Set-ADSyncScheduler -SyncCycleEnabled $false
Get-ADSyncScheduler |
    Select-Object SyncCycleEnabled, StagingModeEnabled
```

Also stop or isolate other systems that write to AD:

- Identity lifecycle and HR provisioning.
- MIM synchronization.
- Password-writeback services.
- Privileged-access workflows.
- Automated account and group management.

🟢 **Checkpoint:** one recovery DC selected, all other DCs isolated, recovery point approved, and automated directory writers stopped.

---

## 4 — Phase 1: Restore the First Writable DC

### 4.1 Use an AD-aware restore

Restore the chosen DC by using one of the methods supported by the backup product and the DC platform:

1. Full-server recovery with an authoritative SYSVOL restore.
2. Full-server recovery followed by a System State restore.
3. A supported virtual-DC restore that correctly handles the VM-Generation ID.

The AD DS database restore is **nonauthoritative**. SYSVOL on this first recovered DC is **authoritative**.

> 🟡 **Do not copy `ntds.dit` from a backup and boot it manually.** AD-aware restore processing handles database identity, invocation IDs, update sequence numbers, and other state that a file copy does not.

> 🟡 **IFM is not the first-DC recovery mechanism.** Install From Media requires a healthy writable DC as its source. It becomes useful later, when redeploying additional DCs from the recovered environment.

Keep the DC isolated after it boots. Log on with DSRM or restored domain credentials as required by the backup procedure.

### 4.2 Validate the restored data before changing it

Check the obvious things first:

```powershell
Get-Service NTDS, DNS, Netlogon, DFSR |
    Format-Table Name, Status, StartType

Get-ADDomain
Get-ADForest
Get-ADDomainController -Identity $env:COMPUTERNAME

net share
```

Inspect several known objects, organizational units, groups, and GPOs. Confirm that the database represents the selected recovery point.

If the restored data is damaged or already contains the incident, stop and select an earlier trusted backup.

### 4.3 Work around initial synchronization only if required

A restored FSMO holder can wait indefinitely for replication partners that no longer exist. If AD DS does not advertise because initial synchronization cannot complete, Microsoft documents this temporary setting:

```powershell
$ntdsParameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

New-ItemProperty -Path $ntdsParameters `
    -Name 'Repl Perform Initial Synchronizations' `
    -PropertyType DWord `
    -Value 0 `
    -Force
```

Restart AD DS or the server if the recovery procedure requires it.

> 🔵 Record this change. Set it back to `1` after the forest is stable so normal initial-synchronization safeguards return.

---

## 5 — Phase 2: Make SYSVOL Authoritative

The first recovered DC owns the copy of SYSVOL that every new DC will trust.

If the System State restore was performed with `wbadmin -authsysvol`, the backup application might already have completed this step. Verify with the backup documentation before changing anything manually.

For a DFSR-replicated SYSVOL, the authoritative flag is `msDFSR-Options = 1` on the recovered DC's `SYSVOL Subscription` object:

```powershell
Import-Module ActiveDirectory

$domainDn = (Get-ADDomain).DistinguishedName
$dcName   = $env:COMPUTERNAME
$sysvolSubscription = @(
    "CN=SYSVOL Subscription"
    "CN=Domain System Volume"
    "CN=DFSR-LocalSettings"
    "CN=$dcName"
    "OU=Domain Controllers"
    $domainDn
) -join ','

Get-ADObject -Identity $sysvolSubscription `
    -Properties msDFSR-Options

Set-ADObject -Identity $sysvolSubscription `
    -Replace @{'msDFSR-Options' = 1}

Restart-Service DFSR -PassThru
```

Look for DFS Replication event `4602`, then confirm both shares exist:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'DFS Replication'
    Id      = 4602
} -MaxEvents 5 |
    Format-Table TimeCreated, Id, LevelDisplayName

net share SYSVOL
net share NETLOGON
```

🟢 **Checkpoint:** event `4602` is present and `SYSVOL` plus `NETLOGON` are shared.

> 🔴 Never mark two independent SYSVOL copies authoritative. There must be one source of truth.

---

## 6 — Phase 3: Reclaim the Domain

### 6.1 Recover the built-in Administrator account

The built-in domain Administrator account ends with RID `500`, even if it was renamed:

```powershell
$domainSid = (Get-ADDomain).DomainSID.Value
$rid500Sid = [System.Security.Principal.SecurityIdentifier]::new(
    "$domainSid-500"
)

$rid500 = Get-ADUser -Identity $rid500Sid -Properties Enabled
$rid500 | Format-List SamAccountName, Enabled, DistinguishedName
```

Confirm that the account is enabled, controlled, and usable. In the forest root domain, it must be able to exercise Domain Admins, Enterprise Admins, and Schema Admins privileges during recovery.

If the incident involves compromise, reset all privileged credentials according to the incident-response plan — not only RID-500.

### 6.2 Seize all FSMO roles

The previous role holders are not coming back. Seize all five roles on the recovered DC:

```powershell
Move-ADDirectoryServerOperationMasterRole `
    -Identity $env:COMPUTERNAME `
    -OperationMasterRole SchemaMaster,
                         DomainNamingMaster,
                         PDCEmulator,
                         RIDMaster,
                         InfrastructureMaster `
    -Force

netdom query fsmo
```

In a single-domain forest, the Infrastructure Master can safely run on a Global Catalog. The classic separation concern applies to multidomain forests.

🟢 **Checkpoint:** all five roles point to the recovered DC.

### 6.3 Remove every other DC from the recovered directory

Inventory what the restored database still knows:

```powershell
Get-ADDomainController -Filter * |
    Sort-Object HostName |
    Format-Table HostName, Site, IPv4Address, IsGlobalCatalog

repadmin /viewlist *
nltest /dclist:$env:USERDNSDOMAIN
```

Now clean the metadata of **every DC except the recovered one**.

The safest visual method is Active Directory Users and Computers:

1. Open the **Domain Controllers** OU.
2. Delete an old DC computer object.
3. Select **This Domain Controller is permanently offline and can no longer be demoted**.
4. Confirm the deletion, including the Global Catalog prompt if displayed.
5. Repeat for every old DC.

Modern ADUC performs the associated metadata cleanup automatically. `ntdsutil` remains available when GUI cleanup cannot complete:

```text
ntdsutil
metadata cleanup
remove selected server <OldDCName>
quit
quit
```

Then verify:

```powershell
repadmin /viewlist *
nltest /dclist:$env:USERDNSDOMAIN
```

Only the recovered DC should remain.

> 🔴 Read the list twice before deleting anything. Metadata cleanup is the point at which the other DCs stop being replicas and become machines that must be rebuilt.

### 6.4 Clean DNS

The recovered DC must host or reach a working copy of the AD-integrated DNS zones. In the usual single-domain design, configure its preferred DNS server to its own production IP.

Check the zones:

```powershell
Get-DnsServerZone |
    Format-Table ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone

Resolve-DnsName $env:USERDNSDOMAIN
Resolve-DnsName "_ldap._tcp.dc._msdcs.$env:USERDNSDOMAIN" `
    -Type SRV
```

Remove stale references to deleted DCs from:

- Host A/AAAA records.
- `_msdcs` GUID CNAME records.
- LDAP, Kerberos, GC, and site-specific SRV records.
- Zone NS records.
- Reverse PTR records.

Force the recovered DC to register its own records again:

```powershell
ipconfig /registerdns
Restart-Service Netlogon

dcdiag /test:dns /v
```

### 6.5 Check DNS application-partition role owners

Metadata cleanup can leave the Infrastructure role owner of `DomainDNSZones` or `ForestDNSZones` pointing to a deleted NTDS Settings object.

Inspect both values:

```powershell
$domainDn = (Get-ADDomain).DistinguishedName
$rootDn   = (Get-ADForest).RootDomain |
    ForEach-Object { (Get-ADDomain $_).DistinguishedName }

$dnsInfrastructureObjects = @(
    "CN=Infrastructure,DC=DomainDNSZones,$domainDn"
    "CN=Infrastructure,DC=ForestDNSZones,$rootDn"
)

$dnsInfrastructureObjects | ForEach-Object {
    Get-ADObject -Identity $_ -Properties fSMORoleOwner
} | Format-Table DistinguishedName, fSMORoleOwner -Wrap
```

If a value contains `\0ADEL:`, the owner is a deleted object. Repair it using a reviewed procedure that assigns `fSMORoleOwner` to the recovered DC's current `dsServiceName`.

> 🟡 This is a low-level directory modification. Do not rewrite a healthy value just because the step exists in the runbook.

---

## 7 — Phase 4: Prevent SID Reuse

Imagine that RID `12042` belonged to a privileged user created after the selected backup. The restored database no longer contains that user, but an ACL somewhere might still contain the old SID. If AD reissues RID `12042`, a completely different account could inherit those permissions.

That is why forest recovery handles **both** RID levels:

1. Move the domain-wide allocation point forward.
2. Discard the restored DC's local pool.

### 7.1 Raise the domain RID pool

First, capture the current value and add the approved safety margin. Microsoft uses `100,000` in its forest recovery example:

```powershell
$domainDn  = (Get-ADDomain).DistinguishedName
$ridDn     = "CN=RID Manager$,CN=System,$domainDn"
$ridObject = Get-ADObject -Identity $ridDn `
    -Properties rIDAvailablePool

$oldRidPool = [Int64]$ridObject.rIDAvailablePool
$newRidPool = $oldRidPool + 100000

[pscustomobject]@{
    OldValue = $oldRidPool
    NewValue = $newRidPool
    Increase = 100000
}
```

Review the values, record them in the recovery log, then apply:

```powershell
Set-ADObject -Identity $ridDn `
    -Replace @{rIDAvailablePool = $newRidPool}

Get-ADObject -Identity $ridDn `
    -Properties rIDAvailablePool |
    Select-Object DistinguishedName, rIDAvailablePool
```

> 🟡 RIDs are finite. `100,000` is a common recovery margin, not a magic universal number. Large environments should calculate the lowest safe increase from their actual RID consumption since the backup.

### 7.2 Invalidate the restored DC's local RID pool

```powershell
$domain   = New-Object System.DirectoryServices.DirectoryEntry
$domainSid = $domain.objectSid
$rootDse  = New-Object System.DirectoryServices.DirectoryEntry(
    'LDAP://RootDSE'
)

$rootDse.UsePropertyCache = $false
$rootDse.Put('invalidateRidPool', $domainSid.Value)
$rootDse.SetInfo()
```

On supported versions, Directory-Services-SAM event `16654` confirms invalidation:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Directory-Services-SAM'
    Id           = 16654
} -MaxEvents 5
```

The first attempt to create a security principal is expected to fail because it triggers allocation of a fresh RID pool. Retry once:

```powershell
New-ADGroup -Name 'RID-Recovery-Test' `
    -SamAccountName 'RID-Recovery-Test' `
    -GroupCategory Security `
    -GroupScope Global
```

If the first attempt fails, run the same command again. Then validate and remove the test group:

```powershell
dcdiag /test:ridmanager /v

Get-ADGroup 'RID-Recovery-Test' |
    Remove-ADGroup -Confirm:$false
```

🟢 **Checkpoint:** the RID Manager test passes and a new security principal receives a SID above the abandoned range.

---

## 8 — Phase 5: Break Trust with the Old World

### 8.1 Reset the recovered DC's machine password twice

Run this **only on the sole recovered DC**:

```powershell
Reset-ComputerMachinePassword
Reset-ComputerMachinePassword
```

This moves the machine-account secret through its two-value history and prevents pre-recovery DCs from authenticating replication with the recovered DC.

> 🔴 This intentionally breaks replication with the old DC population. Never run it casually across a healthy forest.

### 8.2 Reset `krbtgt` twice — slowly

The `krbtgt` account also retains two password values. Two resets remove the pre-recovery key material, but they must not be back-to-back.

First reset:

```powershell
$firstPassword = Read-Host `
    'Enter a temporary complex value for the first krbtgt reset' `
    -AsSecureString

Set-ADAccountPassword -Identity 'krbtgt' `
    -Reset `
    -NewPassword $firstPassword

Remove-Variable firstPassword
Get-ADUser krbtgt -Properties PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet
```

Wait longer than the effective maximum Kerberos user/service ticket lifetime — **10 hours by default**. This allows tickets signed with the previous key to age out.

Then perform the second reset with a different temporary value:

```powershell
$secondPassword = Read-Host `
    'Enter a different temporary value for the second krbtgt reset' `
    -AsSecureString

Set-ADAccountPassword -Identity 'krbtgt' `
    -Reset `
    -NewPassword $secondPassword

Remove-Variable secondPassword
Get-ADUser krbtgt -Properties PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet
```

> 🔵 The value entered is not used as a normal service password: AD generates the effective `krbtgt` key material. What matters here is executing two distinct reset operations with the required delay.

If the forest has RODCs, their `krbtgt_<number>` accounts need a dedicated recovery plan. Do not delete them blindly.

### 8.3 Rotate everything else required by the incident

For a security incident, `krbtgt` is only one item in a much larger rotation plan:

- Privileged user and service accounts.
- gMSA/KDS-related exposure.
- External and forest trust passwords.
- DSRM credentials.
- Backup and hypervisor credentials.
- AD FS service and certificate material.
- AD CS keys and enrollment-agent credentials.
- Application secrets stored in AD or SYSVOL.

The exact scope comes from the incident, not from a generic checklist.

---

## 9 — Phase 6: Restore Time and Global Catalog Services

### 9.1 Configure the PDC Emulator as authoritative time source

The recovered DC now owns the PDC Emulator role. Point it to the organization's approved external NTP peers:

```powershell
w32tm /config `
    /manualpeerlist:"<NTP1>,0x8 <NTP2>,0x8" `
    /syncfromflags:manual `
    /reliable:yes `
    /update

Restart-Service W32Time
w32tm /resync /rediscover
w32tm /query /status
w32tm /query /peers
```

Kerberos tolerates only limited clock skew. Do not postpone time validation until users report authentication failures.

### 9.2 Keep the Global Catalog in a single-domain forest

In a multidomain recovery, Microsoft recommends temporarily removing GC from restored DCs to avoid lingering partial replicas from differently aged domain backups.

That issue does not apply here: there is only one domain. Keep or enable GC on the recovered DC:

```powershell
Get-ADDomainController -Identity $env:COMPUTERNAME |
    Select-Object HostName, IsGlobalCatalog

repadmin /options $env:COMPUTERNAME +IS_GC
```

Directory Service event `1119` confirms GC promotion:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Directory Service'
    Id      = 1119
} -MaxEvents 5
```

---

## 10 — Phase 7: Validate the Recovered Domain

Do not reconnect production because *"ADUC opens"*. That is a very low bar. 😄

### 10.1 Core validation

```powershell
dcdiag /v
dcdiag /test:dns /v
dcdiag /test:ridmanager /v

repadmin /viewlist *
repadmin /replsum

netdom query fsmo
nltest /dclist:$env:USERDNSDOMAIN
```

Expected state:

| Check | Expected result |
|---|---|
| DC inventory | Only the recovered DC exists |
| FSMO | All five roles are on the recovered DC |
| DNS | Domain and `_msdcs` zones load; SRV records resolve |
| SYSVOL | `SYSVOL` and `NETLOGON` are shared |
| DFSR | Event `4602`; no blocking DFSR errors |
| RID | `dcdiag /test:ridmanager` passes |
| GC | The recovered DC is a Global Catalog |
| Time | PDC synchronizes with approved external peers |
| Kerberos | Fresh interactive logon and service-ticket acquisition work |

### 10.2 Test SYSVOL and Group Policy

```powershell
$domain = Get-ADDomain
$sysvol = "\\$($domain.DNSRoot)\SYSVOL"
$netlogon = "\\$($domain.DNSRoot)\NETLOGON"

Test-Path $sysvol
Test-Path $netlogon

Get-GPO -All |
    Select-Object DisplayName, Id, GpoStatus |
    Sort-Object DisplayName
```

Use a controlled test workstation later to validate computer policy, user policy, logon scripts, and access to a representative business service.

### 10.3 Undo the temporary initial-sync bypass

If `Repl Perform Initial Synchronizations` was set to `0`, restore the normal behavior:

```powershell
$ntdsParameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

Set-ItemProperty -Path $ntdsParameters `
    -Name 'Repl Perform Initial Synchronizations' `
    -Value 1
```

### 10.4 Create the first post-recovery backup

Once every checkpoint passes, take a new full-server/System State backup of the recovered DC.

> 🟢 **Major checkpoint:** this backup is the first clean recovery baseline. Do not begin mass redeployment before it completes successfully.

---

## 11 — Phase 8: Redeploy Additional Domain Controllers

The old replica databases cannot be reused after their metadata has been removed. Build clean servers and promote them into the recovered domain.

On each new server:

1. Configure a static IP.
2. Point preferred DNS to the recovered DC.
3. Join the domain.
4. Install AD DS and DNS.
5. Promote it as an additional DC.

```powershell
Install-WindowsFeature AD-Domain-Services `
    -IncludeManagementTools

Install-ADDSDomainController `
    -DomainName $env:USERDNSDOMAIN `
    -InstallDNS `
    -Credential (Get-Credential) `
    -Force
```

After reboot:

```powershell
repadmin /showrepl
repadmin /replsum
dcdiag /v

Get-Service NTDS, DNS, Netlogon, DFSR |
    Format-Table Name, Status, StartType

net share
```

Confirm that the new DC:

- Receives every directory partition.
- Registers correct DNS records.
- Receives SYSVOL nonauthoritatively from the recovered DC.
- Advertises as a DC and, if required, as a GC.
- Passes authentication and Group Policy tests.

### Where IFM finally makes sense

For large databases or slow links, create IFM from the **trusted recovered environment** and use it to reduce initial replication traffic:

```text
ntdsutil
activate instance ntds
ifm
create full C:\IFM
quit
quit
```

Use that media only to promote additional DCs. It does not replace replication, and it was not the backup used to recover the first DC.

> 💡 Restore service strategically: deploy DCs first where critical applications and major user populations need them. Branch-office redundancy can follow after core services are stable.

---

## 12 — Phase 9: Reconnect Production Carefully

Reconnect the recovered environment in controlled stages:

1. Core network, DNS, and NTP.
2. Tier 0 administration workstations and tooling.
3. Critical servers and service accounts.
4. Representative user workstations.
5. Broader sites and workloads.
6. Hybrid identity and provisioning systems last.

At each stage, monitor:

- Directory Service, DNS Server, DFS Replication, System, and Security logs.
- Authentication failures and Kerberos errors.
- DNS registration and DC Locator behavior.
- Unexpected account, group, or ACL changes.
- Replication health between the newly built DCs.

Do not reintroduce an old DC to *"see if it works"*. It belongs to a topology that no longer exists.

---

## 13 — Microsoft Entra Connect: Do Not Press Export Yet

Rolling AD back creates a simple but dangerous picture:

```text
Before incident:  10,000 synchronized objects
Restored backup:   9,700 synchronized objects
Difference:          300 objects that Entra Connect may interpret as deleted
```

Those 300 objects might still exist in Microsoft Entra ID. Blindly enabling exports can turn a recoverable data gap into a cloud deletion event.

### Safe reintroduction pattern

1. Keep the scheduler disabled or place the server in staging mode.
2. Verify the Entra Connect configuration and OU filtering.
3. Ensure accidental-deletion protection is enabled with an appropriate threshold.
4. Run full imports and synchronization **without exports**.
5. Export the pending connector-space changes to a file and review every add, update, and delete.
6. Recover missing on-premises objects if required.
7. Permit exports only after the delta is understood and approved.

```powershell
Import-Module ADSync

Get-ADSyncScheduler |
    Select-Object SyncCycleEnabled, StagingModeEnabled

Get-ADSyncExportDeletionThreshold
```

> 🔴 A successful sync engine run does not mean the proposed changes are correct. During recovery, the pending export is the evidence that matters.

### Can the metaverse help recover post-backup objects?

Sometimes, yes.

The Entra Connect metaverse can retain useful information about users and groups that were synchronized after the selected AD backup. This can help reconstruct:

- User and group identities.
- Selected synchronized attributes.
- Group memberships.
- Source anchors used to reconnect on-premises and cloud objects.

There are two big caveats:

1. The metaverse is **not an Active Directory backup**.
2. Only imported attributes are available. If an attribute was never projected into the metaverse, it cannot be recovered from there.

For example, `groupType` is not present in every default metaverse design. Adding and flowing it before a disaster preserves whether a group was security/distribution and global/domain-local/universal, making accurate reconstruction much easier.

That subject deserves its own runbook. Keep metaverse recovery as a separate, tested procedure rather than improvising SQL queries during the forest outage.

---

## 14 — Optional Object and Attribute Recovery

Forest recovery returns the directory to the backup timestamp. Objects created or modified later require a separate data-recovery decision.

### Deleted objects still in the Recycle Bin

```powershell
Get-ADObject -Filter * `
    -IncludeDeletedObjects `
    -Properties whenChanged, lastKnownParent |
    Where-Object IsDeleted |
    Select-Object Name, ObjectClass, whenChanged, lastKnownParent
```

Restore only reviewed objects:

```powershell
Get-ADObject -Identity '<DeletedObjectGUID>' `
    -IncludeDeletedObjects |
    Restore-ADObject
```

### Compare attributes with a mounted snapshot

`ntdsutil snapshot` plus `dsamain` can expose an AD snapshot on a nonstandard LDAP port. That is useful for comparing selected attributes with the live recovered directory.

Treat the snapshot as a **read-only reference**. Export differences, review them, then apply only approved attributes to live objects.

> 🟡 Do not bulk-copy every attribute. System-managed, linked, constructed, security, and identity attributes require different handling.

### Authoritative object restore

Use `ntdsutil` authoritative restore only when the Recycle Bin and safer reconstruction methods cannot meet the requirement. It changes object versioning so restored data wins replication and must be planned separately from the initial forest recovery.

---

## 15 — Common Mistakes That Ruin a Forest Recovery

| Mistake | Why it hurts |
|---|---|
| Connecting the restored DC to production too early | Old DCs or automated writers can contaminate the recovered state |
| Restoring several DCs independently | Creates competing databases and SYSVOL sources |
| Treating IFM as a backup | IFM needs a healthy source and is designed for additional-DC promotion |
| Forgetting authoritative SYSVOL | GPOs and scripts might never become available to rebuilt DCs |
| Keeping old DC metadata | KCC, DNS, FSMO, and RID allocation continue referencing dead replicas |
| Skipping the RID increase | New principals might reuse SIDs created after the backup |
| Skipping local RID invalidation | The restored DC can continue consuming its old assigned pool |
| Resetting `krbtgt` twice immediately | Existing tickets do not have time to expire safely |
| Removing GC in a single-domain forest | Adds downtime without solving the multidomain lingering-object problem |
| Starting Entra Connect exports immediately | Missing on-premises objects might be deleted or changed in the cloud |
| Booting an old DC after cleanup | Reintroduces a replica whose metadata and secrets are no longer valid |

---

## 16 — Final Recovery Checklist

### First recovered DC

- [ ] Recovery point and backup approved.
- [ ] Recovery environment isolated.
- [ ] One writable DC restored with an AD-aware method.
- [ ] Restored directory data inspected.
- [ ] SYSVOL marked authoritative.
- [ ] DFSR event `4602` confirmed.
- [ ] `SYSVOL` and `NETLOGON` shared.

### Domain ownership

- [ ] RID-500 account controlled and tested.
- [ ] All five FSMO roles seized.
- [ ] All other writable DC metadata removed.
- [ ] Stale DNS records removed.
- [ ] DNS application-partition owners valid.
- [ ] RID pool raised and local pool invalidated.
- [ ] Restored DC machine password reset twice.
- [ ] `krbtgt` reset twice with the correct delay.
- [ ] Incident-specific secrets rotated.

### Service validation

- [ ] PDC Emulator synchronizes with approved NTP peers.
- [ ] Global Catalog available.
- [ ] `dcdiag` passes expected tests.
- [ ] DNS and DC Locator tests pass.
- [ ] New security principal receives a safe RID.
- [ ] Fresh Kerberos logon works.
- [ ] GPO and logon-script tests pass.
- [ ] Temporary initial-sync bypass removed.
- [ ] New post-recovery backup completed.

### Redeployment

- [ ] Additional DCs built from clean operating systems.
- [ ] AD DS, DNS, SYSVOL, and GC replication validated.
- [ ] Old DCs permanently prevented from reconnecting.
- [ ] Production connectivity restored in controlled stages.
- [ ] Entra Connect pending exports reviewed before activation.
- [ ] Tier 0 and business application owners completed their tests.

---

## 17 — What Changes in a Multidomain Forest?

The recovery principles stay the same, but a multidomain forest adds three moving parts: **one recovery DC per domain, the domain trust hierarchy, and Global Catalog partial replicas**.

Consider this forest:

```text
contoso.com
├── emea.contoso.com
└── amer.contoso.com
```

Instead of restoring a single DC, recover one trusted writable DC from each domain — always starting with the forest root:

```text
Restore contoso.com
    ↓
Restore emea.contoso.com and amer.contoso.com
    ↓
Reconnect the recovered DCs on an isolated network
    ↓
Repair DNS, trusts, and cross-domain replication
    ↓
Re-enable Global Catalog services
    ↓
Rebuild the remaining DCs in every domain
```

The main differences are:

| Area | Multidomain consideration |
|---|---|
| Recovery order | Recover the forest root before any child domain to preserve DNS and the trust hierarchy |
| Restored DCs | Restore one writable DC from backup in **each** domain |
| FSMO roles | Seize the two forest-wide roles in the root; seize the three domain-wide roles in every domain |
| SYSVOL | Select one authoritative SYSVOL copy independently for each domain |
| RID and `krbtgt` | Raise/invalidate RID pools and reset `krbtgt` separately in every domain |
| Metadata cleanup | Remove non-restored DCs from every domain and from the forest-wide Configuration partition |
| DNS | Restore child-domain delegations, `_msdcs`, application partitions, and cross-domain name resolution |
| Trusts | Validate and, if required, repair parent/child and external trust passwords |
| Replication | Reconnect one recovered DC per domain on a common isolated network and validate all forest partitions |
| Global Catalog | Temporarily remove GC from restored DCs when backup ages differ, then re-enable it after every domain is healthy |

> 🔴 **The Global Catalog is the big difference.** A GC restored from a newer backup can contain partial objects from another domain restored from an older backup. Keeping GC disabled until the domains agree helps prevent lingering objects from entering the recovered forest.

> 🔵 A multidomain recovery deserves its own tested runbook. Do not take this single-domain procedure, wrap it in a `foreach` loop, and hope the trust hierarchy sorts itself out. It will not appreciate the optimism. 😅

---

## Conclusion

A single-domain forest recovery is simpler than a multidomain recovery, but it is not casual work. The sequence matters:

```text
Isolate → Restore one DC → Authorize SYSVOL → Seize FSMO
        → Remove old DCs → Protect RID/Kerberos
        → Validate → Back up → Rebuild → Reconnect
```

The first recovered DC is not just another replica. For a while, it **is the forest**.

Treat it accordingly: one trusted source, no shortcuts, checkpoints after every destructive step, and no old DC returning from the grave. 🧟‍♂️

---

## References

- [Active Directory Forest Recovery Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide)
- [Perform initial recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-initial-recovery)
- [Perform an authoritative synchronization of DFSR-replicated SYSVOL](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-authoritative-recovery-sysvol)
- [Clean metadata of removed writable domain controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-cleaning-metadata-of-removed-dcs)
- [Raise the value of available RID pools](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-raise-rid-pool)
- [Invalidate the current RID pool](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-invaildate-rid-pool)
- [Reset the computer account password of the recovered DC](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-computer-account-dc)
- [Reset the `krbtgt` password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [Redeploy remaining domain controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-restore-additional-dcs)
- [Microsoft Entra Connect Sync operational tasks and staging mode](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-staging-server)
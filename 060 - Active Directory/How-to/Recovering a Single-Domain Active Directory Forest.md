# Recovering a Single-Domain Active Directory Forest — A Practical Step-by-Step Runbook
🗓️ Published: 2026-09-02

## Introduction

This runbook covers **one forest, one domain, and DFSR-replicated SYSVOL**. The method is:

1. Restore **one writable DC** from a trusted Windows Server Backup.
2. Make its SYSVOL the authoritative copy.
3. Remove the old replication topology and validate the recovered domain.
4. Build **new servers** and promote them as additional DCs.

The AD DS restore is **nonauthoritative**; SYSVOL on the first recovered DC is **authoritative**. The new DCs receive AD and SYSVOL by replication. This is not an authoritative object restore into a forest whose other DCs remain online.

> 🔴 Never reconnect the old DC databases to the recovered environment. A multidomain forest, RODCs, legacy FRS, and recovery of dependent systems such as AD CS or AD FS require separate procedures.

### How to use this runbook

- Follow the numbered steps in order. Read the explanation, run the command block, then check the result.
- Unless another machine is named, run commands **on the restored DC**, in an **elevated Windows PowerShell 5.1 session**, in **normal startup mode**. DSRM is not used for these AD-management commands.
- After a reboot or a new console logon, reopen PowerShell and re-create any variables used by the next block.
- Stop at a failed checkpoint. Do not paste all blocks into one unattended script.
- A Web console is sufficient. With no clipboard or network transfer, stage the runbook and command files on an offline disk or ISO before the session.

## 1 — Prepare the Recovery

For this runbook, select a trusted backup of a **writable DC that hosts DNS**. Prefer a DC that is also a Global Catalog.

Have the following information and files available offline:

| Item | What to record |
|---|---|
| Forest and domain | DNS name, NetBIOS name, forest/domain functional levels |
| Domain controllers | Hostname, site, IP, OS, DNS/GC roles, backup coverage |
| Preferred recovery DC | Writable DC with current, regularly tested backups |
| FSMO roles | Current owners before the incident |
| Domain administrator | RID-500 account name and password valid at the backup date; another usable domain administrator if RID-500 was disabled |
| DSRM | Separate local DSRM administrator password valid at the backup date, for offline troubleshooting |
| Network | Recovery VLAN, firewall rules, DNS, gateway, NTP source |
| Backup | Full-server/Bare Metal recovery backup, source DC, version ID, timestamp, and accessible backup media |
| SYSVOL | DFSR state and expected GPO count |
| Trusts | External and forest trusts, owners, reset procedure |
| Hybrid identity | Entra Connect servers, staging mode, configuration export, deletion threshold |
| Tier 0 dependencies | AD CS, AD FS, MIM, gMSA, PAM, backup agents, security tooling |

Prepare a target VM or physical server with the same firmware boot mode as the source, the required disks, and disk sizes at least as large as those in the backup. Keep the backup disk separate from the disks to be restored. Have storage/network drivers and BitLocker recovery keys available if required.

Prepare the **installation ISO matching the Windows Server version of the backed-up DC**. Bare Metal Recovery restores the backed-up OS; it does not upgrade Windows Server. No OS needs to be preinstalled on the target.

Before the session, verify the backup catalog on the source DC or a prepared Windows Server Backup host. Replace both values:

```powershell
$backupTarget = 'E:'
$sourceDc = '<SOURCE_DC_NAME>'

wbadmin get versions "-backupTarget:$backupTarget" "-machine:$sourceDc"

if ($LASTEXITCODE -ne 0) {
    throw "Unable to read the source backup catalog. wbadmin exit code: $LASTEXITCODE"
}
```

🟢 **Checkpoint:** the selected version belongs to the expected DC and supports Bare Metal Recovery. Record its timestamp and version ID. An isolated System State backup alone is not the input for this runbook.

---

## 2 — Isolate the Recovery Environment

### 2.1 Select the recovery point

Before touching a DC, record:

- Why a forest recovery is required.
- The selected backup timestamp.
- What data will be lost between the backup and the incident.
- Which DC is the recovery source.
- Who is authorized to approve each irreversible step.

If the failure might be malicious, the backup must predate the earliest known compromise — not merely the final outage.

> 🔴 **Do not restore malware, persistence, or stolen Tier 0 secrets into a clean network.** A compromise-driven recovery needs incident-response evidence, credential rotation, gMSA review, certificate review, and potentially a broader rebuild strategy.

### 2.2 Prevent contact with old DCs

**For a rehearsal:** leave production running. Put the restored VM and future test DCs on a separate network with no route to production DCs, production clients, or cloud synchronization services.

**For a real disaster:** shut down or network-isolate every old DC and prevent automatic restart or reconnection:

- Disconnect virtual NICs.
- Quarantine hypervisor port groups.
- Block recovery VLAN access at the firewall.
- Disable automated VM restart and failover.
- Stop backup or orchestration jobs that might boot an old replica.

Initially, only the selected recovery DC and the approved backup/NTP hosts are allowed into the recovery network. New DCs and test clients are added later.

> 🔴 Once the recovered DC's machine password is reset and the old DC metadata is removed, an old DC must **never** reconnect. Label the old VMs clearly and keep them offline only for forensic or rollback purposes.

### 2.3 Keep directory writers away

For a rehearsal, do not stop production synchronization: keep the recovered environment unreachable from it.

For a real recovery, stop scheduled synchronization **on the Entra Connect server**, not on the DC:

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

🟢 **Checkpoint:** recovery point approved; the recovered directory cannot communicate with old DCs, production clients, or automated directory writers.

---

## 3 — Restore the First DC with Windows Server Backup

### 3.1 Restore the full server

Use the Web or physical console of the **target server**:

1. Attach the installation ISO matching the backed-up Windows Server version.
2. Make the backup accessible through a separate disk or an approved share on the isolated network.
3. Boot from the ISO. Select the language and keyboard, then **Next**.
4. Select **Repair your computer**, not **Install now**.
5. Select **Troubleshoot** → **System Image Recovery**.
6. Select the detected Windows Server installation if prompted.
7. Select **Select a system image** and choose the approved backup version. Do not accept the latest image without checking its source and timestamp.
8. If the image is on a share, use **Advanced** → **Search for a system image on the network**. Supply the isolated share path and credentials. Load drivers if disks or the network adapter are not visible.
9. Review the target disks. **Format and repartition disks** overwrites the selected target disks: exclude the disk containing the backup and check the mapping before confirming.
10. Start recovery and wait for it to finish. Disconnect the installation ISO before rebooting from the restored system disk.

The recovered machine keeps the backed-up DC's name, OS, directory database, and system configuration. Keep it isolated after reboot.

> 🟡 **Do not copy `ntds.dit` from a backup and boot it manually.** AD-aware restore processing handles database identity, invocation IDs, update sequence numbers, and other state that a file copy does not.

🟢 **Checkpoint:** the full-server recovery completes and the backed-up OS boots. If recovery fails, stop here; do not compensate by manually copying directory files.

### 3.2 Log on and check the network

**DSRM is not a mandatory step in this full-server recovery.** Use the accounts as follows:

| Moment | Account and mode |
|---|---|
| Boot from the ISO and restore the server image | No DSRM logon. If the backup is on a share, use that share's access credentials |
| First normal boot after recovery | The **domain RID-500 administrator**, using its actual account name and password valid at the backup date |
| SYSVOL, FSMO, metadata cleanup, RID allocation, and account resets | A domain administrator in **normal startup mode**, with elevated PowerShell |
| Offline troubleshooting in DSRM, only if needed | The **local DSRM administrator** and its separate password. AD DS is stopped; do not run AD-management cmdlets |

If you entered DSRM, exit that startup mode and reboot normally before logging on as `DOMAIN\<RID500AccountName>` and continuing this runbook. The DSRM account is not the domain RID-500 account, even if both are named Administrator.

If RID-500 was disabled in the backup or its password is unknown, use another restored domain administrator to log on and enable/reset it in step 5.1. **DSRM credentials cannot replace domain credentials for these commands.** If no usable domain administrator is available, stop and resolve access before continuing.

Check the restored IP configuration:

```powershell
Get-NetIPConfiguration
Get-DnsClientServerAddress -AddressFamily IPv4
```

Keep the intended static DC IP on the isolated network. Configure preferred DNS to this DC's own IP, not an old production DC. Use the adapter's IPv4 properties if the restored settings need changing.

### 3.3 Check services and the restored directory

```powershell
Get-Service NTDS, ADWS, DNS, Netlogon, DFSR |
    Format-Table Name, Status, StartType

Import-Module ActiveDirectory

Get-ADDomain -Server $env:COMPUTERNAME
Get-ADForest -Server $env:COMPUTERNAME
Get-ADDomainController -Identity $env:COMPUTERNAME `
    -Server $env:COMPUTERNAME

net share
```

Inspect known users, organizational units, groups, and GPOs. Confirm that the data represents the selected recovery point and that the forest contains only one domain. SYSVOL shares may still be missing until step 4.

If the restored data is damaged or already contains the incident, stop and select an earlier trusted backup.

### 3.4 Only if initial synchronization blocks AD DS

A restored FSMO holder can wait indefinitely for replication partners that no longer exist. If AD DS does not advertise because initial synchronization cannot complete, Microsoft documents this temporary setting:

```powershell
$ntdsParameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

New-ItemProperty -Path $ntdsParameters `
    -Name 'Repl Perform Initial Synchronizations' `
    -PropertyType DWord `
    -Value 0 `
    -Force `
    -ErrorAction Stop

Restart-Computer
```

After reboot, log on normally, reopen elevated PowerShell, and repeat step 3.3. If AD is still unavailable, inspect the Directory Service log; do not use this setting as a generic fix.

> 🔵 Record this temporary change. Step 9.3 restores the normal value after the old topology has been removed.

🟢 **Checkpoint:** the restored domain is readable, the recovery point is correct, and AD management works against the local DC.

---

## 4 — Make SYSVOL Authoritative

**Why:** SYSVOL contains Group Policy files and logon scripts. The first DC cannot wait for old replication partners; its restored copy must initialize as the source for future DCs.

After the full-server recovery, set `msDFSR-Options = 1` on the recovered DC's `SYSVOL Subscription` object and restart DFSR:

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

$sysvolRecoveryStart = Get-Date

Set-ADObject -Identity $sysvolSubscription `
    -Replace @{'msDFSR-Options' = 1} `
    -ErrorAction Stop

Restart-Service DFSR -PassThru -ErrorAction Stop
```

Wait up to five minutes for a **new** DFS Replication event `4602`, then confirm both shares exist. The restored event log can contain old success events: those do not validate this operation.

```powershell
$deadline = (Get-Date).AddMinutes(5)
$sysvolEvent = $null

Write-Host 'Waiting up to five minutes for a new SYSVOL event 4602...'

do {
    try {
        $sysvolEvent = Get-WinEvent -FilterHashtable @{
            LogName   = 'DFS Replication'
            Id        = 4602
            StartTime = $sysvolRecoveryStart
        } -MaxEvents 1 -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
            throw
        }
    }

    if (-not $sysvolEvent) {
        Start-Sleep -Seconds 5
    }
} while (-not $sysvolEvent -and (Get-Date) -lt $deadline)

if (-not $sysvolEvent) {
    throw 'No new event 4602 within five minutes. Stop and inspect the DFS Replication log.'
}

$sysvolEvent | Format-Table TimeCreated, Id, LevelDisplayName

net share SYSVOL
net share NETLOGON
```

🟢 **Checkpoint:** event `4602` belongs to this authoritative operation, and `SYSVOL` plus `NETLOGON` are shared. A timeout is a stop condition, not a reason to continue.

> 🔴 Never mark two independent SYSVOL copies authoritative. There must be one source of truth.

---

## 5 — Recover Administration and Remove the Old Topology

### 5.1 Check the built-in Administrator account

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

Run the following commands in an **elevated Windows PowerShell session on the isolated, restored DC, in normal startup mode**, using an account with the required domain permissions. AD account-management commands are not run in DSRM.

If RID-500 is disabled, enable it **while logged on as another usable domain administrator**. This cannot be done with `Enable-ADAccount` in DSRM:

```powershell
Enable-ADAccount -Identity $rid500.SID `
    -Server $env:COMPUTERNAME `
    -ErrorAction Stop
```

If its password is unknown or the recovery plan requires a reset, set a new password. Store it in the approved recovery credential vault outside the forest:

```powershell
$adminPassword = Read-Host 'Enter the new RID-500 password' -AsSecureString

try {
    Set-ADAccountPassword -Identity $rid500.SID `
        -Server $env:COMPUTERNAME `
        -Reset `
        -NewPassword $adminPassword `
        -ErrorAction Stop
}
finally {
    $adminPassword.Dispose()
}

Get-ADUser -Identity $rid500.SID `
    -Server $env:COMPUTERNAME `
    -Properties Enabled, PasswordLastSet |
    Select-Object SamAccountName, Enabled, PasswordLastSet
```

🟢 **Checkpoint:** the account is enabled and a fresh console logon with its known password succeeds. Record any reset; do not change a usable password merely because the command is available.

If the incident involves compromise, reset all privileged credentials according to the incident-response plan — not only RID-500.

### 5.2 Seize all five FSMO roles

The previous role holders are not coming back. Seize all five roles on the recovered DC:

```powershell
Move-ADDirectoryServerOperationMasterRole `
    -Identity $env:COMPUTERNAME `
    -OperationMasterRole SchemaMaster,
                         DomainNamingMaster,
                         PDCEmulator,
                         RIDMaster,
                         InfrastructureMaster `
    -Force `
    -ErrorAction Stop

netdom query fsmo
```

All five roles belong on the recovered DC at this stage. In this single-domain forest, it can also remain a Global Catalog.

🟢 **Checkpoint:** all five roles point to the recovered DC.

### 5.3 Remove every other DC's metadata

Inventory what the restored database still knows:

```powershell
Get-ADDomainController -Filter * -Server $env:COMPUTERNAME |
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

Confirm against the local directory:

```powershell
$remainingDcs = @(Get-ADDomainController -Filter * `
    -Server $env:COMPUTERNAME -ErrorAction Stop)

$remainingDcs | Format-Table HostName, Site, IsGlobalCatalog

if ($remainingDcs.Count -ne 1 -or
    $remainingDcs[0].Name -ne $env:COMPUTERNAME) {
    throw 'Metadata cleanup is incomplete. Only the recovered DC may remain.'
}
```

> 🔴 Read the list twice before deleting anything. Metadata cleanup is the point at which the other DCs stop being replicas and become machines that must be rebuilt.

### 5.4 Clean stale DNS records

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

Use DNS Manager on the recovered DC to review these records. Remove only entries for the deleted DCs, not shared application records or the restored DC's own records.

Force the recovered DC to register its own records again:

```powershell
ipconfig /registerdns
Restart-Service Netlogon

dcdiag /test:dns /v
```

### 5.5 Check DNS application-partition role owners

Metadata cleanup can leave the Infrastructure role owner of `DomainDNSZones` or `ForestDNSZones` pointing to a deleted NTDS Settings object.

Inspect both values:

```powershell
$domainDn = (Get-ADDomain -Server $env:COMPUTERNAME).DistinguishedName

$dnsInfrastructureObjects = @(
    "CN=Infrastructure,DC=DomainDNSZones,$domainDn"
    "CN=Infrastructure,DC=ForestDNSZones,$domainDn"
)

$dnsInfrastructure = @($dnsInfrastructureObjects | ForEach-Object {
    Get-ADObject -Identity $_ `
        -Server $env:COMPUTERNAME `
        -Properties fSMORoleOwner `
        -ErrorAction Stop
})

$dnsInfrastructure |
    Format-Table DistinguishedName, fSMORoleOwner -Wrap
```

If a value contains `\0ADEL:`, it references a deleted NTDS Settings object. After reviewing the output, repair **only those deleted owners**:

```powershell
$localNtdsDn = (Get-ADRootDSE -Server $env:COMPUTERNAME `
    -Properties dsServiceName -ErrorAction Stop).dsServiceName

if (-not $localNtdsDn) {
    throw 'The restored DC did not return its NTDS Settings distinguished name.'
}

$dnsInfrastructure |
    Where-Object { $_.fSMORoleOwner -match '\\0ADEL:' } |
    ForEach-Object {
        Set-ADObject -Identity $_.DistinguishedName `
            -Server $env:COMPUTERNAME `
            -Replace @{fSMORoleOwner = $localNtdsDn} `
            -ErrorAction Stop
    }

$dnsInfrastructureObjects | ForEach-Object {
    Get-ADObject -Identity $_ -Server $env:COMPUTERNAME `
        -Properties fSMORoleOwner -ErrorAction Stop
} | Format-Table DistinguishedName, fSMORoleOwner -Wrap
```

> 🟡 This is a low-level directory modification. Do not rewrite a healthy value just because the step exists in the runbook.

🟢 **Checkpoint:** only the recovered DC remains; all five FSMO roles point to it; DNS resolves its records and no DNS partition owner references a deleted DC.

---

## 6 — Protect RID Allocation

**Why:** objects created after the backup no longer exist in the restored directory, but their SIDs can remain in permissions. Move RID allocation forward so new objects cannot reuse those identities.

Do both operations:

1. Move the domain-wide allocation point forward.
2. Discard the restored DC's local pool.

### 6.1 Raise the domain RID pool

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

Do not rerun the increase after it succeeds: each execution consumes another safety margin.

### 6.2 Invalidate the restored DC's local RID pool

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

### 6.3 Test a newly allocated RID

The first attempt to create a security principal is expected to fail with a **RID allocation error**, because it triggers allocation of a fresh pool. Run the following block; if that specific error occurs, retry it once. Stop for any other error:

```powershell
New-ADGroup -Name 'RID-Recovery-Test' `
    -SamAccountName 'RID-Recovery-Test' `
    -GroupCategory Security `
    -GroupScope Global `
    -ErrorAction Stop
```

After creation succeeds, compare the SID's last component with the new pool's allocation floor, then remove the test group:

```powershell
$minimumRid = $newRidPool -band [int64]4294967295
$testGroup = Get-ADGroup 'RID-Recovery-Test' -ErrorAction Stop
$testRid = [int64]($testGroup.SID.Value.Split('-')[-1])

[pscustomobject]@{
    SID        = $testGroup.SID.Value
    RID        = $testRid
    MinimumRID = $minimumRid
}

if ($testRid -lt $minimumRid) {
    throw 'The test object received a RID below the new allocation floor.'
}

dcdiag /test:ridmanager /v

Remove-ADGroup -Identity $testGroup -Confirm:$false -ErrorAction Stop
```

Keep the values from step 6.1 in the same session until this check is complete.

🟢 **Checkpoint:** the RID Manager test passes and a new security principal receives a SID above the abandoned range.

---

## 7 — Reset the Recovered DC's Secrets

### 7.1 Reset the recovered DC's machine password twice

Run this **only on the sole recovered DC**:

```powershell
Reset-ComputerMachinePassword
Reset-ComputerMachinePassword
```

This moves the machine-account secret through its two-value history and prevents pre-recovery DCs from authenticating replication with the recovered DC.

> 🔴 This intentionally breaks replication with the old DC population. Never run it casually across a healthy forest.

### 7.2 Reset `krbtgt` twice

The `krbtgt` account retains two password values. Two resets remove the pre-recovery keys used to sign Kerberos tickets.

**Choose the timing before proceeding:**

- **Published Microsoft recovery guidance:** wait 10 hours between resets, or longer than the configured maximum user/service ticket lifetime if it differs. This preserves the transition for existing tickets.
- **Fully isolated rehearsal with no client or application sessions to preserve:** two consecutive resets can deliberately invalidate all old tickets. Record this test choice and use fresh logons afterwards. Having just one DC is not, by itself, a reason to skip the waiting period.

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

At the timing chosen above, perform the second reset with a different temporary value:

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

> 🔵 AD generates the effective `krbtgt` key material independently of the value entered. The two reset operations and their timing are what matter.

After both resets, sign out and log on again through the console before testing authentication. Reopen elevated PowerShell; variables from the previous session are no longer available.

If the forest has RODCs, their `krbtgt_<number>` accounts need a dedicated recovery plan. Do not delete them blindly.

### 7.3 Only for a security incident: rotate exposed secrets

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

### 7.4 Record the decision for trust relationships

A single-domain forest can still have external or forest trusts. Inventory them on the recovered DC:

```powershell
Get-ADTrust -Filter * `
    -Server $env:COMPUTERNAME `
    -ErrorAction Stop |
    Select-Object Source, Target, Direction, ForestTransitive
```

Record a decision for each trust:

| Situation | Action |
|---|---|
| No trusts are returned | Record **not applicable** |
| Isolated DC restore test; partner forests are outside the test | Keep partners unreachable and defer trust repair. No trust-password reset is needed to validate this DC alone |
| Trust required when recovering production | Coordinate validation and, if necessary, password repair with the partner administrator before reconnecting |

> 🔴 Do not reset every trust blindly. A one-sided reset can break authentication with a healthy partner. Trust repair needs its own reviewed procedure, credentials, and agreed timing.

🟢 **Checkpoint:** every trust is either outside the isolated test or has an approved repair and validation plan.

---

## 8 — Configure Time and Keep the Global Catalog

### 8.1 Configure the PDC Emulator's time source

The recovered DC now owns the PDC Emulator role. Replace the NTP placeholders with approved peers **reachable from the isolated network**; Internet access is not required:

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

🟢 **Checkpoint:** `w32tm /query /status` shows the intended source and a successful synchronization. A configured but unreachable peer is not success.

### 8.2 Keep or enable the Global Catalog

There is only one domain, so **do not remove the Global Catalog**. Check it:

```powershell
Get-ADDomainController -Identity $env:COMPUTERNAME |
    Select-Object HostName, IsGlobalCatalog
```

Only if `IsGlobalCatalog` is false, enable it:

```powershell
repadmin /options $env:COMPUTERNAME +IS_GC

if ($LASTEXITCODE -ne 0) {
    throw "Unable to enable the Global Catalog. repadmin exit code: $LASTEXITCODE"
}

Get-WinEvent -FilterHashtable @{
    LogName = 'Directory Service'
    Id      = 1119
} -MaxEvents 5
```

Directory Service event `1119` confirms promotion. An event from before the recovery is not evidence of a new promotion; also verify the current GC state and advertising tests below.

---

## 9 — Validate and Back Up the Recovered DC

Do not build the next DC until AD DS, DNS, SYSVOL, RID issuance, time, and fresh authentication work on the recovered DC.

### 9.1 Check AD DS, DNS, roles, and services

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
| DFSR | Event `4602` from this recovery; no blocking DFSR errors |
| RID | `dcdiag /test:ridmanager` passes |
| GC | The recovered DC is a Global Catalog |
| Time | PDC synchronizes with approved external peers |
| Kerberos | Fresh interactive logon and service-ticket acquisition work |

With only one DC, replication tools may show no partners. That is expected **after metadata cleanup**; it does not yet prove that a new DC can replicate. Record failures from `dcdiag` and resolve active faults. Historical log entries must be distinguished from errors generated by this recovery.

### 9.2 Test SYSVOL, Group Policy, and authentication

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

On a clean workstation in the isolated network, point DNS to the recovered DC, join the recovered domain, and sign in with a restored test account. Run:

```powershell
whoami /user
klist purge
gpupdate /force
```

Replace the placeholder with the recovered DC's FQDN, then check ticket issuance and applied policies:

```powershell
klist get 'cifs/<RECOVERED_DC_FQDN>'
klist
gpresult /r
```

🟢 **Checkpoint:** fresh domain logon succeeds, a service ticket is issued, and the expected policies and logon scripts are applied. Do not use an existing cached workstation session as proof.

### 9.3 Restore the initial-sync safeguard

If `Repl Perform Initial Synchronizations` was set to `0`, restore the normal behavior:

```powershell
$ntdsParameters = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

Set-ItemProperty -Path $ntdsParameters `
    -Name 'Repl Perform Initial Synchronizations' `
    -Value 1 `
    -ErrorAction Stop
```

Reboot the recovered DC and repeat the core checks if the temporary bypass was used. If it stops advertising again, the recovery is not ready: inspect the remaining topology and Directory Service log.

### 9.4 Create the first post-recovery backup

Once every checkpoint passes, create a Windows Server Backup containing **all critical volumes for Bare Metal Recovery and System State**.

Run in an elevated Windows PowerShell session on the recovered DC, with the Windows Server Backup feature installed. Replace `E:` with a dedicated backup disk that has enough free space and is **not one of the volumes being backed up**. Do not overwrite the original recovery backup.

```powershell
$backupTarget = 'E:'

if (-not (Test-Path -LiteralPath "$backupTarget\")) {
    throw "Backup destination $backupTarget is not accessible."
}

wbadmin start backup "-backupTarget:$backupTarget" `
    -allCritical -systemState -quiet

if ($LASTEXITCODE -ne 0) {
    throw "Post-recovery backup failed. wbadmin exit code: $LASTEXITCODE"
}

wbadmin get versions "-backupTarget:$backupTarget" `
    "-machine:$env:COMPUTERNAME"

if ($LASTEXITCODE -ne 0) {
    throw "Unable to verify the backup catalog. wbadmin exit code: $LASTEXITCODE"
}
```

Check that the catalog contains the backup just completed, for the recovered DC, with the expected timestamp and **Bare Metal Recovery plus System State** recovery capabilities. Record its version identifier and destination in the recovery log. Merely listing an older backup is not success.

`-allCritical` does not include unrelated data volumes. Add them with `-include` if the recovery plan requires a complete image of those volumes too.

> 🟢 **Major checkpoint:** this backup is the first clean recovery baseline. Do not begin mass redeployment before it completes successfully.

---

## 10 — Build and Promote New DCs

The old replica databases cannot be reused after their metadata has been removed. Build clean servers and promote them into the recovered domain.

**Run this step on each new server, not on the recovered DC.**

1. Install a supported Windows Server version and updates.
2. Give the server a unique hostname and static IP on the recovery network.
3. Configure preferred DNS to the recovered DC's IP. Verify that the recovered domain resolves.
4. Install the AD DS role and management tools:

```powershell
$installation = Install-WindowsFeature AD-Domain-Services `
    -IncludeManagementTools -ErrorAction Stop

if (-not $installation.Success) {
    throw 'AD DS role installation failed.'
}
```

5. Open elevated PowerShell. Replace the placeholders, supply a new DSRM password for this server, and promote it using the recovered DC as the replication source. Promotion joins the domain if the server is not already a member; DNS is installed by `-InstallDNS`:

```powershell
$domainName = '<DOMAIN_FQDN>'
$sourceDc = '<RECOVERED_DC_FQDN>'
$dsrmPassword = Read-Host 'Enter the new DC DSRM password' -AsSecureString

Install-ADDSDomainController `
    -DomainName $domainName `
    -ReplicationSourceDC $sourceDc `
    -InstallDNS `
    -SafeModeAdministratorPassword $dsrmPassword `
    -Credential (Get-Credential) `
    -Force `
    -ErrorAction Stop
```

Use recovered-domain administrator credentials, not credentials from an unrelated production forest. Save the DSRM password in the approved vault.

6. After the automatic reboot, log on and validate replication:

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

🟢 **Checkpoint:** the new DC replicates successfully with the recovered DC, shares SYSVOL/NETLOGON, and passes DNS and authentication tests. Repeat for the remaining new DCs. Never make their SYSVOL copies authoritative.

---

## 11 — Finish the Rehearsal or Return to Service

### 11.1 Keep a rehearsal isolated

For a test, keep the restored forest and all test DCs isolated from production. Record the recovery duration, backup version, changes made, successful checks, and remaining faults. There is no production reconnection step.

For a **real disaster recovery only**, reconnect dependent services after the recovered and newly built DCs have passed validation:

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

Old DCs must remain permanently disconnected.

### 11.2 Only for a real recovery: reintroduce Entra Connect

Objects created after the AD backup may still exist in Entra ID. Enabling exports without review can delete or change them in the cloud.

Perform these checks **on the Entra Connect server**, not on the recovered DC. Do not connect production synchronization to an isolated rehearsal.

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

---

## Final Recovery Checklist

### First recovered DC

- [ ] Recovery point and backup approved.
- [ ] Recovery environment isolated.
- [ ] One writable DC restored with an AD-aware method.
- [ ] Restored directory data inspected.
- [ ] SYSVOL marked authoritative.
- [ ] DFSR event `4602` from this recovery confirmed.
- [ ] `SYSVOL` and `NETLOGON` shared.

### Domain ownership

- [ ] RID-500 enabled, password known, and fresh domain console logon tested in normal startup mode, not DSRM.
- [ ] All five FSMO roles seized.
- [ ] All other writable DC metadata removed.
- [ ] Stale DNS records removed.
- [ ] DNS application-partition owners valid.
- [ ] RID pool raised and local pool invalidated.
- [ ] Restored DC machine password reset twice.
- [ ] `krbtgt` reset twice with the approved timing; fresh logon tested afterwards.
- [ ] Incident-specific secrets rotated.
- [ ] Trust relationships inventoried; test exclusions or repair plans recorded.

### Service validation

- [ ] PDC Emulator synchronizes with approved NTP peers.
- [ ] Global Catalog available.
- [ ] `dcdiag` passes expected tests.
- [ ] DNS and DC Locator tests pass.
- [ ] New security principal receives a safe RID.
- [ ] Fresh Kerberos logon works.
- [ ] GPO and logon-script tests pass.
- [ ] Temporary initial-sync bypass removed.
- [ ] New post-recovery backup completed; version, timestamp, destination, and BMR/System State capabilities verified.

### Redeployment

- [ ] Additional DCs built from clean operating systems.
- [ ] AD DS, DNS, SYSVOL, and GC replication validated.
- [ ] Old DCs permanently prevented from reconnecting.
- [ ] Rehearsal: test environment remains isolated and results recorded.
- [ ] Real recovery only: production connectivity restored in controlled stages.
- [ ] Real recovery only: Entra Connect pending exports reviewed before activation.
- [ ] Real recovery only: Tier 0 and business application owners completed their tests.

---

## References

- [Active Directory Forest Recovery Guide](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-guide)
- [Perform initial recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-initial-recovery)
- [Perform a full server recovery](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-perform-full-server-recovery)
- [Perform an authoritative synchronization of DFSR-replicated SYSVOL](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-authoritative-recovery-sysvol)
- [Clean metadata of removed writable domain controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-cleaning-metadata-of-removed-dcs)
- [Raise the value of available RID pools](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-raise-rid-pool)
- [Invalidate the current RID pool](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-invaildate-rid-pool)
- [Reset the computer account password of the recovered DC](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-computer-account-dc)
- [Reset the `krbtgt` password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [Get-ADTrust](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust)
- [wbadmin start backup](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-start-backup)
- [wbadmin get versions](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-get-versions)
- [Redeploy remaining domain controllers](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-restore-additional-dcs)
- [Microsoft Entra Connect Sync operational tasks and staging mode](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-staging-server)
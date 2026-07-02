---
title: "Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios"
date: 2025-10-24
---

# Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios

## Introduction

Welcome to my Active Directory Attack Lab.
A small, isolated playground where we poke AD to see what Microsoft Defender for Identity MDI notices.
This repo contains samples labs, some expected MDI alerts for each scenario, and the evidence to collect.
Ready to break things and learn how they show up in telemetry?

**Prerequisites**
- A closed lab: Domain controllers + member workstations + Commando VM as attacker.
- Microsoft Defender for Identity sensors deployed on DCs (Healthy)
- Commando VM Installed 
- Some Domain accounts

> I'll use "C:\AttackResults" has my working folder

---

## Recon & mapping

Recon & mapping — passive, low-impact discovery of the Active Directory environment: enumerate users, groups, computers, service principal names (SPNs) and ACLs to build a comprehensive attack-surface map.
This phase collects datas like LDAP/WMI and DNS data, produces BloodHound datasets and highlights potential escalation paths and lateral-movement opportunities — all without attempting exploitation.

* MDI alerts expected — Reconnaissance & Mapping

During this phase, the attacker performs low-impact enumeration using native tools or LDAP queries. Microsoft Defender for Identity detects these activities under the Reconnaissance and Discovery category. Typical alerts include:

| Security alert name                                   | Severity | External ID | Description                                                |
| ----------------------------------------------------- | -------- | ----------- | ---------------------------------------------------------- |
| **Account Enumeration reconnaissance**                | Medium   | 2003        | Enumeration of user accounts using OS commands or scripts. |
| **Account Enumeration reconnaissance (LDAP)**         | Medium   | 2437        | LDAP queries used to enumerate domain accounts.            |
| **Network-mapping reconnaissance (DNS)**              | Medium   | 2007        | Unusual DNS queries or host enumeration activity.          |
| **User and IP address reconnaissance (SMB)**          | Medium   | 2012        | SMB connections used to list users or connected devices.   |
| **User and Group membership reconnaissance (SAMR)**   | Medium   | 2021        | Enumeration of group memberships through SAMR protocol.    |
| **Active Directory attributes reconnaissance (LDAP)** | Medium   | 2210        | Mass LDAP queries for AD attributes.                       |
| **Honeytoken was queried via LDAP**                   | Low      | 2429        | LDAP query detected against a decoy (honeytoken) account.  |

### DNS / SRV discovery

**Why:**
Query AD SRV records to discover Domain Controllers and Kerberos endpoints. This tells us where LDAP/Kerberos services live so we can target later enumeration and correlate telemetry. Expected results: SRV targets (FQDNs), and for each SRV record the priority/weight/port if present. If SRV records are missing or point to unexpected hosts, that’s a useful finding.

**How:**

```powershell
New-Item -Path "C:\AttackResults\1.ReconMapping" -ItemType Directory -Force | Out-Null

nslookup -type=SRV _ldap._tcp.dc._msdcs.mathiasmotron.com > C:\AttackResults\1.ReconMapping\SRV_ldap.txt
nslookup -type=SRV _kerberos._tcp.mathiasmotron.com > C:\AttackResults\1.ReconMapping\SRV_kerberos.txt

Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.mathiasmotron.com" -Type SRV | Out-File C:\AttackResults\1.ReconMapping\Resolve_SRV_ldap.txt
Resolve-DnsName -Name "_kerberos._tcp.mathiasmotron.com" -Type SRV | Out-File C:\AttackResults\1.ReconMapping\Resolve_SRV_kerberos.txt
```

![](<./assets/Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios/2025-10-24-11-29-24.png>)

**What to watch in MDI:**
This is low-impact network discovery and normally should not produce high-severity alerts.
Possible MDI signals: Network-mapping reconnaissance (DNS) or similar if many DNS queries come from the same host quickly.

![](<./assets/Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios/2025-10-24-13-15-48.png>)

> You can as well try to trigger the Alert with NSLOOKUP ls -d <domainname.com>

> Repeated plain nslookup calls often do not always trigger MDI recon alerts by themselves. DNS lookups are very noisy in normal operations and MDI can sometime treat them as low-importance unless they’re part of a larger pattern.

## Basic AD reconnaissance

- Enumerate Domain Admins metadata infos

**Why:**
Perform low-impact LDAP/SAMR reads to discover domain metadata, privileged groups and inventory of users and computers.
Purpose + expected info: domain name and functional info, Domain Admins membership (who the high-value accounts are), a shortlist of user accounts (candidates for further testing), and a list of computers with last-logon info (targets for lateral movement). These outputs feed next phase (SPN selection, Kerberoast targets, hosts to probe for credential theft and lateral movement).

**How:**
Run these commands from Commando VM PowerShell where PowerView.ps1 is available.

![](<./assets/Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios/2025-10-24-13-47-44.png>)

- Get basic domain metadata

```powershell
Get-NetDomain | Out-File C:\AttackResults\1.ReconMapping\Get-NetDomain.txt -Encoding utf8
```

Native Powershell AD Alternative
```powershell
Get-ADDomain | Out-File C:\AttackResults\1.ReconMapping\Get-ADDomain.txt -Encoding UTF8
```

WMI Alternative
```powershell
wmic ntdomain > C:\AttackResults\1.ReconMapping\get-Domain_wmi.txt
```

- Get all users infos

```powershell
Get-ADUser -LDAPFilter "(objectCategory=person)(objectClass=user)" -Properties sAMAccountName | Select-Object -ExpandProperty sAMAccountName | Out-File C:\AttackResults\1.ReconMapping\all_users.txt -Encoding utf8 -Force
```
Powerview Alternative
```powershell
Get-DomainUser | Select-Object -ExpandProperty sAMAccountName | Out-File C:\AttackResults\1.ReconMapping\all_users_powerview.txt -Encoding utf8 -Force
```

WMI Alternative
```powershell
wmic useraccount > C:\AttackResults\1.ReconMapping\get-UserDomain_wmi.txt
```

- Get all computers infos

```powershell
Get-ADComputer -LDAPFilter "(objectClass=computer)" -Properties Name | Select-Object -ExpandProperty Name | Out-File C:\AttackResults\1.ReconMapping\all_computers.txt -Encoding utf8 -Force
```
Powerview Alternative
```powershell
Get-DomainComputer | Select-Object -ExpandProperty Name | Out-File C:\AttackResults\1.ReconMapping\all_computers_powerview.txt -Encoding utf8 -Force
```

- Enumerate Domain Admins and Domain Controllers

**Why:**
Find who holds the high-value privileged accounts (Domain Admins).

**How:**
```powershell
 (Get-DomainGroup -Identity "Domain Admins").member | Out-File C:\AttackResults\1.ReconMapping\DomainAdmins.txt -Encoding utf8 -Force
Get-Content C:\AttackResults\1.ReconMapping\DomainAdmins.txt
```

Net Group Alternative
```powershell
net group "Domain Controllers" /domain > C:\AttackResults\1.ReconMapping\DomainControllers_netgroup.txt
net group "Domain Admins" /domain > C:\AttackResults\1.ReconMapping\DomainAdmins_netgroup.txt
```

 - Enumerate accounts with SPN

**Why:**
Service accounts with SPNs can be targeted later to request service tickets (TGS) and attempt offline cracking (Kerberoast).

**How:**
```powershell
Get-DomainUser -SPN | Select-Object Name, sAMAccountName, @{n='SPNs';e={$_.servicePrincipalName -join ';'}} | Export-Csv C:\AttackResults\1.ReconMapping\spn_accounts.csv -NoTypeInformation -Encoding utf8 -Force
Get-Content C:\AttackResults\1.ReconMapping\spn_accounts.csv
```

RiskySPN Alternative
```powershell

```


 **What to watch in MDI:**
Regarding the environment or previous behavior detected, some alerts can occurs like "Security principal reconnaissance (LDAP)", "Account Enumeration reconnaissance (LDAP)", "Active Directory attributes reconnaissance (LDAP)", etc.

![](<./assets/Active Directory Attack Simulation Lab - Testing MDI Detection Scenarios/2025-10-24-14-09-36.png>)

- SMB / session enumeration

**Why:**
Enumerate active SMB sessions and shared resources to discover where privileged accounts have active sessions and which hosts expose sensitive shares. This reveals practical lateral-movement pivot points (machines with many admin sessions), candidate hosts for credential harvesting, and high-value shares (profiles, backups). Expected outputs: list of SMB sessions (machine ⇄ user mappings with idle time), list of SMB shares on key hosts (share name, path, description), and a mapping of which accounts are connected to which machines.

**How:**



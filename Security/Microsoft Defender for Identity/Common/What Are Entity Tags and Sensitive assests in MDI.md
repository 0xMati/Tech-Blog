# What Are Entity Tags and Sensitive assests in Microsoft Defender for Identity?
🗓️ Published: 2025-07-17

Entity tags in MDI allow you to mark key identities and resources for enhanced monitoring and detection logic. There are three main tag types:

- **Sensitive**: Users, devices, and groups that represent high-value assets (e.g., Domain Admins, critical servers, VIP users).  
- **Honeytoken**: Decoy user or device accounts that should never see real activity—any use triggers an alert.  
- **Exchange server**: Devices running Exchange Server, automatically or manually tagged, to boost protection around your mail infrastructure.

---

## Why Tagging Matters?

- **Sharper detections**: MDI adjusts baselines for tagged entities, so anomalies stand out.  
- **Lateral movement prevention**: you’ll catch reconnaissance or pivot attempts against your top targets.  
- **Priority alerts**: events with entity tags bubble up first, reducing noise and alert fatigue.  
- **Unified view**: see all your critical identities and decoys in one place in the MDI portal.

---

## How to Configure Entity Tags

1. **Sign in** to the **Microsoft Defender XDR** portal at security.microsoft.com.  
2. Go to **Settings > Identities > Entity tags**.  
3. Select the tab for the tag type:
   - **Sensitive** (supports Users, Devices, Groups)  
   - **Honeytoken** (supports Users, Devices)  
   - **Exchange server** (supports Devices only)  
4. Click **Tag users** (or Tag devices / Tag groups), then search/select the entities you want to tag and click **Add selection**.  

![](assets/What%20Are%20Entity%20Tags%20and%20Sensitive%20assests%20in%20MDI/2025-07-17-14-02-12.png)

---

## Default Sensitive Entities

MDI automatically tags members of these built-in AD groups (and nested members) as **Sensitive**:

- Administrators  
- Power Users  
- Account Operators  
- Server Operators  
- Print Operators  
- Backup Operators  
- Replicators  
- Network Configuration Operators  
- Incoming Forest Trust Builders  
- Domain Admins  
- Domain Controllers  
- Group Policy Creator Owners  
- Read-only Domain Controllers  
- Enterprise Read-only Domain Controllers  
- Schema Admins  
- Enterprise Admins  
- Microsoft Exchange Servers  
- Certificate Authority Servers  
- DHCP Servers  
- DNS Servers  

*Note*: Remote Desktop Users were auto-tagged before September 2018; review any existing tags if needed.

In addition to these groups, MDI identifies the following high value asset servers and automatically tags them as Sensitive:

Microsoft Certificate Authority Server
Microsoft DHCP Server
Microsoft DNS Server
Microsoft Exchange Server

---

## Impact on Alerting

- **Portal alerts**: MDI surfaces tag-related alerts with higher priority.  

---

## Best Practices

- **Review tags quarterly** to keep your inventory up-to-date.  
- **Limit tags** to truly high-impact entities to avoid diluting focus.  



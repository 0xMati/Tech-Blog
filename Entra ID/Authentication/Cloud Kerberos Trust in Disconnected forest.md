---
title: "Lab: Playing with Cloud Kerberos Trust in a Disconnected Forest – **Work in Progress**"
date: 2025-05-20
---

# 🔐 Objective

Demonstrate how it is possible to manipulate attributes sync to configure **Cloud Kerberos Trust** in a disconnected (not directly synced by Entra ID Connect) Active Directory forest for hybrid identity scenarios.
This document does not provide a detailed step-by-step guide but rather a high-level overview to achieve a working configuration.

This lab assumes:
- 1 Forest "contoso.local"
    - This forest contains user accounts used for daily local authentication
    - It also contains computer objects, domain-joined to contoso.local, used by employees with their respective user accounts

- 1 Forest "fabrikam.com"
    - This forest contains user accounts consolidated from all contoso.local forests (if multiple exist)

- No trust exists between fabrikam.com and any contoso.local forests.

- 1 Tenant "0x1mati.online" with Managed (Password Hash Sync) authentication configuration

- 1 MIM Sync Service (or equivalent) to Synchronize (and provision) required attributes from Contoso.local forest to fabrikam.com forest

- 1 Entra ID Connect server (located in fabrikam.com) that synchronizes user objects from fabrikam.com to Entra ID and synchronizes computer objects from contoso.local to enable Hybrid Join.

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-55-53.png)
---

# 📋 Prerequisites

## 🖥️ On-Premises
- Windows Server 2016 or later on Domain Controllers.
- Domain/Forest Functional Level: Windows Server 2016 minimum.
- Writable Domain Controllers accessible for client

## ☁️ Azure AD
- Entra ID P1 or P2 license (for WHfB).
- Public Domain name (0x1mati.online) verified and configured for Managed/PHS authentication

---

# ⚙️ Steps Overview

1. [ ] Sync Users from contoso.local to fabrikam with MIM
2. [ ] Entra ID Connect - Sync Users from fabrikam.com to Entra ID
3. [ ] Implement Hybrid Join Configuration
4. [ ] Create the AzureADKerberos object in the disconnected forest
5. [ ] Deploy WHfB configuration
6. [ ] Test Configuration

---

# 📋 Sync Users from contoso.local to fabrikam with MIM

This section does not focus on how to provision objects with MIM. The main objective is to understand the required attribute flows from the contoso.local forest to the fabrikam.com forest.

→ Join condition in MIM is based on the `mail` attribute in this example. Adapt as needed.  
→ The `mS-DS-ConsistencyGuid` is written back for consistency.

## Required attributes flow with MIM

| Contoso.local                 | MIM Metaverse                                   | Fabrikam.com                    | Flow Direction         |
|------------------------------|-------------------------------------------------|----------------------------------|------------------------|
| ObjectSID -->                | ObjectSID -->                                   | ObjectSID2                       | Export to Fabrikam     |
| ObjectSIDString* -->         | ObjectSIDString -->                             | msDS-cloudExtensionAttribute7    | Export to Fabrikam     |
| sAMAccountName -->           | AccountName -->                                 | msDS-cloudExtensionAttribute20   | Export to Fabrikam     |
| mS-DS-ConsistencyGuid <--    | mS-DS-ConsistencyGuid <--                       | mS-DS-ConsistencyGuid            | Export to Contoso      |
| userPrincipalName -->        | userPrincipalName -->                           | msDS-cloudExtensionAttribute5    | Export to Fabrikam     |
| "CONTOSO"** -->              | domain -->                                      | msDS-cloudExtensionAttribute6    | Export to Fabrikam     |
| "CONTOSO.LOCAL"** -->        | domainfqdn -->                                  | msDS-cloudExtensionAttribute3    | Export to Fabrikam     |



*ObjectSIDString : A custom string representation of the SID, calculated in a Rule Extension or custom MIM code.
**"CONTOSO" and "CONTOSO.LOCAL" : Hardcoded constant values set during the flow for use in WHfB/Cloud Kerberos scenarios.

Ex : Contoso MA

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-20-23-56-03.png)

Ex : Fabrikam MA 

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-20-23-56-35.png)

Ex of a User account in Fabrikam with custom values populated:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-02-10.png)

---

# 📋 Entra ID Connect - Sync Users from fabrikam.com to Entra ID

The goal here is to take values in Fabrikam that originated from Contoso and push them into the Entra ID metaverse, making them available in the cloud.

## Required attributes flow with Entra ID Connect for Users in Fabrikam to Entra ID (Fabrikam MA)

Configure Entra ID Connect attribute flows to ensure that values from contoso.local are synchronized to Entra ID.
This can be achieved with a custom sync rule. In this example, I chose to implement an inbound rule, but an outbound rule could also be used.

| Fabrikam.com                        | Entra ID Connect Metaverse                      | Entra ID MA                     | Flow Direction         |
|------------------------------------|-------------------------------------------------|----------------------------------|------------------------|
| ObjectSID2 -->                     | ObjectSID -->                                   | onPremiseSecurityIdentifier     | Export to Entra ID     |
| msDS-cloudExtensionAttribute7 -->  | ObjectSidString -->                             | ??                              | Export to Entra ID     |
| msDS-cloudExtensionAttribute20 --> | AccountName -->                                 | onPremisesSamAccountName        | Export to Entra ID     |
| msDS-cloudExtensionAttribute5 -->  | userPrincipalName -->                           | onPremisesUserPrincipalName     | Export to Entra ID     |
| msDS-cloudExtensionAttribute6 -->  | domainNetBios -->                               | netBiosName                     | Export to Entra ID     |
| msDS-cloudExtensionAttribute6 -->  | ForestNetBios -->                               | ??                              | Export to Entra ID     |
| msDS-cloudExtensionAttribute3 -->  | domainfqdn -->                                  | dnsDomainName                   | Export to Entra ID     |
| msDS-cloudExtensionAttribute3 -->  | forestfqdn -->                                  | ??                              | Export to Entra ID     |


![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-11-25.png)

# 📋 Entra ID Connect – Implement Hybrid Join Configuration

## Deploy Hybrid Join Configuration for Devices in contoso.local

* Option 1 – Configure the Service Connection Point (SCP) in the domain

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-13-24.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-14-06.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-14-21.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-15-27.png)

* Option 2 – Deploy registry keys via GPO to domain-joined computers

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD  
TenantId (REG_SZ): Entra tenant ID  
TenantName (REG_SZ): Entra tenant name (e.g., *.onmicrosoft.com)    

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-16-29.png)

## Perform Hybrid Join of computer

- Hybrid Join is automatically attempted at every logon or lock/unlock event. However, you can manually trigger it by running the following scheduled task:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-25-32.png)

- Verify that Hybrid Join completed successfully using Event Viewer:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-27-46.png)

- And also with the dsregcmd command:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-29-05.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-29-19.png)

---

# 📋 Create the AzureADKerberos object in the disconnected forest

```powershell
# Register the AzureADKerberos object in the disconnected domain
$domain = $env:USERDNSDOMAIN
$userPrincipalName = "myadmin@0x1mati.onmicrosoft.com"
$domainCred = Get-Credential

Set-AzureADKerberosServer -Domain $domain -UserPrincipalName $userPrincipalName -DomainCredential $domainCred
```

→ Verify the presence of the AzureADKerberos RODC object

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-18-03.png)

→ Verify the krbtgt_AzureAD object is created successfully

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-18-20.png)

---

# 📋 Deploy Windows Hello for Business (WHfB) Configuration

## On the Entra ID Side

- Enable Windows Hello for Business in Intune with settings that fit your needs:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-21-28.png)

## On the Active Directory Side for Hybrid Join and Entra ID Joined Devices

- Enable support for Windows Hello for Business for your Hybrid Joined devices.
This can be achieved using a GPO or Intune policy:

* Enable MDM enrollment for domain-joined devices:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-31-32.png)

* Enable Windows Hello for Business and Cloud Kerberos Trust support:

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-33-38.png)


---

# ⚙️ Verify the Configuration

## Entra ID Joined Device

- Perform Entra ID Join on the device  

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-40-24.png)

- Sign in with a synced user  
- Complete Windows Hello for Business registration  
- Log off and log on using WHfB credentials  
- Verify the presence of the Azure PRT, Cloud TGT, and On-prem TGT

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-40-53.png)

- Use klist to request an on-prem TGS and verify it was issued successfully

## Entra Hybrid Joined Device

- Sign in with a synced user  
- Complete Windows Hello for Business registration  
- Log off and log on using WHfB credentials  
- Use `dsregcmd` to verify the presence of Azure PRT, Cloud TGT, and On-prem TGT

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-38-28.png)

- Use klist cloud_debug and klist to verify issued tickets

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-39-11.png)


---
title: "Lab : Playing with Cloud Kerberos Trust in Disconnected Forest - **Work in Progress** "
date: 2025-05-20
---

# 🔐 Objective

Demonstrate how it possible to manipulate attributes sync to configure **Cloud Kerberos Trust** in a disconnected (not directly synced by Entra ID Connect) Active Directory forest for hybrid identity scenarios.
There is no advanced description of all steps, just general idea to make it work.

This lab assumes:
- 1 Forest "contoso.local"
    - The forest contains Users Accounts used in day to day local authentication for people
    - The forest contains Computers objects, domain joined to "contoso.local", used by people with theirs contoso.local Users accounts.

- 1 Forest "fabrikam.com"
    - This forest contains Users Accounts consolidated from all contoso.local forests (if multiple exist)

- No Trust exist between Fabrikam.com and Contoso Forests

- 1 Tenant "0x1mati.online" with Managed (Password Hash Sync) authentication configuration

- 1 MIM Sync Service (or equivalent) to Synchronize (and provision) required attribute from Contoso.local forest to fabrikam.com forest

- 1 Entra ID Connect Server (in Fabrikam), that synchronize Users objects consolidated from Fabrikam.com to Entra ID, and Sync Computers object from Contoso Forest to perform Hybrid Join

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

2. [ ] Sync Users required attributes from contoso forests to Fabrikam
3. [ ] Configure Entra ID Connect
1. [ ] Create the AzureADKerberos object in the disconnected forest
4. [ ] Deploy WHfB policy.
5. [ ] Test authentication with partial and full TGT flow.

---

# 📋 Sync Users from contoso.local to fabrikam with MIM

I don't focus on how to provision objects with MIM, the main idea here is to understand required attributes flow from the local AD contoso.local to fabrikam.com

--> Join Condition in MIM is based on "mail" attribute in this example, adapt to your needs
--> mS-DS-ConsistencyGuid is writebacked for consistency

## Required attribut flow with MIM

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

The idea here is to get values in Fabrikam that came from Contoso and push them to the Entra ID Metaverse to populate theses values to the cloud

## Required attribut flow with EIDC for Users in Fabrikam to Entra ID (Fabrikam MA)

Manipulate Entra ID Connect Attribute flow to ensure that value from contoso.local are synced to Entra ID.
It can be acheive with a custom Sync Rule, in this example I choose to implement an Inbound Rule, but outbound rule can be used.

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

# 📋 Entra ID Connect - Implement Hybrid Join Configuration

## Deploy Device Hybrid Join Configuration for Computers in Contoso

* Option 1 - Configure SCP in the domain 

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-13-24.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-14-06.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-14-21.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-15-27.png)

* Option 2 - Deploy Reg key with GPO to Computers

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ\AAD
TenantId (REG-SZ): ID of Entra Tenant 
TenanName (REG-SZ): Name of Entra Tenant (tech name *.onmicrosoft.com)   

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-16-29.png)

## Perform Hybrid Join of computer

- Hybrid join is automatically done/try at every logon, lock/unlock, but you can trigger it manually by running this scheduled task :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-25-32.png)

- Verify that Hybrid Join is completed successfully in Event Viewer :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-27-46.png)

- and with dsregcmd command :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-29-05.png)

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-29-19.png)

---

# 📋 Create the AzureADKerberos object in the disconnected forest

```powershell
$domain = $env:USERDNSDOMAIN
$userPrincipalName = "myadmin@0x1mati.onmicrosoft.com"
$domainCred = Get-Credential

Set-AzureADKerberosServer -Domain $domain -UserPrincipalName $userPrincipalName -DomainCredential $domainCred
```

--> Check AzureADKerberos RODC Object

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-18-03.png)

--> Check krbtgt_AzureAD Object

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-18-20.png)

---

# 📋 Deploy WHfB configuration

## Entra ID side

- Enable WH4B in inTune with settings that fits your needs :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-21-28.png)

## Active Directory side for Hybrid Join Computers (and/or Entra ID Join (only) Computers)

- Enable Support of WH4B for your Hybrid Join machine

Can be acheive by GPO (or inTune policies) with :

* Enable MDM management :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-31-32.png)

* Enable support of Windows Hello and Support of Cloud Trust for Authentication :

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-33-38.png)


---

# ⚙️ Verify configuration

## Entra ID Join machine

- Perform Entra ID Connect Join on the machine

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-40-24.png)

- log with a Synced User
- Perform WH4B registration
- logoff/logon with Windows Hello For Business Credential
- Check presence of Azure PRT + Cloud TGT + Onprem TGT

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-40-53.png)

- Try to get an onprem TGS with klist

## Entra Hybrid Join machine

- log with a Synced User
- Perform WH4B registration
- logoff/logon with Windows Hello For Business Credential
- Check presence of Azure PRT + Cloud TGT + Onprem TGT with dsregcmd

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-38-28.png)

- Check klist cloud_debug & klist

![](assets/Cloud%20Kerberos%20Trust%20in%20Disconnected%20forest/2025-05-21-00-39-11.png)


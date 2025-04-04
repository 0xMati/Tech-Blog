# Azure AD Connect – Hard Matching Cloud & On-Prem Accounts  
🗓️ Published: 2022-04-23  

---

## 📘 Table of Contents

1. Introduction  
2. Prerequisites  
3. Azure AD Connect Overview  
4. Configuration Steps  
5. Console Walkthrough  
6. Antivirus Exclusions  
7. Verifying Password Sync  
8. Sync Rule Editor Overview  

---

## 🧩 Introduction

This post outlines how to perform a **Hard Match** between **Azure AD Cloud-Only accounts** and **on-prem Active Directory accounts**, using Azure AD Connect.

The goal is to manually align the identifiers (anchors) of both objects to allow Azure AD Connect to link them during synchronization.

---

## ✅ Prerequisites

- A **Global Administrator** account on the Azure AD tenant  
- An on-prem account with **sufficient AD privileges**  
- PowerShell modules for **Active Directory** and **AzureAD** installed

---

## ⚙️ Azure AD Connect – Matching Principle

Azure AD Connect uses the attribute `ms-DS-ConsistencyGuid` as the **default anchor** on-premises.

To match an on-prem and a cloud-only object, you simply need to ensure **the same anchor value** exists in both:

- On-prem AD → `ms-DS-ConsistencyGuid`  
- Azure AD → `ImmutableID`

### 🧪 Example PowerShell Script

```powershell
Connect-AzureAD

$localupn = "mylocaluser@localupn.com"
$cloudupn = "myclouduser@cloudupn.onmicrosoft.com"

# Generate anchor from local AD object
$ConsistencyGuid = (Get-ADUser -Filter {UserPrincipalName -eq $localupn}).ObjectGUID
$ImmutableID = [System.Convert]::ToBase64String($ConsistencyGuid.ToByteArray())

# Retrieve and inspect cloud user
$CloudUserToSync = Get-AzureADUser -ObjectId $cloudupn
$CloudUserToSync | Format-List

# Apply ms-DS-ConsistencyGuid to local user
(Get-ADUser -Filter {UserPrincipalName -eq $localupn}) | Set-ADUser -Replace @{ 'ms-DS-ConsistencyGUID' = $ConsistencyGuid }

# Apply ImmutableID to cloud user
(Get-AzureADUser -ObjectId $cloudupn) | Set-AzureADUser -ImmutableId $ImmutableID

# Verify changes
$CloudUserToSync = Get-AzureADUser -ObjectId $cloudupn
$CloudUserToSync | Format-List
```

You can easily adapt this script to process a **bulk set of users**.

Once the attributes are aligned, simply allow Azure AD Connect to pick up the objects and the synchronization will link them correctly.

---

## 📌 Notes

- Make sure **AAD Connect is configured to use `ms-DS-ConsistencyGuid`** as the anchor (default since version 1.1.614.0).  
- Ensure the cloud object is not already synced or linked to another source.  
- Use caution when applying anchors programmatically across multiple objects — always test on a pilot set.

---

## 🛠️ Tools Used

- PowerShell with AzureAD and ActiveDirectory modules  
- Azure AD Connect console  
- Event Viewer and Sync Rules Editor (for validation)

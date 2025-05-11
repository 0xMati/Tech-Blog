---
title: "How work Cloud Kerberos Trust"
date: 2025-05-10
---

# 🔐 Introduction to Cloud Kerberos Trust

**Cloud Kerberos Trust (CKT)** is a modern hybrid authentication protocol developed by Microsoft to enable **secure, seamless, and passwordless access** to both cloud and on-premises resources. It is a key component of the **Windows Hello for Business (WHfB)** ecosystem and represents the evolution of traditional Kerberos authentication into a more cloud-native, identity-driven model.

At its core, Cloud Kerberos Trust simplifies authentication by removing two of the major roadblocks faced in previous WHfB trust models—namely, **dependency on a Public Key Infrastructure (PKI)** and **delays caused by Entra ID Connect sync operations**. By leveraging **Entra ID Kerberos**, devices can now receive **Kerberos TGTs** directly via Entra ID, skipping the complexity of synchronizing key credentials to Active Directory or relying on certificate issuance.

CKT works by having Entra ID issue a **partial Kerberos Ticket Granting Ticket (TGT)** as part of the Primary Refresh Token (PRT) process. This TGT is signed using a cryptographic key from a special **AzureADKerberos object**, which is synchronized into the on-premises Active Directory. Once a Windows client receives the partial TGT, it can seamlessly **exchange it with an on-premises domain controller for a full TGT**, enabling access to domain resources such as SMB shares or legacy apps—even on **Entra ID joined devices with no line-of-sight to a domain controller**.


## 1. Why Cloud Kerberos Trust matters

- 🔐 **Passwordless-first**: Enables secure, phishing-resistant sign-ins through Windows Hello for Business (biometric or PIN backed by TPM).
- ⚡ **Instant SSO**: Eliminates the wait for msDS-KeyCredentialLink synchronization—SSO works immediately after provisioning.
- 🔧 **No PKI**: Removes the need for certificate-based infrastructure and such as CRL checks.
- 🌐 **Cloud-native architecture**: Authenticates via Entra ID while still honoring traditional Kerberos flows for on-prem access.
- 🧠 **Reduced domain controller load**: Avoids the CPU overhead seen with WHfB key trust authentication at scale.

Cloud Kerberos Trust isn’t just a technical shortcut—it’s a strategic step forward for organizations seeking to **modernize identity**, **reduce attack surface**, and **simplify hybrid access** scenarios. It delivers a smoother end-user experience while reducing administrative overhead and security complexity.

This article will guide you through a **deep technical understanding** of how Cloud Kerberos Trust works—from concepts to packet flows, configuration details, and security architecture. Whether you're planning a deployment or just seeking to demystify the trust model, this series will cover all angles—**one validated step at a time**.


## 👤 2. A Quick Refresher on Windows Hello for Business

Before diving deeper into Cloud Kerberos Trust, it’s important to understand the foundation it builds upon: **Windows Hello for Business (WHfB)**.

WHfB is Microsoft’s **passwordless authentication framework**, designed to replace traditional passwords with **strong, device-bound credentials**. It supports both **PINs** and **biometric methods** (e.g., fingerprint, facial recognition), all backed by **asymmetric cryptographic key pairs** stored in the **Trusted Platform Module (TPM)** or in software (less secure fallback).


### Key Principles of WHfB

- 🔑 **Asymmetric Key-Based Authentication**: WHfB generates a public/private key pair. The **private key never leaves the device**, and the **public key** is registered in the Identity Provider (Entra ID or AD).
- 🧷 **Device-Bound Credentials**: The credential is tied to both the user and the device. Unlike passwords, it cannot be reused from a different machine.
- 🔐 **Phishing-Resistant**: Because there is no shared secret transmitted over the wire (no password), WHfB is immune to password replay attacks and common phishing techniques.
- 🧠 **TPM-Backed Protection**: The private key is often protected in hardware, and incorrect PIN attempts are mitigated by **TPM anti-hammering** protections.
- 🛡️ **Multi-Factor by Design**: WHfB meets MFA requirements by combining “something you have” (device/private key) with “something you know or are” (PIN or biometric).


### Trust Models in WHfB

WHfB can operate under three distinct trust models:
1. **Key Trust**: Uses the public key written into the `msDS-KeyCredentialLink` attribute in Active Directory. Requires Entra ID Connect and domain controller support (Windows Server 2016+).
2. **Certificate Trust**: Issues a certificate to the user during WHfB enrollment. Typically used in federated environments (e.g., with AD FS). Requires PKI.
3. **Cloud Kerberos Trust**: The most modern model, removing the need for certificate issuance and key sync delays. The TGT is delivered as part of the Entra ID authentication flow and exchanged with a domain controller on demand.

Cloud Kerberos Trust extends WHfB to function **instantly after enrollment** and **without PKI**, making it the most efficient and cloud-optimized trust model available today.

📘 **Deployment Guide**: For a full deployment guide on Windows Hello for Business, refer to the official Microsoft documentation:  
[https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/)


# ⚙️ Prerequisites for Cloud Kerberos Trust

Before enabling **Cloud Kerberos Trust (CKT)** in your hybrid identity environment, you need to ensure that all key infrastructure components are in place: **operating system versions, domain controller capabilities, device join state, and user synchronization**. These requirements provide the foundation for a secure and functional deployment.


## 1. Operating System Requirements

- ✅ Devices must run at least:
  - **Windows 10 21H2** with **KB5010415** or later
  - **Windows 11 21H2** with **KB5010414** or later
- ✅ **TPM 2.0** is strongly recommended for secure key storage


## 2. Device Join State & Management

- ✅ Devices must be **Entra ID Joined** or **Hybrid Entra ID Joined**
- ✅ Devices **must be managed via Intune or Group Policy**, as **specific configuration must be pushed to clients**
  - In particular, the setting `UseCloudTrustForOnPremAuth` (within the *PassportForWork* CSP) must be enabled to allow the device to use Cloud Kerberos Trust
  - This configuration will be detailed in the **Deployment** section

> 💡 Cloud Kerberos Trust works only if the WHfB configuration is properly pushed to the device during provisioning.


## 3. Directory Synchronization

- ✅ A properly configured **Entra ID Connect (Entra Connect)** must be in place
- ✅ User objects must be **synchronized from on-premises Active Directory to Entra ID**
- ✅ The **`msDS-KeyCredentialLink` attribute is not required** with Cloud Kerberos Trust, in contrast to Key Trust deployments

> ⚠️ Users must have the following Microsoft Entra attributes populated through Microsoft Entra Connect for Cloud Kerberos Trust to work:

    - onPremisesSamAccountName (accountName in Microsoft Entra Connect)
    - onPremisesDomainName (domainFQDN in Microsoft Entra Connect)
    - onPremisesSecurityIdentifier (objectSID in Microsoft Entra Connect)
Microsoft Entra Connect synchronizes these attributes by default. If you change which attributes to synchronize, make sure you select accountName, domainFQDN, and objectSID for synchronization.

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-01-30.png)

> 🔍 This eliminates the sync delay that previously prevented immediate WHfB SSO after provisioning.


## 4. Domain Controller Requirements

- ✅ Domain Controllers must run:
  - **Windows Server 2016 or newer**
  - Fully patched (minimum KB5005417 recommended)
- ✅ **Sufficient read-write DCs** must be available in every AD site where users will log on using WHfB

> ⚠️ A **read-write DC** is required because partial TGTs from Entra ID must be validated and exchanged for a **full Kerberos TGT** by the domain controller. This enables the device to access resources like file shares or on-prem applications.

---

## Licensing


- ✅ **No paid license is required** for Cloud Kerberos Trust itself
  - **Microsoft Entra ID Free** is sufficient for basic use
- 🔒 A **paid Entra ID P1/P2 license** is required if you plan to:
  - Use **Conditional Access**
  - Automatically enroll devices via **Intune MDM**
  - Leverage advanced **compliance and reporting** features

> 📘 License comparison: [https://m365maps.com](https://m365maps.com)


---

# 🏗️ Architecture Overview – Cloud Kerberos Trust

Cloud Kerberos Trust introduces a new hybrid authentication model that enables **Entra ID to participate directly in Kerberos-based authentication flows**. This model reduces infrastructure complexity while maintaining compatibility with legacy on-premises applications and file shares.

At a high level, Cloud Kerberos Trust establishes **a chain of trust** between the user, the device, Entra ID, and the on-premises Active Directory domain. The flow is streamlined and does not rely on public key infrastructures (PKI), certificate enrollment, or key credential synchronization.


## 1. 🔄 End-to-End Trust Flow

The following steps describe the technical flow behind Cloud Kerberos Trust authentication, enabling Entra ID-joined or hybrid devices to securely access on-premises resources using Windows Hello for Business (WHfB):

1. **The user signs in to the device using Windows Hello for Business (WHfB)**, either via PIN or biometric gesture.  
   ➤ *This initiates a strong, passwordless authentication using a private key stored securely in the TPM.*
   ➤ *This triggers the Windows Credential Provider, which collects the user’s gesture and interacts with LSA and Winlogon.*

2. **Entra ID authenticates the WHfB credential by issuing a nonce, which is then signed by the client using its WHfB private key (stored in the TPM).**.  
   ➤ *Entra ID validates this signature using the WHfB public key associated with the user object in Entra ID.*

3. **Entra ID issues a Primary Refresh Token (PRT), and:**  
   ➤ *a partial Kerberos Ticket Granting Ticket (TGT), returned as part of the same authentication flow, signed using the key from the AzureADKerberos object (mirrored in on-prem AD),*
   ➤ *and a session key encrypted for the client,*
   ➤ *The session key is securely imported into the client’s TPM for later use.*

4. **The Windows client extracts the partial TGT, and when accessing on-prem resources, it uses DC Locator (via DNS) to identify a valid on-premises domain controller.**  
   ➤ *A `TGS_REQ` message containing the partial TGT is sent to the selected DC.*

5. **The domain controller validates the signature of the partial TGT** using the key material associated with the `AzureADKerberos` object.  
   ➤ *The DC resolves the user’s SID and ensures the signature matches what Entra ID issued.*

6. **If the partial TGT is valid, the DC issues a full Kerberos TGT, allowing the device to access on-premises resources such as SMB shares, LDAP directories, or legacy line-of-business apps.**  
   ➤ *This process is seamless to the user and completes the passwordless SSO flow.*

> 📌 This exchange happens without needing VPN, certificate-based authentication, or AD FS federation.
> 🧠 This process is functionally similar to how clients interact with a Read-Only Domain Controller (RODC), but the partial TGT originates from Entra ID and is validated by a writable DC.

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-20-35-01.png)

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-21-27-54.png)


## 2. 🧭 How DC Locator Works with Entra ID Joined Devices

When a device is **Entra ID Joined (AADJ)** and not domain-joined, it is treated as a **workgroup machine** from the perspective of the **DC Locator (DsGetDcName)** API. Although the machine has no computer account in Active Directory, it can still perform DC discovery — with some limitations.

Here’s how it works in the context of **Cloud Kerberos Trust**:

1. **DC Locator Runs in the Caller Context**  
   Unlike domain-joined machines where DC Locator logic executes inside **Netlogon** with centralized caching and site awareness, AADJ devices execute DC discovery within the **calling process**. This means:  
   - ❌ No site awareness  
   - ❌ No trust relationship logic  
   - ❌ No centralized cache  
   - ✅ But it still works — functionally enough to locate DCs for Kerberos ticket exchange

2. **Domain Identification via Synchronized Attributes**  
   The attributes `onPremisesDomainName`, `onPremisesUserPrincipalName`, and `onPremisesSamAccountName` (synced via Entra Connect) are used to:  
   - Resolve the **target AD domain name**  
   - Identify the **user’s on-prem identity**  
   - Allow **DC Locator to find an appropriate domain controller** via SRV record lookup (e.g., `_kerberos._tcp.domain.com`)

3. **DC Failover Works**  
   Although AADJ machines don’t have all the features of DJ machines, they **can fail over to alternate DCs** if the preferred one is unavailable. This is confirmed by field tests and supported by the native behavior of `DsGetDcName`.

4. **Requirements for DC Compatibility**  
   Only **Windows Server 2016 or newer domain controllers** can process partial TGTs issued by Entra ID in the Cloud Kerberos Trust model. Therefore, DC Locator may locate older DCs, but authentication will fail unless the DC is supported and correctly patched.

5. **Hybrid Join Offers More Capabilities**  
   For full **site awareness**, **trust resolution**, and **optimal DC selection**, Microsoft recommends using **Hybrid Entra ID Join** rather than pure AADJ, especially in complex enterprise environments.

> 🧪 You can manually trigger and test DC location using `nltest /dsgetdc:<domain>` or by inspecting Kerberos debug logs and SRV DNS queries via tools like `klist`, `nslookup`, and Event Viewer logs under:  
> **Applications and Services Logs → Microsoft → Windows → Kerberos-Client → Operational**


## 3. 🔧 Key Components

| Component | Role |
|----------|------|
| **Windows Client** | WHfB-capable device that initiates authentication |
| **Entra ID** | Issues PRT + partial TGT using Entra Kerberos |
| **AzureADKerberos Object** | AD computer object with a long-term key. This object contains the key material used by Microsoft Entra ID to sign partial TGTs |
| **Active Directory DC** | Validates partial TGT, issues full TGT for on-premises access |
| **TPM (optional)** | Secure storage for private keys and PIN protection on the client |


## 4. 🔐 Trust Characteristics

- No certificate or smart card deployment needed
- No synchronization of user key material (e.g., `msDS-KeyCredentialLink`)
- No dependency on PKI or Certificate Revocation Lists (CRLs)
- Domain controllers remain authoritative for Kerberos ticket issuance
- Works over VPN, but also supports remote scenarios without line-of-sight to DC at sign-in

# 🚀 Deployment of Cloud Kerberos Trust


Deploying **Cloud Kerberos Trust (CKT)** involves configuring several components across Microsoft Entra ID, Active Directory, and client devices. This section provides a **step-by-step guide**, including PowerShell, Intune, and GPO options for full flexibility.

---

## 1. ✅ Enable Microsoft Entra Kerberos in Active Directory

You must first create a **Kerberos Server object** in Active Directory, which acts like a virtual Read-Only Domain Controller (RODC) for Entra ID. This object is used to sign **partial TGTs**.

> 🛠️ **Prerequisites**:
- Must be a **Domain Admin**
- Must use a user with the **Global Administrator** role in Entra ID
- Requires PowerShell and TLS 1.2 support

**PowerShell**:

```powershell
Install-Module -Name AzureADHybridAuthenticationManagement -AllowClobber

# Required for TLS 1.2 support
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$domain = $env:USERDNSDOMAIN
$userPrincipalName = "admin@yourtenant.onmicrosoft.com"
$domainCred = Get-Credential

Set-AzureADKerberosServer -Domain $domain -UserPrincipalName $userPrincipalName -DomainCredential $domainCred
```

> ✅ This creates an `AzureADKerberos` object in the Domain Controllers OU.  
> You can verify it with:
```powershell
Get-AzureADKerberosServer -Domain $domain -UserPrincipalName $userPrincipalName
```

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-03-58.png)

---

## 2. ✅ Configure Entra Connect Authentication Type

Cloud Kerberos Trust works with:

- **Password Hash Synchronization (PHS)** ✅ Recommended
- **Pass-through Authentication (PTA)**
- **Federation authN with ADFS**

Ensure your tenant uses one of these, and verify that **Hybrid Join is enabled** via “Device Options” in Entra ID Connect.

---

## 3. ✅ Configure Windows Hello for Business via Intune or GPO

You must enable **Windows Hello for Business** and configure it to use **Cloud Kerberos Trust**.


### 🔧 Intune Settings Catalog (Recommended)

1. Go to **Intune Admin Center** → Devices → Configuration Profiles
2. Create a new profile:
   - Platform: Windows 10 and later
   - Profile Type: Settings Catalog

3. Add these settings:
   - `Use Windows Hello for Business` → Enabled
   - `UseCloudTrustForOnPremAuth` → Enabled
   - `Use a hardware security device` → Enabled

> ⚠️ The “(User)” scope setting will apply per user even if targeting devices.


### 🛠️ GPO Equivalent

| Path | Setting | Value |
|------|---------|-------|
| Computer/User Configuration > Administrative Templates > Windows Components > Windows Hello for Business | Use Windows Hello for Business | Enabled |
| Computer Configuration > Windows Hello for Business | Use cloud Kerberos trust for on-premises authentication | Enabled |
| Computer Configuration > Windows Hello for Business | Use a hardware security device | Enabled |

---

## 4. ✅ Optional: Configure Additional Cloud Kerberos OMA-URIs (Custom CSP)

If you use **Custom Profiles in Intune**, you can manually define OMA-URIs.


### Enable Cloud Kerberos Ticket Retrieval

```
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Kerberos/CloudKerberosTicketRetrievalEnabled
Data type: Integer
Value: 1
```

### Enable WHfB Cloud Trust

```
OMA-URI: ./Device/Vendor/MSFT/PassportForWork/{TenantID}/Policies/UseCloudTrustForOnPremAuth
Data type: Boolean
Value: True
```

> 📌 Replace `{TenantID}` with your actual Entra tenant ID.

---


# 🔍 Validate Configuration and Functionality

After deployment, validate using the following tools:

**🧪 klist cloud_debug**  
Shows if a **partial TGT** has been issued to the client.

```cmd
klist cloud_debug
```

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-11-48.png)

If nothing appears, you can trigger a PRT refresh with:

```cmd
dsregcmd /refreshprt
```

**📊 dsregcmd /status**  
Check:
```
AzureAdJoined : YES
DomainJoined : NO or YES (depending on Hybrid join)
OnPremTgt : YES
CloudTgt  : YES
```

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-13-16.png)

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-13-50.png)

**📋 Event Viewer**
- Go to: `Applications and Services Logs > Microsoft > Windows > User Device Registration`
- Look for **Event ID 358** to confirm WHfB and Cloud Kerberos Trust policy was applied.

![](assets/How%20Works%20Cloud%20Kerberos%20Trust/2025-05-11-22-18-06.png)

**🛠 Common Issues & Fixes**

| Symptom                                 | Possible Cause                          | Resolution                                            |
| --------------------------------------- | --------------------------------------- | ----------------------------------------------------- |
| ❌ `klist cloud_debug` shows nothing     | PRT not issued or WHfB not active       | Run `dsregcmd /refreshprt`, verify WHfB               |
| ❌ SSO fails to on-prem share            | DC unreachable or signature invalid     | Check DNS, firewall, AzureADKerberos object, patch DC |
| ❌ No `OnPremTgt`                        | Incorrect domain attributes in Entra ID | Verify sync of `onPremisesDomainName` and SID         |
| ❌ Event ID 358 missing                  | Policy not applied                      | Recheck Intune/GPO assignment and sync status         |
| ❌ User prompted for password at sign-in | WHfB not provisioned                    | Enforce WHfB policy, check TPM and PIN enrollment     |


---

## 🔄 Rotate AzureADKerberos Keys (Optional)

For security hygiene, rotate the key used by the `AzureADKerberos` object:

```powershell
Set-AzureADKerberosServer -Domain "yourdomain.com" -RotateServerKey
```

This is similar to rotating the `krbtgt` password and helps mitigate long-term key compromise.



# ✅ Summary

Cloud Kerberos Trust bridges the cloud and on-prem worlds by allowing Entra ID to kickstart Kerberos authentication securely. It simplifies the infrastructure required for Windows Hello for Business and dramatically **reduces setup complexity** while **preserving compatibility** with on-prem Active Directory resources.

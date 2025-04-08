---
title: "Do I really need ADFS?"
date: 2025-04-08
---

## Do I Really Need ADFS?

> _This article builds on the classic post by Pierre Audonnet in 2017 ([source](https://blogs.technet.microsoft.com/pie/2017/02/06/do-i-really-need-adfs/)) and integrates recent developments and best practices in identity management._

### Introduction
In recent years, the access management landscape has evolved drastically. With the rise of cloud adoption, hybrid working, and modern authentication, many of the traditional reasons for deploying Active Directory Federation Services (ADFS) are now challenged by cloud-native alternatives like Azure Active Directory (Azure AD), now part of **Microsoft Entra ID**.

Let's explore whether ADFS is still necessary, and what alternatives Microsoft offers today.

---

### What Is ADFS?
Active Directory Federation Services is an on-premises identity federation solution that allows organizations to use their Windows credentials to access third-party or cloud applications. It supports protocols like SAML, OAuth, and WS-Federation.

Historically, ADFS was required to:
- Enable Single Sign-On (SSO) for Office 365 and other apps
- Maintain authentication fully on-premises
- Avoid password hash synchronization to Azure
- Support custom claims and third-party MFA providers
- Handle legacy scenarios like Windows 7 device registration

However, ADFS has downsides:
- Requires deploying and managing infrastructure (redundant servers, proxies, certificates)
- Higher operational complexity
- Limited insight and monitoring without third-party tools

---

### What Is Azure AD (Microsoft Entra ID)?
Azure AD is Microsoft’s cloud-native identity platform. It provides:

- SSO to SaaS apps (Microsoft 365, Salesforce, Dropbox, etc.)
- Modern MFA (SMS, Authenticator App, FIDO2, biometrics)
- Conditional Access policies
- Identity governance and risk detection
- Seamless integration with on-prem AD via Azure AD Connect

Azure AD supports multiple authentication methods:
- **Password Hash Sync (PHS)**
- **Pass-Through Authentication (PTA)**
- **Federation (with ADFS)**

With the introduction of **PTA** in 2017, it became possible to authenticate on-prem users without deploying ADFS.

---

### Why You Might Still Need ADFS
ADFS may still be useful if:
- You have apps requiring SAML 1.1 or custom claims not supported in Azure AD
- Your organization mandates that **all authentication occurs on-premises**
- You use legacy operating systems or applications not compatible with modern auth
- You require support for **custom MFA solutions** not yet supported in Azure
- You have complex hybrid trusts (e.g., multi-tenant AD forests)

However, these cases are becoming rare.

---

### Modern Alternatives That Shrink ADFS Use Cases
Microsoft has added several capabilities to Azure AD that cover most traditional ADFS needs:

#### ✅ **Azure AD Pass-Through Authentication (PTA)**
Authenticates users directly against your on-prem DC via a lightweight agent. No passwords stored in the cloud.

#### ✅ **Seamless SSO with Azure AD Connect**
Provides Windows Integrated Auth to domain-joined devices without ADFS.

#### ✅ **FIDO2 and Windows Hello for Business**
You can now implement **passwordless authentication** with biometric devices, security keys or PINs – no ADFS required.

#### ✅ **Certificate-Based Authentication (CBA)**
Supported natively in Azure AD, allowing smart card or certificate auth.

#### ✅ **External Authentication Methods**
Azure AD now lets you plug in third-party MFA providers via the [External Authentication Methods](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-policy#external-authentication-method) feature.

---

### Considerations for Migration
If you're still using ADFS solely for federated Azure AD login, consider switching to PTA or PHS. Microsoft provides:
- [Migration guide](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-migrate-adfs-pass-through-authentication)
- [SaaS integration tutorials](https://docs.microsoft.com/en-us/azure/active-directory/saas-apps/tutorial-list)

You can use flowcharts like [this one](https://github.com/kennethvs/blog/blob/master/Azure%20AD%20authentication%20integration%20flowchart.pdf) to evaluate your options.

---

### Summary: ADFS vs. Azure AD (Entra ID)
| Feature | ADFS | Azure AD |
|--------|------|----------|
| Hosting | On-prem | Cloud-native |
| Passwordless (FIDO2, WHfB) | ⚠️ (complex setup) | ✅ |
| Certificate Auth | ⚠️ (complex setup) | ✅ (native support) |
| Custom Claims | ✅ | Limited |
| MFA Options | External via claims rules | Native, Conditional Access, External Auth Methods |
| Self-Service Password Reset | ❌ | ✅ |
| App Monitoring | ⚠️ (complex setup) | ✅ (Azure insights) |
| Setup Complexity | High | Low |

---

### Final Thoughts
Today, the **default recommendation** from Microsoft is to use **PHS** or **PTA** for hybrid identity unless you have very specific use cases requiring ADFS. Most legacy scenarios are now supported natively in Azure AD.

If you're already on ADFS, it’s worth considering a **migration to cloud-native auth** to reduce cost, simplify infrastructure, and enhance your security posture.

---

### Sources
- Original article by Pierre Audonnet (2017) — [Technet Blog](https://blogs.technet.microsoft.com/pie/2017/02/06/do-i-really-need-adfs/)
- Microsoft Docs — [Pass-through Authentication](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-pta)
- Sherweb — [Azure AD vs. ADFS Guide](https://www.sherweb.com/blog/)
- GitHub — [Azure AD Authentication Flowchart](https://github.com/kennethvs/blog/blob/master/Azure%20AD%20authentication%20integration%20flowchart.pdf)

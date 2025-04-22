---
title: "Azure Managed Identities & Service Principals – Overview & Recommendations"
date: 2021-05-24
---

## Azure Managed Identities & Service Principals – Overview & Recommendations

---

## 🎯 Objectives

- Understand **Managed Identities** in Azure
- Clarify what **Service Principals** are and how they’re used
- Explore security and lifecycle considerations
- Demonstrate authentication flows without credentials
- Review best practices

---

## 🧠 What Are Managed Identities in Azure AD?

### ❓ Why Use Managed Identities?

When an Azure resource (like a VM or Function App) needs to access another Azure resource (like a Key Vault or Storage Account), storing credentials in code is insecure.

![](assets/System%20Managed%20Identities/2025-04-22-15-28-20.png)

**Managed Identity (MI)** solves this by assigning an identity to the resource so it can authenticate directly with Azure AD.

### 🔑 Example Flow

1. A VM requests a token from Azure AD for access to a Storage Account.
2. Azure AD validates the identity and issues the token.
3. The VM uses this token for authenticated API calls.


![](assets/System%20Managed%20Identities/2025-04-22-15-28-59.png)


---

## 🔄 Types of Managed Identities

| Type              | Description                         |
|-------------------|-------------------------------------|
| System-Assigned   | 1:1 relationship with a resource    |
| User-Assigned     | 1:Many – reusable across resources  |

![](assets/System%20Managed%20Identities/2025-04-22-15-29-26.png)

![](assets/System%20Managed%20Identities/2025-04-22-15-29-39.png)

Benefits:

- **No secrets in code**
- **Lifecycle tied to resource (for system-assigned)**
- **No extra cost**
- **RBAC integrated natively**

📚 [Azure Services that support Managed Identities](https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/services-support-managed-identities)

---

## 🔐 Service Principals in Azure

When an application is registered in Azure AD, it creates:

- An **Application Object** (global, static)
- A **Service Principal** (tenant-scoped, instance of the app)

![](assets/System%20Managed%20Identities/2025-04-22-15-32-03.png)



Service Principals are how **apps authenticate and get permissions** in your tenant.

### 🔁 Typical Flow

1. Register App in Azure AD
2. Define app permissions & secrets
3. Consent to app usage
4. Use SP for scripting or automation scenarios


![](assets/System%20Managed%20Identities/2025-04-22-15-32-50.png)

![](assets/System%20Managed%20Identities/2025-04-22-15-33-20.png)

![](assets/System%20Managed%20Identities/2025-04-22-15-33-43.png)

---

## ✅ Advantages of Service Principals

- Enable **script-based authentication** via secrets or certificates
- Support **MFA bypass** for automation (while maintaining control)
- Fine-grained **permission scopes**
- Visible and manageable via the **Enterprise Applications** blade

---

## 🔐 Consent & Multi-Tenant Access

- Apps can be marked **multi-tenant** and shared across organizations
- **Consent** is needed for each tenant
- SPs are created in each tenant referencing the same App object

---

## 📦 Use Case Matrix

| Feature                                | Managed Identity        | Service Principal         |
|----------------------------------------|--------------------------|----------------------------|
| No secrets in code                     | ✅ Yes                   | ❌ Requires secrets/certs  |
| Resource-bound identity                | ✅ System-assigned only  | ❌                         |
| Reusable across resources              | ✅ User-assigned only    | ✅                         |
| App-to-App authentication              | ❌                       | ✅                         |
| Automation scenarios                   | ✅                       | ✅                         |
| Granular RBAC                          | ✅                       | ✅                         |

---

## 📌 Final Thoughts

Azure Managed Identities and Service Principals are powerful tools to enable secure, scalable identity for your apps and services in the cloud. Properly choosing between them (or using both together) is key to simplifying identity management and reducing risk.

---

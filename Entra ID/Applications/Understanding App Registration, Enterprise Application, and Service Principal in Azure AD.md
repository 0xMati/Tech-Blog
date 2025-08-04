# Understanding App Registration, Enterprise Application, and Service Principal in Azure AD
🗓️ Published: 2025-08-04  

When working with Azure Active Directory (Azure AD), you’ll often encounter the terms **App Registration**, **Enterprise Application**, and **Service Principal**. These foundational concepts for managing applications and their access can be confusing. This article clarifies what each term means and how they relate to each other, following official Microsoft definitions.

---

## 1. App Registration

- **Definition**: An App Registration is the global definition or blueprint of an application in Azure AD.
- **Purpose**: It describes the application's identity, configuration, and permissions.
- **Scope**: Exists once per application, typically in the developer’s tenant.
- **Contents**:
  - Application (client) ID
  - Redirect URIs
  - API permissions requested
  - Certificates and secrets
  - Branding information

**In short**: It’s the application’s global “profile” or “identity template.”

![](assets/Understanding%20App%20Registration,%20Enterprise%20Application,%20and%20Service%20Principal%20in%20Azure%20AD/2025-08-05-00-29-37.png)

---

## 2. Service Principal (Enterprise Application)

- **Definition**: A Service Principal is the **identity object** in Azure AD that represents the application in a specific tenant.
- **Relation to Enterprise Application**:  
  The term **Enterprise Application** refers to the **representation of the Service Principal in the Azure portal**. Essentially, **Enterprise Applications are the portal interface to manage Service Principals**.

- **Purpose**:
  - Provides an identity for the app in the tenant
  - Enables authentication and authorization within the tenant
  - Controls permissions, user assignments, and policies scoped to the tenant

- **Scope**: Each tenant that uses an application has its own Service Principal (Enterprise Application) for that app.

**In short**:  
- The **Service Principal** is the backend Azure AD object representing the app's identity in the tenant.  
- The **Enterprise Application** is the name for that object as displayed and managed in the Azure portal.

---

## How They Work Together

| Concept             | What It Represents                     | Where It Lives                  | Role                                      |
|---------------------|---------------------------------------|--------------------------------|-------------------------------------------|
| App Registration    | The global app definition (template)  | Developer’s (or publishing) tenant | Defines app’s identity and configuration  |
| Service Principal (Enterprise Application) | Instance of app in a tenant           | Each tenant using the app       | Enables app authentication, authorization, and tenant-specific management |

An application must have an associated Enterprise Application (Service Principal) in a tenant in order to be used within that tenant. This is why in the developer’s tenant you typically see both the App Registration (the application definition) and the Service Principal (the instance of that app), allowing the app to authenticate and be authorized in that environment.

![](assets/Understanding%20App%20Registration,%20Enterprise%20Application,%20and%20Service%20Principal%20in%20Azure%20AD/2025-08-05-00-37-38.png)

---

## Example Scenario

1. A developer creates an App Registration for their application in their Azure AD tenant.  
2. An organization wants to use this application, so when they consent to it, Azure AD creates a Service Principal (represented as an Enterprise Application in the portal) in their tenant.  
3. The organization manages access, user assignments, and policies on this Service Principal (Enterprise Application).


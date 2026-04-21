---
title: "SharePoint Online Conditional Access Without Impacting Teams"
date: 2026-04-21
---

## Controlling SharePoint Online Access Without Impacting Teams

A common challenge in Microsoft 365 environments is applying **Conditional Access restrictions on SharePoint Online** (e.g., IP-based filtering) **without breaking the Teams experience**. This article explores the root cause of this coupling and the available approaches to decouple them.

---

### The Problem: SharePoint Online and Teams Are Tightly Coupled

When users access files in **Microsoft Teams** — whether through the Files tab, shared documents in chats, or channel file libraries — Teams relies on **SharePoint Online** (and OneDrive for Business) as the underlying storage backend.

From an authentication perspective, accessing a file in Teams triggers a token request to the **SharePoint Online** cloud application (`Office 365 SharePoint Online` — AppId `00000003-0ff1-ce00-0000-000000000002`).

This means:

- Any Conditional Access policy targeting the **SharePoint Online cloud app** also affects file access in Teams
- IP-based restrictions on SharePoint Online will block users from opening, editing, or downloading files in Teams from untrusted networks
- It is **not possible** to create a single CA policy that blocks direct SharePoint browsing while allowing Teams file access, because both use the same service principal

---

### Use Case: External Collaboration With Security Controls

A typical scenario driving this challenge:

- An organization wants to **open SharePoint to external collaboration** (B2B guests)
- The security team requires that **internal users on unmanaged devices or untrusted IPs** cannot access SharePoint directly
- However, **Teams must remain accessible** from any location for real-time collaboration
- A global IP filter on SharePoint is too broad and also blocks Teams file operations

---

## Approach 1: Authentication Context (Recommended)

### Concept

**Authentication Contexts** allow you to apply Conditional Access policies at a **granular, per-site level** rather than at the application level. Instead of targeting the SharePoint Online cloud app globally, you assign an authentication context to specific SharePoint sites.

### How It Works

1. An **Authentication Context** is created in Entra ID (e.g., `Restricted SPO Access`)
2. A **Conditional Access policy** targets this Authentication Context (not the SPO app) with the IP restriction condition
3. The Authentication Context is **assigned to specific SharePoint sites** via sensitivity labels or PowerShell
4. When a user accesses a protected site, the authentication context triggers the CA policy — but only for that site

### Configuration Steps

**Step 1 — Create the Authentication Context**

1. Go to **Entra ID Admin Center** → **Protection** → **Conditional Access** → **Authentication Contexts**
2. Click **+ New authentication context**
3. Name it (e.g., `Restricted SPO Access`) and note the ID (e.g., `c1`)
4. Mark it as available for use in Conditional Access

**Step 2 — Create the Conditional Access Policy**

1. Go to **Conditional Access** → **+ New Policy**
2. **Assignments:**
   - Users: All users (or scoped group)
   - **Target resources** → Select **Authentication context** → Choose `Restricted SPO Access`
3. **Conditions:**
   - **Locations** → Include: Any location / Exclude: Trusted locations (your corporate IPs)
4. **Access controls:**
   - **Grant** → Block access
5. Enable policy in **Report-only** mode first

**Step 3 — Assign to SharePoint Sites**

Option A — Via **Microsoft Purview Sensitivity Labels**:

1. Create a sensitivity label in Microsoft Purview with **Sites and Groups** scope
2. In the label settings, associate the Authentication Context `Restricted SPO Access`
3. Apply this label to the target SharePoint sites

Option B — Via **PowerShell** (SharePoint Online Management Shell):

```powershell
# Connect to SharePoint Online
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# Assign authentication context to a site
Set-SPOSite -Identity https://contoso.sharepoint.com/sites/ConfidentialSite `
    -ConditionalAccessPolicy AuthenticationContext `
    -AuthenticationContextName "Restricted SPO Access"
```

### Impact on Teams

| Action | Impact |
|---|---|
| Teams chat & meetings | ✅ No impact |
| Files tab in Teams (non-protected site) | ✅ No impact |
| Files tab in Teams (protected site) | ⚠️ CA policy applies — blocked from untrusted IP |
| Direct SPO browsing (protected site) | 🚫 Blocked from untrusted IP |
| Direct SPO browsing (unprotected site) | ✅ No impact |

### Licensing

- **Microsoft Entra ID P1** (for Conditional Access)
- **Microsoft Purview Information Protection** (if using sensitivity labels)

---

## Approach 2: SharePoint Advanced Management — Restricted Access Control

### Concept

**Restricted Access Control (RAC)** is a feature of **SharePoint Advanced Management** that allows restricting access to SharePoint sites based on **Entra ID security group membership** and **Conditional Access policy compliance**, at the **site level**.

### How It Works

1. A site-level access policy is defined for specific SharePoint sites
2. Only users in a designated security group — and who meet the associated CA policy — can access the site
3. Other users (including those accessing via Teams) are blocked from that specific site

### Configuration Steps

**Step 1 — Enable Restricted Access Control for a site**

```powershell
# Connect to SharePoint Online
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# Enable RAC on a specific site
Set-SPOSite -Identity https://contoso.sharepoint.com/sites/RestrictedSite `
    -RestrictedAccessControl $true
```

**Step 2 — Add an authorized security group**

```powershell
# Only members of this group can access the site
Set-SPOSite -Identity https://contoso.sharepoint.com/sites/RestrictedSite `
    -AddRestrictedAccessControlGroups "SPO-Restricted-Users"
```

**Step 3 — Combine with Conditional Access**

Create a CA policy targeting the security group with IP restrictions. Only group members on trusted IPs will be able to access the protected site.

### Impact on Teams

Same behavior as Authentication Context: the restriction applies at the site level, so Teams file access to protected sites is affected, but Teams messaging and meetings are not.

### Licensing

- **SharePoint Advanced Management** add-on license

---

## Approach 3: Session Controls with App-Enforced Restrictions

### Concept

Instead of **blocking** access entirely, this approach uses **session controls** to limit what users can **do** on SharePoint from untrusted locations — for example, allowing read-only access but blocking downloads.

### How It Works

1. A Conditional Access policy targets SharePoint Online with **session controls**
2. SharePoint applies **app-enforced restrictions** based on the session context
3. From untrusted IPs: users can **view** but cannot **download, print, or sync**

### Configuration Steps

**Step 1 — Create the Conditional Access Policy**

1. Go to **Conditional Access** → **+ New Policy**
2. **Assignments:**
   - Users: All users
   - **Target resources** → Cloud apps → **Office 365 SharePoint Online**
3. **Conditions:**
   - **Locations** → Include: Any location / Exclude: Trusted locations
4. **Session controls:**
   - ✅ **Use app-enforced restrictions**
5. Enable in **Report-only** first

**Step 2 — Configure SharePoint Access Control**

1. Go to **SharePoint Admin Center** → **Policies** → **Access control**
2. Under **Unmanaged devices**, select **Allow limited, web-only access**

### Impact on Teams

| Action | Trusted IP | Untrusted IP |
|---|---|---|
| Teams chat & meetings | ✅ Full | ✅ Full |
| Open files in Teams | ✅ Full | ⚠️ View-only (web) |
| Download files from Teams | ✅ Full | 🚫 Blocked |
| Print/sync from Teams | ✅ Full | 🚫 Blocked |
| Direct SPO browsing | ✅ Full | ⚠️ View-only (web) |

> **Note:** This approach affects **all SharePoint sites globally** and applies to Teams file operations as well. It does not block access but limits actions.

### Licensing

- **Microsoft Entra ID P1**

---

## Approach 4: Microsoft Defender for Cloud Apps — Session Policies

### Concept

For more **granular control**, Microsoft Defender for Cloud Apps (formerly MCAS) provides **session policies** that can apply per-action, per-file-type, and per-label restrictions.

### How It Works

1. A Conditional Access policy routes sessions through **Conditional Access App Control**
2. Defender for Cloud Apps inspects the session in real time
3. Policies can block downloads based on sensitivity labels, file types, user groups, or network locations

### Configuration Steps

**Step 1 — Create the Conditional Access Policy**

1. **Target resources**: Office 365 SharePoint Online
2. **Conditions**: Locations → Any / Exclude trusted
3. **Session controls**: ✅ **Use Conditional Access App Control** → Monitor only (or Block downloads)

**Step 2 — Create Session Policy in Defender for Cloud Apps**

1. Go to **Microsoft Defender Portal** → **Cloud Apps** → **Policies** → **Session policies**
2. Create a policy:
   - Activity type: **File download**
   - Filter: Source IP ≠ trusted ranges
   - Action: **Block** or **Protect** (apply encryption on download)
3. Optionally add filters:
   - Sensitivity label = Confidential → Block
   - File type = Office documents → Allow with watermark

### Impact on Teams

- Sessions routed through the proxy can add latency
- Very granular control: per-file, per-label, per-action
- Can differentiate between Teams file access and direct SPO browsing using the **User Agent** or **App** filter

### Licensing

- **Microsoft Defender for Cloud Apps** (standalone or as part of Microsoft 365 E5 Security)
- **Microsoft Entra ID P1**

---

## Comparison Summary

| Criteria | Auth Context | SPO Advanced Mgmt (RAC) | App-Enforced Restrictions | Defender for Cloud Apps |
|---|---|---|---|---|
| **Granularity** | Per site | Per site | Global (all SPO) | Per action / per file |
| **Impact on Teams** | Only protected sites | Only protected sites | All file operations | Configurable |
| **Action type** | Block access | Block access | Limit actions | Block / Monitor / Protect |
| **External users** | ✅ Supported | ✅ Supported | ✅ Supported | ✅ Supported |
| **Complexity** | Medium | Low | Low | High |
| **Licensing** | Entra ID P1 + Purview | SPO Advanced Mgmt | Entra ID P1 | Defender for Cloud Apps |

---

## ✅ Best Practices

- **Start with Report-Only mode** on all CA policies before enforcing
- **Pilot with a small group** of users before broad deployment
- **Segment your SharePoint sites**: separate sites for external collaboration from internal-only sites
- **Document your named locations** and keep trusted IP ranges up to date
- **Combine approaches**: use Authentication Context for high-security sites, and App-Enforced Restrictions as a baseline for all SPO access
- **Monitor Sign-in logs** in Entra ID to verify policies are applied as expected
- For **B2B external collaboration**, remember that guest users are subject to **both** your CA policies and their home tenant's cross-tenant access settings

---

## ⚠️ Key Considerations for External Collaboration

When opening SharePoint to B2B guests:

1. **Cross-Tenant Access Settings**: Configure inbound trust settings in Entra ID → External Identities → Cross-tenant access settings
2. **Sharing policies**: Adjust SharePoint sharing settings per site (SharePoint Admin Center → Sites → select site → Sharing)
3. **Guest CA policies**: Consider creating dedicated CA policies for guest users (`All guest and external users`) with appropriate controls
4. **Authentication Context and guests**: If a guest accesses a site with an Authentication Context, the CA policy applies to them as well — ensure trusted locations include partner networks if needed

---

### 📚 References

- [Authentication Context in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context)
- [SharePoint and OneDrive integration with Authentication Context](https://learn.microsoft.com/en-us/sharepoint/authentication-context-example)
- [Control access from unmanaged devices](https://learn.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices)
- [Restricted Access Control in SharePoint Advanced Management](https://learn.microsoft.com/en-us/sharepoint/restricted-access-control)
- [Session policies in Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/session-policy-aad)
- [Configure cross-tenant access for B2B collaboration](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration)

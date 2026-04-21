---
title: "SharePoint Online Conditional Access Without Impacting Teams"
date: 2026-04-21
---

## Controlling SharePoint Online Access Without Impacting Teams

A common challenge in Microsoft 365 environments is applying **Conditional Access restrictions on SharePoint Online** (e.g., IP-based filtering) **without breaking the Teams experience**.

This article explains why this happens, explores the available approaches, and recommends a **combined strategy** that works at scale.

> **TL;DR** — You can't block SPO without impacting Teams file access, because both use the same service principal. The recommended approach is a **3-layer strategy**: a global baseline with App-Enforced Restrictions (view-only from untrusted IPs), Authentication Context for critical sites (total block), and no restriction on sites opened to externals.

---

## The Problem

### Why SharePoint and Teams Are Coupled

When users access files in **Microsoft Teams** — through the Files tab, shared documents in chats, or channel file libraries — Teams calls **SharePoint Online** in the backend.

From an authentication perspective, both actions request a token for the same cloud application:

| User action | Cloud app called |
|---|---|
| Browse `contoso.sharepoint.com/sites/Marketing` | `Office 365 SharePoint Online` |
| Open a file from the Teams Files tab | `Office 365 SharePoint Online` |
| Share a file in a Teams chat | `Office 365 SharePoint Online` |

Same service principal (`AppId 00000003-0ff1-ce00-0000-000000000002`) = same Conditional Access policies apply.

**Consequence**: any CA policy targeting the SharePoint Online cloud app — including IP-based restrictions — will also block file operations in Teams.

### A Concrete Example

Contoso has a global IP filter on SharePoint Online. An employee working from home opens Teams:

- Chat and meetings work fine
- They click on the **Files** tab in a Teams channel → **blocked** (the request goes to SharePoint Online, which checks the IP)
- They try to open a shared document from a Teams chat → **blocked**

This is exactly the situation the security team did not intend.

---

## Real-World Use Case

A defense organization wants to:

1. **Open certain SharePoint sites to external partners** (B2B guests with identities in the corporate directory)
2. **Keep IP restrictions for internal users** — employees must connect from a trusted device/IP to access SharePoint
3. **Not break Teams** — chat, meetings, and file access in Teams must remain usable from any location

Their current setup: a **global IP filter on SPO**. They planned to replace it with Conditional Access policies, but quickly discovered that **any CA targeting SPO also breaks Teams file access**.

> The following approaches solve this problem with different trade-offs.

---

## Approach 1: Authentication Context

### Concept

**Authentication Contexts** let you apply Conditional Access at the **site level** instead of the application level. You tag specific SharePoint sites with a context, and the CA policy only triggers when users access those sites.

### How It Works

```
User accesses site → Site has Auth Context? 
  → Yes → CA policy evaluates (IP check) → Grant or Block
  → No  → No additional check, normal access
```

### Configuration

**Step 1 — Create the Authentication Context**

1. **Entra ID Admin Center** → **Protection** → **Conditional Access** → **Authentication Contexts**
2. Click **+ New authentication context**
3. Name it (e.g., `Restricted SPO Access`) and note the ID (e.g., `c1`)

**Step 2 — Create the Conditional Access Policy**

1. **Conditional Access** → **+ New Policy**
2. **Target resources** → Select **Authentication context** → `Restricted SPO Access`
3. **Conditions** → **Locations** → Include: Any location / Exclude: Trusted locations
4. **Grant** → Block access
5. Enable in **Report-only** first

**Step 3 — Assign to SharePoint Sites**

Via **PowerShell**:

```powershell
Connect-SPOService -Url https://contoso-admin.sharepoint.com

Set-SPOSite -Identity https://contoso.sharepoint.com/sites/ConfidentialProject `
    -ConditionalAccessPolicy AuthenticationContext `
    -AuthenticationContextName "Restricted SPO Access"
```

Or via **Microsoft Purview Sensitivity Labels**: create a label with Sites and Groups scope, associate the Authentication Context, and apply the label to target sites.

### Impact on Teams

| Action | Result |
|---|---|
| Teams chat and meetings | No impact |
| Files tab (non-protected site) | No impact |
| Files tab (protected site) | Blocked from untrusted IP |
| Direct SPO browsing (protected site) | Blocked from untrusted IP |
| Direct SPO browsing (unprotected site) | No impact |

### Operational Consideration

With Authentication Context, you tag the **sites to protect** — not the sites to open. If your tenant has hundreds of sites, you would need to tag all of them except the few opened to externals. **Any forgotten site has no IP restriction.**

This makes Authentication Context alone impractical at scale. It works best for a **small number of high-security sites**, combined with a global baseline (see Recommended Strategy below).

### Licensing

- Microsoft Entra ID P1
- Microsoft Purview Information Protection (if using sensitivity labels)

---

## Approach 2: SharePoint Advanced Management — Restricted Access Control

### Concept

**Restricted Access Control (RAC)** restricts access to specific SharePoint sites based on **security group membership**. Only members of a designated group can access the site.

### Configuration

```powershell
Connect-SPOService -Url https://contoso-admin.sharepoint.com

# Enable RAC
Set-SPOSite -Identity https://contoso.sharepoint.com/sites/RestrictedSite `
    -RestrictedAccessControl $true

# Allow only members of this group
Set-SPOSite -Identity https://contoso.sharepoint.com/sites/RestrictedSite `
    -AddRestrictedAccessControlGroups "SPO-Restricted-Users"
```

Then create a CA policy targeting the security group with IP restrictions. Only group members connecting from trusted IPs can access the site.

### Impact on Teams

Same as Authentication Context: restriction applies at the site level. Teams messaging and meetings are not affected, but file access to protected sites is.

### Operational Consideration

Same limitation as Authentication Context — this is a **per-site** control. You must enable RAC on every site you want to protect. Forgotten sites have no restriction. Use it for a small number of critical sites, not as a global strategy.

### Licensing

- SharePoint Advanced Management add-on

---

## Approach 3: App-Enforced Restrictions (View-Only Baseline)

### Concept

Instead of **blocking** access, this approach **limits what users can do** from untrusted locations. Users can view documents but cannot download, print, or sync them. This applies **globally to all SharePoint sites** — no per-site tagging needed.

### How It Works

```
User on untrusted IP accesses any SPO site
  → Can view documents in the browser ✓
  → Cannot download, print, or sync ✗
```

### Configuration

**Step 1 — Conditional Access Policy**

1. **Target resources** → Cloud apps → **Office 365 SharePoint Online**
2. **Conditions** → **Locations** → Include: Any location / Exclude: Trusted locations
3. **Session controls** → Check **Use app-enforced restrictions**
4. Enable in **Report-only** first

**Step 2 — SharePoint Admin Center**

1. **Policies** → **Access control** → **Unmanaged devices**
2. Select **Allow limited, web-only access**

### Impact on Teams

| Action | Trusted IP | Untrusted IP |
|---|---|---|
| Teams chat and meetings | Full access | Full access |
| Open files in Teams | Full access | View-only (web) |
| Download files from Teams | Full access | Blocked |
| Print/sync from Teams | Full access | Blocked |
| Direct SPO browsing | Full access | View-only (web) |

> This approach affects **all SharePoint sites globally**, including Teams file operations. It does not block access — it limits actions. This makes it ideal as a **baseline**.

### Licensing

- Microsoft Entra ID P1

---

## Approach 4: Defender for Cloud Apps — Session Policies

### Concept

For **granular, per-action control**, Microsoft Defender for Cloud Apps provides **session policies** that can filter by action type, file label, file type, and network location.

### Configuration

**Step 1 — Conditional Access Policy**

1. **Target resources** → Office 365 SharePoint Online
2. **Conditions** → Locations → Any / Exclude trusted
3. **Session controls** → Check **Use Conditional Access App Control**

**Step 2 — Session Policy in Defender Portal**

1. **Microsoft Defender Portal** → **Cloud Apps** → **Policies** → **Session policies**
2. Create a policy:
   - Activity type: **File download**
   - Filter: Source IP ≠ trusted ranges
   - Action: **Block** (or **Protect** — encrypt on download)
3. Optional filters:
   - Block downloads of files labeled "Confidential"
   - Allow download of non-sensitive files with watermark

### Example

> A user on an untrusted IP opens a Teams channel. They can view all files. They try to download a document labeled "Confidential" → blocked. They download an unlabeled document → allowed, but a watermark is applied.

### Considerations

- Sessions are routed through a **reverse proxy**, which can add latency
- The most flexible approach, but also the most **complex to configure and maintain**
- Can use **User Agent** or **App** filters to differentiate Teams vs. direct SPO browsing

### Licensing

- Microsoft Defender for Cloud Apps (or Microsoft 365 E5 Security)
- Microsoft Entra ID P1

---

## Recommended Strategy: Combine Approaches

For large tenants, the most practical approach is a **3-layer strategy**:

### Layer 1 — Global Baseline: App-Enforced Restrictions

Apply Approach 3 across all SharePoint Online:

- **All users** on untrusted IPs get **view-only access** — no download, no sync, no print
- Covers every site automatically, no tagging needed
- Prevents data exfiltration while keeping content accessible
- Teams file access works (view-only from untrusted IPs)

### Layer 2 — Critical Sites: Authentication Context

For the few sites that need a **total block** from untrusted IPs (not even view-only):

- Apply an Authentication Context with a blocking CA policy
- Only tag the **handful of high-security sites**
- Much more manageable than tagging every site

### Layer 3 — External Collaboration Sites

Sites opened to B2B guests:

- No Authentication Context → subject to the global baseline only
- Configure sharing settings per site
- Optionally exclude from the baseline if the security team accepts full access for externals

### Concrete Example

Contoso has 500 SharePoint sites:

| Category | Count | Strategy | Behavior from untrusted IP |
|---|---|---|---|
| Standard internal sites | ~480 | Baseline only | View-only, no download |
| High-security projects | ~10 | Auth Context + Baseline | Fully blocked |
| External collaboration | ~10 | Baseline only (or excluded) | View-only or full access |

Only **10 sites** need to be tagged with an Authentication Context. The other 490 are covered by the global baseline.

> **Key question for the security team**: Is view-only access (no download/sync/print) from untrusted IPs an acceptable baseline? If yes, this strategy avoids tagging hundreds of sites while maintaining strong protection.

---

## Comparison Summary

| Criteria | Auth Context | SPO Advanced Mgmt | App-Enforced Restrictions | Defender for Cloud Apps |
|---|---|---|---|---|
| Granularity | Per site | Per site | Global (all SPO) | Per action / per file |
| Impact on Teams | Protected sites only | Protected sites only | All file operations | Configurable |
| Action type | Block access | Block access | Limit actions | Block / Monitor / Protect |
| External users | Supported | Supported | Supported | Supported |
| Per-site tagging | Required | Required | Not needed | Not needed |
| Complexity | Medium | Low | Low | High |
| Licensing | Entra ID P1 + Purview | SPO Advanced Mgmt | Entra ID P1 | Defender for Cloud Apps |

---

## Considerations for External Collaboration (B2B)

When opening SharePoint to external guests:

1. **Cross-Tenant Access Settings** — Configure inbound trust in Entra ID → External Identities → Cross-tenant access settings. This controls whether you trust MFA and device compliance from the partner tenant.

2. **Per-site sharing settings** — Adjust sharing at the site level (SharePoint Admin Center → Sites → Sharing). Don't open sharing tenant-wide.

3. **Dedicated CA policies for guests** — Consider creating specific policies for `All guest and external users` with appropriate controls (e.g., require MFA, block from certain locations).

4. **Authentication Context and guests** — If a guest accesses a site tagged with an Authentication Context, the CA policy applies to them too. Make sure trusted locations include partner networks if needed.

**Example**: Contoso opens `contoso.sharepoint.com/sites/PartnerProject` to Fabrikam guests. The site has no Authentication Context, so guests are only subject to the global baseline. If Contoso's security team requires full access for these guests, they can exclude the site from the baseline or create a dedicated CA policy for guest users.

---

## Best Practices

- Start with **Report-Only mode** on all CA policies before enforcing
- **Pilot with a small group** before broad deployment
- Keep **named locations** (trusted IP ranges) documented and up to date
- Separate sites for external collaboration from internal-only sites
- **Monitor Sign-in logs** to verify policies apply as expected
- Remember that B2B guests are subject to **both** your CA policies and their home tenant's cross-tenant access settings

---

## References

- [Authentication Context in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps#authentication-context)
- [SharePoint integration with Authentication Context](https://learn.microsoft.com/en-us/sharepoint/authentication-context-example)
- [Control access from unmanaged devices](https://learn.microsoft.com/en-us/sharepoint/control-access-from-unmanaged-devices)
- [Restricted Access Control in SharePoint Advanced Management](https://learn.microsoft.com/en-us/sharepoint/restricted-access-control)
- [Session policies in Defender for Cloud Apps](https://learn.microsoft.com/en-us/defender-cloud-apps/session-policy-aad)
- [Cross-tenant access for B2B collaboration](https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration)

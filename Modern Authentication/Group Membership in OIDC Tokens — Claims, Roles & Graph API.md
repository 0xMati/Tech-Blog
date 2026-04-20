# Group Membership in OIDC Tokens — Claims, Roles & Graph API
🗓️ Published: 2026-04-20

## Introduction

When integrating an application with OpenID Connect (OIDC) in Microsoft Entra ID, one of the most common requirements is: **how does the application know which groups the user belongs to?**

This seemingly simple question has several answers, because Entra ID offers multiple mechanisms — each with its own trade-offs in terms of simplicity, scalability, and security.

In this article, we'll cover the three main approaches:
✅ The **groups claim** — Entra ID populates the token with group memberships
✅ **App Roles** — groups are translated into application-specific roles in the token
✅ **Microsoft Graph API** — the application queries group memberships at runtime

We'll also dive into the infamous **200 groups overage limit**, which catches many teams off guard in production.

---

## Approach 1: Groups Claim in the Token

The most straightforward approach. Entra ID includes the user's group memberships directly inside the JWT token (ID token and/or access token) as a `groups` claim.

### How to Configure It

📍 **Where**: App Registration → Token Configuration → Add groups claim

When you add a groups claim, you choose:
- **Which token types** to emit it in (ID, Access, SAML)
- **Which groups to include**

### Group Filtering Options

| Option | What gets emitted | Best for |
|---|---|---|
| **Security groups** | All security groups the user is a member of | Most common scenario |
| **Directory roles** | Entra ID admin roles (Global Admin, User Admin, etc.) | Admin portals |
| **All groups** | Security groups + distribution lists + directory roles | Rarely needed — generates large tokens |
| **Groups assigned to the application** | Only groups explicitly assigned to the Enterprise App | ✅ Recommended — keeps tokens small and scoped |

> 💡 **Best practice**: Use "Groups assigned to the application" to avoid bloating the token. Assign only the relevant groups in Enterprise Application → Users and groups.

### Group Identifier Format

By default, groups are emitted as **Object IDs** (GUIDs). Depending on your environment, you can choose a different format:

| Format | Example | Requirement |
|---|---|---|
| **Group ID** (default) | `"groups": ["7a3e4b2c-..."]` | None |
| `sAMAccountName` | `"groups": ["Domain Admins"]` | Requires Entra Connect Sync (hybrid) |
| `NetbiosDomain\sAMAccountName` | `"groups": ["CONTOSO\\Domain Admins"]` | Requires Entra Connect Sync (hybrid) |
| `OnPremisesGroupSecurityIdentifier` | `"groups": ["S-1-5-21-..."]` | Requires Entra Connect Sync (hybrid) |
| **Cloud display name** | `"groups": ["IT-Team"]` | Cloud-only groups or synced groups |

### What the Token Looks Like

```json
{
  "sub": "abc123",
  "name": "John Doe",
  "email": "john@contoso.com",
  "groups": [
    "7a3e4b2c-1234-5678-9abc-def012345678",
    "8b4f5c3d-2345-6789-abcd-ef0123456789"
  ]
}
```

### ⚠️ The 200 Groups Overage Limit

This is where many teams get caught. There is a **hard limit** on how many groups can be included in a JWT token:

| Token type | Maximum groups |
|---|---|
| **JWT** (OIDC / OAuth 2.0) | **200** |
| **SAML** | **150** |

**What happens when the user is in more than 200 groups?**

Entra ID does **not** include any groups in the token. Instead, it emits an **overage indicator** — a special claim that tells the application: "there are too many groups, call Graph API to get them."

The token will contain:

```json
{
  "_claim_names": {
    "groups": "src1"
  },
  "_claim_sources": {
    "src1": {
      "endpoint": "https://graph.microsoft.com/v1.0/users/{user-id}/getMemberObjects"
    }
  }
}
```

The application must then:
1. Detect the presence of `_claim_names` / `_claim_sources` instead of `groups`
2. Call the Graph API endpoint to retrieve the actual groups
3. Use the access token to authenticate the Graph call

> ⚠️ **This is a common production issue.** Everything works fine in dev/test where users are in 5 groups. Then in production, a user with 250 group memberships logs in and the app breaks because it expected a `groups` claim that isn't there.

### How to Avoid Overage

| Strategy | How |
|---|---|
| Use "Groups assigned to the application" | Only assigned groups appear → typically < 200 |
| Switch to App Roles | No overage limit (see Approach 2) |
| Handle overage in code | Detect `_claim_names` and fall back to Graph API |
| Filter unnecessary groups | Remove stale/unused group assignments |

---

## Approach 2: App Roles

Instead of dumping raw group IDs into the token, you can define **application-specific roles** and map groups to them. This is the cleanest approach for Role-Based Access Control (RBAC).

### How It Works

```
    ┌─────────────────────────────┐
    │     App Registration        │
    │                             │
    │  App Roles:                 │
    │   • Admin                   │
    │   • Editor                  │
    │   • Reader                  │
    └──────────────┬──────────────┘
                   │
                   ▼
    ┌─────────────────────────────┐
    │     Enterprise Application  │
    │                             │
    │  Assignments:               │
    │   • IT-Admins  → Admin      │
    │   • Editors    → Editor     │
    │   • All-Staff  → Reader     │
    └──────────────┬──────────────┘
                   │
                   ▼
    ┌─────────────────────────────┐
    │     Token (JWT)             │
    │                             │
    │  "roles": ["Admin"]         │
    │                             │
    │  (if user is in IT-Admins)  │
    └─────────────────────────────┘
```

### Step by Step

#### 1. Define App Roles

📍 App Registration → App Roles → Create app role

| Field | Example |
|---|---|
| Display name | `Admin` |
| Allowed member types | Users/Groups |
| Value | `Admin` (this is what appears in the token) |
| Description | `Full access to the application` |

Repeat for each role your application needs (Editor, Reader, Viewer, etc.).

#### 2. Assign Groups to Roles

📍 Enterprise Application → Users and groups → Add user/group

Select a **group** and assign it to one of the defined roles.

> 📌 **Prerequisite**: The Enterprise Application must have **"User assignment required"** set to **Yes** in Properties if you want to restrict access to assigned users/groups only.

#### 3. The Token

When a user who belongs to the "IT-Admins" group signs in, the token contains:

```json
{
  "sub": "abc123",
  "name": "John Doe",
  "roles": ["Admin"]
}
```

If the user is in multiple groups mapped to different roles:

```json
{
  "roles": ["Admin", "Editor"]
}
```

### Why App Roles Are Often the Best Choice

| Advantage | Detail |
|---|---|
| ✅ **Human-readable** | `"Admin"` instead of `"7a3e4b2c-1234-..."` |
| ✅ **No overage limit** | The `roles` claim is not subject to the 200 group limit |
| ✅ **Decoupled** | The app doesn't need to know Entra group Object IDs |
| ✅ **Scoped** | Only roles explicitly assigned to the app appear |
| ✅ **Works in code** | Frameworks like ASP.NET Core, Spring Security, etc. natively support `roles` claims |
| ✅ **Portable** | If you change group names or IDs, the role mapping stays the same |

### App Roles in Code

Most frameworks make it easy to use roles from the token:

**ASP.NET Core:**
```csharp
[Authorize(Roles = "Admin")]
public IActionResult AdminPanel() { ... }
```

**Python (Flask):**
```python
roles = token_claims.get("roles", [])
if "Admin" not in roles:
    abort(403)
```

**JavaScript (Node/Express):**
```javascript
const roles = req.authInfo.roles || [];
if (!roles.includes("Admin")) {
    return res.status(403).send("Forbidden");
}
```

---

## Approach 3: Query Microsoft Graph API

The application doesn't rely on token claims at all. Instead, it calls the Microsoft Graph API after authentication to retrieve group memberships.

### Available Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/me/memberOf` | GET | Direct group memberships of the signed-in user |
| `/me/transitiveMemberOf` | GET | Direct + inherited memberships (nested groups) |
| `/me/checkMemberGroups` | POST | Check if user is member of specific groups (pass a list of group IDs) |
| `/me/checkMemberObjects` | POST | Same but for any directory object type |
| `/me/getMemberObjects` | POST | All objects (groups + roles) the user is a member of |
| `/users/{id}/memberOf` | GET | Same as `/me/memberOf` but for any user (requires app permission) |

### Required Permissions

| Permission | Type | Scope |
|---|---|---|
| `GroupMember.Read.All` | Delegated | Read group memberships (recommended) |
| `Directory.Read.All` | Delegated or Application | Read all directory data (broader) |
| `User.Read` | Delegated | Required for `/me` endpoints |

### Example: Check Membership in Specific Groups

```http
POST https://graph.microsoft.com/v1.0/me/checkMemberGroups
Content-Type: application/json

{
  "groupIds": [
    "7a3e4b2c-1234-5678-9abc-def012345678",
    "8b4f5c3d-2345-6789-abcd-ef0123456789"
  ]
}
```

Response:
```json
{
  "value": [
    "7a3e4b2c-1234-5678-9abc-def012345678"
  ]
}
```

### Example: Get All Groups with Display Names

```http
GET https://graph.microsoft.com/v1.0/me/transitiveMemberOf/microsoft.graph.group?$select=displayName,id
```

Response:
```json
{
  "value": [
    { "id": "7a3e4b2c-...", "displayName": "IT-Admins" },
    { "id": "8b4f5c3d-...", "displayName": "All-Staff" }
  ]
}
```

### When to Use Graph API

| Scenario | Why Graph |
|---|---|
| User could be in > 200 groups | No token size limit |
| Need real-time group data | Token is a snapshot at login time; Graph is live |
| Need group details (name, description, members) | Token only gives IDs |
| Need to handle nested groups precisely | `transitiveMemberOf` gives the full picture |
| Overage fallback | When `_claim_names` is present instead of `groups` |

### The Overage Fallback Pattern

A robust application should handle both cases:

```
    ┌─────────────────────────────────┐
    │  Receive token after login      │
    └──────────────┬──────────────────┘
                   │
          Does the token contain
           a "groups" claim?
                   │
          ┌────────┴────────┐
          ▼                 ▼
       ┌─────┐          ┌──────┐
       │ YES │          │  NO  │
       └──┬──┘          └──┬───┘
          │                │
    Use groups         Check for
    from token       _claim_names
          │                │
          │           ┌────┴────┐
          │           ▼         ▼
          │      ┌────────┐  ┌──────────┐
          │      │ EXISTS │  │ NO GROUPS │
          │      └───┬────┘  └──────────┘
          │          │
          │    Call Graph API
          │    /me/memberOf
          │          │
          └────┬─────┘
               ▼
    ┌─────────────────────────────────┐
    │  Application has group list     │
    │  → Authorize accordingly        │
    └─────────────────────────────────┘
```

---

## Comparing All Three Approaches

| | **Groups Claim** | **App Roles** | **Graph API** |
|---|---|---|---|
| **Data location** | In the token | In the token | API call at runtime |
| **Format** | Object IDs (GUIDs) | Human-readable role names | Full objects (ID + name + metadata) |
| **Limit** | 200 groups (JWT) | No overage limit | No limit |
| **Real-time** | ❌ Snapshot at login | ❌ Snapshot at login | ✅ Live data |
| **Extra API call** | ❌ (unless overage) | ❌ | ✅ Always |
| **Nested groups** | ✅ Transitive by default | Via group assignment | ✅ `transitiveMemberOf` |
| **Configuration** | Token Configuration | App Roles + group assignment | API Permissions |
| **App code changes** | Read `groups` claim | Read `roles` claim | HTTP call to Graph |
| **Best for** | Simple apps, < 200 groups | RBAC, production apps | Large orgs, real-time needs |

---

## Decision Guide

```
        Does your app need group info?
                    │
                    ▼
        ┌───────────────────────┐
        │ How many groups could │
        │ a user be in?         │
        └───────────┬───────────┘
                    │
       ┌────────────┴────────────┐
       ▼                         ▼
   < 200 groups            ≥ 200 groups
       │                         │
       ▼                         ▼
  ┌──────────┐        ┌───────────────────┐
  │ Groups   │        │ Does the app need │
  │ claim    │        │ all groups or     │
  │ (simple) │        │ just roles?       │
  └──────────┘        └─────────┬─────────┘
                                │
                   ┌────────────┴────────────┐
                   ▼                         ▼
            Just roles /              All groups /
            access control            detailed info
                   │                         │
                   ▼                         ▼
            ┌──────────┐           ┌────────────────┐
            │ App Roles│           │ Graph API      │
            │ (best)   │           │ (/me/memberOf) │
            └──────────┘           └────────────────┘
```

---

## Combining Approaches

The three approaches are **not mutually exclusive**. A common production pattern is:

| Layer | Mechanism | Purpose |
|---|---|---|
| **Primary authorization** | App Roles in the token | Fast, no API call, role-based UI rendering |
| **Fine-grained checks** | Graph API (`checkMemberGroups`) | Verify specific group membership for sensitive operations |
| **Fallback** | Graph API (`memberOf`) | Handle overage if groups claim is also configured |

Example: an application uses **App Roles** for page-level access (`Admin` sees the admin panel, `Reader` does not), and calls **Graph API** to check if the user belongs to a specific security group before allowing a destructive action like deleting records.

---

## Key Takeaways

- **Groups claim** is the simplest but has a **200 group limit** — test with real production users, not just dev accounts with 5 groups
- **App Roles** are the cleanest pattern for RBAC — no GUIDs in your code, no overage risk, natively supported by most frameworks
- **Graph API** is the most flexible but adds latency — use it for real-time checks or as an overage fallback
- **"Groups assigned to the application"** is an underused setting that dramatically reduces token size
- **Always plan for overage** — even if your users currently have < 200 groups, organizational growth can push them past the limit overnight

---

## References

- [Configure group claims for applications — Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-fed-group-claims)
- [Optional claims reference — groups](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference)
- [Application roles — Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
- [Groups overage claim](https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference#groups-overage-claim)
- [Microsoft Graph: List memberOf](https://learn.microsoft.com/en-us/graph/api/user-list-memberof)
- [Microsoft Graph: Check member groups](https://learn.microsoft.com/en-us/graph/api/directoryobject-checkmembergroups)

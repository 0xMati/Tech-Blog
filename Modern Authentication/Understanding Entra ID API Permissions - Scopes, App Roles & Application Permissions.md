# Understanding Entra ID API Permissions - Scopes, App Roles & Application Permissions
🗓️ Published: 2025-11-14

### *Everything you always wanted to know about `scp`, `roles`, consent, and “why the hell is my token empty?”*

If you’ve ever tried to secure an API with Entra ID, you’ve probably hit at least one of these moments:

- “Why does my token have `scp` sometimes, and `roles` other times?”  
- “Why does my daemon app get *no* permissions even though I see them in **API Permissions**?”  
- “Why does everything break when I turn on **Assignment required = Yes**?”  
- “What’s the difference between **Application Permissions** and **App Roles** anyway? Are these two things? Three things? Zero things?”  

If that sounds familiar, welcome — you’re in the right place

This guide aims to **demystify** how Entra ID handles API permissions.  
We’ll break things down using **real tokens**, **simple test apps**, and tools you already know:

- **OIDC Debugger** → for flows with users (delegated permissions)  
- **Postman / curl / PowerShell** → for daemons & background jobs  
- **jwt.ms** → to decode tokens and understand what’s really going on

By the end of this article, you will understand:

- Why **there are only two real permission models** in Entra ID (delegated vs application)  
- Why **“Application Permissions”** in the portal are simply **App Roles (Application)**  
- When Entra ID puts **`scp`** in a token  
- When it puts **`roles`**  
- When it puts *nothing* (and your API cries)  
- How to design APIs correctly for:
  - users  
  - services  
  - hybrid flows
- And how to build a tiny reproducible lab to test all these scenarios in your own tenant

---

# 2. Fundamental Concepts  
### *Before diving into tokens and permissions, let’s get the mental model straight.*

Entra ID + OAuth can feel like a mashup of similar screens and terminology that changes depending on where you click.  
So before we touch scopes, roles, or tokens, let’s establish the foundations 👇

---

## 2.1. App Registration vs Enterprise Application  
This is **the most underrated concept** in Entra ID.

When you create an application, Entra ID automatically creates **two different objects**:

### **1. App Registration** (the blueprint 🧬)
- The *definition* of the application.  
- Contains client ID, redirect URIs, API exposure, scopes, app roles, manifest, etc.  
- It does **not** authenticate anything by itself.

### **2. Enterprise Application** (the instance 🏷️)  
- Also called the **Service Principal**.  
- This is the object that *lives inside the tenant*.  
- This is where:
  - users or groups can be assigned to roles,  
  - applications can be assigned to roles,  
  - **“Assignment required = Yes”** is enforced,  
  - conditional access applies.

💡 **Key takeaway:**  
You **define** permissions on the App Registration.  
You **assign** and **enforce** them on the Enterprise Application.

---

## 2.2. The different token types  
OAuth loves tokens. But they don’t all serve the same purpose.

### **ID Token**  
- Identifies the **user**.  
- Used so your app knows *who* is signed in.  
- Not used to call an API.

### **Access Token**  
- Grants access to an **API**.  
- This is where you will see `scp` or `roles`.  
- This is the token we will analyze throughout this guide.

### **Refresh Token**  
- Lets the client get new tokens without re-authenticating the user.  
- Not relevant for API authorization logic.

---

## 2.3. Claims you must understand (`aud`, `scp`, `roles`, `sub`, `azp`, `appid`)
When you decode a token on https://jwt.ms, a few key fields tell the whole story:

### **`aud` – Audience**  
- “Which API is this token intended for?”  
- Must match your API’s Application ID URI.

### **`scp` – Scopes (delegated permissions)**  
- Only present when a **user** is involved.  
- Example: `scp: "Orders.Read Orders.Write"`

### **`roles` – App Roles (application permissions)**  
- Present when:
  - a service calls your API via client_credentials, or  
  - a user/app has been assigned an App Role.  
- Example: `roles: ["Orders.Read.All"]`

### **`sub` – Subject**  
- The entity represented by the token (user or application).

### **`azp` – Authorized Party**  
- The client application that requested the token.

### **`appid` – Application ID**  
- The ID of the calling application in app-only flows.

---

## 2.4. The golden rule of Entra ID OAuth  
This single rule explains **80% of confusing behavior** you’ll see in tokens:

> ## 👉 If there is a **user**, Entra emits **`scp`**.  
> ## 👉 If there is **no user**, Entra emits **`roles`**.  
> ## 👉 You don’t get both (except in special hybrid/OBO cases).

Print it. Frame it. Tattoo it. Put it on a mug ☕.

This rule explains why:
- a daemon never gets `scp`,  
- a web app never gets `roles`,  
- some access tokens look “empty”,  
- enabling **Assignment required = Yes** breaks certain apps.

---

# 3. The Two Permission Models in Entra ID
### *There are only two — even if the portal makes it look more complicated.*

Entra ID exposes exactly **two** permission models for APIs:

- **Delegated Permissions (Scopes)**
- **Application Permissions (App Roles – Application)**

Everything else in the UI is just wording pointing to these two mechanisms.

---

## 3.1 Delegated Permissions (Scopes)

Delegated permissions are used when an **application acts on behalf of a user**.

They are defined under:

```
Expose an API → Add a scope
```

A delegated permission expresses:

> “What is this user allowed to do through this application?”

### Key characteristics
- Requires a **signed‑in user**
- Appears in the access token as the **`scp`** claim
- Granted through **user or admin consent**
- Used by:
  - Web apps
  - SPAs
  - Mobile apps
  - Device Code flow
  - On‑Behalf‑Of (OBO)

### Example scope definition
```json
{
  "oauth2PermissionScopes": [
    {
      "value": "Orders.Read",
      "description": "Read customer orders",
      "id": "11111111-2222-3333-4444-555555555555"
    }
  ]
}
```

### Example delegated token
```json
{
  "scp": "Orders.Read",
  "sub": "user-guid",
  "roles": null
}
```

If you see `scp`, a **user** is involved.  
If you see `scp` inside a **client_credentials** token → something is wrong.

---

## 3.2 Application Permissions (App Roles)

Application Permissions are used when an **application acts as itself**, with **no user involved**.

These permissions map directly to **App Roles** with:

```json
"allowedMemberTypes": ["Application"]
```

They are defined under:

```
Expose an API → App roles
```

In the Entra portal, they appear under **API Permissions → Application permissions**, but they are technically just App Roles.

### Key characteristics
- Work **without a user**
- Appear in the token as the **`roles`** claim
- Require **admin consent**
- Must be **assigned** to the calling application (Enterprise Application → Assign role)
- Only produced in **client_credentials** flows

### Example App Role (Application)
```json
{
  "appRoles": [
    {
      "value": "Orders.Read.All",
      "description": "Daemon can read all orders",
      "allowedMemberTypes": ["Application"],
      "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    }
  ]
}
```

### Example application token
```json
{
  "roles": ["Orders.Read.All"],
  "scp": null,
  "sub": "client-app-id"
}
```

If you see `roles`, the caller is an **application**, not a user.

---

## 3.3 App Roles can target **users** or **applications**

App Roles are a general‑purpose mechanism.

They can be assigned to:

- **Users** (`allowedMemberTypes: ["User"]`)
- **Applications** (`allowedMemberTypes: ["Application"]`)
- **Both**

### Example App Role (User)
```json
{
  "value": "Dashboard.Read",
  "allowedMemberTypes": ["User"]
}
```

→ Appears in a user token:
```json
{
  "roles": ["Dashboard.Read"]
}
```

### Example App Role (Application)
```json
{
  "value": "Orders.Read.All",
  "allowedMemberTypes": ["Application"]
}
```

→ Appears in a daemon token.

---

## 3.4 Side‑by‑side comparison

| Feature | Delegated Permissions (Scopes) | Application Permissions (App Roles) |
|--------|--------------------------------|-------------------------------------|
| Used when | A **user** is signing in | An **application** acts alone |
| Flow | Auth Code, Device Code, OBO | Client Credentials |
| Token claim | `scp` | `roles` |
| Defined in | `oauth2PermissionScopes` | `appRoles` |
| Assigned to | Users (via consent) | Apps (via role assignment) |
| Portal name | Delegated permissions | Application permissions |
| Works without user? | ❌ No | ✅ Yes |
| Appears in client_credentials token? | ❌ Never | ✅ Always (if assigned) |

---

## 3.5 Why people get confused

Because the portal uses **different names** depending on context:

- In *Expose an API*:  
  - You create **Scopes**  
  - You create **App Roles**

- In *API Permissions*:  
  - Scopes appear as **Delegated Permissions**  
  - App Roles appear as **Application Permissions**

**Same objects — different labels.**

This is why developers often think there are three permission types,  
when in reality there are only two.

---

# 4. Scopes vs App Roles vs Application Permissions  
### *This is where most people get confused — and it's not their fault.*

The Entra ID admin portal uses **three different labels** for what are actually  
**only two permission mechanisms**.

This section clears up the terminology once and for all.

---

# 4.1 What Scopes really are

Scopes = **Delegated Permissions**.

You define them under:

```
Expose an API → Add a scope
```

They appear under **API Permissions → Delegated Permissions**.

They show up in tokens as the **`scp`** claim — but *only* when a **user** is involved.

### Example
```json
"scp": "Orders.Read Orders.Write"
```

If there is **no user** → no `scp`, ever.

---

# 4.2 What App Roles really are

App roles are defined under:

```
Expose an API → App roles
```

They can target:

- **Users** (`allowedMemberTypes: ["User"]`)
- **Applications** (`allowedMemberTypes: ["Application"]`)
- **Both**

This makes App Roles a **generic authorization mechanism** used by Entra ID.

### When assigned to a user  
→ They appear in the token under `roles`  
```json
"roles": ["Dashboard.Read"]
```

### When assigned to an app  
→ They are displayed in the portal as **Application Permissions**  
→ They show up in the token under `roles`
```json
"roles": ["Orders.Read.All"]
```

Same mechanism. Different UI labels.

---

# 4.3 “Application Permissions” is *not* a third permission type

This is the critical point:

> **Application Permissions = App Roles with `allowedMemberTypes: ["Application"]`**  
> They are not a separate system.

Scopes = delegated.  
App Roles = generic roles for users *or* apps.  
Application Permissions = App Roles (Application).

---

# 4.4 The portal vocabulary problem (why everyone gets confused)

Depending on where you look in the portal, you’ll see different names:

### In **Expose an API**
- “Scopes”
- “App Roles”

### In **API Permissions**
- “Delegated Permissions” → scopes  
- “Application Permissions” → App Roles (Application)

### In **Enterprise Applications → Users and groups**
- “App roles” → App Roles (User)

**Same objects. Different names. Different places.**

This leads many developers to believe there are three permission types.

There are only **two**.

---

# 4.5 Visual model

```
Expose an API
 ├── Scopes (Delegated Permissions)
 │      → appear as `scp` in tokens
 │
 └── App Roles
        ├── User roles (allowedMemberTypes: ["User"])
        │      → appear as `roles` in user tokens
        │
        └── Application roles (allowedMemberTypes: ["Application"])
               → shown as Application Permissions in API Permissions
               → appear as `roles` in daemon tokens
```

---

# 4.6 Summary table

| Portal Label | Actual Mechanism | Token Claim | Requires User? |
|-------------|------------------|-------------|----------------|
| Delegated Permissions | Scope | `scp` | ✅ Yes |
| Application Permissions | App Role (Application) | `roles` | ❌ No |
| App roles (Users) | App Role (User) | `roles` | Depends |

---

# 4.7 Why this matters (and why things break)

### Common mistake:
A daemon app is granted a **scope** in API Permissions.

Looks fine visually…  
But the token contains:

```json
"scp": "",
"roles": null
```

Because:
- Scopes don’t work without a user  
- App Roles were never assigned  

Result:
- missing claims  
- 401 / 403 errors  
- developers disabling **Assignment Required** thinking it's a bug  
- confusion and frustration

Now you know why.

---

This concludes Section 4.

# 5. How Entra ID Decides What Goes Into a Token  
### *If you understand this section, you understand everything.*

When an application requests a token for your API, Entra ID must decide:  
- Should the token contain `scp` (delegated permissions)?  
- Should it contain `roles` (app roles)?  
- Should it contain both?  
- Should it contain *none*?  
- Which identity does the token represent (`sub`)?  
- What is the audience (`aud`)?  

This section breaks down exactly how Entra ID makes these decisions.

---

# ## 5.1 If there is a user → Entra emits **`scp`**

Whenever the authentication flow involves a **user**:

- Authorization Code (with or without PKCE)  
- Device Code  
- On-Behalf-Of (OBO)  
- ROPC (discouraged, but still used)  

…Entra ID will issue a token with **delegated permissions** based on the scopes requested.

### Example  
Client requests:

```
scope: api://my-api/Orders.Read
```

Token contains:

```json
{
  "scp": "Orders.Read",
  "sub": "user-guid",
  "roles": null
}
```

👉 If you see `scp` → a **signed-in user** was involved.

---

# ## 5.2 If there is **no user** → Entra emits **`roles`**

When the client uses:

- **Client Credentials flow**  
- **A daemon / background job**  
- **API-to-API call without user context**  

Entra ID **cannot** emit `scp`, because scopes represent user-delegated permissions.

Instead, Entra issues **Application Permissions**, which come from **App Roles** assigned to the calling application.

### Example  
Enterprise Application → Assign role → `Orders.Read.All`

Token contains:

```json
{
  "roles": ["Orders.Read.All"],
  "sub": "client-app-id",
  "scp": null
}
```

👉 If you see `roles` and no `scp` → it is an **application acting as itself**.

---

# ## 5.3 You rarely (almost never) get both

Hybrid flows like **On-Behalf-Of** (OBO) can produce special tokens that contain:

- user identity  
- delegated permissions  
- app-level identity data  

But even in OBO, you typically get **`scp`**, not `roles`.

> Having **both** `scp` and `roles` in the same access token is exceptionally rare and typically the result of explicit custom logic, not normal behavior.

---

# ## 5.4 Understanding the `aud` claim (Audience)

The `aud` claim tells you which **API** the token is intended for.

Examples:

```json
"aud": "api://my-api"
```

```json
"aud": "https://graph.microsoft.com"
```

Rule of thumb:

> ## An API must **never** trust a token unless `aud` matches its own identifier.

This prevents token replay across APIs.

---

# ## 5.5 Understanding `sub`, `azp`, and `appid`

### **`sub` – Subject**
Represents the entity the token is about:
- user  
- or application  

### **`azp` – Authorized Party**
Identifies the **client application** that requested the token.  
Useful when multiple apps call the same API.

### **`appid` – Application ID**
Present in app-only flows; identifies the calling application.

Example (client_credentials):

```json
{
  "sub": "client-app-id",
  "azp": "client-app-id",
  "appid": "client-app-id"
}
```

---

# ## 5.6 Why your token sometimes looks “empty”

A common scenario:

- Developer configures **scopes** on the API  
- Developer grants the scope in **API Permissions**  
- Developer uses **client_credentials** to request a token  
- Token contains **no `scp`** and **no `roles`**

Why?

Because:

- Scopes don’t apply without a user  
- App Roles haven’t been assigned  
- Therefore Entra ID emits a **minimal token with no permissions**

This leads to 401/403 errors and lots of confusion.

---

# ## 5.7 Decision diagram

```
                ┌───────────────┐
                │ Is a user     │
                │ signing in?   │
                └───────┬───────┘
                        │ Yes
                        ▼
                 Emit `scp`
                 (delegated)
                        │
                        ▼
            User must consent to scopes


                        │ No
                        ▼
             Emit `roles`
             (app roles / application perms)
                        │
                        ▼
     Calling app must be assigned to an App Role
```

---

# ## 5.8 Summary

The rules are simple:

- **User present → `scp`**  
- **No user → `roles`**  
- **No assigned App Role → no permissions**  
- **Scopes in app-only flows do nothing**  
- **`aud` must match the API**  
- **Enterprise Application controls assignment & enforcement**  

Once you internalize these rules, Entra ID’s token behavior becomes predictable and intuitive.

---

# 6. Understanding the “API Permissions” Screen  
### *Why it looks helpful… and still manages to confuse almost everyone.*

The **API Permissions** blade in Entra ID looks like *the* place where you understand  
“what an app is allowed to do”.

That’s only half true.

This screen mixes **two different things**:

- Delegated permissions (**scopes**)  
- Application permissions (**App Roles for applications**)  

…without really telling you which is which in terms of token behavior.

Let’s decode it.

---

## 6.1 What you actually see in “API Permissions”

When you open:

> **App Registration → API Permissions**

You’ll see two main sections:

- **Delegated permissions**  
- **Application permissions**

Under the hood, this maps to:

- **Delegated permissions** → `oauth2PermissionScopes` (Scopes)  
- **Application permissions** → `appRoles` with `allowedMemberTypes: ["Application"]`  

So:

- Every line under **Delegated permissions** corresponds to a *scope* your app can request.  
- Every line under **Application permissions** corresponds to an *App Role (Application)* your app can be assigned to.

The portal just shows them together.

---

## 6.2 Consent: who gives it, and for what?

For each permission, Entra ID requires **consent**.  
There are two types:

### User consent
A **user** consents for *themselves* (if allowed by tenant policy):

- Applies only to **Delegated Permissions** (scopes).  
- Typical for multi-tenant apps, productivity apps, etc.

### Admin consent
An **admin** consents on behalf of:

- All users in the tenant (for some delegated permissions), and/or  
- The tenant itself (for application permissions / app roles).

**Application Permissions always require admin consent.**  
A daemon app cannot self-consent — an admin must approve.

---

## 6.3 The dangerous illusion: “I see it in API Permissions, so it must be in the token”

This is the trap.

Example scenario:

1. You add a **scope** `Orders.Read` to your API.
2. In your daemon app’s **API Permissions**, you add that scope under **Delegated permissions**.
3. An admin gives consent.
4. You call the token endpoint with **client_credentials**.
5. You inspect the token and see:

```json
"scp": "",
"roles": null
```

No `scp`. No `roles`. No permissions.

Why?

Because:

- You are using **client_credentials** → there is **no user**.  
- Scopes only apply when there is a user.  
- You did not assign any App Role (application permission).  

Conclusion:

> **The fact that you see a permission in the “API Permissions” screen does *not* guarantee it will appear in the token.**

The token is the source of truth.  
The **API Permissions** screen is only configuration + consent status.

---

## 6.4 How “API Permissions” and assignment work together

Another subtle point:

- **Scopes** → once consented, any client can request them (with a user).  
- **App Roles (Application permissions)** → must be *assigned* to the client’s **Enterprise Application**.

Two levels:

1. **Consent** (admin)  
   - “I allow this app to ever use this application permission.”

2. **Assignment** (role assignment on Enterprise Application)  
   - “This specific app *has* this role.”

If you skip the assignment step, the token will still be empty.

So for **Application permissions** to show up in `roles`, you need:

- App Role defined on the API  
- Admin consent on the client app  
- Role assigned to the client’s Enterprise Application  

Only then will Entra ID emit `roles` in the access token.

---

## 6.5 Mental model: API Permissions is a *catalog*, not a token preview

Think of the **API Permissions** screen as:

> A list of “what this client *is allowed to ask for*”,  
> not “what this client *actually gets in tokens*”.

What the client **actually gets** depends on:

- The **flow** (user vs no user)  
- The **requested resource** (`aud`)  
- Whether the right **App Roles** are **assigned**  
- Whether the scopes are requested **during authentication**

---

## 6.6 Checklist for reading API Permissions correctly

When you look at API Permissions for a client app, ask yourself:

1. **Under Delegated Permissions:**  
   - Are these scopes meant for flows with users?  
   - Is the app actually using such a flow (auth code, device code, etc.)?

2. **Under Application Permissions:**  
   - Do these entries correspond to App Roles defined on the target API?  
   - Has an admin consented?  
   - Is the role **assigned** to this application’s Service Principal?

3. **In the token:**  
   - For user flows → do I see `scp`?  
   - For app-only flows → do I see `roles`?  
   - If not, which of the above is missing?

---

## 6.7 A simple rule to remember

> **API Permissions shows configuration and consent.  
> The access token shows reality.**

When in doubt, always trust the token.

---

# 7. Building a Mini Lab to Test Everything Yourself  
### *Two tiny apps, real tokens, zero confusion.*

Theory is great — but Entra ID behavior only becomes crystal clear when you see real tokens.

In this section, you will build a **minimal reproducible lab** with:

- **One API** (your protected resource)  
- **One user‑based client** (OIDC Debugger)  
- **One daemon client** (client_credentials via Postman / curl / PowerShell)

This lab takes 10 minutes and will let you validate every concept in this guide.

---

# 7.1 Create the API App Registration

### 1. Go to *Entra ID → App registrations → New application*

- Name: **Demo‑API**
- Type: **Accounts in this organizational directory only**
- Redirect URI: *(none needed)*

### 2. Expose the API  
Go to:

> **Expose an API → Set Application ID URI**

Use the suggested value (e.g., `api://<client-id>`).

### 3. Add a delegated permission (scope)

```
Expose an API → Add a scope
```

Example:

- Scope name: `Orders.Read`
- Who can consent: Admins & users
- Description: “Read orders”

### 4. Add an application permission (App Role)

```
Expose an API → App roles → Create app role
```

Example:

```json
{
  "value": "Orders.Read.All",
  "allowedMemberTypes": ["Application"],
  "description": "Daemon apps can read all orders"
}
```

You now have:

- **1 scope** → `Orders.Read`
- **1 App Role (Application)** → `Orders.Read.All`

---

# 7.2 Create the user‑based client (OIDC Debugger)

We will use **OIDC Debugger** to request a token *with a user*, so we expect an **`scp`** claim.

### 1. Create the client app  
App name: **Demo‑Client‑User**

Platform: **Web**

Redirect URI:

```
https://oidcdebugger.com/debug
```

### 2. Add API permissions

Go to:

> **API Permissions → Add a permission → My APIs → Demo‑API**

Select:

- **Delegated Permissions → Orders.Read**

Grant admin consent (optional but easier).

### 3. Test with OIDC Debugger

Open:  
https://oidcdebugger.com/

Use:

- **Authorize URL:** Your tenant’s `/oauth2/v2.0/authorize`
- **Client ID:** The Demo‑Client‑User app
- **Scope:**  
  ```
  api://<api-client-id>/Orders.Read openid profile offline_access
  ```

Sign in.

### 4. Inspect the access token

Go to https://jwt.ms and paste the access token.

You will see:

```json
"scp": "Orders.Read",
"roles": null
```

👉 Perfect — delegated permission detected.

---

# 7.3 Create the daemon client (client_credentials)

This client calls the API **without a user**, so we expect a **`roles`** claim.

### 1. Create the client app  
Name: **Demo‑Client‑Daemon**

Platform: *None*  
Add a **client secret**.

### 2. Add API Permissions  
Add:

- **Application Permissions → Orders.Read.All**

Click **Grant admin consent**.

### 3. Assign the App Role  
This step is *crucial*.

Go to:

> **Enterprise Applications → Demo‑Client‑Daemon → Assign Users and Groups**

- Assign the App Role:
  - **Orders.Read.All**

Without this step → the token will be empty.

### 4. Request a token using Postman / curl / PowerShell

**PowerShell example:**

```powershell
$tenant = "<tenant-id>"
$clientId = "<daemon-client-id>"
$clientSecret = "<secret>"
$scope = "api://<api-client-id>/.default"

$body = @{
    client_id     = $clientId
    scope         = $scope
    client_secret = $clientSecret
    grant_type    = "client_credentials"
}

Invoke-RestMethod -Method Post `
  -Uri "https://login.microsoftonline.com/$tenant/oauth2/v2.0/token" `
  -Body $body
```

### 5. Inspect the access token

Paste the token into https://jwt.ms.

You will see:

```json
"roles": ["Orders.Read.All"],
"scp": null
```

👉 Exactly what we expect — application permission emitted.

---

# 7.4 What you can test in this lab

With 2 clients and 1 API, you can reproduce every confusing behavior:

### ✔ User token → `scp`  
Remove delegated permissions → watch `scp` disappear.

### ✔ Daemon token → `roles`  
Remove role assignment → watch token become empty.

### ✔ “Assignment required = Yes”  
Enable it on the **API’s Enterprise Application** and see:
- user app break if scopes aren’t assigned  
- daemon app break if roles aren’t assigned

### ✔ `.default` scope behavior  
Test:

```
scope = api://<api-id>/.default
```

to confirm it only applies **App Roles**, not scopes.

### ✔ Misconfigurations and real‑world mistakes  
Try granting a *scope* to the daemon → nothing appears in token.  
Try granting an *App Role* to the user app → nothing appears in token.

---

# 7.5 Final architecture diagram

```
                  ┌───────────────────┐
                  │     Demo‑API      │
                  │  (Scopes + Roles) │
                  └─────────┬─────────┘
                            │
            ┌───────────────┴────────────────┐
            │                                │
┌───────────────────────┐        ┌─────────────────────────┐
│ Demo‑Client‑User       │        │ Demo‑Client‑Daemon      │
│  (OIDC Debugger)       │        │ (client_credentials)     │
└───────────┬────────────┘        └────────────┬────────────┘
            │                                   │
          User                                No user
            │                                   │
            ▼                                   ▼
      Token contains:                     Token contains:
        "scp": "Orders.Read"               "roles": ["Orders.Read.All"]
        "roles": null                      "scp": null
```

---

# 7.6 You now have a complete, reproducible playground

With this lab:

- You can demonstrate every behavior explained in Sections 1–6.  
- You can validate scope vs role behavior.  
- You can help clients debug real production issues instantly.  
- You can test hybrid flows (OBO) later.  

This is the exact same lab Microsoft engineers use internally to troubleshoot OAuth issues.

---

# 8. Putting It All Together: The Full End‑to‑End OAuth Flow  
### *From permissions → to consent → to token → to API enforcement.*

You now understand the theory, the lab, the differences between scopes and roles,  
and how Entra ID decides what ends up inside an access token.

Section 8 ties everything together in a **single real-world flow**, step by step.

We’ll cover:

1. How a client *actually requests* permissions  
2. How Entra validates & processes these permissions  
3. How scopes and roles are resolved  
4. How the API enforces them  
5. How things fail (and how to diagnose instantly)

This is the “master flow” that explains 99% of OAuth behavior in Entra ID.

---

# 8.1 Step 1 — The client requests a token

A client app requests a token by calling:

```
/oauth2/v2.0/authorize   (user flows)
```

or

```
/oauth2/v2.0/token       (client_credentials)
```

The client must specify:

- **who** it is → `client_id`  
- **what** it wants → `scope` or `.default`  
- **how** it authenticates → redirect, secret, certificate, etc.  
- **which resource** → the API’s Application ID URI

### Example: user flow

```
scope=openid profile api://<api-id>/Orders.Read
```

### Example: daemon flow

```
scope=api://<api-id>/.default
```

---

# 8.2 Step 2 — Entra ID processes the request

Entra performs multiple checks:

### ✔ Does the API exist?  
Is the `aud` valid?

### ✔ Does the client have access to that API?  
- For **delegated perms** → did the user/admin consent?  
- For **app perms** → did an admin consent & assign the role?

### ✔ Is the flow compatible with the requested permissions?  
- User exists → delegated permissions allowed  
- No user → only application permissions allowed

### ✔ Does Conditional Access allow this request?  
(More relevant for delegated permissions)

If everything is valid, Entra ID prepares the token.

---

# 8.3 Step 3 — Entra ID decides **what to put inside the token**

This is the logic:

```
IF user exists THEN
      include `scp` from delegated permissions
ELSE
      include `roles` from application permissions
END
```

It uses:

- the **App Registration** for definitions (scopes, roles)  
- the **Enterprise Application** for assignments & enforcement  

If neither applies → the token is minimal and contains **no permissions**.

---

# 8.4 Step 4 — Entra ID emits the token

### User Flow Token  
Contains:

```json
{
  "aud": "api://<api-id>",
  "scp": "Orders.Read",
  "roles": null,
  "sub": "<user-id>"
}
```

### App-only Flow Token  
Contains:

```json
{
  "aud": "api://<api-id>",
  "roles": ["Orders.Read.All"],
  "scp": null,
  "sub": "<client-id>"
}
```

The token is now ready to be sent to the API.

---

# 8.5 Step 5 — The API validates the token

When the API receives the token, it **must** validate:

1. **Signature** → is it from Entra ID?  
2. **Audience (`aud`)** → is this token meant for me?  
3. **Issuer (`iss`)** → does it match the tenant?  
4. **Permissions** → does the client have the required scope/role?  
5. **Expiration (`exp`)** → still valid?

Only after validation can the API authorize the action.

---

# 8.6 Step 6 — API enforces authorization

Examples:

### ✔ Checking scopes (delegated perms)

```csharp
[Authorize(Policy = "Orders.Read")]
```

### ✔ Checking App Roles (application perms)

```csharp
[Authorize(Roles = "Orders.Read.All")]
```

### ✔ Checking both (hybrid scenario)

```csharp
if (token.HasScope("Orders.Read") || 
    token.HasRole("Orders.Read.All"))
{
    allow();
}
```

The API must enforce **its own rules**  
— the token only contains data, not logic.

---

# 8.7 Step 7 — Common failure points and how to diagnose

### ❌ Missing `scp`  
Cause:  
- No user  
- Wrong flow (client_credentials used by mistake)  
- Delegated permission not requested via `scope=`  

Fix:  
- Use user-based flow  
- Request the scope explicitly

---

### ❌ Missing `roles`  
Cause:  
- App Role not assigned  
- Admin consent missing  
- App calling wrong API (`aud` mismatch)

Fix:  
- Assign the App Role  
- Validate `.default` scope usage  
- Decode token to verify `aud`

---

### ❌ Token contains nothing (empty permissions)  
Cause:  
- Wrong flow for the requested permission  
- Misunderstanding of API Permissions UI  
- Missing assignment

Fix:  
- Check token on https://jwt.ms  
- Apply Section 6 checklist  
- Ensure the correct flow is used

---

### ❌ “Assignment required = Yes” breaks the app  
Cause:  
- App not assigned to required App Role  
- User not assigned to scope or role (if user app)

Fix:  
- Assign the role in the Enterprise Application  
- Re-check delegated permissions

---

# 8.8 End-to-End Diagram

```
Client App
   │
   │ 1. Requests token (with scope or .default)
   ▼
Entra ID
   │
   │ 2. Validates consent & assignments
   │ 3. Chooses between `scp` or `roles`
   │ 4. Issues access token
   ▼
Client App
   │
   │ 5. Sends token to API
   ▼
API
   │
   │ 6. Validates token (sig, aud, exp)
   │ 7. Enforces scopes/roles
   ▼
Access granted
```

---

# 8.9 Final Summary

Entra ID’s behavior is predictable — once you know the rules:

- **There are only two permission models**  
  - Delegated Permissions (Scopes)  
  - Application Permissions (App Roles)

- **User flow → `scp`**  
- **Daemon flow → `roles`**

- **API Permissions UI ≠ token contents**  
- **Enterprise Application controls assignment & enforcement**  
- **The token is the only source of truth**

Mastering these principles makes you unstoppable in troubleshooting OAuth in Microsoft Entra.

---

# 9. Advanced Topics (Optional but Highly Recommended)  
### *Deep dives for architects, security engineers, and anyone who wants to go beyond the basics.*

If you’ve made it all the way here: congratulations —  
you now understand Entra ID API permissions better than 95% of developers and consultants.

Section 9 explores **bonus** advanced scenarios that often come up in real enterprise environments:

- `.default` and why it confuses everyone  
- multi-API scenarios  
- OBO (On-Behalf-Of) and hybrid permissions  
- conditional access interactions  
- multi-tenant app pitfalls  
- verifying permissions programmatically  
- cross-tenant access cases

Let’s dive.

---

# 9.1 The `.default` Scope  
### *Powerful, misunderstood, and sometimes dangerous.*

`.default` is a **meta-scope** that tells Entra ID:

> “Give me all **Application Permissions** (App Roles for Applications)  
> that an admin has consented to for this client.”

This only applies to **client_credentials**.

Example request:

```
scope=api://<api-id>/.default
```

This returns **only App Roles**, never scopes.

### Why `.default` exists  
Originally created for Microsoft Graph:

```
scope=https://graph.microsoft.com/.default
```

It gives daemons whatever Graph permissions the admin approved.

### Common misconception  
Developers sometimes think:

> “`.default` gives me all scopes.”

❌ Wrong.  
It gives you **none**.  
Scopes always require a user.

---

# 9.2 Multi-API Scenarios  
### *One token, multiple audiences? Not in OAuth.*

In OAuth, a token has exactly one `aud` value.

If your app needs to call:

- API A  
- then API B  
- then API C  

It must request **separate tokens**.

### Why?

Because:

- Each API has its own App Roles  
- Each API has its own scopes  
- Each API has its own resource ID (`aud`)  

Sharing tokens across APIs breaks the trust model and is blocked by design.

---

# 9.3 On-Behalf-Of (OBO): The Hybrid Flow  
### *When a backend API needs to call another API using the user’s identity.*

Scenario:

1. Front-end app gets a token for API A  
2. API A needs to call API B  
3. API A must request a **new** token “on behalf of” the user

### OBO token characteristics

The resulting token:

- Includes **`scp`** (delegated permissions)  
- Represents the **user** (`sub` = user GUID)  
- Identifies the **frontend client** via `azp`  
- May include **App Roles** if configured, but only in special cases  

OBO is the **only** scenario where a token can have user-related and app-related claims.

### Most common OBO bug  
Backend app sends the **original** token to API B.

Token fails because:

- `aud` mismatch  
- Wrong permissions  

---

# 9.4 Conditional Access and API Permissions  
### *CA affects user-based flows, but not daemon flows.*

Conditional Access policies apply when:

- a **user** signs in  
- a user-based flow requests access (Authorization Code, Device Code, ROPC)

They **do not** apply to:

- client_credentials  
- daemons  
- background services  

If your API needs CA rules for machine-to-machine traffic:

> **You must enforce them at the API layer.**

Examples:

- Only allow certain client app IDs  
- Only allow tokens issued after certain Policies  
- Enforce certificate-based auth for daemons

---

# 9.5 Multi-Tenant Apps  
### *Where permission behavior gets spicy.*

In a multi-tenant setup:

- Your App Registration lives in your tenant  
- Each customer tenant creates an Enterprise Application instance  
- Each tenant manages its own:
  - admin consent  
  - delegated permissions  
  - application permissions (App Roles)  
  - assignments  
  - conditional access  

If a customer reports:

> “The token is empty.”

The cause is almost always:

- Missing App Role assignment in the **customer’s** tenant  
- Incorrect `.default` usage  
- A scope request without user interaction  
- Missing admin consent  

---

# 9.6 Programmatically Verifying Permissions  
### *Never trust the UI. Always trust the token.*

Inside an API (C#, Python, Node), the correct pattern is:

### Check scopes  
```csharp
var hasScope = httpContext.User.HasClaim("scp", "Orders.Read");
```

### Check App Roles  
```csharp
var hasRole = httpContext.User.IsInRole("Orders.Read.All");
```

### Check multiple permissions  
```csharp
if (hasScope || hasRole)
{
    // allow request
}
```

This ensures:

- both user and daemon scenarios work  
- hybrid flows work  
- misconfiguration is detected early  

---

# 9.7 Cross-Tenant Calls and External Identities  
### *The new frontier in enterprise API design.*

Scenarios:

- Partner tenants call your API  
- External apps act as daemons  
- B2B users call internal APIs  

Key points:

- App Roles (Application) must be granted in the **external** tenant  
- Consent must be done in the external tenant  
- API must validate issuer carefully  
- You may need to allow multiple `iss` values  
- Using Microsoft Entra ID External Identities simplifies federation  

This is a whole topic on its own, but important to know at a high level.

---

# 9.8 Final Recommendation for Real-World Systems

If you build or secure APIs in enterprise environments:

- **Use Scopes** for user-facing apps  
- **Use App Roles (Application)** for daemons  
- **Use `.default`** only for daemons  
- **Do not mix scopes and app roles** unless using OBO  
- **Document role assignments** in the Enterprise Application  
- **Never assume API Permissions UI reflects the token**  
- **Design your API to check roles/scopes explicitly**  

Following these guidelines eliminates 95% of OAuth-related incidents.

---

# 10. FAQ & Troubleshooting Guide  
### *The most common “WTF moments” when working with Entra ID API permissions — solved.*

This section collects the questions developers, architects, and admins ask the most.  
Use it as a quick-reference guide when debugging real-world OAuth issues in Entra ID.

---

# 10.1 “My token is empty — no `scp`, no `roles`”  
### ✔ Root cause  
The app is requesting permissions that **don’t match the flow**.

- Using `client_credentials` → scopes never appear  
- App Role not assigned → roles never appear

### ✔ Fix  
- If it’s a **daemon**:  
  - Use `.default`  
  - Assign an **App Role (Application)**  
- If it’s a **user app**:  
  - Request the scope with `scope=`  
  - Ensure user/admin consent

---

# 10.2 “I added a Delegated Permission but it doesn’t show in the token”  
### ✔ Root cause  
You added a **scope** but the app is not doing a **user-based flow**.

### ✔ Fix  
Use an Authorization Code, Device Code, SPA, or OBO flow.

---

# 10.3 “I added an Application Permission but it doesn’t show in the token”  
### ✔ Root cause  
An App Role (Application) was added, but:

- admin consent not granted  
- assignment not done in Enterprise Application  
- token request missing `.default`

### ✔ Fix  
- Grant admin consent  
- Assign the App Role  
- Request token with:  
  ```
  scope=api://<api-id>/.default
  ```

---

# 10.4 “Assignment required = Yes breaks my app”  
### ✔ Root cause  
The Enterprise Application has this setting enabled, but:

- user is not assigned to a role  
- daemon app is not assigned to a role  
- no default role is present

### ✔ Fix  
Assign the correct role(s) to:

- users (for delegated perms)  
- applications (for app perms)

---

# 10.5 “`.default` doesn’t return scopes, only roles — is this normal?”  
### ✔ Short answer: Yes.  
`.default` **never** returns scopes.  
It always returns App Roles (Application).

---

# 10.6 “Can I have both `scp` and `roles` in the same token?”  
### ✔ Rarely.  
Only in **OBO scenarios**, where an API calls a second API on behalf of a user.

In normal flows:  
- user → `scp`  
- daemon → `roles`

---

# 10.7 “My daemon app needs delegated permissions — is that possible?”  
### ✔ No.  
Delegated permissions require a **user**.  
Daemons have no user → no delegated permissions.

Use an App Role instead.

---

# 10.8 “Do I need both Scopes *and* App Roles for my API?”  
### ✔ Yes, if your API must support:  
- user flows (web apps, SPAs, mobile apps)  
- daemon flows (services, background jobs)

Define:

- 1+ scopes for users  
- 1+ App Roles (Application) for daemons

---

# 10.9 “Why does my app fail after enabling Conditional Access?”  
### ✔ Root cause  
Conditional Access only applies to **user flows**.  
Your app may now require:

- MFA  
- compliant device  
- specific network conditions  
- particular identity provider

### ✔ Fix  
Review CA policies affecting sign-in.

Daemon flows bypass CA entirely.

---

# 10.10 “Why does my partner’s tenant get empty tokens?”  
### ✔ Root cause  
For multi-tenant apps:

- customer tenant has not assigned App Roles  
- customer tenant has not granted admin consent  
- customer tenant misunderstanding scopes vs roles

### ✔ Fix  
In the partner’s tenant:

- grant admin consent  
- assign App Roles  
- validate `.default` usage  
- validate token on jwt.ms

---

# 10.11 “How can I debug token problems quickly?”  
### ✔ The 3-step method  
1. **Decode token on https://jwt.ms**  
2. Check which permissions appear:  
   - `scp` → user  
   - `roles` → application  
3. Compare with your App Registration → Expose an API

If they don't match:  
→ Check Enterprise Application assignments  
→ Check the flow used  
→ Check the requested scopes

---

# 10.12 “My API receives tokens meant for a different API”  
### ✔ Root cause  
Your client app used the wrong resource:

```
scope=api://<wrong-api>/.default
```

### ✔ Fix  
Check `aud` in the token → must match your API.

---

# 10.13 “Can I rename scopes or roles after deployment?”  
### ✔ Not safely.  
Clients cache permissions.  
Renaming may break:

- consent  
- assignment  
- existing integrations  
- automation scripts

Use new scopes/roles instead.

---

# 10.14 “Should I disable ‘user assignment required’?”  
### ✔ Depends.  
You should keep it **ON** if:

- only specific users/apps can access the API  
- sensitive data is involved  
- the API is internal

You can keep it **OFF** if:

- the API is public/multi-tenant  
- no sensitive data  
- you’re using scopes only

---

# 10.15 “What’s the difference between consent and assignment again?”  
### ✔ User/Admin consent  
Allows the client to *request* the permission.

### ✔ Assignment  
Grants the permission to a specific user/app instance.

Both must be satisfied for permissions to appear in the token.

---

# Conclusion  
### *You now fully control how Entra ID handles API permissions.*

By reaching the end of this guide, you’ve gone through the entire landscape of how Microsoft Entra ID manages:

- **Scopes (Delegated Permissions)**  
- **App Roles (Application Permissions)**  
- **Consent**  
- **Assignment**  
- **Token emission logic**  
- **User vs daemon flows**  
- **Real lab scenarios**  
- **Troubleshooting patterns**  

What you now know puts you ahead of most developers, architects, and even experienced cloud engineers.

---

# 🎯 The 5 Golden Rules to Remember

## **1️⃣ Scopes = Delegated Permissions = always require a user**  
If there is a user → expect `scp`.  
If no user → scopes do nothing.

## **2️⃣ App Roles = Application Permissions (for applications)**  
App Roles (Application) → appear as `roles` in tokens.  
They must be *assigned* in the Enterprise Application.

## **3️⃣ API Permissions UI shows configuration — not reality**  
Only the **token** tells you what the client actually received.

## **4️⃣ The Enterprise Application enforces access**  
Assignments, “User assignment required”, and app-level authorization all live here.

## **5️⃣ `.default` is for daemons — never for user apps**  
`.default` always returns App Roles.  
Never scopes.

---

# 🚀 Why this matters

Mastering Entra ID permissions means you can now:

- Build clean, future-proof OAuth architectures  
- Design APIs that work for both users and machines  
- Debug token issues in seconds  
- Explain the model clearly to customers and colleagues  
- Avoid 90% of production incidents caused by misconfigured permissions  

You’ve turned what most consider “black magic” into a predictable, crystal-clear system.

---

# 🧠 Final thought

Entra ID isn’t complicated — it’s **consistent**.

Once you understand the mental model:

- *What you define* (App Registration)  
- *What you assign* (Enterprise Application)  
- *What Entra emits* (token)  
- *What your API enforces* (authorization logic)  

Everything makes sense.

Keep this article as your reference.  
Use the lab to debug.  
And trust the token — always.

---

Thank you for reading.  
Now go build secure, elegant APIs. 💙  





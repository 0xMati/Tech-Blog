# Advanced Conditional Access How Entra Decides in a Zero Trust World  
**From Baseline Security to Adaptive Zero Trust (Deep Dive Edition)**
🗓️ Published: 2025-12-13

---

## TL;DR (for people who have meetings)

- **Conditional Access (CA)** is *not* a threat detection system. It’s the **real-time policy engine** that decides: *allow / require controls / block*.
- CA decisions happen **during token issuance**. If no new token is minted, **CA won’t magically re-run**.
- If you don’t understand **tokens + sessions**, you’ll keep asking “why is the user still logged in?” (and the logs will keep answering: “because the token is still valid”).
- Mature CA design is **few policies**, broad scope, strong hygiene: **Report-only**, break-glass, automation, and rollback.
- Advanced CA isn’t “bonus features”. It’s the **modern baseline**: **Authentication Strengths**, **Authentication Context**, **Device/App filters**, **External user granularity**, **Workload identities**, **Global Secure Access**, **EAM**, and **Mandatory MFA for admin portals**.

---

# Chapter 1 — What Conditional Access really is (and where it lives)

## 1. Conditional Access, beyond “MFA everywhere”

The security perimeter is gone. Identities authenticate from anywhere, on any device, to any application — often outside the organization’s direct control.

Conditional Access is Microsoft Entra’s **policy enforcement engine**.  
It does not detect attacks. It does not hunt threats.  
It **decides, in real time, whether an access request should succeed, be challenged, or be blocked**.

If you think Conditional Access is just “MFA rules with a fancy UI”… let’s fix that.

---

## 2. Zero Trust principle: *No application is trusted by default*

Zero Trust is not a product. It is a mindset:

> **Never trust an access request — always verify it, every time.**

In a Zero Trust model, **every application must be explicitly protected by Conditional Access**.  
Any app excluded from CA quietly becomes part of a trusted perimeter — whether you wanted that or not.

**Best practices**
- Apply at least one baseline CA policy to **all cloud apps**
- Treat exclusions as **temporary exceptions**, not “design”
- Regularly review excluded apps and legacy dependencies

> **Rule of thumb:** in CA, *absence of policy is itself a policy* — and it’s usually an unsafe one.

---

## 3. Security Defaults vs Conditional Access

Microsoft offers two ways to enforce MFA:

- **Security Defaults** (baseline protection, limited control)
- **Conditional Access** (granular, adaptive enforcement)

**Security Defaults**
- Available to all tenants
- Enforce baseline MFA with minimal configuration
- Limited visibility and flexibility

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-13-41-32.png)

**Conditional Access**
- Requires **Microsoft Entra ID P1 or P2** (or equivalent bundles: *Microsoft 365 Business Premium, M365 E3/E5, EMS E3/E5*)
- Supports risk, device, session, and app-based conditions
- Enables Zero Trust enforcement at scale

Security Defaults are a **starting point**.  
Conditional Access is the **control plane**.

---

## 4. Conditional Access vs Identity Protection (no more confusion)

This distinction matters — a lot.

| Capability | Identity Protection | Conditional Access |
|---|---|---|
| Detect compromise | Yes | No |
| Use ML & large-scale telemetry | Yes | No |
| Produce a risk score | Yes | No |
| Enforce access decisions | No | Yes |
| Issue or deny tokens | No | Yes |

- **Identity Protection** answers: *“Is this risky?”*  
- **Conditional Access** answers: *“Given this risk, what do we do?”*

CA never calculates risk by itself.  
It **consumes outcomes** produced by other engines.

---

## 5. Where CA executes: token issuance (the part most people miss)

Conditional Access is **not** evaluated *after* authentication.  
It is evaluated **during token issuance**.

### Simplified evaluation flow

```text
User authentication
   ↓
Signal collection
(identity, device, location, risk, session, app/action)
   ↓
Conditional Access evaluation
(policy evaluation & enforcement)
   ↓
Token issued / denied / constrained
   ↓
App access + session controls
```

### Key implications

- **No token → no access**
- CA decisions influence **token claims** and session behaviors
- **If no new token is issued, CA is not re-evaluated**

This explains the classic “why did this user stay logged in?” question.

---

## 6. Tokens, sessions… and the hard truth

Conditional Access does **not** continuously inspect traffic.  
It acts at **token issuance time**.

That means:
- A user can pass CA at 09:00
- Keep a valid token
- Still access resources at 17:00
- Without CA being re-evaluated

Unless:
- **Sign-in Frequency** forces reauthentication
- **Continuous Access Evaluation (CAE)** revokes the session/token
- The app triggers a new token request

> **Hard truth:** if you don’t understand tokens, you don’t really understand Conditional Access.

---

## 7. Session controls that actually matter

### 7.1 Sign-in Frequency

Sign-in Frequency defines **how often Conditional Access forces a new interactive sign-in**, triggering a full policy re-evaluation.

By default, without Sign-in Frequency:
- Access tokens are short-lived (~1 hour)
- Sessions can persist via silent token renewal
- Conditional Access is **not re-evaluated interactively** unless:
  - the user signs in again,
  - a blocking event occurs (password reset, account disabled),
  - or Continuous Access Evaluation (CAE) revokes the session.

Sign-in Frequency is **not a baseline control** and should not be applied universally.

It is most relevant for:
- **Privileged roles and admin portals**
- **Sensitive or high-value applications**
- **Risk-based step-up scenarios** (for example: risk detected → reauthentication every time)

Applying it broadly to all users often increases friction without proportional security gains.

**Key point:** Sign-in Frequency reduces long-lived access **where the risk justifies it** — it is not meant to force unnecessary reauthentication for standard users.

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-13-57-35.png)
---

### 7.2 Continuous Access Evaluation (CAE)

CAE enables near real-time enforcement when critical session events occur:

- User disabled
- Password changed
- Risk level changes
- Other critical account events

Reality check:
- CAE is **near** real-time, not instantaneous
- Not all apps support CAE
- CAE **complements** CA — it doesn’t replace good design

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-13-49-18.png)

---

# Chapter 2 — Signals, conditions, and enforcement building blocks

## 8. Signals CA can evaluate (and why correlation matters)

Conditional Access evaluates multiple signal categories simultaneously:

| Signal category | Examples |
|---|---|
| Identity | User, group, role, workload identity |
| Device | Compliance, join type, OS |
| Location | Named locations, IP ranges |
| Risk | User risk, sign-in risk |
| Session | Sign-in frequency, CAE |
| App / Action | Cloud app, authentication context (protected actions) |

The power of CA comes from **correlation**, not single conditions.

---

## 9. Risk-based Conditional Access (deep dive)

Risk-based CA consumes risk signals from multiple engines.

Three different models exist:

| Risk type | Signal source | Scope | Typical action |
|---|---|---|---|
| **Sign-in risk** | Entra ID Protection | Single authentication | Require MFA / Block |
| **User risk** | Entra ID Protection | Identity over time | Require password change / Block |
| **Insider risk** | Microsoft Purview (Adaptive Protection) | User data-related behavior over time | Require stronger auth / Terms of Use / Block |

Sign-in risk is **transactional** (one auth attempt).  
User risk is **sticky** (the identity stays risky until remediated).  
Insider risk is **behavioral** (data & usage patterns), and is meant to drive **adaptive enforcement** based on internal risk context.

> **Common pitfall:** applying **User Risk** policies to **guests** and wondering why access turns into a permanent lockout.

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-14-06-15.png)

---

### 9.1 Migrate legacy Identity Protection risk policies to CA

Legacy Identity Protection risk policies (user risk / sign-in risk) should be migrated to Conditional Access.

Benefits:
- Single policy plane
- **Report-only mode** for safe testing
- Graph API support and automation
- Better sign-in logs diagnostics (which policy applied)
- Ability to combine risk with other conditions (device, location, etc.)

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-14-07-19.png)

---

### 9.2 A practical pattern: Risk + Sign-in Frequency = “Every time”

**MFA is the control.**  
**Sign-in Frequency is the trigger** that forces a fresh authentication (and token issuance) so the control can be applied again.

A common pattern:
- Normal access → no additional friction
- Risk detected → **Require MFA** + **Sign-in Frequency = Every time**

Why it works:
- It prevents previously issued tokens from bypassing a newly detected risk.
- It forces Conditional Access to re-evaluate the decision on each risky attempt.

> **Nuance:**  
> Sign-in Frequency = *Every time* should be reserved for **high-risk signals, privileged roles, or sensitive applications**.  
> Applying it tenant-wide would introduce unnecessary user friction without proportional security benefit.

---

## 10. Authentication Methods Policy (the foundation beneath CA)

Conditional Access does not define *which authentication methods exist*.  
It defines **when and how they are required**.

The list of allowed methods is governed by the **Authentication Methods Policy**.

It is the recommended control plane for:
- MFA methods
- Passwordless methods
- Registration scope
- Method availability per user/group

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-14-20-03.png)

### 10.1 From legacy MFA/SSPR to unified method governance

Historically, methods were managed through:
- legacy MFA settings
- legacy SSPR settings

These legacy models:
- apply tenant-wide
- lack granularity
- don’t model modern passwordless well

The Authentication Methods Policy provides a unified approach.

### 10.2 Methods vs enforcement (critical separation)

| Layer | Responsibility |
|---|---|
| Authentication Methods Policy | Defines **which methods are allowed** |
| Conditional Access | Defines **when/how methods are required** |

Example:
- Methods Policy enables **FIDO2** and **Microsoft Authenticator**
- CA enforces **phishing-resistant MFA** for a sensitive app

If methods aren’t enabled/scoped/registered correctly, CA enforcement will fail or degrade.

### 10.3 Governance and roles

The Authentication Methods Policy can be managed by the **Authentication Policy Administrator** role.

This separation of duties:
- reduces blast radius
- prevents mixing method governance with policy enforcement
- improves operational hygiene

---

## 11. Authentication Strengths (more than “MFA yes/no”)

Authentication Strength lets you control **how MFA is performed**, not just whether it happens.

Examples:
- Require phishing-resistant MFA
- Exclude SMS-based methods
- Enforce hardware-backed credentials

Authentication Strength is **context-aware**. It can be used to:
- require specific methods for sensitive resources
- require a specific method for sensitive actions (with Authentication Context)
- enforce stronger auth outside corporate networks
- require more secure methods for high-risk users
- enforce specific methods for guest users (with cross-tenant settings)

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-14-26-01.png)

---

## 12. Authentication Context (protected actions, not just app entry)

Classic Conditional Access enforces controls **when the application is accessed**.

Authentication Context introduces a different model:
> **Step-up authentication triggered by the application itself, when a user reaches a sensitive action or data path inside the app.**

This is **application-triggered Conditional Access**, evaluated *at runtime*, not only at sign-in.

Authentication Context must not be confused with **User actions** in Conditional Access:
- *User actions* protect **global identity workflows** (MFA registration, device registration)
- *Authentication Context* protects **in-app actions and data paths**

---

### 12.1 What Authentication Context actually enables

Authentication Context is designed for **application-defined protected actions**, such as:
- Accessing sensitive employee, customer, or financial data
- Performing high-value or irreversible business transactions
- Executing administrative actions **inside an application**
- Calling sensitive APIs or data scopes requiring higher assurance

These are **not Entra-wide actions**.  
They are **business or security decisions owned by the application**.

The application decides *when* stronger assurance is required — Conditional Access decides *how* it is enforced.

---

### 12.2 Authentication Context vs User Actions

| Capability | Authentication Context | User actions |
|---|---|---|
| Triggered by | Application | Microsoft Entra ID |
| Scope | In-app actions & data paths | Global identity workflows |
| Extensible | Yes (custom contexts) | No (fixed list) |
| Typical use | Step-up auth inside apps | MFA registration, device join |
| Zero Trust role | Action-level enforcement | Identity hygiene enforcement |

Only **Authentication Context** enables true **Zero Trust inside the application**.

---

### 12.3 How it works (conceptually)

Applications using **OpenID Connect (OIDC)** can request a specific authentication context by including an `acrs` claim when a sensitive action is reached.

Conditional Access evaluates this request **at that moment**, not only at initial sign-in.

```text
User accesses app → standard authentication
           ↓
User reaches protected action or data
           ↓
Application requests authentication context (OIDC acrs claim)
           ↓
Conditional Access evaluates policy
           ↓
Step-up enforced (e.g. phishing-resistant MFA)
           ↓
Access granted for that protected action
```

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-15-16-40.png)

---

## 13. MFA registration: the “Trust on First Use” (TOFU) trap

MFA registration introduces a risk many teams underestimate: **Trust on First Use (TOFU)**.

The very first MFA registration is implicitly trusted:
- no prior device trust
- limited behavioral baseline
- minimal historical context

If an attacker already controls the primary credentials, they may:
- register their own MFA method,
- lock out the legitimate user,
- establish long-term persistence.

---

### 13.1 Why TOFU cannot be fully eliminated

There is no cryptographic way to prove that *the first registrant is the legitimate user*.

MFA registration is therefore **a risk-reduction problem**, not a risk-elimination one.
The goal is to **increase attacker cost and reduce silent persistence**, not to guarantee identity.

---

### 13.2 Practical controls to reduce TOFU risk

**1. Control *when* MFA registration happens**  
Avoid arbitrary or random registration prompts.

Prefer:
- registration during onboarding (with TAP),
- first access to corporate resources (from trusted location),
- known, documented entry points.

This reduces surprise and social engineering opportunities.

---

**2. Restrict registration context with Conditional Access**  
Use Conditional Access to limit *where* MFA registration can occur:
- trusted locations,
- managed or compliant devices,
- low-risk sign-ins only.

This ensures the first MFA method is not registered from an unknown or hostile context.

---

**3. Apply risk-based Conditional Access to registration flows**  
If **sign-in risk** or **user risk** is detected:
- block MFA registration,
- or require stronger authentication before allowing it.

This prevents attackers from registering MFA while the identity is already suspicious.

---

**4. Monitor MFA registration explicitly**  
MFA registration is a **high-signal security event**.

Teams should:
- monitor Entra audit logs for registration events,
- alert on unusual timing, location, or volume,
- investigate registration immediately after credential compromise indicators.

Registration without follow-up is how TOFU becomes persistence.

---

**5. Combine with user education**  
Users must know:
- when MFA registration is expected,
- what a legitimate registration flow looks like,
- when to report suspicious prompts.

Without user awareness, TOFU becomes an attacker advantage.

---

### 13.3 Key takeaway

MFA registration is **a privileged operation**, not a neutral setup step.

Treat it as:
- a controlled process,
- a monitored event,
- and a potential attack surface.

Strong MFA enforcement starts **before** MFA is even registered.


---

## 14. Privileged access: CA and PIM are a coupled design

Privileged identities require stricter CA controls.

CA complements PIM by:
- enforcing strong authentication at elevation time
- restricting privileged access to trusted devices/locations
- reducing session persistence

Key principle:
- PIM governs **who can become privileged**
- CA governs **how and under what conditions** that privilege is exercised

Treating privileged users like standard users is a fast path to security debt (and late-night incidents).

If your goal is to ensure that users must provide authentication during activation, you can use On activation, require Microsoft Entra Conditional Access authentication context together with Authentication Strengths. These options require users to authenticate during activation by using methods different from the one they used to sign in to the machine.

For example, if users sign in to the machine by using Windows Hello for Business, you can use On activation, require Microsoft Entra Conditional Access authentication context and Authentication Strengths. This option requires users to do passwordless sign-in with Microsoft Authenticator when they activate the role.

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-15-29-19.png)
---

## 15. Device filters (dynamic targeting at sign-in time)

Device filters are not groups.  
They are **dynamic expressions evaluated at sign-in time** against device properties.

Implications:
- No membership processing
- No static assignment
- Real-time evaluation

### 15.1 The “null device” behavior

For **unregistered/unknown devices**, device properties often evaluate to **null**.

Consequences:
- Filters relying on attributes may never match
- Policies might silently not apply
- You can create security gaps without realizing

That’s why negative logic is sometimes required (carefully):
- target devices that are **not compliant**
- target devices that are **not joined**
- block **unmanaged** devices

> keep it simple, If you have to explain your filter twice, it’s probably wrong.

---

## 16. Application filters (custom security attributes) — scale without policy sprawl

Application filters allow you to tag service principals with **custom security attributes** and reference those tags in CA policies.

**Important behavior:** filters are evaluated **at token issuance runtime**, not just at policy configuration time.

So:
- Apps are not “assigned” statically
- The decision is made dynamically during auth
- New apps become protected as soon as they receive the matching attribute

Operational wins:
- Automatic coverage for newly onboarded apps
- Reduced drift (“we forgot to add the app to CA”)
- Better governance

Role separation exists here too (dedicated roles):
- Attribute Definition Administrator
- Attribute Assignment Administrator

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-15-31-07.png)
---

# Chapter 3 — External users, break-glass, admin enforcement, and modern edge cases

## 17. External users targeting (guests, externals, and the “it depends” matrix)

Conditional Access provides granular targeting for external users — far beyond “guest vs member”.

External users can be categorized by:
- how they authenticate (internal vs external)
- relationship to tenant (guest vs member)
- tenant/source conditions in B2B scenarios

### 17.1 UX change (no functional impact, more precision)

The former **“All guest and external users”** option has been replaced with:
- **“Guest and external users”** with explicit sub-types

This change:
- does **not** alter Conditional Access evaluation logic,
- improves policy scoping clarity and auditability,
- enables precise include / exclude targeting for external identities.

What *did* change is **visibility and intent**.

---

### 17.1.1 External user types explained

Microsoft Entra now distinguishes several categories of external users, based on **how the identity is created and how authentication is performed**.

| External user type | Description | Typical scenario |
|---|---|---|
| **B2B collaboration guest users** | External users invited into the tenant and represented as `Guest` objects | Partners, contractors, external consultants |
| **B2B collaboration member users** | External users invited but represented as `Member` objects | Long-term partners treated like internal users |
| **B2B direct connect users** | Users accessing resources via cross-tenant trust without being added as guests | Teams shared channels, multi-tenant collaboration |
| **Local guest users** | Guest accounts created and managed directly in the tenant | Temporary access, lab or test scenarios |
| **Service provider users** | External users coming from managed service providers (MSPs) | Outsourced IT or SOC providers |
| **Other external users** | Catch-all category for external identities not matching the above | Edge or legacy scenarios |

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-15-35-40.png)
---

### 17.1.2 Why this distinction matters for Conditional Access

Different external user types imply **different trust assumptions**:

- **B2B collaboration guests**  
  Often authenticate in their *home tenant* → cross-tenant trust becomes critical.

- **B2B member users**  
  Look like internal users but **are not owned by the tenant** → higher blast radius if over-trusted.

- **B2B direct connect users**  
  Never exist as guest objects → Conditional Access depends heavily on **cross-tenant access settings**.

- **Service provider users**  
  Usually highly privileged → should be isolated with stricter CA policies.

Without explicit sub-types, all these identities were effectively treated the same.

---

### 17.1.3 Design implication

The new model forces administrators to answer a critical question explicitly:

> *Which kinds of external identities do we actually trust — and under what conditions?*

This reduces:
- accidental over-inclusion,
- blanket MFA enforcement on all guests,
- blind trust in partner-issued claims.

Granularity here is not cosmetic — it is **a prerequisite for Zero Trust in B2B scenarios**.

---

## 18. Cross-tenant access settings (inbound/outbound + trusted claims)

Cross-tenant access is evaluated on **both sides**:

- **Outbound access settings** (home tenant): who can go out, to which apps/tenants
- **Inbound access settings** (resource tenant): who can come in, and which claims are trusted

Inbound trust can allow the resource tenant to accept or reject security claims from the other tenant, including:
- MFA claims
- Compliant device claims
- Hybrid Microsoft Entra ID joined device claims

Why it matters:
- Without trust alignment, you get redundant MFA prompts and confusing behavior
- With alignment, CA remains Zero Trust while reducing friction

---

## 19. Break-glass accounts (reality, not theory)

Break-glass accounts exist because CA *will* lock you out one day.

Baseline best practices:
- Cloud-only
- `*.onmicrosoft.com`
- Strong auth (FIDO2 / CBA)
- Explicitly excluded from CA policies
- Actively monitored (sign-in & audit logs)

### 19.1 Always use more than one break-glass account

A single emergency account is a single point of failure.

Maintain **at least two**:
- One excluded from all CA
- One excluded from phone-based MFA dependencies (or configured differently)

### 19.2 Real-world scenarios that require break-glass

- Federation outage (AD FS / external IdP down)
- Telco outage (MFA phone/SMS unreachable)
- Loss of admin devices
- Misconfigured CA causing tenant-wide lockout
- Last Global Admin leaves the org
- Natural disaster / broad infrastructure outages

### 19.3 Method dependencies matter

Break-glass must not rely on the **same methods** as normal admins.

Example:
- Admins use Authenticator → break-glass uses FIDO2 or CBA
- Phone-based MFA common → at least one break-glass avoids phone dependency

### 19.4 Permanent role assignment required

Break-glass should have **permanent** Global Admin assignment.  
Making it “eligible” in PIM defeats the purpose (PIM activation can itself require MFA/CA).

### 19.5 Secure, non-personal credential storage

Credentials/devices should not be tied to one employee.  
Store them in secure locations accessible to multiple trusted individuals, with documented procedures.

---

## 20. Mandatory MFA for admin portals (outside Conditional Access)

Microsoft Entra enforces **mandatory MFA** for administrative access to critical portals — independently of CA.

Characteristics:
- Global
- Non-configurable
- Implemented by Microsoft Entra (not your CA policies)
- Visible in sign-in logs as the MFA requirement source

### 20.1 Scope and where you’ll see it

Applies to admin CRUD operations in:
- Azure portal
- Entra admin center
- Intune admin center
- Microsoft 365 admin center
- Azure CLI / PowerShell
- Azure mobile app
- IaC tooling

Rollout is phased (Phase 1 in 2024, Phase 2 through 2025).

### 20.2 What is *not* impacted

- Workload identities (managed identities, service principals)
- Non-admin access to Azure-hosted applications

If you use **user identities** for automation, those users will be impacted.  
Migrate user-based service accounts to **workload identities**.

### 20.3 Break-glass accounts are not exempt

Break-glass accounts are still required to authenticate with MFA once enforcement begins.  
Recommended methods: **FIDO2 passkeys** or **CBA**.

### 20.4 Postponement (possible, but risky)

Microsoft allowed postponement until **March 15, 2025** for complex environments.

Postponing increases risk: admin portals are prime targets.

---

## 21. External Authentication Methods (EAM) — Preview

External Authentication Methods (EAM) allow third-party authentication providers to satisfy MFA requirements **while identities remain managed in Entra ID**.

This is **not federation**.

With EAM:
- identity is managed in Entra ID
- external provider is used only for an authentication step
- Entra remains the authority issuing tokens/claims

### 21.1 What EAM can satisfy

- Conditional Access MFA requirements
- Risk-based CA policies
- PIM activation requirements
- Apps that require MFA

### 21.2 Technical model (OIDC-based)

```text
Primary auth to Entra
   ↓
CA requires MFA
   ↓
Redirect to external provider (OIDC)
   ↓
External auth performed
   ↓
Entra validates returned token/claims
   ↓
Sign-in completes, access token issued
```

### 21.3 Required metadata

- Provider Application ID (multi-tenant app) + admin consent
- Provider Client ID (identifies Entra as requesting auth)
- OIDC Discovery URL

### 21.4 Management via Microsoft Graph

Managing Authentication Methods Policy via Graph requires:
- `Policy.ReadWrite.AuthenticationMethod`

### 21.5 Preview limitations

- Not included in Authentication Strengths
- No system-preferred MFA (in current preview)
- No proof-up/registration flows
- No credential recovery (SSPR)
- Requires Entra ID P1+

Expectation communicated: **by end of January 2025**, support for:
- default sign-in method
- system preferred MFA

---

## 22. Workload identities (where “MFA” doesn’t exist)

A workload identity is an identity that allows an application/service principal to access resources (sometimes in a user context).

They differ from users because they:
- can’t perform MFA
- often have no formal lifecycle process
- must store credentials or secrets somewhere

### 22.1 Why workloads are hard

Core challenges:
- Access control complexity across many services
- Credential management and rotation at scale
- Monitoring/visibility gaps
- AuthN/AuthZ constraints (no interactive verification)
- Hybrid/multi-cloud integration complexity
- Identity sprawl (orphaned, unused, over-permissioned identities)

Modern attacks increasingly target **non-human identities** because they often yield persistent, broad access.

### 22.2 What CA can enforce for workloads

- **Conditional Access for workload identities** (service principals owned by your org)
- Location conditions (trusted IPs/egress)
- Risk policies combined with **CAE for workload identities** (real-time enforcement on risk/location signals)

### 22.3 Controls that complement CA (but are not CA)

- **Managed identities**: no secret management for Azure-hosted workloads
- **Workload identity federation**: avoid stored secrets for supported scenarios (GitHub Actions, Kubernetes, external compute)
- **Access reviews for service principals**: review privileged directory role assignments, permissions, orphaned SPs
- **Custom security attributes**: govern and scope apps consistently

![](assets/Advanced%20Conditional%20Access%20How%20Entra%20Decides%20in%20a%20Zero%20Trust%20World/2025-12-15-15-43-27.png)

---

## 23. Universal Conditional Access with Global Secure Access (traffic-level enforcement)

Traditional CA evaluates access at the **application sign-in level**.  
Global Secure Access (GSA) extends CA enforcement to **network traffic**.

This is a big shift: CA is no longer only about apps; it can control traffic profiles and tunnels to Microsoft Security Service Edge.

### 23.1 Universal CA flow

1. GSA client connects to Microsoft’s Security Service Edge
2. Client redirects to Entra for authN/authZ
3. User + device authenticate (often seamlessly via a valid **PRT**)
4. **Universal CA policy enforcement** occurs for Microsoft/Internet tunnels
5. Entra issues access token for the GSA client
6. Token is presented to Security Service Edge and validated
7. Tunnels establish
8. Traffic is acquired and tunneled to destination

### 23.2 Why it matters

- Apply CA to Microsoft traffic and private access flows
- Better IP/source visibility
- Combine identity/device/risk and network context in one decision
- Stronger troubleshooting because identity decisions map to tunnels

---

# Chapter 4 — Operations: design, automation, and troubleshooting (the “don’t get paged” part)

## 24. Conditional Access as Code (because humans forget)

Treat CA like infrastructure:
- Microsoft Graph APIs
- Export and backup
- Drift detection
- Change auditing

Manual configuration doesn’t scale. Automation does.

### 24.1 Why automation matters (practically)

Automation helps:
- Reduce human error (wrong exclusions, inverted logic, missed break-glass)
- Automate testing/validation (especially with Report-only)
- Integrate approval workflows (PRs, reviews, gated deployments)
- Enforce consistent naming conventions
- Track changes (audit trail + accountability)
- Deploy at scale faster
- Backup CA policies regularly
- Restore policies to a known-good state (point-in-time rollback)

> If you want “resilient CA”, you want “versioned CA”.

### 24.2 Policy sprawl is the enemy

Fewer, broader, well-documented policies reduce:
- conflicts
- unexpected interactions
- troubleshooting time
- lockout risk

If a CA policy cannot be explained in one sentence, it’s probably too complex.

---

## 25. Report-only mode (design tool, not a “test button”)

Report-only mode is powerful because it lets you:
- predict user impact without disruption
- spot unexpected exclusions/legacy dependencies
- validate policy logic against real traffic

But:
- it does not perfectly simulate enforcement
- token reuse/session behavior still apply
- sign-in logs remain the source of truth

A CA policy should not move to enforcement without time in Report-only.

---

## 26. Troubleshooting: reality checks that save hours

Tools:
- Sign-in logs (start here)
- Conditional Access insights
- What-if tool (useful but imperfect)

Golden rule:
> **If it’s not in the sign-in logs, it didn’t happen.**

Also: operational processes matter as much as policy design:
- user blocked flows
- lost/replaced MFA devices
- re-registration procedures
- emergency playbooks

Strong policies without recovery procedures eventually become “please disable CA” tickets.

---

# Conclusion — Conditional Access is a policy engine, not magic

Conditional Access is powerful — but not magical.

It:
- enforces decisions at authentication time
- shapes tokens and sessions
- relies on the quality of upstream signals and method governance

Used well, it’s the backbone of Zero Trust.  
Used poorly, it becomes a very expensive annoyance engine.

Identity is the control plane.  
Conditional Access is where trust is decided.

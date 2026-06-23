---
title: "Active Directory Design Guidelines (Architecture Overview)"
date: 2026-06-23
---

# Active Directory Design Guidelines (Architecture Overview)

## Introduction

This document is an **architecture overview** for designing a new Active Directory (AD) forest — or for reviewing an existing one against good practice. It is deliberately written as a **hub**: it lays out the structural decisions that shape every AD deployment, and links to the deeper, focused articles in this collection for the topics that deserve their own treatment (tiering, DNS scavenging, JIT elevation, foreign security principals).

The guiding philosophy is simple: **the vast majority of "good AD design" is universal.** Whether you are building a single-company forest of 8,000 users or consolidating 150 small entities into one shared infrastructure, roughly 90% of the design is identical. What changes between scenarios is not the *nature* of the model but the *degree* to which certain dials — repetition, isolation, delegation rigor — are turned up.

For that reason, this article presents the **generic model first**, then closes with a dedicated section on one demanding application of it: the **shared forest hosting multiple delegated entities**.

> **🔵 Important — scope.**
>
> This is an *architecture* document. It explains the decisions and the *why*, not every click. For security boundary enforcement it relies on, and points to, the dedicated [Active Directory Tiering Model](Active%20Directory%20Tiering%20Model%20for%20On-Prem%20Environment.md). It is not a build runbook.

### 🗂️ Quick Navigation

- [🌲 1 — Forest and Domain Design](#-1--forest-and-domain-design)
- [🗂️ 2 — Organizational Unit (OU) Design](#-2--organizational-unit-ou-design)
- [🔐 3 — Delegation Model](#-3--delegation-model)
- [🛡️ 4 — Security Baseline and Tier 0](#-4--security-baseline-and-tier-0)
- [🌐 5 — Sites, Replication and Topology](#-5--sites-replication-and-topology)
- [📡 6 — DNS Design](#-6--dns-design)
- [🔗 7 — Trusts](#-7--trusts)
- [📐 8 — Group Policy Strategy](#-8--group-policy-strategy)
- [🛠️ 9 — Tooling and Industrialization](#-9--tooling-and-industrialization)
- [🏢 10 — Applied Scenario: A Shared Forest for Multiple Entities](#-10--applied-scenario-a-shared-forest-for-multiple-entities)
- [📌 11 — Summary of Key Decisions](#-11--summary-of-key-decisions)
- [📚 References](#-references)

### 🎨 Reading Legend

- 🔴 Critical: security boundary or compromise risk
- 🟡 Warning: high chance of lockout or operational breakage
- 🔵 Important: deployment constraint or sequencing requirement
- 🟢 Recommendation: best practice to improve resilience

---

## 🌲 1 — Forest and Domain Design

### 1.1 — One forest, one domain (when you can)

🟢 **Default to a single-domain forest.** Modern AD comfortably handles millions of objects in one domain, so object count is almost never a reason to split.

#### Why a single forest

> 🔴 **The forest — not the domain — is the security boundary in Active Directory.** Every domain in a forest shares the same schema, the same configuration partition, the same Enterprise Admins group, and full transitive trust. A Domain Admin in a child domain can, through well-documented techniques (SID history, trust key abuse, schema/configuration access), reach **any** other domain in the forest. There is therefore **no security isolation between domains of the same forest** — only an *administrative convenience* boundary.

The practical consequences:

- **Splitting into multiple domains does not contain a breach.** If you need a true security/blast-radius boundary (e.g. to separate production from a hostile or untrusted environment), you need a **separate forest**, not another domain. This is exactly why the admin-forest / red-forest pattern uses a *forest*.
- **A single forest gives you one schema, one global catalog, one trust fabric.** Cross-domain operations (GC lookups, universal group membership, Kerberos referrals) all cost something; collapsing to one domain removes that cost entirely.

#### Why a single domain

A single domain is simpler on **every** axis that matters operationally:

| Multi-domain adds… | …and you rarely need it |
|---|---|
| Additional DCs per domain (each domain needs its own resilient pair) | More hardware/VMs, patching, monitoring |
| Inter-domain replication + more complex site topology | More moving parts, more failure modes |
| Two sets of FSMO roles (PDC/RID/Infrastructure per domain) | More Tier 0 to protect and document |
| Cross-domain Kerberos referrals + GC dependency for logon | Subtle auth failures when a GC is unreachable |
| `ForeignSecurityPrincipals` and SID-history baggage | Harder ACL audits, migration debt |

🟢 **Fewer domains = smaller Tier 0 attack surface.** Every domain is another set of privileged groups, KRBTGT accounts, and DCs an attacker can target. Consolidation is a **security win**, not just an ops simplification.

#### Demolishing the usual "we need another domain" arguments

Most requests for a second domain are really requests for something a single domain already provides:

- **"Different password policies per population."** → Solved by **PSOs (Fine-Grained Password Policies)** — multiple coexisting policies in one domain, targeted by group. *Example: a 25-character PSO applied to `Contoso-Tier0-Admins` while standard users keep the default 12-character policy — all inside `corp.contoso.com`.*
- **"Departments/entities must be administered separately."** → Solved by **OU delegation** (§3). Delegation is an *OU* concern, never a *domain* one. *Example: handing `OU=Sales` to the Sales IT team without giving them any rights over `OU=Finance`.*
- **"Different GPOs per population."** → Solved by **OU structure + GPO linking** (§8). *Example: a stricter lockdown GPO linked only to `OU=Call-Center`, a looser one on `OU=Engineering`.*
- **"We want a different DNS namespace per entity."** → Solved by **additional UPN suffixes** and DNS zones, without a new domain. *Example: users in `corp.contoso.com` can still sign in as `alice@fabrikam.com` by adding `fabrikam.com` as a UPN suffix.*
- **"Isolation/security between business units."** → A domain does **not** provide this (see above). If you genuinely need it, the answer is a **separate forest**, and you should weigh that cost deliberately.

#### The legitimate reasons to split

🔵 There *are* real cases — they are just rarer than people assume:

- **A separate forest** (not domain) for a hard security boundary: admin/red forest, an untrusted M&A environment, a DMZ/extranet identity, or a sovereignty/air-gap requirement.
- **A separate domain** within a forest only for: legal/regulatory **replication** constraints that forbid certain data leaving a region, drastically different **DC operational ownership**, or genuinely incompatible **domain-wide** settings that PSOs can't cover.

> 🟢 **Rule of thumb:** start with **one forest, one domain**. Add a **domain** only when a domain-wide constraint forces it, and add a **forest** only when you need a real security boundary. Complexity in AD is a permanent tax — pay it only when you must.

### 1.2 — Functional level

🟢 **Set the Forest and Domain Functional Level to the highest value your DC fleet can support.** On a greenfield forest built entirely on Windows Server 2025, that means going straight to the **Windows Server 2025 functional level** — there is no reason to deploy a new forest at an older level.

#### What the functional level actually controls

A common misconception is that raising the functional level "turns on" most modern AD features. It doesn't. The functional level really does only **two** things:

1. **It sets a minimum OS version for domain controllers** — this is its main job. The level dictates **which Windows Server versions are allowed to be DCs**. *Example: at the 2025 level, every DC must be Windows Server 2025 (you can no longer add a WS2022 DC); at the 2016 level you can freely mix WS2016, 2019, 2022 and 2025 DCs.*
2. **It enables a small number of directory-wide behaviors** — a *handful*, not a big catalog (see the table below).

The table maps each level to the behaviors it unlocks and the DCs it allows:

| Functional level | What it unlocks | DCs allowed |
|---|---|---|
| **Windows Server 2016** | PAM with MIM, Kerberos PKINIT Freshness Extension, rolling of NTLM secrets for "smart card required" accounts | WS2016 → WS2025 |
| **Windows Server 2025** *(new — first new level since 2016)* | **32k database page size** optional feature + general supportability | **WS2025 only** |

> 🔵 **Correction worth knowing:** Windows Server 2019 and 2022 introduced **no** new functional level — both top out at the **2016** level. Windows Server 2025 is the **first new functional level since 2016** (it maps to `DomainLevel 10` / `ForestLevel 10`).

#### The trade-off of raising to the 2025 level

🟡 Raising to the **WS2025 functional level locks every DC to Windows Server 2025**. You can no longer introduce a WS2022 DC afterwards. On a greenfield all-2025 build this is a non-issue; on an existing forest it is a real constraint to weigh.

- The headline payload of the 2025 level is the **32k database page size** — a forest-wide ESE upgrade that lifts long-standing 8k limits. *Concretely: a **multivalued, non-linked** attribute can hold roughly **3,200 values instead of ~1,200**. (Note this does **not** apply to large group membership — `member` is a **linked** attribute with its own replication mechanism and was never bound by that limit.)* The upgrade is **decided at the forest level and requires *all* DCs to be 32k-capable**, which is exactly why **doing it at forest creation is ideal** (retrofitting later is heavier).
- Beyond that, the 2025 level is largely about **supportability** — not a big bag of new end-user features.

#### Don't confuse functional level with OS-level hardening

🟢 Most of the **security value** of Windows Server 2025 comes from the **DC operating system**, *independently of the functional level*. Even at the 2016 FFL, WS2025 DCs give you:

- **Kerberos no longer issues RC4 TGTs**; PKINIT cryptographic agility.
- **LDAP sealing/signing required by default** and **LDAP over TLS 1.3**.
- **SMB signing required by default**, SMB NTLM blocking, SMB rate limiter.
- **Randomized default machine-account passwords**; confidential attributes require an encrypted connection.
- **Delegated Managed Service Accounts (dMSA)** and the latest **Windows LAPS** improvements.
- **Credential Guard on by default**, NUMA scalability (>64 cores).

➡️ **Design takeaway:** choose the OS first (WS2025 everywhere), get most of the security benefit immediately, then set the functional level as high as your DC fleet allows — for a new all-2025 forest, that is the **2025 level**, ideally with the **32k page size** decision made up front.

### 1.3 — Naming

The forest root domain name is chosen **once** and is effectively **permanent** — Microsoft is explicit that this domain "remains the forest root domain for the life cycle of the AD DS deployment." Renaming is, at best, a heavy and constrained operation. So this is a decision worth getting right on day one.

#### The recommended pattern: a dedicated, registered subdomain

🟢 Build the AD name as a **prefix + a suffix you own and have registered** with an internet registrar — typically a **dedicated subdomain** of your public domain:

```
corp.example.com   ←  prefix "corp"  +  registered suffix "example.com"
ad.example.com     ←  prefix "ad"    +  registered suffix "example.com"
```

Why this pattern, per Microsoft guidance:

- 🔵 **Registered = globally unique.** Only names registered with an internet authority are guaranteed unique. If you later **merge with or acquire** an organization that uses the same name, two infrastructures using the same DNS name **cannot interoperate**. A registered name prevents that collision.
- 🔵 **A new prefix creates a clean namespace.** Attaching a *new* prefix to an *existing* registered suffix produces a dedicated AD namespace that integrates with your existing DNS **without modifying the existing infrastructure**.
- 🟢 **Pick a prefix that won't age.** Microsoft recommends **generic prefixes** like `corp` or `ds` — never a product line, OS, business unit, or geographic name, all of which change or become misleading over time.
- 🟢 **Keep it short.** DNS is hierarchical, so a short root keeps every descendant FQDN (and therefore computer names) short and memorable.

#### Names to avoid (and the actual reason)

| Anti-pattern | Why it's a problem (per Microsoft) |
|---|---|
| **Single-label name** (`contoso`, no suffix) | Can't be registered; requires extra configuration; the DNS Server service **can't locate DCs**; domain members **don't do dynamic updates** to single-label zones by default. Microsoft: *"Do not use single-label DNS names."* |
| **`.local` / any unregistered suffix** | Explicitly *not recommended*; `.local` collides with internet-standard special use. You also can't prove ownership, so **public CAs won't issue TLS certificates** for it¹ — friction for LDAPS, ADFS, and other TLS services. |
| **A real internet TLD on the intranet** (`.com`, `.net`, `.org`) | Intranet machines that also reach the internet can hit **name-resolution errors**. |
| **Your exact public domain** (`example.com`) | Forces **split-brain DNS** — you must maintain a duplicate internal copy of the public zone. A dedicated subdomain avoids this entirely. |
| **Acronyms / business-unit / division / geographic names** | Users may not recognize an acronym; BUs and divisions **change and become obsolete or misleading**; hard-to-spell geo names hurt usability. |
| **Underscores (`_`)** | RFC-strict applications **reject** the name; older DNS servers misbehave. |

#### NetBIOS name

- 🔵 The NetBIOS domain name is limited to **15 characters**; if your prefix is ≤ 15 characters, **the NetBIOS name simply equals the prefix** (e.g. prefix `corp` → NetBIOS `CORP`).
- 🟡 Keep it **short and stable** — it is awkward to change later and is what legacy/down-level systems display. Windows uses it in **uppercase** in practice.
- Avoid periods, ampersands, and the other disallowed characters; don't reuse a reserved word (it breaks trusts).

#### A couple of hard limits to respect

- 🔵 **FQDN ≤ 64 characters.** The AD FQDN appears **twice** in every `SYSVOL` GPO path, which is itself bound by the 260-character `MAX_PATH` limit — so the directory restricts the FQDN to 64 characters. Long, deep names eat into that budget.
- 🟢 **Keep the primary DNS suffix aligned** with the AD domain name to avoid a **disjoint namespace** (computer suffix ≠ AD domain), a known source of SRV-registration and locator problems.

> ¹ Industry fact (CA/Browser Forum baseline requirements), not a Microsoft statement: since 2015 public certificate authorities no longer issue TLS certificates for internal-only or unregistered names — one more reason to base AD on a name you actually own.

---

## 🗂️ 2 — Organizational Unit (OU) Design

The OU is the unit of **two things at once**: **delegation** and **GPO linking**. You therefore design the OU tree around those two needs — *not* around the HR org chart. The org chart changes every reorg; administration is far more stable, so the right design question is never *"how is the company organized?"* but:

> **"Who administers what, and which GPOs must apply to what?"**

### 2.1 — The core decision: what goes at the top of the tree?

This is the choice that shapes everything else, and it is usually framed wrongly as an either/or:

| Logic | Strength | Weakness |
|---|---|---|
| **By object type first** (`Users` / `Groups` / `Computers` near the top) | Simple, few OUs, no repetition; centralized, homogeneous administration | You **cannot** cleanly hand "the Sales objects" to a Sales admin |
| **By scope/department first** (a self-contained subtree per perimeter) | Clean **delegation** — hand a whole branch to a local admin, isolated by construction | Slightly more repetition |

🟢 **In reality you almost always do both** — the real question is *which logic sits at the top* (the first sort key). And the answer is dictated by **one thing: delegation**, because **delegation is inherited down a subtree**. So whatever you need to delegate as a unit must be a subtree.

#### What actually decides it

| Decisive question | → Top-level structure |
|---|---|
| Is administration **delegated per perimeter** (local IT teams, separate entities, admins who don't trust each other)? | **Yes → scope/entity first** |
| Is administration **centralized** — one IT team, isolation between populations is not a requirement? | **Yes → object type first** (simpler) |

#### Case A — Centralized administration → object type first

If a **single IT team** runs everything, splitting `Users` / `Computers` / `Groups` at the top is the simplest choice — fewer OUs, no repetition, and it maps naturally to GPO (user vs computer settings are separate anyway):

```
corp.contoso.com
├── OU=Users         (whole company)
├── OU=Computers
└── OU=Groups
```

→ Fits a single-IT organization, or any perimeter where **nobody needs to be isolated from anybody**.

#### Case B — Delegated administration → scope/entity first

The moment you must hand **"all of Sales"** to the Sales IT team **without** letting them touch Finance, Sales has to be a **self-contained subtree** holding its own users, computers and groups:

```
corp.contoso.com
└── OU=Departments
    ├── OU=Sales
    │   ├── OU=Users
    │   ├── OU=Computers
    │   ├── OU=Groups
    │   └── OU=Admins
    └── OU=Finance
        └── (identical template)
```

→ You set **one delegation on `OU=Sales`**, inherited to the whole branch. Isolation by construction.

🔴 **Why Case A breaks here:** if every user lives in one global `OU=Users`, you **cannot** cleanly delegate "the Sales users" to the Sales team — you'd be reduced to per-object ACLs, which is unmanageable and drifts immediately. **Delegation wants a subtree per perimeter.**

#### The nuance: it's a spectrum, not a binary

- 🟢 **Very small organization (single IT, a few dozen seats):** don't over-engineer. The flat object-type model (Case A) is perfectly fine — a per-department tree you never actually delegate is just empty ceremony.
- 🔵 **Growing / multi-team / multi-entity:** the more administration fragments, the further **up** the tree the scope dimension must move. At the extreme (many mutually-untrusted entities), the per-scope subtree becomes mandatory — that's the applied scenario in §10.
- ⚠️ **Whatever you pick, stay consistent.** The one genuinely unmanageable design is a **hybrid that switches logic by depth** (object-type here, scope there, at the same level). Pick the top-level key and apply it uniformly.

> 🟢 **Rule of thumb:** put **scope at the top only to the extent you actually delegate by scope**. No delegation boundary → object type first (simpler). Delegation boundary → scope first (so the boundary is a subtree). Everything else follows from that.

Note that admin/tiering OUs (`_Admin`, `_Infrastructure`, `_Staging` below) are a **separate, transverse axis**: they are organized by *function/tier*, independently of the production scopes — which is itself a deliberate, consistent split, not a contradiction.

### 2.2 — Generic baseline structure

```
example.com
│
├── OU=_Admin                 ← admin accounts, role/delegation groups, service accounts
├── OU=_Infrastructure        ← centrally managed objects (servers, gMSA), never delegated
├── OU=_Staging               ← pre-staging / unclassified objects before placement
│
├── OU=Departments (or Entities)
│   ├── OU=<Scope-A>
│   │   ├── OU=Users
│   │   ├── OU=Groups
│   │   ├── OU=Computers
│   │   └── OU=Admins         ← local admin accounts/groups for this scope
│   └── OU=<Scope-B>
│       └── (identical template)
│
└── (Domain Controllers stay in the native container)
```

### 2.3 — Rules of thumb

- 🔵 **Use an identical template** for repeated scopes — it is what makes deployment and delegation **scriptable**.
- 🟡 **Use a stable code** (`SCOPE001`) rather than the commercial name (which changes on mergers/renames); put the friendly name as a suffix.
- ⚠️ **Keep depth reasonable** (3–4 levels). Deep trees complicate GPO and delegation with no benefit.
- 🟢 Avoid **Block Inheritance**; favor a clean GPO design instead (see §8).
- 🔵 Protect OUs with **`ProtectedFromAccidentalDeletion`**.
- Note: the native **`Domain Controllers`** container does not move — DCs stay there with the Default Domain Controllers Policy.

---

## 🔐 3 — Delegation Model

### 3.1 — The golden rule: RBAC, never direct ACLs

🔴 **Never delegate rights to a user directly.** Always go through:

```
User  →  Role group  →  ACL / delegation on the OU
```

For each delegated scope, define a small, repeatable set of **role groups**:

| Role group (per scope) | Delegated scope (on the scope's branch) |
|---|---|
| `ROLE-<Scope>-UserAdmin` | Create/modify/disable users, reset passwords (non-admin), manage attributes |
| `ROLE-<Scope>-GroupAdmin` | Create/manage groups and memberships |
| `ROLE-<Scope>-ComputerAdmin` | Join/manage computer objects, read LAPS |
| `ROLE-<Scope>-Helpdesk` | Password reset + unlock only (reduced scope) |

➡️ A local admin placed in the scope-A role groups has **no rights** on scope B. **Isolation by construction.**

🟢 **Group scope — follow the A-G-DL-P model.** The group that actually *holds the permission* on the OU should be a **Domain Local** group; the **accounts** go into a **Global** group, which is then nested into the Domain Local one (**A**ccounts → **G**lobal → **D**omain **L**ocal → **P**ermission). Domain Local is the scope designed to carry resource permissions, and it can contain Global groups from any domain in the forest — which keeps the model clean if the forest ever grows beyond one domain. In a single-domain forest you can get away with plain Global role groups, but A-G-DL-P costs nothing to adopt up front and ages better.

### 3.2 — How to apply delegation

- 🔵 Apply delegation as **ACLs on the OU**, inherited to child objects. Define each role's permission set **once**, then apply it **identically** across every scope so the model stays consistent and auditable.
- ⚠️ **Avoid one-off, click-by-click delegation.** N scopes × several roles = hundreds of permission entries — they must be applied **uniformly from a single template**, not hand-crafted per scope (which inevitably drifts).
- 🔴 **Grant the narrowest right set — never `Full Control`.** Delegate only the specific permissions a role needs (e.g. *Reset Password* on user objects, *Create/Delete Computer objects*). `Full Control` — or any permission that includes **`WriteDACL`/`WriteOwner`** — lets the delegate **rewrite the OU's ACL or take ownership** and silently escalate their own rights. Least privilege here is a security boundary, not just tidiness.
- 🔴 **Protect admin objects**: local `OU=Admins` and role groups must not be delegable to end users (strict owner + ACL + accidental-deletion protection).
- 🟢 **Windows LAPS**: delegate *read* of the local admin password only on the computers in the scope's own OU.

### 3.3 — Isolation guardrails

- 🔴 **List Object Mode** (`dsHeuristics`) if scopes must not even *enumerate* each other's objects (by default any authenticated user can browse the directory). It strengthens confidentiality but complicates troubleshooting — evaluate the trade-off.
- 🟢 **Confidential attributes** for sensitive attributes when needed.
- ⚠️ Watch **group delegation**: a local GroupAdmin must never be able to add itself to a privileged central group.

### 3.4 — The AdminSDHolder / SDProp gotcha

🔵 There is one mechanism that **silently overrides OU delegation**, and every delegation design must account for it.

- A background process called **SDProp** runs **every 60 minutes on the PDC Emulator**. It compares the ACL of every **protected** account and group against the template ACL on the **`AdminSDHolder`** object (in `CN=System`), and **resets** any that differ.
- Crucially, **inheritance is disabled** on these protected objects — and it **stays disabled even if you move the object into another OU**. They are flagged with **`adminCount = 1`**.
- 🔴 **Consequence for delegation:** an ACL you set on an OU is **inherited** to its children — but a protected object placed in that OU **does not inherit it**. So delegation simply **does not apply** to protected accounts/groups. Worse, an account that *used* to be in a privileged group can be left **orphaned** with `adminCount = 1` and broken inheritance long after it was removed — a frequent source of "why doesn't my delegation work on this one user?".
- The protected set includes **Administrator, Administrators, Domain Admins, Enterprise Admins, Schema Admins, Account/Server/Print/Backup Operators, Domain Controllers, RODC, Replicator, Key/Enterprise Key Admins, and krbtgt**.

➡️ **Design takeaways:** keep **privileged accounts out of delegated production OUs** entirely (they belong in Tier 0 / admin OUs anyway, per §4); **audit for orphaned `adminCount = 1` objects** as part of routine hygiene; and never try to "fix" a protected object's ACL directly — SDProp will revert it within the hour. If you must change protected-object permissions, you edit the `AdminSDHolder` template (with great care).

---

## 🛡️ 4 — Security Baseline and Tier 0

Security is **not optional plumbing** — it is a structural pillar. The depth of this topic is covered in its own document; this section is the checklist that every design must satisfy.

> **🔵 See the dedicated article:** [Active Directory Tiering Model for On-Premises Environments](Active%20Directory%20Tiering%20Model%20for%20On-Prem%20Environment.md) for the full Tier 0 / Tier 1 / Tier 2 model, PAW, logon restrictions, and GPO hardening.

Baseline checklist:

- 🔴 **Tier 0 isolation**: Domain Controllers, AD-integrated DNS, and anything that can control AD belong to Tier 0. Keep Tier 0 credentials off lower tiers.
- 🔴 **Authentication Policies & Silos** to cage privileged accounts.
- 🔴 **Protected Users** for sensitive admin accounts — ⚠️ but beware Kerberos delegation side effects (these accounts cannot be delegated, which breaks double-hop apps).
- 🟢 **Force Kerberos AES, disable RC4**; require **LDAP signing + channel binding** and **SMB signing**.
- 🟢 **`ms-DS-MachineAccountQuota = 0`** — stop users from joining arbitrary machines (a classic attack vector).
- 🟢 **gMSA / dMSA** for all service accounts instead of static passwords.
- 🟢 Disable or tightly control the built-in **`Administrator`** account; prefer named admin accounts.
- 🔵 **AD backup**: system state of at least 2 DCs, plus a **tested forest recovery** procedure kept offline.

For cross-forest privileged access without permanent Domain Admins, see [Just-in-Time AD Admin Elevation with Shadow Principals (without MIM)](Just-in-Time%20AD%20Admin%20Elevation%20with%20Shadow%20Principals%20(without%20MIM).md).

---

## 🌐 5 — Sites, Replication and Topology

### 5.1 — Domain controllers

- 🔴 **Minimum 2 DCs** for resilience — never run a single DC in production.
- Object count rarely drives DC count; **fault tolerance and geography** do. A few-thousand-object directory is light.
- 🟢 In a single-domain forest, make **all DCs Global Catalog** — there is no downside.
- 🔵 For a **physically insecure location** (branch office, unstaffed closet), prefer a **Read-Only Domain Controller (RODC)**: it holds no writable copy of the directory and, by default, **caches no account secrets** — so a stolen RODC exposes far less than a full DC.

### 5.2 — Centralized or distributed DCs?

This is one of the design answers that has genuinely **changed over time**, and it deserves a deliberate decision rather than a reflex.

Microsoft characterizes a branch/remote site as one with *"relatively few users, poor physical security, relatively poor network bandwidth to a hub site"* — and the **RODC was designed precisely for that case**. Historically, the deciding factor was that **last point**: WAN links were slow and unreliable, so you put a DC (or RODC) in every site so users could still authenticate and reach resources when the link was congested or down.

> 🟢 **What changed (design reasoning, not a Microsoft citation):** the widespread availability of **fast, reliable, often redundant links** (fiber, SD-WAN, 4G/5G failover) has largely removed the *bandwidth* argument. The modern default for most organizations is therefore to **centralize DCs in two or more datacenters** and let remote sites authenticate over the WAN — which also **shrinks the Tier 0 footprint** (fewer physically-exposed DCs to protect, consistent with §1.1 and the RODC note above).

A local DC/RODC is still the right call when one of these holds:

- 🔵 **Authentication must survive a WAN outage** — the site runs business-critical operations that cannot stop if the link drops (factory floor, point-of-sale, healthcare).
- 🔵 **The link is genuinely unreliable or high-latency**, or has no redundant path.
- 🔵 **A large user population** at the site makes WAN authentication traffic significant, or local services (DFS, print, PKI) need a nearby DC.
- 🔴 If you do place one in a **physically insecure** site, make it an **RODC** (no writable copy, no cached secrets by default) — or place **no DC at all** and rely on the WAN.

➡️ **Rule of thumb:** default to **centralized DCs over reliable links**; deploy a **local RODC** only where a WAN outage would actually stop the business or the link can't be trusted. Don't put a writable DC in an unsecured remote closet out of habit.

### 5.3 — Sites

- ⚠️ **Sites model NETWORK topology, not organization.** Do not create a site per department/entity. Departments are **OUs**, not **sites**.
- Use **one site** if everything is hosted in one datacenter/region; add sites only where there are distinct physical locations with local DCs.
- 🔵 Map **subnets → sites** correctly so clients are steered to the right DC for logon and DFS.
- Why it matters for replication: **within a site**, DCs replicate almost immediately (change notification, uncompressed) — keep DCs that share a fast LAN in the same site. **Between sites**, replication is **scheduled and compressed** along site links to spare the WAN. Getting subnet-to-site mapping wrong therefore degrades both logon steering *and* replication efficiency.

### 5.4 — FSMO and virtualization

- Place the **PDC Emulator** on a robust, central DC; document all 5 FSMO roles.
- 🔴 For virtualized DCs, ensure **VM-GenerationID** support (modern Hyper-V/VMware) to prevent USN rollback. Hypervisor hosts running DCs are **Tier 0**.
- 🔵 The USN-rollback safeguard **only works if the hypervisor exposes a VM-GenerationID**: when the ID changes (snapshot restore, copy), the DC resets its InvocationID and discards its RID pool, forcing safe re-convergence. On a hypervisor that doesn't expose it, you fall back to the old, weaker USN-rollback *quarantine* — another reason to require a modern hypervisor for DCs.
- 🔴 **A snapshot is not a backup.** The VM-GenerationID safeguard prevents *corruption* on a snapshot revert, but it does **not** replace a real **system-state backup** and a **tested forest-recovery** procedure (per §4). Never treat "I can roll back the VM" as your AD recovery plan.

---

## 📡 6 — DNS Design

- 🟢 Use **AD-integrated zones** (multi-master, replicated through AD).
- � **Set dynamic updates to "Secure only"** on AD-integrated zones — this is the main security reason to use them. It ties each record to the authenticated computer that owns it, so an unauthenticated host **cannot overwrite or spoof** an existing record (name-takeover protection).
- 🔵 Configure **Aging and Scavenging** from day one — a greenfield forest is the ideal moment to get it right. See [Dns Aging and Scavenging Explained with verification script](Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script.md).
- Set **forwarders** to central resolvers and **conditional forwarders** toward trusted forests (needed for cross-forest name resolution over trusts).
- 🔵 **Point each DC's DNS client at *another* DC first**, then itself (loopback `127.0.0.1` last, never as the only entry). A DC that resolves only against itself can hit the **"DNS island" problem** at boot and fail to locate replication partners.
- 🔴 **DNS is a Tier 0 role** (hosted on the DCs). Do not delegate DNS to local admins.
- 🟢 **Keep the default protections on**: the **DNS socket pool** and **cache locking** are enabled by default on modern Windows Server — don't disable them. Consider **DNSSEC** on critical zones to defend against cache poisoning.
- 🔵 Don't let the AD zone collide with your **public** namespace — base AD on a dedicated subdomain (see §1.3) to avoid a **split-brain** zone you'd have to maintain by hand.

---

## 🔗 7 — Trusts

When the forest must interoperate with an administration forest and/or a resource forest:

| Relationship | Recommended trust |
|---|---|
| **Admin forest → account forest** (administration) | **Forest trust**, often **one-way**, ideally paired with **PAM/Shadow Principals** and **Authentication Policies/Silos**. |
| **Account forest ↔ resource forest** | **Forest trust**, transitive, one-way or two-way depending on access direction. |

🔵 **Pick the right *type* of trust.** A **forest trust** is **transitive** and spans the whole forest (every domain on both sides), which is what you want for a clean inter-forest boundary. An **external trust** is **non-transitive** and links a single domain to a single domain — use it only for a narrow, legacy domain-to-domain need, not for forest-to-forest interoperability.

Security settings:

- 🔴 **Selective Authentication** on the trust: by default (`forest-wide`) every user can authenticate everywhere. Selective auth makes you grant `Allowed to Authenticate` explicitly — strongly recommended in shared scenarios.
- 🔴 **Keep SID Filtering enabled** (default on forest trusts) — it **discards SIDs from the trusted forest that don't belong to it** (notably an injected `SIDHistory`), which is precisely what blocks a Tier 0 SID-injection attack across the trust. The **only** legitimate reason to relax it is a **migration that relies on `SIDHistory`** — and even then, re-enable it the moment the migration is done.
- 🟢 **Leave TGT delegation disabled across the forest trust** (the default on a new forest trust). It stops a server configured for **unconstrained delegation** in the trusting forest from capturing a TGT of a user coming from the trusted forest — a known cross-forest credential-theft vector.
- 🟢 Force **Kerberos AES**, disable RC4 on trusts.
- 🟢 Use the **minimum trust direction** that satisfies the requirement.

For the SID-stub objects created by cross-forest group membership, see [What are FSPs — Audit and Manage them in AD](What%20are%20FSPs%20-%20Audit%20and%20Manage%20them%20in%20AD.md).

---

## 📐 8 — Group Policy Strategy

GPO is where most of the day-to-day *configuration* lives, and a forest accumulates GPOs faster than any other object. A deliberate strategy — **processing order, filtering, loopback, naming** — is what keeps it auditable instead of becoming an unexplainable pile.

### 8.1 — Processing order and precedence

🔵 GPOs apply in a fixed order — **Local → Site → Domain → OU** (the classic **LSDOU**) — and, because each stage is applied *after* the previous one, **the last writer wins**: the GPO closest to the object (deepest OU) overrides settings higher up.

- Within a single container, multiple linked GPOs are ordered by **link order** — **link order 1 has the highest precedence** (it is applied last).
- 🟡 **`Enforced`** reverses the usual logic: an *Enforced* link **always wins** and **cannot be overridden by a lower OU**, and it also **punches through a Block Inheritance**.
- 🟡 **`Block Inheritance`** stops parent GPOs from flowing into an OU — but it is a blunt instrument: it blocks *everything* from above (including the domain security baseline), and it is invisible unless you go looking. **Avoid both `Enforced` and `Block Inheritance`** where you can; they break the simple top-to-bottom readability of LSDOU. The one common, legitimate `Enforced` link is the **domain-wide security baseline** you never want a delegated OU admin to override.

### 8.2 — Filtering: who a GPO actually applies to

A GPO linked to an OU applies, by default, to **every** user/computer in that OU. Three mechanisms narrow that down — and one of them has a notorious trap.

- 🔵 **Security filtering** — the normal way to target a subset. By default a new GPO grants **`Authenticated Users`** both **Read** and **Apply group policy**. To target a specific group, you swap the *Apply* right onto that group.
- 🔴 **The `Authenticated Users` trap (post-MS16-072).** Since the June 2016 security update, a GPO is **downloaded in the security context of the *computer* account**, not the user. So if you remove `Authenticated Users` entirely to scope a GPO to, say, `GRP-Sales-Users`, the **computer can no longer read the GPO and it silently stops applying**. **Fix:** when you replace the *Apply* right, **leave a plain `Read` (no Apply) for `Authenticated Users` or `Domain Computers`** so the machine can still fetch the policy. *(Established behavior; Microsoft's MS16-072 KB is the reference — the page is intermittently unavailable today, but the requirement is unchanged.)*
- 🟢 **WMI filtering** — applies a GPO only where a WMI query is true (e.g. only on a given OS build, or only laptops). Powerful, but it is **re-evaluated on every policy refresh**, so it carries a real logon/refresh cost — reserve it for cases a simple OU/security-group split can't express.
- 🟢 **Item-Level Targeting (Group Policy Preferences)** — the preferred granular tool: it targets individual *preference items* by group, OU, site, IP range, OS, etc. **without multiplying GPOs** and is generally cheaper and more flexible than WMI filtering.

### 8.3 — Loopback processing

🔵 **Loopback** makes a machine apply **user-side settings based on the *computer's* location**, not the user's. It is the right tool for **shared / special-purpose machines** — kiosks, classrooms, RDS/VDI session hosts, and DCs — where the user experience must depend on *where they logged in*, not *who they are*.

- **Replace mode** — ignore the user's own GPOs entirely; only the computer-location user settings apply (maximum lockdown, e.g. a kiosk).
- **Merge mode** — apply the user's normal GPOs **then** add the computer-location user settings on top, the latter winning on conflict (e.g. an RDS host that layers extra restrictions over the user's baseline).

### 8.4 — Naming convention

🟢 A GPO's name is its only label in the console, so encode **scope + type + intent** in it. *(Design reasoning, not a Microsoft prescription.)* A workable scheme:

```
<scope/tier>-<config>-<purpose>
   SEC-Baseline-Domain          ← domain-wide security baseline (Enforced)
   T0-Computer-DC-Hardening     ← Tier 0, computer config, DC hardening
   U-Sales-Mapped-Drives        ← user config, Sales drive mappings
   C-Laptops-BitLocker          ← computer config, laptop encryption
```

A consistent prefix makes precedence and ownership obvious at a glance and keeps a 200-GPO forest navigable.

### 8.5 — Design principles

- Link a **domain baseline** (common security) high, inherited everywhere — this is the one link worth marking **`Enforced`**.
- Use **per-tier GPOs** (Tier 0 on DCs/infra, Tier 1 on servers), aligned with the tiering model.
- 🟡 **Limit GPO proliferation.** Many scopes × several GPOs each becomes unmanageable. Instead of one GPO per population (`GPO-Sales-Drives`, `GPO-Finance-Drives`, … — all identical bar one value), prefer **a single shared GPO whose individual settings are conditioned per population with Item-Level Targeting** (§8.2): one `U-Drive-Mappings` GPO holding a *map S: → \\\\srv\\sales* item targeted at `GRP-Sales`, a *map S: → \\\\srv\\finance* item targeted at `GRP-Finance`, and so on.
- 🟢 **Disable the unused half of a GPO.** If a GPO carries only computer settings (or only user settings), disable the other half in its details — it **skips that half at processing time** and speeds up logon/startup.
- 🟢 Base the security baseline on the **Microsoft Security Compliance Toolkit** (WS2025 baselines), and keep GPOs under **version control** (backup/export) so configuration is reproducible and reviewable.

---

## 🛠️ 9 — Tooling and Industrialization

The single most valuable design principle in a well-templated forest is **consistency through automation**: identical structures should be produced identically, not rebuilt by hand each time. This section is about *which capabilities to plan for*, not how to script them.

### 9.1 — Capabilities to plan for

| Need | Design choice |
|---|---|
| Forest/DC bootstrap | A **repeatable, documented build** (infrastructure-as-code mindset) rather than manual promotion |
| Security baseline | **Microsoft Security Compliance Toolkit** baselines as the reference, applied uniformly |
| Config as code | Keep **OU structure, GPOs and delegation definitions under version control** |
| GPO reproducibility | Treat GPOs as **versioned artifacts** that can be restored to a known-good state |

🟢 The **Security Compliance Toolkit** is more than a bag of baselines: it ships **Policy Analyzer** and **`LGPO.exe`**, which let you **compare your live GPOs against the Microsoft baseline** (and against each other) to surface redundant, conflicting or drifted settings — exactly the feedback loop "config as code" needs. *(Microsoft fact: the SCT page lists Policy Analyzer, LGPO, Set Object Security and GPO-to-PolicyRules alongside the WS2025 baselines.)*

🟢 **Lean on the native toolchain before reaching for anything custom.** The build and configuration surface is fully scriptable with in-box Microsoft tooling:

- **`ADDSDeployment`** PowerShell module (`Install-ADDSForest`, `Install-ADDSDomainController`) — promote DCs from a documented script, not the GUI wizard.
- **Active Directory Administrative Center (ADAC)** — the console that surfaces the **Recycle Bin**, **Fine-Grained Password Policies** and **Authentication Policies/Silos**, and that **echoes the equivalent PowerShell** for everything you click (a fast way to turn a GUI action into a repeatable script).
- **AD Recycle Bin** — an **optional feature to enable at build time** (the enablement is **irreversible**); once on, a deleted object can be restored *with* its attributes and group memberships intact.
- **GPMC** — back up, export and restore GPOs as files, which is what makes the "GPO as versioned artifact" goal above real.

### 9.2 — Daily operations

| Need | Design choice |
|---|---|
| Delegation | **RBAC role groups**, never direct ACLs; documented |
| Local machine passwords | **Windows LAPS**, delegated read per scope |
| Service accounts | **gMSA / dMSA** |
| Stale object cleanup | A defined **lifecycle** for inactive users/computers |
| Security monitoring | **Microsoft Defender for Identity (MDI)** sensors on Tier 0 identity servers |

🔵 **MDI is not just "on the DCs".** Its lightweight sensor runs on your **identity infrastructure** — domain controllers first, but also **AD CS, AD FS and Entra Connect servers** where they exist (all Tier 0). Deploy it everywhere that infrastructure lives, not only on the DCs. *(Microsoft fact: the MDI architecture page describes sensors running across the identity infrastructure; the per-role server list comes from the MDI deployment pages.)*

### 9.3 — Health, diagnostics and security assessment

**Operational health** relies on native diagnostics that ship with the DC role — but they are **scattered across commands and servers**: `repadmin` (replication), `dcdiag` (DC health), `dfsrdiag` (SYSVOL/DFSR), `nltest` (secure channel) and `w32tm` (time). Running each by hand, per DC, does not scale.

🟢 **Consolidate them into a single scheduled check.** The companion script [AD Health Check Script](../Tools/AD-HealthCheck/AD%20Health%20Check%20Script.md) does exactly that: it auto-discovers every DC and runs FSMO, replication, services, connectivity, secure-channel, `dcdiag`, time-sync, storage and event-log checks, then emits a console summary, an HTML report, a CSV log and an optional alert email. It is **read-only**, designed to run **unattended as a scheduled task**, and returns an exit code (`0` = OK, `1` = WARN, `2` = FAIL) a monitoring system can consume.

**Security assessment** is a separate, periodic exercise — score the directory and map what an attacker could actually reach:

- 🟢 **PingCastle** *(third-party)* — fast risk **scoring** and reporting; the usual baseline for a recurring AD exposure review.
- 🟢 **Purple Knight** *(third-party, Semperis)* — indicator-of-exposure scan across AD and Entra ID.
- 🟢 **BloodHound / SharpHound** *(third-party, SpecterOps; community edition is free)* — graphs the **attack paths** to Tier 0, surfacing privilege-escalation chains that a flat permissions audit misses.
- 🔵 **Locksmith** *(third-party)* — only relevant **once you run AD CS**: it finds the well-known certificate-template misconfigurations (the `ESC*` escalation paths). Skip it entirely if you have no PKI.

### 9.4 — Templated provisioning

🟢 Where a structure repeats, treat the **entity/scope as a template**: the OU subtree, the role groups, the delegation, the standard GPO links and the accidental-deletion protection should all be defined **once** and produced the **same way every time**. The design goal is that onboarding a new scope is a **single, predictable operation** — this is what keeps a large, delegated forest consistent and sustainable over time.

---

## 🏢 10 — Applied Scenario: A Shared Forest for Multiple Entities

Everything above is **generic**. This section covers the one demanding application that pushes the dials to maximum: **consolidating many independent entities into a single shared forest** (e.g. ~150 small entities of 5–150 people each), administered from an existing admin forest, with identity/provisioning handled elsewhere.

> 🔵 **Key insight:** "multiple entities" is **not** a different *model*. It is the generic delegated-OU model with three dials turned up. The architecture is the same; only the *degree* changes.

### 10.1 — What the multi-entity case actually changes

| Dimension | Impact of the multi-entity case |
|---|---|
| **1. OU symmetry / repetition** | You want an **identical OU template repeated N times** rather than one organic structure → **templated, automated provisioning becomes mandatory**, not optional. |
| **2. Horizontal isolation** | Entity A must not see/touch entity B → **watertight per-scope delegation** + optionally List-Object mode. In a single company, isolation is mostly *vertical* (by tier); here it is also *horizontal* (between peers). |
| **3. Mutually untrusted local admins** | Local IT of 150 entities do not trust each other → the **rigor of delegation isolation becomes critical**, vs admins of one IT department who broadly trust each other. |

That is all. **The multi-entity factor is one of degree (repetition, watertightness, untrusted admins), not of nature.**

> 🔴 **Assume the shared-forest security trade-off explicitly.** Because **the forest — not the OU — is the security boundary** (§1.1), per-OU delegation gives entities **administrative** isolation, **not** a security boundary between them. All 150 entities share one schema, one configuration partition and one Tier 0: a compromise of any entity that reaches Tier 0 brings down **every** entity at once. This is the deliberate price of mutualisation — you accept a shared blast radius in exchange for one infrastructure. It is precisely *why* the model **deports Tier 0 to the admin forest** and keeps **no permanent human Domain Admin** in the shared forest (§10.2). If any entity genuinely requires a hard security boundary from the others, it does **not** belong in the shared forest — it needs its own.

### 10.2 — Concrete adaptations

- **OU root** `OU=Entities` with an **identical template** per entity (`Users / Groups / Computers / Admins`), keyed by stable entity code (`ENT001-Alpha`).
- **Templated provisioning is the cornerstone**: onboarding a 151st entity should reproduce the exact same OU tree, role groups, delegation, GPO links and protection as every other entity — predictably and identically.
- **Per-entity role groups** (`ROLE-ENT001-UserAdmin`, …) handed to that entity's local IT only — strict horizontal isolation.
- **Tier 0 stays in the admin forest** via the trust (+ PAM/Shadow Principals); **no permanent human Domain Admin** in the shared forest.
- **Give each entity its own login/mail identity without a new domain**: add a **UPN suffix per entity** (`user@entity-alpha.fr`) on the single shared domain (§1.1) — entities keep their own namespace while the directory stays one domain. Pair it with DNS zones as needed.
- **Don't multiply GPOs per entity.** Reuse the GPO anti-proliferation principle (§8.5): a **shared GPO whose items are scoped per entity with Item-Level Targeting** (targeting `GRP-ENT001-*`) beats minting a fresh GPO set for every one of the 150 entities — which would be unmanageable.
- **Consider List Object Mode** so entities cannot enumerate each other.
- **Sites still follow network topology**, not entities — do not create 150 sites for 150 entities.

```mermaid
flowchart TD
    ROOT["example.com"]
    ENT["OU=Entities"]
    E1["OU=ENT001-Alpha\nUsers / Groups / Computers / Admins"]
    E2["OU=ENT002-Bravo\n(identical template)"]
    E3["OU=ENT###-...\n(×150)"]

    ROOT --> ENT
    ENT --> E1
    ENT --> E2
    ENT --> E3

    style ROOT fill:#1e3a8a,stroke:#93c5fd,stroke-width:2px,color:#f9fafb
    style ENT fill:#1f2937,stroke:#f59e0b,stroke-width:2px,color:#f9fafb
    style E1 fill:#14532d,stroke:#86efac,stroke-width:2px,color:#f9fafb
    style E2 fill:#14532d,stroke:#86efac,stroke-width:2px,color:#f9fafb
    style E3 fill:#14532d,stroke:#86efac,stroke-width:2px,color:#f9fafb
```

---

## 📌 11 — Summary of Key Decisions

| Decision | Recommendation |
|---|---|
| **Forests / domains** | **1 forest, 1 domain** unless a hard constraint forces otherwise |
| **Functional level** | **WS2025 FFL** on a greenfield all-2025 fleet; decide the **32k page size** at forest creation |
| **Naming** | **Registered, dedicated subdomain** prefix (`corp.example.com`); never single-label or `.local` |
| **OU design** | Structured for **delegation + GPO**; identical template where repeated |
| **Delegation** | **RBAC role groups** applied as inherited OU ACLs; never direct ACLs |
| **Tier 0** | Isolated (or deported to an admin forest); no permanent human DA |
| **Sites** | Follow **network topology**, not org structure |
| **DCs** | **2+ DCs**, all **GC + DNS** |
| **DNS** | **AD-integrated + scavenging** from day one |
| **Trusts** | **Forest trust + Selective Auth + SID Filtering + TGT delegation off** |
| **GPO** | Domain baseline + per-tier; avoid GPO proliferation; ILT over per-scope GPOs |
| **Industrialization** | **Templated, repeatable provisioning** of each scope is the cornerstone |
| **Tooling** | LAPS, gMSA/dMSA, scheduled AD health checks, PingCastle/Purple Knight/BloodHound, MDI |

---

## 📚 References

- [Active Directory Tiering Model for On-Premises Environments](Active%20Directory%20Tiering%20Model%20for%20On-Prem%20Environment.md)
- [Just-in-Time AD Admin Elevation with Shadow Principals (without MIM)](Just-in-Time%20AD%20Admin%20Elevation%20with%20Shadow%20Principals%20(without%20MIM).md)
- [Dns Aging and Scavenging Explained with verification script](Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script.md)
- [What are FSPs — Audit and Manage them in AD](What%20are%20FSPs%20-%20Audit%20and%20Manage%20them%20in%20AD.md)
- Microsoft — [Best Practices for Securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- Microsoft — [Securing privileged access (Enterprise Access Model)](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- Microsoft — [Delegating administration by using OU objects](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-of-account-ous-and-resource-ous)

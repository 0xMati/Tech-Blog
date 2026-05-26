---
title: "Move from MIM to Entra ID - Practical Migration Playbook"
date: 2026-05-06
---

# Move from MIM to Entra ID — Practical Migration Playbook

This guide helps you move from Microsoft Identity Manager (MIM) to Microsoft Entra ID capabilities with a pragmatic, phased approach.

It is based on your migration deck topics and current Microsoft Entra guidance.

> 🎯 TL;DR
>
> - Most classic MIM scenarios now have a cloud-native equivalent in Entra.
> - The migration is not "rip and replace". It is a capability-by-capability transition.
> - The biggest wins usually come first from: sync modernization, governance, and access automation.
> - Keep MIM only where there is still a hard technical dependency or niche connector gap.

---

## 1) 📋 Scope of this migration

This playbook covers the same scenario families as your deck:

- 🏢 On-prem to cloud sync and provisioning
- ☁️ Cloud to on-prem provisioning
- 🔗 Tenant-to-tenant sync
- 🔄 Cloud to SaaS and SaaS to cloud
- 🌐 SaaS to on-prem (AD / apps / LDAP / SQL)
- 👥 Identity lifecycle, group governance, access governance
- 🔑 SSPR / profile portals / password flows
- 🚀 PAM to PIM transition
- 🔐 Authentication and authorization workflows
- ⚙️ Custom objects and advanced workflows

---

## 2) 🗺️ Capability mapping: MIM → Entra

| MIM capability area | Primary Entra replacement | Status |
|---|---|---|
| 🔄 AD → Entra sync | Microsoft Entra Connect Sync or Cloud Sync | ✅ Ready |
| 🌳 Multi-forest sync | Cloud Sync multi-agent + disconnected forest support | ✅ Ready |
| 🔐 Password sync / writeback | PHS + SSPR writeback (Connect/Cloud Sync scenarios) | ✅ Ready |
| 📱 Cloud → SaaS provisioning | Entra application provisioning (SCIM/connectors) | ✅ Ready |
| 📊 Workday / SuccessFactors inbound | Entra HR-driven provisioning | ✅ Ready |
| 🤝 Tenant-to-tenant user lifecycle | Cross-tenant synchronization | ✅ Ready |
| 👤 Lifecycle workflows (joiner/mover/leaver) | Entra Lifecycle Workflows | ✅ Ready |
| ✍️ Access request / approval / expiration | Entitlement Management (Access Packages) | ✅ Ready |
| ✔️ Access recertification | Access Reviews | ✅ Ready |
| 🎭 PAM (JIT/JEA governance) | Entra PIM (roles/groups/resources) | ✅ Ready |
| 🤖 Dynamic group automation | Entra dynamic group rules | ✅ Ready |
| 🔧 Complex on-prem downstream provisioning (LDAP/SQL/custom apps) | Entra + API/SCIM + integration patterns (Logic Apps/Functions/partners) | ⚠️ Case-by-case |
| 🎯 Custom object metaverse-heavy logic | Graph-based automation + integration platform + selective coexistence | ⚠️ Case-by-case |

---

## 3) 🎯 Migration patterns by scenario

### 3.1 🏢 → ☁️ Sync + Provisioning from OnPrem to Cloud

Recommended target pattern:

- Start with current Entra Connect Sync baseline if already deployed
- Evaluate migration to Cloud Sync where architecture/feature fit is validated
- Keep source-of-authority clear (AD/HR) before changing sync tooling

Use when:

- You need simpler operations
- You have disconnected forests
- You want cloud-managed sync configuration

### 3.2 ☁️ → 🏢 Sync + Provisioning from Cloud to OnPrem

Typical modern use cases:

- Group provisioning/writeback scenarios
- Password writeback and account unlock paths
- Cloud-governed access reflected to AD-dependent systems

Design note:

- Validate every writeback dependency early (permissions, OU design, ownership, rollback)

### 3.3 🔗 Sync + Provisioning Tenant to Tenant

Use cross-tenant synchronization for:

- Multi-tenant organizations
- Automated B2B user lifecycle
- Centralized onboarding/offboarding across tenants

Important:

- Cross-tenant sync is not a tenant migration tool
- Plan source and target authority boundaries explicitly

### 3.4 ☁️ → 📱 Sync + Provisioning from Cloud to SaaS Apps

Target architecture:

- Entra app provisioning engine (SCIM/native connectors)
- Attribute mappings + scoping filters + assignment governance

Practical sequence:

1. Pilot one business app
2. Validate create/update/disable/delete
3. Add access governance and periodic review

### 3.5 📱 → ☁️ Sync from SaaS Apps to Cloud

Common migration path from MIM connectors:

- Use built-in HR connectors (Workday, SuccessFactors) when possible
- For other SaaS sources, use API-based ingestion/integration patterns
- Normalize identity attributes before they become authoritative

### 3.6 📱 → 🏢 Sync from SaaS to OnPrem (AD / apps / LDAP / SQL)

This is often the hardest area in MIM exits.

Modern pattern:

- SaaS -> Entra authoritative identity
- Entra governance decides entitlement
- Integration layer executes downstream provisioning where no native connector exists

Options for integration layer:

- SCIM where available
- API + Logic Apps / Functions
- Partner IAM tooling for legacy endpoints (LDAP/SQL/app-specific)

---

## 4) 👥 Governance modernization (usually the highest ROI)

### 4.1 ⭐ User lifecycle management

Replace manual or MIM workflow-heavy operations with:

- 👤 Lifecycle Workflows for joiner/mover/leaver
- 🔋 Trigger-based tasks + extensions for advanced actions

### 4.2 💬 Group and membership governance

- 🤖 Dynamic groups for attribute-based membership
- 🏪 Group ownership model and periodic recertification
- 🔄 Hybrid writeback only where required for on-prem dependencies

### 4.3 😐 Access management / governance

- ✍️ Entitlement Management for request/approval/expiration
- 🤜 Access Packages for role bundles
- ✔️ Access Reviews for recertification and audit evidence

### 4.4 🔐 PAM to PIM

- 🚀 Move privileged standing access to just-in-time (JIT)
- 🔓 Add approvals, MFA/strong auth requirements, and auditability
- 🎯 Start with high-risk roles and admin groups first

---

## 5) 🔐 Authentication and authorization workflows

Modern replacement for custom MIM-era policy chains:

- 🏠 **Authentication controls**: Conditional Access + Authentication Strengths
- ⚖️ **Authorization controls**: group/app/role assignment governed by entitlement policy
- 🔋 **Action workflows**: Lifecycle Workflows + automation hooks

**Outcome:**
- ⌨️ Less custom code
- 📄 More policy-driven controls
- 🔍 Better audit and recertification model

---

## 6) 🔄 User and group synchronization: Entra Connect Sync or Cloud Sync?

### Current state: MIM as primary sync engine

If MIM is currently synchronizing users and groups from Active Directory → Entra ID, your first major decision is choosing the replacement sync platform. Choose wisely! 🎯

---

### 🖥️ Option A: Entra Connect Sync (current standard — the "server on steroids")

**Best for:**
- 🎮 Organizations already using Entra Connect Sync (add cloud provisioning to MIM scope)
- 📱 Hybrid device scenarios (device registration, Windows Hello, modern auth with legacy on-prem AD expectations)
- 🧬 Complex filtering or attribute-flow rules
- 🏢 Highly dependent on on-prem AD as the identity source

**How it works:**
- 💾 Installed on Windows Server, runs continuous sync (every 2 minutes default)
- 🌐 Full hybrid management: on-prem AD + Entra ID + Exchange, Teams, SharePoint
- 🔐 Supports password hash sync (PHS), pass-through auth, and federated identity
- ↩️ Can provision to on-prem AD (write-back, a key MIM feature)

**Migration from MIM:**
- 🚀 Deploy Entra Connect Sync on a new or existing server (typically small footprint)
- 📝 Migrate sync rules from MIM to Entra Connect (rule syntax differs, but logic is similar)
- 🧪 Test in pilot environment with filtered sync (example: single OU, 100-500 users)
- 📈 Gradually expand scope until all users are synced from Entra Connect
- ✅ Shut down MIM sync when validated, but keep MIM running for other workflows if they exist

→ **Reference**: [What is Entra Connect Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect)

---

### ☁️ Option B: Entra ID Cloud Sync (newer, strategic default — "the cloud-native way")

**Best for:**
- 🆕 New Entra deployments or MIM migrations without strong on-prem constraints
- 🌳 Multi-forest or M&A scenarios (independent agents per forest, no metaverse synchronization required)
- 🚀 Organizations wanting to eliminate on-prem infrastructure (except for DC/AD itself)
- 🔌 Disconnected forests or temporary connections
- 🧹 Reducing operational overhead (cloud-managed, auto-patched)

**How it works:**
- 🪶 Lightweight agent (ECMA Connector Host) installed on Windows Server or hybrid worker
- ☁️ Manages sync configuration entirely in Azure cloud portal
- ↔️ Supports AD → Entra sync, Entra → AD (group write-back), cross-cloud scenarios
- 🚄 Faster feature velocity (new capabilities added quarterly to cloud, not dependent on on-prem agent updates)
- 🔄 Multiple agents can run in parallel (no single point of failure unlike Entra Connect)

**Key differences from MIM:**

```
┌─────────────────────────────────────────┐
│        MIM          │     Cloud Sync     │
├─────────────────────────────────────────┤
│ Agent count:        │ Multiple agents    │
│ 1 per metaverse     │ (redundancy ✅)    │
│                     │                    │
│ Sync frequency:     │ ~2 minutes         │
│ Real-time/scheduled │ (cloud-managed)    │
│                     │                    │
│ Metaverse:          │ No, simplified     │
│ Yes, complex        │ object model ✅    │
│                     │                    │
│ On-prem writeback:  │ Limited            │
│ Yes (MIM strength)  │ (groups only)      │
│                     │                    │
│ Licensing:          │ Included in Entra  │
│ MIM (expensive)     │ (no extra cost) ✅ │
└─────────────────────────────────────────┘
```

**Migration from MIM:**
1. 🚀 Deploy ECMA Connector Host on Windows Server (can be same server as MIM initially)
2. ⚙️ Create Cloud Sync configuration in Entra admin center (scoped to pilot OU)
3. 🔀 Run both MIM and Cloud Sync in parallel for 1-2 weeks (verify sync quality)
4. 📈 Expand Cloud Sync scope, disable MIM sync on those users
5. 🎉 Once fully migrated, decommission MIM

→ **Reference**: [What is Entra Cloud Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)

---

### 🤔 Decision criteria: which sync engine should replace MIM?

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃        CLOUD SYNC                      ┃
┃    (modern, cloud-native)              ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ ✅ 2-minute sync = acceptable          ┃
┃ ✅ Simple OU-based filtering           ┃
┃ ✅ Want to ditch on-prem sync infra    ┃
┃ ✅ Multiple forests (M&A scenario)     ┃
┃ ✅ Entra as source of authority        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃        ENTRA CONNECT SYNC               ┃
┃    (traditional, battle-tested)        ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ ✅ Sub-2-minute sync = critical        ┃
┃ ✅ Complex attribute-flow logic        ┃
┃ ✅ Hybrid Device Management invested   ┃
┃ ✅ Exchange Hybrid/Teams resources     ┃
┃ ✅ Heavy on-prem dependencies          ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃    🎯 HYBRID APPROACH (best of both)   ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Use Entra Connect as PRIMARY            ┃
┃ Add Cloud Sync for specific forests     ┃
┃ Run both in parallel (no conflicts)     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

→ **Reference**: [Cloud Sync vs Connect Sync Decision Guide](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide)

---

## 7) 🔧 What to do with custom objects and niche MIM workflows

Some MIM implementations include advanced metaverse logic, custom object types, or connectors with no cloud-native equivalent. Time to make hard choices! 💪

**Use this decision rule:**

```
┌────────────────────────────────────────────┐
│ 🟢 If Entra has native capability         │
│    → Migrate now (no looking back!)        │
├────────────────────────────────────────────┤
│ 🟡 If Entra + lightweight automation      │
│    → Redesign and migrate                  │
├────────────────────────────────────────────┤
│ 🔴 If business-critical & no equivalent   │
│    → Keep reduced MIM coexistence (temp!)  │
└────────────────────────────────────────────┘
```

**Integration patterns for custom/niche scenarios:**
- 🔌 Custom ECMA connectors for LDAP directories, SQL databases, REST APIs, or PowerShell integrations
- ⚡ Logic Apps/Azure Functions for complex orchestration beyond Lifecycle Workflows
- 🤝 Partner IAM tools for legacy endpoints (example: Okta, Ping, or others for advanced federation)
- 📊 Graph API automation for attribute-driven scenarios

→ **Reference**: [ECMA Connector Host Overview](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ecma-connector-overview)

> 💡 **Golden Rule**: Keep MIM only for true gaps, not for historical habits.

---

## 8) 🚀 Recommended phased roadmap

### Phase 1 (0-30 days) — 🔍 Discovery and mapping

**Objectives:**
- 📋 Complete inventory of MIM management agents, rules, workflows, and dependencies
- 🔬 Technical audit: connector types, rule complexity, attribute flows, custom code
- 👥 Business audit: which flows are critical, which are legacy, ownership clarity

**Key activities:**
- 🏷️ Classify each flow: retire / replace / redesign / coexist
- 📍 Define identity source-of-authority per object and per attribute domain
- 🗺️ Map current MIM workflows to Entra equivalents (Lifecycle Workflows, Entitlement Management, etc.)
- 📱 Document all downstream systems consuming MIM data (which systems will be affected by shutdown?)
- ⚖️ Evaluate Entra Connect Sync vs Cloud Sync readiness
- 💰 Assess licensing requirements (Entra ID P1/P2, ID Governance, or Suite)

**Checkpoint:** ✅ Signed off on capability mapping, executive stakeholder alignment on phased approach

---

### Phase 2 (31-60 days) — 🧪 Pilot by capability

**Objectives:**
- ✔️ Validate Entra can handle real workloads without MIM
- 🐛 Identify gaps, reconfiguration efforts, and coexistence strategies early
- 📚 Build team confidence and runbooks

**Pilot sequence (low risk first):**

```
1️⃣  Sync Modernization Pilot
    📊 Scope: single OU or department
    ✅ If on Entra Connect: baseline + Cloud Sync readiness check
    ✅ If migrating: deploy agents, validate 2-min sync SLA
    ✅ Verify password hash sync for fallback auth
    
2️⃣  SaaS Provisioning Pilot (e.g., Salesforce/ServiceNow/Slack)
    👤 Test: create/update/disable/delete user lifecycle
    🎯 Validate attribute mappings (custom attrs need extensions)
    ✅ Establish approval workflows
    📈 Run 2 weeks: measure activation time + error rates
    
3️⃣  Lifecycle Workflows Pilot (Joiner + Leaver)
    👋 Joiner: Manager notification + group assignment + license assignment
    🚪 Leaver: Disable account + remove groups + revoke access packages + audit export
    📊 Measure: time to completion, manual overrides, audit trail quality
    
4️⃣  Access Package + Review Pilot (one business unit)
    📦 Create 2-3 representative access packages (role bundles)
    ⏳ Simulate request/approval/expiration lifecycle
    🔍 Conduct first access review (recertification)
    📈 Measure: review time, approval latency, recommendation false positives
```

**Checkpoint:** ✅ All pilots succeed with <5% manual intervention, runbooks documented, team trained

---

### Phase 3 (61-120 days) — 🎯 Industrialize and cutover

**Objectives:**
- 📈 Scale approved patterns to full production scope
- 🔄 Maintain operational continuity throughout transition
- 📖 Establish new support models and runbooks

**Cutover strategy by scenario:**

```
🔷 SYNC CUTOVER (most critical)
   ↓ Enable Entra sync on FULL directory scope
   ↓ Keep MIM sync running in parallel for 5-7 days (safety net)
   ↓ Monitor: duplicates, missing users, attribute mismatches
   ↓ After validation: STOP MIM sync = CUTOVER COMPLETE

🔷 APP PROVISIONING CUTOVER (sequential)
   ↓ Week 1: Cut over 3-5 low-criticality SaaS apps
   ↓ Week 2-3: Cut over strategic apps (HR, sales, finance)
   ↓ Week 4: Cut over custom connectors (LDAP, SQL, REST)
   ↓ Maintain MIM provisioning in parallel until done

🔷 GOVERNANCE CUTOVER (parallel with provisioning)
   ↓ Deploy Entitlement Management (access requests)
   ↓ Activate Access Reviews (compliance recertification)
   ↓ Deploy Lifecycle Workflows (JML automation)
   ↓ Train business owners on delegated admin

🔷 DEPROVISIONING/CLEANUP
   ↓ Define clear Entra policies (soft-delete → hard-delete after 30d)
   ↓ Test bulk user deletion + account unlock workflows
   ↓ Document fallback procedures (recovery, restore deleted users)
```

**Rollback checkpoints:** After each cutover step, keep MIM in standby mode for 7 days before full shutdown

**Checkpoint:** ✅ 95%+ workload in Entra with <1% error rate, MIM in standby-only mode

---

### Phase 4 — 🎉 Residual decommissioning

**Objectives:**
- 🧹 Eliminate all remaining MIM dependencies
- 🔌 Decommission MIM infrastructure cleanly
- 📦 Archive configuration for compliance/audit

**Decommissioning steps:**

```
1️⃣  ISOLATE RESIDUALS
    Identify MIM-only use cases (should be <5% of original by now)
    
2️⃣  REPLACE OR RETIRE EACH
    🟢 Replace with Entra native feature, OR
    🟡 Replace with ECMA connector + Logic Apps, OR
    🔴 Implement via partner tool for legacy endpoints, OR
    ⚫ Retire the flow entirely (often legacy processes)
    
3️⃣  DECOMMISSION COMPONENTS
    ⏹️ Stop all connectors
    ⏹️ Disable management agents
    ⏹️ Take FIM/MIM databases offline
    📦 Archive configuration database (7-year retention for compliance)
    🗑️ Decommission MIM servers (hardware recycling)
    💳 Release MIM licensing
    
4️⃣  KNOWLEDGE TRANSFER
    📚 Document Entra governance model vs old MIM model
    💾 Archive MIM workflow logic as reference
    👨‍🎓 Train support teams on Entra troubleshooting
```

**Checkpoint:** ✅ MIM completely offline, all systems on Entra, incident rates stable

---

## 9) ⚠️ Migration pitfalls to avoid

```
🚫 BIG BANG MIGRATION
   → Don't move sync + provisioning + governance + auth all at once!
   → Move in waves, test each thoroughly
   
🚫 MOVING SYNC WITHOUT SOURCE-OF-AUTHORITY
   → Define who owns what BEFORE you migrate
   → Is AD the source? HR? SaaS? 
   → Chaos ensues if you don't clarify this first!
   
🚫 IGNORING DEPROVISIONING DURING PILOTS
   → Pilot "enable" is easy, but what about "disable"?
   → Test account deletion, group removal, access revocation
   → This is where things break in production!
   
🚫 PROVISIONING WITHOUT GOVERNANCE CONTROLS
   → Don't just sync users to SaaS without approvals
   → Add: access requests, approval workflows, expiration policies, reviews
   → Governance = the real win from this migration!
   
🚫 KEEPING BROAD STANDING ADMIN RIGHTS
   → Don't let people stay in admin groups during transition
   → Use PIM + JIT for privileged access
   → Make it a feature of the migration, not an afterthought!
```

---

## 10) 🏛️ Practical target architecture (high-level)

```
┌──────────────────────────────────────────────────┐
│ 📍 AUTHORITATIVE SOURCES                        │
│  • 🏢 Active Directory (on-prem)                 │
│  • 🧑‍💼 HR System (Workday, SuccessFactors)        │
│  • 📱 SaaS Applications                          │
└────────────────┬─────────────────────────────────┘
                 │
                 ↓
┌──────────────────────────────────────────────────┐
│ ☁️ MICROSOFT ENTRA ID                            │
│ (identity + governance CONTROL PLANE)           │
│                                                  │
│  🔄 Cloud Sync / Connect Sync                   │
│  ↓                                               │
│  📱 App Provisioning (SCIM/connectors)          │
│  ↓                                               │
│  👥 Lifecycle Workflows                         │
│  ↓                                               │
│  💼 Entitlement Management + Access Reviews     │
│  ↓                                               │
│  🔐 PIM + Conditional Access                    │
└────────────────┬─────────────────────────────────┘
                 │
        ┌────────┼────────┐
        ↓        ↓        ↓
┌──────────┐  ┌──────────┐  ┌──────────────────┐
│ 📱 SaaS  │  │ 🏢 ON-PREM│  │ 🤝 B2B COLLAB   │
│  APPS    │  │  AD-DEP   │  │   + PARTNERS    │
│          │  │  RESOURCES │  │                 │
└──────────┘  └──────────┘  └──────────────────┘
        ↓        ↓                 ↓
     ┌──────────────────────────────────┐
     │ 🔧 INTEGRATION LAYER              │
     │ (Logic Apps / Functions / APIs)   │
     └────────┬───────────┬──────────────┘
              ↓           ↓
         ┌─────────┐  ┌──────────┐
         │ LDAP    │  │ SQL      │
         │ CUSTOM  │  │ LEGACY   │
         │ SYSTEMS │  │ APPS     │
         └─────────┘  └──────────┘
```

---

## 11) 📚 References (official + practical)

### 🎯 MIM baseline

- **Microsoft Identity Manager documentation**  
  https://learn.microsoft.com/en-us/microsoft-identity-manager/

### 🔄 Hybrid identity and sync

- **What is Microsoft Entra Cloud Sync?**  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync

- **Decision guide: Connect Sync vs Cloud Sync**  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide

- **Password hash synchronization (Connect Sync)**  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization

### 📱 Provisioning and app integration

- **App provisioning in Microsoft Entra ID**  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/user-provisioning

- **SCIM provisioning architecture in Entra**  
  https://learn.microsoft.com/en-us/entra/architecture/sync-scim

- **Provisioning connectors in the Entra app gallery**  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/provisioning-connectors-gallery

### 🤝 Multi-tenant and external identity

- **Cross-tenant synchronization overview**  
  https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview

### 👥 Identity governance

- **Lifecycle Workflows**  
  https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows

- **Entitlement Management overview**  
  https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview

- **Access Reviews overview**  
  https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview

- **Licensing fundamentals for Identity Governance**  
  https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals

### 🔐 Privileged access and authentication controls

- **Privileged Identity Management (PIM)**  
  https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

- **Conditional Access overview**  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview

- **Authentication Strengths**  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths

- **Conditional Access & authentication security**  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-register-security-info

### 🔑 SSPR and hybrid password operations

- **How SSPR works**  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks

- **Enable SSPR writeback**  
  https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback

### 🔌 Custom connectors and automation

- **ECMA Connector Host (custom provisioning)**  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ecma-connector-overview

- **Azure Logic Apps for integration**  
  https://learn.microsoft.com/en-us/azure/logic-apps/

- **Azure Functions for serverless automation**  
  https://learn.microsoft.com/en-us/azure/azure-functions/

---

## 🎯 Final recommendation: The 4-Wave Migration Strategy

Move from MIM to Entra **in waves**, not in one shot. Here's the proven playbook:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🌊 WAVE 1: Sync Modernization (Weeks 0-8)       ┃
┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃
┃ ✅ Migrate mature capabilities first                ┃
┃ ✅ Deploy Entra Connect or Cloud Sync               ┃
┃ ✅ Run in parallel, validate sync quality           ┃
┃ 📊 Quickest win, highest impact                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🌊 WAVE 2: Governance & Lifecycle (Weeks 8-16)   ┃
┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃
┃ ✅ Deploy Lifecycle Workflows (JML)                ┃
┃ ✅ Activate Entitlement Management                 ┃
┃ ✅ Set up Access Reviews (recertification)         ┃
┃ 👥 Most business value, easy to pilot             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🌊 WAVE 3: App Provisioning (Weeks 16-24)        ┃
┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃
┃ ✅ Redesign edge connectors                        ┃
┃ ✅ Use API/SCIM integration patterns               ┃
┃ ✅ Migrate SaaS provisioning sequentially           ┃
┃ 🔌 Flexible approach for complex scenarios        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 🌊 WAVE 4: Final Decommissioning (Week 24+)      ┃
┃━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┃
┃ ✅ Keep MIM in standby only for proven gaps       ┃
┃ ✅ Decommission MIM only after full validation     ┃
┃ ✅ Archive configuration (7-year compliance)       ┃
┃ 🎉 MIM completely offline, all systems on Entra   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---

### 🎓 Key Success Factors

| Factor | Why It Matters |
|--------|---|
| 📋 **Clear Classification** | Not everything moves at once (retire vs. replace vs. redesign) |
| 🎯 **Source-of-Authority** | Define who owns what BEFORE you migrate (AD? HR? SaaS?) |
| 🧪 **Pilot Everything** | Test sync, provisioning, governance, and deprovisioning before going prod |
| 🔄 **Parallel Running** | Keep MIM and Entra running side-by-side for validation periods |
| 📊 **Measurable Checkpoints** | <5% manual intervention in pilots, <1% error rate in production |
| 👥 **Team Training** | Support team must understand Entra governance model, not just MIM |
| ✅ **Governance First** | The real win is governance (access requests, reviews, PIM), not just sync |

---

### 💡 Remember

> **MIM was a pioneer in identity management.** Entra is the future.
>
> This is not a rip-and-replace. It's a **capability-by-capability transition** where you keep only what Entra can't (yet) do natively.
>
> **The migration is your opportunity** to modernize identity governance, not just move sync engines.
>
> 🚀 **You've got this.**

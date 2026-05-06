# Move from MIM to Entra ID — Practical Migration Playbook
🗓️ Published: 2026-05-06

This guide helps you move from Microsoft Identity Manager (MIM) to Microsoft Entra ID capabilities with a pragmatic, phased approach.

It is based on your migration deck topics and current Microsoft Entra guidance.

> 🎯 TL;DR
>
> - Most classic MIM scenarios now have a cloud-native equivalent in Entra.
> - The migration is not "rip and replace". It is a capability-by-capability transition.
> - The biggest wins usually come first from: sync modernization, governance, and access automation.
> - Keep MIM only where there is still a hard technical dependency or niche connector gap.

---

## 1) Scope of this migration

This playbook covers the same scenario families as your deck:

- On-prem to cloud sync and provisioning
- Cloud to on-prem provisioning
- Tenant-to-tenant sync
- Cloud to SaaS and SaaS to cloud
- SaaS to on-prem (AD / apps / LDAP / SQL)
- Identity lifecycle, group governance, access governance
- SSPR / profile portals / password flows
- PAM to PIM transition
- Authentication and authorization workflows
- Custom objects and advanced workflows

---

## 2) Capability mapping: MIM -> Entra

| MIM capability area | Primary Entra replacement | Migration status |
|---|---|---|
| AD -> Entra sync | Microsoft Entra Connect Sync or Cloud Sync | ✅ Mature |
| Multi-forest sync | Cloud Sync multi-agent + disconnected forest support | ✅ Mature |
| Password sync / writeback | PHS + SSPR writeback (Connect/Cloud Sync scenarios) | ✅ Mature |
| Cloud -> SaaS provisioning | Entra application provisioning (SCIM/connectors) | ✅ Mature |
| Workday / SuccessFactors inbound | Entra HR-driven provisioning | ✅ Mature |
| Tenant-to-tenant user lifecycle | Cross-tenant synchronization | ✅ Mature |
| Lifecycle workflows (joiner/mover/leaver) | Entra Lifecycle Workflows | ✅ Mature |
| Access request / approval / expiration | Entitlement Management (Access Packages) | ✅ Mature |
| Access recertification | Access Reviews | ✅ Mature |
| PAM (JIT/JEA governance) | Entra PIM (roles/groups/resources) | ✅ Mature |
| Dynamic group automation | Entra dynamic group rules | ✅ Mature |
| Complex on-prem downstream provisioning (LDAP/SQL/custom apps) | Entra + API/SCIM + integration patterns (Logic Apps/Functions/partners) | ⚠️ Case-by-case |
| Custom object metaverse-heavy logic | Graph-based automation + integration platform + selective coexistence | ⚠️ Case-by-case |

---

## 3) Migration patterns by scenario

### 3.1 Sync + Provisioning from OnPrem to Cloud

Recommended target pattern:

- Start with current Entra Connect Sync baseline if already deployed
- Evaluate migration to Cloud Sync where architecture/feature fit is validated
- Keep source-of-authority clear (AD/HR) before changing sync tooling

Use when:

- You need simpler operations
- You have disconnected forests
- You want cloud-managed sync configuration

### 3.2 Sync + Provisioning from Cloud to OnPrem

Typical modern use cases:

- Group provisioning/writeback scenarios
- Password writeback and account unlock paths
- Cloud-governed access reflected to AD-dependent systems

Design note:

- Validate every writeback dependency early (permissions, OU design, ownership, rollback)

### 3.3 Sync + Provisioning Tenant to Tenant

Use cross-tenant synchronization for:

- Multi-tenant organizations
- Automated B2B user lifecycle
- Centralized onboarding/offboarding across tenants

Important:

- Cross-tenant sync is not a tenant migration tool
- Plan source and target authority boundaries explicitly

### 3.4 Sync + Provisioning from Cloud to SaaS Apps

Target architecture:

- Entra app provisioning engine (SCIM/native connectors)
- Attribute mappings + scoping filters + assignment governance

Practical sequence:

1. Pilot one business app
2. Validate create/update/disable/delete
3. Add access governance and periodic review

### 3.5 Sync from SaaS Apps to Cloud

Common migration path from MIM connectors:

- Use built-in HR connectors (Workday, SuccessFactors) when possible
- For other SaaS sources, use API-based ingestion/integration patterns
- Normalize identity attributes before they become authoritative

### 3.6 Sync from SaaS to OnPrem (AD / apps / LDAP / SQL)

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

## 4) Governance modernization (usually the highest ROI)

### 4.1 User lifecycle management

Replace manual or MIM workflow-heavy operations with:

- Lifecycle Workflows for joiner/mover/leaver
- Trigger-based tasks + extensions for advanced actions

### 4.2 Group and membership governance

- Dynamic groups for attribute-based membership
- Group ownership model and periodic recertification
- Hybrid writeback only where required for on-prem dependencies

### 4.3 Access management / governance

- Entitlement Management for request/approval/expiration
- Access Packages for role bundles
- Access Reviews for recertification and audit evidence

### 4.4 PAM to PIM

- Move privileged standing access to just-in-time (JIT)
- Add approvals, MFA/strong auth requirements, and auditability
- Start with high-risk roles and admin groups first

---

## 5) Authentication and authorization workflows

Modern replacement for custom MIM-era policy chains:

- Authentication controls: Conditional Access + Authentication Strengths
- Authorization controls: group/app/role assignment governed by entitlement policy
- Action workflows: Lifecycle Workflows + automation hooks

Outcome:

- Less custom code
- More policy-driven controls
- Better audit and recertification model

---

## 6) User and group synchronization: Entra Connect Sync or Cloud Sync?

### Current state: MIM as primary sync engine

If MIM is currently synchronizing users and groups from Active Directory → Entra ID, your first major decision is choosing the replacement sync platform.

### Option A: Entra Connect Sync (current standard)

**Best for:**
- Organizations already using Entra Connect Sync (add cloud provisioning to MIM scope)
- Hybrid device scenarios (device registration, Windows Hello, modern auth with legacy on-prem AD expectations)
- Complex filtering or attribute-flow rules
- Highly dependent on on-prem AD as the identity source

**How it works:**
- Installed on Windows Server, runs continuous sync (every 2 minutes default)
- Full hybrid management: on-prem AD + Entra ID + Exchange, Teams, SharePoint
- Supports password hash sync (PHS), pass-through auth, and federated identity
- Can provision to on-prem AD (write-back, a key MIM feature)

**Migration from MIM:**
- Deploy Entra Connect Sync on a new or existing server (typically small footprint)
- Migrate sync rules from MIM to Entra Connect (rule syntax differs, but logic is similar)
- Test in pilot environment with filtered sync (example: single OU, 100-500 users)
- Gradually expand scope until all users are synced from Entra Connect
- Shut down MIM sync when validated, but keep MIM running for other workflows if they exist

→ **Reference**: [What is Entra Connect Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect)

### Option B: Entra ID Cloud Sync (newer, strategic default)

**Best for:**
- New Entra deployments or MIM migrations without strong on-prem constraints
- Multi-forest or M&A scenarios (independent agents per forest, no metaverse synchronization required)
- Organizations wanting to eliminate on-prem infrastructure (except for DC/AD itself)
- Disconnected forests or temporary connections
- Reducing operational overhead (cloud-managed, auto-patched)

**How it works:**
- Lightweight agent (ECMA Connector Host) installed on Windows Server or hybrid worker
- Manages sync configuration entirely in Azure cloud portal
- Supports AD → Entra sync, Entra → AD (group write-back), cross-cloud scenarios
- Faster feature velocity (new capabilities added quarterly to cloud, not dependent on on-prem agent updates)
- Multiple agents can run in parallel (no single point of failure unlike Entra Connect)

**Key differences from MIM:**
| Feature | MIM | Cloud Sync |
|---------|-----|-----------|
| Agent count | 1 per metaverse | Multiple agents (redundancy) |
| Sync frequency | Real-time or scheduled | ~2 minutes (cloud-managed) |
| Metaverse | Yes, complex | No, simplified object model |
| Scope filtering | Attribute + rule-based | Simple OU or attribute filter |
| Password sync | Yes, via PHS | Via PHS or PT Auth |
| On-prem AD write-back | Yes (MIM strength) | Yes, but limited (groups only) |
| Disconnected forests | Complex (requires extra config) | Native (each agent independent) |
| Licensing | MIM license (expensive) | Included in Entra ID, no extra cost |

**Migration from MIM:**
1. Deploy ECMA Connector Host on Windows Server (can be same server as MIM initially)
2. Create Cloud Sync configuration in Entra admin center (scoped to pilot OU)
3. Run both MIM and Cloud Sync in parallel for 1-2 weeks (verify sync quality)
4. Expand Cloud Sync scope, disable MIM sync on those users
5. Once fully migrated, decommission MIM

→ **Reference**: [What is Entra Cloud Sync?](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync)

### Decision criteria: which sync engine should replace MIM?

**Go with Cloud Sync if:**
- ✅ You can tolerate 2-minute sync frequency (vs. real-time)
- ✅ Your current filtering is OU-based or simple attribute rules
- ✅ You want to eliminate on-prem sync server management
- ✅ You have multiple forests and want independent agents per forest
- ✅ You're open to Entra as source of authority (reverse sync to AD for groups)

**Go with Entra Connect if:**
- ✅ You need sub-2-minute sync frequency (real-time requirements)
- ✅ You have complex attribute-flow logic or multiple rule sets
- ✅ You're invested in Hybrid Device Management (Azure AD Join, HAADJ)
- ✅ You need Exchange Hybrid, Teams resource accounts, or other complex integrations

**Hybrid approach (many organizations):**
- Use **Entra Connect Sync** as primary sync engine (for its breadth)
- Add **Cloud Sync** agents for specific forests or M&A integrations (parallel agents on different forests)
- Both can coexist without conflicts (they sync different scopes)

→ **Reference**: [Cloud Sync vs Connect Sync Decision Guide](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide)

---

## 7) What to do with custom objects and niche MIM workflows

Some MIM implementations include advanced metaverse logic, custom object types, or connectors with no cloud-native equivalent.

Use this decision rule:

- If Entra has native capability: migrate now
- If Entra + lightweight automation can cover it: redesign and migrate
- If business-critical and no acceptable equivalent exists yet: keep a reduced MIM coexistence scope temporarily

**Integration patterns for custom/niche scenarios:**
- Custom ECMA connectors for LDAP directories, SQL databases, REST APIs, or PowerShell integrations
- Logic Apps/Azure Functions for complex orchestration beyond Lifecycle Workflows
- Partner IAM tools for legacy endpoints (example: Okta, Ping, or others for advanced federation)
- Graph API automation for attribute-driven scenarios

→ **Reference**: [ECMA Connector Host Overview](https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ecma-connector-overview)

> 💡 Goal: keep MIM only for true gaps, not for historical habits.

---

## 8) Recommended phased roadmap

### Phase 1 (0-30 days) — Discovery and mapping

**Objectives:**
- Complete inventory of MIM management agents, rules, workflows, and dependencies
- Technical audit: connector types, rule complexity, attribute flows, custom code
- Business audit: which flows are critical, which are legacy, ownership clarity

**Key activities:**
- Classify each flow: retire / replace / redesign / coexist
- Define identity source-of-authority per object and per attribute domain
- Map current MIM workflows to Entra equivalents (Lifecycle Workflows, Entitlement Management, etc.)
- Document all downstream systems consuming MIM data (which systems will be affected by shutdown?)
- Evaluate Entra Connect Sync vs Cloud Sync readiness
- Assess licensing requirements (Entra ID P1/P2, ID Governance, or Suite)

**Checkpoint:** Signed off on capability mapping, executive stakeholder alignment on phased approach

### Phase 2 (31-60 days) — Pilot by capability

**Objectives:**
- Validate Entra can handle real workloads without MIM
- Identify gaps, reconfiguration efforts, and coexistence strategies early
- Build team confidence and runbooks

**Pilot sequence (low risk first):**
1. **Sync modernization pilot** on low-risk scope (single OU or department)
   - If on Entra Connect: establish baseline, prepare for Cloud Sync if readiness criteria met
   - If migrating to Cloud Sync: deploy agents, validate 2-minute sync frequency meets SLAs
   - Verify password hash sync works if needed for fallback auth

2. **One SaaS provisioning pilot** (example: Salesforce, ServiceNow, or Slack)
   - Test create/update/disable/delete user lifecycle
   - Validate attribute mappings (custom attributes may need directory extensions)
   - Establish approval workflows if app requires access governance
   - Run for 2 weeks with real users, measure time to activate and error rates

3. **Lifecycle Workflows pilot** (Joiner + Leaver scenarios)
   - Joiner: Manager notification + group assignment + license assignment
   - Leaver: Account disable + group removal + access package revocation + export audit report
   - Measure: time to completion, manual override frequency, audit trail completeness

4. **Access package + review pilot** (one business unit)
   - Create 2-3 representative access packages (role bundles)
   - Simulate request/approval/expiration lifecycle
   - Conduct first access review (recertification)
   - Measure: time to review, approval latency, false positives in recommendations

**Checkpoint:** All pilots succeed with <5% manual intervention, runbooks documented, team trained

### Phase 3 (61-120 days) — Industrialize and cutover

**Objectives:**
- Scale approved patterns to full production scope
- Maintain operational continuity throughout transition
- Establish new support models and runbooks

**Cutover strategy by scenario:**
1. **Sync cutover** (most critical):
   - Enable Entra sync on full directory scope (not just pilots)
   - Keep MIM sync running in parallel for 5-7 days as safety net
   - Monitor: duplicate accounts, missing users, attribute discrepancies
   - After validation period: stop MIM sync, complete cutover

2. **App provisioning cutover** (sequential by app):
   - Week 1: Cut over 3-5 low-criticality SaaS apps
   - Week 2-3: Cut over strategic apps (HR, sales, finance)
   - Week 4: Cut over integrations with custom connectors (LDAP, SQL, REST)
   - Maintain MIM provisioning in parallel until all apps migrated

3. **Governance cutover** (parallel with provisioning):
   - Deploy Entitlement Management for access request scenarios
   - Activate Access Reviews for compliance recertification
   - Deploy Lifecycle Workflows for JML automation
   - Train business owners on delegated administration

4. **Deprovisioning/cleanup**:
   - Establish clear deprovisioning policies in Entra (soft-delete then hard-delete after 30 days)
   - Test bulk user deletion and account unlock workflows
   - Document fallback procedures (account recovery, restore deleted users)

**Rollback checkpoints:** After each cutover step, maintain MIM in standby mode for 7 days before full shutdown

**Checkpoint:** 95%+ of workload running in Entra with <1% error rate, MIM reduced to standby-only mode

### Phase 4 — Residual decommissioning

**Objectives:**
- Eliminate all remaining MIM dependencies
- Decommission MIM infrastructure cleanly
- Archive configuration for compliance/audit

**Steps:**
1. Isolate remaining MIM-only use cases (should be <5% of original workload by this point)
2. For each residual:
   - Replace with Entra native feature OR
   - Replace with ECMA connector + Logic Apps OR
   - Implement via partner tool if no Entra solution available
   - Or, retire the flow entirely (often legacy processes)

3. Decommission MIM components in order:
   - Stop all connectors
   - Disable management agents
   - Take FIM/MIM databases offline
   - Archive configuration database for 7 years (compliance/audit)
   - Decommission MIM servers (hardware recycling)
   - Release MIM licensing

4. Knowledge transfer:
   - Document Entra governance model vs old MIM model
   - Archive MIM workflow logic as reference
   - Train support teams on Entra troubleshooting

**Checkpoint:** MIM completely offline, all systems relying exclusively on Entra, incident rates stable

---

## 9) Migration pitfalls to avoid

- Treating migration as one big bang
- Moving sync without defining source-of-authority
- Ignoring deprovisioning behavior during pilots
- Migrating provisioning without governance controls (approvals/reviews/expiry)
- Keeping broad standing admin rights during transition

---

## 10) Practical target architecture (high-level)

```text
Authoritative sources (AD / HR / SaaS)
        |
        v
Microsoft Entra ID (identity + governance control plane)
  - Cloud Sync / Connect Sync
  - App Provisioning (SCIM/connectors)
  - Lifecycle Workflows
  - Entitlement Management + Access Reviews
  - PIM + Conditional Access
        |
        v
Targets
  - SaaS applications
  - On-prem AD-dependent resources
  - Multi-tenant collaboration targets
  - Custom downstream systems via integration layer
```

---

## 11) References (official + practical)

### MIM baseline

- Microsoft Identity Manager documentation  
  https://learn.microsoft.com/en-us/microsoft-identity-manager/

### Hybrid identity and sync

- What is Microsoft Entra Cloud Sync?  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/what-is-cloud-sync

- Decision guide: Connect Sync vs Cloud Sync  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/connect-to-cloud-sync-decision-guide

- Password hash synchronization (Connect Sync)  
  https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization

### Provisioning and app integration

- App provisioning in Microsoft Entra ID  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/user-provisioning

- SCIM provisioning architecture in Entra  
  https://learn.microsoft.com/en-us/entra/architecture/sync-scim

- Provisioning connectors in the Entra app gallery  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/provisioning-connectors-gallery

### Multi-tenant and external identity

- Cross-tenant synchronization overview  
  https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview

### Identity governance

- Lifecycle Workflows  
  https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows

- Entitlement Management overview  
  https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview

- Access Reviews overview  
  https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview

- Licensing fundamentals for Identity Governance  
  https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals

### Privileged access and authentication controls

- Privileged Identity Management (PIM)  
  https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure

- Conditional Access overview  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview

- Authentication Strengths  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths

- Conditional Access & authentication security  
  https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-register-security-info

### SSPR and hybrid password operations

- How SSPR works  
  https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-howitworks

- Enable SSPR writeback  
  https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr-writeback

### Custom connectors and automation

- ECMA Connector Host (custom provisioning)  
  https://learn.microsoft.com/en-us/entra/identity/app-provisioning/on-premises-ecma-connector-overview

- Azure Logic Apps for integration  
  https://learn.microsoft.com/en-us/azure/logic-apps/

- Azure Functions for serverless automation  
  https://learn.microsoft.com/en-us/azure/azure-functions/

---

## Final recommendation

Move from MIM to Entra in waves, not in one shot.

1. Migrate mature capabilities first (sync, governance, access).
2. Redesign edge connectors with API/SCIM integration patterns.
3. Keep a temporary coexistence only for proven hard gaps.
4. Decommission MIM only after deprovisioning and audit controls are fully validated in Entra.

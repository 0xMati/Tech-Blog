# Admin-Only Second Tenant (“Red Tenant”): Smart Move or Trap?
Published: 2025-08-29

## TL;DR & Position
A dedicated admin-only second tenant sounds clean on a whiteboard, but in real life it’s a bad idea. Microsoft guidance is to **avoid a second tenant for administration** and instead **harden a single production tenant** using the Enterprise Access Model (EAM) and Zero Trust controls.

![](assets/Red%20Tenant%20Smart%20move%20or%20trap/2025-08-29-01-03-39.png)

**Why:** a “red tenant” doubles licenses and operations, complicates incident response, weakens assurance in subtle ways (Conditional Access, device trust, logging), and creates an illusion of safety while the production tenant remains your blast radius.

---

## From Red Forest (ESAE) to the Enterprise Access Model (EAM)
**Old world:** ESAE/Red Forest isolated Tier‑0 by creating an admin forest. That playbook is retired for the cloud era. In hybrid/cloud, your **control plane is Entra ID** and the risk is identity + device + session. Copy‑pasting the ESAE idea into a second tenant doesn’t isolate risk; it **moves complexity across a new seam**.

**Modern world:** EAM + Zero Trust. Segment privileges by tiers, enforce **Privileged Access Workstations (PAWs)**, require **phishing‑resistant MFA** and **compliant/hybrid devices** for admin sessions, manage elevation with **PIM**, and observe everything with unified auditing and detections. One tenant = one truth for identities, devices, policies, and logs.

---

## What a “Red Tenant” Promises (and Why It Disappoints)
On slide decks, a red tenant looks like clean separation: PAWs and admin identities here, production there. Reality is messier.

| Pitch | Reality |
|---|---|
| “Hard isolation of admin identities and devices” | Cross‑tenant trust can carry MFA/device claims, but you **can’t target external devices** with device filters or scope policies by their attributes. Assurance weakens at the boundary. |
| “Safer Intune for PAWs” | You just created **two MDMs, two app catalogs, two patch rings**, and two helpdesk flows. Drift and blind spots multiply. |
| “Cleaner PIM story” | PIM still runs in the production tenant for production roles. Splitting groups/roles across tenants **adds elevation paths and human error**. |
| “Cheaper to segregate” | Double‑tenant means **duplicated P2/Intune/Defender** for PAWs, extra Sentinel ingestion, and glue to stitch it all. |
| “Better IR” | Investigations now traverse **two timelines, two alerting fabrics, two log sets**. Mean Time To Reason goes up, not down. |

---

## Where This Breaks in Microsoft Reality
Short, surgical, and painful in practice:

- **Conditional Access precision drops.** In one tenant, device filters let you say “only these PAWs can touch admin portals/PowerShell.” Across tenants you mostly get “any compliant device from that tenant,” which is looser and harder to prove.
- **Intune fragmentation.** Separate enrollment, policy, analytics, patching, app delivery, support. Admins juggle identities; tickets ping‑pong between two device records.
- **PIM & scoping aren’t solved by a second tenant.** You still need clean role hygiene, just‑in‑time elevation, and access reviews in production. A red tenant **adds** cross‑tenant elevation paths to keep safe.
- **Workload identities sprawl.** Cross‑tenant consents, duplicated app registrations, key rotation in two places, and ambiguous break‑glass for automation.
- **Logging & IR slow down.** Split audit trails and detections force stitching in Sentinel. Every minute spent reconciling tenants is a minute not containing the incident.
- **People & process friction.** More exceptions, more context switching, more things to forget during on‑call.

---

## Operational & Cost Impact (What Teams Feel Day 2)
- **Licenses:** Admins typically need P2 + Intune + Defender where their PAWs live. With a red tenant, that’s **twice**.
- **Drift:** Two policy surfaces, two automation pipelines, two places to miss a cleanup.
- **Runbooks:** On‑call playbooks start with “which tenant?” and branch from there.
- **Human cost:** Tenant hopping slows approvals, reviews, and basic troubleshooting.

---

## Security Pitfalls of a Red Tenant
- **Assurance dilution:** You trade precise targeting for coarse external‑tenant trust. Attackers aim for seams.
- **Privilege sprawl:** More elevation paths, more secrets, more approvals to guard.
- **False comfort:** The production tenant still holds the real risk. If it’s weak, a red tenant is cosmetic.

---

## What To Do Instead (Single‑Tenant, EAM‑Aligned)
A practical baseline that beats two tenants every time:

- **EAM tiers:** Map roles to Tier 0/1/2; keep Tier 0 tiny. No standing Global Admins.
- **PAWs:** Dedicated hardware or VDI. Enroll in Intune, hardened baselines, dedicated local admin, no personal use.
- **Conditional Access:** Require phishing‑resistant MFA + compliant/hybrid device for admin portals/PowerShell. Use device filters to target PAW groups. Apply tight session controls.
- **PIM everywhere:** JIT for all admin roles with approval, justification, and access reviews.
- **Identity Governance:** Lifecycle workflows for admin identities, periodic reviews, separation of duties.
- **Workload identities:** Inventory app/managed identities; enforce least privilege and key rotation (Key Vault + automation).
- **Unified logging:** One Sentinel workspace with Entra sign‑ins, M365 audit, Defender signals; saved hunting queries for admin sessions.
- **Break‑glass:** Two cloud‑only accounts in production, excluded from CA but operationally protected and tested.

---

## Common Objections — Quick Rebuttals
- **“We need hard isolation for PAWs.”** You get stronger isolation with **CA device filters + PAW baselines** in one tenant than with coarse external‑tenant trust.
- **“Our tenant is messy; a clean red tenant is faster.”** A second tenant delays the real work. Run an **EAM hardening** program; don’t outsource hygiene to a new boundary.
- **“Licensing won’t change much.”** It will. PAWs and admin features live where the admin identity enrolls; two tenants usually means **double**.
- **“IR will be simpler.”** Two tenants mean split evidence and longer timelines. Incident response favors **one identity plane**.
- **“Auditors demand separation.”** Auditors want **controls and evidence**, not extra topology. It’s easier to prove **PIM + CA + unified logging** in one tenant than to reconcile evidence across two.
- **“Cross‑tenant device compliance is good enough.”** Trust is **binary** and coarse. You **can’t target external devices** with device filters or Intune policy. Assurance drops; exceptions multiply.
- **“Contractors should live in another tenant.”** Use **B2B/B2B direct connect** with scoped cross‑tenant settings and govern them **in production**. Keep the control plane single‑tenant.
- **“We need an air‑gap.”** Cloud tenants aren’t air‑gapped; identity and tokens cross boundaries. Enforce **PAWs + phishing‑resistant MFA + CA + token protections** instead of a pseudo‑gap.
- **“Greenfield PAW build is faster in a new tenant.”** You can get a clean start with **Intune scopes/filters** and dedicated rings inside production—without paying a migration tax later.
- **“Second tenant reduces blast radius if compromised.”** You’ve **doubled the attack surface** and added a cross‑tenant trust to abuse. Harden production; don’t add a second failure domain.
- **“PIM for groups / AU limits force us out.”** These edge cases are **narrow**; solve them with **role hygiene, scoping, and process**. A red tenant relocates the pain and adds complexity.
- **“Our PAM (e.g., CyberArk) fits better with a red tenant.”** Enforce **PAW‑only access** and network segmentation to PAM from production. Keep **elevation and evidence** in one tenant.

---

## Closing
Second tenants feel neat in theory. In practice, they slow you down and blur your controls. Secure the plane you actually fly: **one tenant, EAM‑aligned, with PAWs, PIM, tight Conditional Access, and full‑fidelity logging**. If someone insists on a red tenant, treat it like a **temporary containment with a written exit date**—and get back to one tenant fast.

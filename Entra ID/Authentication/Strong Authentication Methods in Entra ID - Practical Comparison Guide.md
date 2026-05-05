# Strong Authentication Methods in Entra ID
**Practical guide: what to choose, why, and when (without marketing fluff) 🔐**
Published: 2026-05-04

---

## TL;DR ⚡ (for busy admins)

→ Short version you can use in a client discussion:

- 🛡️ **Priority 1: Phishing-resistant methods (target state)**
	- FIDO2/Passkeys
	- Windows Hello for Business
	- Certificate-Based Authentication (CBA)
	- Security level: **AAL3**

- 📲 **Priority 2: Strong mainstream methods (transition state)**
	- Microsoft Authenticator push (number matching)
	- Authenticator phone sign-in (passwordless app, not FIDO2)
	- OATH TOTP as fallback only
	- Security level: **AAL2**

- 🚀 **Priority 3: Bootstrap and legacy fallback (exception state)**
	- Temporary Access Pass (TAP) for onboarding and recovery only
	- SMS/Voice only as tightly controlled emergency fallback
	- Security level: TAP is contextual, SMS/Voice is **AAL1**

- 🔧 **Design lever to insist on**
	- Use **Authentication Strength** in Conditional Access
	- "Require MFA" alone is not precise enough

- 🔑 **Passwordless key message**
	- Passwordless does not delete the password in the directory
	- Password expiry policies must be aligned to avoid incidents

---

## 1. What is a strong authentication method in Entra ID? 🧠

Most teams start with a simple question: "Do we have MFA enabled?" ✅

Good start. Not the finish line.

In Entra ID, two users can both pass MFA and still sit in very different risk tiers:

- User A signs in with WHfB or FIDO2 (phishing-resistant) 🛡️
- User B signs in with SMS OTP (interceptable, weaker) ⚠️

→ Same MFA checkbox, different blast radius.

A strong authentication strategy should always define 4 things:

- Which methods are allowed
- Which populations can use them
- Which apps/actions require stronger assurance
- Which context/risk signals can tighten access

When these 4 points are explicit, decisions are faster, policies are cleaner, and exceptions stop spreading.

### Stakeholder takeaway 🎯

- Do not stop at: "Do we have MFA?"
- Move to: "Which MFA strength do we enforce for which business risk?"

That is the shift from checkbox security to decision-grade security.

---

### 1.1 Authentication Strength, Phishing-Resistant MFA, and AAL3 🏛️

→ **Core idea:** this is where strategy becomes enforceable policy.

In Entra ID, **phishing-resistant MFA** is not just a label. It is an actual control you can enforce: **Authentication Strength** in Conditional Access.

**Why it matters:**

- A single global MFA baseline protects low-risk *and* high-risk workloads the same way → **rarely acceptable**
- Privileged accounts without **phishing-resistant requirements** stay exposed to takeover paths → **high impact**
- If method strength is not explicit in policy, exceptions slowly become the norm → **policy drift**

**Authentication Strength** lets you bind accepted methods to each scenario. Microsoft provides three built-in levels:

| Strength | What it requires |
|---|---|
| **Multifactor authentication** | Any MFA combination, including SMS + password |
| **Passwordless MFA** | Passwordless methods: WHfB, FIDO2, certificate-based |
| **Phishing-resistant MFA** | FIDO2, WHfB, or CBA only — *no replayable shared secret* |

→ **Governance pattern that works**

- **Privileged operations & admin portals:** require phishing-resistant MFA
- **Standard business apps:** allow strong mainstream methods *where justified*
- **Transitional/legacy flows:** allow tightly scoped exceptions *with expiry and review*

Much more defensible than one global "require MFA" switch.

#### <u>**What is AAL, and where does AAL3 fit?**</u>

**AAL** (Authenticator Assurance Level) comes from NIST SP 800-63B — widely used in audits and regulated environments:

| Level | Assurance grade | Actual methods | Use case |
|---|---|---|---|
| 🔴 **AAL1** | Single factor, **minimal** | 🔐 **Password** alone<br>📞 **SMS / Voice OTP** | Legacy baseline only |
| 🟡 **AAL2** | MFA, **moderate** | 📱 **Authenticator push** (number matching)<br>📱 **Authenticator phone sign-in** (passwordless)<br>⏱️ **OATH TOTP** + password<br>🎟️ **TAP** (temporary context) | General user population, transition phase |
| 🟢 **AAL3** | 🛡️ **Hardware-bound, phishing-resistant** | 🔑 **FIDO2 / Passkeys**<br>💻 **Windows Hello for Business** (TPM + PIN/biometrics)<br>📜 **Certificate-Based Auth** (CBA) | Admins, privileged access, sensitive workloads |

→ **Quick translation** 🔄

- Microsoft wording: **phishing-resistant MFA**
- Compliance wording: **AAL3**
- Practical meaning: *same security objective, different vocabulary*

→ **Boss-level recommendation** 🕹️

- Use **Authentication Strength** in *every* critical Conditional Access policy
- **Target AAL3** everywhere as your long-term goal — phishing-resistant is the objective
- **At minimum**, enforce AAL3 for *privileged access, sensitive data, high-impact applications* today
- **Keep** weaker methods as *controlled transition paths*, with explicit migration timelines off them

---

## 2. Quick comparison table 📊

| Method | Assurance | AAL | Strategic status | User experience | Prerequisites | Pros | Cons | Best use |
|---|---|---|---|---|---|---|---|---|
| 🔑 **FIDO2 Security Keys / Passkeys** *(including Authenticator passkeys)* | 🟢 Very high (5/5) | **AAL3** | ✅ **Target** | Fast (tap + PIN/biometric) | FIDO2-enabled client/browser, Entra FIDO2/passkey policy, user registration | Very strong, no shared secret, ideal for admins and modern passwordless rollout | Credential lifecycle depends on passkey type (hardware key logistics or mobile device recovery/replacement) | Admins, privileged access, high-risk environments |
| 💻 **Windows Hello for Business (WHfB)** | 🟢 Very high (5/5) | **AAL3** | ✅ **Target** | Excellent on managed endpoints | Compliant/joined device, TPM recommended, Intune/GPO config | Passwordless, excellent UX, device-bound credential | Depends on device posture and rollout quality | Managed internal users, long-term passwordless |
| 📜 **Certificate-Based Authentication (CBA)** | 🟢 High to very high (4-5/5) | **AAL3** | ✅ **Target** | Varies by setup | PKI, user certificates, lifecycle processes | Robust, compliance-friendly in regulated sectors | PKI complexity and operational burden | Regulated sectors, smartcard/CAC scenarios |
| 📱 **Authenticator push (number matching)** | 🟡 Medium to high (3-4/5) | **AAL2** | 🔄 **Transition** | Very good for most users | Smartphone, Authenticator app, policy tuning | Easy to deploy, fast adoption, strong balance | MFA fatigue risk if policy is loose | Practical baseline for large populations |
| 📱 **Authenticator phone sign-in (passwordless)** | 🟡 Medium to high (3-4/5) | **AAL2** | 🔄 **Transition** | Good | Smartphone, Authenticator app, phone sign-in enabled | Passwordless flow, reduced password exposure | Not equivalent to FIDO2/WHfB/CBA phishing resistance; recovery required | Passwordless bridge for non-privileged populations |
| ⏱️ **OATH TOTP (app/hardware token)** | 🟠 Medium (3/5) | **AAL2** | ⚠️ **Fallback** | Good | TOTP app or hardware token, enrollment | Works offline, useful backup | Phishable code, more user friction | Backup in constrained environments |
| 🎟️ **Temporary Access Pass (TAP)** | 🔵 Context-dependent | Contextual | ⚠️ **Bootstrap only** | Good for onboarding | TAP policy enabled, HR/IT process | Excellent for passwordless bootstrap/recovery | Must stay short-lived and tightly governed | Onboarding and secure recovery |
| 📞 **SMS / Voice OTP** | 🔴 Low to medium (2/5) | **AAL1** | 🚫 **Legacy fallback only** | Familiar but fragile | Valid phone number, telecom availability | Maximum compatibility | SIM-swap/interception risk; lower trust level | Emergency compatibility case |

---

## 2.1 How to read section 2 quickly 🧭

Use the **Strategic status** column in section 2 as the policy decision lever:

- ✅ **Target**: preferred long-term state (default to **AAL3**)
- 🔄 **Transition**: allowed while migrating to AAL3, with a dated plan
- ⚠️ **Fallback/Bootstrap**: temporary by design, tightly scoped and reviewed
- 🚫 **Legacy fallback only**: emergency compatibility path with retirement objective

→ Rule of thumb: keep one source of truth in section 2, and treat every non-target method as temporary unless formally justified.

---

## 3. Method-by-method details (field reality edition) 🎮

### 3.1 FIDO2 Security Keys and Passkeys

→ Quick take: best-in-class for high-value access and admin scenarios.

#### 🧾 What it is (and why it is strong)

FIDO2 uses public-key cryptography: the private key stays on the authenticator, and Entra ID validates a challenge response. There is no reusable secret to steal and replay.

In practice, this can be a hardware security key or a synced/device-bound passkey (including passkeys registered through Microsoft Authenticator, depending on platform support and policy).

#### ✅ Why it is great

- Native phishing resistance 🛡️
- No password entry
- Excellent for privileged accounts

#### ⚠️ Watch-outs

- Credential lifecycle management (hardware key logistics or mobile device recovery/replacement)
- Requires a clean backup and recovery process

#### 🎯 Best fit

- Long-term target for all user populations as part of a phishing-resistant strategy
- Coexists with WHfB: use WHfB on managed Windows endpoints and FIDO2/Passkeys where WHfB is not available or not practical
- Immediate priority for Admin/IT/SecOps, admin portals, PIM activation, and critical consoles

#### 🧠 Passkey model nuance (advanced)

- **Device-bound passkey**: key material stays tied to one device/authenticator (strong local control model).
- **Synced passkey**: credential portability improves UX and recovery, but governance depends more on ecosystem and account/device protection.
- **Hardware security key**: strongest portability with explicit possession control and clear break-glass handling.
- Practical policy approach: prioritize phishing resistance first, then choose passkey model per population, device posture, and recovery maturity.

---

### 3.2 Windows Hello for Business (WHfB)

→ Quick take: top-tier security with excellent daily UX on managed devices.

#### 🧾 What it is (and why it is strong)

WHfB replaces password entry with a device-bound key protected by TPM. Users unlock locally with PIN or biometrics, and the credential is never exposed as a reusable secret over the network.

It is phishing-resistant by design when deployed with proper device and policy controls.

#### ✅ Why it is great

- Excellent user comfort (local PIN/biometric)
- Credential is bound to the device
- Strong resistance against common credential attacks

#### ⚠️ Watch-outs

- Requires serious device hygiene
- More of a structured identity/device program than "just enable MFA"

#### 🎯 Best fit

- Long-term phishing-resistant target for managed Windows users
- Coexists with FIDO2/Passkeys for non-Windows, shared, or less-managed scenarios

#### 🔬 Implementation notes (quick)

- **TPM is non-negotiable** for strong assurance: enforce via Intune/GPO.
- **PIN and biometrics are local unlock methods** for the same TPM-protected key (not stacked sequential prompts).
- **Policy quality determines outcome**: require compliant devices, enforce PIN policy, and define recovery/reset operations.

#### 🧠 WHfB factor model (advanced)

- **Have**: TPM-backed private key bound to the device.
- **Know / Are**: user unlocks with PIN *or* biometrics.
- **Why not 3 sequential prompts?** Because PIN and biometrics are alternative local gestures to unlock the same key, not cumulative remote challenges.
- Practical outcome: the assurance is achieved by architecture (hardware-bound key + local user verification), not by multiplying user prompts.

---

### 3.3 Certificate-Based Authentication (CBA)

→ Quick take: extremely strong if your PKI game is mature.

#### 🧾 What it is (and why it is strong)

CBA uses X.509 certificates to authenticate users instead of passwords or OTP codes. Trust is anchored in your PKI chain and certificate issuance controls.

When certificate lifecycle and revocation are well governed, it provides strong assurance and excellent auditability in regulated environments.

#### ✅ Why it is great

- Very strong when PKI is mature
- Good fit for compliance-heavy requirements

#### ⚠️ Watch-outs

- PKI means operations, procedures, lifecycle, support
- Poor PKI design quickly becomes technical debt

#### 🎯 Best fit

- AAL3 target where PKI is already mature or mandated
- Regulated sectors, smartcards, and certificate-centric environments

#### 🔬 Implementation notes (quick)

- Define strict certificate issuance proofing and role separation.
- Enforce revocation hygiene (CRL/OCSP and lifecycle monitoring).
- Treat certificate renewal and lost-token handling as production runbooks.

---

### 3.4 Microsoft Authenticator push (number matching)

→ Quick take: the practical default for large populations and phased modernization.

#### 🧾 What it is (and where it fits)

This is classic MFA: user enters password, then approves a mobile prompt with number matching. It significantly improves security versus password-only and is easy to deploy at scale.

It remains AAL2 and can still be phished through real-time attack paths, so it should be treated as a transition baseline, not a final target for high-risk access.

#### ✅ Why it is great

- Strong security/UX balance
- Fast user adoption
- Works well in phased migrations

#### ⚠️ Watch-outs

- Can suffer from MFA fatigue if policies are too permissive
- Dependency on personal or corporate smartphones

#### 🎯 Best fit

- Broad user populations as a practical AAL2 baseline
- Transition phase while rolling out phishing-resistant methods by default

#### 🔬 Implementation notes (quick)

- Enforce number matching and disable weak approval patterns.
- Pair with Conditional Access context controls (device/risk/location).
- Define a step-up path to AAL3 for privileged and sensitive access.

---

### 3.5 Microsoft Authenticator phone sign-in (passwordless)

→ Quick take: a practical passwordless option for users not yet on WHfB/FIDO2, but not equivalent to phishing-resistant methods.

#### 🧾 What it is (and where it fits)

Phone sign-in removes daily password entry and authenticates through the Authenticator app flow. It is often a strong adoption step because users keep familiar mobile habits.

Important distinction: passwordless does not automatically mean phishing-resistant at AAL3 level. This method is typically positioned as AAL2 transition.

#### ✅ Why it is useful

- Passwordless user experience with a familiar mobile app
- Reduces daily password exposure and password-related friction
- Easy to position as a transition step toward stronger passwordless methods

#### ⚠️ Watch-outs

- Not FIDO2 and not phishing-resistant at the same level as WHfB/FIDO2/CBA
- Strongly dependent on smartphone lifecycle and recovery readiness
- Requires clear guidance so users and stakeholders do not confuse it with Authenticator push MFA

#### 🎯 Best fit

- General user populations during passwordless transition
- Organizations not ready for full WHfB/FIDO2 coverage yet

#### 🔬 Implementation notes (quick)

- Position clearly as transition AAL2, not final phishing-resistant state.
- Plan recovery scenarios (new phone, lost phone, app reset) before broad rollout.
- Avoid user confusion with push MFA by documenting both experiences.

---

### 3.6 OATH TOTP (third-party apps or hardware token)

→ Quick take: useful backup path, but not where you want to stop.

#### 🧾 What it is (and where it fits)

TOTP generates a short-lived numeric code based on a shared secret and time window. It works in low-connectivity conditions and is widely supported.

Because the code is still replayable during its validity window, it is not phishing-resistant and should stay a controlled backup path.

#### ✅ Why it is useful

- Works even without mobile data
- Simple alternative in constrained environments

#### ⚠️ Watch-outs

- More phishing-vulnerable (replayable code in a time window)
- Less fluid UX than push/passkeys

#### 🎯 Best fit

- Backup method
- Specific cases without push notification support

#### 🔬 Implementation notes (quick)

- Keep as backup only and require explicit business justification.
- Monitor usage and remove persistent dependency where possible.
- Pair with migration milestones toward phishing-resistant methods.

---

### 3.7 Temporary Access Pass (TAP)

→ Quick take: fantastic bootstrap tool, risky if governance is loose.

#### 🧾 What it is (and where it fits)

TAP is a temporary credential designed to bootstrap strong methods (WHfB, FIDO2) or recover access without bypassing identity checks.

It is operationally powerful, but only if validity, issuance rights, and verification steps are tightly controlled.

#### ✅ Why it is excellent

- Ideal bootstrap to move users into passwordless flows 🚀
- Supports recovery without bypassing security controls

#### ⚠️ Watch-outs

- If validity is too long, risk surface grows unnecessarily
- Requires strict governance

#### 🎯 Best fit

- Day-one onboarding
- Controlled recovery (support + identity verification)

#### 🔬 Implementation notes (quick)

- Keep lifetime short and scope tightly controlled.
- Restrict issuance rights and require operator verification steps.
- Audit issuance and usage patterns as part of identity operations.

---

### 3.8 SMS and Voice OTP

→ Quick take: keep only as a tightly controlled emergency fallback.

#### 🧾 What it is (and where it fits)

SMS/voice OTP delivers one-time codes through telecom channels and remains broadly accessible for edge scenarios.

Because telecom channels can be intercepted or socially engineered, this method should remain emergency-only with an explicit retirement objective.

#### ✅ Why it still exists

- Nearly universal reach
- Very easy to explain to users

#### ⚠️ Watch-outs

- Weaker security compared to modern methods ⚠️
- Vulnerable to SIM swap and telecom attacks

#### 🎯 Best fit

- Temporary fallback, tightly scoped, with a migration-off plan

#### 🔬 Implementation notes (quick)

- Keep disabled by default where business constraints allow.
- If enabled, scope to emergency groups and review periodically.
- Track retirement metrics to drive elimination over time.

---

## 4. How to choose without regretting it in 6 months 🧭

→ Decision principle: **target phishing-resistant (AAL3) by default**, and treat weaker methods as temporary states with exit dates.

### 4.1 Fast decision model (use this in architecture reviews)

1. **Set the default**: for new access policies, default to phishing-resistant methods.
2. **Classify populations and resources**: privileged users and sensitive workloads get AAL3 immediately.
3. **Allow transition only with controls**: if AAL2 is temporarily required, define scope, owner, and retirement date.
4. **Bind method + device + context**: enforce Authentication Strength with Conditional Access Trusted Signals.

### 4.2 Why teams regret their first rollout

- They deploy "Require MFA" and assume all MFA has equivalent strength.
- They keep fallback methods open-ended, with no migration timeline.
- They separate identity policy from device posture and contextual risk.

### 4.3 Pragmatic rollout order

1. Define Authentication Strength policy tiers and make AAL3 the default target state.
2. Enforce AAL3 immediately for admin portals, PIM, and high-impact applications.
3. Scale AAL3 on managed Windows endpoints with WHfB.
4. Extend AAL3 to broader and cross-platform populations with FIDO2/passkeys (including Authenticator passkeys where supported).
5. Keep Authenticator push/phone sign-in (AAL2) as controlled transition paths with dated migration plans.
6. Keep TOTP as a **justified exception only** — explicit scope, owner, and monitoring required.
7. **Disable SMS/Voice by default** — no exception without formal justification and CISO-level approval.
7. Use TAP for onboarding and recovery, with short validity and strict issuance controls.

→ Bonus reality check: if your strongest method is optional, users will converge on the weakest allowed path.

### 4.4 Trusted Signals — method is only one dimension 🔗

A common mistake: treating authentication as a single gate. In Entra ID, the trust decision is a **compound evaluation**.

| Signal dimension | What it covers | Examples |
|---|---|---|
| 👤 **Who** | Identity + role + group | Authenticated user, admin role, guest status |
| 🔑 **How** | Authentication method + AAL level | FIDO2 (AAL3), Authenticator push (AAL2) |
| 💻 **Device** | Compliance state + hardware posture | Intune-compliant, Entra-joined, TPM active |
| 🌍 **Context** | Risk signals + environment | Named location, sign-in risk, session anomaly |

→ **The key principle:** a phishing-resistant method on an unmanaged device is stronger than SMS, but weaker than the same method on an Intune-compliant, TPM-equipped device. Method strength and device posture are not independent variables.

**In practice**, this means Conditional Access policies should bind all four dimensions:
- **Authentication Strength** for the method
- **Device compliance** requirement for device posture
- **Identity Protection** risk conditions for contextual signals
- **Named locations / network conditions** where relevant

→ That is what separates checkbox MFA from a real defense-in-depth architecture.

---

## 5. Example matrix: method by population 👥

Use this matrix to map populations to methods in your Authentication Strength and Conditional Access policies. Every non-AAL3 cell is a transition state, not a permanent configuration.

| Population | AAL target | Primary method | Transition/fallback | Avoid | Key deployment note |
|---|---|---|---|---|---|
| 👑 **Cloud/tenant admins** | **AAL3 now** | FIDO2 or WHfB | Authenticator push (temporary, scoped) | SMS/Voice, no exceptions | First population to enforce phishing-resistant; no grace period |
| 💻 **Internal users on managed Windows devices** | **AAL3 target** | WHfB | FIDO2/Passkeys for shared or non-Windows use | SMS as default method | WHfB rollout tied to device compliance program |
| 📱 **Internal users on unmanaged or mobile-first devices** | **AAL2 → AAL3** | Authenticator push or phone sign-in | FIDO2/Passkeys as devices onboard | SMS/Voice | Define device onboarding path to unlock AAL3 over time |
| 🌐 **External users / B2B partners** | **AAL2 minimum** | Based on cross-tenant trust + Authentication Strength policy | Authenticator/TOTP per partner policy | Untracked exceptions, no enforcement | Negotiate Authentication Strength at federation boundary |
| 🏭 **Field teams / shared workstations** | **AAL3 where possible** | FIDO2 hardware key (portable, shared-safe) | OATH hardware token (if FIDO2 not deployable) | Full dependency on SMS | Hardware key is often the right answer here; plan stock and replacement |
| 🆕 **New joiners / day-1 users** | Contextual | TAP (bootstrap only) | → WHfB or FIDO2 after enrollment | TAP as a permanent method | TAP validity ≤ 24h; enrollment must be completed before expiry |
| 🔒 **Break-glass / emergency accounts** | **AAL3 always** | FIDO2 hardware key (dedicated, stored securely) | None | Any MFA-bypass pattern | Monitored 24/7; separate key per account stored in physical safe |

---

## 6. Passwordless ≠ Password Removed from the Directory 🔑

→ **The trap**: teams deploy WHfB or FIDO2, users stop typing passwords — and assume the password is gone. It is not.

**Going passwordless does not delete the user's password.** In Entra ID — and in hybrid environments — the password remains in the directory. The authentication flow bypasses it, but the password still exists and still has a lifecycle. This distinction has concrete operational consequences that are easy to overlook until they cause incidents.

### What actually happens to the password?

| Scenario | Password status | Risk if ignored |
|---|---|---|
| WHfB or FIDO2 deployed, user authenticates without password daily | Password **still exists** in Entra ID | If it **expires**, fallback flows and legacy auth paths break unexpectedly |
| Hybrid user synced from on-prem AD | On-prem **AD password policy governs expiry** | AD expiry triggers Kerberos failures and sync issues — even if the user has not typed it in months |
| Cloud-only user in full passwordless flow | Entra ID **password policy applies** | Expired password can block legacy auth fallback or trigger a confusing reset prompt |

### The password expiry problem

If you deploy passwordless without adjusting password expiry policies, you will eventually see:

- Users suddenly prompted for a password they have **not typed in months** — and do not remember
- **Helpdesk calls at scale**, disproportionate to any actual security gain
- **Hybrid sync issues or Kerberos failures** triggered by on-prem AD expiry, invisible to the user until something breaks

→ **Microsoft's recommendation for cloud-only accounts** in a full passwordless deployment: set password policies to **Password Never Expires**. The password exists as a silent backstop but is never surfaced to the user. It can be rotated programmatically if required by policy, without the user ever interacting with it.

→ **For hybrid accounts**: coordinate with the AD team. If the user will never be prompted for their on-prem AD password, expiry-driven disruption has **no security value** — it only creates operational noise. Use **Fine-Grained Password Policies (FGPPs)** to carve out passwordless populations from the standard expiry cycle.

### Practical checklist for passwordless deployments

- 🔍 **Audit** current password expiry policies *before* rolling out passwordless at scale
- ☁️ **Cloud-only users**: plan the switch to **Password Never Expires** once passwordless enrollment is confirmed
- 🏢 **Hybrid users**: work with the AD team on **Fine-Grained Password Policies** for passwordless populations
- 🆘 **Document and test the fallback path** — what happens when WHfB or FIDO2 is unavailable?
- 🔄 **Use TAP** as the recovery method, not the old password
- 📋 **Communicate to users**: they may still have a password in the system, but it is no longer their authentication method

---

## 7. Entra ID implementation checklist ✅

Use this checklist as a starting framework for any authentication modernization project. Items are ordered by phase, not by priority — all of them matter.

### 🏗️ Phase 1 — Foundation

- [ ] **Migrate** to the unified Authentication Methods policy (legacy MFA/SSPR per-user settings fully disabled)
- [ ] **Audit** currently enabled methods and remove anything not explicitly justified
- [ ] **Define Authentication Strength tiers**: at minimum, one for general MFA (AAL2) and one for phishing-resistant (AAL3)
- [ ] **Protect MFA and device registration** with Conditional Access (registration should never be uncontrolled)

### 🔐 Phase 2 — Method deployment

- [ ] **Enforce AAL3** immediately on admin portals, PIM activation, and high-impact applications
- [ ] **Deploy WHfB** on all Intune-managed Windows endpoints with TPM enforcement
- [ ] **Deploy FIDO2/Passkeys** for admin populations and cross-platform/non-Windows use cases
- [ ] **Enable Authenticator push (number matching)** as the AAL2 baseline for general populations — with a dated migration plan to AAL3
- [ ] **Disable SMS/Voice** by default — no exception without formal justification and CISO-level approval
- [ ] **Configure TAP** with short validity, restricted issuance rights, and documented recovery process

### 🏛️ Phase 3 — Governance

- [ ] **Map Authentication Strengths** to every Conditional Access policy explicitly — no implicit "require MFA"
- [ ] **Bind device compliance** requirements alongside method strength in policies (Trusted Signal model)
- [ ] **Adjust password expiry policies** for passwordless populations (cloud: Password Never Expires; hybrid: FGPP)
- [ ] **Define and test break-glass accounts**: FIDO2 hardware key, monitored, stored securely
- [ ] **Document exception process**: any non-AAL3 method must have a named owner and retirement date

### 📈 Phase 4 — Monitoring and continuous improvement

- [ ] **Monitor sign-in logs** for authentication method distribution and drift
- [ ] **Track registration health** (users enrolled in strong vs weak methods)
- [ ] **Alert on legacy auth attempts** and review periodically
- [ ] **Review exceptions quarterly**: any AAL2 or lower scope still active must be re-justified or closed

---

## 8. Conclusion 🎯

Not all MFA is equal. Two users can both pass MFA and sit in completely different risk tiers. That gap is not a configuration mistake — it is a **design choice** that needs to be made explicitly.

The shift this guide is pushing for:

| From | To |
|---|---|
| "Require MFA" as a single checkbox | **Authentication Strength** bound to each access scenario |
| MFA deployed, job done | **AAL3 as default target**, weaker methods as temporary transitions |
| Identity policy disconnected from device posture | **Trusted Signals**: user + method + device + context evaluated together |
| Passwordless = passwords removed | **Passwordless = passwords bypassed** — lifecycle still needs governance |

→ **One practical north star:**

- **Target phishing-resistant (AAL3) by default** — for all populations, not just admins
- **Keep weaker methods as controlled exceptions** with named owners and exit dates
- **Treat onboarding and recovery as first-class security operations** — not an afterthought

That is where Entra ID moves from checkbox MFA to **production-grade strong authentication**. 🛡️

# Strong Authentication Methods in Entra ID
**Practical guide: what to choose, why, and when (without marketing fluff) 🔐**
Published: 2026-05-04

---

## TL;DR ⚡ (for busy admins)

Short version you can use in a client discussion:

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

Good start. Wrong finish line.

In Entra ID, two users can both "pass MFA" and still be in totally different risk leagues:

- User A signs in with WHfB or FIDO2 (phishing-resistant) 🛡️
- User B signs in with SMS OTP (interceptable, weaker) ⚠️

=> Same MFA checkbox, different blast radius.

So a strong authentication strategy should always answer 4 questions:

- Which method is allowed?
- For which population?
- For which app or sensitive action?
- Under which context/risk signals?

If those 4 are explicit, decisions get faster, policies get cleaner, and exceptions stop multiplying like gremlins after midnight.

### Stakeholder takeaway 🎯

- Do not stop at: "Do we have MFA?"
- Move to: "Which MFA strength do we enforce for which business risk?"

That is the shift from checkbox security to decision-grade security. Section 1.1 shows how Entra ID implements this with Authentication Strengths and AAL mapping.

---

### 1.1 Authentication Strength, Phishing-Resistant MFA, and AAL3 🏛️

Core idea: authentication strength is a **policy dial**, not a buzzword.

When Entra ID says "phishing-resistant MFA", it means a specific enforceable level: **Authentication Strength** in Conditional Access.

Why this is a big deal in real life:

- One generic MFA baseline for all apps means high-value workloads inherit low-value protection
- If privileged identities are not forced to phishing-resistant methods, one successful phishing attempt can escalate fast
- If strength is not explicit in policy, exceptions grow quietly until they become the default

Authentication Strength fixes this by binding accepted method families to each scenario. Microsoft provides three built-in levels:

| Strength | What it requires |
|---|---|
| Multifactor authentication | Any MFA combination, including SMS + password |
| Passwordless MFA | Passwordless methods such as WHfB, FIDO2, and certificate-based options |
| Phishing-resistant MFA | FIDO2, WHfB, or CBA only — no replayable shared secret |

This is where architecture becomes governance:

- Admin portals and privileged operations: enforce phishing-resistant MFA
- Standard internal apps: allow strong mainstream methods where justified
- Legacy/transitional scenarios: allow narrower exceptions with expiration and review

Much stronger than one global "require MFA" toggle everywhere.

**Where does AAL3 fit?**

AAL (Authenticator Assurance Level) comes from **NIST SP 800-63B** and is common in audits and regulated programs:

| Level | Description | Typical methods |
|---|---|---|
| AAL1 | Single factor, minimal assurance | Password alone |
| AAL2 | MFA, moderate assurance | Authenticator push, TOTP + password |
| AAL3 | Hardware-bound, phishing-resistant authenticator | FIDO2, WHfB with TPM, smartcard/CBA |

Quick translation 🔄

- "Phishing-resistant MFA" in Microsoft language and "AAL3" in compliance language point to the same security objective
- You can discuss architecture with IT teams and still answer audit/compliance questions without changing strategy

Boss-level recommendation 🕹️

- Use **Authentication Strength** in every critical Conditional Access policy
- Reserve phishing-resistant / AAL3 for privileged access, sensitive data, and high-impact business applications
- Treat weaker methods as controlled transition paths, not permanent endpoints

---

## 2. Quick comparison table 📊

| Method | Quick score | Phishing resistance level | User experience | Prerequisites | Pros | Cons | Best use case |
|---|---|---|---|---|---|---|---|
| FIDO2 Security Keys / Passkeys | ⭐⭐⭐⭐⭐ | 🟢 Very high (5/5) | Fast (tap + PIN/biometric) | Compatible key, modern browser/OS, FIDO2 policy | Very strong, no shared secret, great for admins | Hardware cost, key logistics, loss/replacement handling | Admins, privileged access, high-risk environments |
| Windows Hello for Business (WHfB) | ⭐⭐⭐⭐⭐ | 🟢 Very high (5/5) | Excellent on managed endpoints | Compliant/joined device, TPM recommended, Intune/GPO config | Passwordless, excellent UX, device-bound credential | Depends on device posture, broader rollout effort | Internal users on company-managed devices |
| Certificate-Based Authentication (CBA) | ⭐⭐⭐⭐ | 🟢 High to very high (4-5/5) | Varies by setup | PKI, user certificates, cert lifecycle processes | Robust, compliance-friendly in regulated sectors | PKI complexity, heavier operations | Regulated environments, smartcard/CAC scenarios |
| Microsoft Authenticator push (number matching) | ⭐⭐⭐⭐ | 🟡 Medium to high (3-4/5) | Very good for most users | Smartphone, Authenticator app, proper policy tuning | Easy to deploy, fast adoption, strong balance | MFA fatigue risk if misconfigured, mobile dependency | Large user populations, practical MFA baseline |
| Microsoft Authenticator phone sign-in (passwordless) | ⭐⭐⭐⭐ | 🟡 Medium to high (3-4/5) | Good | Smartphone, Authenticator app, phone sign-in enabled, user registration completed | Passwordless user flow, reduced password exposure, familiar mobile UX | Device dependency, recovery process required if phone is lost | Passwordless transition for non-privileged populations |
| OATH TOTP (app/hardware token) | ⭐⭐⭐ | 🟠 Medium (3/5) | Good | TOTP app or hardware token, enrollment | Works offline, simple fallback | Phishable, more friction, reset overhead | Backup method, users with limited mobile data |
| Temporary Access Pass (TAP) | ⭐⭐⭐ | 🔵 Context-dependent (temporary method) | Good for onboarding | TAP policy enabled, HR/IT process | Great for passwordless bootstrap and recovery | Temporary by design, risky if validity window is too broad | Onboarding, break-fix, secure reset |
| SMS / Voice OTP | ⭐⭐ | 🔴 Low to medium (2/5) | Familiar but fragile | Valid phone number, telecom availability | Maximum compatibility | SIM swap risk, interception risk, lower trust level | Temporary fallback only |

---

## 2.1 Strength ladder at a glance 🪜

| Tier | Methods | Phishing-resistant | NIST level | Recommended scope |
|---|---|---|---|---|
| 🟢 **Phishing-resistant** | FIDO2 / Passkeys, WHfB, CBA | ✅ Yes | AAL3 | Admins, privileged access, sensitive workloads |
| 🔵 **Strong mainstream (MFA)** | Microsoft Authenticator push (number matching) | ⚠️ Partial | AAL2 | Large user populations, phased modernization |
| 🟦 **Strong mainstream (passwordless app)** | Microsoft Authenticator phone sign-in | ⚠️ Partial | AAL2 | Passwordless transition when FIDO2/WHfB is not yet generalized |
| 🟡 **Backup** | OATH TOTP (app or hardware token) | ❌ No | AAL2 | Constrained environments, fallback only |
| 🟣 **Temporary bootstrap** | Temporary Access Pass (TAP) | — Contextual | — | Onboarding, recovery — never permanent |
| 🔴 **Legacy fallback** | SMS / Voice OTP | ❌ No | AAL1 | Emergency fallback, tightly scoped, with an exit plan |

Rule of thumb: the more sensitive the resource or the more privileged the user, the higher the required tier. Lower tiers should have an explicit justification and a migration-off plan — not a permanent home.

---

## 3. Method-by-method details (field reality edition) 🎮

### 3.1 FIDO2 Security Keys and Passkeys

Quick take: best-in-class for high-value access and admin scenarios.

#### ✅ Why it is great

- Native phishing resistance 🛡️
- No password entry
- Excellent for privileged accounts

#### ⚠️ Watch-outs

- Physical key lifecycle management (stock, loss, replacement)
- Requires a clean backup and recovery process

#### 🎯 Best fit

- Admin, IT, and SecOps teams
- Admin portals, PIM activation, critical consoles

---

### 3.2 Windows Hello for Business (WHfB)

Quick take: top-tier security with excellent daily UX on managed devices.

#### ✅ Why it is great

- Excellent user comfort (local PIN/biometric)
- Credential is bound to the device
- Strong resistance against common credential attacks

#### ⚠️ Watch-outs

- Requires serious device hygiene
- More of a structured program than "just enable MFA"

#### 🎯 Best fit

- Internal users on managed laptops
- Long-term passwordless strategy

#### 🔬 Focus: TPM + PIN + Biometrics — do all three factors really apply?

This is a recurring question and the answer requires unpacking how WHfB actually works under the hood.

**The three factor types in identity security:**

| Factor type | Description | In WHfB |
|---|---|---|
| Something you **have** | A physical object | TPM chip (hardware-bound private key) |
| Something you **know** | A secret you memorize | PIN (local only, never transmitted to any server) |
| Something you **are** | A biological trait | Fingerprint or facial recognition (biometrics) |

**How WHfB actually uses them:**

WHfB generates a key pair directly inside the TPM. The private key never leaves the chip — not during sign-in, not during token issuance, never. To unlock that key, the user provides a local verification: either a PIN or biometrics. These are local gestures, not credentials in flight.

Important nuance: **PIN and biometrics are alternative unlock methods, not stacked steps**. The user either enters a PIN or scans a fingerprint — both unlock the same TPM-protected key. They are not performed simultaneously.

**So does WHfB achieve "three-factor" authentication?**

The answer is: yes, by design — but not in the way most people picture it.

- **TPM (have)** is always active: the credential is device-bound and hardware-protected, regardless of how the user unlocks it.
- **PIN (know)** or **biometrics (are)** is the active second gate at unlock time.
- When biometrics is enabled, the combination is **have (TPM) + are (biometrics)**, with PIN as a fallback that brings in the **know** dimension when biometrics are unavailable.

All three factor types are present in the architecture. What does not happen is three sequential verification steps — it is one fluid gesture that engages two or three factor types simultaneously depending on the unlock method used.

**Can you configure and enforce TPM + PIN + biometrics together in WHfB?**

Yes, and this is the recommended production setup:

- **TPM requirement**: enforced via Intune device configuration profile or GPO — ensures the credential is hardware-bound.
- **PIN complexity**: enforced via Windows Hello for Business policy — minimum length, complexity rules, expiry if required.
- **Biometrics**: enabled via policy as a companion unlock method alongside PIN.

The result in practice: a user on a TPM-equipped Intune-managed device who authenticates via facial recognition is satisfying all three factor types without a single extra step. For them it is "look at the laptop". For your security posture it is a hardware-bound, phishing-resistant, AAL3-grade credential with no password in flight, no OTP code, and no secret that can be stolen remotely.

This is precisely what separates WHfB from traditional MFA: the security depth is embedded in the architecture, not added as an extra prompt.

---

### 3.3 Certificate-Based Authentication (CBA)

Quick take: extremely strong if your PKI game is mature.

#### ✅ Why it is great

- Very strong when PKI is mature
- Good fit for compliance-heavy requirements

#### ⚠️ Watch-outs

- PKI means operations, procedures, lifecycle, support
- Poor PKI design quickly becomes technical debt

#### 🎯 Best fit

- Regulated sectors, smartcards, legacy federation contexts

---

### 3.4 Microsoft Authenticator push (number matching)

Quick take: the practical default for large populations and phased modernization.

#### ✅ Why it is great

- Strong security/UX balance
- Fast user adoption
- Works well in phased migrations

#### ⚠️ Watch-outs

- Can suffer from MFA fatigue if policies are too permissive
- Dependency on personal or corporate smartphones

#### 🎯 Best fit

- Large user base
- Transitional phase before phishing-resistant by default

---

### 3.5 Microsoft Authenticator phone sign-in (passwordless)

Quick take: a practical passwordless option for users not yet on WHfB/FIDO2, but not equivalent to phishing-resistant methods.

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

---

### 3.6 OATH TOTP (third-party apps or hardware token)

Quick take: useful backup path, but not where you want to stop.

#### ✅ Why it is useful

- Works even without mobile data
- Simple alternative in constrained environments

#### ⚠️ Watch-outs

- More phishing-vulnerable (replayable code in a time window)
- Less fluid UX than push/passkeys

#### 🎯 Best fit

- Backup method
- Specific cases without push notification support

---

### 3.7 Temporary Access Pass (TAP)

Quick take: fantastic bootstrap tool, risky if governance is loose.

#### ✅ Why it is excellent

- Ideal bootstrap to move users into passwordless flows 🚀
- Supports recovery without bypassing security controls

#### ⚠️ Watch-outs

- If validity is too long, risk surface grows unnecessarily
- Requires strict governance

#### 🎯 Best fit

- Day-one onboarding
- Controlled recovery (support + identity verification)

---

### 3.8 SMS and Voice OTP

Quick take: keep only as a tightly controlled emergency fallback.

#### ✅ Why it still exists

- Nearly universal reach
- Very easy to explain to users

#### ⚠️ Watch-outs

- Weaker security compared to modern methods ⚠️
- Vulnerable to SIM swap and telecom attacks

#### 🎯 Best fit

- Temporary fallback, tightly scoped, with a migration-off plan

---

## 4. How to choose without regretting it in 6 months 🧭

Use this simple rule:

- The more sensitive the resource, the more phishing-resistant the method must be.
- The more privileged the user, the rarer the exception should be.
- The weaker the method, the smaller and more temporary its scope should be.

A fourth dimension often overlooked: **device posture as a Trusted Signal**. In a mature Conditional Access design, trust is not just placed in what the user knows or has — it is also placed in the device they are using, its compliance state, and the context of the access request. A phishing-resistant method on an unmanaged device is stronger than SMS, but weaker than the same method on a TPM-equipped, Intune-compliant device. This compound evaluation — user + method + device + context — is what Conditional Access Trusted Signals enable. See section 6 for the full treatment.

### Pragmatic rollout order

1. Enable and enforce Microsoft Authenticator (number matching, consistent geo controls when relevant).
2. Deploy WHfB for managed internal devices.
3. Target FIDO2/Passkeys for admins and high-risk populations.
4. Keep TOTP as a limited backup.
5. Reduce SMS/Voice to strict minimum.
6. Use TAP for onboarding/recovery, never as a permanent method.

Bonus reality check: if your strongest method is optional, users will discover the weakest one in record time.

---

## 5. Example matrix: method by population 👥

| Population | Primary method | Secondary method | Avoid |
|---|---|---|---|
| Cloud/tenant admins | FIDO2 or WHfB | Authenticator push | SMS/Voice |
| Internal managed users | WHfB | Authenticator push | SMS as default method |
| External users/B2B | Based on cross-tenant trust + Authentication Strength | Authenticator/TOTP based on partner policy | Untracked exceptions |
| Field teams without corporate smartphone | Hardware TOTP or FIDO2 | TAP for recovery | Full dependency on SMS |

---

## 6. Passwordless ≠ Password Removed from the Directory 🔑

One of the most persistent misconceptions in passwordless deployments: **going passwordless does not delete the user's password**.

In Entra ID — and in hybrid environments — the password remains in the directory. What changes is that the user no longer needs it to authenticate. The authentication flow bypasses the password entirely. But the password still exists, and this distinction has concrete operational consequences that are easy to overlook until they cause incidents.

### What actually happens to the password?

| Scenario | Password status | Risk if ignored |
|---|---|---|
| WHfB or FIDO2 deployed, user authenticates daily without password | Password still exists in Entra ID | If it expires, fallback flows and legacy protocol fallbacks break unexpectedly |
| Hybrid user synced from on-prem AD | On-prem AD password policy governs expiry | AD password expiry triggers Kerberos issues and sync disruptions even if the user has not typed it in months |
| Cloud-only user in full passwordless flow | Entra ID password policy applies | An expired password can block legacy auth fallback or generate a confusing reset prompt |

### The password expiry problem

If you deploy passwordless without adjusting password expiry policies, you will eventually see:

- Users suddenly prompted for a password they have not typed in months — and do not remember
- Helpdesk calls at scale, disproportionate to any actual security gain
- Hybrid sync issues or Kerberos ticket failures triggered by on-prem AD password expiry, invisible to the user until something breaks

**Microsoft's recommendation for cloud-only accounts in a full passwordless deployment**: set password policies to **Password Never Expires**. The password exists as a silent backstop but is never surfaced to the user. It can be rotated programmatically if required by policy, without the user ever interacting with it.

**For hybrid accounts**: coordinate with the AD team. If the user will never be prompted for their on-prem AD password, expiry-driven disruption has no security value and only creates operational noise. Use Fine-Grained Password Policies (FGPPs) to carve out passwordless populations from the standard expiry cycle.

### Trusted Signal: why device posture matters here too

This connects to the **Trusted Signal** concept in Conditional Access. In a passwordless design, the trust is no longer placed in a secret the user knows — it is placed in the combination of:

- **The device** (compliant, Intune-managed, TPM-protected)
- **The authentication method** (WHfB, FIDO2)
- **The contextual signals** (location, risk score, session characteristics)

A Conditional Access policy that enforces phishing-resistant MFA and requires a compliant device is not just checking "did the user prove identity" — it is checking "did the right user, on the right device, in the right context, use the right method". That is the Trusted Signal model: authentication is no longer a single gate, it is a compound signal evaluated at every access request.

### Practical checklist for passwordless deployments

- 🔍 Audit current password expiry policies **before** rolling out passwordless at scale
- ☁️ Cloud-only users: plan the switch to **Password Never Expires** once passwordless enrollment is confirmed and validated
- 🏢 Hybrid users: work with the AD team on Fine-Grained Password Policies for passwordless populations
- 🆘 Document and test the fallback path — what happens when WHfB or FIDO2 is unavailable?
- 🔄 Use TAP as the recovery method, not the old password
- 📋 Communicate clearly to users: they may still have a password in the system, but it is no longer their authentication method

---

## 7. Entra ID implementation checklist ✅

- 🔄 Verify Authentication Methods migration status is fully modern and complete
- 🧹 Clean up remaining legacy MFA options
- 🧱 Define clear Authentication Strengths (standard vs phishing-resistant)
- 🔗 Map the right strengths to the right Conditional Access policies
- 🛡️ Protect sensitive user actions (MFA registration, device registration)
- 🆘 Define a recovery process (TAP, identity verification, time limits)
- 🚨 Implement tightly controlled break-glass exclusions
- 📈 Monitor sign-in logs and authentication method changes

---

## 8. Conclusion 🎯

Not all MFA methods are equal. The real question is not "MFA enabled: yes/no". The real question is:

- which method,
- for which population,
- in which context,
- with which governance model.

If you want one practical north star:

- target phishing-resistant by default,
- keep weaker methods as exceptions,
- treat onboarding/recovery as first-class security operations.

That is where Entra ID moves from checkbox MFA to production-grade strong authentication. 🎯

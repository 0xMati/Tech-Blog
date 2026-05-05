# Strong Authentication Methods in Entra ID
**Practical guide: what to choose, why, and when (without marketing fluff) 🔐**
Published: 2026-05-04

---

## TL;DR ⚡ (for busy admins)

Short version you can use in a client discussion:

- 🛡️ **Priority 1: Phishing-resistant MFA**
	- FIDO2/Passkeys
	- Windows Hello for Business
	- Certificate-Based Authentication (CBA)
	- Security level: **AAL3**

- 📲 **Priority 2: Microsoft Authenticator push**
	- Require number matching
	- Security level: **AAL2** (good mainstream default)

- 🔢 **Priority 3: OATH TOTP**
	- Useful fallback when needed
	- Security level: **AAL2** (more phishable than push/passwordless)

- ⚠️ **SMS/Voice should stay exceptional**
	- Security level: **AAL1**
	- Keep only as temporary fallback, with an exit plan

- 🚀 **Temporary Access Pass (TAP)**
	- Great for onboarding and account recovery
	- Not a daily sign-in method

- 🔧 **Design lever to insist on**
	- Use **Authentication Strength** in Conditional Access
	- "Require MFA" alone is not precise enough

- 🔑 **Passwordless key message**
	- Passwordless does not delete the password in the directory
	- Password expiry policies must be aligned to avoid incidents

---

## 1. What is a strong authentication method in Entra ID? 🧠

In Entra ID, MFA is often discussed as a simple yes/no checkbox. In reality, not all MFA methods are equal.

Two users can both be "doing MFA", but:

- one uses a phishing-resistant FIDO2 key,
- the other uses an SMS code that can be intercepted.

Both are technically MFA. Security-wise, they are not the same game.

Think of it like gaming gear: both setups can "run the game", but one is ultra settings at 120 FPS and the other is lagging at 18 FPS.

The goal of a solid Entra ID design is to:

- allow the right methods (Authentication Methods Policy),
- enforce the right strength by context (Authentication Strengths + Conditional Access),
- keep user experience practical so the helpdesk does not turn into a crisis hotline.

Quick takeaway: strong auth is not about adding more prompts, it is about using the right method for the right risk.

---

### 1.1 Authentication Strength, Phishing-Resistant MFA, and AAL3 🏛️

When Entra ID talks about "phishing-resistant MFA", it refers to a specific **Authentication Strength** level you configure in Conditional Access — not just a toggle on the user account.

**Authentication Strength** is a named policy that defines which authentication method combinations are acceptable to satisfy an access requirement. Microsoft ships three built-in strengths:

| Strength | What it requires |
|---|---|
| Multifactor authentication | Any MFA combination, including SMS + password |
| Passwordless MFA | Passwordless methods: WHfB, FIDO2, certificate |
| Phishing-resistant MFA | FIDO2, WHfB, or CBA only — methods with no shared secret that can be intercepted or replayed |

In Conditional Access, you attach a strength to a policy instead of the generic "require MFA" option. This gives you real precision: an admin portal demands phishing-resistant MFA, a low-risk internal app accepts standard MFA, and the policy enforces that distinction automatically.

**Where does AAL3 fit?**

AAL (Authenticator Assurance Level) comes from the **NIST SP 800-63B** framework — a government-grade identity standard widely referenced in regulated industries and government contracts:

| Level | Description | Typical methods |
|---|---|---|
| AAL1 | Single factor, minimal assurance | Password alone |
| AAL2 | MFA, moderate assurance | Authenticator push, TOTP + password |
| AAL3 | Hardware-bound, phishing-resistant authenticator | FIDO2, WHfB with TPM, smartcard/CBA |

Microsoft's "phishing-resistant MFA" Authentication Strength maps directly to **AAL3**. If a client or auditor references AAL3, they are describing the same control — the terminology simply differs depending on whether the conversation is Microsoft-native or compliance-framework-driven.

Practical rule: in Conditional Access, always use **Authentication Strength** — not just "require MFA" — to enforce the right level for the right resource. Phishing-resistant / AAL3 is the target for privileged access, sensitive data workloads, and high-risk populations.

---

## 2. Quick comparison table 📊

| Method | Quick score | Phishing resistance level | User experience | Prerequisites | Pros | Cons | Best use case |
|---|---|---|---|---|---|---|---|
| FIDO2 Security Keys / Passkeys | ⭐⭐⭐⭐⭐ | 🟢 Very high (5/5) | Fast (tap + PIN/biometric) | Compatible key, modern browser/OS, FIDO2 policy | Very strong, no shared secret, great for admins | Hardware cost, key logistics, loss/replacement handling | Admins, privileged access, high-risk environments |
| Windows Hello for Business (WHfB) | ⭐⭐⭐⭐⭐ | 🟢 Very high (5/5) | Excellent on managed endpoints | Compliant/joined device, TPM recommended, Intune/GPO config | Passwordless, excellent UX, device-bound credential | Depends on device posture, broader rollout effort | Internal users on company-managed devices |
| Certificate-Based Authentication (CBA) | ⭐⭐⭐⭐ | 🟢 High to very high (4-5/5) | Varies by setup | PKI, user certificates, cert lifecycle processes | Robust, compliance-friendly in regulated sectors | PKI complexity, heavier operations | Regulated environments, smartcard/CAC scenarios |
| Microsoft Authenticator (push + number matching) | ⭐⭐⭐⭐ | 🟡 Medium to high (3-4/5) | Very good for most users | Smartphone, Authenticator app, proper policy tuning | Easy to deploy, fast adoption, strong balance | MFA fatigue risk if misconfigured, mobile dependency | Large user populations, transition to passwordless |
| OATH TOTP (app/hardware token) | ⭐⭐⭐ | 🟠 Medium (3/5) | Good | TOTP app or hardware token, enrollment | Works offline, simple fallback | Phishable, more friction, reset overhead | Backup method, users with limited mobile data |
| Temporary Access Pass (TAP) | ⭐⭐⭐ | 🔵 Context-dependent (temporary method) | Good for onboarding | TAP policy enabled, HR/IT process | Great for passwordless bootstrap and recovery | Temporary by design, risky if validity window is too broad | Onboarding, break-fix, secure reset |
| SMS / Voice OTP | ⭐⭐ | 🔴 Low to medium (2/5) | Familiar but fragile | Valid phone number, telecom availability | Maximum compatibility | SIM swap risk, interception risk, lower trust level | Temporary fallback only |

---

## 2.1 Strength ladder at a glance 🪜

| Tier | Methods | Phishing-resistant | NIST level | Recommended scope |
|---|---|---|---|---|
| 🟢 **Phishing-resistant** | FIDO2 / Passkeys, WHfB, CBA | ✅ Yes | AAL3 | Admins, privileged access, sensitive workloads |
| 🔵 **Strong mainstream** | Microsoft Authenticator push (number matching) | ⚠️ Partial | AAL2 | Large user populations, phased modernization |
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

### 3.4 Microsoft Authenticator (push + number matching)

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

### 3.5 OATH TOTP (third-party apps or hardware token)

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

### 3.6 Temporary Access Pass (TAP)

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

### 3.7 SMS and Voice OTP

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

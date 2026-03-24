# Microsoft Authenticator as a FIDO2 Passkey — The End of Phishable MFA

**Your phone is now a security key. Let's talk about what that actually means.**

Published: 2026-03-25

---

## Table of Contents

- [1. The Uncomfortable Truth About Classic MFA](#1-the-uncomfortable-truth-about-classic-mfa)
  - [1.1 Pass-the-Cookie](#11-pass-the-cookie)
  - [1.2 Attacker-in-the-Middle (AiTM)](#12-attacker-in-the-middle-aitm)
  - [1.3 Why Classic MFA Falls Short](#13-why-classic-mfa-falls-short)
- [2. Enter FIDO2 — The Cryptographic Answer to Phishing](#2-enter-fido2--the-cryptographic-answer-to-phishing)
  - [2.1 One Site, One Key Pair](#21-one-site-one-key-pair)
  - [2.2 Origin Binding — The Anti-Phishing Trap](#22-origin-binding--the-anti-phishing-trap)
  - [2.3 Why the Proxy Can't Cheat](#23-why-the-proxy-cant-cheat)
- [3. Authenticator as a FIDO2 Passkey — How It Works](#3-authenticator-as-a-fido2-passkey--how-it-works)
  - [3.1 Local Authentication (On the Phone)](#31-local-authentication-on-the-phone)
  - [3.2 Cross-Device Authentication (Phone to PC)](#32-cross-device-authentication-phone-to-pc)
  - [3.3 The Bluetooth Constraint](#33-the-bluetooth-constraint)
  - [3.4 RDP and Remote Sessions](#34-rdp-and-remote-sessions)
- [4. Authenticator Passkey vs Physical FIDO2 Key vs Classic MFA](#4-authenticator-passkey-vs-physical-fido2-key-vs-classic-mfa)
- [5. Attack Coverage Matrix](#5-attack-coverage-matrix)
- [6. Setting It Up in Entra ID](#6-setting-it-up-in-entra-id)
  - [6.1 Enable FIDO2 Authentication Method](#61-enable-fido2-authentication-method)
  - [6.2 FIDO2 Policy Options Explained](#62-fido2-policy-options-explained)
  - [6.3 User Registration](#63-user-registration)
  - [6.4 Enforce via Conditional Access](#64-enforce-via-conditional-access)
- [7. The Recommended Stack](#7-the-recommended-stack)
- [8. Wrapping Up](#8-wrapping-up)
- [References](#references)

---

# 1. The Uncomfortable Truth About Classic MFA

You've deployed MFA. Push notifications, number matching, maybe even TOTP codes. You're feeling good about it.

Here's the problem: **modern attackers don't try to guess your password anymore. They let you authenticate, and then steal the result.**

Two attack patterns make classic MFA a speed bump rather than a wall.

---

## 1.1 Pass-the-Cookie

The attacker steals the **session cookie** from the victim's browser — through malware, a rogue browser extension, or physical access. They inject it into their own browser and **resume the authenticated session**.

The MFA challenge? Already completed. The cookie *is* the proof that MFA succeeded. The attacker skips the front door entirely.

```
Victim's browser                    Attacker's browser
      |                                    |
  Login + MFA -> Cookie issued             |
      |                                    |
  Cookie stolen --------------------------->
      |                                    |
                                    Inject cookie
                                    -> Full access
                                    (no MFA prompt)
```

---

## 1.2 Attacker-in-the-Middle (AiTM)

This one is nastier. The attacker sets up a **reverse proxy** (tools like Evilginx or Modlishka) that sits between the victim and the real login page. The victim sees a legitimate-looking Microsoft login page, enters their credentials, approves the MFA push — everything looks normal.

Except the proxy is **capturing the session token in real time**, right after MFA validation.

```
Victim             Proxy (evil-login.com)         Microsoft
  |                        |                          |
  |--- Login ------------>|--- Forward -------------->|
  |                        |                          |
  |                        |<--- MFA challenge -------|
  |<-- MFA challenge ------|                          |
  |                        |                          |
  |--- Approve MFA ------->|--- Forward -------------->|
  |                        |                          |
  |                        |<--- Token/Cookie ---------|
  |<-- "You're in!" -------|                          |
  |                        |                          |
  |              Attacker now has the token            |
```

The victim is logged in. The attacker is *also* logged in. From a different machine, a different country.

---

## 1.3 Why Classic MFA Falls Short

The core issue is simple. Classic MFA methods — push notifications, SMS codes, TOTP — are **channel-independent**. They validate that *someone* is trying to log in, but they have **zero awareness of where the login is actually happening**.

| What classic MFA checks | What it doesn't check |
|---|---|
| "Someone is trying to log in — approve?" | Which website is asking |
| A number to match (number matching) | Whether the URL is legitimate or a proxy |
| A one-time code | Whether the response is being intercepted |

The phone says "approve?", the user says "yes", and nobody checks if the door they're opening is the right one.

---

# 2. Enter FIDO2 — The Cryptographic Answer to Phishing

FIDO2 (WebAuthn + CTAP2) takes a fundamentally different approach. Instead of sending a code or tapping "approve", the authenticator **signs a cryptographic challenge** — and that signature is mathematically bound to the website's identity.

No shared secrets. No codes flying over the network. No "approve" button that works regardless of context.

---

## 2.1 One Site, One Key Pair

When you register a FIDO2 credential (whether it's a YubiKey or Authenticator), the device generates a **unique key pair per Relying Party** (i.e., per website/service):

```
Phone / Security Key — Secure Enclave
┌──────────────────────────────────────────────┐
│                                              │
│  login.microsoftonline.com  ->  Key pair A   │
│  github.com                 ->  Key pair B   │
│  google.com                 ->  Key pair C   │
│                                              │
│  Each private key:                           │
│  - Bound to ONE Relying Party ID             │
│  - Can ONLY sign challenges for that RP      │
│  - Can NEVER be exported from hardware       │
└──────────────────────────────────────────────┘
```

- **Private key** stays in the hardware (Secure Enclave on iPhone, TEE/StrongBox on Android, TPM on PC)
- **Public key** is sent to the service (stored in Entra ID for Microsoft)
- Compromising one site reveals nothing about the others — full isolation

---

## 2.2 Origin Binding — The Anti-Phishing Trap

This is the key insight. During authentication, the protocol includes the **origin** (the actual URL in the browser's address bar) in the data that gets signed. The authenticator checks this origin against the Relying Party ID it has on file.

```
Victim             Proxy (evil-login.com)          Microsoft
  |                        |                           |
  |--- Login ------------->|--- Forward --------------->|
  |                        |<--- FIDO2 Challenge -------|
  |<-- Challenge ----------|     "Sign this for         |
  |    (relayed)           |      login.microsoft       |
  |                        |      online.com"           |
  |                        |                           |
  v                        |                           |
Phone (Authenticator)      |                           |
  |                        |                           |
  | Checks origin:         |                           |
  | Browser says: "evil-login.com"                     |
  | Registered RP: "login.microsoftonline.com"         |
  |                        |                           |
  | MISMATCH -> REFUSE     |                           |
  |                        |                           |
  Nothing happens. Attack fails silently.              |
```

The authenticator doesn't ask the user "do you approve?". It checks the math. If the math doesn't work, it refuses. The user can't override this — there's no "approve anyway" button.

---

## 2.3 Why the Proxy Can't Cheat

The attacker is stuck in a trilemma:

| What the proxy tries | What happens |
|---|---|
| Keep its own domain (`evil-login.com`) | Origin mismatch — the key refuses to sign |
| Rewrite the origin to `login.microsoftonline.com` | The signature covers the *real* origin from the browser — forgery is detected |
| Relay the challenge as-is | The browser still uses *its current URL* as origin — which is the proxy domain |

There is no escape. The origin is baked into the cryptographic signature. It can't be faked, rewritten, or stripped without invalidating the entire authentication.

> **Classic MFA**: "Someone is knocking, do you open?"  
> **FIDO2**: "The lock checks the visitor's fingerprint automatically. If it's a stranger, the door doesn't move — even if you wanted it to."

---

# 3. Authenticator as a FIDO2 Passkey — How It Works

Since mid-2023, Microsoft Authenticator can act as a **device-bound passkey** — essentially turning your phone into a FIDO2 security key. Same cryptographic guarantees as a YubiKey, but it lives in your pocket (where your phone already is).

The private key is generated and stored in the phone's **Secure Enclave** (iOS) or **TEE/StrongBox** (Android). It never leaves the hardware. Biometric verification (fingerprint, face) is required to unlock the key for signing.

Two scenarios exist depending on *where* you're logging in.

---

## 3.1 Local Authentication (On the Phone)

When you log in from an app or browser **on the phone itself**, everything stays local:

```
Phone
┌─────────────────────────────────────┐
│                                     │
│  Browser / App                      │
│       |                             │
│       v                             │
│  Authenticator (passkey)            │
│       |                             │
│       v                             │
│  Secure Enclave                     │
│  -> Biometric check (face/finger)   │
│  -> Sign the challenge              │
│       |                             │
│       v                             │
│  Signed response -> Microsoft       │
│                                     │
└─────────────────────────────────────┘
```

No external communication needed. No Bluetooth, no NFC, no USB. The challenge goes in, the signature comes out, all within the same device.

---

## 3.2 Cross-Device Authentication (Phone to PC)

When you log in on a **PC** but your passkey lives on your **phone**, the two devices need to talk. This uses the **CTAP 2.2 hybrid transport** protocol (formerly called caBLE):

```
PC (Edge/Chrome)                         Phone (Authenticator)
       |                                         |
  1. "Sign in with a passkey"                    |
       |                                         |
  2. Displays QR code  ---- scan ------>  3. Scan QR
       |                                         |
       |<--- 4. Bluetooth Low Energy tunnel ---->|
       |         (CTAP 2.2 hybrid)               |
       |                                         |
  5. Challenge sent via BLE  ----------->  6. Biometric verification
       |                                      -> Sign challenge
       |                                         |
       |<------- 7. Signature via BLE ----------|
       |                                         |
  8. Signature sent to Microsoft -> OK           |
```

**Step by step:**
1. The PC browser shows "Sign in with a passkey" and displays a QR code
2. You scan the QR code with your phone's camera
3. The PC and phone establish a **Bluetooth Low Energy** connection
4. The FIDO2 challenge travels over BLE to the phone
5. Authenticator asks for your biometric (fingerprint/face)
6. The Secure Enclave signs the challenge
7. The signature travels back to the PC over BLE
8. The PC forwards it to Microsoft — authentication complete

The QR code is only needed for the **first pairing**. After that, the Bluetooth connection can be established automatically (if both devices remember each other).

---

## 3.3 The Bluetooth Constraint

Here's the catch. Cross-device authentication (PC + phone) **requires Bluetooth Low Energy on both devices**. There is no fallback — no WiFi, no USB cable, no NFC for this scenario.

| Situation | Bluetooth required? |
|---|---|
| Login on the phone itself | **No** — everything is local |
| Login on a PC, passkey on the phone | **Yes** — BLE is the only transport |
| Bluetooth disabled on either device | **Doesn't work** |
| Physical distance > ~10 meters | **Doesn't work** |

This is both a security feature (physical proximity required) and an operational constraint (your phone must be nearby with Bluetooth on).

**For PC-based workflows, this is why Windows Hello for Business is often the better fit** — the passkey lives in the PC's own TPM, so no phone and no Bluetooth are needed.

---

## 3.4 RDP and Remote Sessions

FIDO2 authentication happens at the **browser level on the local machine**. In an RDP session, the browser runs on the remote host — which can't see your phone or your security key.

| Scenario | Works? | Requirement |
|---|---|---|
| RDP + Authenticator passkey (phone) | **No** by default | WebAuthn Redirection (Win 11 22H2+ both sides) |
| RDP + YubiKey USB | **No** by default | WebAuthn Redirection |
| RDP + Windows Hello for Business | **No** by default | Remote Credential Guard |
| Azure Virtual Desktop / Windows 365 | **Yes** | WebAuthn Redirection built-in |
| Direct login (no RDP) | **Yes** | N/A |

**WebAuthn Redirection** (available since Windows 11 22H2) intercepts the FIDO2 challenge on the remote host and redirects it to the local machine where the authenticator actually lives. Both client and host must support it.

For organizations that heavily rely on RDP to manage servers, this is a real planning consideration. Options include:
- Upgrading to Windows 11 22H2+ / Server 2025 for WebAuthn Redirection
- Using Azure Virtual Desktop or Windows 365 (native support)
- Designing CA policies with alternative controls for RDP-heavy admin scenarios (PAW, network restrictions)

---

# 4. Authenticator Passkey vs Physical FIDO2 Key vs Classic MFA

| Criteria | Classic MFA (Push/OTP) | Authenticator Passkey | Physical Key (YubiKey) |
|---|---|---|---|
| **Phishing-resistant** | No | Yes (origin binding) | Yes (origin binding) |
| **Secret leaves the device** | Yes (OTP transmitted) | No (only signature) | No (only signature) |
| **Origin-aware** | No | Yes | Yes |
| **Hardware needed** | Phone (already have it) | Phone (already have it) | Dedicated key ($25-70) |
| **Works on mobile** | Yes | Yes (local) | Yes (NFC) |
| **Works on PC** | Yes | Yes (needs Bluetooth) | Yes (USB/NFC, no BLE) |
| **Works via RDP** | Yes | No (without WebAuthn Redir.) | No (without WebAuthn Redir.) |
| **Can be lost** | Phone loss = problem | Phone loss = problem | Key loss = smaller device |
| **Multi-site isolation** | N/A (same MFA for all) | Yes (1 key pair per site) | Yes (1 key pair per site) |
| **User experience** | Approve push / enter code | Biometric on phone | Touch the key |
| **Backup story** | Easy (re-register phone) | Register a second passkey | Carry a backup key |

**When to use what:**

| Use case | Best option |
|---|---|
| Users on managed PCs (Intune) | **Windows Hello for Business** — passkey in the PC's TPM, no phone needed |
| Users primarily on mobile | **Authenticator passkey** — local, no Bluetooth, seamless |
| Admins, shared machines, break-glass | **YubiKey** (USB/NFC) — hardware you can lock in a safe |
| Unmanaged PCs (BYOD, kiosks) | **Authenticator passkey via BLE** or **YubiKey** |
| All of the above combined | Mix and match — users can register multiple FIDO2 credentials |

---

# 5. Attack Coverage Matrix

This is the table that matters. It shows what each layer of defense actually stops.

| Attack | Classic MFA | Phishing-resistant MFA | + Device Compliance | + Token Protection |
|---|---|---|---|---|
| **Credential phishing** | Stops it | Stops it | — | — |
| **AiTM (reverse proxy)** | **Bypassed** | **Stops it** (origin binding) | Stops it (device claim) | Stops it |
| **Pass-the-Cookie** | **Bypassed** | **Bypassed** | **Stops it** (PRT/device) | **Stops it** (TPM binding) |
| **Token replay** | **Bypassed** | **Bypassed** | **Stops it** | **Stops it** |
| **Session hijacking** | **Bypassed** | **Bypassed** | Partial | **Stops it** |

Key takeaway: **no single layer covers everything**. The full stack is:
1. **Phishing-resistant MFA** — blocks the initial credential theft
2. **Device compliance** — ties tokens to known/managed devices via PRT
3. **Token Protection** — cryptographically binds the token to the device's TPM

Layer 1 alone still leaves you exposed to cookie theft. All three together? The attacker has nothing usable even if they intercept a token.

---

# 6. Setting It Up in Entra ID

## 6.1 Enable FIDO2 Authentication Method

```
Entra ID -> Security -> Authentication methods -> Policies -> FIDO2 Security Key
```

- **Enable**: Yes
- **Target**: Start with a pilot group (e.g., `SG-FIDO2-Pilot`), then expand

---

## 6.2 FIDO2 Policy Options Explained

| Option | Values | What it does | Recommendation |
|---|---|---|---|
| **Allow self-service set up** | Yes / No | **Yes** = users can register their own keys at [mysignins.microsoft.com/security-info](https://mysignins.microsoft.com/security-info). **No** = only admins can register keys for users. | **Yes** — simplifies rollout. Use **Temporary Access Pass** (TAP) so users can bootstrap registration even without an existing MFA method. |
| **Enforce attestation** | Yes / No | **Yes** = Entra ID verifies the key's attestation certificate during registration (proves it's a genuine hardware key from a known manufacturer via FIDO Alliance metadata). If the key can't prove its identity, registration is **rejected**. **No** = any FIDO2-compliant key is accepted, no manufacturer verification. | **Yes** in enterprise — blocks virtual keys and unverified hardware. Test with your specific key models first, as some older keys lack attestation support. |
| **Enforce key restrictions** | Yes / No | **Yes** = enables filtering by **AAGUID** (a unique identifier per key model). Only keys matching the list below are allowed or blocked. **No** = all FIDO2 keys accepted, no model filtering. | **Yes** — control exactly which hardware enters your environment. |
| **Restrict specific keys** | Allow / Block | **Allow** = whitelist mode. Only the AAGUIDs you list are permitted; everything else is blocked. **Block** = blacklist mode. The listed AAGUIDs are blocked; everything else is permitted. | **Allow** (whitelist) — only authorize the models your organization purchased. |
| **Microsoft Authenticator (passkey)** | Enable/Disable | Allows Microsoft Authenticator to act as a device-bound FIDO2 passkey. | **Enable** — gives users a phishing-resistant option without purchasing hardware keys. |

**About AAGUIDs:** Every FIDO2 key model has a unique AAGUID. Examples:

| Key Model | AAGUID |
|---|---|
| YubiKey 5 NFC | `2fc0579f-8113-47ea-b116-bb5a8db9202a` |
| YubiKey 5C NFC | `c5ef55ff-ad9a-4b9f-b580-adebafe026d0` |
| Authenticator (iOS) | `de1e552d-db1d-4423-a619-566b625cdc84` |
| Authenticator (Android) | `90a3ccdf-635c-4729-a248-9b709135078f` |

If you use a whitelist and want Authenticator passkeys to work, you **must** include the Authenticator AAGUIDs in the allowed list.

---

## 6.3 User Registration

Users go to [https://mysignins.microsoft.com/security-info](https://mysignins.microsoft.com/security-info) and:

1. Click **"Add sign-in method"**
2. Select **"Passkey in Microsoft Authenticator"** (or "Security Key" for physical keys)
3. Follow the guided setup — biometric enrollment, key creation
4. Done. The public key is now stored in Entra ID, the private key in the phone's Secure Enclave.

For users who don't yet have any MFA method (chicken-and-egg problem), issue a **Temporary Access Pass**:

```
Entra ID -> Users -> [select user] -> Authentication methods -> Add -> Temporary Access Pass
```

The TAP is a time-limited, one-use code that lets the user register their first FIDO2 credential.

---

## 6.4 Enforce via Conditional Access

```
Entra ID -> Security -> Conditional Access -> New Policy
```

| Setting | Value |
|---|---|
| **Name** | Require Phishing-Resistant MFA |
| **Users** | Start with admin roles, then pilot group, then all users |
| **Cloud apps** | All cloud apps |
| **Grant** | Require authentication strength -> **Phishing-resistant MFA** (built-in) |
| **Session** | Optionally: Sign-in frequency (e.g., 12h) |

The built-in **"Phishing-resistant MFA"** authentication strength only accepts:
- FIDO2 security keys
- Windows Hello for Business
- Certificate-based authentication (CBA)

Classic push MFA, SMS, and TOTP are **excluded**. If a user only has those methods registered, they'll be blocked until they register a phishing-resistant credential.

**Rollout tip**: Use **Report-only mode** first to see how many users would be blocked, then gradually enforce.

---

# 7. The Recommended Stack

There is no single "best" option. The strongest posture combines several layers depending on the device type:

```
┌────────────────────────────────────────────────────────────┐
│                  MANAGED PC (Intune)                       │
│                                                            │
│  Authentication:  Windows Hello for Business               │
│                   (passkey in TPM, face/finger/PIN)        │
│  No phone needed. No Bluetooth. No hardware to carry.      │
├────────────────────────────────────────────────────────────┤
│                  MOBILE (iOS / Android)                     │
│                                                            │
│  Authentication:  Authenticator passkey                    │
│                   (local, Secure Enclave, biometric)       │
│  Everything on-device. Seamless.                           │
├────────────────────────────────────────────────────────────┤
│                  SHARED / BREAK-GLASS / ADMIN              │
│                                                            │
│  Authentication:  YubiKey (USB-A/C, NFC)                   │
│                   Physical key you can lock in a safe.     │
│  No dependency on any phone or PC enrollment.              │
├────────────────────────────────────────────────────────────┤
│                  UNMANAGED PC (BYOD / Kiosk)               │
│                                                            │
│  Authentication:  Authenticator passkey (via BLE)          │
│                   or YubiKey USB                           │
│  BLE requires proximity + Bluetooth on both devices.       │
└────────────────────────────────────────────────────────────┘

           +── Conditional Access ──────────────────+
           |                                        |
           |  Require: Phishing-resistant MFA       |
           |  Require: Compliant device             |
           |  Session:  Token Protection (preview)  |
           |                                        |
           +────────────────────────────────────────+
```

**Why device compliance matters on top of FIDO2:**

Even with phishing-resistant MFA, a stolen session cookie can still be replayed. Device compliance ties the token to the device through the **Primary Refresh Token (PRT)**, which contains a key bound to the device's TPM.

```
Legitimate user                              Attacker
      |                                          |
  Login + FIDO2 MFA                              |
  Device = Entra Joined, compliant               |
  -> PRT issued (key in TPM)                     |
  -> Token contains device claim                 |
      |                                          |
  Cookie stolen  -----------------------------> Replays cookie
      |                                      from different device
      |                                          |
                                         No PRT, no TPM key
                                         Device not compliant
                                         CA blocks access
```

**Token Protection** goes one step further: it cryptographically binds the token to the device's TPM, making a stolen cookie **cryptographically invalid** on any other machine.

---

# 8. Wrapping Up

The shift from classic MFA to phishing-resistant authentication isn't optional anymore. AiTM toolkits are commodity software. Pass-the-cookie is a standard post-exploitation step. If your MFA can be approved from a push notification while a proxy is relaying the session, you don't have MFA — you have a compliance checkbox.

Microsoft Authenticator as a FIDO2 passkey brings hardware-grade security to a device people already carry. It's not the answer to everything (Bluetooth on PC, RDP limitations), but combined with WHfB on managed endpoints and YubiKeys for break-glass, it covers the realistic threat landscape without requiring users to carry yet another device.

**The formula:**

| Layer | What it blocks |
|---|---|
| Phishing-resistant MFA (FIDO2/WHfB) | Credential theft, AiTM proxy |
| Device compliance (PRT) | Cookie replay, token theft from unmanaged devices |
| Token Protection (TPM binding) | Any token used outside the original device |

Three layers. Full coverage. No single point of failure.

---

# References

- [Microsoft — FIDO2 security keys in Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-passwordless#fido2-security-keys)
- [Microsoft — Enable passkeys in Microsoft Authenticator](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-enable-passkey-fido2)
- [Microsoft — Authentication strengths (Conditional Access)](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- [Microsoft — Token protection in Conditional Access](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)
- [Microsoft — WebAuthn Redirection in RDP](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-webauthn-redirection)
- [FIDO Alliance — How FIDO Works](https://fidoalliance.org/how-fido-works/)
- [W3C — Web Authentication (WebAuthn) specification](https://www.w3.org/TR/webauthn-3/)

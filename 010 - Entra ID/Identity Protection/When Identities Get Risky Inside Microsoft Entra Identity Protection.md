---
title: "When Identities Get Risky: Inside Microsoft Entra Identity Protection"
date: 2025-12-13
---

# When Identities Get Risky: Inside Microsoft Entra Identity Protection

## Introduction

Identities are no longer static objects protected by static rules.  
They are continuously evaluated, scored, and challenged based on risk.

Microsoft Entra Identity Protection is often confused with Conditional Access. In reality, they solve two distinct problems:

- **Identity Protection detects and evaluates risk**
- **Conditional Access enforces decisions based on that risk**

This article focuses on what happens *before* access is granted: how identity risks are detected, scored, and exposed — and how those signals feed Conditional Access policies to stop compromised identities in real time.

---

## 1. Overview

Identity has become the primary security control plane. Most modern attacks begin by compromising an identity long before touching any workload.

Microsoft Entra Identity Protection focuses on **detecting identity compromise**, not enforcing access. It continuously evaluates users, sign-ins, and workload identities using behavioral analytics, threat intelligence, and machine learning to assign a **risk level**.

Identity Protection and Conditional Access are designed to work together, but they serve different purposes:

- **Identity Protection** → detection and risk evaluation  
- **Conditional Access** → access enforcement  

### Detection vs Enforcement

```text
┌──────────────────────────┐
│ Identity Activity        │
│ (users, tokens, apps)    │
└─────────────┬────────────┘
              │
              ▼
┌──────────────────────────┐
│ Entra Identity Protection│
│ - Signals                │
│ - ML & heuristics        │
│ - Risk calculation       │
└─────────────┬────────────┘
              │  Risk level
              ▼
┌──────────────────────────┐
│ Conditional Access       │
│ - Allow                  │
│ - Require MFA            │
│ - Force password reset   │
│ - Block                  │
└──────────────────────────┘
```

### Operational Visibility

The Entra Identity Protection dashboard provides a centralized view of identity risk across the tenant, including:

- Key metrics measuring protection effectiveness
- Detected identity attack patterns
- Geographic distribution of risky sign-ins
- Actionable recommendations
- Recent risk-related activity

![](<./assets/When Identities Get Risky Inside Microsoft Entra Identity Protection/2025-12-14-22-17-58.png>)

It is the primary entry point for monitoring and investigation before enforcement or SIEM correlation.

![](<./assets/When Identities Get Risky Inside Microsoft Entra Identity Protection/2025-12-14-22-18-08.png>)

---

## 2. What Do We Mean by "Identity"?

In modern environments, identity is not limited to user accounts.

From an ITDR perspective, an identity represents **any entity that can authenticate, receive permissions, or access resources**.

Identities can be classified along three main dimensions.

### Identity Types

- **Human identities**  
  Employees, partners, guests, and customers.

- **Workload identities**  
  Applications, service principals, managed identities, devices, and automated processes.

- **Identity infrastructure**  
  The underlying systems, configurations, and policies that support identity services, such as directory services, authentication protocols, and trust relationships.

### Identity Locations

Identities can exist across multiple environments:

- **On-premises**  
  Active Directory and on-prem identity infrastructure, monitored for example by Defender for Identity.

- **Cloud**  
  Microsoft Entra ID and cloud-native identity services.

- **Hybrid**  
  Combined on-premises and cloud identity environments with synchronization and trust relationships.

### Identity Providers

Identities are not always managed by a single organization.

They may originate from:
- **Microsoft-managed identity platforms**
- **Third-party identity providers**
- **External organizations in B2B collaboration scenarios**

This distribution of identity ownership is a key challenge addressed by ITDR strategies.

---

## 3. Identity Protection Risk Types

Identity Protection evaluates **probability**, not certainty.  
Risk is contextual and continuously recalculated.

### Risk Types at a Glance

The same identity can have multiple risk “views” depending on *what* is being evaluated (a user, a sign-in, or a workload identity) and *where* enforcement happens.

| Risk type | What it represents | Scope | Persistence | Typical enforcement outcome |
|---|---|---|---|---|
| **Sign-in risk** | “Was this authentication attempt legitimate?” | A single authentication event | No | MFA / Block |
| **User risk** | “Is this user likely compromised?” | The user identity | Yes (until remediated/dismissed) | Password reset / Block |
| **Workload identity risk** | “Is this app/service principal likely compromised?” | Workload identity | Often persistent until action taken | Investigate / rotate credentials / restrict permissions |

> This table is a conceptual mapping. Identity Protection detects and evaluates risk; Conditional Access enforces risk-based decisions.

### User Risk

Probability that a **user identity** has been compromised.

Common signals:
- Leaked credentials
- Suspicious inbox manipulation rules
- Anomalous user behavior
- Token-related anomalies

User risk is **persistent** until remediated or dismissed.

### Sign-in Risk

Probability that a **specific authentication attempt** was not performed by the legitimate user.

Common signals:
- Atypical travel
- Anonymous or malicious IP addresses
- Adversary-in-the-Middle (AiTM) patterns

Sign-in risk is **session-based** and scoped to the authentication event.

### Workload Identity Risk

Probability that an **application or service principal** has been compromised.

Workload identities are particularly risky because they:

- Cannot perform MFA
- Often lack ownership and lifecycle governance
- Rely on long-lived secrets or certificates

Common signals:
- Suspicious service principal behavior
- Leaked secrets or certificates
- Malicious or suspicious applications
- Anomalous access patterns

Workload identity risk is exposed via Microsoft Graph:
- `riskyServicePrincipals`
- `servicePrincipalRiskDetections`

---

## 4. How Risk Signals Work

Risk is never based on a single event. It emerges from **correlated signals evaluated at scale**.

Microsoft processes **trillions of identity-related signals daily** across Entra ID, Defender products, Microsoft accounts, and global threat intelligence.

### Why Scale Matters

A password spray attack illustrates this clearly.

- A single user → looks normal  
- A single IP → looks benign  
- A single sign-in → looks legitimate  

Only when signals are correlated **across users, time, and locations** does the attack become visible.

This is why Identity Protection requires massive telemetry and machine learning.

### Signal Sources

![](<./assets/When Identities Get Risky Inside Microsoft Entra Identity Protection/2025-12-14-22-21-48.png>)

#### Autogenerated (ML-based)
- Atypical travel
- Anonymous IP usage
- Token anomalies
- Suspicious sign-in patterns

#### Expert-Generated
- Known malicious infrastructure
- Nation-state and cybercrime networks

##### Verified Threat Actor IPs

Some expert-generated detections rely on IP addresses that have been **explicitly verified as belonging to known threat actors**.

These detections are calculated **in real time** and are based on intelligence curated by the Microsoft Threat Intelligence Center (MSTIC). They identify sign-in activity originating from IP addresses associated with:

- Nation-state actors
- Organized cybercrime groups
- Known attack infrastructure used in active campaigns

Unlike heuristic or behavioral detections, verified threat actor IPs are **high-confidence indicators**. They do not rely on user history or anomaly scoring, but on confirmed attribution to malicious infrastructure.

When a sign-in originates from such an IP address, Identity Protection can immediately flag the authentication attempt as high risk, allowing Conditional Access policies to respond without delay.

These detections play a critical role in stopping:
- Active intrusion attempts
- Credential validation from known attacker infrastructure
- Ongoing attack campaigns targeting cloud identities

#### End-User Generated
- MFA fraud reports
- User-reported suspicious sign-ins

##### User-Reported Suspicious Activity

Some of the most valuable risk signals come directly from users themselves.

When a user receives an unexpected or suspicious MFA prompt, they can report the attempt as fraud using Microsoft Authenticator or supported phone-based flows. These reports are immediately ingested by Entra Identity Protection as high-confidence signals.

User-reported signals serve two critical purposes:

- **Early detection**  
  A fraudulent MFA prompt often indicates that an attacker already possesses valid credentials. Reporting it allows Identity Protection to flag the sign-in attempt and potentially elevate user risk before access is granted.

- **Human-in-the-loop validation**  
  Unlike automated detections, user reports provide direct confirmation that an authentication attempt was not initiated by the legitimate identity owner. This dramatically increases signal confidence and reduces false positives.

Once reported, these signals contribute to:
- Sign-in risk calculation
- User risk elevation
- Real-time Conditional Access enforcement
- SOC investigation workflows through dashboards, APIs, and SIEM integration

User reporting effectively turns every user into an additional detection sensor, strengthening identity security beyond purely automated analysis.

### Healthy vs Anomalous Sign-in Flows

Risk evaluation is always relative to a baseline.

In a healthy authentication flow:
- Tokens are refreshed frequently (often daily)
- Access patterns are consistent over time
- Users typically access familiar resources in a predictable order (for example: Office services followed by Azure Portal)
- Devices, locations, and clients remain stable

Sign-in anomalies are detected when behavior deviates from this baseline.

#### Sign-in Anomaly Categories (Slide-to-Article Mapping)

| Category | What is being evaluated | Examples (from the slide) | Why it matters |
|---|---|---|---|
| **Location** | Network & geography context | IP address, ASN, country | Stolen creds used from attacker infrastructure or unusual regions |
| **Token lifetime** | Session/token behavior | Unusually old tokens, tokens used out of order | Token replay / session hijack / bypass attempts |
| **Device** | Client context | Different browser/OS, unusual client config | New device risk; potential attacker tooling |
| **Auth failures** | Authentication patterns | Repeated failures, spray/brute-force indicators | Often precedes successful compromise |
| **Resources** | Post-auth target selection | “Should this identity + device + token type access this?” | Suspicious pivot into sensitive admin/data apps |

Individually, these signals may appear benign.  
Correlated together, they significantly increase confidence that a sign-in is not legitimate.

### Endpoint-Originated Signals

Not all identity risks originate from the authentication flow itself.

Endpoint activity can provide strong signals that an identity is already compromised or about to be abused. These signals are correlated with sign-in activity to increase confidence in risk evaluation.

Common endpoint-related risk indicators include:

- **Malware activity**
  - Access to browser cookies or on-device credential stores
  - Token theft and replay techniques
  - Abnormal system behavior linked to credential abuse

- **Phishing activity**
  - Browser access to known malicious or phishing URLs
  - User interaction with credential-harvesting pages
  - Signals correlated with subsequent anomalous sign-ins

- **Suspicious remote access**
  - Unexpected remote sessions
  - Access from unfamiliar networks
  - Activity occurring outside of normal working hours

Individually, these endpoint signals may not trigger immediate enforcement.  
When correlated with identity signals, they significantly increase the probability that an identity has been compromised.

### From Signals to Risk

```text
Raw Signals
   │
   ▼
Correlation (UEBA, heuristics, ML)
   │
   ▼
Risk Classification
(Low / Medium / High)
```

Context such as trusted locations, historical behavior, and device familiarity is applied to reduce noise.

### Post-Authentication Behavior Signals

Identity compromise does not stop at successful authentication.

Once an attacker gains access using a valid identity, post-authentication activity often reveals malicious intent. These behaviors are critical signals for identifying identity abuse beyond the sign-in phase.

Common post-authentication risk indicators include:

- **Reconnaissance**
  - Directory and resource enumeration
  - Discovery of users, roles, services, and permissions
  - Unusual listing or querying patterns across Entra ID and cloud services

- **Exfiltration**
  - Mass access to email, files, or cloud resources
  - Abnormal download or export patterns
  - Data access inconsistent with the user’s role or historical behavior

- **Persistence**
  - Enrollment of new devices
  - Creation of new user or service accounts
  - Configuration changes intended to maintain long-term access

- **Privilege Escalation**
  - Assignment of administrative roles
  - Modification of role memberships
  - Attempts to expand permissions beyond normal scope

Individually, these actions may appear legitimate.  
When correlated with identity, sign-in, and endpoint signals, they significantly increase confidence that an identity is actively being abused.

---

### ML-Based Risk Scoring

Identity Protection evaluates **session risk in real time** by combining:

- User behavior patterns
- Sign-in context (location, device, network)
- Authentication characteristics
- Historical activity
- Threat intelligence

Each sign-in receives a **sign-in risk score**.  
Repeated risky sign-ins can elevate **user risk** over time.

---

### Continuous Learning and Dynamic Weighting

Models continuously evolve using feedback loops and new telemetry.

Signals are **weighted dynamically**:
- Device familiarity
- IP reputation
- Login time patterns
- Application sensitivity

A signal may be low-risk alone but high-risk when combined with others.

This adaptive weighting is what allows Identity Protection to outperform static, rule-based systems.

---

### Named Locations and Noise Reduction

Named locations provide essential context.

Only locations explicitly marked as **trusted** influence risk evaluation:
- Reduce false positives
- Suppress atypical travel alerts
- Increase model confidence

Best practices:
- Corporate office IP ranges
- VPN egress addresses
- Stable geographic regions

Regular review is essential as networks and travel patterns change.

---

### Rule-Based Detections and Risk Simulation

Not all Identity Protection detections rely on machine learning.

Some detections are based on deterministic, rule-based models designed to identify well-known attack patterns with high confidence and low ambiguity. These models use predefined conditions that, when met, immediately indicate suspicious or malicious behavior.

Rule-based detections are especially valuable because they are:
- Easy to understand and explain
- Effective for real-time detection
- Suitable for testing and simulation scenarios

#### Common Rule-Based Detection Examples

- **Anonymous Browsing (Including Tor)**
  - Sign-ins originating from Tor exit nodes or known anonymizing networks
  - These networks are frequently used to obscure attacker location and intent

- **Atypical or Impossible Travel**
  - Logins from geographically distant locations within an unrealistic time window
  - Strong indicator of credential compromise or token replay

- **Leaked Credentials**
  - Authentication attempts using credentials known to be exposed in public breach datasets
  - Often associated with credential stuffing or password reuse attacks

These detections do not depend on historical behavior or statistical models.  
They trigger when known malicious conditions are met.

#### Simulating Risk for Testing and Validation

Administrators may want to simulate identity risk to validate security controls before deploying them in production.

Risk simulation is commonly used to:
- Populate Identity Protection with sample risk events
- Test risk-based Conditional Access policies
- Validate user remediation flows (MFA, password reset, blocking)

Microsoft provides built-in capabilities to simulate certain risk detections for testing purposes, allowing organizations to safely evaluate the impact of their policies without exposing real users to risk.

> Risk simulation is a critical step when designing adaptive access strategies, ensuring that detection, enforcement, and remediation behave as expected.

Reference:  
https://learn.microsoft.com/en-us/entra/id-protection/howto-identity-protection-simulate-risk

---

## 5. Risk-Based Conditional Access

Identity Protection **does not block access**.  
It feeds risk signals into Conditional Access.

### Risk Policy Types

#### Sign-in Risk Policy
- Evaluates a specific authentication attempt
- Typical actions: MFA, block
- Session-scoped

#### User Risk Policy
- Evaluates identity compromise over time
- Typical actions: password reset, block
- Persistent until remediated

Both policies can be combined for layered protection.

Self-Service Password Reset (SSPR) and MFA enable user-driven remediation.  
In hybrid environments, user risk remediation can also be performed through on-premises password changes when Self-Service Password Reset is properly integrated with Active Directory.

It is important to note that Conditional Access decisions differ depending on whether the evaluated signal is a sign-in risk or a user risk.  
Sign-in risk drives session-level controls such as MFA or access blocking, while user risk enables identity-level remediation such as forced password reset.

### MFA Registration as a Prerequisite for Risk-Based Protection

Microsoft Entra Identity Protection includes a dedicated **Multifactor Authentication registration policy** that ensures users are enrolled for MFA before risk-based controls are enforced.

This policy is **not a Conditional Access policy**.  
Its purpose is to **force users to register MFA methods**, not to challenge sign-ins.

When enabled:
- Users are prompted to register MFA methods at their next sign-in
- A 14-day grace period is provided before registration is enforced
- The policy applies across all Entra-integrated applications
- Emergency access (break-glass) accounts must be explicitly excluded

This mechanism ensures that when Identity Protection or Conditional Access requires MFA as a remediation step, users are technically able to respond, preventing enforcement deadlocks and support escalations.

---

## 6. Identity Protection and B2B Users

In B2B scenarios:

- **User risk** is evaluated in the *home tenant*
- **Sign-in risk** is evaluated in the *resource tenant*

Implications:
- Risky guests don’t appear as risky users in the resource tenant
- Resource tenant admins cannot remediate guest user risk
- Guest users must remediate risk in their home tenant

This distinction is critical when designing cross-tenant Conditional Access policies.

Reference:  
Microsoft Entra ID Protection and B2B users - Microsoft Learn

### A Common B2B Pitfall: User Risk Policies

In B2B scenarios, **User Risk policies can easily lead to hard blocks**.

If a guest user triggers a user risk and the policy enforces a password reset:
- The reset must occur in the user’s home tenant
- Resource tenant administrators cannot remediate or dismiss the risk
- If self-service password reset is not available in the home tenant, access remains blocked

For this reason, many organizations avoid applying **User Risk policies** to guest users and instead rely primarily on **Sign-in Risk policies** for B2B access control.

---

## 7. Identity Threat Detection and Response (ITDR)

Identity Protection is a foundational component of **ITDR**.

In the Microsoft ecosystem:
- **Entra Identity Protection** → prevention & risk detection
- **Defender for Identity** → identity attack detection & response
- **XDR** → cross-domain correlation

### Investigation and SIEM Integration

Risk data is available via:
- Entra Identity Protection dashboard
- Microsoft Graph APIs
- Azure Monitor & Microsoft Sentinel
- Third-party SIEMs

### Data Retention and Export

Risk data retention is limited.

For long-term analysis, export via diagnostic settings to:
- Log Analytics
- Azure Event Hub
- Azure Storage

Requires an Azure subscription and appropriate Entra ID permissions.

### Identity Protection APIs: Detection vs State vs Activity

Microsoft Entra Identity Protection exposes risk information through distinct Microsoft Graph endpoints, each serving a different purpose.

- **riskDetections**  
  Provides detailed information about individual risk detections, including the detection type, risk level, and timestamp.  
  This endpoint answers the question: *why was risk detected?*

- **riskyUsers**  
  Represents the current risk state of a user identity.  
  This endpoint answers the question: *is this user currently considered compromised?*

- **signIns**  
  Exposes authentication events enriched with risk information.  
  This endpoint answers the question: *how and under what conditions did the user authenticate?*

These APIs enable security teams to build automated investigation and response workflows, correlating identity risk with endpoint, network, and application signals in SIEM or SOAR platforms.

```text
User
 ├─ Sign-in 1
 │   ├─ Risk detection A
 │   └─ Risk detection B
 └─ Sign-in 2
     ├─ Risk detection C
     └─ Risk detection D
```

---

## 8. Identity Landscapes and Protection Coverage

Identity protection strategies must adapt to the environment where identities live.

Modern organizations operate across multiple identity landscapes, each with different attack surfaces, detection capabilities, and response mechanisms.

### On-Premises

- **Identity system**: Active Directory
- **Primary risks**: credential theft, lateral movement, privilege escalation
- **Detection & response**: Microsoft Defender for Identity

In on-premises environments, identity protection focuses on detecting post-authentication activity and abnormal behavior within the directory and network.

### Cloud

- **Identity system**: Microsoft Entra ID
- **Primary risks**: credential theft, token abuse, phishing, session hijacking
- **Prevention**: Entra Identity Protection + Conditional Access
- **Detection & response**: Identity Protection signals and downstream security tooling

### Hybrid

- **Identity system**: Active Directory + Microsoft Entra ID
- **Attack surface**: authentication flows, synchronization, trust boundaries
- **Prevention**: Entra Identity Protection
- **Detection & response**: Defender for Identity + cloud identity signals

---

## Conclusion

Identity is no longer just an authentication problem.  
It is a continuous risk evaluation process.

Microsoft Entra Identity Protection enables early detection of identity compromise, contextual risk scoring, and adaptive enforcement through Conditional Access.

In modern environments, **identity is the new perimeter** — and risk is the signal that tells you when that perimeter is under attack.


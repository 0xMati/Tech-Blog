# Audit and Enforcement of Kerberos Encryption Type
Published: 2025-12-03

Kerberos hardening got a lot more interesting with KB5021131. On paper, the change is simple: reduce legacy RC4 usage and move the ecosystem toward AES. In practice, it is one of those deceptively clean security stories where the directory can look compliant while the wire still tells a very different story.

That is why this topic matters. You can set a registry value, update a few account attributes, and still watch RC4 tickets being issued in production because an old SPN-bearing account never rotated its secret, a service stayed stuck on legacy crypto, or a client path kept negotiating something weaker than expected. In other words: the config may look sharp, but the packets are still out there doing weird things.

Microsoft reference:
https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d

## Why this topic matters 🔍

Kerberos encryption posture is not just a domain controller setting. It is the combined result of directory configuration, key material, and real ticket issuance.

To know whether you are actually ready for AES-only enforcement, you need to look at three layers together:

1. The KDC default used when an account does not explicitly declare supported encryption types.
2. The encryption capability declared on users, computers, service accounts, and SPN-bearing identities.
3. The encryption type that is actually observed in live 4768 and 4769 traffic.

Miss any one of those, and you can end up with a false sense of security. The directory looks clean, the GPO looks clean, but 4769 is still quietly handing out RC4 service tickets like it is 2012. That is the kind of gap that makes an environment look hardened in PowerPoint and legacy in the Security log.

## Ticket encryption vs session key 🧠

This distinction matters a lot, because many Kerberos discussions casually say “the ticket is RC4” when they really mean “some part of the Kerberos exchange is still using RC4.” Those are related ideas, but they are not exactly the same thing.

At a high level, Kerberos relies on two different cryptographic objects during authentication:

1. The ticket itself
2. The session key carried inside that ticket

### The ticket

The ticket is the blob issued by the KDC for a specific recipient.

- A TGT is intended for the KDC itself later in the flow, so it is encrypted with the long-term key of `krbtgt`.
- A service ticket is intended for the target service, so it is encrypted with the long-term key of the service account or computer account behind the SPN.

That point is critical: the ticket encryption type depends on the long-term key material of the recipient. For a TGS ticket, that means the service-side identity matters directly.

### The session key

The session key is different. It is a temporary symmetric key placed inside the ticket so the client and the service can securely talk to each other during the Kerberos exchange.

It is not just an implementation detail. It is the actual working key used by the client and service once the ticket is presented.

### Why people mix them up

They are tightly linked in practice, so it is easy to blur them together:

- the ticket has its own encryption type
- the session key has its own negotiated outcome
- both are influenced by what the KDC believes the client and target account support

That is why the subject gets confusing fast. A change in account key material can alter the ticket encryption outcome, the session key outcome, or both depending on the scenario.

### Why this matters for this article

This article is about deciding whether you are truly ready to move away from RC4. That requires understanding what exactly your evidence is proving.

If you see RC4 in Kerberos ticket events:

- it usually means the KDC still had a reason to issue a ticket using RC4
- for TGS traffic, that often points straight at the service-side account and its available keys
- it is therefore not just a cosmetic event-log detail, it is often a sign that remediation is incomplete

And this is the important connection to the rest of the article: when we audit `msDS-SupportedEncryptionTypes`, `DefaultDomainSupportedEncTypes`, and live 4768/4769 traffic, we are trying to explain why the KDC made that cryptographic choice.

### The practical consequence

If the target service account only has RC4-usable key material, you will often see RC4 survive where you expected AES. That is exactly why changing an attribute alone is not enough. The secret has to be rotated so usable AES keys actually exist.

Once AES key material exists and the environment is configured correctly, you should expect to see AES dominate both the ticket evidence and the effective session path.

That is why this section is not just theory. It explains why a service account with stale keys can keep your environment on RC4 even when the DCs are patched and the directory settings look modern.

### A concrete example

Take a simple case:

1. A client asks the KDC for a service ticket to access `HTTP/app.mathiasmotron.com`.
2. The KDC resolves that SPN to a service account.
3. That account has either explicit RC4-only configuration, or stale key material that still leaves RC4 as the practical option.
4. The KDC issues a TGS ticket that ends up using RC4.
5. You later see that outcome in 4769 and wonder why RC4 is still alive even though the domain was patched.

That is the exact kind of situation this article is trying to explain.

If you only look at the patch level of the DCs, you miss the service-side dependency.
If you only look at the account attribute, you may miss the fact that the secret was never rotated.
If you only look at the event log, you see the symptom but not the reason.

Put those three together, and the story becomes readable:

- the KDC had to make a choice
- the target account's usable key material constrained that choice
- the event log recorded the result

That is why the article keeps insisting on combining configuration evidence and live ticket evidence. Without both, you are only seeing half of the protocol story.

## What KB5021131 changed ⚙️

KB5021131 changed the default Kerberos behavior so that patched domain controllers prefer AES more aggressively.

The practical impact is this:

- AES is preferred for session keys when supported encryption types are not explicitly defined on the account.
- `DefaultDomainSupportedEncTypes` gives you a way to lock the domain-wide KDC default to AES-only instead of relying on implicit behavior.
- Unset accounts are less likely to drift into RC4 by omission, but that still does not prove your environment is ready for enforcement.

The critical nuance is that the patch does not magically create AES keys for an account that never refreshed its secret after AES support was enabled. That is where many environments get trapped: configuration says one thing, cryptographic reality says another. And Kerberos, as usual, is brutally honest once you start reading the tickets instead of the intent.

## How to think about the problem like an investigator 🕵️

If you want a more useful mental model, stop thinking in terms of a single “Kerberos setting” and start thinking in terms of a decision chain.

When a ticket is issued, three questions matter:

1. What does the client say it can use?
2. What keys does the target account actually have available?
3. What is the KDC allowed or forced to do when it has to choose?

That framing is important because RC4 usually survives for boring reasons, not mysterious ones. A service account never rotated. A machine account is stale. An SPN points to an identity whose attribute changed, but whose usable keys never caught up. Or the KDC is still allowed to make a mixed-mode choice because the default was never fully locked down.

Once you look at the problem that way, the troubleshooting path becomes much cleaner: do not ask “why is Kerberos bad?” Ask “which actor in the ticket path is still introducing legacy crypto?”

## The two controls that matter most 🛠️

### `msDS-SupportedEncryptionTypes`

This is the per-account declaration that tells the KDC what the identity is supposed to support.

That wording matters. The attribute expresses capability and intent, but it is only useful if the underlying key material is consistent with it.

Common values:

- `0x18` = AES128 + AES256
- `0x04` = RC4 only
- `0` or absent = unset, historically ambiguous, now less dangerous after KB5021131 but still not ideal for long-term enforcement

Why it matters for the article:

- this is one of the first places where you can spot obviously weak service identities
- it helps explain why a service ticket was issued in RC4 instead of AES
- it lets you separate explicit weak configuration from implicit or ambiguous configuration

Why it is not enough on its own:

- the attribute can say “AES is supported”
- but if the secret was never rotated after that change, the KDC may still not have usable AES keys for that account

That is why changing the attribute is only half the job. Once you move an account toward AES, the secret also needs to be refreshed so the KDC can actually mint AES keys:

- user or traditional service account: change the password
- computer account: reset the machine password
- gMSA: rotation is automatic

If you skip that step, you have basically repainted the dashboard while the engine still runs on the old parts. The attribute looks modern; the usable keys do not.

This is also why the script does not treat `msDS-SupportedEncryptionTypes` as the final truth. It treats it as one signal that must be compared with live ticket behavior.

### `DefaultDomainSupportedEncTypes`

This is the domain controller registry baseline under:

`HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes`

It defines the default encryption types used when `msDS-SupportedEncryptionTypes` is not set on the account.

In other words, when an account is silent, the KDC still has to choose. This setting influences that choice.

For an AES-only target state, the value you ultimately want is usually:

- `0x18` = AES128 + AES256 only

Why it matters for the article:

- it explains whether the domain is still structurally allowing mixed behavior
- it tells you whether “unset” accounts are being handled under an explicit hardened baseline or a more permissive default
- it helps you distinguish between a service-specific problem and a broader KDC baseline problem

Why it is not enough on its own:

- a strong default does not fix stale service account keys
- a strong default does not prove that live tickets are no longer using RC4
- a missing or mixed default does not automatically mean every ticket will be weak

So this control is important, but it is a baseline control, not proof of outcome. That is why the article keeps pairing it with account posture and real 4768/4769 evidence.

And this is the operational takeaway: set it too early, and you risk breaking services you did not fully understand. Set it too late, and you keep an unnecessary downgrade path alive. The right time to lock it is after the audit tells you the environment is ready.

## Why `0` or absent is still tricky after KB5021131 🧪

This is one of the most misunderstood parts of the story.

After KB5021131, an unset `msDS-SupportedEncryptionTypes` value is less dangerous than it used to be because the KDC is better at preferring AES by default. But “less dangerous” is not the same thing as “proven safe.”

An unset account still leaves you with ambiguity:

- you do not have an explicit declaration of intended encryption capability
- you still need to care about whether usable AES key material actually exists
- you still need live ticket evidence to prove what the KDC is issuing

That is why mature remediation usually aims for explicitness. In a hardened environment, “we think the default should do the right thing” is weaker than “the account explicitly advertises AES and the tickets prove it.”

For a deep-dive review, it helps to separate these three states clearly:

- explicit AES: best state, because intent and capability are aligned
- unset: potentially acceptable temporarily, but operationally ambiguous
- explicit RC4-only: clear remediation target

## Why SPN-bearing accounts are the highest priority 🎯

If you want to know where RC4 is still alive, follow the SPNs.

SPN-bearing accounts drive service ticket encryption. That means they are usually the first place to investigate when 4769 still shows RC4.

Prioritize:

- traditional service accounts
- computer accounts hosting services
- gMSAs and sMSAs
- any account tied to `HTTP/`, `MSSQLSvc/`, `CIFS/`, `LDAP/`, `HOST/`, and similar SPNs

If these identities are still RC4-only, the domain can remain fully operational while silently issuing weak service tickets behind the scenes. That is why service identities are usually the real story, not the easy account inventory summary you get on page one. If you are hunting RC4, the interesting trail usually starts where the SPNs live.

## Reading 4768 and 4769 without getting lost in the weeds 📡

Event 4768 and event 4769 are where the deep dive becomes real.

- 4768 gives you the AS exchange side, which is where you see TGT issuance behavior.
- 4769 gives you the TGS side, which is usually where the useful RC4 hunting happens because it shows service ticket issuance.

Why this matters for the article:

- directory settings tell you what should happen
- event logs tell you what did happen

That difference is the whole point of the audit. Without live events, you can easily mistake declared posture for actual protocol behavior.

In most environments, 4769 is the better place to spend your time first. That is where SPN-backed services show up, and that is where lingering RC4 tends to be tied to a real dependency you can remediate.

Here is the practical reading model:

1. Start with 4769 to find which services are still receiving RC4 tickets.
2. Look at the requestor accounts to understand who was involved in that traffic.
3. Correlate that with the target service account in AD.
4. Compare the observed ticket type with the advertised or configured AES capability.

The useful questions are:

1. Is RC4 showing up mostly in TGTs, TGS tickets, or both?
2. Which requestor accounts are repeatedly associated with RC4?
3. Which target services are repeatedly receiving RC4 TGS tickets?
4. Do the event fields indicate that client, service, and DC all support AES anyway?

That last point matters a lot. If the client advertises AES, the service has AES-capable keys, and the DC also supports AES, but the ticket is still RC4, you are no longer looking at a vague legacy condition. You are looking at a highly actionable inconsistency.

That is exactly why the script highlights avoidable RC4 TGS cases. Those are the tickets that deserve immediate attention because the environment is already close to the correct state.

This is also why the article spends so much time on service accounts and SPNs. 4769 is where those objects stop being abstract directory entries and become observable protocol behavior.

## What usually causes RC4 to survive longer than expected 🧨

In real environments, RC4 tends to persist for a small set of repeat offenders:

- old service accounts whose password has not changed in years
- application identities that were updated in AD but never retested end to end
- machine accounts with stale secrets or edge-case platform behavior
- accounts with SPNs attached where nobody realized ticket encryption was anchored to that identity
- environments that improved defaults but never validated ticket outcomes

None of this is especially glamorous, but that is the point. Kerberos crypto drift is usually operational debt wearing a protocol badge.

## Companion script 🤖

The companion script in this folder consolidates the audit into one PowerShell file:

- [Invoke-KerberosEncryptionAudit.ps1](Invoke-KerberosEncryptionAudit.ps1)

It performs all of the following in one run:

1. Audits `DefaultDomainSupportedEncTypes` on each domain controller.
2. Inventories users, computers, and managed service accounts for `msDS-SupportedEncryptionTypes`.
3. Prioritizes SPN-bearing and service identities that still allow RC4 or do not explicitly declare AES.
4. Collects 4768 and 4769 from domain controllers for a configurable lookback window.
5. Breaks down ticket encryption types across TGT and TGS traffic.
6. Highlights RC4 requestors and RC4 target services.
7. Flags avoidable RC4 TGS events where client, service, and DC all advertised AES capability.
8. Generates a clean HTML report, a JSON report, and optional CSV exports.

The point of the script is not to guess whether your Kerberos posture is healthy. It is to let the directory, the DCs, and the ticket stream answer that question together. Think of it as a reality check for environments that are convinced they are already done with RC4.

In other words, the script is built around correlation. A single data source can be misleading. Registry alone is not enough. Account attributes alone are not enough. Event logs alone are noisy without directory context. Put them together, and the picture gets a lot sharper.

## How to run it

Basic run:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1
```

Run against the last 48 hours and open the report automatically:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -Hours 48 -OpenReport
```

Run with CSV exports:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -Hours 48 -ExportCsv
```

Run against a specific DC subset:

```powershell
.\Invoke-KerberosEncryptionAudit.ps1 -DomainControllers MM-DC1.mathiasmotron.com,MM-DC2.mathiasmotron.com
```

## What the report tells you 📊

The HTML report is built to answer four operational questions quickly.

### 1. Is the KDC default already locked to AES-only?

If not, the report shows which DCs still allow mixed or implicit behavior.

### 2. Which identities still block AES-only enforcement?

The report highlights priority accounts, with emphasis on SPN-bearing identities and service accounts.

### 3. Is RC4 still present in live Kerberos traffic?

The report summarizes ticket encryption for both TGT and TGS events, not just account configuration.

### 4. Is the remaining RC4 avoidable?

The report surfaces RC4 TGS cases where client, service, and domain controller all appear to support AES. Those are often the fastest wins because the protocol path already has the right ingredients and is still making the wrong choice. From an engineering perspective, those are the nicest findings: ugly enough to matter, clean enough to fix.

## A practical deep-dive workflow 🧭

If you want to use the report like an engineer doing triage rather than just reading it top to bottom, this order works well:

1. Check the KDC default section to understand whether mixed behavior is still structurally allowed.
2. Check the priority account list to see which SPN-bearing or service identities still look weak on paper.
3. Check the global ticket breakdown to understand whether RC4 is rare, common, or concentrated.
4. Check the RC4 target services table to find the service-side hotspots.
5. Check the avoidable RC4 cases to identify the shortest remediation path.

That order matters because it moves from control plane to data plane. First: what is allowed. Then: what accounts claim. Then: what the KDC is actually issuing. That sequence keeps the analysis readable and prevents you from drowning in event noise too early.

## Recommended migration path 🚀

Use this order.

1. Audit the KDC default, account posture, and real ticket traffic.
2. Fix SPN-bearing accounts first.
3. Refresh the relevant secrets so AES keys actually exist.
4. Re-run the audit until RC4 is gone or fully understood.
5. Lock `DefaultDomainSupportedEncTypes` to `0x18`.
6. Restrict client Kerberos encryption types to AES128 and AES256 only.

The sequence matters. If you jump straight to enforcement before you have evidence from live tickets, you are not hardening, you are gambling. And Kerberos outages caused by “we thought it was fine” are rarely fun to explain afterward.

## Common mistakes to avoid ⚠️

- Setting `msDS-SupportedEncryptionTypes` without rotating the secret afterward.
- Looking only at account configuration and ignoring 4768 and 4769.
- Treating absent values as fully remediated just because KB5021131 improved the default.
- Enforcing AES-only on the KDC before identifying the SPN-bearing accounts still tied to RC4.

## Practical takeaway ✅

If your goal is to enforce AES-only Kerberos safely, you need evidence from both configuration and live traffic.

That is exactly what the companion script in this folder is built to provide: not a theoretical compliance snapshot, but a technical view of what your KDCs, your identities, and your ticket stream are actually doing. If the goal is AES-only Kerberos without surprises, this is the kind of evidence you want before touching enforcement.

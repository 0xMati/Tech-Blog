# Audit and Enforcement of Kerberos Encryption Type
Published: 2025-12-03

Kerberos hardening got a lot more interesting with KB5021131. On paper, the change is simple: reduce legacy RC4 usage and move the ecosystem toward AES. In practice, it is one of those deceptively clean security stories where the directory can look compliant while the wire still tells a very different story.

That is why this topic matters. You can set a registry value, update a few account attributes, and still watch RC4 tickets being issued in production because an old SPN-bearing account never rotated its secret, a service stayed stuck on legacy crypto, or a client path kept negotiating something weaker than expected.

Microsoft reference:
https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d

## Why this topic matters

Kerberos encryption posture is not just a domain controller setting. It is the combined result of directory configuration, key material, and real ticket issuance.

To know whether you are actually ready for AES-only enforcement, you need to look at three layers together:

1. The KDC default used when an account does not explicitly declare supported encryption types.
2. The encryption capability declared on users, computers, service accounts, and SPN-bearing identities.
3. The encryption type that is actually observed in live 4768 and 4769 traffic.

Miss any one of those, and you can end up with a false sense of security. The directory looks clean, the GPO looks clean, but 4769 is still quietly handing out RC4 service tickets like it is 2012.

## Ticket encryption vs session key

These two concepts are frequently mixed together, and that leads to bad assumptions during remediation.

- A Kerberos ticket is encrypted with the long-term key of the ticket recipient.
  - TGTs are encrypted with the `krbtgt` key.
  - Service tickets are encrypted with the key of the service or computer account.
- The session key is a temporary key carried inside the ticket and used by the client and service during the Kerberos exchange.

In the real world, if the target account only has RC4 material available, you often end up with RC4 for both the ticket and the session path. If AES is available and preferred, you should see AES in the ticket events and in the effective Kerberos flow.

## What KB5021131 changed

KB5021131 changed the default Kerberos behavior so that patched domain controllers prefer AES more aggressively.

The practical impact is this:

- AES is preferred for session keys when supported encryption types are not explicitly defined on the account.
- `DefaultDomainSupportedEncTypes` gives you a way to lock the domain-wide KDC default to AES-only instead of relying on implicit behavior.
- Unset accounts are less likely to drift into RC4 by omission, but that still does not prove your environment is ready for enforcement.

The critical nuance is that the patch does not magically create AES keys for an account that never refreshed its secret after AES support was enabled. That is where many environments get trapped: configuration says one thing, cryptographic reality says another.

## The two controls that matter most

### `msDS-SupportedEncryptionTypes`

This is the per-account declaration that tells the KDC what the identity supports.

Common values:

- `0x18` = AES128 + AES256
- `0x04` = RC4 only
- `0` or absent = unset, historically ambiguous, now less dangerous after KB5021131 but still not ideal for long-term enforcement

Changing this attribute is only half the job. Once you move an account toward AES, the secret also needs to be refreshed so the KDC can actually mint AES keys:

- user or traditional service account: change the password
- computer account: reset the machine password
- gMSA: rotation is automatic

If you skip that step, you have basically repainted the dashboard while the engine still runs on the old parts.

### `DefaultDomainSupportedEncTypes`

This is the domain controller registry baseline under:

`HKLM\SYSTEM\CurrentControlSet\Services\Kdc\DefaultDomainSupportedEncTypes`

It defines the default encryption types used when `msDS-SupportedEncryptionTypes` is not set on the account.

For an AES-only target state, the value you ultimately want is usually:

- `0x18` = AES128 + AES256 only

But that should come after you have audited both directory posture and live Kerberos traffic. Enforcing it too early is how you discover hidden dependencies at exactly the wrong moment.

## Why SPN-bearing accounts are the highest priority

If you want to know where RC4 is still alive, follow the SPNs.

SPN-bearing accounts drive service ticket encryption. That means they are usually the first place to investigate when 4769 still shows RC4.

Prioritize:

- traditional service accounts
- computer accounts hosting services
- gMSAs and sMSAs
- any account tied to `HTTP/`, `MSSQLSvc/`, `CIFS/`, `LDAP/`, `HOST/`, and similar SPNs

If these identities are still RC4-only, the domain can remain fully operational while silently issuing weak service tickets behind the scenes. That is why service identities are usually the real story, not the easy account inventory summary you get on page one.

## Companion script

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

The point of the script is not to guess whether your Kerberos posture is healthy. It is to let the directory, the DCs, and the ticket stream answer that question together.

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

## What the report tells you

The HTML report is built to answer four operational questions quickly.

### 1. Is the KDC default already locked to AES-only?

If not, the report shows which DCs still allow mixed or implicit behavior.

### 2. Which identities still block AES-only enforcement?

The report highlights priority accounts, with emphasis on SPN-bearing identities and service accounts.

### 3. Is RC4 still present in live Kerberos traffic?

The report summarizes ticket encryption for both TGT and TGS events, not just account configuration.

### 4. Is the remaining RC4 avoidable?

The report surfaces RC4 TGS cases where client, service, and domain controller all appear to support AES. Those are often the fastest wins because the protocol path already has the right ingredients and is still making the wrong choice.

## Recommended migration path

Use this order.

1. Audit the KDC default, account posture, and real ticket traffic.
2. Fix SPN-bearing accounts first.
3. Refresh the relevant secrets so AES keys actually exist.
4. Re-run the audit until RC4 is gone or fully understood.
5. Lock `DefaultDomainSupportedEncTypes` to `0x18`.
6. Restrict client Kerberos encryption types to AES128 and AES256 only.

The sequence matters. If you jump straight to enforcement before you have evidence from live tickets, you are not hardening, you are gambling.

## Common mistakes to avoid

- Setting `msDS-SupportedEncryptionTypes` without rotating the secret afterward.
- Looking only at account configuration and ignoring 4768 and 4769.
- Treating absent values as fully remediated just because KB5021131 improved the default.
- Enforcing AES-only on the KDC before identifying the SPN-bearing accounts still tied to RC4.

## Practical takeaway

If your goal is to enforce AES-only Kerberos safely, you need evidence from both configuration and live traffic.

That is exactly what the companion script in this folder is built to provide: not a theoretical compliance snapshot, but a technical view of what your KDCs, your identities, and your ticket stream are actually doing.

# Audit and Enforcement for Kerberos Encryption Type
🗓️ Published: 2025-12-03

**Understand and manage change in cve-2022-37966**
https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d

## Kerberos encryption — what changed and why (KB5021131, CVE-2022-37966)

### Ticket vs. Session key (two different things)
- **Kerberos ticket** (TGT or service ticket): issued by the KDC (domain controller) and **encrypted with the long-term key** of the recipient  
  - TGT → encrypted with the **krbtgt** account key  
  - Service ticket → encrypted with the **service/machine** account key  
  - The Security events **4768/4769** expose the **ticket encryption type** (e.g., AES256, AES128, RC4).
- **Session key**: a **temporary symmetric key** *inside* the ticket, shared between client and service, used to protect the live Kerberos exchanges (AP-REQ/AP-REP, etc.).

> If an account only has RC4 available, you typically end up with **RC4 tickets** and **RC4 session keys**.  
> If the account has AES and the KDC prefers it, you get **AES tickets** and **AES session keys**.

---

### `msDS-SupportedEncryptionTypes` (per-account knob)
This AD attribute tells the KDC which ciphers an individual **account** (user, service, or machine) supports.
- Common values:
  - **24** (`0x18`) = **AES128 + AES256** (target)
  - **0** or **absent** = historically ambiguous (often allowed RC4 in practice)
- **Important**: after changing the attribute to allow AES, you must **refresh the secret** so the KDC can mint AES keys for that account:
  - User/service: change the **password** (and update the app)
  - Machine (`$`): **reset machine password** (e.g., `Reset-ComputerMachinePassword` / `netdom resetpwd`)
  - gMSA: rotates **automatically**

---

### `DefaultDomainSupportedEncTypes` (domain-wide KDC baseline)
This is a **KDC registry setting** that defines the default **encryption types** the KDC assumes for **accounts that do not have** `msDS-SupportedEncryptionTypes` set.  
- Use it to **force AES-only defaults** (e.g., `0x18`) so “unset” accounts don’t silently fall back to RC4.

---

### What KB5021131 changed
Microsoft hardened Kerberos so that environments naturally move away from RC4:
- The KDC **prefers AES** for **session keys** when an account doesn’t explicitly define supported types.
- The new KDC default switch (`DefaultDomainSupportedEncTypes`) lets you **lock** the domain default to **AES-only**, closing the “RC4-by-omission” gap.
- Together, these changes make it easier to converge to **AES-only** for both **ticket encryption** and **session keys**.

---

### Why all of this matters
- **RC4-HMAC** is weaker and enables downgrade/legacy paths.  
- **AES128/256** is the modern baseline. Moving to AES reduces your attack surface and aligns with current security guidance.

---

### How to get to AES-only (practical path)
1. **Fix accounts**: set `msDS-SupportedEncryptionTypes = 24` (AES128+AES256) and **refresh their secret** (password/machine reset; gMSA rotates by itself).  
2. **Harden clients**: GPO **Network security: Configure encryption types allowed for Kerberos** → **allow only AES128/AES256**.  
3. **Lock the default** (optional, recommended): set KDC `DefaultDomainSupportedEncTypes = 0x18` (AES-only) so undefined accounts don’t drift to RC4.  
4. **Validate**: watch Security **4768/4769** → expect **0x12/0x11 (AES256/AES128)** and eliminate **0x17 (RC4)**; your RC4 share should trend to **0%**.

> Tip: A rise in AES in 4768/4769 confirms **ticket** encryption is now AES; because the same capability drives the **session key** choice, you’re also eliminating RC4 from the live session crypto.


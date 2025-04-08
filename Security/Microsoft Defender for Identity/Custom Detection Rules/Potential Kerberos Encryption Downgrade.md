# CDR – Potential Kerberos Encryption Downgrade
🗓️ Published: 2025-02-20

---

## 🧠 MITRE ATT&CK Techniques

- [T1558.003 – Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [T1562.010 – Impair Defenses: Downgrade Attack](https://attack.mitre.org/techniques/T1562/010/)

---

## 💍 Rule Description

Some adversaries may attempt to **downgrade Kerberos encryption algorithms** to exploit **weaker, legacy ciphers**.  
These algorithms are **vulnerable to brute-force attacks**, enabling the attacker to crack credentials and prepare for a **kerberoasting attack**.

This rule surfaces encryption standard changes on **domain-joined devices**. If a supported encryption type is changed to an older or weak algorithm after device deployment, it could indicate malicious intent.

### ⚠️ Known Weak Algorithms

- `des-cbc-crc`
- `des-cbc-md4`
- `des-cbc-md5`
- `des3-cbc-sha1`
- `arcfour-hmac`
- `arcfour-hmac-exp`

---

## ⚠️ Risk Analysis

- **Encryption Downgrade**  
  Enables brute-force attacks on Kerberos tickets and prepares for credential extraction.
- **Stealthy Prep Phase**  
  Attackers may modify encryption before using tools like Rubeus or Impacket.
- **Environment Misconfigurations**  
  Environments that allow older ciphers are at higher risk of being compromised.

---

## ⚙️ Detection Logic (KQL Query)

```kusto
IdentityDirectoryEvents
| where ActionType == "Account Supported Encryption Types changed"
| extend
    ToAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['TO AccountSupportedEncryptionTypes']),
    FromAccountSupportedEncryptionTypes = tostring(parse_json(AdditionalFields).['FROM AccountSupportedEncryptionTypes']),
    TargetDevice = tostring(parse_json(AdditionalFields).['TARGET_OBJECT.DEVICE']),
    ActorDevice = tostring(parse_json(AdditionalFields).['ACTOR.DEVICE'])
| where FromAccountSupportedEncryptionTypes != "N/A"
| project Timestamp, DeviceName, FromAccountSupportedEncryptionTypes, ToAccountSupportedEncryptionTypes, ActorDevice, TargetDevice
```

---

## 🛠️ Recommended Actions

1. **Review Encryption Policies**
   - Ensure allowed encryption types do not include legacy or deprecated algorithms.
2. **Audit Group Policy**
   - Verify domain-wide GPO enforcing modern encryption standards (AES256/AES128).
3. **Investigate Actor Device**
   - Analyze device and user that initiated the change.

---

## 💎 References

- [Microsoft Docs – Configure Encryption Types](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos)
- [Original Detection Rule on GitHub](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Identity/PotentialKerberosEncryptionDowngrade.md)

---

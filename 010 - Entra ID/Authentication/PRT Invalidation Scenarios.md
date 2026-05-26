# 📊 PRT Invalidation Scenarios (Password / WHfB / Certificate)
🗓️ Published: 2025-08-06

## Primary Refresh Token Invalidation by Type

| **PRT Type** | **Specific Invalidation Causes** | **Examples** |
|--------------|----------------------------------|--------------|
| **🔑 Password PRT** | - Password change or reset<br>- Password expiration<br>- Session revocation (*Revoke Sessions*)<br>- Device removed or marked non-compliant<br>- Conditional Access policy change requiring MFA | - User changes password via Outlook Web Access<br>- Admin revokes all sessions from Entra portal<br>- Device marked *Retired* in Intune |
| **🔐 WHfB PRT** | - TPM key reset or deletion<br>- WHfB PIN reset<br>- WHfB disabled or reprovisioned<br>- Session revocation<br>- Device removed or unenrolled | - TPM clear → WHfB keys deleted<br>- User loses PIN and reprovisions WHfB<br>- Device deleted from Entra ID |
| **📜 Certificate PRT** | - Certificate expiration<br>- Certificate revocation by CA<br>- Certificate removed from Windows store<br>- Loss of trust chain<br>- Session revocation<br>- Device removed or reprovisioned | - User certificate not renewed<br>- CA revokes compromised certificate<br>- Root CA removed or expired |

---

## 💡 Common Scenarios for All PRT Types (Always Invalidating)

| **Cause** | **Details** |
|-----------|-------------|
| 🔒 Account disabled or deleted | PRT is no longer valid if the identity is disabled or removed |
| 🧹 Device removal / unenrollment | PRT is tied to an Entra ID-registered device |
| 📵 Device non-compliance (Intune) | If a policy requires compliance, non-compliant devices lose PRT validity |
| ⏱ System clock desynchronization | Large time skew invalidates token signatures and lifetimes |
| ⚠️ Conditional Access policy change | Policy changes (e.g. MFA requirement) may force PRT rejection |

---

✅ **Key takeaway:**  
- **Password PRT** depends on password validity.  
- **WHfB PRT** depends on TPM key integrity.  
- **Certificate PRT** depends on certificate validity and trust chain.

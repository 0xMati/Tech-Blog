# ADCS Web Enrollment Hardening
🗓️ Published: 2026-02-27

## Introduction

Active Directory Certificate Services (AD CS) Web Enrollment (`/certsrv/`) is a legacy component that allows manual certificate enrollment through IIS.

In on-premises environments, this role significantly increases the attack surface if not properly secured. Modern attack techniques such as:

- NTLM Relay  
- PetitPotam  
- PrinterBug / Coercion attacks  
- ESC8 (NTLM Relay to AD CS HTTP endpoint)  

can leverage weak configurations to escalate privileges and compromise the entire domain.

---

## Why Web Enrollment Is Sensitive

The risk is not IIS alone.

The danger appears when:

1. An authentication (NTLM) can be coerced  
2. That authentication can be relayed  
3. AD CS accepts the relayed authentication  
4. A certificate template allows issuance of a usable authentication certificate  

If these conditions are met:

- An attacker can obtain a Domain Controller certificate  
- Request a Kerberos TGT via PKINIT  
- Escalate privileges to Domain Admin  
- Achieve full domain compromise  

AD CS must therefore be treated as Tier 0 infrastructure.

---

## Core Hardening Principles

### 1. Never Install Web Enrollment on a Domain Controller

Web Enrollment must be hosted on a dedicated server, separate from Domain Controllers and ideally separate from the CA itself.

**Reason:**  
Combining DC + IIS + AD CS drastically reduces the attack path complexity.

---

### 2. Enforce HTTPS Only

- Disable HTTP bindings in IIS  
- Use TLS with a valid certificate  
- Do not allow port 80  

**Reason:**  
TLS is required for Channel Binding protection and prevents downgrade attacks.

---

### 3. Enable Extended Protection for Authentication (EPA)

In IIS:

- Windows Authentication → Advanced Settings  
- Extended Protection = **Required**

**Reason:**  
EPA enforces Channel Binding Tokens (CBT), which bind NTLM authentication to the TLS channel.  
Without EPA, NTLM relay to `/certsrv/` remains possible (ESC8).

---

### 4. Restrict or Disable NTLM

Where possible:

- Restrict NTLM via Group Policy  
- Audit NTLM usage before enforcement  

**Reason:**  
NTLM is relayable by design. Reducing NTLM reduces the entire coercion + relay attack surface.

---

### 5. Enforce LDAP and SMB Signing

- Domain Controllers: LDAP Signing = Require  
- SMB Signing = Always  

**Reason:**  
Even if Web Enrollment is protected, attackers may relay authentication to LDAP or SMB instead.  
Defense must be global, not isolated.

---

### 6. Harden Certificate Templates

Review all published templates:

- Remove “Authenticated Users” enrollment rights  
- Disable “Supply in the request” if not required  
- Remove unnecessary EKUs (especially Client Authentication / Any Purpose)  
- Restrict auto-enrollment scope  

**Reason:**  
Most AD CS compromises occur due to misconfigured templates, not IIS itself.

---

### 7. Network Isolation

- Place CA and Web Enrollment in Tier 0 network segment  
- Restrict access via firewall  
- Do not expose broadly to user VLANs  

**Reason:**  
Reduces lateral movement and internal exploitation opportunities.

---

### 8. Monitoring and Detection

Enable auditing and monitor:

- Event ID 4886 / 4887 (Certificate requests / issuance)  
- Event ID 4768 (Kerberos TGT with certificate information)  

**Reason:**  
Certificate-based privilege escalation is often silent unless actively monitored.

---

## Hardening Control Matrix

| Control | Why It Matters | What It Blocks | How to Implement |
|----------|---------------|----------------|------------------|
| Separate CA and Web Enrollment | Prevents direct compromise of the Certification Authority if IIS is exploited | Direct CA compromise via IIS | Deploy CA on dedicated Tier 0 server; host Web Enrollment on separate hardened server |
| Never install Web Enrollment on a Domain Controller | Reduces attack path complexity and eliminates direct DC-to-CA pivot | Direct relay from DC to CA | Verify installed roles; remove ADCS-Web-Enrollment from any DC |
| Enforce HTTPS only | Required for Channel Binding and prevents downgrade attacks | MITM and downgrade scenarios | Remove HTTP bindings in IIS; enforce TLS 1.2+; redirect HTTP to HTTPS |
| Enable EPA (Extended Protection) | Binds NTLM authentication to TLS channel | NTLM Relay to `/certsrv/` (ESC8) | IIS → Windows Authentication → Extended Protection = Required |
| Restrict or disable NTLM | NTLM is relayable by design | NTLM coercion attacks (PetitPotam, PrinterBug) | Configure GPO: Restrict NTLM; audit before enforcement |
| Enforce SMB Signing | Prevents manipulation/relay of SMB sessions | SMB relay and lateral movement | GPO: Digitally sign communications (always) for client & server |
| Enforce LDAP Signing | Prevents relayed authentication to LDAP | SMB→LDAP relay and AD modification | GPO: Domain controller LDAP server signing requirements = Require signing |
| Remove “Authenticated Users” from templates | Prevents broad enrollment abuse | Unauthorized certificate issuance | Modify template security; restrict to controlled security groups |
| Disable “Supply in the request” | Prevents subject impersonation | Identity spoofing via certificate request | Template → Subject Name → Build from AD only |
| Review EKUs (Client Auth / Any Purpose) | Limits authentication-capable certificates | PKINIT abuse and Kerberos escalation | Remove unnecessary EKUs from templates |
| Restrict auto-enrollment scope | Reduces exposure of machine templates | Mass exploitation scenarios | Scope GPO auto-enrollment to specific groups only |
| Network segmentation (Tier 0) | Limits internal attack surface | Lateral movement from user networks | Place CA/IIS in admin VLAN; restrict firewall access |
| Firewall restrictions | Reduces exposure footprint | Unauthorized internal access | Allow only required ports (443) from trusted segments |
| Disable unused EFSRPC exposure | Prevents coercion vectors | PetitPotam NTLM coercion | Apply Microsoft mitigations; restrict RPC where possible |
| Monitor certificate issuance (4886/4887) | Detects suspicious certificate requests | Silent certificate abuse | Enable CA auditing; forward to SIEM |
| Monitor certificate-based logon (4768) | Detects PKINIT-based TGT usage | Stealth privilege escalation | Audit Kerberos events on DCs |
| Treat AD CS as Tier 0 | Aligns governance with risk level | Organizational under-protection | Restrict admin access; use privileged access workstations |
| Validate necessity of Web Enrollment | Avoids unnecessary attack surface | Exposure without business need | If not required, remove ADCS-Web-Enrollment role |

---

## Conclusion

Web Enrollment is not inherently insecure.

However, in a modern threat landscape, it must be:

- Isolated  
- Hardened  
- Monitored  
- Treated as Tier 0  

A misconfigured AD CS Web Enrollment endpoint can lead to full domain compromise in minutes.

Security posture must assume that NTLM coercion techniques will be attempted.
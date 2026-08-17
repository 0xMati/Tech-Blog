---
title: "Windows Security Power-Ups: The Quick Wins That Actually Matter"
date: 2026-08-17
---

# Windows Security Power-Ups: The Quick Wins That Actually Matter

## Maximum armor, minimum drama

Windows hardening does not begin with a 900-page standard and a heroic plan to configure every policy before Friday. It begins by fixing the controls that remove the largest attack paths for the least operational pain.

This is not a sacred Top 10. Security controls do not become better because they fit on a countdown. This is a practical collection of **quick wins**, **audit-first wins**, and **bigger projects** for Windows workstations and member servers.

The goal is simple:

- remove reusable credentials;
- reduce exposed services and legacy protocols;
- protect credentials and data;
- block common attacker behavior;
- make the remaining activity visible;
- prove that every control is really active.

> This guide targets supported Windows clients and member servers. Domain controllers, certification authorities, Exchange servers, failover clusters, and other Tier 0 or application-specific systems require dedicated baselines and compatibility testing. Applying every setting everywhere is not hardening. It is configuration roulette.

---

## The three deployment levels

| Level | Meaning | Deployment rule |
| --- | --- | --- |
| **Level 1 — Equip now** | High value, low complexity, limited compatibility risk | Pilot quickly, validate, then expand |
| **Level 2 — Scan before firing** | Strong control with known application or protocol dependencies | Audit first, remediate dependencies, then enforce |
| **Level 3 — Boss fight** | High-value architectural change | Treat as a project with owners, telemetry, milestones, and rollback |

The level describes deployment complexity, not security value. A Level 3 control can be essential; it simply deserves more engineering than one registry key and optimism.

## Quick map

| Power-up | Level | Main attack path reduced | First proof point |
| --- | --- | --- | --- |
| Windows LAPS | Equip now | Password reuse and lateral movement | Unique, rotating local password is backed up |
| Remove unnecessary local administrators | Equip now | Privilege escalation | Managed local Administrators membership |
| Patch Windows and third-party software | Equip now | Exploitation of known vulnerabilities | Update compliance and enforced deadline |
| Microsoft Defender Antivirus hardening | Equip now | Malware execution and tampering | Real-time, cloud, behavior, and tamper protection active |
| Windows Firewall on every profile | Equip now | Remote exploitation and lateral movement | All profiles enabled; inbound exceptions justified |
| Remove SMBv1 | Equip now | Legacy SMB exploitation and downgrade | SMB1 feature absent and no dependency observed |
| Disable unnecessary Print Spooler | Equip now | Print service exploitation | Service disabled where printing is not required |
| Remove PowerShell 2.0 | Equip now | Downgrade to weak script visibility | Optional feature absent |
| Remove unused software and roles | Equip now | Unnecessary attack surface | Approved software and role inventory |
| Secure Boot and TPM health | Equip now | Boot-chain and offline tampering | Secure Boot on; TPM ready and owned |
| Microsoft Security Baseline | Scan before firing | Configuration drift and insecure defaults | Baseline comparison report |
| Attack Surface Reduction rules | Scan before firing | Office, script, driver, and ransomware tradecraft | Audit telemetry reviewed before Block |
| LSA protection and Credential Guard | Scan before firing | Credential dumping and pass-the-hash | `RunAsPPL` and VBS state verified |
| BitLocker with recovery escrow | Scan before firing | Offline data theft | Encryption complete and recovery key retrievable |
| SMB signing | Scan before firing | SMB relay and traffic tampering | Signing required; incompatible devices identified |
| Disable LLMNR, NetBIOS name resolution, and unused WPAD | Scan before firing | Name-poisoning credential capture | No production dependency; policies enforced |
| Harden RDP and WinRM | Scan before firing | Remote administration abuse | Restricted sources, strong authentication, useful logs |
| Modernize TLS | Scan before firing | Legacy protocol and cipher use | Real handshake proves TLS 1.2 or later |
| Advanced audit policy and centralized logs | Scan before firing | Invisible attacker activity | Critical events arrive centrally with correct timestamps |
| Reduce and remove NTLM | Boss fight | Relay, pass-the-hash, and weak authentication | NTLM audit shows known, shrinking dependencies |
| LDAP signing and channel binding | Boss fight | LDAP relay and tampering | DC audit events show no incompatible clients |
| Passwordless user authentication | Boss fight | Password phishing and reuse | Windows Hello for Business or passkey adoption |
| Application control | Boss fight | Unapproved executable and script execution | App Control policy succeeds in Audit before Enforce |
| Endpoint detection and response | Boss fight | Post-compromise activity | Devices onboarded, healthy, and producing telemetry |
| Privileged access separation | Boss fight | Credential exposure across security tiers | Separate admin identities and restricted logon paths |
| Resilient, tested recovery | Boss fight | Ransomware and destructive attacks | Successful restore test, not merely a green backup job |

---

## Level 1 — Equip now

### 1. Deploy Windows LAPS

Shared local administrator passwords turn one compromised endpoint into a reusable ticket for the rest of the fleet. **Windows LAPS** gives each managed machine a unique password, rotates it automatically, and backs it up to Windows Server Active Directory or Microsoft Entra ID.

Use the native Windows LAPS implementation, not the deprecated legacy Microsoft LAPS package, on supported systems. Restrict who can retrieve passwords, enable password encryption in AD DS where supported, monitor retrieval, and define an emergency-access process. Domain controllers can also use Windows LAPS to manage their Directory Services Restore Mode password.

**Verify:** retrieve a test password through the approved administrative path, confirm that unauthorized operators cannot read it, force a rotation, and inspect the dedicated LAPS event log. A policy existing in a console is not proof that a password reached the backup directory.

### 2. Remove unnecessary local administrators

Users rarely need permanent local administrator rights to read email, browse the web, or build spreadsheets. Malware is delighted when they have them anyway.

Manage the local **Administrators** group through Group Policy, Intune, or another authoritative platform. Remove stale domain groups, old deployment accounts, vendor identities, and direct user assignments. Keep a controlled recovery account managed by LAPS rather than a shared password written in a deployment document from 2017.

**Verify:** compare actual membership with the approved model and alert on additions. Also inspect nested groups; a clean-looking top-level group can hide an entire family tree of privilege.

### 3. Give patching a deadline

An update system that reports missing patches but never forces installation is a vulnerability newsletter.

Define deployment rings, maintenance windows, restart behavior, exception ownership, and a maximum remediation time based on severity and exploitation status. Include browsers, productivity software, runtimes, drivers, firmware, VPN clients, compression tools, and other third-party software. Prioritize vulnerabilities listed as exploited in the wild rather than sorting only by CVSS score.

**Verify:** measure exposure age, not just scan count. A useful dashboard answers: *How many devices remain vulnerable, for how long, and who owns the exception?*

### 4. Make Microsoft Defender Antivirus earn its silicon

Where Microsoft Defender Antivirus is the primary antivirus, enable real-time protection, behavior monitoring, cloud-delivered protection, automatic sample submission, potentially unwanted application protection, and tamper protection. Keep platform, engine, and intelligence updates healthy.

Where a third-party antivirus is primary, confirm the resulting Defender mode and ensure the replacement provides equivalent capabilities. Two installed antivirus products do not automatically mean twice the protection; sometimes they mean twice the exclusions and half the clarity.

**Verify:** inspect health centrally, run the standard EICAR validation in an authorized test scope, and confirm that tamper protection prevents an unapproved local change. Do not use production malware as a health check. That experiment has poor rollback characteristics.

### 5. Keep Windows Firewall enabled everywhere

Windows Firewall should remain enabled for Domain, Private, and Public profiles. Its default inbound-deny behavior removes services from the network unless a rule explicitly exposes them.

Scope inbound rules to the required profiles, programs, services, ports, and source networks. Remove duplicate and obsolete rules. Never stop the `MpsSvc` service; Microsoft does not support that as a firewall-disablement method, and other Windows functionality depends on it.

**Verify:** check all three profiles, enumerate enabled inbound allow rules, and test from an allowed and a denied source. A firewall rule named `TEMP-ALLOW-ANY` is not temporary after its third birthday.

```powershell
Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### 6. Remove SMBv1

SMBv1 is obsolete and lacks the security architecture of SMB2 and SMB3. Remove the client and server components unless a documented dependency still exists.

Inventory first on file servers and infrastructure that talks to old NAS devices, scanners, multifunction printers, laboratory systems, and embedded appliances. The proper fix is to update or isolate the dependency, not to preserve SMBv1 forever because one device has sentimental value.

**Verify:** confirm that the optional feature is absent and monitor for failed legacy connections after the pilot.

```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
```

### 7. Disable Print Spooler where nobody prints

The Print Spooler is unnecessary on many member servers and most dedicated infrastructure systems. If a machine does not print and does not provide print services, disable the service.

Do not apply this blindly to print servers, Remote Desktop Session Hosts, or applications that generate documents through print components. For systems that need the service, restrict Point and Print behavior and driver installation through the current Microsoft baseline.

**Verify:** document the systems that genuinely require printing and confirm the service remains disabled elsewhere after reboot and policy refresh.

```powershell
Get-Service -Name Spooler | Select-Object Status, StartType
```

### 8. Remove Windows PowerShell 2.0

Windows PowerShell 2.0 lacks modern security and logging capabilities. If the optional engine is still present on an older supported system, remove it after checking legacy scripts and applications.

This does **not** mean replacing Windows PowerShell 5.1 with PowerShell 7 everywhere. They are separate runtimes with different compatibility surfaces. The win is removing the obsolete downgrade path, not breaking every management module before lunch.

**Verify:** confirm the PowerShell V2 optional feature is absent and test the approved administration scripts under their intended runtime.

### 9. Remove unused software, roles, and features

Every installed agent, web runtime, remote tool, language pack, sample application, and server role adds code to patch and potentially expose. Uninstall what the machine no longer needs.

Start with unsupported software, duplicate remote-management products, abandoned monitoring agents, old Java and .NET runtimes, browser extensions, trialware, and server roles with no listening workload. Tie the inventory to an owner and business purpose.

**Verify:** compare installed software and Windows features against the approved build standard. Scan again afterward; the best vulnerability is the product that is no longer installed.

### 10. Verify Secure Boot and TPM health

Secure Boot protects the boot chain from untrusted components, while the TPM provides hardware-backed key protection and measurements used by BitLocker, Windows Hello, and other platform controls.

Enable them on compatible physical systems and Generation 2 virtual machines. Treat BIOS-to-UEFI conversion and firmware changes as planned work: changing boot mode on an existing installation without preparing the disk can produce a very secure machine that no longer boots.

**Verify:** collect Secure Boot state, TPM readiness, firmware mode, and model compatibility centrally.

```powershell
Confirm-SecureBootUEFI
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated
```

---

## Level 2 — Scan before firing

### 11. Start from a Microsoft Security Baseline

Microsoft Security Baselines provide a maintained, tested starting point for Windows and Windows Server. Use the Security Compliance Toolkit, Intune security baselines, or your configuration-management platform to compare the current estate with the recommended state.

Do not import a baseline directly into the entire domain and call the resulting outage a penetration test. Diff it against current policy, classify deviations, pilot by device role, and document every accepted exception.

**Verify:** produce a compliance report by baseline version and OS role. The baseline must evolve when Windows does; a perfectly enforced 2019 baseline is still a 2019 baseline.

### 12. Roll out Attack Surface Reduction rules

Attack Surface Reduction (ASR) rules block behaviors commonly used by malware: Office spawning child processes, executable content arriving through email, script-based downloaders, vulnerable signed drivers, credential theft, persistence through WMI, and ransomware activity.

Begin with Microsoft's standard protection rules and evaluate the remaining rules in **Audit** mode on representative devices. Move low-noise rules to **Block**, create the narrowest possible exclusions, and keep deployment methods consistent. Pay special attention to Configuration Manager, administrative tooling, Office automation, and line-of-business macros.

**Verify:** review per-rule audit events and Defender telemetry, then track the percentage of devices in Audit, Warn, and Block. `Not configured` is not a deployment ring.

### 13. Protect LSASS with LSA protection and Credential Guard

LSA protection runs LSASS as a protected process and blocks untrusted code from loading into it. Credential Guard goes further by isolating NTLM hashes, Kerberos secrets, and domain credentials using virtualization-based security.

Pilot LSA protection first and inspect Code Integrity events for incompatible LSA plug-ins. Pilot Credential Guard against smart-card middleware, VPN clients, authentication packages, unconstrained delegation dependencies, and applications requiring legacy authentication behavior.

Credential Guard is enabled by default on eligible Windows 11 22H2 and Windows Server 2025 domain-joined non-DC systems, but **default** should still be verified. Do not enable it on domain controllers, and it is unsupported on Exchange Server.

**Verify:** use `msinfo32.exe` or Device Guard CIM data to confirm that virtualization-based security and Credential Guard are running, not merely configured.

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
```

### 14. Deploy BitLocker with tested recovery

BitLocker protects data at rest when a device is lost, stolen, recycled, or booted offline. Prefer TPM-backed protection and Secure Boot on compatible hardware.

Back up recovery information to AD DS or Microsoft Entra ID **before** enforcement, restrict who can retrieve it, and monitor retrieval. Define whether workstations require TPM-only or TPM+PIN based on the threat model. Include fixed data drives and removable media where the business risk justifies it.

**Verify:** confirm encryption percentage, protection status, protector type, and successful recovery-key escrow. Then retrieve a sample key through the approved process. A key that allegedly exists somewhere is an interesting theory, not a recovery plan.

```powershell
Get-BitLockerVolume |
    Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, KeyProtector
```

### 15. Require SMB signing

SMB signing protects message integrity and helps prevent SMB relay and spoofing. Domain controllers already require signing for clients connecting to them, but member-server and client behavior must also be assessed. On Windows 11 24H2 and Windows Server 2025, SMB signing is required by default, so finding incompatible peers early matters more than ever.

Inventory non-Windows file servers, NAS devices, scanners, appliances, and old software before requiring signing on both SMB clients and servers. Use Kerberos rather than connecting to shares by IP address, and avoid aliases that silently force NTLM unless SPNs are configured correctly.

Windows 11 24H2 provides SMB signing and encryption compatibility auditing for third-party peers. Use the telemetry before enforcement, then require signing through supported policy rather than relying on the obsolete `EnableSecuritySignature` setting for SMB2/3.

**Verify:** inspect active SMB connections and confirm that signing is required on both sides of the intended flow.

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
Get-SmbConnection | Select-Object ServerName, ShareName, Dialect, Signed, Encrypted
```

### 16. Retire LLMNR, NetBIOS name resolution, and unused WPAD

LLMNR and NetBIOS name resolution allow local-network name poisoning that can capture or relay authentication. Disable them after proving that DNS is healthy and legacy applications no longer depend on single-label or broadcast name resolution.

Review Web Proxy Auto-Discovery as well. If WPAD is not deliberately deployed and controlled, remove the dependency and prevent clients from discovering an attacker-controlled proxy.

**Verify:** capture DNS and name-resolution failures during the pilot, inspect authentication telemetry for responder-style poisoning, and test the applications that everyone says are too old to document.

### 17. Harden RDP and WinRM

Remote administration should be reachable only from management networks, jump hosts, or approved operator devices. For RDP, require Network Level Authentication, use TLS, protect internet-facing access behind an RD Gateway or equivalent control, and add MFA where possible. Disable unnecessary device, drive, clipboard, and credential redirection.

For WinRM, restrict firewall scope, prefer Kerberos in the domain, remove unencrypted transport and Basic authentication unless a documented exception requires them, and use Just Enough Administration for constrained operator tasks.

**Verify:** test from approved and unapproved sources, review listener configuration, and centralize successful and failed remote-logon events. Port `3389` disappearing from an external scan is a beginning, not the whole control.

### 18. Modernize TLS without guessing

Disable TLS 1.0 and 1.1 only after inventorying application, service, driver, and runtime dependencies. Configure supported TLS versions at the SChannel layer, ensure .NET applications use system defaults and strong cryptography, and review cipher-suite policy separately.

Registry values prove configuration intent. A real handshake proves behavior. Use the companion guide [Check TLS 1.2 status on Windows Server](./Check%20TLS%201.2%20status%20on%20Windows%20Server.md) to check SChannel, .NET Framework flags, and an actual TLS 1.2 connection.

**Verify:** test inbound and outbound connections for each important workload. Do not infer server-side TLS health from a successful browser connection to somebody else's website.

### 19. Turn on useful audit policy and centralize the logs

Enable Advanced Audit Policy subcategories that support your detection use cases: logon, account management, process creation, policy change, object access where justified, PowerShell activity, Defender, Firewall, BitLocker, SMB, and remote administration.

Forward critical events through Windows Event Forwarding, an agent, or a SIEM. Size logs to survive disconnection and incident response, synchronize time, and monitor forwarding health. PowerShell Script Block Logging is valuable, but transcription and command-line collection can capture credentials or sensitive business data; protect access and retention accordingly.

**Verify:** generate known test events and prove they arrive centrally with the expected fields, host identity, and timestamp. A collector with zero alerts may indicate a wonderfully quiet estate or a wonderfully disconnected collector.

---

## Level 3 — The boss fights

### 20. Reduce, restrict, and eventually remove NTLM

NTLM enables compatibility, but it also enables relay, pass-the-hash, and authentication flows that lack modern protections. Start with domain and endpoint auditing, map every source, destination, account, and application, then remediate one dependency at a time.

Fix DNS and SPNs, use Kerberos-capable service identities, remove IP-address access to services, and repair applications that silently fall back. Add NTLM restrictions in controlled stages with explicit exceptions and expiry dates.

**Verify:** the NTLM event volume trends toward zero and every remaining flow has an owner. Do not begin with a domain-wide deny setting unless incident response is already your preferred deployment method.

### 21. Enforce LDAP signing and channel binding

LDAP signing protects integrity; LDAP channel binding ties authentication to the TLS channel and helps stop relay. Audit domain controllers for unsigned LDAP binds and channel-binding incompatibilities before enforcement.

Update or reconfigure applications, Linux integrations, appliances, monitoring tools, and old LDAP libraries. Prefer LDAPS or StartTLS with valid certificate trust where confidentiality is required, but remember that TLS alone does not magically repair every authentication choice.

**Verify:** relevant Directory Service audit events show no unknown incompatible clients across a representative observation window, then enforcement succeeds without authentication regressions.

### 22. Move users to passwordless authentication

Windows Hello for Business and FIDO2/passkeys reduce password phishing, replay, and reuse. They also change enrollment, recovery, device trust, and help-desk workflows, which is why this is a program rather than a checkbox.

Choose the trust model deliberately, protect registration, require strong bootstrap authentication, and design recovery before broad enrollment. Privileged users deserve a dedicated rollout rather than being added to the general population as an afterthought.

**Verify:** measure active passwordless usage, not registered methods. A passkey enrolled while the password remains the daily sign-in path is potential energy, not a completed migration.

### 23. Control which code is allowed to run

Microsoft App Control for Business provides a strong allow-listing model for executables, scripts, installers, libraries, and drivers. It can stop unknown code even when the file is not yet classified as malware.

Build policies from managed software sources and publisher trust, deploy in Audit mode, review blocked and would-be-blocked events, then move well-understood device groups to enforcement. Keep emergency policy recovery and signing procedures outside the machine being protected.

**Verify:** known business software, updates, drivers, and administration workflows succeed while an unapproved test binary is blocked. Application control without a maintenance workflow eventually becomes application archaeology.

### 24. Deploy endpoint detection and response

An EDR platform adds behavioral detection, investigation, isolation, response, and fleet-wide visibility beyond preventative controls. For Microsoft Defender for Endpoint, onboard supported devices, apply role-based access, integrate vulnerability management, and use EDR in block mode where licensing and architecture support it.

**Verify:** onboarding status, sensor health, cloud connectivity, alert delivery, automated investigation, and device isolation are tested. An agent icon in the tray is not a detection strategy.

### 25. Separate privileged identities and logon paths

Administrators should not browse the web, read email, and manage sensitive servers with the same identity and workstation. Use separate administrative accounts, privileged access workstations or hardened jump hosts, and logon restrictions that prevent high-value credentials from reaching lower-trust systems.

Replace static service passwords with gMSA or dMSA where supported, remove interactive logon from service identities, and use just-in-time or approval-based elevation where the management platform allows it.

**Verify:** model where privileged credentials can log on, detect violations, and test that ordinary endpoints reject Tier 0 identities. The cleanest password hash is the one that never arrived on the machine.

### 26. Build recovery that survives the incident

Security posture includes the ability to recover after prevention fails. Maintain offline or immutable backup copies, separate backup administration from production administration, protect recovery credentials, and document rebuild priorities.

For endpoints, ensure business data is redirected or synchronized to managed storage rather than living only on local disks. For servers, test application-consistent recovery, not just file presence.

**Verify:** perform scheduled restoration exercises and record recovery time and recovery point results. A successful backup job proves that data left the source. Only a restore proves that useful data comes back.

---

## A rollout pattern that scales

Use the same deployment loop for every control:

1. **Inventory** — identify supported systems, dependencies, owners, and existing configuration.
2. **Observe** — enable audit mode or collect representative telemetry where available.
3. **Pilot** — include ordinary devices, administrators, developers, remote workers, and awkward applications.
4. **Enforce** — expand in rings with an explicit stop condition.
5. **Validate** — test behavior from both the allowed and denied side.
6. **Monitor drift** — report devices that fall out of compliance.
7. **Expire exceptions** — every exception needs an owner, reason, compensating control, and review date.

This loop is less exciting than deploying twenty-six settings in one GPO. It is also considerably more likely to survive contact with production.

## What to do first

If the estate has no mature baseline yet, start with this order:

1. Deploy Windows LAPS and remove unnecessary local administrators.
2. Fix patching, Defender health, and Windows Firewall coverage.
3. Remove SMBv1, unused Print Spooler instances, PowerShell 2.0, and abandoned software.
4. Compare the estate against the current Microsoft Security Baseline.
5. Pilot ASR rules, LSA protection, Credential Guard, and BitLocker.
6. Centralize the telemetry before enforcing SMB signing, LDAP protections, or NTLM restrictions.
7. Build the longer program for passwordless authentication, application control, privileged access, and recovery.

The best first control is not always the most advanced one. It is the control that closes a real path, can be verified, and stays closed after the project team moves on.

---

## Microsoft references

- [Windows LAPS overview](https://learn.microsoft.com/windows-server/identity/laps/laps-overview)
- [Windows security baselines](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
- [Attack Surface Reduction rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Credential Guard overview](https://learn.microsoft.com/windows/security/identity-protection/credential-guard/)
- [SMB signing overview](https://learn.microsoft.com/windows-server/storage/file-server/smb-signing-overview)
- [BitLocker overview](https://learn.microsoft.com/windows/security/operating-system-security/data-protection/bitlocker/)
- [Windows Firewall overview](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/)
- [Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319)

Stack the small wins, measure the result, and save the heroic boss music for the controls that genuinely need it.
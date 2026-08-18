---
title: "Windows Client Security Power-Ups: The Quick Wins That Actually Matter"
date: 2026-08-17
---

# Windows Client Security Power-Ups: The Quick Wins That Actually Matter

## Maximum armor, minimum drama

Windows hardening does not begin with a 900-page standard and a heroic plan to configure every policy before Friday. It begins by fixing the controls that remove the largest attack paths for the least operational pain.

This is not a sacred Top 10. Security controls do not become better because they fit on a countdown. This is a practical collection of **quick wins**, **audit-first wins**, and **bigger projects** for Windows client endpoints — the laptops and desktops your users actually work on.

The goal is simple:

- remove reusable credentials;
- reduce exposed services and legacy protocols;
- protect credentials and data;
- block common attacker behavior;
- make the remaining activity visible;
- prove that every control is really active.

> This guide is for supported Windows client endpoints (Windows 10 and Windows 11). Servers — domain controllers, file servers, Exchange, and other Tier 0 or application-specific roles — are out of scope and need their own baselines and compatibility testing. A few controls here also touch the surrounding domain (NTLM, SMB signing, LDAP hardening); those are flagged as environment-level work. Applying every setting everywhere is not hardening. It is configuration roulette.

---

## The three deployment levels

| Level | Meaning | Deployment rule |
| --- | --- | --- |
| **Level 1 — Do now** | High value, low complexity, limited compatibility risk | Pilot quickly, validate, then expand |
| **Level 2 — Test first** | Strong control with known application or protocol dependencies | Audit first, remediate dependencies, then enforce |
| **Level 3 — Plan and build** | High-value architectural change | Treat as a project with owners, telemetry, milestones, and rollback |

The level describes deployment complexity, not security value. A Level 3 control can be essential; it simply deserves more engineering than one registry key and optimism.

## Quick map

| Power-up | Level | Main attack path reduced | First proof point |
| --- | --- | --- | --- |
| Windows LAPS | Do now | Password reuse and lateral movement | Unique, rotating local password is backed up |
| Remove unnecessary local administrators | Do now | Privilege escalation | Managed local Administrators membership |
| Patch Windows and third-party software | Do now | Exploitation of known vulnerabilities | Update compliance and enforced deadline |
| Microsoft Defender Antivirus hardening | Do now | Malware execution and tampering | Real-time, cloud, behavior, and tamper protection active |
| Turn on SmartScreen and reputation-based protection | Do now | Malicious sites, downloads, and low-reputation apps | SmartScreen enabled for OS, Edge, and downloads |
| Disable AutoRun and AutoPlay | Do now | Removable-media auto-execution | Policy applied; media no longer auto-runs |
| Disable cleartext WDigest credential caching | Do now | Cleartext credentials in memory | `UseLogonCredential` is 0 or absent |
| Windows Firewall on every profile | Do now | Remote exploitation and lateral movement | All profiles enabled; inbound exceptions justified |
| Block insecure SMB guest authentication | Do now | Rogue-share guest fallback | Insecure guest logons disabled |
| Remove SMBv1 | Do now | Legacy SMB exploitation and downgrade | SMB1 feature absent and no dependency observed |
| Harden or disable Print Spooler | Do now | Remote print spooler exploitation | No inbound remote printing; service off where unused |
| Remove PowerShell 2.0 | Do now | Downgrade to weak script visibility | Optional feature absent |
| Remove unused software and features | Do now | Unnecessary attack surface | Approved software inventory |
| Secure Boot and TPM health | Do now | Boot-chain and offline tampering | Secure Boot on; TPM ready and owned |
| Microsoft Security Baseline | Test first | Configuration drift and insecure defaults | Baseline comparison report |
| Attack Surface Reduction rules | Test first | Office, script, driver, and ransomware tradecraft | Audit telemetry reviewed before Block |
| LSA protection and Credential Guard | Test first | Credential dumping and pass-the-hash | `RunAsPPL` and VBS state verified |
| BitLocker with recovery escrow | Test first | Offline data theft on lost/stolen devices | Encryption on and recovery key escrowed (not local-account-only) |
| SMB signing | Test first | SMB relay and traffic tampering | Signing required; incompatible devices identified |
| Disable LLMNR, NetBIOS name resolution, and unused WPAD | Test first | Name-poisoning credential capture | No production dependency; policies enforced |
| Harden RDP and WinRM | Test first | Remote administration abuse | Restricted sources, strong authentication, useful logs |
| Modernize TLS | Test first | Legacy protocol and cipher use | Real handshake proves TLS 1.2 or later |
| Advanced audit policy and centralized logs | Test first | Invisible attacker activity | Critical events arrive centrally with correct timestamps |
| Reduce and remove NTLM | Plan and build | Relay, pass-the-hash, and weak authentication | NTLM audit shows known, shrinking dependencies |
| LDAP signing and channel binding | Plan and build | LDAP relay and tampering | DC audit events show no incompatible clients |
| Passwordless user authentication | Plan and build | Password phishing and reuse | Windows Hello for Business or passkey adoption |
| Application control | Plan and build | Unapproved executable and script execution | App Control policy succeeds in Audit before Enforce |
| Endpoint detection and response | Plan and build | Post-compromise activity | Devices onboarded, healthy, and producing telemetry |
| Privileged access separation | Plan and build | Credential exposure across security tiers | Separate admin identities and restricted logon paths |
| Resilient, tested recovery | Plan and build | Ransomware and destructive attacks | Successful restore test, not merely a green backup job |

---

## Level 1 — Do now

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

### 5. Turn on SmartScreen and reputation-based protection

On Windows clients, Microsoft Defender SmartScreen and reputation-based protection warn or block malicious websites, downloads, and low-reputation or potentially unwanted applications before they run. On the endpoints where users actually click links and open attachments, this closes one of the most common initial-access paths.

Enable SmartScreen for apps and files and for Microsoft Edge, and turn on reputation-based protection, including potentially unwanted app blocking. It costs users almost nothing and blocks a large share of drive-by and download-based attacks.

**Verify:** confirm through policy that SmartScreen is enabled for apps, Edge, and downloads, and test with a benign reputation prompt or Microsoft's SmartScreen demonstration pages rather than a live malicious URL.

### 6. Disable AutoRun and AutoPlay

AutoRun and AutoPlay can execute code from removable media and network locations with almost no user interaction, a classic delivery path for USB-borne malware.

Disable AutoRun and AutoPlay for all drive types through Group Policy or the equivalent management platform. User impact is minimal; removable media can still be opened manually.

**Verify:** confirm the policy is applied and that inserting removable media no longer triggers automatic execution.

### 7. Disable cleartext credential caching (WDigest)

Older Windows kept plaintext credentials in memory for WDigest authentication, which made credential theft trivial. Modern Windows disables this by default, but explicitly enforcing it stops a silent regression from re-exposing cleartext secrets in LSASS.

Set `UseLogonCredential` to `0` under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. The change is near-zero risk on supported systems and complements LSA protection and Credential Guard.

**Verify:** confirm the value is `0` or absent, and that no management tooling quietly re-enables it.

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -ErrorAction SilentlyContinue |
    Select-Object UseLogonCredential
```

### 8. Keep Windows Firewall enabled everywhere

Windows Firewall should remain enabled for Domain, Private, and Public profiles. Its default inbound-deny behavior removes services from the network unless a rule explicitly exposes them.

Scope inbound rules to the required profiles, programs, services, ports, and source networks. Remove duplicate and obsolete rules. Never stop the `MpsSvc` service; Microsoft does not support that as a firewall-disablement method, and other Windows functionality depends on it.

**Verify:** check all three profiles, enumerate enabled inbound allow rules, and test from an allowed and a denied source. A firewall rule named `TEMP-ALLOW-ANY` is not temporary after its third birthday.

```powershell
Get-NetFirewallProfile |
    Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
```

### 9. Block insecure SMB guest authentication

Windows SMB clients can fall back to unauthenticated guest access, which lets an attacker lure a client to a rogue share without credentials. Blocking insecure guest logons stops that silent fallback and pairs naturally with removing SMBv1.

Disable insecure guest authentication on the SMB client. Modern Windows editions already block it by default, but enforcing it prevents drift. Confirm first that no production share genuinely depends on guest access.

**Verify:** check the SMB client configuration and monitor for failed guest connections during the pilot.

```powershell
Get-SmbClientConfiguration | Select-Object EnableInsecureGuestLogons
```

### 10. Remove SMBv1

SMBv1 is obsolete and lacks the security architecture of SMB2 and SMB3. Remove the client and server components unless a documented dependency still exists.

On a client, remove both the SMBv1 client and server components. The usual dependency is a workstation still reaching an old NAS device, scanner, or multifunction printer; inventory those connections first. The proper fix is to update or isolate the offending device, not to preserve SMBv1 forever because one printer has sentimental value.

**Verify:** confirm that the optional feature is absent and monitor for failed legacy connections after the pilot.

```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
```

### 11. Harden or disable the Print Spooler

The Print Spooler has been a repeat source of remote code execution. Most client endpoints still need it for local printing, so keep the service running but stop it from accepting inbound remote print connections, and restrict Point and Print behavior and driver installation through the current Microsoft baseline. On endpoints that never print — kiosks and task-specific or shared-purpose devices — disable the service entirely.

Check first for applications that generate documents through print components before disabling it outright.

**Verify:** confirm the service is disabled where unused and, where it must run, that inbound remote printing is blocked. Re-check after reboot and policy refresh.

```powershell
Get-Service -Name Spooler | Select-Object Status, StartType
```

### 12. Remove Windows PowerShell 2.0

Windows PowerShell 2.0 lacks modern security and logging capabilities. If the optional engine is still present on an older supported system, remove it after checking legacy scripts and applications.

This does **not** mean replacing Windows PowerShell 5.1 with PowerShell 7 everywhere. They are separate runtimes with different compatibility surfaces. The win is removing the obsolete downgrade path, not breaking every management module before lunch.

**Verify:** confirm the PowerShell V2 optional feature is absent and test the approved administration scripts under their intended runtime.

### 13. Remove unused software and features

Every installed app, browser extension, runtime, agent, and preinstalled OEM utility adds code to patch and potentially expose. Uninstall what the endpoint no longer needs.

Start with unsupported software, OEM bloatware, duplicate remote-support tools, abandoned agents, old Java and .NET runtimes, unused browser extensions, and trialware. Tie the inventory to an owner and business purpose.

**Verify:** compare installed software and Windows features against the approved build standard. Scan again afterward; the best vulnerability is the product that is no longer installed.

### 14. Verify Secure Boot and TPM health

Secure Boot protects the boot chain from untrusted components, while the TPM provides hardware-backed key protection and measurements used by BitLocker, Windows Hello, and other platform controls.

Enable them on compatible physical systems and Generation 2 virtual machines. Treat BIOS-to-UEFI conversion and firmware changes as planned work: changing boot mode on an existing installation without preparing the disk can produce a very secure machine that no longer boots.

**Verify:** collect Secure Boot state, TPM readiness, firmware mode, and model compatibility centrally.

```powershell
Confirm-SecureBootUEFI
Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated
```

---

## Level 2 — Test first

### 15. Start from a Microsoft Security Baseline

Microsoft Security Baselines provide a maintained, tested starting point for Windows and Windows Server. Start with the Windows client baseline for your OS version. Use the Security Compliance Toolkit, Intune security baselines, or your configuration-management platform to compare the current build with the recommended state.

Do not push a baseline to the whole fleet in one shot and call the resulting outage a penetration test. Diff it against current policy, classify deviations, pilot by device group, and document every accepted exception.

**Verify:** produce a compliance report by baseline version and device group. The baseline must evolve when Windows does; a perfectly enforced 2019 baseline is still a 2019 baseline.

### 16. Roll out Attack Surface Reduction rules

Attack Surface Reduction (ASR) rules are a client-endpoint sweet spot: they block behaviors commonly used by malware where users actually get hit — Office spawning child processes, executable content arriving through email, script-based downloaders, credential theft, vulnerable signed drivers, persistence through WMI, and ransomware activity.

Begin with Microsoft's standard protection rules and evaluate the remaining rules in **Audit** mode on representative devices. Move low-noise rules to **Block**, create the narrowest possible exclusions, and keep deployment methods consistent. Watch line-of-business macros, in-house scripts, and any admin tooling (Configuration Manager relies heavily on WMI) before enforcing.

**Verify:** review per-rule audit events and Defender telemetry, then track the percentage of devices in Audit, Warn, and Block. `Not configured` is not a deployment ring.

### 17. Protect LSASS with LSA protection and Credential Guard

LSA protection runs LSASS as a protected process and blocks untrusted code from loading into it. Credential Guard goes further by isolating NTLM hashes, Kerberos secrets, and domain credentials using virtualization-based security.

Pilot LSA protection first and inspect Code Integrity events for incompatible LSA plug-ins. Pilot Credential Guard against smart-card middleware, VPN clients, authentication packages, unconstrained delegation dependencies, and applications requiring legacy authentication behavior.

Credential Guard is enabled by default on eligible Windows 11 22H2 and later domain-joined clients, but **default** should still be verified rather than assumed.

**Verify:** use `msinfo32.exe` or Device Guard CIM data to confirm that virtualization-based security and Credential Guard are running, not merely configured.

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
```

### 18. Deploy BitLocker with tested recovery

BitLocker protects data at rest when a laptop is lost, stolen, recycled, or booted offline — the single most likely data-loss event for a mobile client. On modern Windows 11 clients, **Device Encryption** often turns BitLocker on automatically, but a device signed in with **local accounts only stays unprotected** because its recovery key is never escrowed. Managed recovery-key backup is therefore the real control, not encryption alone.

Back up recovery information to Microsoft Entra ID or AD DS **before** enforcement, restrict who can retrieve it, and monitor retrieval. Prefer TPM-backed protection with Secure Boot; decide TPM-only versus TPM+PIN from the threat model. Include fixed data drives, and removable media where the business risk justifies it.

**Verify:** confirm encryption percentage, protection status, protector type, and successful recovery-key escrow. Then retrieve a sample key through the approved process. A key that allegedly exists somewhere is an interesting theory, not a recovery plan.

```powershell
Get-BitLockerVolume |
    Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, KeyProtector
```

### 19. Require SMB signing

SMB signing protects message integrity and helps prevent SMB relay and spoofing. On Windows 11 24H2 the SMB client requires signing by default, so the job is mostly confirming that state and finding peers that still cannot sign.

Inventory the shares your clients reach — NAS devices, scanners, appliances, and old third-party file servers — before enforcing client-side signing. Use Kerberos rather than connecting to shares by IP address, and avoid aliases that silently force NTLM unless SPNs are configured correctly.

Windows 11 24H2 provides SMB signing and encryption compatibility auditing for third-party peers. Use that telemetry before enforcement, then require signing through supported policy rather than relying on the obsolete `EnableSecuritySignature` setting for SMB2/3.

**Verify:** inspect active SMB connections and confirm that signing is required on both sides of the intended flow.

```powershell
Get-SmbClientConfiguration | Select-Object RequireSecuritySignature
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature
Get-SmbConnection | Select-Object ServerName, ShareName, Dialect, Signed, Encrypted
```

### 20. Retire LLMNR, NetBIOS name resolution, and unused WPAD

LLMNR and NetBIOS name resolution allow local-network name poisoning that can capture or relay authentication. Disable them after proving that DNS is healthy and legacy applications no longer depend on single-label or broadcast name resolution.

Review Web Proxy Auto-Discovery as well. If WPAD is not deliberately deployed and controlled, remove the dependency and prevent clients from discovering an attacker-controlled proxy.

**Verify:** capture DNS and name-resolution failures during the pilot, inspect authentication telemetry for responder-style poisoning, and test the applications that everyone says are too old to document.

### 21. Harden RDP and WinRM

On most client endpoints, inbound RDP and WinRM are simply not needed — disabling the listeners removes that attack surface outright. Where remote administration is required, it should be reachable only from management networks, jump hosts, or approved operator devices. For RDP, require Network Level Authentication, use TLS, protect internet-facing access behind an RD Gateway or equivalent control, and add MFA where possible. Disable unnecessary device, drive, clipboard, and credential redirection.

For WinRM, restrict firewall scope, prefer Kerberos in the domain, remove unencrypted transport and Basic authentication unless a documented exception requires them, and use Just Enough Administration for constrained operator tasks.

**Verify:** test from approved and unapproved sources, review listener configuration, and centralize successful and failed remote-logon events. Port `3389` disappearing from an external scan is a beginning, not the whole control.

### 22. Modernize TLS without guessing

Disable TLS 1.0 and 1.1 only after inventorying application, service, driver, and runtime dependencies. Configure supported TLS versions at the SChannel layer, ensure .NET applications use system defaults and strong cryptography, and review cipher-suite policy separately.

Registry values prove configuration intent. A real handshake proves behavior. Use the companion guide [Check TLS 1.2 status on Windows Server](../../110%20-%20Platform/Windows%20Server/How-to/Check%20TLS%201.2%20status%20on%20Windows%20Server.md) to check SChannel, .NET Framework flags, and an actual TLS 1.2 connection.

**Verify:** test inbound and outbound connections for each important workload. Do not infer server-side TLS health from a successful browser connection to somebody else's website.

### 23. Turn on useful audit policy and centralize the logs

Enable Advanced Audit Policy subcategories that support your detection use cases: logon, account management, process creation, policy change, object access where justified, PowerShell activity, Defender, Firewall, BitLocker, SMB, and remote administration.

Forward critical events through Windows Event Forwarding, an agent, or a SIEM. Size logs to survive disconnection and incident response, synchronize time, and monitor forwarding health. PowerShell Script Block Logging is valuable, but transcription and command-line collection can capture credentials or sensitive business data; protect access and retention accordingly.

**Verify:** generate known test events and prove they arrive centrally with the expected fields, host identity, and timestamp. A collector with zero alerts may indicate a wonderfully quiet estate or a wonderfully disconnected collector.

---

## Level 3 — Plan and build

### 24. Reduce, restrict, and eventually remove NTLM

NTLM enables compatibility, but it also enables relay, pass-the-hash, and authentication flows that lack modern protections. Start with domain and endpoint auditing, map every source, destination, account, and application, then remediate one dependency at a time.

Fix DNS and SPNs, use Kerberos-capable service identities, remove IP-address access to services, and repair applications that silently fall back. Add NTLM restrictions in controlled stages with explicit exceptions and expiry dates.

**Verify:** the NTLM event volume trends toward zero and every remaining flow has an owner. Do not begin with a domain-wide deny setting unless incident response is already your preferred deployment method.

### 25. Enforce LDAP signing and channel binding

LDAP signing protects integrity; LDAP channel binding ties authentication to the TLS channel and helps stop relay. This is an **environment-level control configured on domain controllers**, not a per-client setting — but it directly hardens how every client binds to the directory, so it belongs on the roadmap. Audit domain controllers for unsigned LDAP binds and channel-binding incompatibilities before enforcement.

Update or reconfigure applications, Linux integrations, appliances, monitoring tools, and old LDAP libraries. Prefer LDAPS or StartTLS with valid certificate trust where confidentiality is required, but remember that TLS alone does not magically repair every authentication choice.

**Verify:** relevant Directory Service audit events show no unknown incompatible clients across a representative observation window, then enforcement succeeds without authentication regressions.

### 26. Move users to passwordless authentication

Windows Hello for Business and FIDO2/passkeys reduce password phishing, replay, and reuse. They also change enrollment, recovery, device trust, and help-desk workflows, which is why this is a program rather than a checkbox.

Choose the trust model deliberately, protect registration, require strong bootstrap authentication, and design recovery before broad enrollment. Privileged users deserve a dedicated rollout rather than being added to the general population as an afterthought.

**Verify:** measure active passwordless usage, not registered methods. A passkey enrolled while the password remains the daily sign-in path is potential energy, not a completed migration.

### 27. Control which code is allowed to run

Microsoft App Control for Business provides a strong allow-listing model for executables, scripts, installers, libraries, and drivers. It can stop unknown code even when the file is not yet classified as malware.

Build policies from managed software sources and publisher trust, deploy in Audit mode, review blocked and would-be-blocked events, then move well-understood device groups to enforcement. Keep emergency policy recovery and signing procedures outside the machine being protected.

**Verify:** known business software, updates, drivers, and administration workflows succeed while an unapproved test binary is blocked. Application control without a maintenance workflow eventually becomes application archaeology.

### 28. Deploy endpoint detection and response

An EDR platform adds behavioral detection, investigation, isolation, response, and fleet-wide visibility beyond preventative controls. For Microsoft Defender for Endpoint, onboard supported devices, apply role-based access, integrate vulnerability management, and use EDR in block mode where licensing and architecture support it.

**Verify:** onboarding status, sensor health, cloud connectivity, alert delivery, automated investigation, and device isolation are tested. An agent icon in the tray is not a detection strategy.

### 29. Separate privileged identities and logon paths

Administrators should not browse the web, read email, and manage sensitive systems from the same identity and the same everyday workstation. Use separate administrative accounts, privileged access workstations or hardened jump hosts, and logon restrictions that keep high-value credentials off ordinary client endpoints where they can be harvested.

Replace static service passwords with gMSA or dMSA where supported, remove interactive logon from service identities, and use just-in-time or approval-based elevation where the management platform allows it.

**Verify:** model where privileged credentials can log on, detect violations, and test that ordinary endpoints reject Tier 0 identities. The cleanest password hash is the one that never arrived on the machine.

### 30. Build recovery that survives the incident

Security posture includes the ability to recover after prevention fails. Maintain offline or immutable backup copies, separate backup administration from production administration, protect recovery credentials, and document rebuild priorities.

For client endpoints, make sure business data is redirected or synchronized to managed storage (OneDrive Known Folder Move, redirected folders) rather than living only on a local disk that ransomware or a dead SSD can take with it.

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

This loop is less exciting than deploying thirty settings in one GPO. It is also considerably more likely to survive contact with production.

## What to do first

If the estate has no mature baseline yet, start with this order:

1. Deploy Windows LAPS and remove unnecessary local administrators.
2. Fix patching, Defender health, and Windows Firewall coverage.
3. Remove SMBv1, PowerShell 2.0, and abandoned software; harden the Print Spooler; and disable cleartext WDigest, AutoRun, and insecure SMB guest access.
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

Stack the small wins, measure the result, and save the heavy planning for the controls that genuinely need it.
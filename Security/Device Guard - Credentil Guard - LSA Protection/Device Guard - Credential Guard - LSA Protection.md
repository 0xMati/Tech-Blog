# WDAC, HVCI, Credential Guard & LSA Protection — Comprehensive Guide

🗓️ Published: 2026-03-23

Hey everyone! In this article we're going to deep dive into four critical Windows security features that every AD admin and security engineer should know: **Device Guard (WDAC)**, **HVCI (Hypervisor-protected Code Integrity)**, **Credential Guard**, and **LSA Protection (RunAsPPL)**. We'll cover what they do, what they protect against, their impact on your environment, how to deploy them — and yes, whether you can (and should) run them on Domain Controllers.

🔗 https://learn.microsoft.com/en-us/windows/security/

---

## 📋 Table of Contents

- [🎯 Overview — What Are These Features?](#-overview--what-are-these-features)
- [🛡️ Device Guard / Windows Defender Application Control (WDAC)](#️-device-guard--windows-defender-application-control-wdac)
  - [What Is WDAC?](#what-is-wdac)
  - [What Does It Protect Against?](#what-does-it-protect-against)
  - [Requirements](#requirements)
  - [Impact & Considerations](#impact--considerations)
  - [Can I Deploy WDAC on Domain Controllers?](#can-i-deploy-wdac-on-domain-controllers)
  - [How to Deploy WDAC](#how-to-deploy-wdac)
- [🧱 HVCI — Hypervisor-protected Code Integrity](#-hvci--hypervisor-protected-code-integrity)
  - [What Is HVCI?](#what-is-hvci)
  - [What Does HVCI Protect Against?](#what-does-hvci-protect-against)
  - [Requirements](#requirements-hvci)
  - [Impact & Considerations](#impact--considerations-hvci)
  - [Can I Deploy HVCI on Domain Controllers?](#can-i-deploy-hvci-on-domain-controllers)
  - [How to Deploy HVCI](#how-to-deploy-hvci)
  - [How to Verify HVCI Is Running](#how-to-verify-hvci-is-running)
- [🔐 Credential Guard](#-credential-guard)
  - [What Is Credential Guard?](#what-is-credential-guard)
  - [What Does It Protect Against?](#what-does-it-protect-against-1)
  - [Requirements](#requirements-1)
  - [Impact & Considerations](#impact--considerations-1)
  - [Can I Deploy Credential Guard on Domain Controllers?](#can-i-deploy-credential-guard-on-domain-controllers) ⚠️
  - [How to Deploy Credential Guard](#how-to-deploy-credential-guard)
  - [How to Verify Credential Guard Is Running](#how-to-verify-credential-guard-is-running)
- [🔒 LSA Protection (RunAsPPL)](#-lsa-protection-runasppl)
  - [What Is LSA Protection?](#what-is-lsa-protection)
  - [What Does It Protect Against?](#what-does-it-protect-against-2)
  - [Requirements](#requirements-2)
  - [Impact & Considerations](#impact--considerations-2)
  - [Can I Deploy LSA Protection on Domain Controllers?](#can-i-deploy-lsa-protection-on-domain-controllers)
  - [How to Deploy LSA Protection](#how-to-deploy-lsa-protection)
  - [How to Verify LSA Protection Is Active](#how-to-verify-lsa-protection-is-active)
- [📊 Comparison Matrix](#-comparison-matrix)
- [🏗️ Deployment Strategy & Recommendations](#️-deployment-strategy--recommendations)
- [⚠️ Common Pitfalls](#️-common-pitfalls)
- [📚 References](#-references)

---

## 🎯 Overview — What Are These Features?

These four features are part of the **Windows Virtualization-Based Security (VBS)** ecosystem and defense-in-depth strategy. They each address a different layer of attack:

| Feature | Protection Layer | Primary Goal |
|---|---|---|
| **Device Guard / WDAC** | Application execution (user mode) | Only trusted code runs on the machine |
| **HVCI** | Kernel code integrity | Only trusted code runs in the kernel |
| **Credential Guard** | Credentials in memory | Prevent credential theft (Pass-the-Hash, Pass-the-Ticket) |
| **LSA Protection (RunAsPPL)** | LSA process integrity | Block unauthorized code from accessing the LSA process |

> 💡 **Tip**: These features are complementary — they protect different attack surfaces and should ideally be deployed together as part of a layered security strategy.

---

## 🛡️ Device Guard / Windows Defender Application Control (WDAC)

### What Is WDAC?

**Windows Defender Application Control (WDAC)** — formerly known as **Device Guard** — is a security feature that controls which drivers and applications are allowed to run on a Windows device.

The original "Device Guard" term encompassed two technologies:
- **WDAC** (code integrity policies) — the application control engine (covered in this section)
- **HVCI** (Hypervisor-protected Code Integrity) — uses VBS to protect the kernel code integrity process (covered in the [next section](#-hvci--hypervisor-protected-code-integrity))

Microsoft now recommends using the term **WDAC** for application control policies and **HVCI** for the hypervisor-based kernel protection. They are **two distinct protections** that can be enabled independently.

🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol

### What Does It Protect Against?

WDAC protects against:

- **Unauthorized applications** — Malware, ransomware, untrusted executables
- **Script-based attacks** — PowerShell, VBScript, JScript abuse (when configured with script enforcement)
- **Driver-based attacks** — Vulnerable or malicious kernel drivers (with HVCI)
- **Living-off-the-land binaries (LOLBins)** — Abuse of built-in Windows tools
- **DLL sideloading** — Loading malicious DLLs via trusted applications

### Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10 / Windows 11 / Windows Server 2016+ |
| **HVCI (optional)** | Requires VBS support (UEFI, Secure Boot, TPM 2.0, compatible hypervisor) |
| **WDAC only** | No specific hardware requirements — works on any supported OS |
| **Management** | GPO, Intune, SCCM, or manual deployment via CIPolicy |

### Impact & Considerations

| Area | Impact |
|---|---|
| **Application compatibility** | ⚠️ **High** — Any unsigned or non-whitelisted application will be blocked. Requires thorough application inventory before deployment. |
| **Performance** | Low — Minimal overhead on modern hardware. |
| **User experience** | Applications that don't match the policy silently fail or show a block notification. |
| **Administration** | Requires ongoing policy management as new applications are introduced. |
| **Rollback** | Policies can be deployed in **Audit mode** first (no blocking, only logging). |

> 💡 **Tip**: Always start with **Audit mode** (`Enabled:Audit Mode`) to identify what would be blocked before switching to **Enforced mode**. Event log: `Microsoft-Windows-CodeIntegrity/Operational` — Event IDs **3076** (audit block) and **3077** (enforced block).

### Can I Deploy WDAC on Domain Controllers?

**Yes**, WDAC is supported on Domain Controllers. However, extra care is required:

- Domain Controllers run a well-defined set of software — this makes them good candidates for application control
- You must ensure that **all AD-related binaries**, third-party agents (antivirus, monitoring, backup), and Microsoft management tools are covered by the policy
- Use the **Microsoft recommended block rules** and **Microsoft recommended driver block rules** as baselines
- Test thoroughly in **Audit mode** before enforcement

🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol

### How to Deploy WDAC

#### Step 1 — Create a Base Policy from a Reference Machine

```powershell
# Scan the reference machine and create a policy
New-CIPolicy -Level Publisher -FilePath "C:\Policies\BasePolicy.xml" -UserPEs -Fallback Hash

# Optionally add the Microsoft recommended block rules
# Download from: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol
```

#### Step 2 — Set the Policy to Audit Mode

```powershell
# Ensure the policy starts in Audit mode
Set-RuleOption -FilePath "C:\Policies\BasePolicy.xml" -Option 3  # Enabled:Audit Mode
```

#### Step 3 — Convert the Policy to Binary

```powershell
# Convert XML to binary
ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" `
    -BinaryFilePath "C:\Policies\{PolicyID}.cip"
```

#### Step 4 — Deploy via Group Policy

1. **Copy the policy file** to a network share accessible by target machines (e.g. `\\domain.local\SYSVOL\domain.local\Policies\WDAC\`) or to a local folder
2. **Open the GPMC console** (`gpmc.msc`)
3. **Create a new GPO**: right-click the target OU → *Create a GPO in this domain, and Link it here...*
   - Name the GPO explicitly, e.g. `SEC - WDAC - Audit Mode` or `SEC - WDAC - Enforce`
4. **Edit the GPO** → navigate to:

```
Computer Configuration
  → Administrative Templates
    → System
      → Device Guard
        → Deploy Windows Defender Application Control
```

5. **Enable the setting** → select **Enabled**
6. **Specify the path** to the `.cip` or `.p7b` file:
   - E.g. `\\domain.local\SYSVOL\domain.local\Policies\WDAC\BasePolicy.cip`
   - Or the local path if deployed differently: `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyID}.cip`
7. **Click OK** and close the editor

> 💡 **Tip**: For a progressive rollout:
> - Create an **AD security group** (e.g. `GRP-WDAC-Pilot`) and filter the GPO with **Security Filtering** on that group
> - Start with a few pilot machines in **Audit mode**
> - Analyze Event IDs 3076 for 2-4 weeks
> - Then gradually expand the scope

> ⚠️ **Important**: The GPO only points to the policy file — the policy content (audit vs enforce, authorization rules) is defined in the XML/CIP file itself. Changing the mode requires regenerating and redeploying the `.cip` file.

#### Step 5 — Monitor Audit Events

```powershell
# Check for audit block events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" |
    Where-Object { $_.Id -in @(3076, 3077) } |
    Select-Object TimeCreated, Id, Message -First 20
```

#### Step 6 — Switch to Enforced Mode

```powershell
# Remove audit mode option to enforce the policy
Set-RuleOption -FilePath "C:\Policies\BasePolicy.xml" -Option 3 -Delete

# Re-convert and redeploy the policy
ConvertFrom-CIPolicy -XmlFilePath "C:\Policies\BasePolicy.xml" `
    -BinaryFilePath "C:\Policies\{PolicyID}.cip"

# Replace the .cip file on the network share or the path used by the GPO
# The GPO will automatically apply the new policy at the next gpupdate
```

---

## 🧱 HVCI — Hypervisor-protected Code Integrity

### What Is HVCI?

**HVCI** (Hypervisor-protected Code Integrity), also known as **Memory Integrity**, uses **Virtualization-Based Security (VBS)** to protect the Windows kernel code integrity verification process. Instead of the kernel verifying its own code (which can be tampered with if the kernel is compromised), HVCI moves that verification into an isolated VBS container that the kernel cannot access.

In simple terms:
- **Without HVCI**: The kernel checks its own drivers and code → if the kernel is compromised, the attacker can load malicious drivers
- **With HVCI**: A separate VBS-isolated process checks kernel code → even a compromised kernel cannot bypass the verification

🔗 https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity

### What Does HVCI Protect Against?

| Threat | Protection |
|---|---|
| **Vulnerable kernel drivers** | ✅ Blocks unsigned or known-vulnerable drivers from loading into the kernel |
| **BYOVD (Bring Your Own Vulnerable Driver)** | ✅ Prevents attackers from loading legitimate but vulnerable signed drivers to gain kernel access |
| **Kernel rootkits** | ✅ Makes it significantly harder to load unsigned kernel code |
| **Kernel-mode code injection** | ✅ VBS isolation prevents tampering with code integrity checks |
| **Bootkits** | ⚠️ Partial — Combined with Secure Boot, provides strong protection |

> ⚠️ **Important**: HVCI is a key defense against the increasingly popular **BYOVD** attack technique, where attackers use legitimate but vulnerable signed drivers (e.g., old hardware drivers with known exploits) to gain kernel-level access. Microsoft maintains a **vulnerable driver blocklist** that works with HVCI.
>
> 🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

### Requirements {#requirements-hvci}

| Requirement | Details |
|---|---|
| **OS** | Windows 10 / Windows 11 / Windows Server 2016+ |
| **Firmware** | UEFI firmware with Secure Boot |
| **Virtualization** | Hardware virtualization (Intel VT-x / AMD-V) + SLAT (Intel EPT / AMD RVI) |
| **TPM** | TPM 2.0 recommended (not strictly required) |
| **Drivers** | All kernel drivers must be compatible with HVCI (signed, no executable non-paged pool, etc.) |

> ⚠️ **Important**: Starting with **Windows 11**, HVCI (Memory Integrity) is **enabled by default** on new installations with compatible hardware.

### Impact & Considerations {#impact--considerations-hvci}

| Area | Impact |
|---|---|
| **Driver compatibility** | ⚠️ **Medium-High** — Older or poorly written kernel drivers may be incompatible with HVCI. They will fail to load. |
| **Performance** | ⚠️ **Low-Medium** — VBS adds some CPU and memory overhead. Gaming and high-performance workloads may see 5-10% impact on older hardware. Negligible on modern hardware. |
| **Legacy hardware** | ❌ Drivers for older peripherals (printers, scanners, industrial hardware) may not be HVCI-compatible. |
| **Virtualization software** | ⚠️ Some older virtualization software (VirtualBox < 6.x, VMware older versions) may conflict with VBS/HVCI. |
| **Rollback** | ✅ Can be disabled via GPO, registry, or Windows Security app (unless UEFI-locked). |

> 💡 **Tip**: You can check driver HVCI compatibility before enabling it:
> ```powershell
> # Check HVCI compatibility via System Information
> # Run msinfo32.exe → look for "Virtualization-based security" and
> # "Virtualization-based security Services Running" to see the current state.
>
> # Check via PowerShell / WMI
> $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
> $dg | Select-Object VirtualizationBasedSecurityStatus, SecurityServicesRunning
> # VirtualizationBasedSecurityStatus: 0 = Not enabled, 1 = Enabled but not running, 2 = Running
> # SecurityServicesRunning: look for value 2 (HVCI)
>
> # On Windows Security App → Device Security → Core Isolation → Memory Integrity
> # Windows will show a list of incompatible drivers preventing HVCI from being enabled.
> ```

### Can I Deploy HVCI on Domain Controllers?

**Yes**, HVCI is supported on Domain Controllers and provides strong kernel-level protection:

- ✅ **Recommended** on Tier 0 assets — DCs are high-value targets for kernel exploits
- ✅ Domain Controllers typically use only Microsoft-signed, HVCI-compatible drivers
- ⚠️ Validate that any third-party drivers (storage HBA, NIC, monitoring agents with kernel components) are HVCI-compatible
- ⚠️ Test on a non-production DC first — an incompatible driver could cause a BSOD or fail to load
- 💡 Combine with the **Microsoft vulnerable driver blocklist** for maximum protection

### How to Deploy HVCI

#### Option 1 — via Group Policy

1. **Open the GPMC console** (`gpmc.msc`)
2. **Create a new GPO**: right-click the target OU → *Create a GPO in this domain, and Link it here...*
   - Name the GPO: e.g. `SEC - VBS and HVCI`
3. **Edit the GPO** → navigate to:

```
Computer Configuration
  → Administrative Templates
    → System
      → Device Guard
        → Turn On Virtualization Based Security
```

4. **Enable the setting** → select **Enabled**
5. **Configure the options**:

| Option | Recommended value | Description |
|---|---|---|
| **Select Platform Security Level** | `Secure Boot and DMA Protection` | Platform security level. "Secure Boot" alone is the minimum. "Secure Boot and DMA Protection" is more secure but requires IOMMU-compatible hardware (Intel VT-d / AMD-Vi). |
| **Virtualization Based Protection of Code Integrity** | `Enabled with UEFI lock` (prod) or `Enabled without lock` (test) | Enables HVCI. The UEFI lock prevents remote disabling — requires physical access to disable. |
| **Require UEFI Memory Attributes Table** | `True` (if supported) | Strengthens protection by requiring the firmware to expose memory attributes via UEFI MAT. |
| **Credential Guard Configuration** | Leave `Not Configured` here if managed separately | Credential Guard can be enabled in the same GPO or separately (see Credential Guard section). |

6. **Click OK** → close the editor
7. **Link the GPO** to the appropriate OU (start with a limited scope)

> 💡 **Tip**: Use **“Enabled without lock”** during testing so you can easily roll back. Switch to **“Enabled with UEFI lock”** only when you are confident all drivers are compatible.

> ⚠️ **Important**: This GPO enables VBS **and** HVCI. If you want to enable VBS without HVCI (e.g. for Credential Guard only), leave the “Virtualization Based Protection of Code Integrity” option set to `Not Configured` or `Disabled`.

#### Option 2 — via Registry

```powershell
# Enable VBS (if not already enabled)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

# Enable HVCI (1 = Enabled with UEFI lock, 2 = Enabled without lock)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name "Enabled" -Value 1 -Type DWord -Force

# Restart required
Restart-Computer
```

#### Option 3 — via Windows Security App (Workstations)

```
Windows Security
  → Device Security
    → Core isolation details
      → Memory integrity: On
```

#### Option 4 — via Intune / MDM

```
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity
Value: 1

OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceGuard/HypervisorEnforcedCodeIntegrity
Value: 1
```

### How to Verify HVCI Is Running

```powershell
# Method 1: System Information
# Run msinfo32.exe → look for:
#   "Virtualization-based security"     → Running
#   "Virtualization-based security Services Running" → Hypervisor enforced Code Integrity

# Method 2: PowerShell / WMI
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard |
    Select-Object -Property VirtualizationBasedSecurityStatus,
        SecurityServicesConfigured, SecurityServicesRunning

# SecurityServicesRunning:
# 1 = Credential Guard
# 2 = HVCI  ← this is what you're looking for
# 3 = System Guard Secure Launch

# Method 3: Windows Security App
# Windows Security → Device Security → Core isolation
# "Memory integrity" should show "On"

# Method 4: Registry check
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" `
    -Name "Enabled" -ErrorAction SilentlyContinue |
    Select-Object Enabled
```

---

## 🔐 Credential Guard

### What Is Credential Guard?

**Credential Guard** uses **Virtualization-Based Security (VBS)** to isolate and protect secrets (NTLM hashes, Kerberos TGTs) so that only privileged system software can access them. Credentials are stored in an isolated container that the main OS kernel cannot access — even if the kernel is fully compromised.

🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

### What Does It Protect Against?

Credential Guard specifically mitigates:

| Attack | Without Credential Guard | With Credential Guard |
|---|---|---|
| **Pass-the-Hash (PtH)** | ❌ Attacker dumps NTLM hashes from LSASS | ✅ Hashes are isolated in VBS — cannot be extracted |
| **Pass-the-Ticket (PtT)** | ❌ Attacker steals Kerberos TGTs from memory | ✅ TGTs are managed by the isolated LSA — not accessible |
| **Kerberoasting (indirect)** | ❌ Service tickets are in memory | ⚠️ Partial — TGTs are protected, but service tickets may still be accessible |
| **Mimikatz / credential dumping** | ❌ Full credential extraction from LSASS | ✅ Mimikatz cannot read isolated credentials |
| **NTLM relay (indirect)** | ❌ NTLM hashes available | ✅ Hashes are not accessible for relay |

> 💡 **Tip**: Credential Guard protects **derived credentials** (NTLM hashes, Kerberos tickets). It does **not** protect against keyloggers capturing passwords at input time, or against phishing.

### Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 10 Enterprise/Education, Windows 11 Enterprise/Education, Windows Server 2016+ |
| **Edition** | Enterprise or Education required (not available on Pro) |
| **Firmware** | UEFI firmware with Secure Boot |
| **TPM** | TPM 1.2 or 2.0 (TPM 2.0 recommended) |
| **Virtualization** | Hardware virtualization (Intel VT-x / AMD-V) + SLAT (Intel EPT / AMD RVI) |
| **Hyper-V** | Hyper-V role must be available (installed automatically when enabling VBS) |

> ⚠️ **Important**: Starting with **Windows 11 22H2** and **Windows Server 2025**, Credential Guard is **enabled by default** (without UEFI lock) on devices that meet the requirements. On Windows Server 2025, Domain Controllers are **explicitly excluded** from default enablement.
>
> 🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure

### Impact & Considerations

| Area | Impact |
|---|---|
| **NTLM v1** | ⚠️ **SSO blocked** — NTLMv1 single sign-on no longer works. Users are forced to enter credentials manually. Consider eliminating NTLMv1 entirely. |
| **Unconstrained delegation** | ❌ **Broken** — Credential Guard blocks TGT delegation. Use **constrained** or **resource-based constrained delegation** instead. |
| **MS-CHAPv2 / CredSSP** | ⚠️ **SSO blocked** — Single sign-on for MS-CHAPv2 (PEAP-MSCHAPv2, EAP-MSCHAPv2) and CredSSP is blocked. Manual credential entry still works. Move to certificate-based auth (PEAP-TLS, EAP-TLS). |
| **Kerberos DES encryption** | ❌ **Blocked** — DES-based Kerberos is not supported. |
| **Kerberos TGT extraction** | ❌ **Blocked** — Applications that require extracting Kerberos TGTs (e.g. Java GSS API) will fail. |
| **Digest authentication** | ⚠️ **SSO blocked** — WDigest single sign-on is blocked; users are prompted for credentials. Plaintext credential caching is also prevented. |
| **DPAPI (machine)** | ⚠️ Machine DPAPI works but user DPAPI-protected data loaded at boot may have caveats. |
| **Third-party SSPs** | ❌ **Blocked** — Custom Security Support Providers cannot load into LSASS. |
| **Performance** | Low — VBS adds minimal overhead (~1-2% CPU). May be more noticeable on older hardware. |

> ⚠️ **Critical**: Before enabling Credential Guard, **audit your environment for unconstrained delegation** and legacy protocols. Use tools like:
> ```powershell
> # Find computers with unconstrained delegation
> Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
>     Select-Object Name, DNSHostName, TrustedForDelegation
>
> # Find users with unconstrained delegation
> Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
>     Select-Object Name, SamAccountName, TrustedForDelegation
> ```

### Can I Deploy Credential Guard on Domain Controllers?

**Not recommended by Microsoft.** The official documentation explicitly states:

> ⚠️ *"Enabling Credential Guard on domain controllers isn't recommended. Credential Guard doesn't provide any added security to domain controllers, and can cause application compatibility issues on domain controllers."*

**Why doesn't it protect DCs?**

Credential Guard protects **derived credentials** in memory (NTLM hashes, Kerberos TGTs in LSASS). However, on a Domain Controller, these secrets are also stored in the **Active Directory database (NTDS.dit)** and in the **SAM**. Even with Credential Guard, an attacker with access to the DC can extract credentials directly from the AD database.

- ❌ Microsoft does **not** recommend Credential Guard on DCs
- ❌ DCs are **explicitly excluded** from default enablement on Windows Server 2025
- ❌ Credential Guard on **Exchange Server** is not supported and can lead to performance issues
- ⚠️ Can cause application compatibility issues on DCs
- 💡 To protect DCs, use instead: **LSA Protection (RunAsPPL)**, **HVCI**, **WDAC**, and tiering best practices

🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/

### How to Deploy Credential Guard

#### Option 1 — via Group Policy

1. **Open the GPMC console** (`gpmc.msc`)
2. **Create or reuse a VBS GPO**: If you already have a GPO for HVCI (e.g. `SEC - VBS and HVCI`), you can add Credential Guard in the same GPO. Otherwise, create a dedicated new GPO (e.g. `SEC - Credential Guard`)
3. **Edit the GPO** → navigate to:

```
Computer Configuration
  → Administrative Templates
    → System
      → Device Guard
        → Turn On Virtualization Based Security
```

4. **Enable the setting** → select **Enabled** (if not already done)
5. **Configure Credential Guard options**:

| Option | Recommended value | Description |
|---|---|---|
| **Select Platform Security Level** | `Secure Boot and DMA Protection` | Same as for HVCI. |
| **Credential Guard Configuration** | `Enabled with UEFI lock` (prod) or `Enabled without lock` (test) | Enables Credential Guard. The UEFI lock protects against remote disabling. |
| **Secure Launch Configuration** | `Enabled` (if supported) | Enables System Guard Secure Launch for additional boot-time protection. |

6. **Click OK** → close the editor
7. **Filter the scope**:
   - **Never link this GPO to the Domain Controllers OU** (not recommended by Microsoft)
   - Link the GPO to the workstations / member servers OU
   - Use **Security Filtering** to target a pilot group first (e.g. `GRP-CredGuard-Pilot`)
   - Or use a **WMI Filter** to target Enterprise edition machines only: 
     ```
     SELECT * FROM Win32_OperatingSystem WHERE Caption LIKE "%Enterprise%"
     ```

> 💡 **Tip**: Use **“Enabled without lock”** during testing — with the UEFI lock, you need physical access (or firmware intervention) to disable Credential Guard. During testing, you want to be able to roll back via GPO or registry.

> ⚠️ **Important**: If you enable Credential Guard **and** HVCI, both can be configured in the **same GPO** under the same “Turn On Virtualization Based Security” setting. No need for 2 separate GPOs.

#### Option 2 — via Registry

```powershell
# Enable VBS
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
    -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord

# Enable Credential Guard
# 1 = Enabled with UEFI lock (strongest, requires physical presence to disable)
# 2 = Enabled without lock (can be disabled remotely — recommended for testing)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LsaCfgFlags" -Value 2 -Type DWord

# Restart required
Restart-Computer
```

#### Option 3 — via Intune / MDM

Use the **Endpoint Security** > **Account Protection** profile, or a custom OMA-URI policy with **two settings** :

```
# Enable VBS
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceGuard/EnableVirtualizationBasedSecurity
Type: Integer
Value: 1

# Enable Credential Guard
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/DeviceGuard/LsaCfgFlags
Type: Integer
Value: 1 (UEFI lock) or 2 (without lock)
```

🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure

### How to Verify Credential Guard Is Running

```powershell
# Method 1: System Information
# Run msinfo32.exe → System Summary
# Look for "Virtualization-based security Services Running"
# Should include: "Credential Guard"

# Method 2: PowerShell / WMI
(Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning
# Returns an array of running services:
# 1 = Credential Guard
# 2 = HVCI
# 3 = System Guard Secure Launch
# 4 = SMM Firmware Measurement
# If 1 is in the array → Credential Guard is running

# Method 3: Check Event Log (WinInit events in System log)
Get-WinEvent -LogName "System" | Where-Object {
    $_.ProviderName -eq "Wininit" -and $_.Id -in @(13, 14, 15, 16, 17)
} | Select-Object TimeCreated, Id, Message -First 5
# Event ID 13: "Credential Guard (LsaIso.exe) was started and will protect LSA credentials."
# Event ID 14: "Credential Guard (LsaIso.exe) configuration: [0x0|0x1|0x2], 0"
#   First variable: 0x1 or 0x2 = configured to run. 0x0 = not configured.
#   Second variable: 0 = protect mode, 1 = test mode.
# Event ID 15 (Warning): Credential Guard configured but secure kernel not running
# Event ID 16 (Warning): Credential Guard failed to launch
# Event ID 17 (Error): Error reading Credential Guard UEFI configuration
```

---

## 🔒 LSA Protection (RunAsPPL)

### What Is LSA Protection?

**LSA Protection** — also known as **RunAsPPL** (Protected Process Light) — configures the **Local Security Authority (LSA)** process (`lsass.exe`) to run as a **Protected Process Light (PPL)**. This means that only digitally signed code (by Microsoft) can load into or interact with the LSASS process.

🔗 https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection

### What Does It Protect Against?

| Threat | Protection |
|---|---|
| **Mimikatz / credential dumping** | ✅ Blocks unsigned code from reading LSASS memory |
| **DLL injection into LSASS** | ✅ Only Microsoft-signed DLLs can load into LSASS |
| **Memory scraping** | ✅ Protected Process Light prevents standard process memory reads |
| **Unsigned SSP/AP packages** | ✅ Custom Security Support Providers must be signed |

> ⚠️ **Important**: LSA Protection is **not a silver bullet**. A sufficiently privileged attacker (e.g., with kernel-level access or a vulnerable signed driver) can potentially bypass PPL. Credential Guard provides stronger isolation using hardware-based virtualization. **Use both together** for defense in depth.

### Requirements

| Requirement | Details |
|---|---|
| **OS** | Windows 8.1+ / Windows Server 2012 R2+ |
| **Hardware** | No specific hardware requirements |
| **UEFI (recommended)** | UEFI with Secure Boot recommended to enable persistent PPL protection via firmware |
| **Edition** | All editions (Pro, Enterprise, Education, Server) |

### Impact & Considerations

| Area | Impact |
|---|---|
| **Third-party LSASS plugins** | ❌ **Blocked** — Unsigned DLLs that hook into LSASS (some old AV, smart card middleware, password filters, custom SSPs) will be blocked. |
| **Password filters** | ⚠️ Must be **Microsoft-signed** or they will fail to load. |
| **Smart card drivers** | ⚠️ Some older smart card middleware may be blocked. |
| **Performance** | Negligible — No measurable performance impact. |
| **WDigest** | Plaintext credential caching is blocked (same as disabling WDigest via registry). |
| **Audit mode** | Available on **Windows 11 22H2+** and **Windows Server 2025** — logs what would be blocked without actually blocking. |

> 💡 **Tip**: On **Windows 11 22H2+**, LSA Protection audit mode is **enabled by default**. The audit logs plugins/drivers that would fail to load under LSA Protection. Check event log: `Microsoft-Windows-CodeIntegrity/Operational`:
> - **Audit mode** (Events **3065** and **3066**): Logged when a plug-in/driver doesn't meet signing requirements but is still allowed to load
> - **Enforcement mode** (Events **3033** and **3063**): Logged when a plug-in/driver is actually blocked from loading into LSASS

### Can I Deploy LSA Protection on Domain Controllers?

**Yes, absolutely.** LSA Protection is strongly recommended on Domain Controllers:

- ✅ **Fully supported** on Windows Server 2012 R2 and later
- ✅ **Low risk** on DCs — Domain Controllers typically run only Microsoft-signed components
- ✅ **Quick wins** — Simple registry change, minimal compatibility concerns on clean DC installations
- ⚠️ Validate that no third-party password filters, custom SSPs, or unsigned plugins are used on the DC
- 💡 This should be one of the **first hardening steps** on any DC (Tier 0 asset)

### How to Deploy LSA Protection

#### Option 1 — via GPO Registry Preferences (All OS versions)

For OS versions **prior to Windows 11 22H2** (no native GPO setting), use **GPO Preferences** to push the registry key:

1. **Open the GPMC console** (`gpmc.msc`)
2. **Create a new GPO**: right-click the target OU → *Create a GPO in this domain, and Link it here...*
   - Name the GPO: e.g. `SEC - LSA Protection (RunAsPPL)`
3. **Edit the GPO** → navigate to:

```
Computer Configuration
  → Preferences
    → Windows Settings
      → Registry
```

4. **Right-click → New → Registry Item** and configure:

| Field | Value |
|---|---|
| **Action** | `Update` |
| **Hive** | `HKEY_LOCAL_MACHINE` |
| **Key Path** | `SYSTEM\CurrentControlSet\Control\Lsa` |
| **Value name** | `RunAsPPL` |
| **Value type** | `REG_DWORD` |
| **Value data** | `1` (with UEFI variable) or `2` (without UEFI variable — Win 11 22H2+ only) |

5. **Click OK** → close the editor
6. **A reboot is required** for the protection to take effect

> 💡 **Tip**: You can also use **Item-Level Targeting** in Preferences to target a specific security group or OS, enabling a progressive rollout.

Or via PowerShell locally / GPO startup script:

```powershell
# Enable LSA Protection (RunAsPPL)
# 1 = with UEFI variable (cannot be disabled without physical access)
# 2 = without UEFI variable (Win 11 22H2+ only — can be disabled via registry)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord
```

#### Option 2 — via Group Policy Native Setting (Windows 11 22H2+ / Server 2025)

On recent OS versions, a native GPO setting is available with advanced options (audit mode, UEFI lock):

1. **Open the GPMC console** (`gpmc.msc`)
2. **Create a new GPO** (or reuse the existing LSA GPO): e.g. `SEC - LSA Protection`
3. **Edit the GPO** → navigate to:

```
Computer Configuration
  → Administrative Templates
    → System
      → Local Security Authority
        → Configure LSASS to run as a protected process
```

4. **Enable the setting** → select **Enabled**
5. **Choose the mode** from the dropdown:

| Mode | Value | Description |
|---|---|---|
| **Enabled with UEFI Lock** | Strongest | Protection cannot be disabled remotely — requires physical access. Recommended for production. |
| **Enabled without UEFI Lock** | Medium | Protection active but can be disabled via registry. Useful for testing. |
| **Audit Mode** | Test only | Blocks nothing — only logs DLLs that would be blocked. Available only on Windows 11 22H2+ and Server 2025. |

6. **Click OK** → close the editor
7. **A reboot is required** after the GPO is applied

> 💡 **Tip**: Recommended deployment strategy:
> 1. Deploy in **Audit Mode** for 2-4 weeks
> 2. Check Event IDs **3065** and **3066** in `Microsoft-Windows-CodeIntegrity/Operational` (audit mode)
> 3. Resolve identified incompatibilities
> 4. Switch to **Enabled without UEFI Lock** — enforcement events become **3033** and **3063**
> 5. After validation, switch to **Enabled with UEFI Lock**

#### Option 3 — via Intune / MDM

```
OMA-URI: ./Device/Vendor/MSFT/Policy/Config/LocalSecurityAuthority/ConfigureLsaProtectedProcess
Value: 1 (Enabled with UEFI lock) or 2 (Enabled without lock)
```

### How to Verify LSA Protection Is Active

```powershell
# Method 1: Check registry value
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" |
    Select-Object RunAsPPL
# Value 1 = Enabled

# Method 2: Check via Task Manager
# Open Task Manager → Details tab → right-click column headers → Select Columns → add "Protection"
# The lsass.exe process should show "PsProtectedSignerLsa-Light" when PPL is enabled.
# If it shows empty or "None", LSA Protection is not active.

# Method 3: Check event log for LSA protection status
# Event ID 12 from WinInit in the System log
Get-WinEvent -LogName "System" | Where-Object {
    $_.ProviderName -eq "Wininit" -and $_.Id -eq 12
} | Select-Object TimeCreated, Message -First 5
# Event ID 12: "LSASS.exe was started as a protected process with level: 4"
# Level 4 = PsProtectedSignerLsa-Light (PPL enabled)
```

---

## 📊 Comparison Matrix

| Feature | WDAC | HVCI | Credential Guard | LSA Protection (PPL) |
|---|---|---|---|---|
| **What it protects** | Application execution | Kernel code integrity | Credentials in memory | LSA process integrity |
| **Protection type** | Whitelisting / code integrity | VBS-isolated kernel verification | VBS credential isolation | Protected Process Light |
| **Hardware requirements** | None | UEFI, VT-x, SLAT | UEFI, TPM, VT-x, SLAT | None |
| **OS editions** | All | All | Enterprise / Education | All |
| **Minimum OS** | Windows 10 / Server 2016 | Windows 10 / Server 2016 | Windows 10 / Server 2016 | Windows 8.1 / Server 2012 R2 |
| **Supported on DCs** | ✅ Yes | ✅ Yes | ⚠️ Supported but not recommended | ✅ Yes (Server 2012 R2+) |
| **Deployment complexity** | 🔴 High | 🟡 Medium | 🟡 Medium | 🟢 Low |
| **Audit mode available** | ✅ Yes | ❌ No | ❌ No | ✅ Yes (Win 11 22H2+) |
| **Block credential theft** | ❌ Not directly | ❌ Not directly | ✅ Primary purpose | ✅ Basic protection |
| **Block malware execution** | ✅ Primary purpose | ✅ Kernel level | ❌ Not directly | ❌ Not directly |
| **Block vulnerable drivers** | ⚠️ With driver policies | ✅ Primary purpose | ❌ Not directly | ❌ Not directly |
| **Impact on legacy apps** | 🔴 High | 🟡 Medium (drivers) | 🟡 Medium | 🟢 Low |
| **Rollback difficulty** | 🟢 Easy (audit mode) | 🟡 Medium (UEFI lock) | 🟡 Medium (UEFI lock) | 🟢 Easy |

---

## 🏗️ Deployment Strategy & Recommendations

### Recommended Deployment Order

For most organizations, the recommended deployment order is:

```
Phase 1: LSA Protection (RunAsPPL)
  → Low risk, high value, easy to deploy
  → Deploy on DCs first, then all servers, then workstations

Phase 2: Credential Guard
  → Medium complexity, high value for workstations and member servers
  → Deploy on admin workstations first (PAWs)
  → Then extend to all Enterprise edition machines
  → Do NOT deploy on Domain Controllers (not recommended by Microsoft)

Phase 3: HVCI (Memory Integrity)
  → Medium complexity, protects kernel integrity
  → Deploy on DCs and PAWs first
  → Extend to all compatible machines
  → Validate driver compatibility beforehand

Phase 4: WDAC (Application Control)
  → High complexity, very high value
  → Start with DCs (well-defined application set)
  → Extend to servers, then workstations
  → Always use Audit mode first
```

### Tiering Model Alignment

| Tier | LSA Protection | Credential Guard | HVCI | WDAC |
|---|---|---|---|---|
| **Tier 0** (DCs, AD infra) | ✅ Must have | ❌ Not recommended on DCs | ✅ Strongly recommended | ✅ Recommended |
| **Tier 1** (Servers) | ✅ Must have | ✅ Recommended | ✅ Recommended | 🟡 Evaluate per server role |
| **Tier 2** (Workstations) | ✅ Recommended | ✅ Recommended (Enterprise) | ✅ Recommended | 🟡 Complex but ideal |
| **PAWs** | ✅ Must have | ✅ Must have | ✅ Must have | ✅ Must have |

### Pre-Deployment Checklist

Before deploying any of these features:

1. **Inventory applications** — Identify all software running on target machines
2. **Audit delegation** — Find all unconstrained delegation objects in AD
3. **Audit LSASS plugins** — Identify any third-party DLLs loaded into LSASS
4. **Audit legacy protocols** — Check for NTLMv1, DES Kerberos, WDigest usage
5. **Test in audit mode** — Use audit mode before enforcement
6. **Plan rollback** — Know how to disable each feature in case of issues
7. **Communicate** — Inform application owners and help desk

```powershell
# Quick pre-deployment audit script

Write-Host "=== Unconstrained Delegation Objects ===" -ForegroundColor Cyan
Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object Name, DistinguishedName

Get-ADUser -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Select-Object Name, DistinguishedName

Write-Host "`n=== LSASS Loaded Modules ===" -ForegroundColor Cyan
# Note: requires elevation. Will fail if LSA Protection (PPL) is already enabled.
try {
    Get-Process lsass -ErrorAction Stop | Select-Object -ExpandProperty Modules |
        Where-Object { $_.FileVersionInfo.CompanyName -notlike "*Microsoft*" } |
        Select-Object FileName, @{N='Company';E={$_.FileVersionInfo.CompanyName}},
            @{N='Description';E={$_.FileVersionInfo.FileDescription}}
} catch {
    Write-Host "Cannot read LSASS modules (access denied — PPL may already be enabled)" -ForegroundColor Yellow
}

Write-Host "`n=== LSA Protection Status ===" -ForegroundColor Cyan
try {
    $runAsPPL = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction Stop).RunAsPPL
    Write-Host "RunAsPPL: $runAsPPL" -ForegroundColor $(if ($runAsPPL -eq 1) { "Green" } else { "Red" })
} catch {
    Write-Host "RunAsPPL: Not configured" -ForegroundColor Yellow
}

Write-Host "`n=== Credential Guard Status ===" -ForegroundColor Cyan
$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($dg) {
    Write-Host "VBS Status: $($dg.VirtualizationBasedSecurityStatus)"
    Write-Host "Services Running: $($dg.SecurityServicesRunning -join ', ')"
} else {
    Write-Host "Device Guard WMI class not available" -ForegroundColor Yellow
}
```

---

## ⚠️ Common Pitfalls

1. **Enabling Credential Guard with unconstrained delegation** — Applications relying on unconstrained Kerberos delegation will break. Audit delegation objects first.

2. **Forgetting about third-party LSASS plugins** — Password filters, custom SSPs, smart card middleware, and some AV products inject DLLs into LSASS. These will be blocked by LSA Protection.

3. **Enabling WDAC in enforce mode without proper testing** — This can lock users out of their machines. Always start with Audit mode and analyze logs extensively.

4. **UEFI Lock with no rollback plan** — Enabling Credential Guard or LSA Protection with UEFI lock means you need **physical access** (or firmware tools) to disable it. Use "without lock" mode during initial rollout.

5. **Ignoring NTLMv1 dependencies** — Credential Guard blocks NTLMv1 single sign-on. Old network printers, legacy applications, or misconfigured Linux/Samba clients relying on NTLMv1 SSO will require manual credential entry or will break.

6. **Not monitoring event logs after deployment** — Always monitor the relevant event logs for at least 2 weeks after enabling any feature:
   - Code Integrity / WDAC / LSA: `Microsoft-Windows-CodeIntegrity/Operational` (3076, 3077 for WDAC ; 3065, 3066 for LSA audit ; 3033, 3063 for LSA enforcement)
   - Credential Guard: `System` log, source `Wininit` (Event IDs 13, 14, 15, 16, 17)

7. **Enabling Credential Guard on Domain Controllers** — Microsoft explicitly states that Credential Guard **does not provide additional security on DCs** (credentials are also in NTDS.dit) and can cause compatibility issues. Do not enable it on DCs. Similarly, Credential Guard is **not supported on Exchange Server** and can lead to performance issues.

8. **Virtual machines without nested virtualization** — Credential Guard and HVCI require virtualization. VMs on Hyper-V need nested virtualization. VMs on VMware require the `Virtualize Intel VT-x/EPT` option. Hyper-V VMs must be **Generation 2** (Gen 1 VMs are not supported). The Hyper-V host must have an **IOMMU** (Intel VT-d / AMD-Vi).

9. **Live Migration with Hyper-V on Windows Server 2025** — Credential Guard blocks CredSSP-based delegation, which is the default method for Hyper-V Live Migration on Server 2022 and earlier. After upgrading to Server 2025 (where Credential Guard is enabled by default), Live Migration may fail. Switch to **Kerberos Constrained Delegation** or **Resource-Based Kerberos Constrained Delegation** for Live Migration.

---

## 📚 References

- 🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol — WDAC / App Control Overview
- 🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ — Credential Guard
- 🔗 https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection — LSA Protection
- 🔗 https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity — HVCI / VBS
- 🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues — Credential Guard Considerations & Known Issues
- 🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure — Configure Credential Guard (GPO, Intune, Registry)
- 🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/appcontrol-wizard — App Control Policy Wizard Tool
- 🔗 https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management — Credentials Protection Overview
- 🔗 https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules — Microsoft Recommended Driver Block Rules (HVCI)

# 🌐 Microsoft Global Secure Access - Overview
🗓️ Published: 2025-05-28

## 🔰 Introduction

This lab is designed to help you understand the modern shift from traditional perimeter-based security to a cloud-delivered, identity-centric model, using Microsoft’s Security Service Edge (SSE) solution. 

With the rise of SaaS, remote work, BYOD, and hybrid cloud environments, legacy network security architectures are no longer sufficient. Microsoft Entra Internet Access and Microsoft Entra Private Access are part of this new approach to secure access, built around Zero Trust principles.

---

## 🧩 Section 1 - Why Traditional Network Security Falls Short

### 🔎 Legacy model limitations

In traditional enterprise networks:
- Users were on-site.
- Applications were hosted in on-premises datacenters.
- Security was enforced at the network perimeter using firewalls, proxies, VPNs.

But now:
- Users are remote and mobile.
- Apps are in the cloud (IaaS, SaaS, PaaS).
- Devices include personal/BYOD and unmanaged endpoints.

### 🔥 Consequences

- **Network congestion**: Massive increase in internet-bound traffic strains VPNs and on-prem appliances.
- **Hair-pinning**: Traffic from remote users is routed back to corporate before going out to the internet, degrading performance.
- **Shadow IT**: Users bypass controls and access cloud resources directly.
- **Lateral movement**: A compromised device inside the network can spread easily due to flat network topology.

![](assets/Global%20Secure%20Access/2025-05-28-14-33-44.png)

---

## 🔄 Section 2 - Why a New Security Approach is Needed

Legacy network security cannot be fixed by adding more hardware or policies. A fundamental shift is needed to handle modern business, user, and threat realities.

### 🌐 1. Digital Business Transformation
- Apps are hosted across multiple clouds (IaaS, SaaS, PaaS).
- Businesses need to collaborate securely with partners, suppliers, and contractors.
- Mergers and acquisitions increase IT complexity and require multi-cloud/multi-tenant strategies.

### 🧳 2. Work from Anywhere
- Users expect fast, seamless access to resources from any device, anywhere.
- Backhauling traffic through the corporate network introduces latency and creates bottlenecks.
- VPNs are rigid and don’t scale well with hybrid work scenarios.

### ⚠️ 3. Evolving Threat Landscape
- Threats are more sophisticated and identity-driven (e.g., token theft, MFA fatigue).
- VPNs lack the granular control needed to contain compromise.
- Organizations require real-time visibility and conditional access enforcement to minimize risk.

> 💡 A new approach must combine cloud-native networking, identity-aware access controls, and global scalability—delivered through Security Service Edge (SSE).

---

## 🧱 Section 3 - Understanding SASE and SSE

### 🛡️ What is SSE?
**Security Service Edge (SSE)** is the security portion of SASE. It provides a set of integrated, cloud-centric security capabilities including:

| Capability | Description |
|------------|-------------|
| SWG (Secure Web Gateway) | Inspects and filters web traffic. |
| ZTNA (Zero Trust Network Access) | Replaces VPN with granular, identity-based access. |
| CASB (Cloud Access Security Broker) | Enforces policies on SaaS usage and data. |
| FWaaS (Firewall as a Service) | Network-level security delivered from the cloud. |
| RBI, TLS Inspection | Threat protection, visibility into encrypted traffic. |

### 🔐 What is SASE?
**Secure Access Service Edge (SASE)** is an architecture that combines:
- **SD-WAN capabilities**: intelligent routing, WAN optimization, quality of service, etc.
- **Security Service Edge (SSE)**: identity-aware, cloud-delivered security services.

This model aims to converge networking and security in a single, globally distributed platform.

### 🎯 Microsoft’s Approach
Microsoft delivers **SSE with a strong identity foundation**, deeply integrated with:
- **Microsoft Entra Conditional Access**
- **Continuous Access Evaluation (CAE)**
- **Device and user risk signals** from Microsoft Defender and Entra ID

This identity-centric SSE ensures consistent policy enforcement and user experience across:
- Cloud apps (SaaS, M365)
- Internet access
- Private apps (on-prem or IaaS hosted)

![](assets/Global%20Secure%20Access/2025-05-28-14-35-59.png)

---

## 🧭 Section 4 - Key Benefits of Microsoft’s Identity-Centric SSE

Microsoft's Security Service Edge solution provides a comprehensive and scalable foundation for securing access to any application or resource.

### 🧩 Core Concepts

1. **Identity-driven security enforcement**  
   Leverages Conditional Access and Continuous Access Evaluation (CAE) to enforce policies dynamically based on user, device, risk, and context.

2. **Cloud-native and globally distributed**  
   Built on Microsoft’s worldwide backbone, minimizing latency and eliminating the need for traditional on-prem appliances.

3. **Unified access policy model**  
   One engine to manage access to all types of resources—SaaS, Microsoft 365, private applications—with consistent governance.

4. **High performance and resilience**  
   Global network presence, intelligent traffic routing, multiple failover rings, built-in DDoS protection, and encrypted micro-tunnel architecture.

5. **Third-party compatibility**  
   Entra Internet Access and Private Access can be deployed side-by-side with other SSE or SASE vendors.

6. **Two key services in the Microsoft SSE offering:**  
   - **Microsoft Entra Internet Access**: Protects user access to the public internet and SaaS apps. Enables conditional access enforcement on outbound internet traffic.
   - **Microsoft Entra Private Access**: Provides secure Zero Trust access to private apps (on-prem or IaaS), replacing legacy VPNs.

![](assets/Global%20Secure%20Access/2025-05-28-14-38-18.png)


   These services support both **client-based** and **branch network** connectivity models, enabling flexible, phased rollout scenarios.


![](assets/Global%20Secure%20Access/2025-05-28-14-39-16.png)

---

## 🌐 Section 5 - Microsoft Entra Internet Access

Microsoft Entra Internet Access is a Secure Web Gateway (SWG) solution delivered as part of Microsoft’s SSE. It enforces policy and protection on outbound internet traffic, ensuring users are safe, productive, and compliant.

### 🔐 Key Capabilities
- **Conditional Access for Internet traffic**, extended with **network conditions** (IP, location, protocol, port)
- **User, device, risk, and location-based adaptive access controls**
- **Web content filtering** based on categories and FQDNs
- **Threat intelligence filtering** (Microsoft and 3rd party sources)
- **TLS termination and deep packet inspection**, including certificate management via Azure Key Vault
- **Granular traffic controls**: filter by **port**, **protocol**, **IP range**, **FQDN**
- **Compliant network checks** and **source IP restoration** for enhanced log fidelity
- **Protection against token replay** (including refresh token abuse) and **data exfiltration scenarios** (e.g., upload to unauthorized services)
- **Tenant Restrictions v2 (TRv2)** to block access to personal or unauthorized Microsoft accounts from corporate networks

### 📊 Monitoring and Reporting
- Real-time visibility into traffic: users, devices, destinations, methods, bytes transferred
- Enriched sign-in logs with original source IP attribution
- Tenant-level audit via Universal TR logs
- Drill-down dashboards and filtering in the Entra portal
- Export to Microsoft Sentinel, Log Analytics, or third-party SIEMs
- Configurable alerts on critical risk events and anomalous behaviors via Microsoft Sentinel or Defender, enabling proactive security operations

### ⚙️ Deployment Models
- Compatible with both **client-based** (device agent) and **network-based** (e.g., VPN gateway, router) forwarding
- Can be deployed gradually to specific users, groups, or locations

### 🧩 Microsoft Services Scenario (Included in Entra ID P1)
A subset of Entra Internet Access is available **at no additional cost** for Microsoft services traffic:
- Applies Conditional Access to Microsoft 365 traffic
- Supports Tenant Restrictions v2 and CAE for enhanced control
- Provides **source IP preservation** and **enriched logs** for forensic and compliance use cases

> 💡 Entra Internet Access extends Zero Trust controls to web and SaaS traffic, offering full-featured inspection, adaptive policy, and visibility—all without additional on-prem hardware.

![](assets/Global%20Secure%20Access/2025-05-28-14-41-13.png)
---

## 🔒 Section 6 - Microsoft Entra Private Access

Microsoft Entra Private Access is a modern alternative to VPN, built on Zero Trust principles. It provides secure, identity-aware access to internal applications—whether hosted on-premises or in private clouds—without exposing the network.

### 🔐 Key Capabilities
- **Zero Trust Network Access (ZTNA)** for internal apps (HTTP/S, RDP, SSH, SMB, etc.)
- **Conditional Access** with user, device, risk, and location signals
- **SSO and CAE integration** for seamless user experience and session policy enforcement
- **Granular segmentation**: allow access to specific apps and protocols, not entire networks
- **Support for wildcard FQDNs and SPN-based segmentation** (e.g., *.corp.contoso.com, smb://finance-server)
- **App discovery and auto-onboarding** to identify private app traffic and simplify policy definition
- **Token replay protection** and **TLS inspection** to mitigate session hijack and exfiltration attempts

### 🧩 Application and User Experience
- Quick Access capability for one-click app launches
- Native SSO across private apps
- Consistent experience across platforms (Windows, macOS, Android, iOS)
- Compatible with both hybrid join and Entra ID joined devices

### 🧰 Deployment and Operations
- Agent-based and network-based traffic forwarding models
- App segmentation defined by FQDN, IP, protocol, port
- Policy assignment based on groups, device compliance, and user risk
- Visibility and diagnostics integrated into Entra and Defender portals

> 🧠 Entra Private Access helps reduce lateral movement and enforce least privilege by controlling exactly which applications a user can access, not just which networks.

![](assets/Global%20Secure%20Access/2025-05-28-14-42-23.png)
---

## 🏗️ Section 7 - Architecture & Prerequisites

This section outlines the technical foundation and deployment options for Microsoft Entra Internet Access and Microsoft Entra Private Access.

### 🔧 Technical Prerequisites

#### Identity Platform
- Microsoft Entra ID (formerly Azure AD)
- Entra ID P1 or P2 licenses
- Devices hybrid-joined or Entra-joined

#### Entra Internet Access
- Supported OS (Windows 10/11, macOS)
- Client agent installation (or network-based forwarding)
- Outbound HTTPS/TLS connectivity
- TLS inspection certificate authority (optional)

#### Entra Private Access
- Agent-based or network-based app traffic forwarding
- Support for app protocols: HTTP(S), RDP, SSH, SMB, etc.
- DNS resolution internal or hybrid
- Application segmentation defined by FQDN/IP/Port

---

### 🏛️ Deployment Topologies

Microsoft supports flexible, phased rollouts:
- **Pilot groups** by user or department
- **Per-app enablement** for internal resources
- **Branch or campus** integration via network connector

### 🧩 Coexistence and Integration
- Can run side-by-side with 3rd party SWG/ZTNA solutions
- Compatible with existing VPNs (parallel rollout)
- Integrated with Microsoft Defender for Endpoint, Microsoft Sentinel

---

## 🔗 References

- [Microsoft Entra Internet Access](https://learn.microsoft.com/en-us/entra/global-secure-access/internet-access/overview)
- [Microsoft Entra Private Access](https://learn.microsoft.com/en-us/entra/global-secure-access/private-access/overview)
- [Global Secure Access documentation](https://learn.microsoft.com/en-us/entra/global-secure-access/overview)
- [Microsoft Entra licensing plans](https://www.microsoft.com/licensing/)
- [Azure Marketplace: Entra SSE](https://azuremarketplace.microsoft.com)

> 🧭 With Microsoft Entra SSE, you can implement Zero Trust without compromise—providing strong security, improved performance, and a seamless user experience.
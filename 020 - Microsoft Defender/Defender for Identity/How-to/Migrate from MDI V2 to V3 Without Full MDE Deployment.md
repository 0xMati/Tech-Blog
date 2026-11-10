---
title: "Migrate from MDI V2 to V3 Without Full MDE Deployment"
date: 2026-11-10
---

# Migrate from MDI V2 to V3 Without Full MDE Deployment

## Introduction

Your domain controllers are running Microsoft Defender for Identity (MDI) V2. You want V3, but rolling out Microsoft Defender for Endpoint (MDE) is not on today's menu. The portal says **Not ready for migration**. End of the quest? Not quite.

The [built-in V2-to-V3 migration](https://learn.microsoft.com/en-us/defender-for-identity/deploy/migrate-to-sensor-v3) requires MDE. Here, we'll explore a different route: **uninstall the V2 sensor, then deploy V3 in identity-only mode** using the [dedicated onboarding package](https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor#onboard-a-server-without-defender-for-endpoint-deployment). That package supports eligible servers without a V2 sensor installed. This is a **manual replacement**, not an in-place upgrade: expect a gap in MDI monitoring on the DC being switched.

One important catch: **without full MDE does not mean without MDE plumbing**. V3 still uses the Windows **Sense** platform and needs access to the required MDE cloud endpoints. The package activates identity protection, not the full MDE experience.

We'll work through the prerequisites, network and proxy configuration, sensor replacement, and checks that confirm V3 is actually collecting data. One DC at a time. No big-bang adventure.

---

## V2 vs V3: same mission, different engine

As of **November 10, 2026**. Sources: [deployment guidance](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity) and [V3 prerequisites](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3).

| Area | V2 | V3, including identity-only mode | What changes for you |
| --- | --- | --- | --- |
| Sensor platform | Dedicated sensor and updater | Windows Sense | Allow Sense even without a full MDE rollout. |
| Operating system | Supported legacy servers, including Windows Server 2016, and existing newer-server deployments | Windows Server 2019 or later, with the required CU | Keep V2 on servers that cannot run V3. |
| AD access and response accounts | DSA/gMSA and action account configuration | LocalSystem only | Review the workspace-wide action account setting; retain credentials needed by V2. |
| Resource management | V2 capacity planning and sizing | Caps: 30% CPU and 1.5 GB RAM | Not minimum server specifications. Reaching caps can throttle processing or restart the sensor. |
| Cloud connectivity | MDI workspace endpoint | MDE service endpoints | Review firewall, proxy, DNS, and routing. |
| ExpressRoute | Microsoft peering with MDI BGP community `12076:5220` | No MDE ExpressRoute integration | Use direct or proxy HTTPS egress for this guide. |
| Alert formats | Classic and Defender-format | Both formats too | Format does not identify sensor version. Review SOC rules and tuning. |
| VPN integration (RADIUS accounting) | Supported | Not supported | Keep V2 where this integration is required. |
| Syslog notifications | Supported | Not supported | Replace any syslog-dependent SOC ingestion path before switching. |

### ExpressRoute: use direct or proxy HTTPS egress for V3

**V2** supports the Microsoft peering route described in the [V2 network requirements](https://learn.microsoft.com/en-us/defender-for-identity/deploy/prerequisites-sensor-version-2#network-requirements).

**V3** uses MDE infrastructure, which has [no ExpressRoute integration](https://learn.microsoft.com/en-us/microsoft-365/enterprise/azure-expressroute#what-microsoft-365-services-are-included). **For this guide, route V3 cloud traffic through approved direct or proxy HTTPS egress, not ExpressRoute.** Customer-maintained ExpressRoute routing is possible but outside this guide's scope.

Before removing V2:

- Review the [endpoint matrix](#v2-to-v3-cloud-endpoint-matrix) and full Microsoft lists.
- Bypass TLS inspection for `*.endpoint.security.microsoft.com`, as required by the [MDE connectivity guidance](https://learn.microsoft.com/en-us/defender-endpoint/configure-environment).

### V2-to-V3 cloud endpoint matrix

**Scope:** Outbound cloud traffic for eligible Windows Servers in the commercial cloud, using V3 identity-only onboarding with **streamlined connectivity** (consolidated MDE service URLs). Internal AD traffic and government clouds are excluded.

| Outbound traffic | V2 | V3 identity-only, streamlined | Action |
| --- | --- | --- | --- |
| Core cloud service - HTTPS 443 | `<workspace-name>sensorapi.atp.azure.com` | `*.endpoint.security.microsoft.com` | **Add** V3 access. **Keep** V2 rules for remaining sensors and rollback. |
| Certificate revocation and trust lists - HTTP 80 | `crl.microsoft.com`, `ctldl.windowsupdate.com` | Same endpoints | **Keep / Review** existing access or centralized trust management. |
| Microsoft PKI - HTTP 80 | `www.microsoft.com/pki/*`, `www.microsoft.com/pkiops/*` | Same endpoints | **Keep / Review** certificate-validation access. |
| Windows updates | Existing Windows update setup | Windows updates also maintain Sense components used by V3 | **Review** how the DC receives Windows updates: directly from Microsoft, or through an internal service such as WSUS or ConfigMgr. |

**Not an exhaustive allowlist.** Check the applicable Windows, update, and certificate endpoints in the full lists:

- [V2 service URL and certificate dependencies](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-proxy#enable-access-to-defender-for-identity-service-urls-in-the-proxy-server).
- [V3: MDE streamlined URLs](https://learn.microsoft.com/en-us/defender-endpoint/streamlined-device-connectivity-urls-commercial?tabs=Windows), as referenced by the identity-only onboarding instructions.

Use your update service's actual destinations and ports. WSUS or ConfigMgr can avoid direct Microsoft update downloads from each DC, but **do not replace MDE cloud connections**.

Allowing only `https://mdav.eu.endpoint.security.microsoft.com/packages/` is insufficient: this is one path under the core V3 domain, not all required connectivity.

### Alerts: what changes with V3?

- **MDI alerts continue:** V3 identity-only still generates alerts in the Defender portal, without a full MDE deployment.
- **The alert's appearance does not identify the sensor version:** Both V2 and V3 can contribute to classic and Defender-format alerts. Check **Sensor management** for the version, not the alert layout.
- **Syslog notifications are not supported:** If your SOC receives alerts through MDI syslog notifications, prepare another supported ingestion method before switching, or keep V2 on the affected DCs.

Sources: [alert formats](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview) and [V3 limitations](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#sensor-version-limitations).

---

## 1. Before you start

Pick **one domain controller** as your pilot. Leave V2 running during these checks.

You need an **MDI license**, local administrator access, and MDI sensor-management permissions. Check the [V3 prerequisites](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3), including VM memory requirements.

Use a DC in a **commercial tenant**. Identity-only V3 onboarding is [currently unsupported in government clouds](https://learn.microsoft.com/en-us/defender-for-identity/troubleshooting-known-issues#sensor-v3x-activation-without-defender-for-endpoint-isnt-supported-in-government-clouds).

> **Not ready for migration** concerns the built-in migration. Check identity-only eligibility separately.

### Check Windows and updates

Open **PowerShell as Administrator** on the pilot DC:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber

Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 5 HotFixID, Description, InstalledOn
```

**V3.0.10 or later** requires **Windows Server 2019 or later with the September 2026 CU or a later CU**. Match the KB and OS build to the [current requirements](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#server-requirements), not just the installation date.

### Check Windows auditing

Keep the required audit policies and AD SACLs configured. V3 can use **Settings > Identities > General > Advanced features > Automatic Windows auditing configuration**. Review its impact before enabling it: it changes local audit policies and AD SACLs, and GPO settings can conflict.

If automatic auditing is off, maintain the [required auditing settings manually](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection).

### Record the V2 baseline

```powershell
Get-Service -Name AATPSensor, AATPSensorUpdater |
    Format-Table Name, Status, StartType
```

Both services should be **Running**. Record the version and health under **Settings > Identities > On-premises > Sensor management**. Resolve existing health issues before the test.

### Check the network and proxy path

- Allow the required V3 destinations using the [endpoint matrix and linked Microsoft lists](#v2-to-v3-cloud-endpoint-matrix).
- Allow **Sense** to run and connect as **LocalSystem**. It need not already be running or onboarded to full MDE before standalone activation.
- Allow these destinations without user authentication, and bypass TLS inspection for `*.endpoint.security.microsoft.com`.

**The proxy setup changes between versions:**

- **V2:** The proxy was sensor-specific and could be supplied during installation with `ProxyUrl`, plus `ProxyUserName` and `ProxyUserPassword` if needed.
- **V3:** Sense uses a WinHTTP-based network stack. Configure its proxy **before running the standalone onboarding package**; do not assume V2 settings carry over.

**Changing the global WinHTTP proxy is not mandatory.** If a transparent proxy or automatic discovery (WPAD) already provides the required access for **LocalSystem**, no static proxy is needed. Otherwise, use a managed Sense proxy GPO or the static WinHTTP option below.

#### Manual pilot option: static WinHTTP proxy

In elevated PowerShell, inspect and record the existing proxy and bypass list:

```powershell
netsh winhttp show proxy
```

If a static WinHTTP proxy is needed, replace `proxy.contoso.com:8080` with your proxy:

```powershell
netsh winhttp set proxy "proxy.contoso.com:8080"
netsh winhttp show proxy
```

**This is system-wide:** it affects other applications and services using the default WinHTTP configuration. Review existing settings and bypass rules before replacing them; restore the recorded configuration if you roll back.

#### GPO-managed alternative

For centrally managed servers, follow the [MDE sensor static proxy GPO procedure](https://learn.microsoft.com/en-us/defender-endpoint/configure-proxy-internet#configure-an-edr-sensor-static-proxy-by-using-group-policy). The policies set these values under `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection`:

| Policy value | Type | Example data |
| --- | --- | --- |
| `TelemetryProxyServer` | `REG_SZ` | `proxy.contoso.com:8080` (host and port, without `http://`) |
| `DisableEnterpriseAuthProxy` | `REG_DWORD` | `1` |

Use the existing managed policy where applicable rather than stacking conflicting proxy settings. Certificate and Windows update access still need the paths reviewed in the endpoint matrix.

`netsh winhttp show proxy` shows only static WinHTTP settings, **not the sensor-specific GPO or connectivity**. `Direct access` does not rule out automatic discovery or a sensor proxy policy; browser access does not prove LocalSystem access.

### Check accounts and prepare the safety net

| Portal setting | Purpose | V3 |
| --- | --- | --- |
| **Directory services accounts** | Read AD data, such as accounts and groups | Uses **LocalSystem**, not the DSA/gMSA configured for V2 |
| **Manage action accounts** | Perform response actions, such as disabling accounts or resetting passwords | Uses **LocalSystem** too |

Under **Settings > Identities > Microsoft Defender for Identity > Manage action accounts**:

- **V2-only workspace:** You can retain **Manually configure your management accounts** with dedicated action accounts.
- **Before introducing the first V3 sensor:** Select **Automatically use the sensor's local system account**, even if V2 sensors remain. **Do not wait until the last V2 sensor is migrated.**

> **Workspace-wide change:** This also applies to the remaining V2 sensors. Assess their remediation actions before switching. V3 always uses LocalSystem, but Microsoft still requires automatic mode in a mixed workspace.

See Microsoft's [action account requirements](https://learn.microsoft.com/en-us/defender-for-identity/deploy/manage-action-accounts).

**Directory services accounts are separate.** Changing the action-account mode does not remove their configuration. No new DSA/gMSA is needed for V3; keep existing entries while V2 sensors depend on them, and do not remove them during this pilot.

Configured DSA/gMSA credentials remain subject to workspace-wide validation. Invalid credentials can trigger **Directory services user credentials are incorrect** health alerts even on V3 sensors that do not use those accounts. See [account requirements and mixed-version health alerts](https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-sensor-v3#service-account-requirements).

Before uninstalling, prepare:

- The V3 onboarding package.
- The V2 installer, a valid installation access key, and existing configuration for rollback.

Confirm that [V2 reinstallation is allowed in your workspace](https://learn.microsoft.com/en-us/defender-for-identity/deploy/install-sensor). New-workspace installation restrictions can prevent a V2 rollback on Windows Server 2019 or later.

Do not publish access keys. If V3 has already been activated, follow the [offboarding and rollback sequence](#6-if-needed-roll-back-to-v2) before reinstalling V2.

**Checkpoint:** Record the OS build/CU, V2 health, and network/proxy route. Resolve missing prerequisites. **Keep V2 running until step 3.**

---

## 2. Download the V3 onboarding package

In the tenant hosting your existing MDI workspace, follow the [identity-only onboarding route](https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor#onboard-a-server-without-defender-for-endpoint-deployment):

1. Open **Settings > Identities > On-premises > Sensor management**.
2. Select **Download onboarding package**.
3. Expand **Windows Server 2019 or later**, enter a package name, and select **Generate onboarding package with access key**.

   ![Generate the MDI V3 onboarding package](<./assets/Migrate from MDI V2 to V3 Without Full MDE Deployment/2026-11-10-15-34-13.png>)

4. Download the package and keep the **access key** securely.
5. Copy and extract the package on the pilot DC. Keep the **`resources` subfolder** beside the onboarding script.

The commands below use `C:\MDI\MDI-V3` as the extracted folder. Replace it with your actual path.

**Regenerating the access key invalidates the previous key for future installations.**

## 3. Remove the V2 sensor

**The MDI coverage gap on this DC starts when V2 stops.**

1. On the pilot DC, open **Programs and Features** (`appwiz.cpl`).
2. Select the **MDI V2 sensor** installation and choose **Uninstall**.

   ![Uninstall the Microsoft Defender for Identity V2 sensor](<./assets/Migrate from MDI V2 to V3 Without Full MDE Deployment/2026-11-10-16-21-06.png>)

3. Wait for removal to finish. Complete any restart requested by Windows or the uninstaller before continuing.
4. Confirm the V2 entry is gone from installed programs, then check its services:

```powershell
Get-Service -ErrorAction Stop |
    Where-Object { $_.Name -in 'AATPSensor', 'AATPSensorUpdater' } |
    Format-Table Name, Status
```

**Expected: no matching services.** If they remain, stop and finish V2 removal.

5. In **Sensor management**, select and delete the **old V2 entry** for this DC.

Deleting the portal entry alone does not uninstall V2. Follow the [Microsoft removal procedure](https://learn.microsoft.com/en-us/defender-for-identity/uninstall-sensor#delete-and-uninstall-a-sensor-v2x-from-a-domain-controller).

## 4. Onboard V3 in identity-only mode

Only continue once V2 is uninstalled and the proxy/network configuration is ready.

Open **PowerShell as Administrator** in the extracted package folder:

```powershell
Set-Location -LiteralPath 'C:\MDI\MDI-V3' -ErrorAction Stop
.\DefenderForIdentityV3StandaloneOnboardingScript.cmd
```

Enter the access key at the **masked prompt**. Keep the `resources` folder intact.

![Run the MDI V3 onboarding script and enter the access key at the masked prompt](<./assets/Migrate from MDI V2 to V3 Without Full MDE Deployment/2026-11-10-16-23-30.png>)

If the script reports an error, stop and save the exact error without exposing the key. Do not start replacing another DC.

Record the **UTC completion time** for the data check below. V3 activation itself does not require a restart.

## 5. Verify V3

### Check the sensor

On the DC:

```powershell
Get-Service -Name Sense |
    Format-Table Name, Status, StartType
```

**Sense should be Running**, but that alone does not prove MDI is reporting.

In **Sensor management**, confirm:

- The correct DC is listed with **sensor V3**.
- Its activation state is **Running**.
- Its health is healthy, or each reported issue has been investigated and resolved.

Microsoft documents up to **one hour for the first V3 activation** in an environment; subsequent activations normally appear within **five minutes**.

**Can be onboarded** in device inventory is expected for identity-only deployment. It refers to full MDE onboarding, not MDI protection.

If activation stalls, check the required CU, complete endpoint list, LocalSystem proxy access, intact package, and current access key. Use the script output and portal health issues to identify the failure.

### Check recent identity activity

In **Advanced hunting**, replace the UTC timestamp with your recorded onboarding completion time, and replace both example DC names:

```kusto
let OnboardedAt = datetime(2026-11-10T14:00:00Z);
IdentityLogonEvents
| where Timestamp > OnboardedAt and Timestamp > ago(1h)
| where DestinationDeviceName in~ ("dc01.contoso.com", "DC01")
| project Timestamp, ActionType, Protocol, AccountName, DeviceName, DestinationDeviceName
| top 20 by Timestamp desc
```

After normal AD authentication activity involving this DC, look for events **newer than onboarding**. See the [IdentityLogonEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitylogonevents-table).

![Recent Kerberos logon activity involving the pilot domain controller](<./assets/Migrate from MDI V2 to V3 Without Full MDE Deployment/2026-11-10-16-35-49.png>)

This checks recent activity involving the DC, **not the sensor version or exclusive data source**. Keep the V3 sensor and health checks above.

If no rows appear, check the names, UTC time, actual AD traffic, hunting permissions, auditing, and reporting delay. Do not treat an empty result as a successful data check.

### Check SOC workflows

- Validate any required alert-delivery path, especially if replacing syslog notifications.
- Use an approved test account to verify response actions on the V3 pilot and a remaining V2 DC after the workspace-wide action-account change.

**Move to another DC only after the pilot passes the sensor, data, and SOC checks.** Repeat steps 3-5 one DC at a time.

## 6. If needed, roll back to V2

If V3 onboarding was never started, go directly to V2 reinstallation and verification in steps 6-7 below.

If V3 was activated, **offboard identity-only V3 before reinstalling V2**. Deleting its portal entry alone is not enough: the sensor can continue reporting and reactivate.

Follow the [Microsoft identity-only offboarding procedure](https://learn.microsoft.com/en-us/defender-for-identity/uninstall-sensor#offboard-a-server-without-defender-for-endpoint-deployment):

1. In **Sensor management**, select the V3 sensor and choose **Delete**.
2. In the removal dialog, select **Download offboarding package**. Do not finish removing the portal entry yet.
3. Copy and extract the package on the DC.
4. Open elevated PowerShell in its folder and run the tool with the **actual, unexpired `.offboarding` file**. Replace both example paths:

```powershell
Set-Location -LiteralPath 'C:\MDI\Offboarding' -ErrorAction Stop
.\DefenderDeploymentTool_Offboard.exe -Offboard -File:"C:\MDI\Offboarding\WindowsDefenderATP_valid_until_YYYY-MM-DD.offboarding"
```

5. After successful offboarding, return to **Sensor management** and remove the V3 entry.
6. Reinstall V2 using the approved installer, valid key, and original V2 proxy configuration.
7. Repeat the [V2 baseline checks](#record-the-v2-baseline), confirm portal health, and verify identity activity recorded **after V2 reinstallation**.

If onboarding only partially completed and the offboarding path is unclear, stop and resolve that state before reinstalling V2. Do not manually delete Sense or its registry configuration.

Restore any changed WinHTTP or Sense proxy GPO settings only after reviewing other service dependencies. Return action accounts to manual mode only if **no V3 sensors remain in the workspace** and your original configuration requires it. Keep DSA entries still needed by V2.

**Adding full MDE later:** Microsoft documents a separate sequence: offboard identity-only V3, onboard MDE, then activate MDI V3 again. See [the documented conversion steps](https://learn.microsoft.com/en-us/defender-for-identity/deploy/activate-sensor#what-if-i-want-to-add-defender-for-endpoint-later).

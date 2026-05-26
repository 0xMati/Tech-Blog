# ADFS 2012 R2 Web Application Proxy – Re-Establish Proxy Trust
🗓️ Published: 2025-05-28

---

> **Quick Summary**  
> The short-lived WAP authentication certificate expired. As a result, trust between the proxy and the AD FS server was broken. This guide shows how to re-establish trust using either the GUI or PowerShell.

## What Happened?

In this lab scenario, the WAP authentication certificate expired. Communication between the proxy and the Federation Service stopped. Internal AD FS remained healthy, but external traffic through the proxy failed.

### Symptoms

- **Remote Access Console** throws `0x8007520C`.  

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-07-30.png)

- **Event ID 422** on the proxy:  
  ```
  401 Unauthorized fetching proxy config.
  ```

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-07-50.png)

- **Event ID 394** on ADFS:  
  > “Proxy trust certificate … has expired.”  

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-08-43.png)

- **Event ID 276** indicates that the proxy trust should be re-established.

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-08-32.png)



---

## Fix #1: Old-School GUI

1. **Reg tweak**  
   ```
   HKLM\Software\Microsoft\ADFS\ProxyConfigurationStatus
   ```
   Flip the DWORD from `2` → `1`.

2. **Re-open** Remote Access Management (no reboot required).

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-09-25.png)

3. **Run the wizard** again:  
   - Federation Service name: `adfs.tailspintoys.ca` (or yours).  
   - Pick the right SSL cert (thumbprint check!).  
   - Click through the screens—peek at the PowerShell if you’re curious.

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-09-37.png)

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-09-47.png)

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-09-55.png)

4. **Restart ADFS** on the proxy:
   ```powershell
   Restart-Service adfssrv
   ```

Trust is now re-established.

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-06.png)

---

## Fix #2: PowerShell Magic

For CLI aficionados:

```powershell
$thumb = "YOUR_CERT_THUMBPRINT"
$fsn   = "adfs.tailspintoys.ca"

Install-WebApplicationProxy `
  -CertificateThumbprint $thumb `
  -FederationServiceName $fsn
```

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-21.png)

Enter your AD FS admin credentials when prompted and wait for completion. Expected result: **Deployment Succeeded**.

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-30.png)

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-34.png)

---

## Did It Work?

- **Proxy logs**: Event ID 245 confirms configuration retrieval.  
- **ADFS logs**: Event ID 396 confirms trust renewal.

Users can now authenticate from the Internet again.

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-49.png)

![](../assets/wap-trust-to-adfs-broken/2025-06-24-20-10-55.png)
---

## Sources

- https://blogs.technet.microsoft.com/rmilne/2015/04/20/adfs-2012-r2-web-application-proxy-re-establish-proxy-trust/

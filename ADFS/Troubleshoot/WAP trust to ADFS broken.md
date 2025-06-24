# ADFS 2012 R2 Web Application Proxy – Re-Establish Proxy Trust
🗓️ Published: 2025-05-28

---

> **Quickie**  
> Your ADFS Proxy’s short-lived cert kicked the bucket. Now it’s ghosting your ADFS server. Let’s bring it back from the dead—GUI or PowerShell, your call.

## What Happened?

In my lab playground, I let the WAP’s auth cert expire. Ooops. The proxy and the Federation Service stopped chatting—internal ADFS was fine, but the proxy might as well have been on Mars.

### Symptoms

- **Remote Access Console** throws `0x8007520C`.  

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-07-30.png)

- **Event ID 422** on the proxy:  
  ```
  401 Unauthorized fetching proxy config.
  ```

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-07-50.png)

- **Event ID 394** on ADFS:  
  > “Proxy trust certificate … has expired.”  

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-08-43.png)

- **Event ID 276** says: “Hey buddy, re-run that proxy wizard, stat!”

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-08-32.png)



---

## Fix #1: Old-School GUI

1. **Reg tweak**  
   ```
   HKLM\Software\Microsoft\ADFS\ProxyConfigurationStatus
   ```
   Flip the DWORD from `2` → `1`.

2. **Re-open** Remote Access Management (no reboot dance).

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-09-25.png)

3. **Run the wizard** again:  
   - Federation Service name: `adfs.tailspintoys.ca` (or yours).  
   - Pick the right SSL cert (thumbprint check!).  
   - Click through the screens—peek at the PowerShell if you’re curious.

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-09-37.png)

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-09-47.png)

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-09-55.png)

4. **Restart ADFS** on the proxy:
   ```powershell
   Restart-Service adfssrv
   ```

Boom. Trust is back in business.

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-06.png)

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

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-21.png)

Enter your ADFS admin creds when prompted, wait a sec… **Deployment Succeeded!**

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-30.png)

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-34.png)

---

## Did It Work?

- **Proxy logs**: Event ID 245 → “Config retrieved, all good.”  
- **ADFS logs**: Event ID 396 → “Trust renewed, party on!”

Users can now auth from the Internet again. 🎉

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-49.png)

![](assets/WAP%20trust%20to%20ADFS%20broken/2025-06-24-20-10-55.png)
---

## Sources

- https://blogs.technet.microsoft.com/rmilne/2015/04/20/adfs-2012-r2-web-application-proxy-re-establish-proxy-trust/

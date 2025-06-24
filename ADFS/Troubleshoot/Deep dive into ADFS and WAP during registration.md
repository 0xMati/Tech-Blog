# Deep Dive into AD FS and MS WAP – WAP Registration

🗓️ Published: 2025-06-24

---

## Introduction

This article examines how Microsoft Web Application Proxy (WAP) establishes trust—“registration”—with Active Directory Federation Services (AD FS). You’ll see how WAP generates its own certificate, performs the HTTPS calls to AD FS, and retrieves its configuration.

---

## Environment & Tools

- **WAP server** on Windows Server 2012 R2  
- **AD FS farm** behind it  
- **Process Explorer** (Sysinternals) to monitor `RAMgmtUI.exe`  
- **Fiddler** (configured for HTTPS/MITM) to capture HTTP(S) traffic  

All tools run under the administrator account used by the Remote Access Management Console.

---

## Capturing the Registration Traffic

1. **Open Process Explorer**, filter on `RAMgmtUI.exe`.  
2. **Start Fiddler**, trust its root certificate and enable HTTPS decryption.  
3. **Run the “Configure Web Application Proxy” wizard** in the Remote Access Management console—using valid or invalid credentials—to generate the necessary traffic.

---

## The EstablishTrust Request

1. **Initial POST** to  
   ```
   https://<ADFS-FQDN>/adfs/Proxy/EstablishTrust
   ```
   returns **401 Unauthorized** (no auth header yet).

2. **Second POST** includes `Authorization: Basic …` header.  
   - If credentials are wrong, another 401 appears as expected.  
   - If correct, AD FS accepts the request.

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-17-05.png)

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-17-12.png)

3. **Request payload** contains:
   ```json
   {
     "SerializedTrustCertificate": "<Base64-encoded self-signed cert>"
   }
   ```
   WAP has generated a new 2048-bit self-signed certificate (public & private key).

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-17-48.png)

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-17-55.png)
---

## Retrieving Configuration

1. WAP issues repeated GETs to  
   ```
   /adfs/Proxy/GetConfiguration?api-version=2
   ```
   each initially returning 401 until the client cert is supplied.

2. **Supply the client certificate** to Fiddler:  
   - Export the WAP-generated cert (public key) as `ClientCertificate.cer` into  
     ```
     C:\Windows\ServiceProfiles\NetworkService\Documents\Fiddler2
     ```  
   - Restart Fiddler under the Network Service account using PsExec:  
     ```powershell
     psexec -i -u "NT AUTHORITY\Network Service" "C:\Program Files (x86)\Fiddler2\Fiddler.exe"
     ```
3. Re-run the proxy wizard; the GET succeeds and returns a JSON blob describing all supported endpoints and settings.

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-18-34.png)

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-18-47.png)

![](assets/Deep%20dive%20into%20ADFS%20and%20WAP%20during%20registration/2025-06-24-20-18-55.png)

---

## Applying the Configuration

The `Microsoft.IdentityServer.ProxyService.exe` process (running as Network Service) parses the JSON and:

1. Identifies supported endpoints (OAuth, WS-Fed, SAML, etc.).  
2. Uses HTTP.SYS APIs to bind WAP’s local listener to those endpoints.

Once complete, WAP is fully registered and ready to proxy AD FS traffic.

---

## Summary of Steps

1. **Generate** a 2048-bit self-signed certificate (WAP).  
2. **POST** to `/adfs/Proxy/EstablishTrust` with cert + Basic auth.  
3. **GET** `/adfs/Proxy/GetConfiguration` using the new cert.  
4. **Bind** endpoints via HTTP.SYS.  

Trust is now established, and WAP can securely reverse-proxy AD FS requests.

---

## Source

- https://journeyofthegeek.com/2017/08/08/deep-dive-into-ad-fs-and-ms-wap-wap-registration/  

---
title: "How to Configure Detailed Error Pages for the FIM Portal"
date: 2025-04-22
---

## How to Configure Detailed Error Pages for the FIM Portal

The goal of this article is to explain the steps to enable detailed error pages on the FIM Portal. These are more descriptive from an administrator point of view.

---

### Table of Contents

- [Without Custom Error Pages](#without-custom-error-pages)  
- [Enable Detailed Error Pages](#enable-detailed-error-pages)  
- [Disable Detailed Error Pages](#disable-detailed-error-pages)  

---

### Without Custom Error Pages

Whilst the default error page is user-friendly, it's administrator unfriendly. The error is shown whenever something is wrong between the FIM Portal and the FIM Service.

> _The Portal cannot connect to the middle tier using the web service interface. This failure prevents all portal scenarios from functioning correctly._  
> _The cause may be due to a missing or invalid server url, a downed server, or an invalid server firewall configuration._  
> _Ensure the portal configuration is present and points to the resource management service._

![](assets/Enable%20FIM%20Detailed%20Error%20Pages/2025-04-22-17-42-54.png)

![](assets/Enable%20FIM%20Detailed%20Error%20Pages/2025-04-22-17-43-02.png)


The `web.config` file of the FIM Portal is typically located at:

```
C:\inetpub\wwwroot\wss\VirtualDirectories\80
```

> **Important:** Always take a backup of the original `web.config` file before making any changes.

---

### Enable Detailed Error Pages

To enable detailed error pages:

1. Enable the callstack:

```xml
<SafeMode MaxControls="200" CallStack="true" DirectFileDependencies="10" TotalFileDependencies="50" AllowPageLevelTrace="false">
  <PageParserPaths></PageParserPaths>
</SafeMode>
```

2. Disable custom error pages:

```xml
<customErrors mode="Off" />
```

3. Comment the ILMError HTTP module:

```xml
<httpModules>
  <clear />
  <!-- <add name="ILMError" type="Microsoft.IdentityManagement.WebUI.Controls.ErrorHandlingModule, Microsoft.IdentityManagement.WebUI.Controls, Version=4.0.3561.2, Culture=neutral, PublicKeyToken=31bf3856ad364e35" /> -->
</httpModules>
```

4. Perform an IISreset  
5. Reproduce the issue to see detailed errors.

![](assets/Enable%20FIM%20Detailed%20Error%20Pages/2025-04-22-17-42-02.png)

---

### Disable Detailed Error Pages

To restore user-friendly error pages:

1. Disable the callstack:

```xml
<SafeMode MaxControls="200" CallStack="false" DirectFileDependencies="10" TotalFileDependencies="50" AllowPageLevelTrace="false">
  <PageParserPaths></PageParserPaths>
</SafeMode>
```

2. Enable custom error pages:

```xml
<customErrors mode="On" />
```

3. Re-enable the ILMError HTTP module:

```xml
<httpModules>
  <clear />
  <add name="ILMError" type="Microsoft.IdentityManagement.WebUI.Controls.ErrorHandlingModule, Microsoft.IdentityManagement.WebUI.Controls, Version=4.0.3561.2, Culture=neutral, PublicKeyToken=31bf3856ad364e35" />
</httpModules>
```

4. Perform an IISreset

---

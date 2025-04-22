---
title: "FIM Portal - Error Exporting RCDC, SID, etc"
date: 2025-04-22
---

## FIM Portal - Error Exporting RCDC, SID, etc

> _Original error encountered when attempting to export RCDC configuration._

When trying to export RCDC configuration, the following error is displayed:

![](assets/FIM%20Export%20Error%20(RCDC,%20SID,%20...)/2025-04-22-17-51-24.png)

### After Enabling Tracing

The trace reveals:

```
Server Error in '/' Application.
The resource cannot be found.
Description: HTTP 404. The resource you are looking for (or one of its dependencies) could have been removed, had its name changed, or is temporarily unavailable. 
Requested URL: /identitymanagement/ashx/Download.ashx
```

![](assets/FIM%20Export%20Error%20(RCDC,%20SID,%20...)/2025-04-22-17-51-35.png)

### Root Cause and Resolution

This issue occurs because **SharePoint Server 2019** uses a different mechanism to maintain a list of blocked file extensions. The `.ashx` extension used by the MIM Portal may be blocked by default.

To resolve this issue, follow the guidance from Microsoft:

👉 [Prepare the SharePoint Server for MIM Portal](https://docs.microsoft.com/en-us/microsoft-identity-manager/prepare-server-sharepoint)

### Important

If you are using **SharePoint Server 2019**, execute the following commands from the **SharePoint Management Shell** to unblock `.ashx`:

```powershell
$w.BlockedASPNetExtensions.Remove("ashx")
$w.Update()
$w.BlockedASPNetExtensions
```

These steps ensure the `.ashx` handler used by the MIM Portal is no longer blocked by SharePoint, allowing proper RCDC export functionality.


---
title: "MIM SP3 Portal: Repeated Windows Authentication Prompts"
date: 2026-10-16
---

## MIM SP3 Portal: Repeated Windows Authentication Prompts

Encountered with **MIM 2016 SP3 (4.7.6.0), SharePoint Subscription Edition and Windows Server 2025**.

---

### Symptoms

The portal works, but clicking links repeatedly opens a **Windows Security** sign-in dialog. Cancelling it still allows navigation.

Browser developer tools show a **401 Unauthorized** response for:

```text
/IdentityManagement/_api/SP.Web.GetContextWebThemeData?lcid=1033
```

Separate MIM events may report `IdentityIsNotFound` or `GetCurrentUserFromSecurityIdentifier: No such user DOMAIN\svcMIMAppPool`. These events do not automatically explain the SharePoint 401.

---

### Possible workaround: Register the AppPool account in MIM

[Eugene Sergeev's SP3 review](https://www.linkedin.com/pulse/perfectly-objective-review-mim-sp3-eugene-sergeev-hulbc/) describes internal portal calls running under the AppPool identity instead of the user.

For that scenario, the suggested workaround is to register the AppPool account as a **Person in MIM Service**, with its correct Windows SID and the required read permissions through appropriate Management Policy Rules.

This is **not** the same as adding a SharePoint farm administrator. Do not insert SID mappings directly into SQL or grant MIM administrator rights as a blanket workaround.

**In our environment, adding the account as a MIM administrator did not remove the popup.**

---

### Fix validated in our environment: ASP.NET authentication mode

The application used SharePoint claims authentication, but its ASP.NET configuration used `Windows`.

1. Back up the portal's `web.config` outside the web root, in a restricted location. Typical file:

   ```text
   C:\inetpub\wwwroot\wss\VirtualDirectories\80\web.config
   ```

2. Under `configuration/system.web`, change **only** the existing authentication mode:

   ```diff
   - <authentication mode="Windows">
   + <authentication mode="Forms">
   ```

   Preserve all child settings, including the existing Forms login URL `/_login/default.aspx`.

3. Reload the portal and check the failing request again. Editing this file reloads the MIM web application; a global `iisreset` was not needed.

**This does not convert SharePoint to Classic or enable a new Forms-based membership provider.** Windows authentication in IIS, Negotiate/Kerberos and `UseClaimsAuthentication=True` remained unchanged.

---

### Validation

- Portal page: **200**, correct signed-in administrator.
- Theme API: **200**, valid JSON containing `d.GetContextWebThemeData`.
- Theme API without credentials or session: still **401**.
- Browser navigation: **popup gone**, confirmed by the user.

This is an environment-tested configuration fix, not a Microsoft-issued hotfix or a universal prescription. Restore the backup if authenticated access fails or unauthenticated access becomes possible. No SQL changes or additional permissions were needed for this fix.

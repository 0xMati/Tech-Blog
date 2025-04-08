---
title: "Understanding RelayState in ADFS (IDP Initiated Sign-On)"
date: 2025-04-08
---

## Definition

In ADFS, two standard protocols are supported: **SAML** and **WS-Federation**.

**RelayState** is a parameter used in SAML protocol to specify a particular resource the user should be redirected to after authenticating with the Identity Provider (IdP).

---

## IDP Initiated Sign-On vs SP Initiated Sign-On

In a traditional **SP-Initiated login**, the user is redirected to their Identity Provider after attempting to access a Service Provider.

In an **IDP-Initiated login**, the user authenticates directly with the Identity Provider first and is then redirected to a specified application. This implies a change in ADFS traffic flow.

To make this process smoother, RelayState can be included in the URL to define where the user should land post-authentication.

---

## RelayState Structure

RelayState is composed of two main components:

- **RPID**: Identifies the Relying Party (the application you want to access)
- **NR**: Optional. Used when chaining ADFS servers, it identifies the next ADFS server or the final target application.

### Example:

For a scenario with chained ADFS servers:
- First RelayState (e.g., `contoso`) redirects to `fabrikam`
- Second RelayState redirects to the actual RP (application)

RelayState is supported only in **SAML** authentication.

---

## Common Use Cases

- Applications not capable of determining the correct IdP
- Portals requiring users to choose their organization (HRD-like behavior)
- Office 365 relying on UPN suffix for redirect

---

## Demo Behavior

If you access the default ADFS login page:
- You will only see that you're authenticated.
- Without RelayState, ADFS won’t redirect you to any application.

To improve UX:
- Use a redirect URL with RelayState pre-filled.
- Use **ADFS 2.0 Update Rollup 2** or newer for support.

---

## URL Generator Tool

A community tool is available to generate valid RelayState URLs:

👉 [ADFS RelayState Generator (CodePlex)](https://adfsrelaystate.codeplex.com/releases/view/93202)

![](assets/What%20is%20ADFS%20Relay%20State/2025-04-08-16-34-55.png)

Example URL structure:

```text
https://adfs.contoso.com/adfs/ls/idpinitiatedsignon.aspx?
RelayState=RPID%3Dhttps%253A%252F%252Ftest.com%26RelayState%3Dhttps%253A%252F%252Ftest.com
```

> ⚠️ Always test the RelayState logic with your application to ensure compatibility and redirection behavior.


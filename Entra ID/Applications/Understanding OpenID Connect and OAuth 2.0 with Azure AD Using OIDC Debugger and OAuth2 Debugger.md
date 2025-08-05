# Understanding OpenID Connect and OAuth 2.0 with Entra ID Using OIDC Debugger and OAuth2 Debugger  
🗓️ Published: 2025-08-05

## Introduction

If you’ve ever been curious about how modern apps handle user authentication and permissions, you’ve probably bumped into terms like **OAuth 2.0** and **OpenID Connect (OIDC)**. These protocols power the sign-in and access control for millions of apps — including those backed by Entra ID.

In this article, we’ll break down what OAuth 2.0 and OIDC really are, and how you can use two handy tools, **OIDC Debugger** and **OAuth2 Debugger**, to see them in action with Entra ID.

If you want a quick dive into the core concepts behind OAuth and OIDC, check out my previous article here: [Overview of OAuth and OIDC](https://github.com/0xMati/Tech-Blog/blob/main/Modern%20Authentication/Overview%20of%20OAuth%20and%20OIDC.md).

## Configuring OAuth 2.0 Debugger with Entra ID

Before diving into testing tokens and scopes, you need to set up your OAuth 2.0 Debugger client to work with Microsoft Entra ID (formerly Azure AD). This tool lets you simulate OAuth flows and inspect tokens in a simple way — perfect for learning and troubleshooting!

### Step 1: Register an Application in Entra ID

Head over to the [Azure Portal](https://portal.azure.com) and create a new App Registration:

- Give it a friendly name like `OAuth2 Debugger Client`.
- For supported account types, choose what fits your scenario (e.g., Single tenant or Multitenant).
- Set the Redirect URI to the URL used by OAuth 2.0 Debugger (usually something like `https://oauthdebugger.com/debug`).

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-07-43.png)

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-09-24.png)

### Step 2: Set Up Client Secrets

Under **Certificates & secrets**, create a new client secret. You’ll need this secret for your OAuth client to authenticate securely.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-08-37.png)

### Step 3: Input Your App Details in OAuth 2.0 Debugger

Now, open [OAuth 2.0 Debugger](https://oauthdebugger.com):

- Enter your **Authorize URI**: https://login.microsoftonline.com/{YourTenantID}/oauth2/v2.0/authorize
- Add your **Client ID** and **Client Secret**.
- Set the **Scopes** you want to request (e.g., `User.Read`).

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-13-10.png)

- Hit **Send Request** !

You should receive an Authorization code with the requested scopes, ready to use for getting Access Token with the code.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-15-41.png)

### Step 4 Exchanging the Authorization Code for an Access Token Using PowerShell

After successfully obtaining the authorization code using OAuth 2.0 Debugger, the next step is to exchange this code for an access token. This token will allow your application to access protected resources.

Here's how you can do this with PowerShell:

```powershell
# Define your variables
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = "your-client-secret"
$authorizationCode = "the-code-you-received"
$redirectUri = "https://oauthdebugger.com/debug"  # Same as in app registration

# Token endpoint URL for Microsoft Entra ID (Azure AD)
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Prepare the body with required parameters
$body = @{
    client_id     = $clientId
    scope         = "User.Read"
    code          = $authorizationCode
    redirect_uri  = $redirectUri
    grant_type    = "authorization_code"
    client_secret = $clientSecret
}

# Request the token
$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body

# Display the response tokens
$response | Format-List
```

Explanation:
* client_id, client_secret, and redirect_uri must match those used during the app registration and authorization request.
* code is the authorization code you received from the previous step.
* The scope must be the same or a subset of the scopes you initially requested.

The response will contain the access_token.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-22-33.png)

---

## Configuring OpenID Connect 2.0 Debugger with Entra ID

OpenID Connect (OIDC) builds on OAuth 2.0 by adding user authentication on top of authorization. The **OIDC Debugger** tool lets you explore this flow interactively, seeing ID tokens, access tokens, and user info come to life!

### Step 1: Register an Application in Entra ID

Just like before, start by creating a new App Registration in the [Azure Portal](https://portal.azure.com):

- Name it something like `OIDC Debugger Client`.
- Choose supported account types (single or multi-tenant).
- Set the Redirect URI to `https://oidcdebugger.com/debug` (the default for OIDC Debugger).

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-25-36.png)

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-26-27.png)

### Step 2: Set Up Client Secrets

Under **Certificates & secrets**, create a new client secret. This will authenticate your client app during the flow.

![](assets/YourFolder/oidcdebugger-clientsecret.png)

### Step 3: Input Your App Details in OIDC Debugger

Head to [OIDC Debugger](https://oidcdebugger.com):

- Paste your **Authorize URL**: https://login.microsoftonline.com/{YourTenantID}/oauth2/v2.0/authorize
- Add your **Client ID** and **Client Secret**.
- Set scopes such as: `openid`

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-29-41.png)

- Click **Send Request** and authenticate when prompted.

You should receive an Authorization code with the requested scopes, ready to use for getting Access Token with the code.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-30-55.png)

### Step 4 Exchanging the Authorization Code for Access Token & id Token Using PowerShell

Once you’ve obtained the authorization code via OIDC Debugger, you can exchange it for an ID token and access token programmatically.

Here’s a simple PowerShell script to do that:

```powershell
# Define your variables
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = "your-client-secret"
$authorizationCode = "the-authorization-code-you-received"
$redirectUri = "https://oidcdebugger.com/debug"  # Must match app registration redirect URI

# Token endpoint URL for Microsoft Entra ID (Azure AD)
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Prepare the POST body with required parameters
$body = @{
    client_id     = $clientId
    scope         = "openid profile email User.Read"
    code          = $authorizationCode
    redirect_uri  = $redirectUri
    grant_type    = "authorization_code"
    client_secret = $clientSecret
}

# Request the tokens
$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body

# Display the tokens
$response | Format-List
```

Explanation:
* client_id, client_secret, and redirect_uri must match those used during the app registration and authorization request.
* code is the authorization code you received from the previous step.
* The scope must be the same or a subset of the scopes you initially requested.

The response will contain the access_token & id Token

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-33-27.png)

--> Additionally, you can decode the Access Token and ID Token from base64 to inspect their contents:

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-35-45.png)

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-36-04.png)
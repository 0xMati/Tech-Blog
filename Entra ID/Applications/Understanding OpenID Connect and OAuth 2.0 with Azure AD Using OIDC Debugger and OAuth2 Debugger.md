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

---

## Demo: Creating and Testing a Web API with Entra ID and OIDC Debugger

Let’s walk through a practical example where we create a Web API protected by Entra ID and test it using the OIDC Debugger tool. For this demo, we won’t have a real backend API running — instead, the focus is on understanding the app registration, scopes, tokens, and how API calls are authorized. This will help you connect the dots between these key concepts.

### Step 1: Register the Web API Application in Entra ID

- Go to the [Azure Portal](https://portal.azure.com) and create a new **App Registration** for your Web API.
- Name it something like `MySuperWebAPI`.
- Set supported account types according to your needs.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-42-08.png)

- Under **Expose an API**, add a new scope:
  - Scope name / Application ID URI: `api://mathiasmotron.com/MySuperCustomScope`
  - Who can consent: Admins and users
  - Admin consent display name: `Access My Web API`
  - Admin consent description: `Allows the app to access My Web API on behalf of the signed-in user`
  - Save the scope.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-44-24.png)

### Step 2: Authorized Client Applications for OIDC Debugger

- In Entra ID, authorize the **OIDC Debugger** application to access your Web API.
- Under your Web API app registration, navigate to **Expose an API** > **Authorized client applications**.
- Add the **Client ID** of the OIDC Debugger app here.
- This step explicitly allows the OIDC Debugger app to request tokens for your API’s custom scopes.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-49-10.png)


### Step 3: Use OIDC Debugger to Request Authorization Code

- Open [OIDC Debugger](https://oidcdebugger.com).
- Enter your tenant-specific authorization endpoint (e.g., `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize`).
- Enter the client ID and redirect URI configured earlier.
- Set the scope to your custom API scope (`api://mathiasmotron.com/MySuperCustomScope/MySuperCustomScope`).
- Send the authorization request and log in to consent.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-51-07.png)

- You will receive an authorization code.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-51-27.png)

### Step 4: Exchange the Authorization Code for Access Token

- Use PowerShell (or any HTTP client) to send a POST request to the token endpoint (`https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`) with:
  - client_id
  - client_secret
  - code (authorization code received)
  - redirect_uri
  - grant_type = `authorization_code`
  - scope = `api://<api-client-id>/CustomScope1`

```powershell
# Customize these variables
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = "your-client-secret"
$authorizationCode = "the-authorization-code-you-received"
$myscope = "your custom scope created before"
$redirectUri = "https://oidcdebugger.com/debug"  # Must exactly match the URI used during authorization

# Microsoft Entra ID token endpoint
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Prepare the body of the POST request
$body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    code          = $authorizationCode
    redirect_uri  = $redirectUri
    grant_type    = "authorization_code"
    scope         = $myscope
}

# Send POST request to get tokens
$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body

# Display the tokens response
$response | Format-List
```
![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-05-23-59-40.png)

- Receive an access token scoped for your API.

### Understanding the Access Token Response

When you exchange your authorization code for an access token, the response you receive contains several important fields:

- **token_type: Bearer**  
  This indicates the type of token issued. The “Bearer” token is what you include in the HTTP `Authorization` header when calling protected APIs - that we don"t have in this demo :) 

- **scope**  
  This shows the permissions (scopes) granted for the token. In this case, it matches the custom scope defined for your API, meaning this token can be used to access that specific API.

- **expires_in** and **ext_expires_in**  
  These values tell you how long the token is valid (in seconds) before it expires and needs to be refreshed or reissued.

- **access_token**  
  This is the actual JWT (JSON Web Token) string that represents your authenticated session and permissions. You send this token with your API requests to prove your identity and access rights.

### How to Use the Access Token

Whenever you call your secured Web API, you need to include the access token in the HTTP header like this:
**Authorization: Bearer {access_token}**

This header lets the API validate your token and confirm that your client has the correct permissions to access the requested resources.
Even though in this demo we don’t have a real backend API, this token represents the key piece that would allow your application to securely communicate with any protected resource.

---

## Demo: Accessing Microsoft Graph API Using OIDC Debugger

In this final demo, we'll use the **OIDC Debugger** tool to authenticate with Entra ID and obtain tokens that allow us to call the Microsoft Graph API — the powerful API that lets you access user data and many Microsoft 365 services.

### Step 1: Use the Previously Registered OIDC Debugger Application and Add Microsoft Graph Permissions

We’ll use the app registration we created earlier for OIDC Debugger, but now we’ll add the necessary Microsoft Graph API permissions to it.

Make sure to assign the delegated permission **User.Read** + **Mail.Read** (or others you need) under **API permissions**, and grant admin consent if required. This will allow your app to request tokens that can access Microsoft Graph.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-07-51.png)

### Step 2: Configure OIDC Debugger with Your Existing App Details

- Open [OIDC Debugger](https://oidcdebugger.com).
- Enter the **Client ID** of the app you previously registered.
- Set the **Authority URL** to: `https://login.microsoftonline.com/{your-tenant-id}/v2.0`
- Set the **Redirect URI** to `https://oidcdebugger.com/debug` (this must exactly match the URI configured in Entra ID).
- Set the **Scopes** to request the permissions you assigned, for example:  
  `openid profile email User.Read Mail.Read`

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-09-11.png)

### Step 3: Authenticate and Obtain Tokens

- Click **Send Request**.
- Complete the login prompt.

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-09-37.png)

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-10-23.png)

- You’ll receive an **Authorization Code** that you can exchange for tokens (ID token and Access token).

### Step 4: Exchange the Authorization Code for Tokens

- After receiving the authorization code from OIDC Debugger, you need to exchange it for an **ID token** and **Access token**.
- This can be done by sending a POST request to the token endpoint (`https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token`) with the following parameters:
  - `client_id`
  - `client_secret`
  - `code` (the authorization code received)
  - `redirect_uri`
  - `grant_type` = `authorization_code`
  - `scope` (the scopes you requested)
- The response will contain your tokens, which you can then use to call Microsoft Graph API.

```powershell
# Customize these variables
$tenantId = "your-tenant-id"
$clientId = "your-client-id"
$clientSecret = "your-client-secret"
$authorizationCode = "authorization-code-from-oidc-debugger"
$redirectUri = "https://oidcdebugger.com/debug"  # Must exactly match the URI used during authorization

# Microsoft Entra ID token endpoint
$tokenUrl = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"

# Prepare the body of the POST request
$body = @{
    client_id     = $clientId
    client_secret = $clientSecret
    code          = $authorizationCode
    redirect_uri  = $redirectUri
    grant_type    = "authorization_code"
    scope         = "openid profile email User.Read Mail.Read"
}

# Send POST request to get tokens
$response = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body

# Display the tokens response
$response | Format-List
```
![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-13-53.png)

### Step 5: Call Microsoft Graph API Using the Access Token

- Use the Access token to call Graph API endpoints, for example:  
  `https://graph.microsoft.com/v1.0/me`
- You can paste the access token in the Authorization header as:  
  `Authorization: Bearer {access_token}`
- OIDC Debugger lets you test this call directly.

```powershell
# Replace with the actual access token you received
$accessToken = "<your_access_token_here>"
$accessToken = $accessToken -replace "\s", ""

# Microsoft Graph API endpoint to get user profile
$graphApiUrl = "https://graph.microsoft.com/v1.0/me"

# Prepare the Authorization header
$headers = @{
    Authorization = "Bearer $accessToken"
}

# Make the GET request to Microsoft Graph
$response = Invoke-RestMethod -Uri $graphApiUrl -Headers $headers -Method Get

# Display the response
$response | Format-List
```

![](assets/Understanding%20OpenID%20Connect%20and%20OAuth%202.0%20with%20Azure%20AD%20Using%20OIDC%20Debugger%20and%20OAuth2%20Debugger/2025-08-06-00-18-03.png)

This demo shows how easy it is to obtain and use tokens for Microsoft Graph with Entra ID and OIDC Debugger, giving you a hands-on way to explore user info and Microsoft 365 APIs securely.




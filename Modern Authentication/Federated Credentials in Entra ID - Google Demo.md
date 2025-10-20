# Federated Credentials in Entra ID - Google IDP Demo
🗓️ Published: 2025-10-20

## Introduction

Federated Credentials in Microsoft Entra ID allow an external identity provider (IDP) — such as Google, GitHub, or any OpenID Connect (OIDC) compliant provider — to issue tokens that Entra ID can trust to authenticate an application or workload without secrets, certificates, or stored credentials.

This mechanism, also called Workload Identity Federation, enables a secure trust relationship between Entra ID and a third-party identity system. Instead of using a client secret or certificate to request a token, the application presents an OIDC token issued by the external IDP. Entra ID verifies this token against the configured issuer and subject information, and if they match, issues an access token for Microsoft APIs (e.g., Microsoft Graph, Azure Resource Manager, etc.).

## Concept Overview

A federated credential is attached to an App Registration in Entra ID.

It defines:
- The issuer (e.g., https://accounts.google.com)
- The subject (the unique ID from the external IDP)
- The audience (api://AzureADTokenExchange — the fixed value Entra expects)
- When an external workload presents a valid token matching these claims, Entra ID issues an access token as if the app had authenticated normally using a client secret.

## How It Works (Simplified Flow) - Google as Example

1️⃣ Google Cloud (OIDC Issuer)
     ⤷ Issues a signed ID token (JWT)
        iss = https://accounts.google.com
        sub = <unique Service Account or user ID>
        aud = api://AzureADTokenExchange

2️⃣ Microsoft Entra ID
     ⤷ Verifies the token’s signature against the issuer’s JWKS
     ⤷ Checks that iss/sub/aud match a configured Federated Credential
     ⤷ Issues an access token for the Entra application (App Registration)

3️⃣ The workload
     ⤷ Uses the Entra access token to call protected Microsoft APIs
        (e.g., Microsoft Graph, Azure Resource Manager, etc.)

## Advantages of Federated Credentials

| **Advantage** | **Description** |
|----------------|-----------------|
| 🔐 **Zero Secrets** | No need to store or rotate client secrets or certificates — the workload authenticates using short-lived OIDC tokens issued by the external provider. |
| ⏱️ **Short-Lived Trust** | Each token exchange is ephemeral (typically 1 hour), reducing long-term exposure in case of compromise. |
| ☁️ **Cross-Cloud Interoperability** | Enables seamless authentication from other clouds (Google Cloud, AWS, GitHub Actions, etc.) to Microsoft Entra ID without custom identity plumbing. |
| 🧾 **Full Auditability** | Every token exchange is logged in Entra ID sign-in logs, including the external issuer and subject identifier for traceability. |
| ⚙️ **Automated Workload Identity** | Ideal for CI/CD pipelines, service accounts, and machine identities that need to call Microsoft APIs securely without human credentials. |

## Setup the demo

> **Note:** This demo uses only a personal **Google Developer account** (not a full Google Workspace or paid GCP organization). All steps are performed entirely through the web console — no billing, service project, or CLI setup required.

### Environment Setup

This section describes the minimal environment required to demonstrate Federated Credentials between Google (as the OIDC identity provider) and Microsoft Entra ID.

#### Prerequisites

| Requirement                                 | Purpose                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 🟦 **Microsoft Entra ID tenant**            | You must be able to create an App Registration and grant API permissions. Administrator rights are recommended.   |
| 🟥 **Google Developer Account**             | A standard personal Google account is enough; no paid Google Cloud billing or Workspace organization is required. |
| ⚙️ **PowerShell 5.1+**                      | Used later to test the token exchange.                                                        |
| 🧠 **Basic knowledge of OIDC tokens (JWT)** | Helpful for verifying claims with [jwt.ms](https://jwt.ms).                                                       |

#### High-Level Architecture

We will establish a trust chain where Entra ID accepts a Google-signed OIDC token as proof of identity for an application.

        ┌────────────────────────────┐
        │  Google Cloud / Developer  │
        │   • Service Account (OIDC) │
        │   • Workload Identity Pool │
        │   • IAM Credentials API    │
        └─────────────┬──────────────┘
                      │
          (1) ID Token  iss=accounts.google.com  
                       sub=<unique ID>  
                       aud=api://AzureADTokenExchange
                      │
                      ▼
        ┌────────────────────────────┐
        │   Microsoft Entra ID App   │
        │   • Federated Credential   │
        │   • Verifies iss/sub/aud   │
        └─────────────┬──────────────┘
                      │
          (2) Access Token (Bearer)  
          usable on Microsoft Graph API
                      │
                      ▼
        ┌────────────────────────────┐
        │  Microsoft Graph / Azure   │
        └────────────────────────────┘

#### What You Will Create

On Google Cloud:
- A project named Google-Federated-OIDC-App
- An OAuth Consent Screen and OAuth Client ID
- A Service Account capable of generating OIDC tokens
- A Workload Identity Pool and an OIDC Provider (issuer = https://accounts.google.com)
- The IAM Service Account Credentials API enabled

On Entra ID:
- An App Registration
- One Federated Credential entry defining:
    - Issuer = https://accounts.google.com
    - Subject = Google token sub value
    - Audience = api://AzureADTokenExchange

Locally:
- PowerShell script to exchange the Google ID token for an Entra access token

### Google Cloud Configuration

#### Create the Project

The first step is to create a dedicated Google Cloud project that will host all components required for the federation setup (OAuth credentials, Service Account, and Workload Identity Federation).

- Go to the Google Cloud Console:
https://console.cloud.google.com/

- In the top navigation bar, click the project selector ▾ and choose “New Project.”
- Set:
    - Project name → MyGoogleEntraFederatedProject
    - Location → (leave blank if not part of a Workspace)

Click Create.

Once created, switch to this new project.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-33-39.png)

#### Configure the OAuth Consent Screen

Before creating OAuth credentials, Google requires an OAuth consent screen.
Even though we only use it to access the OAuth Playground later, it must exist and be published to production so your account can authenticate without test-user restrictions.

- In your project, go to : APIs & Services → OAuth consent screen.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-35-26.png)

- Clic on "Get Started"
- App name → MyGoogleEntraFederatedApp
- User support email → your Google account email

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-37-58.png)

- Audience → External

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-38-26.png)

- Developer contact information → same email

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-39-13.png)

- Finish and create

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-39-36.png)

Your OAuth consent screen is now active and published, which allows you to use your main Google account in the OAuth Playground without being added as a test user.

- Once the app is created, open the Audience section in the left menu and click Publish app to switch the Publishing status from Testing → In production.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-43-34.png)

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-43-45.png)

#### Create OAuth Credentials for the Playground

To simulate a real OIDC client, we’ll create an OAuth 2.0 Client ID in Google Cloud.
This credential will allow the OAuth Playground to authenticate against Google’s authorization and token endpoints, generating tokens that represent your project.

- In your project, go to APIs & Services → Credentials
or directly https://console.cloud.google.com/apis/credentials

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-45-16.png)

- Click Create credentials → OAuth client ID.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-46-24.png)

    - When prompted:
        - Application type → Web application
        - Name → OAuthPlaygroundClient
    - Under Authorized redirect URIs, add: https://developers.google.com/oauthplayground

    ![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-47-06.png)

You’ll receive:
 - a Client ID (e.g., 1088720670871-xxxx.apps.googleusercontent.com)
 - a Client Secret
Keep these values — we’ll use them in the OAuth Playground later.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-48-08.png)

#### Create the Service Account

The Service Account will be the identity that issues Google-signed OIDC tokens.
Later, this account’s tokens will be trusted by Entra ID through a federated credential.

- In your project, go to IAM & Admin → Service Accounts
or directly https://console.cloud.google.com/iam-admin/serviceaccounts

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-49-42.png)

- Click Create Service Account.
    - Fill in:
        - Service account name → MyGoogleEntraFederatedApp-SA
        - Service account ID → automatically filled

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-50-55.png)

- Click Create and Continue.
- Leave roles/permissions/Principals access empty (we don’t need any resource access).

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-51-44.png)

- Click Done.

Result:
You now have a dedicated Service Account that will later:
- issue ID tokens via the IAM Service Account Credentials API, and
- be linked to a Workload Identity Pool to federate toward Microsoft Entra ID.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-22-54-03.png)

#### Enable the IAM Service Account Credentials API

This API is required for Google Cloud to issue signed OIDC ID tokens on behalf of a Service Account.
It exposes the generateIdToken endpoint we’ll use later in the OAuth Playground.

- Open the Google Cloud Console → APIs & Services → Library
https://console.cloud.google.com/apis/library

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-14-49.png)

- Search for IAM Service Account Credentials API.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-15-16.png)

- Be sure that is it Enabled, clic on "Manage"

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-15-36.png)

Your project can now generate signed ID tokens for any Service Account in your project.
Next, we’ll allow your Google account to use this API to mint tokens for the Service Account.

#### Grant the “Service Account Token Creator” Role

By default, only service accounts themselves (or project editors/admins) can mint tokens on their behalf.
To generate an ID token from the OAuth Playground, your Google account must explicitly be allowed to impersonate the service account.

- Go to IAM & Admin → Service Accounts
https://console.cloud.google.com/iam-admin/serviceaccounts

- Click your service account
google-federated-oidc-app-sa@<your-project>.iam.gserviceaccount.com

- Open the Permissions tab and verify that the account has Service Account Token Creator role

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-24-27.png)

- Go to IAM and add Service Account Token Creator role to your personal account for demo (the one you use in OAuth Playground)

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-26-14.png)

Click Save.

### Generate a Signed ID Token from Google

We’ll use OAuth 2.0 Playground to obtain a Google-signed OIDC ID token for the Service Account. No billing or CLI required.

Configure OAuth Playground:

- Open: https://developers.google.com/oauthplayground

    - Click the gear (top-right) → check Use your own OAuth credentials.
    - Paste the Client ID and Client Secret you created before → Close.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-29-53.png)

- Authorize with a minimal scope: https://www.googleapis.com/auth/cloud-platform

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-30-58.png)

    - Click Authorize APIs → sign in → Allow

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-31-38.png)

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-32-03.png)

    - click Exchange authorization code for tokens

You should now see an Access token.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-33-58.png)


- Call generateIdToken (Service Account)

    - HTTP Method: POST 
    - Request URI: https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SERVICE_ACCOUNT_EMAIL>:generateIdToken
    - Add headers: Content-Type: application/json
    - Request body: 
{
  "audience": "api://AzureADTokenExchange",
  "includeEmail": true
}

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-38-12.png)

    - Click Send the request.
The response should contain:

{ "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6..." }

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-39-08.png)

- Verify the token claims

    - Paste the token into https://jwt.ms and confirm:
        - iss = https://accounts.google.com
        - aud = api://AzureADTokenExchange
        - sub = your Google subject ID (a long numeric string)
        
You will use this sub value when creating the Federated Credential in Entra ID.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-40-39.png)

### Entra ID Configuration

We’ll now create an Entra ID Application Registration that trusts Google as an external OIDC identity provider and accepts the signed tokens generated in the previous step.

#### Create the App Registration

- In the Azure portal, open Microsoft Entra ID → App registrations → New registration.
    - Name it
    - Supported account types → Accounts in this organizational directory only.
    - Redirect URI → leave empty.

 ![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-42-18.png)   

 - Add a Federated Credential

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-43-27.png)

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-43-48.png)

This connects the Google-issued token to Entra ID’s token endpoint.

| Field        | Value                                                           |
| ------------ | --------------------------------------------------------------- |
| **Issuer**   | `https://accounts.google.com`                                   |
| **Type**     | Explicit subject identifier                                     |
| **Value**    | The `sub` claim value from your decoded Google JWT (numeric ID) |
| **Name**     | `Google-Federated-Credential`                                   |
| **Audience** | `api://AzureADTokenExchange` (default)                          |

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-45-06.png)

This allows your app to exchange that Google ID token for an Entra ID access token.

### Entra ID Configuration

#### Exchange the Google Token with Entra ID (PowerShell)

Now that Entra ID trusts Google as an external OIDC issuer, you can request an Entra ID access token using your Google-signed ID token as a client assertion.
This demonstrates how a workload identity (Google SA) can authenticate to Entra ID without any secret.

```powershell
# === Entra ID parameters ===
$TenantId = "<your_tenant_id>"           
$ClientId = "<your_app_client_id>"       

# === Paste your Google ID token ===
$GoogleIdToken = @"
eyJhbGciOiJSUzI1NXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXfQ...
"@

# === Request token from Entra ID ===
$Uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

$Body = @{
  grant_type            = 'client_credentials'
  client_id             = $ClientId
  scope                 = 'https://graph.microsoft.com/.default'
  client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
  client_assertion      = $GoogleIdToken
}

$response = Invoke-RestMethod -Method POST -Uri $Uri -ContentType 'application/x-www-form-urlencoded' -Body $Body

# === Display results ===
$response.token_type
$response.expires_in
$response.access_token.Substring(0,60) + '...'
```

- Expected output: 
Bearer
3599
eyJ0eXAiOiJKV1QiLCJub25jZSI6Ik1DWEpyejZlbUs5b1B5TGlvMS1fUVFF...

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-48-20.png)

If you see "Bearer", you successfully exchanged a Google OIDC token for an Entra ID access token — no secret or certificate used.

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-49-09.png)

- Verify the issued token
    - Paste the resulting token into jwt.ms and check:
    - aud → https://graph.microsoft.com
    - iss → https://sts.windows.net/<tenant_id>/
    - appid → your Entra App Client ID

The identity matches the sub value from your Google JWT

![](assets/Federated%20Credentials%20in%20Entra%20ID%20-%20Google%20Demo/2025-10-20-23-50-32.png)


## Conclusion

This lab demonstrated how to authenticate to **Microsoft Entra ID** from **Google Cloud** without using secrets, certificates, or passwords — only a **signed OIDC ID token** issued by Google.

Through this setup:

- Google acted as the **identity provider**, issuing short-lived, verifiable tokens via the *IAM Service Account Credentials API*.  
- Microsoft Entra ID acted as the **token broker**, validating the token’s issuer, subject, and audience through a **Federated Credential**.  
- The Entra App Registration then issued an **access token for Microsoft Graph**, completing the trust chain.

This approach eliminates credential rotation, reduces attack surface, and enables secure **workload-to-workload federation** between clouds — ideal for CI/CD, automation agents, and multi-cloud services.

---

### ✅ Key Takeaways

| Concept | Description |
|----------|-------------|
| **Federated Credentials** | Entra ID feature that trusts external OIDC issuers to authenticate workloads. |
| **Zero Secrets** | No password, key, or certificate needed — authentication relies on signed ID tokens. |
| **Short-Lived Tokens** | Tokens expire quickly, minimizing exposure in case of compromise. |
| **Cross-Cloud Trust** | Enables Google Cloud workloads to access Microsoft APIs securely. |
| **Auditing** | Every token exchange is logged in Entra sign-in logs for visibility. |

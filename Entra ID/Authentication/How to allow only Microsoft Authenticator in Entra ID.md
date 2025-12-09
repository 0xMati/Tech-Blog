# How to Allow Only Microsoft Authenticator in Entra ID
🗓️ Published: 2025-12-09

## Introduction
Many organizations ask whether Entra ID can enforce Microsoft Authenticator as the only MFA method, blocking all other TOTP applications. The short answer is yes — but only by using modern authentication methods and authentication strengths. Legacy MFA settings alone cannot enforce this restriction.

---

## 1. Understanding the Two Control Layers in Entra ID

### 1.1 Legacy MFA Settings (Per-User)

Before the introduction of modern Authentication Methods, Entra ID relied on the legacy per-user MFA configuration. These settings were designed more than a decade ago and provided very limited control: administrators could enable or disable MFA for a user, but they could not specify *which* MFA methods were allowed.

In this legacy model, the option *“verification code from mobile app or hardware token”* implicitly covered **all** TOTP-based authenticators — including Microsoft Authenticator, Google Authenticator, Authy, and any other app capable of generating OATH codes. As a result, it was not possible to restrict MFA to Microsoft Authenticator only.

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-21-35.png)

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-41-45.png)

Modern deployments should no longer rely on per-user MFA because:

- It does **not** support method-level restrictions  
- It cannot enforce Microsoft Authenticator-only MFA  
- It conflicts with modern Authentication Methods and Conditional Access  
- Microsoft considers it a **legacy** control that will be deprecated over time  

For organizations aiming to enforce Microsoft Authenticator exclusively, the legacy MFA settings must be disabled so that the modern Authentication Methods policy becomes authoritative.

### 1.2 Modern Authentication Methods Policy

The modern **Authentication Methods** policy is the control plane that replaces legacy MFA settings. It provides granular, method-level configuration and is the foundation for enforcing Microsoft Authenticator-only MFA. Unlike the legacy model, this policy allows administrators to explicitly enable or disable individual methods such as:

- Microsoft Authenticator (push notifications and OTP)
- OATH TOTP (third-party authenticator apps)
- FIDO2 security keys
- Windows Hello for Business
- Temporary Access Pass (TAP)
- SMS and voice calls

This policy becomes authoritative only after a tenant completes the **Authentication Methods migration** process. During migration, a tenant can be in one of three states:

- **Pre-migration** – Legacy MFA settings are still authoritative, and modern methods do not take precedence.  
- **Migration in progress** – Both policies may apply depending on the user and scenario; UI inconsistencies may occur.  
- **Complete** – Modern Authentication Methods fully replace legacy MFA settings.

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-22-22.png)

For administrators attempting to restrict TOTP usage or enforce Microsoft Authenticator-only MFA, the migration status is critical. Tenants that have not reached the **Complete** state may still expose registration flows from the legacy system, including the option to use third-party authenticator apps—even when OATH TOTP appears disabled in the modern policy.

Once migration is complete, organizations gain deterministic control: Microsoft Authenticator can be enabled as the sole allowed method, and third-party OATH TOTP can be fully blocked at both registration and authentication time.

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-22-46.png)

---

## 2. Why Disabling OATH TOTP Is Not Always Enough

Many administrators assume that disabling the **OATH TOTP** method in the Authentication Methods policy should prevent users from adding third-party authenticator apps such as Google Authenticator or Authy. In practice, this is not always the case. Several environments have reported that users can still see the option *“Use a different authenticator app”* during MFA registration—even when OATH TOTP is disabled.

This behavior is explained by a key distinction in Entra ID:

**Registration** and **authentication** are governed by different components, and they do not always behave the same way.

When OATH TOTP is disabled:

- **Authentication** using third-party TOTP codes is correctly blocked.  
- **Registration** of third-party authenticator apps may still appear available if the tenant has not fully migrated from legacy MFA settings.

This mismatch typically occurs in tenants that are still in a **Pre-migration** or **Migration in progress** state. In such cases, legacy MFA registration flows can still surface UI elements that were originally designed to allow any TOTP-based authenticator app. As a result, users may be able to add an external authenticator app—even though they will not be able to authenticate with it.

Internal testing at Microsoft confirms this behavior:

- **Newly created users** in migrated tenants no longer see third-party apps when OATH TOTP is disabled.  
- **Existing users** or users in mixed-state tenants may still see legacy UI options for a period of time.  

The key takeaway is that disabling OATH TOTP alone does not guarantee a Microsoft Authenticator-only registration experience unless the tenant’s Authentication Methods migration status is **Complete**. Full enforcement requires both the modern policy and authentication strengths to be in place.

---

## 3. Enforcing Microsoft Authenticator During Registration

Enforcing Microsoft Authenticator as the only MFA method starts with controlling what users are allowed to register. This requires modern Authentication Methods to be fully authoritative and configured appropriately. When done correctly, users will no longer see the option to register third-party authenticator apps and will be guided directly toward Microsoft Authenticator.

### 3.1 Prerequisites

Before enforcing Microsoft Authenticator-only registration, the following conditions must be met:

- **Authentication Methods migration status must be set to “Complete.”**  
  Without this, legacy MFA components may still influence the registration UI and expose options for third-party apps.

  ![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-25-41.png)

- **Disable “Verification code from mobile app or hardware token” in legacy MFA settings.**  
  This legacy setting implicitly allowed *all* TOTP-based apps and must be turned off to avoid conflicts.

- **Disable “Third-party software tokens (OATH)” in the Authentication Methods policy.**  
  This removes the ability for users to authenticate using any non-Microsoft TOTP app.

  ![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-25-23.png)

- **Enable the Microsoft Authenticator method.**  
  This ensures it becomes the primary (and only) app-based MFA option for users.

- **Set “Allow use of Microsoft Authenticator OTP” to Yes.**  
  This enables the OTP fallback experience inside Microsoft Authenticator without relying on third-party TOTP methods.

  ![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-28-19.png)

When all conditions are satisfied, the modern method policy becomes deterministic and prevents the use of external apps during registration.

### 3.2 Expected Result

Once the prerequisites are in place, the user experience changes significantly:

- The option *“I want to use a different authenticator app”* no longer appears during registration.

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-29-59.png)

- Users are guided exclusively toward installing and registering **Microsoft Authenticator**.  

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-30-17.png)

- Any previously registered third-party authenticator apps remain visible but **cannot be used** for MFA authentication.

This produces a clean and consistent onboarding flow where Microsoft Authenticator becomes the only application users can register and use for app-based MFA.

---

## 4. Enforcing Microsoft Authenticator During Authentication

Even after restricting registration flows, users may still have legacy or third-party TOTP methods stored in their account. To fully guarantee that only Microsoft Authenticator can be used during MFA challenges, organizations must enforce this requirement at **authentication time**.

This is achieved through **Authentication Strengths**, the modern Conditional Access capability that defines exactly which methods are allowed for MFA.

### 4.1 Using Authentication Strengths

Authentication Strengths allow administrators to require specific MFA methods for specific scenarios. Microsoft provides built-in strengths such as *Phishing-resistant MFA*, but organizations can also create **custom strengths**.

To enforce Microsoft Authenticator-only MFA, create a strength that includes:

- **Microsoft Authenticator – Push notifications**
- Or/And **Microsoft Authenticator – (Phone sign-in)**

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-33-50.png)

All third-party authenticator apps rely on the **OATH TOTP** method, which can simply be excluded from the strength. Since an authentication strength explicitly defines the allowed methods, any method not included is automatically blocked—even if it is still registered on the user’s account.

This is the only enforcement mechanism that applies consistently during the authentication flow.

### 4.2 Conditional Access Enforcement

Once the custom authentication strength is created, it must be applied through a Conditional Access (CA) policy. Common deployment patterns include:

- Enforcing Microsoft Authenticator-only for **Specific Users**  
- Targeting **Apps**

![](assets/How%20to%20allow%20only%20Microsoft%20Authenticator%20in%20Entra%20ID/2025-12-09-16-35-52.png)

When a CA policy requiring the custom strength is triggered:

- Users with Microsoft Authenticator registered can authenticate normally  
- Users relying on Google Authenticator, Authy, or other TOTP apps will be blocked  
- Users with outdated or unsupported MFA methods will be prompted to register Microsoft Authenticator

This ensures full enforcement, even in scenarios where registration flows or legacy artifacts still exist.

---

## 5. Expected User Experience

Once Microsoft Authenticator is enforced through both the Authentication Methods policy and Authentication Strengths, the user experience becomes much more predictable. However, the behavior still differs slightly between new users, existing users, and external guests.

### 5.1 New Users

Newly created users in a fully migrated tenant see a clean and streamlined onboarding flow:

- During registration, only **Microsoft Authenticator** is offered.
- The option to use a third-party app does not appear.
- Users are guided through installing the app and completing the push or OTP setup.

This provides the most reliable experience and is the recommended way to validate your configuration.

### 5.2 Existing Users

Existing accounts may have previously registered third-party authenticator apps or legacy methods. With the new controls in place:

- Third-party apps may still appear in the **Security Info** page.
- However, they **cannot** be used for MFA authentication when a Conditional Access policy requires a custom authentication strength.
- If an unsupported method is attempted, the user will be prompted to complete registration for Microsoft Authenticator.

It is normal to see registrations persist temporarily—even though they are effectively unusable.

### 5.3 Guest and External Users

Guest users (B2B) introduce some additional complexity:

- They may not always be required to use Microsoft Authenticator, depending on your cross-tenant access settings.
- External users cannot always be forced into the same registration flow as internal users.
- Conditional Access with authentication strengths *will* still enforce Microsoft Authenticator at authentication time if the guest account signs in under your policies.

For sensitive applications or privileged access, organizations often apply Microsoft Authenticator-only MFA specifically to internal users and rely on alternative controls for guests.

---

## 6. Known Limitations (2025)

Even with modern Authentication Methods and Authentication Strengths in place, there are several important limitations to be aware of. These constraints reflect the current state of Entra ID and should be considered when designing an MFA strategy that relies exclusively on Microsoft Authenticator.

### 6.1 Users can register multiple Microsoft Authenticator instances
Entra ID does not currently allow administrators to limit the number of Microsoft Authenticator apps a user can register. Users may add the app on several devices (e.g., phone, tablet), and administrators cannot enforce a “single device only” policy.

### 6.2 Microsoft Authenticator OTP cannot be disabled if push is required
If you require Microsoft Authenticator for MFA, you cannot force users to rely *only* on push notifications.  
The OTP feature inside the app cannot be disabled independently, meaning:

- Push = allowed  
- OTP = always available as a fallback  

You can exclude OTP from an Authentication Strength, but this will also prevent the strength from accepting Microsoft Authenticator in fallback scenarios.

### 6.3 UI inconsistencies in tenants that are not fully migrated
Tenants that have not reached the **Complete** migration state may still display legacy registration screens. These screens can show the option to register a third-party authenticator app even when OATH TOTP has been disabled in the modern Authentication Methods policy.

These options usually disappear for:

- New users created after migration  
- Users who re-register methods  
- Tenants where all legacy policies have been fully decommissioned

### 6.4 Authentication Strengths do not apply to legacy protocols
Authentication Strengths only apply to modern authentication flows governed by Conditional Access.  
Legacy or non-interactive protocols (POP, IMAP, SMTP AUTH, older Office clients, or other legacy auth flows) do **not** support method restrictions. Organizations must block legacy authentication separately to ensure complete enforcement.

### 6.5 Third-party TOTP registrations may remain visible
Disabling OATH TOTP prevents **using** third-party authenticator apps, but it does not retroactively remove them from a user’s Security Info page. They remain visible until the user removes them manually or resets their MFA registration.

---

## 8. Conclusion

Enforcing Microsoft Authenticator as the only MFA method in Entra ID is fully achievable, but it requires using the modern authentication framework rather than relying on legacy MFA settings. Disabling OATH TOTP alone is not sufficient, especially in tenants that have not completed the Authentication Methods migration, where legacy registration flows may still expose the option to add third-party authenticator apps.

True enforcement happens only when two layers work together:

1. **Authentication Methods policy** controls which methods users are allowed to register.  
2. **Authentication Strengths** ensure that only the allowed methods can be used during authentication.

Once both are in place—combined with Conditional Access—organizations obtain a predictable and secure MFA experience where Microsoft Authenticator becomes the exclusive app-based method for all targeted users. This approach aligns with Microsoft’s modern identity strategy and provides the strongest, most consistent enforcement available today.


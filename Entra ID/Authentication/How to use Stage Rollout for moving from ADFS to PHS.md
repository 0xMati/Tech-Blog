# 🔄 Staged Rollout for Password Hash Synchronization (PHS)

**Staged Rollout** allows you to gradually migrate users from federated authentication (e.g., AD FS) to cloud authentication using **Password Hash Synchronization (PHS)** or **Pass-through Authentication (PTA)**. This approach enables safe testing with a subset of users before full rollout.

## ✅ Prerequisites

- **Role required**: Hybrid Identity Administrator in Microsoft Entra ID or Global Administrator
- **Microsoft Entra Connect** installed and updated.
- **PHS or PTA** must be enabled in your environment (PHS here in this example)
- **Security groups** created in Microsoft Entra ID to scope which users will use PHS cloud authentication
  - Limit: max 10 groups per method (no nested or dynamic groups).

## ⚙️ Setup Steps

1. **Be sure that Hashes are sync to Entra ID in your Federated environment**:
   - Open Microsoft Entra Connect.
   - Choose **Configure** > **Customize Synchronization options** > select **Optional Features**.
   - Enable Password Hash Synchronization

![](assets/How%20to%20use%20Stage%20Rollout%20for%20moving%20from%20ADFS%20to%20PHS/2025-05-21-11-59-15.png)

2. **Enable Staged Rollout** (via Entra portal):
   - Create a dedicated Security or M365 Group that will scope Users performing PHS authN
   - Go to **Azure Portal** → **Microsoft Entra ID** → **Microsoft Entra Connect** → **Connect Sync**.
   - Enable **Stage Rollout**.

![](assets/How%20to%20use%20Stage%20Rollout%20for%20moving%20from%20ADFS%20to%20PHS/2025-05-21-12-02-01.png)

   - Assign your target security groups.

![](assets/How%20to%20use%20Stage%20Rollout%20for%20moving%20from%20ADFS%20to%20PHS/2025-05-21-12-02-33.png)

![](assets/How%20to%20use%20Stage%20Rollout%20for%20moving%20from%20ADFS%20to%20PHS/2025-05-21-12-02-49.png)

3. **Monitor the rollout**:
   - Users in the group will start authenticating via PHS instead of ADFS.
   - Consult Audit/Signin Logs to check result

4. **Remove federation after testing**:
   - Once validated, convert the domain to managed using:

```powershell
Set-MgDomainFederationConfiguration -DomainId yourdomain.com -AuthenticationType Managed
```

---

For full details, see the official [Microsoft Docs](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-staged-rollout).

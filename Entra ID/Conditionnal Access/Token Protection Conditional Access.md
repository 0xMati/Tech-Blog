---
title: "Token Protection in Conditional Access"
date: 2025-04-22
---

## 🔐 Token Protection in Microsoft Entra ID

Token Protection is a **Conditional Access** feature in **Microsoft Entra ID** that enhances token security and reduces risks related to **token theft**. It ensures that **authentication tokens** issued to users cannot be reused from a different device or location, thus helping prevent attacks like **token replay**.

---

### 🧩 What Problem Does It Solve?

Tokens issued by identity platforms can be **copied** and **reused** by attackers on unauthorized systems. Traditional Conditional Access policies validate the environment only **at the time of sign-in**. Once a token is issued, it could potentially be reused elsewhere.

Token Protection changes this behavior by **binding the token to the client** and preventing its reuse elsewhere.

---

### 🛠️ How It Works

When Token Protection is enabled, the token includes information about the **client device** and **user session**. If the token is presented from a different context, Microsoft Entra ID will **deny access**.

- For **Windows devices**, the token is bound to a Primary Refresh Token (PRT).
- For **non-Windows platforms**, a session key is used that is not exportable.

---

### ✅ Supported Scenarios

- Azure AD joined and hybrid Azure AD joined **Windows 10/11** machines
- Microsoft apps like Outlook, Teams, and OneDrive for Business
- Supported token types: **Access Tokens** and **Refresh Tokens**

---

### 🚫 Not Supported (As of April 2025)

- iOS, Android, macOS
- Third-party applications
- Older Windows versions (pre-Windows 10)

---

### ⚙️ Enabling Token Protection

Token Protection is configured through **Conditional Access policies** in Entra ID.

Steps:
1. Go to **Entra ID Admin Center**
2. Navigate to **Security > Conditional Access**
3. Create or edit a policy
4. Under **Session controls**, enable **Require token protection**

![](assets/Token%20Protection%20Conditional%20Access/2025-04-22-17-32-02.png)


You can also choose between:


---

### 🧪 Monitoring and Troubleshooting

You can monitor token protection events through **Sign-in logs** in the Entra portal. Look for events where the policy was **applied or failed**, which can help detect suspicious token replays.

---

### 💡 Best Practices

- Start in **Report-Only** mode to evaluate compatibility
- Deploy to **pilot users** before enforcing
- Combine with **device compliance** and **app restrictions**

---

### 📚 References

- [Microsoft Learn - Token Protection](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection)

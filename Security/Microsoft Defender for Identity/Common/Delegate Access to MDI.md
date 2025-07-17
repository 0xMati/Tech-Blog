# Delegate Access to Microsoft Defender for Identity
🗓️ Published: 2025-07-17

Quick guide to give the right visibility to the right people—without granting unnecessary permissions.

---

## Delegate Access to Security Posture / Exposure Management  

The Exposure Management module in Defender portal identified all risks, and risks flagged by MDI.
You may want to grant visibility to non-technical stakeholders (e.g., executives, business owners) so they can track recommendations and help drive priorities.

### Steps to Configure Delegated Access to Exposure Management 

1. **Open the Microsoft 365 Defender portal**  
   Go to https://security.microsoft.com and sign in with an account that has admin privileges.

2. **Navigate to Roles & Permissions**  
   - In the left menu, select **Settings** → **Permissions & roles**.  

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-42-37.png)

3. **Create a Custom role**  

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-43-07.png)

    - Scope permissions to Exposure Management Read

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-43-26.png)

    - Add required Users

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-44-06.png)


### Results

> People will have access to Recommandations and Secure Score metrics, that can be filterd on MDI

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-45-12.png)

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-46-16.png)

---

## Delegate Access to Identity Secure Score

The Identity Secure Score is shown as a percentage that functions as an indicator for how aligned you are with Microsoft's recommendations for security.
Give stakeholders read‑only visibility into your Identity Secure Score and its recommendations, no extra permissions required.

### Steps to Configure Access to Identity Secure Score

1. **Open the Azure portal**  
   Go to https://portal.azure.com and sign in with an account that has admin privileges.

2. **Navigate to Roles**  

> To view the improvement action but not update, you need at least the Service Support Administrator role.

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-21-07-07.png)

### Results

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-21-07-46.png)
---

## Delegate Access to Alerts  

Alerts in Microsoft Defender for Identity surface critical suspicious activities and potential threats in real time. Delegating access to Alerts lets designated analysts or stakeholders view and triage incidents promptly—without granting them full administrative privileges.

### Steps to Configure Delegated Access to Alerts  

1. **Open the Microsoft 365 Defender portal**  
   Go to https://security.microsoft.com and sign in with an account that has admin privileges.

2. **Navigate to Roles & Permissions**  
   - In the left menu, select **Settings** → **Permissions & roles**.  

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-16-42-37.png)

3. **Create a Custom role** 

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-07-12.png)

    - Scope permissions to Alerts / Security data basics Read

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-08-07.png)

    - Optionaly you can scope Alerts and datas to a specific workload like MDI in Assignment
  ⚠️ -> MDI rely on MDCA, you need to add MDCA as a source to view MDI Alerts  

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-19-25.png)


### Results

> People will have read access to Alerts and basics security information, scoped.

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-20-29.png)



## Delegate Access to Audit logs that include XDR change configuration  

The unified audit logs in Microsoft Purview record configuration changes across your tenant, including who did what in the Defender XDR portal.
Delegate access to these logs to enable auditors or analysts to track XDR config changes without granting broader admin rights.

2 Permissions:

- **View‑Only Audit Logs**  
  - Read‑only access to all audit events (who, what, when).  
  - Ideal for stakeholders who only need to review activity.

- **Audit Logs**  
  - Read and export audit events.  
  - Recommended for people that need to archive or analyze logs offline.

> Both roles cover the entire tenant’s audit data, so delegates will see all audit events by default — including but not limited to XDR configuration changes.

### Steps to Configure Audit Roles Delegation in Purview

- Create a custom role in Purview

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-59-30.png)

### Results

> People will have read access to Audit logs, and are able to scope information on XDR infos.

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-18-00-34.png)


⚠️ Restricting Access to XDR‑Only Logs

You can grant read‑only access to XDR configuration events json config file :

{
  "Name": "XDR Configuration Audit Reader",
  "IsCustom": true,
  "Description": "Lecture seule des logs d’activité et de config pour Microsoft Defender XDR",
  "Actions": [
    "Microsoft.Insights/eventtypes/management/Read",
    "Microsoft.SecurityInsights/workspaces/read",
    "Microsoft.SecurityInsights/*/read"
  ],
  "NotActions": [],
  "AssignableScopes": [
    "/subscriptions/{SubID}/resourceGroups/{RG}/providers/Microsoft.SecurityInsights/{workspaceName}"
  ]
}

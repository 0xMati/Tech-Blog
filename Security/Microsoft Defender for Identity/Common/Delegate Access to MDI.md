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

    - Optionaly you can scope Alerts and datas to a specific workload like MDI
  ⚠️ -> MDI rely on MCAS, you need to add MCAS as a source to view MDI Alerts  

![](assets/Delegate%20Access%20to%20MDI/2025-07-17-17-19-25.png)


### Results

> People will have access to Alerts and basics security information, scoped.





## Delegate Access to Audit change configuration  

---

## 4. Delegating Sensor & Sensor Health Monitoring
- **Objective**: Allow infra operations to validate sensor deployment and health.  
- **Target Role**: Defender for Identity Sensor Viewer.  
- **Access to “Sensors” page and health dashboards**.  
- **Automated Escalation** for offline sensors.


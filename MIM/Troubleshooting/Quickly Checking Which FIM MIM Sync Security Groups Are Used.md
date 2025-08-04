# Quickly Checking Which FIM/MIM Sync Security Groups Are Used
🗓️ Published: 2025-08-04  

Based on the Identity Underground note: [Note-to-self: quickly checking which FIM Sync Security groups used](https://identityunderground.wordpress.com/2015/09/15/note-to-self-quickly-checking-which-fim-sync-security-groups-used/)

---

## Introduction

This guide explains how to quickly identify the security groups associated with your FIM Synchronization Service (FIM Sync / MIM Sync).  
It helps determine if the service is using **local groups** or **Active Directory groups**.  
While Microsoft recommends using AD groups, it is not always the case in some environments.

---

## Manual Check Using Component Services

### 1. Open Component Services
- On the Synchronization Service server, open **Component Services** or run **dcomcnfg**
- Navigate to: `Component Services → Computers → My Computer → DCOM Config`

![](assets/Quickly%20Checking%20Which%20FIM%20MIM%20Sync%20Security%20Groups%20Are%20Used/2025-08-05-00-53-46.png)

### 2. Switch to Details View
- If the console is showing icons, switch to **Details view** for easier navigation.

### 3. Locate the FIM Sync Service
- Find **Forefront Identity Synchronization Manager** (FIMSync Service).
- Right-click → **Properties**, then go to the **Security** tab.

![](assets/Quickly%20Checking%20Which%20FIM%20MIM%20Sync%20Security%20Groups%20Are%20Used/2025-08-05-00-54-11.png)

![](assets/Quickly%20Checking%20Which%20FIM%20MIM%20Sync%20Security%20Groups%20Are%20Used/2025-08-05-00-54-35.png)

### 4. Check Launch and Activation Permissions
- In the Security tab, locate the **Launch and Activation Permissions** section.
- Click **Edit** to view the assigned groups.  
  If the Edit button is greyed out, you may need to adjust registry permissions.

  ![](assets/Quickly%20Checking%20Which%20FIM%20MIM%20Sync%20Security%20Groups%20Are%20Used/2025-08-05-00-55-11.png)

### 5. Review the Groups
The list should show the security groups that can launch, activate, or access the service, for example:
- `FIMSyncAdmins`
- `FIMSyncOperators`
- `FIMSyncJoiners`
- `FIMSyncBrowse`
- `FIMSyncPasswordSet`
- System or service accounts such as `NT AUTHORITY\SYSTEM` or `CONTOSO\svcfimsync`

---

## Important Notes

- The groups can be **local groups** or **Active Directory groups**.
- Groups cannot be changed directly in DCOM.  

- To modify them, run the **Synchronization Service installation in repair mode** to reconfigure security (DCOM settings, registry, NTFS ACLs).

---

## Conclusion

This process provides a quick and reliable way to audit which groups control access to the FIM/MIM Synchronization Service.
It is recommended to regularly review these groups to ensure security best practices.

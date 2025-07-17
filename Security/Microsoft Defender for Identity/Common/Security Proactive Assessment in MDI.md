## Security Posture Assessments in Microsoft Defender for Identity
🗓️ Published: 2025-07-17

MDI continuously evaluates your on-premises Active Directory environment and delivers proactive insights and recommendations to strengthen your identity security posture.

---

### Benefits of Continuous Assessment

- **Full visibility**: uncover unsupported or outdated components and misconfigurations.  
- **Proactive defense**: fix risks before they become incidents.  
- **Data-driven**: get prioritized, actionable recommendations instead of generic checklists.  

---

### How to Access Your Continuous Assessments

> **Note:** You need a Defender for Identity license and appropriate sensors deployed for certain categories.

1. Open the **Microsoft Secure Score** dashboard at https://security.microsoft.com/securescore.  
2. Switch to the **Recommended actions** tab.  
3. Filter or search for **“Defender for Identity”** under the Identity category.  

![](assets/Security%20Proactive%20Assessment%20in%20MDI/2025-07-17-14-14-34.png)

4. Click on any **Defender for Identity security posture assessment** to view details, recommendations, and remediation steps.  

![](assets/Security%20Proactive%20Assessment%20in%20MDI/2025-07-17-14-15-18.png)

![](assets/Security%20Proactive%20Assessment%20in%20MDI/2025-07-17-14-15-47.png)

![](assets/Security%20Proactive%20Assessment%20in%20MDI/2025-07-17-14-16-03.png)

5. Check back anytime—scores refresh every 24 hours, and impacted entity lists update continuously.

---

### Key Assessment Categories

- **Hybrid security**: on-premises/cloud integration (AD ↔ Entra ID/Okta) misconfigurations.  
- **Identity infrastructure**: health of domain controllers, replication, and AD Connect.  
- **Certificates**: AD CS template and authority settings assessments.  
- **Group policy**: GPO reviews for privilege escalation and lateral movement risks.  
- **Accounts**: detection of weak passwords, stale accounts, and over-privileged identities.  

---

### Best Practices

- **Review regularly**: set a weekly or monthly check-in to monitor progress.  
- **Automate reporting**: pull Secure Score data into your SIEM or ticketing system if needed.
- **Coordinate fixes**: involve AD, network, and app teams to address findings quickly.  


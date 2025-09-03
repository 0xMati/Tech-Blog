# Automated actions with Microsoft Defender for Identity  ***IN PROGRESS***
🗓️ Published: 2025-08-01  

---

## Welcome!  

Hey there 👋, let’s talk about how you can make your life easier by automating actions in Microsoft Defender for Identity.  
Instead of manually chasing alerts and incidents, why not have your system take care of some responses automatically?  

In this guide, we’ll walk you through the steps to set up smart automations that react to security alerts — helping you stay on top without breaking a sweat.  

Ready to get started? Let’s dive in!  

---

## What happens by default in Microsoft Defender for Identity?

Before we dive into automation, let's clear up what Defender for Identity does out of the box.
By default, Microsoft Defender for Identity doesn’t automatically respond to alerts on its own.
Instead, it gives you the tools to **take action manually**, right from the interface.

Here are some of the key remediation actions you can perform directly in Defender for Identity:

- **Disable a user in Active Directory**  
  Temporarily blocks a user from signing in on-premises. Handy to stop compromised accounts from causing more damage.
- **Reset user password**  
  Forces the user to change their password at next sign-in, cutting off any ongoing unauthorized access.
- **Mark user as compromised**  
  Flags the user with a high-risk level to help prioritize investigations.
- **Suspend user in Entra ID or Okta**  
  Blocks new sign-ins and access to cloud resources or disables user accounts temporarily or permanently.
- **Require user to sign in again**  
  Revokes active sessions to force re-authentication.

To perform these actions, Defender for Identity uses the sensor installed on your domain controllers, which runs under the LocalSystem account by default. You can customize this by configuring a Group Managed Service Account (gMSA) with the exact permissions you want.

Also, you need the right permissions within Microsoft Defender XDR to take these actions—typically a custom role with response (manage) privileges.

## Example: Manual remediation in Defender for Identity

Imagine you receive an alert about a user account suspected of being compromised.

![](assets/Automated%20Actions%20with%20MDI/2025-08-01-23-24-44.png)

![](assets/Automated%20Actions%20with%20MDI/2025-08-01-23-25-08.png)

Using Defender for Identity, you can:

1. Navigate to the user’s page in the portal.  
2. Choose to **disable** the user’s Active Directory account to prevent any further sign-ins.  

![](assets/Automated%20Actions%20with%20MDI/2025-08-01-23-25-37.png)

![](assets/Automated%20Actions%20with%20MDI/2025-08-01-23-25-57.png)

![](assets/Automated%20Actions%20with%20MDI/2025-08-01-23-26-17.png)

3. Optionally, **reset the user’s password** to force them to choose a new one at next login.  
4. Mark the user as **compromised** to highlight the risk level.  
5. If using Entra ID or Okta, you can **suspend the user’s cloud access** temporarily.

All these actions are performed manually via the portal interface, giving you control over each step.

While this manual approach works, it can become time-consuming and error-prone at scale — especially in larger environments or during active attack investigations.

This is where automation comes in to save the day.

---

## Automating actions: Why and how?

So far, we’ve seen how Defender for Identity lets you manually respond to alerts. That’s great for smaller environments or one-off cases. But when you’re dealing with many alerts, or need a faster response to threats, manual intervention just isn’t enough.

Good news: you can automate responses to MDI alerts to save time, reduce errors, and improve your security posture.

Here are some popular tools and approaches you can use to automate actions:

- **Microsoft Sentinel**  
  With its native integration to Defender for Identity, Sentinel centralizes alerts and lets you create detection rules and automated workflows called playbooks to react instantly.
- **Azure Logic Apps**  
  Create custom workflows triggered by alerts, capable of sending notifications, executing scripts, calling APIs, or updating systems — all without manual clicks.
- **Power Automate**  
  Microsoft's user-friendly automation platform that integrates well with many Microsoft services, enabling you to create automated flows responding to alerts without deep coding.
- **PowerShell scripting**  
  For those who like hands-on control, scripts can query alerts via APIs and perform remediation actions like disabling accounts or resetting passwords automatically.
- **SOAR platforms (Security Orchestration, Automation and Response)**  
  Tools like Microsoft Sentinel, Palo Alto Cortex XSOAR, or Splunk Phantom provide advanced automation and orchestration capabilities, integrating multiple security products into seamless response pipelines.
- **Microsoft Graph API**  
  Useful for integrating and automating user management tasks across Azure AD and Microsoft 365 services in response to security signals.

Each of these tools has its strengths and is suited for different environments and skill sets.  

In the next section, we’ll start by connecting Defender for Identity to Microsoft Sentinel to set the foundation for automation.

---

## Microsoft Sentinel and Defender for Identity Automation

### 1. Why Microsoft Sentinel?

Microsoft Sentinel is a powerful cloud-native Security Information and Event Management (SIEM) and Security Orchestration, Automation, and Response (SOAR) solution. It integrates seamlessly with Microsoft Defender for Identity to help security teams centralize alert management and automate responses.

Here’s why Sentinel is a great choice for automating responses to Defender for Identity alerts:

- **Centralized alert management**  
  Sentinel collects alerts from Defender for Identity and many other security sources in one place.
- **Custom detection rules**  
  You can write precise queries to spot the alerts and incidents that matter most to you.
- **Automated playbooks**  
  Using Azure Logic Apps under the hood, playbooks let you build workflows that react automatically — sending notifications, creating tickets, or even remediating threats directly.
- **Scalability and flexibility**  
  Sentinel can handle vast volumes of data and complex workflows, perfect for any size of environment.
- **Rich ecosystem**  
  With many built-in connectors and templates, integrating Sentinel into your existing security operations is straightforward.

### 2. Connecting Microsoft Defender for Identity to Sentinel

To start automating actions based on Defender for Identity alerts, you first need to connect MDI to Microsoft Sentinel. This allows Sentinel to ingest all relevant security alerts and incidents, and set the foundation for automation.

#### Prerequisites

- Access to the Azure portal with sufficient permissions to configure Sentinel and MDI.  
- An existing Microsoft Sentinel workspace in the same region as your resources.  
- Appropriate role assignments, typically Security Administrator or Contributor on the Sentinel workspace.

#### Step-by-step connection

1. Open the Azure portal and navigate to your Microsoft Sentinel workspace.  
2. In the Sentinel workspace menu, click on **Data connectors**.  
3. Search for **Microsoft Defender for Identity** in the list of connectors.
   - Depending on your licensing and setup, you might also see the **Microsoft Defender XDR** connector available.  
   - You can connect either **MDI** or **Microsoft Defender XDR** (which includes MDI among other Defender solutions) based on what fits your environment.

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-02-07.png)
 
4. Select the connector and click **Open connector page**.  
5. Click on **Connect** or **Configure**.  
6. Enable data collection for Defender for alerts.  

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-03-21.png)

7. Wait a few minutes and verify that alerts start to flow into Sentinel.

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-04-19.png)

#### Validation

Once connected, you can verify the integration by querying the Sentinel logs:

```kql
SecurityAlert
| where ProviderName == "Azure Advanced Threat Protection"
| sort by TimeGenerated desc
| take 5
```

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-08-22.png)

Verify as well that incident are synced from XDR portal to Sentinel:

![](assets/Automated%20Actions%20with%20MDI/2025-09-03-20-32-32.png)


### 3. Define and build our testing Scenario

In our scenario, when a honeytoken is triggered on a workstation, an alert email is sent and the corresponding computer is disabled in Active Directory. This is a basic scenario, not necessarily realistic, but it helps us understand how to implement automation.

#### Step 1 - Build the Playbook

A Playbook is essentially an Azure Logic Apps workflow that reacts to alerts and incidents in our case.
Here, the Playbook is triggered when a honeytoken incident is created through Defender XDR.

This Playbook performs two key actions:

It collects information from the incident (such as involved hosts and accounts).
- It sends a structured alert email
- initiates a response workflow — such as disabling the compromised host account in Active Directory via Azure Automation.

This sets the foundation for automating your detection and response workflows.

#### How to create the playbook:

1. In the Azure portal, navigate to your Microsoft Sentinel workspace.  
2. Go to the **Automation** tab and click **Create a playbook** with Incident Trigger.

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-12-02-21.png)

4. Give it a meaningful name like "Playbook_Disable_AD_Account" and create the playbook.

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-23-00.png)

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-23-24.png)

![](assets/Automated%20Actions%20with%20MDI/2025-08-02-00-23-36.png)

5. Logic App Design will now open

- You'll find an empty Playbook with "Microsoft Sentinel Incident" as a start
- Add all actions required.

- Let start the test with an email sent :

![](assets/Automated%20Actions%20with%20MDI/2025-09-03-20-45-15.png)

-> You can find the example json to import here (just fill/replace Email, SubscriptionID and ResourceGroup Name): 

7. Save and publish the playbook.

#### Step 2 - Link the Playbook to an automated rule:

An automation rule links the previously created Playbook to an incident generated in Sentinel — in our scenario, the Honeytoken incident. This ensures that the Playbook is triggered automatically each time the corresponding incident is detected, allowing the defined actions to run without manual intervention.

- Create the rule:
1. In the Microsoft Sentinel workspace, navigate to the **Automation** section.  
2. Click **Create** > **Automation rule**.  

![](assets/Automated%20Actions%20with%20MDI/2025-09-03-20-55-49.png)

3. Give your automation rule a clear name, such as “AR_Honeytoken_IncidentResponse”.
4. Define conditions.  
5. In the **Actions** section, add the playbook(s) you want to run automatically in response to the alert.  
6. Save and activate the automation rule. 

![](assets/Automated%20Actions%20with%20MDI/2025-09-03-20-57-14.png)

---

With this automation rule in place, any alert generated by your detection rule will automatically trigger the linked playbook(s), enabling real-time, hands-off response to threats.

---

Next, we will focus on building the playbook that will perform the actual account disablement in Active Directory.
# MDO – What is Microsoft Defender for Office and how to configure Preset Policies ?
🗓️ Published: 2024-04-22  

---

## Introduction

Every mailbox in Office 365 have a basic level of protection : Exchange Online Protection (EOP) with :
    - AntiPhishing
    - AntiSpam
    - AntiMalware


Since a lot of attack starts with email, you should have the best protection possible on this part.

Microsoft Defender for Office has 2 plans :

    - MDO for Plan 1
    - MDO for Plan 2


There is two differents configuration options :
    
    - Easy configuration, where you accept Microsoft recommandations
    - Manual configuration, to set all parameters to suit your needs


## Easy Configuration / Preset Security Settings


### Access the Defender Portal

Go to security.microsoft.com, and the "Email & Collaboration" blade:

![](assets/What%20is%20MDO/2025-04-22-15-56-42.png)


You'll see "Policies & Rules", and got to "Threat polocies"

![](assets/What%20is%20MDO/2025-04-22-15-58-13.png)


In threat Policies, you can see 3 blocks here :

![](assets/What%20is%20MDO%20and%20how%20to%20configure%20it/2025-04-22-16-12-57.png)

     - Buit-in protection
     - Standard protection
     - Strict protection

All differences can be found here : https://learn.microsoft.com/en-us/defender-office-365/recommended-settings-for-eop-and-office365

You can decide which is the right configuration for you.


Something interesting is that you can choose which kind of people (Users, Groups, Domains) will have applied the built-in, standart or strict policy settings.

For example :

Start with EOP :

![](assets/What%20is%20MDO%20and%20how%20to%20configure%20it/2025-04-22-16-48-46.png)

Next with Defender for O365 (Advanced features, let's see them later)

![](assets/What%20is%20MDO%20and%20how%20to%20configure%20it/2025-04-22-16-49-19.png)

Impersonation protection, where you want to protect special people from being impersonated (VIP, Seniors ...)

![](assets/What%20is%20MDO%20and%20how%20to%20configure%20it/2025-04-22-16-53-50.png)

![](assets/What%20is%20MDO%20and%20how%20to%20configure%20it/2025-04-22-16-54-49.png)


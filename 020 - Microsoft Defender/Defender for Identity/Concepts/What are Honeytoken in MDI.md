---
title: "What’s a HoneyToken in Microsoft Defender for Identity?"
date: 2025-07-17
---

# What’s a HoneyToken in Microsoft Defender for Identity?

A **HoneyToken** in the MDI world is essentially a decoy identity—an Azure AD account you create just to catch the bad guys. You spin up a user that shouldn’t ever see real traffic or log-ins, then let Defender for Identity watch it. If someone tries to use or probe that account, MDI flags it as suspicious, and you get an alert that someone’s poking around where they shouldn’t.

> Think of it as bait: you wouldn’t stock your fridge with spoiled milk, but if an intruder drinks it, you know they’re in your kitchen.

---

## Why Defender for Identity Teams Love HoneyTokens

- **Early breach detection**: honey accounts are zero‑legit–use, so any activity on them is an immediate red flag.  
- **Lateral movement catch**: attackers often hunt for accounts to pivot—your HoneyToken account is a perfect tripwire.  
- **Minimal noise**: unlike real user accounts, there’s no normal background activity, so you avoid alert fatigue.  
- **Easy integration**: alerts land right in the MDI portal, and you can push them to your SIEM or Teams/Slack channels.

---

## How to Configure a HoneyToken in MDI

### 1. Create your decoy account in Active Directory
2. **Pick a bait-worthy name** that screams privilege—think `Admin`, `SQLAdmin`, `ServiceAccount`, etc. Attackers love high-privilege sounding accounts.
Ensure the display name is the juicy lure.
4. Don’t assign any roles or permissions this account should be a ghost until an attacker stirs.

### 2. Add it as a HoneyToken in Defender for Identity
1. Open the **Microsoft Security** portal.
2. Navigate to **Settings  > HoneyToken**.
3. Click **Add account**, then search for your `honeytoken account`.

![](assets/HoneyToken%20in%20MDI/2025-07-17-13-30-35.png)

### 3. Check alert notifications
- **In MDI**: Under **Incidents & Alerts**, verify all Alerts related to your HoneyToken.

![](assets/HoneyToken%20in%20MDI/2025-07-17-13-33-57.png)

---

## Best Practices

- **Keep it clean**: no licenses, no sign‑ins—if you see a log, it’s 100% malicious or accidental leak.  
- **Scatter and label**: deploy multiple HoneyToken accounts across domains, OUs or apps; name them consistently so you know where the probe hit.  
- **Rotate names**: periodically retire old honey accounts and spin up new ones to avoid staleness.  
- **Document response steps**: have a runbook for investigating HoneyToken alerts so your team jumps on incidents lightning‑fast.

---

HoneyTokens in MDI are a lightweight, high‑value trick to catch intruders early. Give it a spin, and happy hunting! 😉


---
title: "Designing a High Availability Architecture for Entra ID Connect"
date: 2025-04-24
---

## Introduction

This guide outlines best practices and detailed steps to design a high availability (HA) architecture for Microsoft Entra ID Connect by adding an additionnal server with same configuration.
It can be used as well to perform a swing migration.
It focuses on scenarios using SQL Express and includes procedures for staging server deployment, configuration comparison, upgrade strategies, server role switching, and backup guidance.

## General Guidance

In some cases, having only one Entra ID Server can impose a considerable risk to production in case there's an issue while upgrading and the server can't be rolled back. A single production server might also be impractical as the initial sync cycle might take multiple days, and during this time, no delta changes are processed.

The recommended method for these scenarios is to use an Entra ID Staging server. You can also use this method when you need to upgrade the Windows Server operating system, upgrade Entra ID Connect version, or you plan to make substantial changes to your environment configuration, which need to be tested before they're pushed to production.

Your architecture will contain two servers - one active server and one passive (staging) server. The active server (shown with solid blue lines in the following diagram) is responsible for the active production load. The staging server (shown with dashed purple lines) is running only import and sync cycles load, no export is done to data sources, but is ready to take the production load (exports) if needed.
The staging server can as well be prepared with the a release or configuration. When it's fully ready, this server is made active. The previous active server, which now has the outdated version or configuration installed, is made into the staging server and is upgraded.

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-55-55.png)

## Key Topics

- Installing a passive (staging) server
- Comparing configurations between servers
- Upgrading Entra ID Connect with minimal disruption
- Switching roles between active and passive servers
- Backup strategies and best practices

## Architecture Overview

To ensure resilience, use a dual-server setup:
- **Active Server**: Handles production load and exports.
- **Passive Server**: Runs sync cycles without exporting data; ready to become active if needed.

## Setup Instructions

### Step 1: Export Configuration from Production
Run the Entra ID Connect Wizard, export current configuration and use this to configure your staging server.
On the current production server, we’ll generate a file that contains the actual configuration of Entra ID connect. We’ll use this file to automatically configure the passive server.

    - Run Entra ID Connect Wizard

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-57-01.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-57-18.png)

    - Choose “View or export current configuration”

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-57-38.png)

    - Clic on “Export settings”

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-58-00.png)

    - Save the file and copy it to the server that you will use as passive/Staging

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-58-37.png)



### Step 2: Install the Staging Server
Use the same or newer version of Entra ID Connect. Opt for customized setup to match your existing environment, and import the configuration settings exported in Step 1.
https://www.microsoft.com/en-us/download/details.aspx?id=47594

    - Run the installer and follow instruction

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-59-41.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-15-59-51.png)

    - Do not Use “Express Setting”, use the Customize option

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-00-19.png)

    - You can change the default configuration to fit yours needs. Import the previous configuration file that has been exported from existing server :

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-01-19.png)

    - Custom installation location let you install the product in another location:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-01-48.png)

    - Use an existing SQL Server is only used if you are using a SQL Server instead of SQ Express:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-02-07.png)

### Step 3: Verify Configuration
Ensure the same credentials, sync rules, and connector setup. Enable **Staging Mode** during the final setup screen.

## Comparing Configuration

Use tools like:
- **Statistics Comparison** in Sync Manager
- **Azure AD Connect Configuration Documenter** for detailed diffs
- **CSExport** and **CSExportAnalyzer** for connector space analysis

## Upgrade Strategy

### Option 1: Upgrade In Place
Upgrade the passive server first, test and switch roles. Then, upgrade the previous production server.

### Option 2: Rebuild Staging Server
Deploy a new server for upgrades involving major OS or hardware changes.

## Switching Server Roles

Switching between active and passive roles is simple using the setup wizard. Always confirm configurations are aligned using the tools mentioned above.

## Backup Practices

- Regular full VM backups (especially with SQL Express)
- Periodic exports of configuration and sync rules
- Keep documentation scripts automated and scheduled

## Best Practices

- Avoid dual active configurations
- Disable auto-updates and follow N-1 versioning
- Use identical service accounts across servers
- Monitor permissions and network prerequisites

## References

- [Azure AD Connect Install Prerequisites](https://learn.microsoft.com/fr-fr/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)
- [Network Requirements](https://learn.microsoft.com/fr-fr/entra/identity/hybrid/connect/reference-connect-ports)

> _Prepared by Mathias Motron, Senior Cloud Solution Architect Engineer_

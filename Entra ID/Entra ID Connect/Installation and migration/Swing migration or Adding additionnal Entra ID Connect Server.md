---
title: "Designing a High Availability Architecture for Entra ID Connect, or performing a swing migration"
date: 2023-07-18
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

    - Use an existing service Account let you use a dedicated service account that can be a GMSA or AD account to run the Sync engine on the server (this is not the MA Account):

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-03-07.png)

It is a good practice to use the same between the Production and staging service, otherwise it will use a Local System Account on the machine

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-03-22.png)

    - Use Custom groups for Entra ID connect administration:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-03-49.png)

By default, the installer will create 4 local groups on the machine to let you delegate administration of Entra ID Connect, you can change the name according to your needs.

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-04-04.png)

    - Import Configuration settings option let you import a configuration file from another Entra ID Server. We can use this option right now to import configuration for the update process. 

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-04-32.png)

    - Launch the install and wait until finish

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-04-56.png)

    - After the installation of binaries, a new assistant will load, and ask you to verify configuration:

Verify Signin method, Connection to Entra ID with Global Admin cred

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-06-48.png)

    - For each on-premises directory included in your synchronization settings, you must provide credentials to create a synchronization account or supply a pre-created custom synchronization account.

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-07-16.png)

It is highly recommended to use same accounts for management agent on production and passive server. You can check with accounts is used in your current production server if you run the wizard and clic on “Review current configuration”:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-07-37.png)

    - In the passive server, fill in credentials to use:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-08-12.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-08-22.png)

    - Review all configuration that will automatically be done and be sure that the check box to enable staging mode is enable

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-08-45.png)

Wait for the process to complete and your passive/staging server is ready.

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-09-11.png)



*** Warning ***

Here are known limitations:
-	Synchronization rules: The precedence for a custom rule must be in the reserved range of 0 to 99 to avoid conflicts with Microsoft's standard rules. Placing a custom rule outside the reserved range might result in your custom rule being shifted around as standard rules are added to the configuration. A similar issue will occur if your configuration contains modified standard rules. Modifying a standard rule is discouraged, and rule placement is likely to be incorrect.

-	Device writeback: These settings are cataloged. They aren't currently applied during configuration. If device writeback was enabled for your original server, you must manually configure the feature on the newly deployed server.

-	Synchronized object types: Although it's possible to constrain the list of synchronized object types (such as users, contacts, and groups) by using the Synchronization Service Manager, this feature isn't currently supported via synchronization settings. After you finish the installation, you must manually reapply the advanced configuration.


-	Configuring the provisioning hierarchy: This advanced feature of the Synchronization Service Manager isn't supported via synchronization settings. It must be manually reconfigured after you finish the initial deployment.

-	A disabled custom synchronization rule will be imported as enabled: A disabled custom synchronization rule is imported as enabled. Make sure to disable it on the new server too.

--> Quickly review your new Entra ID Connect Staging server, you’ll find your custom rules, and configuration:


![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-10-05.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-10-18.png)


## Comparing Configuration between servers

We’ll cover many ways to verify that the configuration is the same between servers (active/passive), use the method that fits you.

Use tools like:
- **Statistics Comparison** in Sync Manager
- **Azure AD Connect Configuration Documenter** for detailed diffs
- **CSExport** and **CSExportAnalyzer** for connector space analysis

### Explore statistics on servers

If your active and passive servers have the same configuration (import options, filters, etc.), it means that they should have the same number of objects

•	On each server, open statistics, compare, and check that number of objects are the same:

-	Clic on Tools, statistics:

On the production server:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-13-03.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-13-12.png)

On the staging server:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-13-31.png)

NB : A few difference does not mean that there is a problem, sometime few orphaned objects can appears on Entra ID Connect, we are looking here for lot of difference to indicate something like a filter difference.

### Compare configuration with Entra ID Connect Configuration Documenter

AAD Connect configuration documenter is a tool to generate documentation of an Azure AD Connect installation. 
The goal of this project is to:
-	To enable quick understanding of the synchronization configuration 
-	To know what was changed when you applied a new build / configuration of Azure AD Connect or added/updated custom sync rules

The current capabilities of the tool include:
-	Documentation of the complete configuration of Azure AD Connect sync.
-	Documentation of any changes in the configuration of two Azure AD Connect sync servers or changes from a given configuration baseline.
-	Generation of the PowerShell deployment script to migrate the sync rule differences or customizations from one server to another.

•	Download the tool “Azure AD Connect Configuration Documenter” from github:
https://github.com/microsoft/AADConnectConfigDocumenter

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-14-22.png)

•	Extract the zip file, this will extract the Documenter application binaries along with the sample data files for "Contoso".

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-14-38.png)

•	Create a folder structure for your organization:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-15-02.png)

•	Edit the cmd file to match your structure:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-15-20.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-15-27.png)


•	Export the production configuration:
Import-Module ADSync
Get-ADSyncServerConfiguration -Path "C:\Users\mathiasadmin.MATHIASMOTRON\Downloads\AADC Documenter\AzureADConnectSyncDocumenter\Data\MathiasMotron\Production"

 
•	Export the production configuration:
Import-Module ADSync
Get-ADSyncServerConfiguration -Path "C:\Users\mathiasadmin.MATHIASMOTRON\Downloads\AADC Documenter\AzureADConnectSyncDocumenter\Data\MathiasMotron\Staging"


-	At this point have production and staging folder filled with configuration files:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-15-53.png)

-	Run the cmd to generate the report:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-16-08.png)

-	You can now analyze the report:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-16-22.png)

-	You can filter the report to show only difference between platforms:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-16-38.png)

-	You’ll be able to see all differences between your 2 servers:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-16-53.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-17-02.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-17-12.png)

--> You can see in this example that some differences exist even if we use the export/import configuration file !


### Use CSExport to dump what will happen if you enable the Passive (Staging) server as Active

When you think you configuration is identical between yours servers, and you need to switch the staging server to active, you can first dump the connector space to have a look on what will happen if you put this server in production.

-	Be sure that Production and Passive/Staging Service did a full sync cycle and have the same level of information at the same time. You can trigger a full sync cycle with the powershell command: Start-ADSyncSyncCycle -PolicyType Initial 


![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-18-41.png)

-	On the Passive/Staging server, find the tool CSEXPORT in “C:\Program Files\Microsoft Azure AD Sync\Bin”

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-18-56.png)

-	Export pending operation for your MAs:
csexport.exe "Connector_name" /f:x

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-19-10.png)

Example 1:
csexport "mamotron.onmicrosoft.com - AAD" /f:x
csexport "mathiasmotron.com" /f:x

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-19-28.png)

--> In that case, no difference will be done, we are good !

Example 2:
csexport "mamotron.onmicrosoft.com - AAD" /f:x
csexport "mathiasmotron.com" /f:x

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-19-55.png)

--> Few differences are detected on connectors let’s analyze.

-	Convert the xml export in CSV type for easier troubleshoot with CSEXPORTANALYZER:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-20-25.png)

.\CSExportAnalyzer.exe "input_xml" > "output_csv”

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-20-39.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-20-51.png)

-	You’ll be able to quickly see what kind of changes will be triggered and analyze why:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-21-06.png)

--> OMODT column will tell what kind of operation will be performed, it could be ADD, DELETE or UPDATE

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-21-26.png)

--> AMODT column will tell you in case of UPDATE what will be changed :

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-21-43.png)


--> You need to review each change and verify why it is happening.
--> When you upgrade the version of Entra ID Connect, it could be normal to have some UPDATE because usually new version are bringing new attributes synchronized!




## Upgrade Strategy with 2 Servers

When you have 2 Entra ID Connect servers with SQL Express, one in production and another on as passive, you can choose 2 methods to upgrade yours servers.

### Option 1: Upgrade In Place
This method is preferred when you have less than about 100,000 objects. If there are any changes to the out-of-box sync rules, full import and full synchronization will occur after the upgrade. This method ensures that the new configuration is applied to all existing objects in the system.

•	Run the installer of the new Entra ID Connect version on the staging server:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-23-06.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-23-14.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-23-32.png)

•	After the upgrade process, just do a CSEXPORT/CSEXPORTANALYZER to review change and check that everything is normal

•	If everything is normal put the current production server as Staging and put the upgraded server as Production

•	Next step is to upgrade the old production server to have an identical version between your 2 servers



### Option 2: Rebuild Staging Server
In some case, it is better to completely recreate your servers during an upgrade of Entra ID Connect (change Server, upgrade OS Version).
In this case just follow the steps described in Part 3 to install a new staging server.
When the upgrade is done and your new server is the production one, repeat the process to create another Staging/Passive server.


## Switching Server Roles

Inverting production server and passive/staging server is a simple process, but before any operation, be sure that Active and Passive servers are the same, you can follow steps in Part 4 to compare configuration with Azure AD Connect Documenter and CSExport.
•	Put your current production server as Staging with the Entra ID Connect wizard:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-24-25.png)

-	Choose Staging mode option:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-24-39.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-24-55.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-25-07.png)

-	Your production server is now a passive server

•	Follow the same step on the Passive server that you want to put in production, uncheck the box “Staging mode”

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-25-23.png)


## Backup Practices

Many options can be used to backup Azure AD Connect.

•	Perform a full backup of the server (like with Window Server backup)
If you use SQL Express, you can restore the entire server, everything will be included in the server, and you’ll be able to re-run the service.

•	Regularly export your settings:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-25-45.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-25-53.png)

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-26-00.png)

-	Regularly export your custom Sync Rules:

![](assets/Swing%20migration%20or%20Adding%20additionnal%20Entra%20ID%20Connect%20Server/2025-04-24-16-26-14.png)

--> You don’t really need to backup the database in fact, creating a new server with the exact same configuration will result in the same data in the DB.

## Best Practices

- DO NOT use dual active configurations
- Enable auto-updates if possible 
- stay at least at N-1 version
- Use identical service accounts across servers
- Monitor permissions and network prerequisites

## References

- [Azure AD Connect Install Prerequisites](https://learn.microsoft.com/fr-fr/entra/identity/hybrid/connect/how-to-connect-install-prerequisites)
- [Network Requirements](https://learn.microsoft.com/fr-fr/entra/identity/hybrid/connect/reference-connect-ports)



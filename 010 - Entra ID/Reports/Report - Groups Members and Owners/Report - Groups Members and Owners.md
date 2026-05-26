# Entra ID Groups Dashboard
🗓️ Published: 2026-02-25

## Purpose

This Power BI dashboard provides an overview of **Microsoft Entra ID (Azure AD) groups** in your tenant. It connects directly to the **Microsoft Graph API** to retrieve group information, owners, and members.

Use it to:
- Identify groups **without owners** (governance risk)
- Spot **empty groups** that could be cleaned up
- Understand the **distribution of group types** (Microsoft 365, Security, Distribution, etc.)
- See which users **own the most groups**
- Browse the **full member list** of each group

---

## Dashboard Pages

| Page | Description |
|---|---|
| **Overview** | KPI cards (total groups, with/without owner, empty), donut charts by type and owner status, size distribution |
| **Owners Analysis** | Unique owners count, % without owner, avg owners per group, top owners bar chart, group detail table |
| **Members Analysis** | Total members, avg/max members per group, top groups by member count, detail table |
| **Details & Filters** | Slicers (type, owner, dynamic, visibility, size) + full filterable group table |
| **Members List** | Searchable table of all members with group name, display name, email, type — filterable by group and member type |

---

## Prerequisites

### 1. Entra ID App Registration

1. Go to [Azure Portal](https://portal.azure.com) > **Microsoft Entra ID** > **App registrations** > **New registration**
2. Name: e.g. `PowerBI-GraphAPI-Groups`
3. Supported account types: **Single tenant**
4. Click **Register**

### 2. API Permissions

In your app registration, go to **API permissions** > **Add a permission** > **Microsoft Graph** > **Application permissions**:

| Permission | Purpose |
|---|---|
| `Group.Read.All` | Read all groups |
| `GroupMember.Read.All` | Read group members and owners |
| `Directory.Read.All` | Read directory data |

Then click **Grant admin consent**.

### 3. Client Secret

Go to **Certificates & secrets** > **New client secret**:
- Description: e.g. `PowerBI`
- Expiry: choose as needed
- **Copy the secret value immediately** (it won't be shown again)

### 4. Collect these values

| Value | Where to find it |
|---|---|
| **Tenant ID** | App registration > Overview |
| **Client ID** | App registration > Overview |
| **Client Secret** | The value you just copied |

---

## Setup in Power BI

1. Open `Dashboard_EntraID_Groups.pbip` in **Power BI Desktop**
2. You will be prompted to enter 3 parameters:
   - **TenantId** — your Azure AD tenant ID
   - **ClientId** — the application (client) ID
   - **ClientSecret** — the client secret value
3. When prompted for **Web Content access**, select **Anonymous** (OAuth is handled internally by the query)
4. Click **Refresh** to load data from Microsoft Graph

---

## Data Refresh

- Click **Home > Refresh** to pull fresh data from Graph API
- The dashboard fetches: all groups, their owners, their members, and member counts
- For large tenants (1000+ groups), the initial refresh may take a few minutes due to pagination

---

## Sharing

- **As .pbix**: File > Save As > select `.pbix` format — this bundles everything into a single file
- **As PBIP folder**: share the entire `Dashboard_EntraID_Groups.*` folder structure
- **To Power BI Service**: click **Publish** to upload to your workspace

> ⚠️ The client secret is stored in the data source parameters. Only share with authorized users.

---

## Project Structure

```
Dashboard_EntraID_Groups.pbip              # Entry point
Dashboard_EntraID_Groups.Report/           # Report layout (pages, visuals)
  ├── report.json
  ├── definition.pbir
  ├── item.config.json
  └── item.metadata.json
Dashboard_EntraID_Groups.SemanticModel/    # Data model (tables, measures, M queries)
  ├── model.bim
  ├── definition.pbism
  ├── item.config.json
  └── item.metadata.json
```

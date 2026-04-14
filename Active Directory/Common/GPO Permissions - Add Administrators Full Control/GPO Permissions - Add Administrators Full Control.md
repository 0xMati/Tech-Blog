---
title: "GPO Permissions - Add Administrators Full Control"
date: 2026-01-22
---

# GPO Permissions — Add Built-in Administrators Full Control

## Problem Statement

By default, the **Built-in Administrators** (`BUILTIN\Administrators`) group is **not** included in the default security descriptor of the `groupPolicyContainer` schema class. This means that when a new GPO is created, the Administrators group does **not** automatically receive Full Control.

The default SDDL for `groupPolicyContainer` typically grants Full Control to:
- **DA** — Domain Admins
- **EA** — Enterprise Admins
- **CO** — Creator Owner
- **SY** — SYSTEM
- **AU** — Authenticated Users (Read only)

But **BA** (Built-in Administrators) is absent.

This can cause operational issues when the Administrators group needs to manage GPOs — for example, delegated administration scenarios, or tools that operate under the context of the local Administrators group.

## Is This a Best Practice?

This is a **common operational choice**, but not a universal recommendation. Whether it's right for your environment depends on your security posture and delegation model.

### Why you might want it

- **Resilience**: If Domain Admins or Enterprise Admins group memberships are accidentally modified, or if a DA account is compromised and disabled, the Administrators group still retains control over GPOs. It acts as a **safety net**.
- **Delegation consistency**: In environments with delegated administration, processes or service accounts that run under `BUILTIN\Administrators` (but are not in DA/EA) need explicit access to manage GPOs.
- **Alignment with other AD objects**: Most other AD objects and containers grant Full Control to Built-in Administrators by default. The `groupPolicyContainer` class is an exception, which creates an inconsistency.
- **Tooling**: Some management tools operate under the Administrators context and fail on GPO operations without this ACE.

### Why you might NOT want it

- **Least privilege**: Adding BA widens the number of principals with Full Control on GPOs. In a strictly hardened environment, you may prefer to limit GPO management to only Domain Admins and Enterprise Admins.
- **Redundancy in most cases**: Domain Admins are automatically members of `BUILTIN\Administrators` on domain controllers. If your GPO management is exclusively done by DA/EA members, the BA ACE may be unnecessary.

### Recommendation

> In most enterprise environments, adding the BA ACE is a **reasonable hardening measure** that improves operational resilience without meaningfully increasing risk — since members of `BUILTIN\Administrators` on DCs are already highly privileged. However, evaluate your own delegation model before applying.

---

## Solution Overview

The fix involves **two steps**:

| Step | Scope | Script |
|------|-------|--------|
| **1. Remediation** | All existing GPOs in a domain | `Set-GPOAdministratorsFullControl.ps1` |
| **2. Schema Modification** | All **new** GPOs (forest-wide) | `Set-GPODefaultSchemaPermission.ps1` |

> ⚠️ Step 2 is a **schema modification** that affects the entire **forest**. It requires **Schema Admins** membership.

---

## Step 1 — Remediate Existing GPOs

### Purpose

Add `Administrators` with **Edit settings, delete, modify security** (`GpoEditDeleteModifySecurity`) on all existing GPOs in a domain.

### Usage

```powershell
# Audit only — no changes, produces a CSV report
.\Set-GPOAdministratorsFullControl.ps1

# Audit + Remediate — adds the permission where missing
.\Set-GPOAdministratorsFullControl.ps1 -Remediate

# Target a specific domain
.\Set-GPOAdministratorsFullControl.ps1 -DomainName child.contoso.com -Remediate

# Custom report path
.\Set-GPOAdministratorsFullControl.ps1 -ReportPath "C:\Reports\gpo_audit.csv" -Remediate
```

### What the script does

1. Enumerates all GPOs via `Get-GPO -All`
2. For each GPO, checks the `Administrators` group permission using `Get-GPPermission`
3. Reports the status: **OK**, **Incomplete** (has some permission but not Full Control), or **Missing**
4. In `-Remediate` mode, uses `Set-GPPermission -Replace` to set `GpoEditDeleteModifySecurity`
5. Exports a CSV report with details for each GPO

### Sample output

```
============================================================
 GPO Administrators Full Control - Audit & Remediation
============================================================

Domain      : contoso.com
Mode        : REMEDIATE
Report      : .\GPO_Administrators_Audit_contoso_com_20260122_143000.csv

Retrieving all GPOs from contoso.com ...
Found 127 GPO(s).

  [FIXED]   Default Domain Policy
  [FIXED]   Workstation Security Baseline
  [MISSING] Server Hardening Policy (Current: None)    <-- dry run

============================================================
 Summary
============================================================
Total GPOs     : 127
Already OK     : 89
Missing / Incomplete : 38
Fixed          : 38
Errors         : 0
```

### CSV report columns

| Column | Description |
|--------|-------------|
| GPOName | Display name of the GPO |
| GPOId | GUID of the GPO |
| GPOStatus | Enabled/Disabled status |
| CreationTime | When the GPO was created |
| ModificationTime | Last modification time |
| Owner | Current owner of the GPO |
| AdminPermission | Current permission level for Administrators |
| Status | OK / Incomplete / Missing |
| ActionTaken | None / Fixed / Error message |

### Requirements

- PowerShell modules: `GroupPolicy`, `ActiveDirectory`
- **Domain Admin** or delegated GPO administrator permissions
- Run from a domain-joined machine

---

## Step 2 — Modify Schema for New GPOs

### Purpose

Modify the `defaultSecurityDescriptor` attribute of the `groupPolicyContainer` class in the AD schema to include the Built-in Administrators (BA) group with Full Control.

After this change, **all newly created GPOs** will automatically inherit the Administrators Full Control permission.

### Understanding the SDDL

The default SDDL for `groupPolicyContainer` looks like this:

```
D:P
  (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;DA)  ← Domain Admins
  (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;EA)  ← Enterprise Admins
  (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;CO)  ← Creator Owner
  (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;SY)  ← SYSTEM
  (A;CI;RPLCLORC;;;AU)                       ← Authenticated Users (Read)
```

The ACE we add:

```
  (A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;BA)  ← Built-in Administrators
```

#### SDDL Rights Breakdown

| Code | Right |
|------|-------|
| RP | Read Property |
| WP | Write Property |
| CC | Create Child |
| DC | Delete Child |
| LC | List Children |
| LO | List Object |
| RC | Read Control (Read Permissions) |
| WO | Write Owner |
| WD | Write DACL |
| SD | Standard Delete |
| DT | Delete Tree |
| SW | Self Write (Validated Writes) |
| CI | Container Inherit |
| A | Access Allowed |

### Usage

```powershell
# Dry run — show current and proposed SDDL, no changes
.\Set-GPODefaultSchemaPermission.ps1

# Apply the schema modification
.\Set-GPODefaultSchemaPermission.ps1 -Apply

# Dry run — show what reverting would look like (remove BA ACE)
.\Set-GPODefaultSchemaPermission.ps1 -Revert

# Revert to default (remove BA ACE from schema)
.\Set-GPODefaultSchemaPermission.ps1 -Revert -Apply
```

### What the script does

1. Identifies the Schema Master FSMO
2. Reads the current `defaultSecurityDescriptor` from the `groupPolicyContainer` class
3. Checks if BA is already present
4. Validates the proposed SDDL using `RawSecurityDescriptor`
5. In `-Apply` mode:
   - Backs up the current SDDL to a text file
   - Writes the updated SDDL to the schema

### Sample output (dry run)

```
Schema Master FSMO : DC01.contoso.com

============================================================
 groupPolicyContainer - Default Security Descriptor
============================================================

Current SDDL:
D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;CO)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;SY)(A;CI;RPLCLORC;;;AU)

Built-in Administrators (BA) is NOT present in the default SDDL.

Proposed new SDDL:
D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;CO)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTDTSW;;;BA)

SDDL validation : OK (6 ACEs)

============================================================
 DRY RUN - No changes applied
 Re-run with -Apply to modify the schema
============================================================
```

### Requirements

- PowerShell module: `ActiveDirectory`
- **Schema Admins** group membership
- Must be run on or able to reach the **Schema Master FSMO**
- This is a **forest-wide** change

### Important Notes

> 🔴 **This is a schema modification.** Schema changes are replicated to all domain controllers in the forest and cannot be easily reversed.

- Only **new** GPOs created after the change will inherit the updated permissions
- **Existing** GPOs are not affected — use the remediation script (Step 1) for those
- Always run in dry-run mode first to review the proposed SDDL
- The script creates a backup file of the current SDDL before applying changes
- Allow time for schema replication across all DCs before testing
- Use `-Revert -Apply` to remove the BA ACE from the schema if needed (the backup file is also created before reverting)

---

## Recommended Execution Order

For a multi-domain forest, the recommended approach is:

1. **Run the schema modification** (Step 2) — this is done once per forest
2. **Run the remediation script** (Step 1) — once per domain where existing GPOs need to be fixed

```powershell
# 1. Schema modification (once per forest, requires Schema Admins)
.\Set-GPODefaultSchemaPermission.ps1          # Dry run first
.\Set-GPODefaultSchemaPermission.ps1 -Apply   # Apply
# To revert: .\Set-GPODefaultSchemaPermission.ps1 -Revert -Apply

# 2. Remediation per domain (requires Domain Admin per domain)
.\Set-GPOAdministratorsFullControl.ps1 -DomainName "domain1.contoso.com"              # Audit
.\Set-GPOAdministratorsFullControl.ps1 -DomainName "domain1.contoso.com" -Remediate   # Fix

.\Set-GPOAdministratorsFullControl.ps1 -DomainName "domain2.contoso.com"              # Audit
.\Set-GPOAdministratorsFullControl.ps1 -DomainName "domain2.contoso.com" -Remediate   # Fix
```

## Verification

After applying both changes, verify by creating a new GPO:

```powershell
# Create a test GPO
$testGPO = New-GPO -Name "TEST_AdminPermission_Check" -Domain "contoso.com"

# Check permissions
Get-GPPermission -Guid $testGPO.Id -All | Format-Table Trustee, Permission, Inherited -AutoSize

# Clean up
Remove-GPO -Guid $testGPO.Id -Domain "contoso.com"
```

Expected output should show `BUILTIN\Administrators` with `GpoEditDeleteModifySecurity`.

# Remove Orphaned SIDs from Active Directory - V2
🗓️ Published: 2026-04-01 | Updated: 2026-04-14 (V2.10)

Over time, Active Directory ACLs accumulate references to accounts that no longer exist — these are called **orphaned SIDs**. They appear as unresolved `S-1-5-21-...` entries in security descriptors, left behind by deleted users, removed service accounts, or decommissioned trusted domains. They clutter your ACLs, make auditing harder, and can mask real security issues.

This script is an improved V2 version inspired by the excellent work of Ali Tajran:
🔗 https://www.alitajran.com/remove-orphaned-sids/

We rebuilt it from the ground up for **better performance**, **proper error handling**, **trusted domain support**, and a **clear reporting output**.

---

### 🎯 What Are Orphaned SIDs?

When a user or group is deleted from Active Directory (or from a trusted domain), their SID doesn't automatically get cleaned up from ACLs where it was granted permissions. The result:

- **In ADUC / ACL Editor** — you see entries like `S-1-5-21-123456789-...` instead of `DOMAIN\Username`
- **In auditing** — these unresolved SIDs generate noise and confusion
- **In security reviews** — you can't tell who had access, which is a compliance risk

These orphaned SIDs can come from:
- **Deleted accounts** in the current domain
- **Removed trusted domains** (forest or external trusts that no longer exist)
- **Migrated accounts** where SID history wasn't properly cleaned up

---

### ⚡ What Does the Script Do?

The script scans all AD objects under a given search base, reads their ACLs, and identifies ACEs that reference unresolved SIDs. It can either **list** them (report mode) or **remove** them.

**Key improvements over V1:**

| Feature | V1 | V2 |
|---------|----|----|
| LDAP queries | Recursive (1 query per level) | Single query with `-SearchScope Subtree` |
| Object filtering | None (all objects) | `-ObjectType` : `All`, `OUOnly`, `ContainersOnly` |
| Domain SID detection | Current domain only | All domains in the forest (parent + child) |
| Search scope | Always forest root | Current domain by default, `-ForestWide` for forest |
| Error handling | None | `try/catch` on every ACL operation + safe ACE enumeration |
| ACL reading | `Get-ACL -Path` (breaks on special chars) | `Get-Acl -LiteralPath` + DN escaping |
| Trusted domains | Not supported | `-IncludeTrustedDomains` switch with reachability check |
| WhatIf / Confirm | Manual implementation | Native `SupportsShouldProcess` |
| Progress | None | `Write-Progress` bar |
| Report | None | Grouped orphan list + summary table + domain SID reference |
| Log path | Hardcoded | Configurable via `-LogPath` |

---

### 🔧 Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SearchBase` | Yes | `"All"` for the current domain (or entire forest with `-ForestWide`), or a specific DN (e.g. `"OU=Users,DC=contoso,DC=com"`) |
| `-List` | Yes* | Report mode — lists orphaned SIDs without modifying anything |
| `-Remove` | Yes* | Removal mode — deletes orphaned SIDs from ACLs |
| `-ObjectType` | No | Filter scanned objects: `All` (default), `OUOnly` (fastest), `ContainersOnly`. Use `OUOnly` on large directories to avoid scanning every object |
| `-ForestWide` | No | When used with `-SearchBase "All"`, scans the entire forest instead of just the current domain |
| `-IncludeTrustedDomains` | No | Also detects orphaned SIDs from trusted domains (not just the current forest) |
| `-WhatIf` | No | Simulates removal without making changes (only with `-Remove`) |
| `-Confirm:$false` | No | Skips confirmation prompts (only with `-Remove`) |
| `-LogPath` | No | Transcript file path (default: `C:\temp\RemoveOrphanedSID-AD-V2.txt`) |

*`-List` and `-Remove` are **mutually exclusive** — you must choose exactly one.

---

### 🔄 How It Works

**1. Initialization**
The script retrieves the current domain DN and SID using `defaultNamingContext` (not `rootDomainNamingContext`), then enumerates all domains in the forest to collect their SIDs. This ensures orphaned SIDs from child/parent domains within the forest are correctly identified.

**2. Trust reachability check (with `-IncludeTrustedDomains`)**
Before scanning anything, the script enumerates all trusts and tests each one for reachability. It first tries `Get-ADDomain` (works for bidirectional and inbound trusts), and falls back to `nltest /dsgetdc:` which uses the DC locator — the same mechanism AD relies on for SID resolution across trusts. This makes it work reliably even for outbound-only trusts. A table shows which trusts are reachable and which aren't. If any trust is unreachable, the script warns about potential false positives and asks for confirmation before continuing.

**3. LDAP query with object filtering**
Objects are collected using `Get-ADObject -SearchScope Subtree` with an LDAP filter that depends on the `-ObjectType` parameter:
- `All` → `(objectClass=*)` — every object
- `OUOnly` → `(objectClass=organizationalUnit)` — only OUs (fastest, covers most delegation scenarios)
- `ContainersOnly` → OUs + Containers + builtinDomain + domainDNS

On large directories with millions of objects, `-ObjectType OUOnly` reduces scan time from hours to minutes.

**4. ACL scanning**
For each object, the script reads its ACL via `Get-Acl -LiteralPath` with proper DN escaping (forward slashes, special characters) and checks each ACE:

- **Without `-IncludeTrustedDomains`**: any unresolved SID (`SecurityIdentifier` object) matching any forest domain SID prefix is flagged
- **With `-IncludeTrustedDomains`**: any unresolved `SecurityIdentifier` is flagged — **excluding well-known SIDs** like `S-1-5-32-*` (BUILTIN), `S-1-5-18` (SYSTEM), etc.

Corrupt or unreadable ACEs are safely skipped with a warning instead of crashing the script.

**5. Removal (if `-Remove`)**
Uses `RemoveAccessRuleSpecific()` to remove the exact ACE, then writes back with `Set-Acl -LiteralPath`. Native `-WhatIf` and `-Confirm` are fully supported.

**6. Reporting**
At the end, the script displays:
- A **detailed list** of orphaned SIDs, **split by origin** — current domain, forest domains (child/parent), and trusted domain SIDs are displayed in separate color-coded sections, each grouped by SID with affected objects
- A **summary table** with total orphaned ACEs and **sub-counters** for current domain, forest domains, and trusted domain ACEs, plus objects modified and errors
- A **domain SID reference table** showing current domain, forest domains, and trusted domain SIDs — so you can immediately identify where each orphaned SID came from

---

### 💡 Usage Examples

**List orphaned SIDs in the current domain (report only):**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List
```

**List orphaned SIDs scanning only OUs (much faster on large AD):**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -ObjectType OUOnly
```

**List orphaned SIDs across the entire forest:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -ForestWide
```

**List orphaned SIDs including trusted domains:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -IncludeTrustedDomains
```

**Scan only OUs in a specific subtree:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -List -ObjectType OUOnly
```

**Simulate removal (see what would be deleted):**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -Remove -WhatIf
```

**Remove orphaned SIDs (with confirmation for each object):**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -Remove
```

**Remove orphaned SIDs without confirmation prompts:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -Remove -Confirm:$false
```

---

### 💥 Important Notes About Trusted Domains

When using `-IncludeTrustedDomains`, the detection relies on **Windows SID resolution**. When the DC reads an ACL, it contacts all reachable trusted domains to resolve SIDs.

**This means:**
- If a trust is **active and reachable**, and the account was deleted → the SID is correctly flagged as orphaned ✅
- If a trust is **down or unreachable** at scan time → valid accounts may appear as orphaned ⚠️ (false positives)
- If a trust was **completely removed** → all SIDs from that domain are correctly flagged ✅

**Built-in safeguard:** The script includes a **trust reachability check** that runs before the scan. It tests each trust and shows a status table (Reachable / Unreachable). If any trust is unreachable, it warns you and asks for confirmation before proceeding — so you won't accidentally clean up valid ACEs from a temporarily down trust.

**Recommended workflow:**
1. Run with `-List -IncludeTrustedDomains` first — the trust check will tell you immediately if anything is down
2. Review the **trust reachability table** — ensure all trusts show "Reachable"
3. Check the **domain SID reference table** at the end and cross-reference orphaned SIDs with trust SIDs
4. Run with `-Remove -WhatIf` to validate
5. Run with `-Remove` when you're confident

---

### 📋 Example Output

**Trust reachability check (with `-IncludeTrustedDomains`):**
```
Checking trust reachability...

+-----------------------------------------------------------------------------------------------------------+
| TRUST                        SID                                              DIRECTION      STATUS      |
+-----------------------------------------------------------------------------------------------------------+
| ext.local                    S-1-5-21-2769473801-1208458500-301403692          BiDirectional  Reachable   |
| child.contoso.com            S-1-5-21-3274687931-2194606015-4130333083        BiDirectional  Reachable   |
| red.local                    S-1-5-21-167705663-2234365120-980853887           Outbound       Reachable   |
+-----------------------------------------------------------------------------------------------------------+

All trusts are reachable.
```

**Orphaned SIDs report:**
```
+---ORPHANED SIDs: CURRENT DOMAIN (12 ACEs)-----------------------------+

  SID: S-1-5-21-2462332226-1795882094-2017209951-679602  (6 ACEs on 3 objects)
    -> CN=e9031b51-...,CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com (2 ACEs)
    -> CN=e366991e-...,CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com (2 ACEs)
    -> CN=CryptoPolicy,CN=ADFS,...,DC=contoso,DC=com (2 ACEs)

  SID: S-1-5-21-2462332226-1795882094-2017209951-500123  (6 ACEs on 2 objects)
    -> OU=Servers,DC=contoso,DC=com (4 ACEs)
    -> OU=Workstations,DC=contoso,DC=com (2 ACEs)

+------------------------------------------------------------------------+

+---ORPHANED SIDs: FOREST DOMAINS (child/parent) (2 ACEs)---------------+

  SID: S-1-5-21-3274687931-2194606015-4130333083-5812  (2 ACEs on 1 objects)
    -> OU=SharedResources,DC=contoso,DC=com (2 ACEs)

+------------------------------------------------------------------------+

+---ORPHANED SIDs: TRUSTED DOMAINS (4 ACEs)-----------------------------+

  SID: S-1-5-21-2769473801-1208458500-301403692-1104  (4 ACEs on 1 objects)
    -> OU=SharedResources,DC=contoso,DC=com (4 ACEs)

+------------------------------------------------------------------------+

+======================================+
|           SUMMARY REPORT             |
+======================================+
| Objects scanned   :             692 |
| Orphaned ACEs     :              18 |
|   Current domain  :              12 |
|   Forest domains  :               2 |
|   Trusted domains :               4 |
| ACEs removed      :               0 |
| Objects modified  :               0 |
| Errors            :               1 |
+======================================+

+--------------------------------------------------------------------------------------------------+
| TYPE           NAME                         SID                                              DIR |
+--------------------------------------------------------------------------------------------------+
| Current Domain CONTOSO                      S-1-5-21-2462332226-1795882094-2017209951        -   |
| Forest Domain  CHILD                        S-1-5-21-3274687931-2194606015-4130333083        -   |
+--------------------------------------------------------------------------------------------------+
| Trust          ext.local                    S-1-5-21-2769473801-1208458500-301403692  BiDirection |
| Trust          red.local                    S-1-5-21-167705663-2234365120-980853887   Outbound    |
+--------------------------------------------------------------------------------------------------+
```

---

### 🔗 Credits & References

This script is inspired by the original work of **Ali Tajran**:
🔗 https://www.alitajran.com/remove-orphaned-sids/

V2 adds performance optimizations, error handling, trusted domain support, and enhanced reporting.

---

### 📝 Changelog

| Version | Date | Changes |
|---------|------|---------|
| V1.00 | 2025-01-27 | Initial version |
| V2.00 | 2026-03-31 | Major rework: single LDAP query, error handling, trusted domain support, SupportsShouldProcess, progress bar, summary report |
| V2.10 | 2026-04-14 | Fix: use current domain (not forest root) for SID detection. Add: `-ObjectType` (All/OUOnly/ContainersOnly) for performance. Add: `-ForestWide` switch. Fix: collect all forest domain SIDs (child domains). Fix: ACL read errors on DNs with special characters (LiteralPath + escaping) |

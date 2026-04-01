# Remove Orphaned SIDs from Active Directory - V2
🗓️ Published: 2026-04-01

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
| Error handling | None | `try/catch` on every ACL operation |
| Trusted domains | Not supported | `-IncludeTrustedDomains` switch with reachability check |
| WhatIf / Confirm | Manual implementation | Native `SupportsShouldProcess` |
| Progress | None | `Write-Progress` bar |
| Report | None | Grouped orphan list + summary table + domain SID reference |
| Log path | Hardcoded | Configurable via `-LogPath` |

---

### 🔧 Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SearchBase` | Yes | `"All"` for the entire forest, or a specific DN (e.g. `"OU=Users,DC=contoso,DC=com"`) |
| `-List` | Yes* | Report mode — lists orphaned SIDs without modifying anything |
| `-Remove` | Yes* | Removal mode — deletes orphaned SIDs from ACLs |
| `-IncludeTrustedDomains` | No | Also detects orphaned SIDs from trusted domains (not just the current domain) |
| `-WhatIf` | No | Simulates removal without making changes (only with `-Remove`) |
| `-Confirm:$false` | No | Skips confirmation prompts (only with `-Remove`) |
| `-LogPath` | No | Transcript file path (default: `C:\temp\RemoveOrphanedSID-AD-V2.txt`) |

*`-List` and `-Remove` are **mutually exclusive** — you must choose exactly one.

---

### 🔄 How It Works

**1. Initialization**
The script retrieves the forest root DN and the current domain SID, then starts a transcript log.

**2. Trust reachability check (with `-IncludeTrustedDomains`)**
Before scanning anything, the script enumerates all trusts and tests each one for reachability. It first tries `Get-ADDomain` (works for bidirectional and inbound trusts), and falls back to `nltest /dsgetdc:` which uses the DC locator — the same mechanism AD relies on for SID resolution across trusts. This makes it work reliably even for outbound-only trusts. A table shows which trusts are reachable and which aren't. If any trust is unreachable, the script warns about potential false positives and asks for confirmation before continuing.

**3. Single LDAP query**
All objects under the search base are collected in one shot using `Get-ADObject -SearchScope Subtree`. No recursive function calls — this is significantly faster on large directories.

**4. ACL scanning**
For each object, the script reads its ACL via `Get-ACL "AD:$dn"` and checks each ACE:

- **Without `-IncludeTrustedDomains`**: only SIDs starting with the current domain SID prefix are flagged (e.g. `S-1-5-21-2462332226-*`)
- **With `-IncludeTrustedDomains`**: any ACE whose `IdentityReference` is still a `SecurityIdentifier` object (not resolved to an `NTAccount`) is flagged — **excluding well-known SIDs** like `S-1-5-32-*` (BUILTIN), `S-1-5-18` (SYSTEM), etc.

**5. Removal (if `-Remove`)**
Uses `RemoveAccessRuleSpecific()` to remove the exact ACE, then writes back with `Set-ACL`. Native `-WhatIf` and `-Confirm` are fully supported.

**6. Reporting**
At the end, the script displays:
- A **detailed list** of orphaned SIDs, **split by origin** — current domain SIDs and trusted domain SIDs are displayed in separate color-coded sections, each grouped by SID with affected objects
- A **summary table** with total orphaned ACEs and **sub-counters** for current domain vs. trusted domain ACEs, plus objects modified and errors
- A **domain SID reference table** showing current domain, forest domains, and trusted domain SIDs — so you can immediately identify where each orphaned SID came from

---

### 💡 Usage Examples

**List orphaned SIDs in the entire forest (current domain only):**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List
```

**List orphaned SIDs including trusted domains:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "All" -List -IncludeTrustedDomains
```

**List orphaned SIDs on a specific OU:**
```powershell
.\RemoveOrphanedSID-AD-V2.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -List
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

+---ORPHANED SIDs: TRUSTED DOMAINS (4 ACEs)-----------------------------+

  SID: S-1-5-21-2769473801-1208458500-301403692-1104  (4 ACEs on 1 objects)
    -> OU=SharedResources,DC=contoso,DC=com (4 ACEs)

+------------------------------------------------------------------------+

+======================================+
|           SUMMARY REPORT             |
+======================================+
| Objects scanned   :             692 |
| Orphaned ACEs     :              16 |
|   Current domain  :              12 |
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

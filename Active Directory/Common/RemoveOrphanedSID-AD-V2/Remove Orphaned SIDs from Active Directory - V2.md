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
| Trusted domains | Not supported | `-IncludeTrustedDomains` switch |
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

**2. Single LDAP query**
All objects under the search base are collected in one shot using `Get-ADObject -SearchScope Subtree`. No recursive function calls — this is significantly faster on large directories.

**3. ACL scanning**
For each object, the script reads its ACL via `Get-ACL "AD:$dn"` and checks each ACE:

- **Without `-IncludeTrustedDomains`**: only SIDs starting with the current domain SID prefix are flagged (e.g. `S-1-5-21-2462332226-*`)
- **With `-IncludeTrustedDomains`**: any ACE whose `IdentityReference` is still a `SecurityIdentifier` object (not resolved to an `NTAccount`) is flagged — **excluding well-known SIDs** like `S-1-5-32-*` (BUILTIN), `S-1-5-18` (SYSTEM), etc.

**4. Removal (if `-Remove`)**
Uses `RemoveAccessRuleSpecific()` to remove the exact ACE, then writes back with `Set-ACL`. Native `-WhatIf` and `-Confirm` are fully supported.

**5. Reporting**
At the end, the script displays:
- A **detailed list** of orphaned SIDs grouped by SID, with affected objects
- A **summary table** (objects scanned, ACEs found/removed, errors)
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

**Recommended workflow:**
1. Run with `-List` first to review findings
2. Check the **domain SID reference table** at the end — verify all trusts are visible
3. Cross-reference orphaned SIDs with the trust SIDs to understand their origin
4. Run with `-Remove -WhatIf` to validate
5. Run with `-Remove` when you're confident

---

### 📋 Example Output

```
+---ORPHANED SIDs FOUND---------------------------------------------------+
| SID                                                ACEs   Object
+------------------------------------------------------------------------+

  SID: S-1-5-21-2462332226-1795882094-2017209951-679602  (6 ACEs on 3 objects)
    -> CN=e9031b51-...,CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com (2 ACEs)
    -> CN=e366991e-...,CN=ADFS,CN=Microsoft,CN=Program Data,DC=contoso,DC=com (2 ACEs)
    -> CN=CryptoPolicy,CN=ADFS,...,DC=contoso,DC=com (2 ACEs)

+------------------------------------------------------------------------+

+======================================+
|           SUMMARY REPORT             |
+======================================+
| Objects scanned   :             692 |
| Orphaned ACEs     :              12 |
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

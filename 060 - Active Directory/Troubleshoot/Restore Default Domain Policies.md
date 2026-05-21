# Restore Default Domain Policies
🗓️ Published: 2026-05-20

When the **Default Domain Policy** or the **Default Domain Controllers Policy** is broken, corrupted, or accidentally deleted, the recovery tool of last resort is `dcgpofix.exe`. It is shipped with Windows Server and is designed to recreate these two GPOs back to their original out-of-the-box state.

This article covers what `dcgpofix` actually does, when to use it, what it does **not** restore, and the operational caveats that surprise people the first time they run it in production.

## ⚠️ Read this before doing anything

`dcgpofix` is a blunt instrument. It **does not merge** your customizations with the defaults — it **overwrites** the two policies with a fresh copy. Any custom settings you added to those policies (password policy tweaks, audit policy, Kerberos ticket lifetimes, user rights assignments on DCs, etc.) will be lost unless you back them up first.

> 🛑 Always **back up the two GPOs** (`Backup-GPO`) before running `dcgpofix`. And if at all possible, **fix the underlying issue** (re-permission, restore from GPO backup, AD authoritative restore on the affected DC) before reaching for `dcgpofix`.

## What `dcgpofix` does and does not do

| Action | Behavior |
|---|---|
| Recreates **Default Domain Policy** (`{31B2F340-016D-11D2-945F-00C04FB984F9}`) | ✅ Yes |
| Recreates **Default Domain Controllers Policy** (`{6AC1786C-016F-11D2-945F-00C04FB984F9}`) | ✅ Yes |
| Restores **other** GPOs you accidentally deleted | ❌ No — use `Restore-GPO` from a backup |
| Preserves **your customizations** in those two policies | ❌ No — they are reset to the OS defaults |
| Restores **GPO links** if the GPO object itself was deleted from AD | ⚠️ Re-creates the link to the domain root / Domain Controllers OU only |
| Restores Group Policy **security settings** (PSO, fine-grained password policy) | ❌ No — those live elsewhere in AD |

> 💡 The two GUIDs above are well-known and identical in every AD domain on the planet. That is what lets `dcgpofix` know which policies to rebuild from its embedded templates.

## When to use it

Reach for `dcgpofix` only when one of the following is true and a clean restore from a GPO backup is not possible:

- The **SYSVOL** folder for one of the two policies is missing or corrupt on every DC, with no usable replica.
- The `groupPolicyContainer` object in AD for one of the two GUIDs has been deleted and the AD Recycle Bin window has expired.
- Permissions on the policy are so broken that the GPMC cannot even open them, and `Set-GPPermission` cannot repair them.
- You inherited a domain in an unknown state and want a clean baseline before re-applying your own settings via a fresh GPO.

If only the **settings inside** the policy are wrong, prefer:

1. **Restore from a GPO backup** if you have one — `Restore-GPO -BackupId <guid> -Path <folder>`.
2. **Edit the policy** via GPMC to set the few settings you actually need.
3. **Authoritative DFSR/FRS restore** of `SYSVOL` if the issue is replication-induced.

## Prerequisites

- Run on a **Domain Controller** in the affected domain — `dcgpofix` will refuse to run elsewhere.
- Be a member of **Domain Admins** (or **Enterprise Admins** for forest-root).
- The **Schema version** on the DC must match the version the binary expects. If you raised your forest functional level past the OS of the DC where you are running the tool, you will see the *"Schema versions do not match"* error. Either run the tool from a newer DC, or use `/ignoreschema` (with caution — see below).

## Syntax

```cmd
dcgpofix [/ignoreschema] [/target:{Domain | DC | Both}]
```

| Switch | Meaning |
|---|---|
| `/target:Domain` | Restores **Default Domain Policy** only |
| `/target:DC` | Restores **Default Domain Controllers Policy** only |
| `/target:Both` (default) | Restores both |
| `/ignoreschema` | Skips the schema version compatibility check. Use only when you understand what you are doing — schema mismatch normally exists for a reason |

## Step-by-step recovery procedure

```powershell
# 1. Inventory — confirm which GPO is broken
Get-GPO -All | Where-Object { $_.DisplayName -like "Default*" } |
    Select-Object DisplayName, Id, GpoStatus, ModificationTime

# 2. Back up BOTH default policies (even the broken one — you may want the settings later)
$backupRoot = "C:\GPO-Backups\Pre-dcgpofix-$(Get-Date -Format yyyyMMdd-HHmmss)"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
Backup-GPO -Name "Default Domain Policy"             -Path $backupRoot
Backup-GPO -Name "Default Domain Controllers Policy" -Path $backupRoot

# 3. Pause replication briefly (optional) so that only the local DC writes the new policy first
#    repadmin /options +DISABLE_OUTBOUND_REPL  (revert with -DISABLE_OUTBOUND_REPL after success)

# 4. Run dcgpofix (interactive — it will prompt for confirmation)
dcgpofix.exe /target:Both

# 5. Verify SYSVOL replicates the new versions
repadmin /syncall /AdeP
dfsrdiag pollad
Get-DfsrBacklog -SourceComputerName <other DC> -DestinationComputerName <local DC> -FolderName "SYSVOL Share"

# 6. Reapply your required customizations (audit policy, password policy, Kerberos, etc.)
#    via Set-GPRegistryValue / Set-GPPrefRegistryValue / GPMC.
```

## What gets reset in practice

The recreated **Default Domain Policy** contains the OS defaults for:

- Account Policies → Password Policy
- Account Policies → Account Lockout Policy
- Account Policies → Kerberos Policy

The recreated **Default Domain Controllers Policy** contains the OS defaults for:

- Local Policies → Audit Policy
- Local Policies → User Rights Assignment (most notably `Access this computer from the network`, `Allow log on locally`, `Deny log on through Remote Desktop Services`, etc.)
- Local Policies → Security Options

> 🔎 If you don’t know exactly what the “OS defaults” look like for your version of Windows Server, the Microsoft Security Compliance Toolkit ships baseline GPOs that you can compare against. See References.

## Common pitfalls

- **The tool returns success but nothing changes on other DCs.** This is almost always a SYSVOL replication issue. Check DFSR health (`dfsrdiag pollad`, `Get-DfsrBacklog`) and AD replication (`repadmin /replsummary`).
- **`dcgpofix` cannot run remotely.** You must be logged on (or `psexec` into) a DC. Group Policy Management Console **cannot** invoke it for you.
- **Custom DC user rights vanish.** If your DCs have non-default `User Rights Assignment` (very common in hardened environments), they will be reset to the OOB Windows defaults. Restore them either via your hardening GPO baseline or by editing the Default Domain Controllers Policy directly after the reset.
- **Schema mismatch error.** Means your DC OS is older than the schema. Run the tool from a newer DC, or update the DC, or use `/ignoreschema` if you are sure.
- **GPO is still broken after restore.** Make sure the **SYSVOL ACLs** are correct (`Authenticated Users` → Read & Apply Group Policy). `dcgpofix` rebuilds policy content but does not always fix delegated permissions added later.

## Verification checklist after running `dcgpofix`

```powershell
# GPO objects exist and are healthy
Get-GPO -Name "Default Domain Policy"
Get-GPO -Name "Default Domain Controllers Policy"

# GPO links are present at expected scopes
(Get-ADDomain).DistinguishedName | ForEach-Object { Get-GPInheritance -Target $_ }
Get-GPInheritance -Target "OU=Domain Controllers,$((Get-ADDomain).DistinguishedName)"

# Replication is healthy
repadmin /replsummary
dfsrdiag replicationstate

# Settings are the OS defaults
Get-GPOReport -Name "Default Domain Policy"             -ReportType Html -Path "C:\Temp\DDP-after.html"
Get-GPOReport -Name "Default Domain Controllers Policy" -ReportType Html -Path "C:\Temp\DDCP-after.html"
```

## What if you do not have a backup?

If you skipped the `Backup-GPO` step and now realize you have lost custom settings, the recovery path is unfortunately limited:

1. **System State backup** of any DC taken before the change — restorable via `wbadmin` or your backup product.
2. **AD Recycle Bin** — only recovers the `groupPolicyContainer` object, not the SYSVOL content (`.pol`, `Registry.pol`, GPT.ini).
3. **Another DC where the policy is still healthy** — sometimes a divergent DFSR replica still has the older version under `SYSVOL_DFSR\<domain>\Policies\<GUID>\` until convergence.
4. **Reapply your settings from documentation / baseline** — slowest but most predictable.

> 💡 This is why preserving a fresh `Backup-GPO` of the two default policies in your operational runbook is one of those small habits that saves a very bad day later.

## 📚 References

- [`dcgpofix` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dcgpofix)
- [Default Domain Policy and Default Domain Controllers Policy — what to do and not do](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/default-domain-policy-default-domain-controllers-policy)
- [`Backup-GPO` cmdlet](https://learn.microsoft.com/powershell/module/grouppolicy/backup-gpo)
- [`Restore-GPO` cmdlet](https://learn.microsoft.com/powershell/module/grouppolicy/restore-gpo)
- [Microsoft Security Compliance Toolkit — baseline GPOs](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10)
- [SYSVOL replication troubleshooting (DFSR)](https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/group-policy-objects-not-replicating)
- [Group Policy well-known GUIDs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/well-known-policy-guids)
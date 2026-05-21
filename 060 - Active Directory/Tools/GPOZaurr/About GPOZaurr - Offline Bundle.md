# GPOZaurr — Offline Bundle

🗓️ Bundle captured: 2026-05-20 (GPOZaurr 1.1.9)

## What is this?

[GPOZaurr](https://github.com/EvotecIT/GPOZaurr) is a community PowerShell module written by **Przemysław Kłys (Evotec)** that audits and reports on Group Policy in Active Directory: orphaned GPOs, empty GPOs, permissions, links, ownership, broken syslvol replication, GPP passwords, and many more.

This folder contains a **self-contained offline copy** of GPOZaurr together with all of its runtime dependencies, captured via:

```powershell
Save-Module -Name GPOZaurr -Path "<this folder>"
```

So you can drop this bundle on a jump host / DC without internet access and load the module directly from disk.

## Folder layout

| Folder | Role |
|---|---|
| `GPOZaurr\1.1.9\` | Main module |
| `PSSharedGoods\` | Helper functions used by GPOZaurr |
| `PSWriteHTML\` | HTML report generation engine |
| `PSWriteColor\` | Colored console output |
| `Pester\` | Test framework — pulled in as a transitive dependency |

## How to use

From an **elevated PowerShell session** on a workstation/server with **RSAT-AD-PowerShell** and **Group Policy Management** installed:

```powershell
# Import the bundled version directly (no install needed)
Import-Module "<path-to-this-folder>\GPOZaurr\1.1.9\GPOZaurr.psd1"

# Generate the full HTML report (most common use case)
Invoke-GPOZaurr -FilePath "C:\Temp\GPOZaurr-Report.html"

# Or query a single area
Get-GPOZaurrBrokenLink
Get-GPOZaurrPermissionAnalysis
Get-GPOZaurrPassword       # GPP cleartext passwords (cpassword)
```

If PowerShell refuses to load the module because of execution policy, use:

```powershell
powershell.exe -ExecutionPolicy Bypass -File <your-script>.ps1
```

> 💡 The bundle is pinned at **GPOZaurr 1.1.9**. For the latest features and fixes, prefer the gallery:
> `Install-Module GPOZaurr -Scope CurrentUser`

## Why keep an offline bundle?

- ✅ Works on disconnected/air-gapped environments (no PSGallery access).
- ✅ Reproducible audits — the version is frozen in this repo.
- ✅ Avoids surprises if a future GPOZaurr release changes behavior or output.

## License & credits

GPOZaurr is published under its upstream license — see `GPOZaurr\1.1.9\LICENSE`. Full credit to the maintainers at [Evotec / Przemysław Kłys](https://github.com/EvotecIT).

## References

- [GPOZaurr GitHub repository](https://github.com/EvotecIT/GPOZaurr)
- [GPOZaurr on PowerShell Gallery](https://www.powershellgallery.com/packages/GPOZaurr)
- [`Save-Module` cmdlet](https://learn.microsoft.com/powershell/module/powershellget/save-module)
- [Evotec blog — Introducing GPOZaurr](https://evotec.xyz/the-only-command-you-will-ever-need-to-understand-and-fix-your-group-policies-gpo/)

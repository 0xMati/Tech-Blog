# How to Export and Import ADFS Relying Party  
🗓️ Published: 2025-09-09

Two PowerShell scripts to **export** and **import** ADFS Relying Party Trusts (RPT):

- `Export-RP.ps1` – exports RPT configuration to XML files.
- `Import-RP.ps1` – imports the exported XML files on a target ADFS server.

> Scripts can be found here : https://github.com/0xMati/Tech-Blog/tree/main/ADFS/Tools

> ⚠️ Run these scripts **on the ADFS server** with an elevated PowerShell session.

---

## Prerequisites

- Administrator rights on the ADFS servers.
- PowerShell execution policy that allows running local scripts (see below).
- Source and destination servers should have the same ADFS farm configuration (service account, certificates, etc.).

> Tip: Instead of setting a permanent execution policy, you can scope it to the current process:

 ```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

---

## Folder layout

The export writes XML files under: `C:\ADFS\ADFS-RP-Output\`
Copy this folder (and the scripts) from the **source** to the **destination** server, preserving the same path.

---

## Quickstart

### 1 On the **source** ADFS server

```powershell
# Run PowerShell as Administrator
Set-ExecutionPolicy Unrestricted -Force    # or use the Process-scoped tip above
```

#### Go to the folder where the scripts are
cd C:\Path\To\Scripts

#### Export all RP trusts
```powershell
.\Export-RP.ps1
```

You should now have XML files under:
C:\ADFS\ADFS-RP-Output```

### 2 On the **destination** ADFS server

```powershell
# Copy the scripts and the exported folder from the source server:
# - C:\ADFS\ADFS-RP-Output# - Export-RP.ps1, Import-RP.ps1

# (Optional) Delete any RP XMLs you do NOT want to import
# from C:\ADFS\ADFS-RP-Output
# Run PowerShell as Administrator
Set-ExecutionPolicy Unrestricted -Force    # or use the Process-scoped tip above
```

cd C:\Path\To\Scripts

#### Import all RPs

```powershell
.\Import-RP.ps1
```

Open the ADFS console (**Relying Party Trusts**) to verify that the trusts have been created on the destination server.

---

## Notes & Known behaviors

- If an RP already exists on the destination (e.g., **DRS**), the import may throw errors – they can be safely ignored in that case.
- The scripts preserve key RP configuration elements (e.g., claim rules, encryption certificates, etc.).

---

## Troubleshooting

- **Execution policy blocks the script**: use the process-scoped bypass shown above.
- **Some RPs fail to import**: remove the corresponding XML from `C:\ADFS\ADFS-RP-Output\` and re-run `.\Import-RP.ps1`, or create/adjust that RP manually.
- **Permissions**: ensure you’re running PowerShell as Administrator and that the account has rights to administer ADFS.

---

## License

MIT
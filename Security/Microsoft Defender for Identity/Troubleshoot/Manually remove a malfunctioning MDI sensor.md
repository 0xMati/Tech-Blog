# 🛠️ How to Manually Remove a Malfunctioning MDI Sensor  
📅 Published: 2022-12-23  

---

## 🧾 Context  
Microsoft Defender for Identity (MDI) normally handles updates automatically.  
However, issues can occasionally prevent removal through the standard **Add/Remove Programs** interface — particularly due to infrastructure problems in MDI clusters.  

This guide outlines the manual steps required to **clean up a stuck MDI sensor** installation.

Thanks to *Martin Schwartzman* and [Morten Knudsen](https://mortenknudsen.net/?p=258) for their contributions.

---

## 🧨 Uninstall Attempt (Standard Method)

Try uninstalling from the `ProgramData\PackageCache` folder:  
Example:
```powershell
cd "C:\ProgramData\Package Cache\{GUID}"
"Azure ATP Sensor Setup.exe" /uninstall
```

Replace `{GUID}` with the relevant folder ID on your machine.

---

## 🔧 Clean Up Services Manually

From an **elevated prompt**, delete lingering services:
```cmd
sc.exe delete aatpsensor
sc.exe delete aatpsensorupdater
```

---

## 🧹 Manual Cleanup Steps

- Verify that these folders no longer exist:
  - `C:\Program Files\Azure Advanced Threat Protection Sensor`
- Rename or delete the sensor’s package cache folder:
  - `C:\ProgramData\PackageCache\{GUID}`
- Remove registry keys related to the sensor. You will need to determine the correct GUID:
```reg
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Products\{GUID}
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Features\{GUID}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{GUID}
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Installer\Dependencies
```

Look for entries with:
```text
DisplayName = Azure Advanced Threat Protection Sensor
```

---

## 📎 References

- [Original blog post by Morten Knudsen](https://mortenknudsen.net/?p=258)

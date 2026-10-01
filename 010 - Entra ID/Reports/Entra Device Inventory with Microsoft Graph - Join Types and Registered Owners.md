---
title: "Entra Device Inventory with Microsoft Graph: Join Types and Registered Owners"
date: 2026-10-01
---

# Entra Device Inventory with Microsoft Graph: Join Types and Registered Owners

**A directory device, an Intune-managed device and its current user are not interchangeable records.**

This short inventory replaces the historical `Get-MsolDevice -ReturnRegisteredOwners` export. It reads Entra device objects and their registered-owner IDs without changing registration, ownership or access.

## Know the identifiers and join types

| Graph value | Meaning |
|---|---|
| `Id` | Directory object ID; use it for the `-DeviceId` parameter of the owner-list cmdlet below |
| `DeviceId` | Device registration identifier, useful for correlation with the endpoint's `dsregcmd /status` |
| `TrustType = ServerAd` | Microsoft Entra hybrid joined |
| `TrustType = AzureAd` | Microsoft Entra joined |
| `TrustType = Workplace` | Microsoft Entra registered; not proof of personal ownership |
| `AccountEnabled` | Whether the directory device account is enabled, not whether the machine is online |

Registered owners are a directory relationship. They are not an inventory of everyone who signs in, an authoritative asset-owner field, or necessarily the Intune primary user. An empty owner list can be legitimate, including for hybrid-joined devices.

## Read devices and owners

On a management host, install compatible versions of `Microsoft.Graph.Authentication` and `Microsoft.Graph.Identity.DirectoryManagement`. The examples use delegated `Device.Read.All`, admin consent where required, and a supported role such as **Directory Readers**. No local administrator or AD FS role is needed.

Only owner IDs are exported. Graph can return limited information for related user objects when the caller cannot read their other properties. Do not request directory write permissions just to turn IDs into names.

```powershell
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
$tenantId = '11111111-2222-3333-4444-555555555555'
Connect-MgGraph -TenantId $tenantId -Scopes 'Device.Read.All' `
    -ContextScope Process -NoWelcome -ErrorAction Stop
if ((Get-MgContext).TenantId -ne $tenantId) {
    throw 'The Graph session is not connected to the intended tenant.'
}
```

Retrieve all pages of devices and owners. A failed owner request stops the inventory, rather than producing an apparently complete report with missing owners:

```powershell
$report = $null
$inventoryComplete = $false
$devices = @(Get-MgDevice -All -Property Id, DeviceId, DisplayName, TrustType,
    AccountEnabled, OperatingSystem, ApproximateLastSignInDateTime -ErrorAction Stop)
if ($devices.Count -eq 0) {
    throw 'No device rows returned. Verify tenant and inventory scope before exporting.'
}
$report = @(foreach ($device in $devices) {
    if ([string]::IsNullOrWhiteSpace($device.Id) -or $device.AccountEnabled -isnot [bool]) {
        throw 'A device row lacks its object ID or enabled state; stop the inventory.'
    }
    $owners = @(Get-MgDeviceRegisteredOwner -DeviceId $device.Id -All -ErrorAction Stop)
    $ownerIds = @(foreach ($owner in $owners) {
        if ([string]::IsNullOrWhiteSpace($owner.Id)) {
            throw 'An owner row lacks its object ID; stop the inventory.'
        }
        $owner.Id
    })
    [pscustomobject]@{
        ObjectId = $device.Id
        DeviceId = $device.DeviceId
        DisplayName = $device.DisplayName
        TrustType = $device.TrustType
        AccountEnabled = $device.AccountEnabled
        OperatingSystem = $device.OperatingSystem
        ApproximateLastSignInDateTime = $device.ApproximateLastSignInDateTime
        RegisteredOwnerIds = $ownerIds
        RegisteredOwnerCount = $ownerIds.Count
    }
})
$inventoryComplete = $true
$report | Group-Object TrustType | Select-Object Name, Count
```

Unknown or missing trust types and sign-in timestamps remain unchanged. Do not force them into a known join category or convert a missing timestamp into an inactivity duration.

## Export only a completed inventory

CLIXML preserves the owner-ID arrays and Boolean fields for later PowerShell analysis:

```powershell
if (-not $inventoryComplete -or $null -eq $report) {
    throw 'The inventory did not complete; no export will be written.'
}
$exportPath = Join-Path $PWD ('EntraDevices-{0}.xml' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
$report | Export-Clixml -LiteralPath $exportPath -Depth 4 -NoClobber -ErrorAction Stop
```

This is a local write, not a cloud configuration change. Treat the file as identity inventory data, not a public attachment. It contains identifiers and is not encrypted by this export.

**Verify:** select known devices of each join type, correlate `DeviceId` with the endpoint and compare owner IDs with the directory. Check that disabled accounts remain `False` and that an empty owner array has a count of zero.

The per-device owner requests make this a simple operational report, not a high-volume synchronization engine. Use the SDK's supported throttling behavior; if retries are exhausted, fix the cause and rerun rather than accepting a partial export. The directory may also change while the inventory is running, so it is not an atomic snapshot.

`ApproximateLastSignInDateTime` is not a live heartbeat or the complete sign-in history. Do not turn this inventory into automatic device deletion. For management, compliance or primary-user questions, correlate the distinct Intune records and their timestamps.

## References

- [Microsoft Graph: List devices and permissions](https://learn.microsoft.com/en-us/graph/api/device-list?view=graph-rest-1.0)
- [Microsoft Graph: Device fields and relationships](https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0)
- [Microsoft Graph: Registered owners and limited-information responses](https://learn.microsoft.com/en-us/graph/api/device-list-registeredowners?view=graph-rest-1.0)
---
title: "Automatic Intune Enrollment with Group Policy: Hybrid Join Is Not Enrollment"
date: 2026-10-01
---

# Automatic Intune Enrollment with Group Policy: Hybrid Join Is Not Enrollment

**A hybrid-joined PC has an identity in Entra. That alone does not mean Intune manages it.**

Group Policy can trigger automatic MDM enrollment for eligible AD domain-joined Windows clients. This procedure covers that existing-device path, not Windows Autopilot, server enrollment or a general co-management deployment.

```text
AD domain membership + completed Entra hybrid join
    -> eligible licensed user and Intune enrollment settings
    -> computer receives the MDM autoenrollment GPO
    -> enrollment task runs and authenticates
    -> MDM enrollment succeeds
    -> Intune management and policy evaluation follow
```

These are separate checkpoints. AD FS can participate in the user's federated authentication, but enabling AD FS device authentication or device writeback is not the operation that enrolls a PC in Intune.

## 1. Check the prerequisites

| Requirement | What to verify |
|---|---|
| Supported Windows client | Supported edition/build and deployment scenario, not an old 1709 minimum copied into a new rollout |
| Completed hybrid join | Endpoint and correct Entra device record agree; a pending synchronized object is not enough |
| Enrollment identity | Intended user has the applicable Intune and Entra automatic-enrollment licensing |
| MDM user scope | Includes that user; use the intended pilot scope rather than enabling all users merely to troubleshoot |
| Intune settings | Windows enrollment is permitted; applicable restrictions, limits and existing-management state are understood |
| Network and authentication | Enrollment endpoints and the user's sign-in work under the relevant proxy and Conditional Access policies |

Check for an existing MDM enrollment or old management agent before introducing another enrollment path. Do not silently remove another management relationship to make the GPO succeed.

On the client, run the following in the **affected user's session** to examine both device and user SSO state:

```powershell
& dsregcmd.exe /status
if ($LASTEXITCODE -ne 0) {
    throw 'Device registration status could not be read.'
}
```

For this hybrid scenario, expect `DomainJoined : YES` and `AzureAdJoined : YES`. Inspect the user's `AzureAdPrt` and its diagnostics if authentication fails. An MDM URL appearing in this output describes discovery/configuration; it is not proof of completed enrollment. An elevated session under another account can give misleading user-state observations.

## 2. Configure the computer GPO

In Group Policy Management, use an appropriately scoped computer GPO:

1. Open **Computer Configuration > Policies > Administrative Templates > Windows Components > MDM**.
2. Enable **Enable automatic MDM enrollment using default Microsoft Entra credentials**. Older administrative templates may still say Azure AD.
3. Select **User Credential** for the ordinary user-centric Intune enrollment scenario.
4. Link and security-filter the GPO for the intended computers. Verify both Read and Apply Group Policy permissions, inheritance and filtering.
5. Allow policy processing and have the eligible user sign in. Resolve any required authentication interaction rather than assuming enrollment can always remain silent.

**Device Credential is not a general workaround for a user sign-in problem.** Microsoft's documented Intune support for that option is limited to co-management and Azure Virtual Desktop multi-session scenarios. Use their specific deployment guidance when applicable.

If the policy is missing from the editor, check the administrative templates actually loaded from the domain Central Store. Update the relevant templates through the existing change process; do not overwrite the entire Central Store with an unrelated package.

On the client, in an elevated administrative session, inspect effective computer policy:

```powershell
& gpresult.exe /Scope Computer /r
if ($LASTEXITCODE -ne 0) {
    throw 'Computer policy results could not be read.'
}
```

This summary identifies applied and denied GPOs. Use Group Policy Results or a detailed report to inspect the winning MDM setting. A local `gpedit.msc` display does not prove which domain policy actually applies.

## 3. Separate task execution from enrollment success

The documented autoenrollment task runs every five minutes for one day after creation. Inspect **Task Scheduler > Microsoft > Windows > EnterpriseMgmt**. Task names can be localized; the folder can also contain tasks from an existing enrollment.

```powershell
$managementTasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
    $_.TaskPath -like '\Microsoft\Windows\EnterpriseMgmt\*'
})
if ($managementTasks.Count -eq 0) {
    Write-Warning 'No EnterpriseMgmt tasks were found; inspect policy processing and enrollment state.'
}
$managementTasks | Select-Object TaskPath, TaskName, State
```

A task's presence or a completed Task Scheduler event does not prove enrollment. In the Task Scheduler Operational log, event 107 shows a trigger and event 102 a completion, even when enrollment itself failed.

Inspect recent MDM administrative events:

```powershell
$mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
Get-WinEvent -LogName $mdmLog -MaxEvents 200 -ErrorAction Stop |
    Where-Object { $_.Id -in 75, 76 } |
    Select-Object TimeCreated, Id, Message
```

This is a bounded sample of the latest 200 log entries, not a complete history. An empty result can mean the relevant attempt was not triggered, fell outside that sample or was not retained. An unreadable or empty log must be investigated, not interpreted as successful enrollment.

| Evidence | Interpretation |
|---|---|
| MDM event 75, "Auto MDM Enroll: Succeeded" | Enrollment succeeded at that recorded time |
| MDM event 76 | Enrollment failed; retain the actual error code and context |
| `0x80180026` | Management enrollment is blocked; inspect conflicting management or enrollment policy, not just credentials |
| Neither enrollment event | Check whether the trigger ran, log retention and policy delivery |
| Task completion only | The task ran; continue to the MDM result |

## 4. Confirm the managed state

On the endpoint, use **Settings > Accounts > Access work or school**, select the relevant connection and inspect **Info** and management details. In Intune, correlate the managed-device record with the Entra device identity, enrollment time and recent check-in. A stale device with the same display name is not a match.

The [Graph device inventory](../../010%20-%20Entra%20ID/Reports/Entra%20Device%20Inventory%20with%20Microsoft%20Graph%20-%20Join%20Types%20and%20Registered%20Owners.md) helps identify the Entra record; it is not a replacement for Intune's managed-device inventory.

**Verify:** the intended user and tenant are used, enrollment succeeds, the correct device checks in, and an assigned test policy reports its actual result. Compliance is evaluated after enrollment and should not be assumed immediately from successful registration.

If enrollment fails, fix the demonstrated prerequisite or policy conflict. Avoid deleting `HKLM\SOFTWARE\Microsoft\Enrollments`, clearing the TPM or running `dsregcmd /leave` as generic enrollment repairs. Those operations affect identity and management state beyond this GPO.

Removing the GPO from scope can stop future policy-driven enrollment attempts, but does not automatically retire or unenroll devices already managed. Plan any removal with the corresponding Intune and endpoint lifecycle procedures.

## References

- [Microsoft Learn: Automatic Windows MDM enrollment using Group Policy](https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy)
- [Microsoft Learn: Troubleshoot Intune Group Policy autoenrollment](https://learn.microsoft.com/en-us/troubleshoot/mem/intune/device-enrollment/troubleshoot-windows-auto-enrollment)
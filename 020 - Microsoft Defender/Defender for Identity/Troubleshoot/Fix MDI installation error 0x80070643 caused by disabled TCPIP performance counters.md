---
title: "Fix MDI installation error 0x80070643 caused by disabled TCP/IP performance counters"
date: 2026-09-10
---

# Fix MDI installation error 0x80070643 caused by disabled TCP/IP performance counters

## Context

An existing Microsoft Defender for Identity sensor had been uninstalled from a
Windows Server 2022 domain controller. Reinstalling the MDI v2 sensor failed with
the generic error:

```text
Installation failed. Error code: 0x80070643
```

The MSI error alone did not identify the root cause. The installer detected the
sensor as absent (`ProductState=-1`), so this was not a stale MSI registration.

## Find the actual error

MDI deployment logs are normally stored in the installing user's temporary
directory, or in a Windows temporary directory when deployment runs as a service:

```text
%LOCALAPPDATA%\Temp
C:\Windows\Temp
C:\Windows\SystemTemp
```

The deployment log showed that `AATPSensorUpdater` could not reach the `Running`
state and that the installer rolled back after several timeouts:

```text
ChangeServiceStatus failed to change service status
[name=AATPSensorUpdater status=Running]
```

The decisive file was `Microsoft.Tri.Sensor.Updater-Errors.log`:

```text
System.InvalidOperationException: Category does not exist.
at System.Diagnostics.PerformanceCounterCategory.GetCounterInstances(...)
at Microsoft.Tri.Infrastructure.MetricManager(...)
```

This proved that the Updater service was starting but failing while loading a
Windows performance-counter category.

## Diagnose the TCP/IP counters

Check whether the network performance-counter categories are available:

```powershell
'Network Interface','Network Adapter','IPv4','TCPv4' |
ForEach-Object {
    [pscustomobject]@{
        Category = $_
        Exists   = [Diagnostics.PerformanceCounterCategory]::Exists($_)
    }
}
```

On the affected server, all four categories returned `False`.

Query the provider that exposes these counters:

```powershell
C:\Windows\System32\lodctr.exe /Q:Tcpip
```

The affected server returned:

```text
[Tcpip] Performance Counters (Disabled)
```

A healthy server returned:

```text
[Tcpip] Performance Counters (Enabled)
```

## Resolution

Run the following commands from an elevated PowerShell console:

```powershell
C:\Windows\System32\lodctr.exe /E:Tcpip
C:\Windows\System32\wbem\winmgmt.exe /resyncperf
C:\Windows\System32\lodctr.exe /Q:Tcpip
```

The final command must report:

```text
[Tcpip] Performance Counters (Enabled)
```

Restart the server. In this case, enabling the provider changed its configured
state immediately, but the categories remained unavailable until Windows was
restarted.

After the restart, verify the categories again. A native check can also be used:

```powershell
C:\Windows\System32\typeperf.exe -q "Network Interface"
```

Once `Network Interface`, `Network Adapter`, `IPv4`, and `TCPv4` were available,
the MDI sensor installation completed successfully.

## Important lesson

`0x80070643` and MSI error `1603` are generic wrapper errors. Do not delete MDI
services or Windows Installer registry keys based only on these codes. In this
case, rebuilding the counter library with `lodctr /R` was not sufficient because
the `Tcpip` performance-counter provider itself was disabled. The required fix
was `lodctr /E:Tcpip`, followed by a server restart.

## References

- [Troubleshoot the Defender for Identity sensor using logs](https://learn.microsoft.com/en-us/defender-for-identity/troubleshooting-using-logs)
- [Manually rebuild performance counters](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/manually-rebuild-performance-counters)
- [`lodctr` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/lodctr)
- [`typeperf` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/typeperf)
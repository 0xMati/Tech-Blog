---
title: "Keep a Windows session active with PowerShell"
date: 2026-08-07
---

# Keep a Windows session active with PowerShell

## The F15 trick

Sometimes you need to keep an interactive Windows session awake while watching a long-running task, a dashboard, or a lab deployment. The machine is not sleeping, the script is still working, but Windows has decided that *you* have left the building.

The small PowerShell script below sends an **F15** key every two minutes. F15 is a real virtual key, but almost no application assigns anything to it. It is therefore a neat little ghost key: Windows sees keyboard activity, while your terminal and documents remain untouched.

The script asks how many hours it should run, accepts an infinite mode, displays a status update every 15 minutes, and gives the console a very visible dark-blue background. `Ctrl+C` stops it at any time and restores the original console colors.

> This is intended for authorized lab, administration, presentation, and monitoring scenarios. It should not be used to bypass an organization's mandatory locking policy. Security software or centrally managed policies may also ignore synthetic input.

---

## PowerShell script

```powershell
[CmdletBinding(DefaultParameterSetName = 'Prompt')]
param(
    [Parameter(ParameterSetName = 'Duration')]
    [ValidateRange(0.01, 8760)]
    [double]$DurationHours,

    [Parameter(ParameterSetName = 'Infinite')]
    [switch]$Infinite
)

Add-Type -AssemblyName System.Windows.Forms

$keyInterval = [TimeSpan]::FromSeconds(120)
$statusInterval = [TimeSpan]::FromMinutes(15)
$originalBackground = $Host.UI.RawUI.BackgroundColor
$originalForeground = $Host.UI.RawUI.ForegroundColor
$originalTitle = $Host.UI.RawUI.WindowTitle

function Read-RunDuration {
    while ($true) {
        $answer = (Read-Host 'Duration in hours (for example 2 or 1.5), or I for infinite').Trim()

        if ($answer -match '^(?i:i|infinite)$') {
            return $null
        }

        $normalizedAnswer = $answer.Replace(',', '.')
        $hours = 0.0
        $numberStyle = [Globalization.NumberStyles]::Float
        $culture = [Globalization.CultureInfo]::InvariantCulture

        if ([double]::TryParse($normalizedAnswer, $numberStyle, $culture, [ref]$hours) -and $hours -gt 0) {
            return [TimeSpan]::FromHours($hours)
        }

        Write-Host 'Invalid value. Enter a positive number or I.' -ForegroundColor Yellow
    }
}

function Format-Duration {
    param([TimeSpan]$Duration)

    if ($Duration.TotalDays -ge 1) {
        return '{0} d {1:00} h {2:00} min' -f [math]::Floor($Duration.TotalDays), $Duration.Hours, $Duration.Minutes
    }

    return '{0:00} h {1:00} min {2:00} s' -f [math]::Floor($Duration.TotalHours), $Duration.Minutes, $Duration.Seconds
}

if ($PSCmdlet.ParameterSetName -eq 'Prompt') {
    $runDuration = Read-RunDuration
}
elseif ($PSCmdlet.ParameterSetName -eq 'Infinite') {
    $runDuration = $null
}
else {
    $runDuration = [TimeSpan]::FromHours($DurationHours)
}

try {
    $Host.UI.RawUI.BackgroundColor = 'DarkBlue'
    $Host.UI.RawUI.ForegroundColor = 'White'
    $Host.UI.RawUI.WindowTitle = 'Session keeper active - F15'
    Clear-Host

    $startedAt = Get-Date
    $stopAt = if ($null -ne $runDuration) { $startedAt.Add($runDuration) } else { $null }
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $nextKeyAt = [TimeSpan]::Zero
    $nextStatusAt = [TimeSpan]::Zero

    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host '                SESSION KEEPER ACTIVE - F15' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ('Started      : {0:yyyy-MM-dd HH:mm:ss}' -f $startedAt)
    if ($null -eq $runDuration) {
        Write-Host 'Duration     : infinite'
    }
    else {
        Write-Host ('Scheduled end: {0:yyyy-MM-dd HH:mm:ss}' -f $stopAt)
    }
    Write-Host 'Manual stop  : Ctrl+C' -ForegroundColor Yellow
    Write-Host

    while ($null -eq $runDuration -or $stopwatch.Elapsed -lt $runDuration) {
        if ($stopwatch.Elapsed -ge $nextKeyAt) {
            [System.Windows.Forms.SendKeys]::SendWait('{F15}')
            $nextKeyAt = $nextKeyAt.Add($keyInterval)
        }

        if ($stopwatch.Elapsed -ge $nextStatusAt) {
            $now = Get-Date
            if ($null -eq $runDuration) {
                Write-Host ('[{0:HH:mm:ss}] Active for {1} - infinite mode' -f $now, (Format-Duration $stopwatch.Elapsed)) -ForegroundColor Green
            }
            else {
                $remaining = $runDuration - $stopwatch.Elapsed
                if ($remaining -lt [TimeSpan]::Zero) {
                    $remaining = [TimeSpan]::Zero
                }
                Write-Host ('[{0:HH:mm:ss}] Time remaining: {1}' -f $now, (Format-Duration $remaining)) -ForegroundColor Green
            }
            $nextStatusAt = $nextStatusAt.Add($statusInterval)
        }

        Start-Sleep -Milliseconds 500
    }

    Write-Host
    Write-Host ('Duration reached at {0:HH:mm:ss}. Session keeper stopped.' -f (Get-Date)) -ForegroundColor Cyan
}
finally {
    if ($null -ne $stopwatch) {
        $stopwatch.Stop()
    }
    $Host.UI.RawUI.BackgroundColor = $originalBackground
    $Host.UI.RawUI.ForegroundColor = $originalForeground
    $Host.UI.RawUI.WindowTitle = $originalTitle
    Write-Host 'Console restored. Session keeper stopped.' -ForegroundColor Yellow
}
```

---

## Running it

Save the script as `Keep-SessionActive.ps1`, open an **interactive** PowerShell console, and run:

```powershell
.\Keep-SessionActive.ps1
```

The interactive prompt accepts a number of hours, including decimal values, or `I` for infinite mode:

```text
Duration in hours (for example 2 or 1.5), or I for infinite: 3
```

You can also skip the prompt and pass the mode directly:

```powershell
# Run for three hours
.\Keep-SessionActive.ps1 -DurationHours 3

# Run until Ctrl+C
.\Keep-SessionActive.ps1 -Infinite
```

The script must run in the logged-on interactive session. Running it as a background service or as a non-interactive scheduled task defeats the purpose: there is no desktop input queue to tickle.

## How it works

### Why F15?

`System.Windows.Forms.SendKeys` injects a keyboard event into the active Windows session. F15 is high enough on the function-key ladder to be ignored by almost everything, but it still counts as a key. It is less distracting than moving the mouse one pixel to the right and then apologetically moving it back.

The interval is stored as a `TimeSpan` and can be changed in one place:

```powershell
$keyInterval = [TimeSpan]::FromSeconds(120)
```

### Why use a stopwatch?

The script does not assume that 7,200 loops equal one hour. Scheduling, console output, and the occasional busy CPU can introduce small delays. `System.Diagnostics.Stopwatch` provides monotonic elapsed time, so the end time and countdown do not slowly drift into another timezone.

### Why is the loop checking every 500 milliseconds?

The half-second sleep keeps CPU usage negligible while allowing the script to stop close to the requested time. F15 is still sent only every two minutes, and console output is produced only every 15 minutes.

### What happens when Ctrl+C is pressed?

The main loop lives inside a `try` block. The `finally` block restores the original background color, foreground color, and console title whether the duration expires normally or PowerShell interrupts the script.

In other words: we leave the console exactly as we found it. Good scripts clean up after themselves.

## Why not `SetThreadExecutionState`?

`SetThreadExecutionState` is the correct API when an application needs to prevent system sleep or display power-off. It does **not** necessarily update the user's last-input timestamp, so Windows may still consider the interactive session idle.

This script has a different goal: generate a small, neutral input event inside the current interactive session. It does not change power settings, Group Policy, or the configured lock timeout.

## A few practical limits

- The script cannot unlock a session that is already locked.
- F15 may be assigned by specialist software, so test it before leaving the script running.
- Teams and other applications may use their own presence logic; an active Windows session does not guarantee a specific presence status.
- Endpoint security products can distinguish injected input from physical keyboard input.
- Mandatory security controls should be changed through the approved policy, not worked around with synthetic input.

Small script, very specific job, satisfyingly oversized function key.
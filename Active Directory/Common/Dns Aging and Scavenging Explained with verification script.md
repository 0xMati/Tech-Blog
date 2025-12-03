# DNS Aging and Scavenging Explained with verification Script
🗓️ Published: 2025-12-03

## Introduction

Managing stale DNS records is essential for maintaining a healthy Active Directory environment. Dynamic DNS entries created by clients, DHCP servers, and domain controllers naturally accumulate over time—and without proper cleanup, they can cause name-resolution issues, duplicate hostnames, broken service registrations, and even authentication failures.

Windows DNS offers a built-in mechanism to clean up old records: Aging and Scavenging.
However, enabling it blindly can be risky if you don’t know which records will be deleted.

This guide explains how DNS aging and scavenging work, and provides a PowerShell dry-run script that evaluates every dynamic DNS record in your zones, classifies them (static, fresh, stale), and shows exactly which entries would be removed before you activate scavenging for real.

It’s designed for AD-integrated zones, primary DNS servers, and supports verbose per-record analysis directly in the console.

## Understanding DNS Aging & Scavenging

DNS Aging & Scavenging exist to solve a very old and very common
problem:\
**dynamic records that never get cleaned up**.

Computers get renamed, reinstalled, moved, or simply disappear from the
network.\
But their DNS records stay behind... forever... unless you enable
scavenging.

### 🔹 Aging: tracking how "old" a DNS record is

When a dynamic DNS record is created or refreshed, Windows adds a
**timestamp**.\
From there, two timers apply:

-   **No-Refresh Interval**\
    The record cannot be refreshed during this period. The timestamp
    stays frozen.

-   **Refresh Interval**\
    The record *can* refresh its timestamp if the client is still
    active.

When both intervals pass without any update, the record becomes
**stale**.

Example 1:

If the Non-Refresh Interval and the Refresh Interval are seven (7) days then a resource record is considered as stale if not refreshed after fourteen (14) days.

![](assets/Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script/2025-12-03-17-27-55.png)

Example 2:

If the Non-Refresh Interval and the Refresh Interval are seven (7) days then a resource record can be refreshed after 7 days starting from the last refresh. Once done, a new Non-Refresh Interval period will start.

![](assets/Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script/2025-12-03-17-28-22.png)

Example 3:

Even if the Non-Refresh and Refresh intervals were elapsed, a resource record can be refreshed as long as the record was not removed from the DNS zone. Once done, a new Non-Refresh Interval will start and the record will no longer be considered as stale.

![](assets/Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script/2025-12-03-17-28-55.png)

### 🔹 Scavenging: safely removing stale records

Scavenging is the cleanup step.\
It deletes only **dynamic** records that:

-   have a timestamp, and\
-   have exceeded the full aging interval, and\
-   are located in zones where aging is enabled, and\
-   are processed by a DNS server with scavenging enabled.

**Static records (no timestamp) are never touched.**

### 🔹 In short

    Aging = marks old records  
    Scavenging = removes old records  
    Static records = ignored forever

This is why a dry-run script is essential:\
you want to know *exactly* which records would be deleted **before**
turning scavenging on.

## How to Configure Aging and Scavenging

Before scavenging can delete stale DNS records, **two separate settings** must be enabled.  
This is where most admins get it wrong: **aging is configured on the zone**, while **scavenging is configured on the server**.  
Both must be active — otherwise nothing happens.

### 1️⃣ Enable Aging on the DNS Zone

Aging tells DNS to track timestamps on dynamic records within a specific zone.

**DNS Manager → Zone (right-click) → Properties → Aging**

Enable:

- **✔ Aging**  
- **✔ No-Refresh Interval** (default: 7 days)
- **✔ Refresh Interval** (default: 7 days)

These two intervals combined determine how long a record can stay unchanged before becoming stale.

> If aging is not enabled on a zone, *no* record in that zone will ever be scavenged.

![](assets/Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script/2025-12-03-17-31-48.png)

---

### 2️⃣ Enable Scavenging on the DNS Server

Scavenging is *performed* by DNS servers, not by zones.

**DNS Manager → Server (right-click) → Properties → Advanced**

Enable:

- **✔ Automatically Scavenge Stale Records**

Specify a scavenging period (default: 7 days).

Every time this timer fires, the server will scan eligible zones and delete stale dynamic records.

![](assets/Dns%20Aging%20and%20Scavenging%20Explained%20with%20verification%20script/2025-12-03-17-32-16.png)

---

### 3️⃣ Verify That Dynamic Records Have Timestamps

Only records with timestamps can be scavenged.  
Static/manual entries never have one and are always preserved.

You can check timestamps by looking at the **Timestamp** column in DNS Manager or using PowerShell.

---

### 4️⃣ (Optional) Trigger Scavenging Manually

If you want to test cleanup immediately:

```powershell
Invoke-DnsServerScavenging
```

---

### Summary

```
Zone Aging        = marks stale records  
Server Scavenging = deletes stale records  
Both required     = scavenging actually works
```

Enable aging → enable scavenging → verify timestamps → done.

## PowerShell Dry-Run Script Overview

Before enabling DNS scavenging in production, it’s critical to understand exactly which dynamic records would be deleted.  
This script provides a **safe, read-only dry-run** that simulates scavenging without modifying anything.

It evaluates every DNS record in every selected zone and classifies them as:

- **SKIP** – Static record (no timestamp)  
- **KEEP** – Dynamic record that is still fresh  
- **CANDIDATE** – Dynamic record older than the full aging interval (No-Refresh + Refresh) and would be deleted by scavenging

The script displays all evaluations live in the console and produces a final table of all scavenging candidates.

### What the script does

- Reads DNS aging parameters for each zone  
- Enumerates all DNS records (A/AAAA/PTR/CNAME/etc.)  
- Checks timestamps and computes each record’s age  
- Determines if the record is stale  
- Shows real-time output for visibility  
- Provides a final summary of candidates  
- (Optional) Exports everything to CSV

### What the script **does NOT** do

- It **does not delete** anything  
- It **does not modify** DNS settings  
- It **does not enable** aging or scavenging  
- It **does not update** timestamps

It is completely safe to run on production DNS servers.

### When this script is useful

- Before enabling scavenging for the first time  
- After migrations or large client refresh cycles  
- Before cleaning up AD-integrated DNS zones  
- To identify abandoned hosts or stale PTR records  
- To validate aging settings across multiple zones  

```powershell
param(
    # Optional: list of zones to test. If empty -> all primary zones (non-reverse) with aging enabled
    [string[]]$ZoneName,
    # CSV output path (optional, export is commented out by default)
    [string]$OutputPath = "C:\Temp\Dns-StaleCandidates.csv"
)

cls

Import-Module DnsServer -ErrorAction Stop

$now       = Get-Date
$results   = @()
$zoneStats = @()

# --- Get target zones ---
if ($ZoneName -and $ZoneName.Count -gt 0) {
    $zones = foreach ($z in $ZoneName) {
        Get-DnsServerZone -Name $z -ErrorAction Stop
    }
}
else {
    $zones = Get-DnsServerZone |
             Where-Object { $_.ZoneType -eq 'Primary' -and -not $_.IsReverseLookupZone }
}

foreach ($zone in $zones) {

    try {
        $aging = Get-DnsServerZoneAging -Name $zone.ZoneName -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve aging settings for zone [$($zone.ZoneName)]: $($_.Exception.Message)"
        continue
    }

    if (-not $aging.AgingEnabled) {
        Write-Host "Zone [$($zone.ZoneName)]: aging is disabled -> zone skipped for dry-run." -ForegroundColor Yellow
        continue
    }

    # Zone aging settings
    $noRefresh = $aging.NoRefreshInterval      # TimeSpan
    $refresh   = $aging.RefreshInterval        # TimeSpan
    $threshold = $noRefresh + $refresh         # TimeSpan

    $zoneNoRefreshDays = [math]::Round($noRefresh.TotalDays, 2)
    $zoneRefreshDays   = [math]::Round($refresh.TotalDays, 2)
    $zoneThresholdDays = [math]::Round($threshold.TotalDays, 2)

    if ($aging.ScavengeServers) {
        $zoneScavengeServers = ($aging.ScavengeServers | ForEach-Object { $_.IPAddressToString }) -join ', '
    }
    else {
        $zoneScavengeServers = "<all eligible DNS servers>"
    }

    # Zone header
    Write-Host ("[ZONE] {0} | Aging={1} | NoRefresh={2} d | Refresh={3} d | Threshold={4} d | ScavengeServers={5}" -f `
        $zone.ZoneName, $aging.AgingEnabled, $zoneNoRefreshDays, $zoneRefreshDays, $zoneThresholdDays, $zoneScavengeServers) -ForegroundColor Cyan

    # Get all records in the zone
    $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue

    $zoneCandidateCount = 0

    foreach ($rr in $records) {

        # Static records: no timestamp -> never scavenged
        if (-not $rr.TimeStamp) {
            Write-Host ("[SKIP] Zone={0} | Host={1} | Type={2} | Reason=Static (no TimeStamp)" -f `
                $zone.ZoneName, $rr.HostName, $rr.RecordType) -ForegroundColor DarkYellow
            continue
        }

        $stamp = $rr.TimeStamp
        if ($stamp -isnot [datetime]) {
            Write-Host ("[SKIP] Zone={0} | Host={1} | Type={2} | Reason=Unusable TimeStamp ({3})" -f `
                $zone.ZoneName, $rr.HostName, $rr.RecordType, $stamp) -ForegroundColor DarkYellow
            continue
        }

        $age     = $now - $stamp
        $ageDays = [math]::Round($age.TotalDays, 2)

        # Human-friendly RecordData
        $data = $null
        switch ($rr.RecordType) {
            'A'     { $data = $rr.RecordData.IPv4Address.IPAddressToString }
            'AAAA'  { $data = $rr.RecordData.IPv6Address.IPAddressToString }
            'CNAME' { $data = $rr.RecordData.HostNameAlias }
            'PTR'   { $data = $rr.RecordData.PtrDomainName }
            default { $data = $rr.RecordData.ToString() }
        }

        if ($age -gt $threshold) {
            # Candidate for scavenging
            $zoneCandidateCount++

            Write-Host ("[CANDIDATE] Zone={0} | Host={1} | Type={2} | Data={3} | Age={4} d > Threshold={5} d -> WOULD BE SCAVENGED" -f `
                $zone.ZoneName, $rr.HostName, $rr.RecordType, $data, $ageDays, $zoneThresholdDays) -ForegroundColor Green

            $results += [pscustomobject]@{
                ZoneName            = $zone.ZoneName
                HostName            = $rr.HostName
                RecordType          = $rr.RecordType
                RecordData          = $data
                TimeStamp           = $stamp
                AgeDays             = $ageDays
                NoRefreshDays       = $zoneNoRefreshDays
                RefreshDays         = $zoneRefreshDays
                ThresholdDays       = $zoneThresholdDays
                ZoneAgingEnabled    = $aging.AgingEnabled
                ZoneScavengeServers = $zoneScavengeServers
            }
        }
        else {
            # Not a candidate
            Write-Host ("[KEEP] Zone={0} | Host={1} | Type={2} | Data={3} | Age={4} d <= Threshold={5} d -> KEPT" -f `
                $zone.ZoneName, $rr.HostName, $rr.RecordType, $data, $ageDays, $zoneThresholdDays) -ForegroundColor DarkGray
        }
    }

    # Per-zone summary
    Write-Host ("    -> {0} candidate record(s) in zone {1}" -f `
        $zoneCandidateCount, $zone.ZoneName) -ForegroundColor Green

    $zoneStats += [pscustomobject]@{
        ZoneName         = $zone.ZoneName
        CandidateRecords = $zoneCandidateCount
        NoRefreshDays    = $zoneNoRefreshDays
        RefreshDays      = $zoneRefreshDays
        ThresholdDays    = $zoneThresholdDays
    }
}

Write-Host ""
Write-Host "===== GLOBAL DRY-RUN SCAVENGING SUMMARY =====" -ForegroundColor White

foreach ($zs in $zoneStats) {
    Write-Host ("Zone {0} : {1} candidate(s) | NoRefresh={2} d | Refresh={3} d | Threshold={4} d" -f `
        $zs.ZoneName, $zs.CandidateRecords, $zs.NoRefreshDays, $zs.RefreshDays, $zs.ThresholdDays) -ForegroundColor Magenta
}

Write-Host ""
Write-Host "===== DETAILED LIST OF CANDIDATE RECORDS =====" -ForegroundColor White

if ($results.Count -gt 0) {
    $results |
        Sort-Object ZoneName, HostName, RecordType |
        Format-Table ZoneName, HostName, RecordType, RecordData, AgeDays, TimeStamp -AutoSize
}
else {
    Write-Host "No candidate records found." -ForegroundColor Yellow
}

Write-Host ""
Write-Host ("✅ {0} record(s) identified as CANDIDATES for scavenging (also available in variable `$results)" -f $results.Count) -ForegroundColor Green

# --- OPTIONAL CSV EXPORT ---
# Uncomment this section if you also want a CSV export
# $dir = Split-Path $OutputPath -Parent
# if ($dir -and -not (Test-Path $dir)) {
#     New-Item -ItemType Directory -Path $dir -Force | Out-Null
# }
# $results |
#     Sort-Object ZoneName, HostName, RecordType |
#     Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
# Write-Host "📁 CSV export written to: $OutputPath" -ForegroundColor Green
```

# 🛠️ Check Active Network Name Resolution for MDI   
📅 Published: 2025-09-29

---

## Context  
Network Name Resolution (NNR) is a main component of Microsoft Defender for Identity functionality.
Using NNR, Defender for Identity can correlate between raw activities (containing IP addresses), and the relevant computers involved in each activity. Based on the raw activities, Defender for Identity profiles entities, including computers, and generates security alerts for suspicious activities.

In cases where no name is retrieved, an unresolved computer profile by IP is created with the IP and the relevant detected activity.
But, NNR data is crucial for detecting the some threats like :

- Suspected identity theft (pass-the-ticket)
- Suspected DCSync attack (replication of directory services)
- Network-mapping reconnaissance (DNS)
...

---

## Script to verify that NNR is enable for a list of devices

```powershell
# =========================
# Network Name Resolution Quick Check (MDI)
# Tests: ICMP Ping, TCP 135 (RPC), TCP 3389 (RDP), UDP 137 (NetBIOS via nbtstat), PTR
# =========================
cls

# ---- Targets ----
$IPs = @(
  '10.0.1.12',
  '192.168.9.11',
  '10.0.1.9'
)

# ---- Helpers ----
function Test-Ping {
  param([string]$Ip)
  try { Test-Connection -ComputerName $Ip -Count 1 -Quiet -ErrorAction Stop } catch { $false }
}

function Test-TcpPort {
  param([string]$Ip,[int]$Port)
  try { (Test-NetConnection -ComputerName $Ip -Port $Port -InformationLevel Quiet) } catch { $false }
}

function Test-PTR {
  param([string]$Ip)
  try {
    $ptr = Resolve-DnsName -Name $Ip -Type PTR -ErrorAction Stop
    $ptr.NameHost.TrimEnd('.')
  } catch { $null }
}

function Test-Udp137 {
  param([string]$Ip)
  try {
    $out = & nbtstat.exe -A $Ip 2>&1
    if ($LASTEXITCODE -eq 0 -and ($out -match 'NetBIOS Remote Machine Name Table' -or $out -match 'MAC Address')) { $true }
    elseif ($out -match 'Host not found' -or $out -match 'Failed to access NBT') { $false }
    else { $false }
  } catch { $false }
}

# Pretty mapping
$ok  = { param($b) if ($b) {'OK '} else {'KO '} }
$ico = { param($b) if ($b) {"✔"} else {"✖"} }

# ---- Run tests ----
$results = foreach($ip in $IPs){
  $pingOK = Test-Ping  -Ip $ip
  $tcp135 = Test-TcpPort -Ip $ip -Port 135
  $tcp3389= Test-TcpPort -Ip $ip -Port 3389
  $udp137 = Test-Udp137 -Ip $ip
  $ptr    = Test-PTR -Ip $ip

  # "Active NNR" = at least one primary method (135/137/3389)
  $activeOk = $tcp135 -or $tcp3389 -or $udp137

  [pscustomobject]@{
    IP           = $ip
    'Ping'       = & $ok $pingOK
    'RPC 135'    = & $ok $tcp135
    'RDP 3389'   = & $ok $tcp3389
    'NBNS 137'   = & $ok $udp137
    'PTR Host'   = if ($ptr) { $ptr } else { '-' }
    'Active NNR' = & $ico $activeOk
    ActiveBool   = [bool]$activeOk   # for summary
  }
}

# ---- Pretty table ----
$results |
  Select-Object IP,'Ping','RPC 135','RDP 3389','NBNS 137','PTR Host','Active NNR' |
  Format-Table -Auto

# ---- Summary ----
$total   = $results.Count
$okCount = ($results | Where-Object { $_.ActiveBool -eq $true } | Measure-Object).Count
$rate    = if ($total) { [math]::Round(100*$okCount/$total,1) } else { 0 }

Write-Host ""
Write-Host ("Summary: {0} / {1} hosts with at least one ACTIVE method (135/137/3389) = {2}% success" -f $okCount,$total,$rate) -ForegroundColor Cyan
Write-Host "Note: Ping doesn't count as 'active name resolution'. Ensure at least one active method (135/137/3389) works from MDI sensors." -ForegroundColor DarkGray

# ---- Optional CSV ----
# $results | Select-Object IP,'Ping','RPC 135','RDP 3389','NBNS 137','PTR Host','Active NNR' |
#   Export-Csv -NoTypeInformation -Encoding UTF8 -Path "$env:TEMP\MDI-NNR-Results.csv"
# Write-Host "CSV exported to $env:TEMP\MDI-NNR-Results.csv"

```

![](assets/Check%20NNR%20Resolution%20to%20Devices/2025-09-30-01-15-47.png)
---
title: "Playing with Identity Protection API"
date: 2025-12-13
---

# Playing with Identity Protection API

This article is a practical, field-tested walkthrough of the most useful Microsoft Entra ID Identity Protection API queries, using the Microsoft Graph PowerShell SDK.  
All examples are based on real outputs and validated filters.

---

## Prerequisites

Required permissions:
- IdentityRiskEvent.Read.All
- IdentityRiskyUser.Read.All
- AuditLog.Read.All

```powershell
Import-Module Microsoft.Graph.Authentication

$Scopes = @(
  "IdentityRiskEvent.Read.All",
  "IdentityRiskyUser.Read.All",
  "AuditLog.Read.All"
)

Connect-MgGraph -Scopes $Scopes -NoWelcome
```

---

## 1. List recent risk detections
Retrieve the most recent Identity Protection detections across the tenant.

```powershell
Get-MgRiskDetection -Top 10 |
  Select-Object Id, Activity, ActivityDateTime, RiskLevel, RiskEventType, UserPrincipalName, IpAddress |
  Sort-Object ActivityDateTime -Descending
```

---

## 2. Filter detections by risk level
Focus on a specific severity level (for example, low risk signals).

```powershell
Get-MgRiskDetection -Filter "riskLevel eq 'low'" -Top 10 |
  Select-Object ActivityDateTime, RiskLevel, RiskEventType, UserPrincipalName
```

---

## 3. Filter detections by risk event type
Target a precise detection category.  
In practice, **riskEventType** is the correct filterable property (not `riskType`).

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'unfamiliarFeatures'" -Top 10 |
  Select-Object ActivityDateTime, RiskLevel, RiskEventType, UserPrincipalName
```

---

## 4. Detect sign-ins from anonymized IP addresses
Identify authentications coming from Tor, VPNs, or anonymization networks.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 20 |
  Select-Object ActivityDateTime, RiskLevel, UserPrincipalName, IpAddress |
  Sort-Object ActivityDateTime -Descending
```

---

## 5. De-duplicate detections (latest per user + IP)
Reduce noise by keeping only the most recent detection per user/IP pair.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 500 |
  Sort-Object ActivityDateTime -Descending |
  Group-Object UserPrincipalName, IpAddress |
  ForEach-Object { $_.Group | Select-Object -First 1 } |
  Select-Object ActivityDateTime, RiskLevel, UserPrincipalName, IpAddress
```

---

## 6. Time-based filtering (client-side)
Apply a reliable time window by filtering locally (example: last 30 days).

```powershell
$cutoff = (Get-Date).AddDays(-30)

Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  Where-Object { $_.ActivityDateTime -ge $cutoff } |
  Sort-Object ActivityDateTime -Descending |
  Select-Object ActivityDateTime, RiskLevel, UserPrincipalName, IpAddress
```

---

## 7. Users with repeated anonymized IP usage
Rank users by how often they authenticate from anonymized IPs.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  Group-Object UserPrincipalName |
  Sort-Object Count -Descending |
  Select-Object Name, Count
```

---

## 8. Weighted “worst offenders” ranking
Prioritize users by combining frequency and risk severity.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  ForEach-Object {
    $weight = switch ($_.RiskLevel) {
      "high" { 10 }
      "medium" { 5 }
      default { 1 }
    }
    [pscustomobject]@{
      UserPrincipalName = $_.UserPrincipalName
      RiskLevel         = $_.RiskLevel
      Weight            = $weight
    }
  } |
  Group-Object UserPrincipalName |
  ForEach-Object {
    [pscustomobject]@{
      UserPrincipalName = $_.Name
      Hits              = $_.Count
      Score             = ($_.Group | Measure-Object Weight -Sum).Sum
      High              = ($_.Group | Where-Object RiskLevel -eq "high").Count
      Medium            = ($_.Group | Where-Object RiskLevel -eq "medium").Count
      Low               = ($_.Group | Where-Object RiskLevel -eq "low").Count
    }
  } |
  Sort-Object Score -Descending |
  Select-Object -First 20
```

---

## 9. Shared anonymized IP addresses
Detect Tor/VPN exit nodes used by multiple user accounts.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  Group-Object IpAddress |
  ForEach-Object {
    $users = $_.Group | Select-Object -ExpandProperty UserPrincipalName -Unique
    [pscustomobject]@{
      IpAddress   = $_.Name
      Hits        = $_.Count
      UniqueUsers = $users.Count
      Users       = ($users -join ", ")
    }
  } |
  Sort-Object UniqueUsers -Descending |
  Select-Object -First 20
```

---

## 10. Recently active offenders (last 7 days)
Highlight accounts currently showing suspicious behavior.

```powershell
$cutoff = (Get-Date).AddDays(-7)

Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  Where-Object { $_.ActivityDateTime -ge $cutoff } |
  Group-Object UserPrincipalName |
  Sort-Object Count -Descending |
  Select-Object Name, Count
```

---

## 11. Timeline investigation for a single user
Rebuild the chronological sequence of detections for a specific account.

```powershell
$upn = "user@contoso.com"

Get-MgRiskDetection -Top 2000 |
  Where-Object { $_.UserPrincipalName -eq $upn } |
  Sort-Object ActivityDateTime -Descending |
  Select-Object ActivityDateTime, RiskEventType, RiskLevel, RiskState, IpAddress, RiskDetail
```

---

## 12. High-confidence anonymized IP detections
Generate an action-oriented list focused on medium and high risks.

```powershell
Get-MgRiskDetection -Filter "riskEventType eq 'anonymizedIPAddress'" -Top 2000 |
  Where-Object { $_.RiskLevel -in @("medium","high") } |
  Sort-Object ActivityDateTime -Descending |
  Group-Object UserPrincipalName, IpAddress |
  ForEach-Object { $_.Group | Select-Object -First 1 } |
  Select-Object ActivityDateTime, RiskLevel, UserPrincipalName, IpAddress, RiskState, RiskDetail
```

---

## 13. Inspect detection context (risk reasons & MITRE)
Extract detection explanations and MITRE ATT&CK mappings.

```powershell
Get-MgRiskDetection -Top 50 |
  ForEach-Object {
    $ai = @()
    if ($_.AdditionalInfo) { $ai = $_.AdditionalInfo | ConvertFrom-Json }

    $reasons = ($ai | Where-Object Key -eq "riskReasons").Value
    $mitre   = ($ai | Where-Object Key -eq "mitreTechniques").Value

    [pscustomobject]@{
      ActivityDateTime  = $_.ActivityDateTime
      UserPrincipalName = $_.UserPrincipalName
      RiskEventType     = $_.RiskEventType
      RiskLevel         = $_.RiskLevel
      IpAddress         = $_.IpAddress
      RiskReasons       = ($reasons -join ", ")
      MitreTechniques   = $mitre
    }
  } |
  Sort-Object ActivityDateTime -Descending
```

---

## Notes

- Identity Protection detections are security **signals**, not raw sign-in logs.
- Multiple detections for a single sign-in are expected.
- Client-side de-duplication is essential for accurate reporting.
- These queries are ideal foundations for threat hunting and SOC investigations.


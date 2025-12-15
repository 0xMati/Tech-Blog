# Playing with Identity Protection and Sentinel
🗓️ Published: 2025-12-13

This article provides a practical set of **Microsoft Sentinel KQL queries** focused on **Microsoft Entra ID Identity Protection** data.  
All examples are designed for **threat hunting, investigation, and SOC workflows**, using the native Sentinel tables.

> ✅ Schemas validated in the workspace:
> - **AADUserRiskEvents** includes `IpAddress` (not `IPAddress`).
> - **AADRiskyUsers** does **not** include `UserId`; it includes `Id` and `UserPrincipalName`.

---

## Data sources

The queries below rely on the following Sentinel tables:
- **AADUserRiskEvents** — individual Identity Protection risk detections
- **AADRiskyUsers** — risky user state snapshots

---

## 1. Top risky users (last 7 days)
Identify the accounts generating the highest number of Identity Protection risk events.

```kql
AADUserRiskEvents
| where TimeGenerated >= ago(7d)
| summarize Events=count(), LastSeen=max(TimeGenerated) by UserPrincipalName
| order by Events desc
```

---

## 2. Anonymized IP sign-ins (de-duplicated)
Produce a clean, action-oriented list of anonymized IP detections, deduplicated per user and IP.

```kql
AADUserRiskEvents
| where TimeGenerated >= ago(30d)
| where RiskEventType == "anonymizedIPAddress"
| summarize LastSeen=max(TimeGenerated),
            AnyLevel=any(RiskLevel),
            AnyState=any(RiskState)
          by UserPrincipalName, IpAddress
| order by LastSeen desc
```

---

## 3. Weighted “worst offenders” ranking
Prioritize users by combining detection frequency and risk severity.

```kql
AADUserRiskEvents
| where TimeGenerated >= ago(30d)
| extend Weight = case(
    RiskLevel == "high", 10,
    RiskLevel == "medium", 5,
    1
)
| summarize Events=count(),
            Score=sum(Weight),
            LastSeen=max(TimeGenerated)
          by UserPrincipalName
| order by Score desc
```

---

## 4. Shared anonymized IP addresses
Detect Tor/VPN exit nodes used by multiple user accounts.

```kql
AADUserRiskEvents
| where TimeGenerated >= ago(30d)
| where RiskEventType == "anonymizedIPAddress"
| summarize Hits=count(),
            UniqueUsers=dcount(UserPrincipalName),
            SampleUsers=make_set(UserPrincipalName, 10)
          by IpAddress
| where UniqueUsers >= 3
| order by UniqueUsers desc, Hits desc
```

---

## 5. Newly risky users (recent snapshots)
Highlight users that have recently appeared as risky (based on AADRiskyUsers snapshots).

```kql
AADRiskyUsers
| where TimeGenerated >= ago(7d)
| summarize LastSeen=max(TimeGenerated),
            AnyLevel=any(RiskLevel),
            AnyState=any(RiskState)
          by UserPrincipalName
| order by LastSeen desc
```

---

## 6. Users still requiring remediation
List risky users whose latest state is not yet remediated or dismissed.

```kql
AADRiskyUsers
| summarize arg_max(TimeGenerated, *) by UserPrincipalName
| where RiskState !in ("remediated", "dismissed")
| project TimeGenerated,
          UserPrincipalName,
          UserDisplayName,
          RiskLevel,
          RiskState,
          RiskDetail,
          RiskLastUpdatedDateTime,
          IsDeleted,
          IsProcessing
| order by TimeGenerated desc
```

---

## 7. User investigation timeline
Rebuild the chronological sequence of Identity Protection detections for a specific user.

```kql
let upn = "user@contoso.com";
AADUserRiskEvents
| where TimeGenerated >= ago(30d)
| where UserPrincipalName == upn
| project TimeGenerated,
          RiskEventType,
          RiskLevel,
          RiskState,
          IpAddress,
          RiskDetail
| order by TimeGenerated desc
```

---

## 8. Correlating risk events with the latest risky user state
Enrich detections with the latest known risky-user status (joined on UserPrincipalName).

```kql
AADUserRiskEvents
| where TimeGenerated >= ago(30d)
| join kind=leftouter (
    AADRiskyUsers
    | summarize arg_max(TimeGenerated, *) by UserPrincipalName
    | project UserPrincipalName,
              UserDisplayName,
              UserRiskLevel=RiskLevel,
              UserRiskState=RiskState,
              UserRiskDetail=RiskDetail,
              UserRiskLastUpdated=RiskLastUpdatedDateTime
) on UserPrincipalName
| project TimeGenerated,
          UserPrincipalName,
          UserDisplayName,
          RiskEventType,
          RiskLevel,
          RiskState,
          IpAddress,
          RiskDetail,
          UserRiskLevel,
          UserRiskState,
          UserRiskDetail,
          UserRiskLastUpdated
| order by TimeGenerated desc

```

---

## Notes

- Identity Protection data represents **security signals**, not raw authentication logs.
- Multiple detections per user or IP are expected and should be de-duplicated.
- Combining **AADUserRiskEvents** and **AADRiskyUsers** provides the most operational value.
- These queries are strong foundations for **Sentinel Analytics rules** and **SOC playbooks**.

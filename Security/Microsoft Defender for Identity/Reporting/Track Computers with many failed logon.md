---
title: "Report: Track Computers with many failed logon"
date: 2025-04-22
---

## Logon failed by Computers

Computers that generate failed logon

### Query

```kusto
IdentityLogonEvents
| where LogonType == "Failed logon"
| where isnotempty(DestinationDeviceName)
| summarize Attempts = count() by DeviceName, DestinationDeviceName , FailureReason
| where Attempts > 100
| order by Attempts desc
```


### Use Case

- **Monitoring** Computers failure monitoring

### Source
https://github.com/DanielpFR/MDI


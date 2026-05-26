---
title: "MDI Custom Detection – Detect Locked Accounts and related sources"
date: 2025-12-01
---

# MDI Custom Detection – Detect Locked Accounts and related sources 

This document provides a KQL approach to detect Active Directory account lockouts using Microsoft Defender for Identity data in Microsoft Defender XDR, and to enrich each lockout event with the preceding failed logons that triggered the lockout.

# Overview

MDI surfaces two types of events critical for lockout analysis:
- IdentityDirectoryEvents – reports changes to AD directory attributes (including account lockout status)
- IdentityLogonEvents – reports authentication events (Kerberos, NTLM, LogonFailed, etc.)

A successful lockout investigation requires:
- Detecting which accounts were locked
- Identifying when they were locked
- Retrieving all failed authentication attempts leading to the lockout
- Identifying the source machine, protocol, and time sequence of failures

# Detecting Locked Accounts

MDI logs lockout state changes as:
* ActionType = "Account Unlock changed"
* AdditionalFields.NewValue = "true"
* AdditionalFields.OldValue = "false"

This means the AD attribute Lockout changed from not locked → locked.

```kql
IdentityDirectoryEvents
| where Timestamp >= ago(1d)
| where ActionType == "Account Unlock changed"
| extend
    NewValue = tostring(parse_json(AdditionalFields).NewValue),
    OldValue = tostring(parse_json(AdditionalFields).OldValue)
| where NewValue == "true" and OldValue == "false"   // False -> True = locked
| project
    LockoutTime = Timestamp,
    TargetAccountUpn,
    TargetAccountDisplayName
| order by LockoutTime desc
```
![](assets/Detect%20Locked%20Account%20and%20sources/2025-12-01-15-33-14.png)

# Enriching Lockouts with Previous Failed Logons

The next step is correlating each lockout with the authentication failures that led to it.

**Correlation logic**

For each locked account:
- Look for IdentityLogonEvents
- Filter on ActionType = "LogonFailed"
- Restrict to the time window before the lockout (e.g., 15 minutes)
- Join using the UPN

```kql
IdentityDirectoryEvents
| where Timestamp >= ago(1d)
| where ActionType == "Account Unlock changed"
| extend
    NewValue = tostring(parse_json(AdditionalFields).NewValue),
    OldValue = tostring(parse_json(AdditionalFields).OldValue)
| where NewValue == "true" and OldValue == "false"   // False -> True = locked
| project
    LockoutTime = Timestamp,
    TargetAccountUpn,
    TargetAccountDisplayName
| join kind=inner (
    IdentityLogonEvents
    | where Timestamp >= ago(1d)
    | where ActionType == "LogonFailed"
    | project
        FailTime      = Timestamp,
        AccountUpn,
        AccountName,
        AccountDomain,
        DeviceName,
        DestinationDeviceName,
        Protocol,
        FailureReason
) on $left.TargetAccountUpn == $right.AccountUpn
| where FailTime between (LockoutTime - 15m .. LockoutTime)
| order by LockoutTime desc, FailTime asc
```

This produces one row per failed authentication event, showing:
- the lockout time
- each failed attempt leading to lockout
- originating device
- destination DC
- protocol (Kerberos / NTLM)
- failure reason (Generic, BadPassword, ClientRevoked, etc.)

![](assets/Detect%20Locked%20Account%20and%20sources/2025-12-01-15-34-14.png)

# Use Cases

This detection helps you:
- Investigate brute force attacks against AD accounts
- Understand which workstation caused repeated authentication failures
- Identify service account lockouts caused by stale credentials
- Build custom XDR detection rules for SOC monitoring.

# Notes

- You may increase the window from 15 minutes to 30 minutes or 1 hour depending on your environment
- For critical service accounts, you can restrict alerts only to accounts in a specific AD group.
- If you ingest Windows Security Logs (Event 4740), you can further correlate MDI with DC-native events



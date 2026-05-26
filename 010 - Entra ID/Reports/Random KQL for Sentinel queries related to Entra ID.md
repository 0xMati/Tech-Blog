# Some Random KQL for Sentinel queries related to Entra ID
🗓️ Published: 2025-12-15

This article is a **small, practical collection of KQL queries** I
somtimes use in **Microsoft Sentinel** when working on **Microsoft
Entra ID** investigations.

The goal is not to be exhaustive, but to provide **ready-to-use
queries** that help quickly answer common questions around
**authentication, Conditional Access, and identity activity**.

------------------------------------------------------------------------

## 1. Sign-ins blocked by Conditional Access (detailed view)

Lists individual sign-in attempts that were blocked by Conditional
Access, including the exact policy responsible.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where ConditionalAccessStatus == "failure"
| where ResultType != 0
| mv-expand CAP = ConditionalAccessPolicies
| where tostring(CAP.result) == "failure"
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    IPAddress,
    Location = strcat(tostring(LocationDetails.countryOrRegion), " / ", tostring(LocationDetails.state), " / ", tostring(LocationDetails.city)),
    ConditionalAccessPolicy = tostring(CAP.displayName),
    FailureReason = ResultDescription,
    Status = tostring(Status.errorCode),
    Device = tostring(DeviceDetail.displayName),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    ClientAppUsed
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 2. Conditional Access failures for a specific user

Quickly shows which Conditional Access policies blocked a given user.

``` kql
let TargetUser = "user@domain.com";
SigninLogs
| where TimeGenerated >= ago(30d)
| where UserPrincipalName =~ TargetUser
| where ConditionalAccessStatus == "failure"
| mv-expand CAP = ConditionalAccessPolicies
| where tostring(CAP.result) == "failure"
| project TimeGenerated, AppDisplayName, IPAddress, ConditionalAccessPolicy=tostring(CAP.displayName), FailureReason=ResultDescription
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 3. Top Conditional Access policies causing blocks

Identifies the Conditional Access policies that block the most sign-ins.

``` kql
SigninLogs
| where TimeGenerated >= ago(30d)
| where ConditionalAccessStatus == "failure"
| mv-expand CAP = ConditionalAccessPolicies
| where tostring(CAP.result) == "failure"
| summarize BlockCount=count(), Users=dcount(UserPrincipalName), Apps=dcount(AppDisplayName) by Policy=tostring(CAP.displayName)
| order by BlockCount desc
```

------------------------------------------------------------------------

## 4. All failed sign-ins

Displays authentication failures

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, ResultDescription
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 5. Risky sign-ins detected by Entra ID Identity Protection

Lists sign-ins flagged with a risk level by Identity Protection.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where RiskLevelDuringSignIn != "none"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, RiskLevelDuringSignIn, RiskState, RiskDetail
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 6. Impossible travel detections

Highlights sign-ins associated with impossible travel or unfamiliar
locations.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where RiskEventTypes has "impossibleTravel"
| project TimeGenerated, UserPrincipalName, IPAddress, LocationDetails, RiskEventTypes
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 7. Sign-ins using legacy authentication

Identifies authentication attempts using legacy (non-modern)
authentication protocols.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Other clients")
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 8. Non-interactive sign-ins (service or background activity)

Useful to investigate token refreshes, background access, or
service-related authentication.

``` kql
AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(7d)
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, ResultType, ResultDescription
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 9. Sign-ins from unfamiliar devices

Shows sign-ins where the device is unknown or not registered.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where isempty(DeviceDetail.deviceId)
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, DeviceDetail
| order by TimeGenerated desc
```

------------------------------------------------------------------------

## 10. Sign-ins by guests (B2B users)

Helps monitor authentication activity coming from external identities.

``` kql
SigninLogs
| where TimeGenerated >= ago(7d)
| where UserType == "Guest"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, ResultDescription
| order by TimeGenerated desc
```

------------------------------------------------------------------------


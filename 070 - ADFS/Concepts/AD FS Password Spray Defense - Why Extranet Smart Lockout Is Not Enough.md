---
title: "AD FS Password Spray Defense - Why Extranet Smart Lockout Is Not Enough"
date: 2026-10-18
---

# AD FS Password Spray Defense - Why Extranet Smart Lockout Is Not Enough

**A thousand accounts receiving one bad password each is a very different problem from one account receiving a thousand bad passwords.**

Password spray spreads a small number of guesses across many identities. Each account can remain below its lockout threshold while the organization receives a substantial attack.

That is why **Extranet Smart Lockout (ESL) is useful, but not sufficient**. Keep it; just do not ask a per-account protection to be the entire detection and response system.

## 1. Different controls answer different questions

| Control | What it helps with | What it does not guarantee |
|---|---|---|
| AD DS lockout policy | Repeated bad passwords against an account | Detection of low-volume guesses across many users |
| AD FS ESL | Familiar/unknown location handling on the documented extranet password path | Coverage of every intranet path, protocol or distributed attack |
| Password quality protection | Rejecting weak passwords at change/reset | Removal of every existing weak password |
| MFA, preferably phishing-resistant where supported | Reducing the value of a stolen password | Prevention of all password attempts or AD DS lockouts |
| Aggregated sign-in detection | Patterns across accounts, IPs and time | Automatic blocking or complete attribution |

The [ESL deployment guide](../How-to/AD%20FS%20Extranet%20Smart%20Lockout%20-%20Deployment%20and%20Account%20Activity.md) covers settings and version differences. This note deliberately does not provide a new "magic threshold."

Password quality is another layer, not an ESL feature:

![Historical password-change validation rejecting an easily guessed password](<./assets/AD FS Password Spray Defense - Why Extranet Smart Lockout Is Not Enough/historical-password-quality-validation.png>)

*Historical cloud password-change capture, cropped to the validation message. It does not demonstrate that an on-premises DC has Password Protection installed, or prescribe today's password-length policy.*

For AD DS, Microsoft Entra Password Protection requires its own deployment. The DC agent evaluates password changes/resets where installed; consistent domain-wide enforcement requires coverage of all DCs. It does not retroactively inspect every existing password.

## 2. Look across accounts, not only inside one account

Useful investigation patterns include:

- One observed IP failing against many distinct accounts.
- Several IPs targeting an overlapping population.
- Repeated low-rate activity across multiple time windows.
- A successful sign-in mixed into otherwise failing activity.

None proves an attack on its own. Shared corporate egress, a broken client rollout or a proxy that loses the original address can create misleading patterns. An IP is a network clue, not a person.

**The current Microsoft route is the AD FS Risky IP report workbook**, backed by `ADFSSignInLogs`, rather than reproducing the old Risky IP report's 2018 portal screens.

Check the prerequisites first: Connect Health AD FS collection/auditing, the appropriate licensing and access, and diagnostic settings streaming **`ADFSSignInLogs` to the intended Log Analytics workspace**. Verify recent ingestion and retention. Simply having Entra sign-in logs or a workbook does not establish that all AD FS requests are being collected.

The following read-only KQL is a **triage example**, not Microsoft's detection algorithm or a recommended production threshold:

```kusto
let MinimumFailedAttempts = 20;
let MinimumDistinctAccounts = 5;
ADFSSignInLogs
| where TimeGenerated >= ago(1h)
| where ResultType in ("50126", "300030")
| where isnotempty(IPAddress) and isnotempty(UserPrincipalName)
| summarize
    BadPasswordErrors = countif(ResultType == "50126"),
    ExtranetLockoutErrors = countif(ResultType == "300030"),
    DistinctAccounts = dcount(UserPrincipalName)
    by IPAddress
| extend FailedAttempts = BadPasswordErrors + ExtranetLockoutErrors
| where FailedAttempts >= MinimumFailedAttempts
    and DistinctAccounts >= MinimumDistinctAccounts
| order by DistinctAccounts desc, FailedAttempts desc
```

The workbook guidance uses `50126` for bad-password errors and `300030` for extranet-lockout errors. Confirm the actual workspace values before adapting the query. An ESL-blocked request is not necessarily another password validation against AD DS, and a log row is not a guaranteed one-to-one count of guessed passwords. `dcount` is approximate.

An empty result means **no match in this dataset, window and filter**. Missing ingestion, missing identities, a distributed campaign or activity below the example thresholds can all escape it. A missing table or query error is a collection problem, not zero attacks.

## 3. A workbook does not block an attacker

Keep four separate steps in mind:

1. **Collection:** are the relevant requests reaching the workspace?
2. **Detection:** do the queries surface the pattern you need?
3. **Alerting:** is an Azure Monitor alert actually configured, evaluated and routed to an owner?
4. **Response:** who investigates and authorizes containment?

Workbook thresholds do not change AD FS ESL thresholds or create a firewall rule. If IP-based containment is appropriate, apply it at the controlled ingress point after checking shared-address impact. Do not automatically deny an entire VPN or load balancer because its address tops a chart.

Also investigate suspicious **successful** sign-ins, protect affected identities and review sessions through your incident-response process. Do not run a password spray against real users to test your dashboard; validate query behavior with synthetic data and use separately authorized lab accounts for end-to-end testing.

**Bottom line:** combine account protection, password quality, stronger authentication and cross-account visibility. If actual lockouts need tracing, follow the [DC / AD FS / WAP correlation guide](../Troubleshoot/AD%20FS%20Account%20Lockouts%20-%20Correlating%20AD%20FS,%20WAP%20and%20Domain%20Controller%20Events.md).

## References

- [Microsoft Learn: AD FS Risky IP report workbook, prerequisites and alerting](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-adfs-risky-ip-workbook)
- [Microsoft Learn: ADFSSignInLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/adfssigninlogs)
- [Microsoft Learn: Extranet Smart Lockout](https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/configure-ad-fs-extranet-smart-lockout-protection)
- [Microsoft Learn: Password Protection for on-premises AD DS](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-on-premises)

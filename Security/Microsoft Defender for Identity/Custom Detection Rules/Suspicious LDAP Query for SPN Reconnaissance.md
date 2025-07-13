# MDI Custom Detection Rule – Suspicious LDAP Query for SPN Reconnaissance
🗓️ Published: 2025-02-21

---

## Rule Description

LDAP queries using `servicePrincipalName=*` are highly indicative of **SPN enumeration**,  
a precursor step in **Kerberoasting** attacks.  
This detection helps identify systems performing such suspicious LDAP queries.

---

## ⚠️ Risk Analysis

- **Reconnaissance for Kerberoasting**  
  Attackers often enumerate service accounts to request TGS tickets for offline cracking.
- **High Privilege Targeting**  
  This technique is aimed at accounts with SPNs, which often have elevated privileges.

---

## Detection Logic (KQL Query)

```kusto
IdentityQueryEvents
| where ActionType == "LDAP query"
| extend ParsedFields = parse_json(AdditionalFields)
| where Query contains " (servicePrincipalName=*)"
| project Timestamp, ActionType, DeviceName, IPAddress, Query, Count = (ParsedFields.Count), DestinationDeviceName, ParsedFields, ReportId
| order by Timestamp desc
```

---

## Recommended Actions

1. **Investigate Source Host**
   - Confirm if this LDAP query was expected or part of a legitimate scan.
2. **Review Queried Accounts**
   - Identify which service accounts were retrieved using SPNs.
3. **Enable Audit Kerberos Service Ticket Operations**
   - Correlate ticket requests to validate potential misuse.

---

## Notes

> This detection logic is **commonly triggered during Kerberoasting attack preparations**.

---


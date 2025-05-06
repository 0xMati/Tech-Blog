# 🎯 ADFS Claim rules - Some Examples, somes samples  
🗓️ Published: 2025-05-06

## 🗂️ Table des matières

1. [🔍 Regular Expressions in ADFS Claim Rules](#regular-expressions-in-adfs-claim-rules)
2. [🎯 ADFS Claim Rules — Practical Examples](#adfs-claim-rules--practical-examples)
   - [🛡️ 1. Send Linux Root Role if Admin](#-1-send-linux-root-role-if-admin)
   - [🖥️ 2. Send ADFSServerName](#-2-send-adfservername)
   - [🎩 3. Magic Claim Rule (pass-through)](#-3-magic-claim-rule-pass-through)
   - [🌐 4. Allow AuthN from External when LS Endpoint is used Except for Outlook User Agent](#-4-allow-authn-from-external-when-ls-endpoint-is-used-except-for-outlook-user-agent)
   - [📱 5. Allow AuthN from External for ActiveSync Client](#-5-allow-authn-from-external-for-activesync-client)
   - [🏢 6. Permit All Users from Internal Location](#-6-permit-all-users-from-internal-location)
   - [📧 7. Block Outlook Access from External Network](#-7-block-outlook-access-from-external-network)
   - [🚫 8. Block ActiveSync for Specific Group](#-8-block-activesync-for-specific-group)
   - [🌐 9. OWA Access for Group Members Only on Internal Network](#-9-owa-access-for-group-members-only-on-internal-network)
   - [🔐 10. Force Forms Authentication While Preserving Internal Access](#-10-force-forms-authentication-while-preserving-internal-access)
   - [🧩 11. Common Client Access Scenarios with ADAL and ADFS](#-11-common-client-access-scenarios-with-adal-and-adfs)
   - [🗂️ 12. LDAP Queries and Attribute Extraction Rules](#-12-ldap-queries-and-attribute-extraction-rules)
   - [🧬 13. Advanced Claim Scenarios: ADLDS, MFA, Client Metadata, Cert Auth](#-13-advanced-claim-scenarios-adlds-mfa-client-metadata-cert-auth)
   - [🔐 14. Advanced MFA Policies in ADFS](#-14-advanced-mfa-policies-in-adfs)
   - [🧪 15. MFA Rules: Exception Handling, Network Checks, and Method Filters](#-15-mfa-rules-exception-handling-network-checks-and-method-filters)
   - [🧱 16. Block All Except Modern Authentication](#-16-block-all-except-modern-authentication)
   - [🧩 17. Send UPN or ExtensionAttribute if UPN is Blank](#-17-send-upn-or-extensionattribute-if-upn-is-blank)
---

## 🔍 Regular Expressions in ADFS Claim Rules

**Before diving into practical claim rule examples, it’s essential to understand the power of regular expressions (RegEx) in ADFS.**  
RegEx is widely used to match, filter, or transform incoming claim values within ADFS policies. The `=~` operator is key when applying regex in rule conditions.

Here's a quick reference table for common regex operations:

| **Symbol** | **Operation**                                | **Example rule**                                                                                                                                                          | **Explanation**                                                                                           |
|------------|-----------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `^`        | Match the beginning of a string               | `c:[type == "http://contoso.com/role", Value =~ "^director"] => issue (claim = c);`                                                                                       | Pass role claims starting with `"director"`                                                              |
| `$`        | Match the end of a string                     | `c:[type == "http://contoso.com/email", Value =~ "contoso.com$"] => issue (claim = c);`                                                                                   | Pass email claims ending in `"contoso.com"`                                                              |
| `|`        | OR                                             | `c:[type == "http://contoso.com/role", Value =~ "^director|^manager"] => issue (claim = c);`                                                                              | Match `"director"` or `"manager"`                                                                         |
| `(?i)`     | Case insensitive flag                         | `c:[type == "http://contoso.com/role", Value =~ "(?i)^director"] => issue (claim = c);`                                                                                   | Ignore case sensitivity                                                                                   |
| `x.*y`     | Match "x" followed by "y"                     | `c:[type == "http://contoso.com/role", Value =~ "(?i)Seattle.*Manager"] => issue (claim = c);`                                                                            | Match claims containing `"Seattle"` followed by `"Manager"` (case insensitive)                           |
| `+`        | Match one or more of preceding character      | `c:[type == "http://contoso.com/employeeId", Value =~ "^0+"] => issue (claim = c);`                                                                                       | Match employeeId starting with one or more `"0"`                                                         |
| `*`        | Match zero or more of preceding character     | _Usually used in RegExReplace scenarios._                                                                                                                                | Useful in advanced replacements, e.g., capturing optional segments                                       |

**Tip:** Always validate your RegEx using tools like [regex101](https://regex101.com) or [regexr](https://regexr.com) before applying them in ADFS rules.

---
# 🎯 ADFS Claim Rules — Practical Examples

This document illustrates various claim issuance rules (Claim Rules) in an ADFS (Active Directory Federation Services) context. Each example includes its purpose, the full rule, and a brief explanation.

---

## 🛡️ 1. Send Linux Root Role if Admin

**Purpose:**  
Assign a specific `Root` role to a user who is a member of the Administrators group (SID `...-512`), typically for Linux systems.

**Rule:**
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "^(?i)S-1-5-21-2462332226-1795882094-2017209951-512$"]
 => issue(Type = "http://contoso.com/LinuxRole", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = "Root", ValueType = c.ValueType);
```

**Explanation:**
- Checks if the user is a member of the Administrators group (based on SID).
- Issues a custom claim with value "Root".

---

## 🖥️ 2. Send ADFSServerName

**Purpose:**  
Emit the name of the ADFS server that processed the request. Useful for auditing or debugging.

**Rule:**
```adfs
=> issue(store = "Internal WID", types = ("http://contoso.com/AdfsServerName"), query = "SELECT HOST_NAME() AS HostName");
```

**Explanation:**
- Executes an SQL query against the local WID database to retrieve the host name.
- Issues the server name as a custom claim.

---

## 🎩 3. Magic Claim Rule (pass-through)

**Purpose:**  
Pass through all incoming claims without filtering or transformation. Useful for diagnostics or debugging.

**Rule:**
```adfs
c:[]
 => issue(claim = c);
```

**Explanation:**
- Captures all incoming claims.
- Forwards them as-is to the relying party.

---

## 🌐 4. Allow AuthN from External when LS Endpoint is used Except for Outlook User Agent

**Purpose:**  
Allow authentication from external networks when the `/adfs/ls/` or `/adfs/oauth2` endpoints are used — except if the request comes from an Outlook user agent.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"])
 && exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value =~ "(/adfs/ls/)|(/adfs/oauth2)"])
 && NOT exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent", Value =~ "(?i)Outlook$"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

**Explanation:**
- Checks if the request originates from outside the corporate network.
- Validates that the login is initiated from specific endpoints (`/adfs/ls/` or `/adfs/oauth2`).
- Denies access if the user agent is Outlook.
- Issues a `permit` claim if all conditions are met.

---

## 📱 5. Allow AuthN from External for ActiveSync Client

**Purpose:**  
Permit authentication from external networks specifically for clients using Microsoft Exchange ActiveSync.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"])
 && exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value == "Microsoft.Exchange.ActiveSync"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

**Explanation:**
- Confirms that the request comes from outside the corporate network.
- Checks if the client application is Microsoft Exchange ActiveSync.
- Issues a `permit` claim to allow authentication.

---

## 🏢 6. Permit All Users from Internal Location

**Purpose:**  
Allow all users to authenticate when the request originates from within the corporate network.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "true"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

**Explanation:**
- Verifies that the request is coming from an internal network location.
- Issues a `permit` claim unconditionally for internal users.

---

## 📧 7. Block Outlook Access from External Network

**Purpose:**  
Prevent Outlook clients from accessing email when not connected to the corporate network, by blocking Active ADFS claims for RPC/HTTPS and EWS services from unauthorized IP addresses.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"]) &&
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value == "/adfs/services/trust/2005/usernamemixed"]) &&
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value == "Microsoft.Exchange.RPC|Microsoft.Exchange.WebServices"]) &&
NOT exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip", Value =~ "\b192\.168\.4\.([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-9])\b|\b10\.3\.4\.5\b"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");
```

**Explanation:**
- Targets **active claims** for Outlook RPC and EWS.
- Applies the rule only if the request comes via an ADFS proxy, using the `usernamemixed` endpoint.
- Blocks access if the client IP is **not in** the allowed NAT/public address range.
- Uses `x-ms-forwarded-client-ip` header inserted by Exchange Online to identify client IP.

This rule ensures Outlook cannot be configured from home or other external networks, meeting a common security requirement in enterprise environments.

---

## 🚫 8. Block ActiveSync for Specific Group

**Purpose:**  
Deny access to Microsoft Exchange ActiveSync for users who are members of a specific Active Directory group.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"]) &&
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "Group SID value of allowed AD group"]) &&
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value == "Microsoft.Exchange.ActiveSync"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");
```

**Explanation:**
- Applies when the user request goes through a proxy.
- Matches users based on AD group SID.
- Denies claims for the ActiveSync client application.

---

## 🌐 9. OWA Access for Group Members Only on Internal Network

**Purpose:**  
Restrict members of a specific group to access Outlook Web App (OWA) only when on the corporate network, by denying passive claims routed through external proxies.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"]) &&
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "S-1-5-21-299502267-1364589140-1177238915-114465"]) &&
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value == "/adfs/ls/"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");
```

**Explanation:**
- Blocks passive claims to `/adfs/ls/` for group members accessing through an external proxy.
- Internal requests bypass the rule because `x-ms-proxy` does not exist or has a different value.

---

## 🔐 10. Force Forms Authentication While Preserving Internal Access

**Purpose:**  
Ensure users authenticate through specific proxies (for example, to enforce Forms-Based Authentication), and allow OWA access only for internal users of a group.

**Rule:**
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy", Value =~ "\badfsp[0-9][0-9]\b"]) &&
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "S-1-5-21-299502267-1364589140-1177238915-114465"]) &&
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value == "/adfs/ls/"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");
```

**Explanation:**
- Identifies users coming through a proxy named like `adfsp##` (external ADFS proxy).
- Denies access to `/adfs/ls/` endpoint for group members if request is routed through external proxy.
- Internal users (e.g., through `adfspi##`) bypass the deny rule.

---

## 🧩 11. Common Client Access Scenarios with ADAL and ADFS

**Purpose:**  
Summarize practical ADFS rules to manage Office 365 access based on location, device type, or client application, with or without Modern Authentication (ADAL).

### 🌍 Scenario 1: Block All External Access
```adfs
c1:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"] &&
c2:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip", Value =~ "^(?!192\.168\.1\.77|10\.83\.118\.23)"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "DenyUsersWithClaim");
```

### 📱 Scenario 2: Allow Only ActiveSync Externally
```adfs
c1:[Type == "http://custom/ipoutsiderange", Value == "true"] &&
c2:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value != "Microsoft.Exchange.ActiveSync"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "DenyUsersWithClaim");
```

### 🌐 Scenario 3: Allow Only Browser Access Externally
```adfs
c1:[Type == "http://custom/ipoutsiderange", Value == "true"] &&
c2:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value != "/adfs/ls/"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "DenyUsersWithClaim");
```

### 👥 Scenario 4: Allow Access Only for Certain AD Groups
```adfs
c1:[Type == "http://custom/ipoutsiderange", Value == "true"] &&
NOT EXISTS([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-32-100"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "DenyUsersWithClaim");
```

**Note:**  
Modern authentication causes all clients to use **passive endpoints**, rendering some header-based filters ineffective. Use `x-ms-client-user-agent` and regular expressions to identify devices or applications.

---

## 🗂️ 12. LDAP Queries and Attribute Extraction Rules

**Purpose:**  
These ADFS claim rules demonstrate how to retrieve attributes like UPN and ImmutableID from LDAP (instead of AD), extract names from account names, and parse domain components.

### 🔁 Retrieve UPN and ImmutableID from LDAP using AccountName
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "LDAP", types = ("http://schemas.xmlsoap.org/claims/UPN", "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = "samAccountName={0};userPrincipalName,objectGUID;{1}", param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);
```

### ✉️ Retrieve UPN and ImmutableID from LDAP using AccountName and Email Domain
```adfs
C1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] &&
C2:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", Value =~ "(?i)@contoso.com$"]
 => issue(store = "LDAP", types = ("http://schemas.xmlsoap.org/claims/UPN", "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = "samAccountName={0};userPrincipalName,objectGUID;{1}", param = regexreplace(c1.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c1.Value);
```

### 🌐 Retrieve UPN and ImmutableID from LDAP using AccountName and Domain Prefix
```adfs
C1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] &&
C2:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Value =~ "^CONTOSO\\.*"]
 => issue(store = "LDAP", types = ("http://schemas.xmlsoap.org/claims/UPN", "http://schemas.microsoft.com/LiveID/Federation/2008/05/ImmutableID"), query = "samAccountName={0};userPrincipalName,objectGUID;{1}", param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);
```

### 🔎 Extract username from windowsaccountname
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => issue(Type = "http://contoso/CustomClaim1", Value = RegexReplace(c.Value, ".*\\", ""));
```

### 🆔 Query employeeID from ADLDS using temporary name
```adfs
c:[Type == "http://contoso/myTempName"]
 => issue(store = "LDAP", types = ("http://contoso/employeeID"), query = "name={0};employeeID", param = c.Value);
```

### 🧾 Extract NetBIOS domain name
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Value =~ "^.*(\\).*$"]
 => issue(Type = "http://temp.org/windowsdomainnamenetbios", Value = RegexReplace(c.Value, "\\.*", ""));
```

### 🌐 Extract DNS domain name from UPN
```adfs
c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "^.*(@).*$"]
 => issue(Type = "http://temp.org/windowsdomainnamefqdn", Value = RegexReplace(c.Value, ".*@", ""));
```

**Note:** These rules assume consistency between UPN and domain names and are based on examples from the Microsoft Geneva forum.


---

## 🧬 13. Advanced Claim Scenarios: ADLDS, MFA, Client Metadata, Cert Auth

**Purpose:**  
These claim rules address more advanced scenarios including nested group retrieval from ADLDS, multifactor authentication claims, client metadata passthrough, and certificate-based authentication.

### 🧾 Retrieve Nested Group Membership from ADLDS After AD Authentication

#### 1. Extract Name for ADLDS
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => add(Type = "http://ADLDS/myTempName", Value = RegexReplace(c.Value, ".*\\", ""));
```

#### 2. Retrieve DN from AD
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => add(store = "Active Directory", types = ("http://AD/myclaims/UserDN"), query = ";distinguishedName;{0}", param = c.Value);
```

#### 3. Retrieve All Nested Groups from AD
```adfs
c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"] &&
c2:[Type == "http://AD/myclaims/UserDN"]
 => issue(store = "Active Directory", types = ("http://AD/myclaims/MemberOfDN"), query = "(member:1.2.840.113556.1.4.1941:={1});distinguishedName;{0}", param = c1.Value, param = c2.Value);
```

#### 4. Retrieve DN from ADLDS
```adfs
c:[Type == "http://ADLDS/myTempName"]
 => add(store = "ADLDS", types = ("http://ADLDS/UserDN"), query = "Name={0};distinguishedname", param = c.Value);
```

#### 5. Retrieve All Nested Groups from ADLDS
```adfs
c1:[Type == "http://ADLDS/myTempName"] &&
c2:[Type == "http://ADLDS/UserDN"]
 => issue(store = "ADLDS", types = ("http://ADLDS/myclaims/MemberOfDN"), query = "(member:1.2.840.113556.1.4.1941:={1});distinguishedName;{0}", param = c1.Value, param = c2.Value);
```

### 🔐 Send MFA Claims if Azure MFA is Primary
```adfs
c:[Type == "http://schemas.microsoft.com/claims/authnmethodsproviders", Value == "AzurePrimaryAuthentication"]
 => issue(Type = "http://schemas.microsoft.com/claims/authnmethodsreferences", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 📡 Forward Client Metadata

#### User Agent
```adfs
c:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent"]
 => issue(claim = c);
```

#### Application ID
```adfs
c:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application"]
 => issue(claim = c);
```

#### Client IP Address
```adfs
c:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip"]
 => issue(claim = c);
```

### 🧾 Certificate-Based Authentication

#### Serial Number
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/serialnumber"]
 => issue(claim = c);
```

#### Issuer
```adfs
c:[Type == "http://schemas.microsoft.com/2012/12/certificatecontext/field/issuer"]
 => issue(claim = c);
```

### ⏳ Send Password Expiration Info
```adfs
c1:[Type == "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime"]
 => issue(store = "_PasswordExpiryStore", types = ("http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl"), query = "{0};", param = c1.Value);
```

**Source:** [TechNet ADFS Forum - Flatten Nested Groups](https://social.technet.microsoft.com/Forums/windowsserver/en-US/ca566e15-4b3b-4830-ae65-e25d83251c07/adfs-claim-to-flatten-groups-and-return-full-dn?forum=winserverDS)

---

## 🔒 14. Advanced MFA Policies in ADFS

**Purpose:**  
Demonstrates how to enforce Multi-Factor Authentication (MFA) in ADFS using different contextual claims like group membership, device registration, network location, and protocol endpoint.

### 🧑‍🤝‍🧑 Scenario 1: MFA for Specific Groups
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "<<Group SID>>"] 
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 📱 Scenario 2: MFA for Unregistered Devices
```adfs
c:[Type == "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");

NOT EXISTS([Type == "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser"])
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 🌐 Scenario 3: MFA for Extranet (External Network)
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 🔗 Scenario 4: Combine Device and Location (AND Logic)
```adfs
[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"] &&
[Type == "http://schemas.microsoft.com/2012/01/devicecontext/claims/isregistereduser", Value == "false"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 🧭 Scenario 5: MFA for Office 365 Based on Endpoint
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"] &&
c1:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value =~ "(/adfs/ls)|(/adfs/oauth2)"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 🚫 Scenario 6: Deny Access If MFA Was Not Performed
```adfs
NOT EXISTS([Type == "http://schemas.microsoft.com/claims/authnmethodsreferences", Value == "http://schemas.microsoft.com/claims/multipleauthn"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "DenyUsersWithClaim");
```

**Summary:**  
These examples leverage AD FS claim rules to enforce MFA policies using claims like `groupsid`, `isregistereduser`, `insidecorporatenetwork`, and `x-ms-endpoint-absolute-path`. The key mechanism to engage MFA is issuing the claim:
```adfs
Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
Value = "http://schemas.microsoft.com/claims/multipleauthn"
```

**Source:** [Ramiro Calderon - MFA in ADFS Blog](https://blogs.msdn.microsoft.com/ramical/2014/01/30/under-the-hood-tour-on-multi-factor-authentication-in-adfs-part-1-policy/)

---

## 🧪 15. MFA Rules: Exception Handling, Network Checks, and Method Filters

**Purpose:**  
These rules demonstrate advanced MFA conditions such as excluding specific client apps, skipping MFA for certain groups, validating MFA method used (e.g., phone or OTP), and bypassing MFA for known IPs.

### 🧾 Bypass MFA for Specific Client Applications (e.g., ActiveSync)
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"]) &&
NOT exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value == "Microsoft.Exchange.Autodiscover"]) &&
NOT exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-application", Value == "Microsoft.Exchange.ActiveSync"])
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 🧑‍🤝‍🧑 Do Not Trigger MFA for Specific Group
```adfs
exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2462332226-1795882094-2017209951-513"]) &&
NOT exists([Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-2462332226-1795882094-2017209951-363602"])
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

### 📞 Enforce MFA and Require Specific MFA Method (Phone Call or OTP)

#### 1. Allow Access if Internal:
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "true"]
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

#### 2. Trigger MFA:
```adfs
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

#### 3. Check MFA Method Used:
```adfs
NOT exists([Type == "http://schemas.microsoft.com/claims/authnmethodsreferences", Value == "http://schemas.microsoft.com/ws/2012/12/authmethod/phoneconfirmation"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");

NOT exists([Type == "http://schemas.microsoft.com/claims/authnmethodsreferences", Value == "http://schemas.microsoft.com/ws/2012/12/authmethod/otp"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/deny", Value = "true");
```

### 🌐 MFA Only from External Network Except Specific IP
```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-proxy"]) &&
NOT exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-forwarded-client-ip", Value =~ "\b156\.146\.63\.15\b"])
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

**Source:** [New Signature - Bypass MFA with ADFS](https://newsignature.com/articles/bypassing-multi-factor-authentication-using-ad-fs-claims-rule/)

---

## 🧱 16. Block All Except Modern Authentication

**Purpose:**  
This rule ensures that only requests using the modern authentication endpoint (typically `/adfs/ls/`) are permitted.

```adfs
exists([Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value =~ "^/adfs/ls/"])
 => issue(Type = "http://schemas.microsoft.com/authorization/claims/permit", Value = "true");
```

**Use Case:**  
Blocks legacy authentication protocols by only allowing WS-Federation requests via the `/adfs/ls/` passive endpoint.


---

## 🧩 17. Send UPN or ExtensionAttribute if UPN is Blank

**Purpose:**  
Fallback logic to populate the UPN claim: if the `extensionAttribute10` exists, use it as the UPN. If not, fallback to the real UPN from Active Directory.

### 1️⃣ Send ExtensionAttribute10 as UPN
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/claims/UPN"), query = ";extensionAttribute10;{0}", param = c.Value);
```

### 2️⃣ Get the real UPN from AD
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => add(store = "Active Directory", types = ("http://custom/RealUPN"), query = "samAccountName={0};userPrincipalName;{1}", param = regexreplace(c.Value, "(?<domain>[^\\]+)\\(?<user>.+)", "${user}"), param = c.Value);
```

### 3️⃣ Check Existence of ExtensionAttribute10 as UPN
```adfs
NOT EXISTS([Type == "http://schemas.xmlsoap.org/claims/UPN"])
 => add(Type = "http://custom/ExtensionAttribute/Existence", Value = "False");
```

### 4️⃣ Issue fallback Real UPN if extensionAttribute is missing
```adfs
c1:[Type == "http://custom/ExtensionAttribute/Existence"] &&
c2:[Type == "http://custom/RealUPN"]
 => issue(Type = "http://schemas.xmlsoap.org/claims/UPN", Value = c2.Value);
```


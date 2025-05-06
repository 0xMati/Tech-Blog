# 🎯 ADFS Claim Rules — Practical Examples

This document illustrates various claim issuance rules (Claim Rules) in an ADFS (Active Directory Federation Services) context. Each example includes its purpose, the full rule, and a brief explanation.

---

## 🛡️ 1. Send Linux Root Role if Admin

**Purpose:**  
Assign a specific `Root` role to a user who is a member of the Administrators group (SID `...-512`), typically for Linux systems.

**Rule:**
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "^(?i)S-1-5-21-2462332226-1795882094-2017209951-512$"]
 => issue(Type = "http://mathiasmotron.com/LinuxRole", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = "Root", ValueType = c.ValueType);
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
=> issue(store = "Internal WID", types = ("http://mathiasmotron.com/AdfsServerName"), query = "SELECT HOST_NAME() AS HostName");
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

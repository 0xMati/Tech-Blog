# 🎯 Implementing ADFS Claim Rules for Cross-Forest Group Membership  
🗓️ Published: 2025-05-06

In complex Active Directory environments, it's often necessary to retrieve group membership information for users in **trusted external forests**. This article outlines how to configure **Active Directory Federation Services (ADFS)** claim rules to pull group memberships (including nested groups) from a **trusted forest**, filter them, and issue them as role claims.

---

## 🛠 Prerequisites

Before setting up the claim rules, ensure the following:

1. The **ADFS service account** must have permission to read the `memberOf` attribute on `foreignSecurityPrincipal` objects in the trusted forest.  
   👉 [Grant access to read foreign group memberships (Microsoft TechNet)](https://social.technet.microsoft.com/Forums/windowsserver/en-US/bda33eb9-ff6e-4e79-967d-f5430ade7310/give-access-to-account-to-view-member-of-attribute-on-foreign-security-principal)

2. Replace the placeholders in the rules:
   - `TESTDOMAIN` → the NetBIOS name of the external trusted forest.
   - `Group-XX` → the prefix for your security groups of interest.  
     > Optional: remove `Value =~ "(?i)^Group-XX"` in Rule 5 if you want to issue all groups without filtering.

---

## 🧩 Step-by-Step: ADFS Claim Rules for TESTDOMAIN

The following claim rules form a pipeline that:
- Pulls the user’s object SID,
- Retrieves their nested group memberships,
- Cleans up the group names,
- Filters the relevant groups,
- Issues them as standard role claims.

### 🔹 Rule 1: Get the user’s SID
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Issuer == "AD AUTHORITY"]
 => add(store = "Active Directory", types = ("http://TESTDOMAIN/phase1"),
        query = "objectSid={0};distinguishedName;TESTDOMAIN\username", param = c.Value);
```

### 🔹 Rule 2: Resolve group membership recursively
```adfs
c:[Type == "http://TESTDOMAIN/phase1"]
 => add(store = "Active Directory", types = ("http://TESTDOMAIN/phase2"),
        query = "(member:1.2.840.113556.1.4.1941:={0});distinguishedName;TESTDOMAIN\username", param = c.Value);
```

### 🔹 Rule 3: Strip trailing data after the CN
```adfs
c:[Type == "http://TESTDOMAIN/phase2"]
 => add(Type = "http://TESTDOMAIN/phase3", Value = regexreplace(c.Value, ",[^
]*", ""));
```

### 🔹 Rule 4: Remove the "CN=" prefix
```adfs
c:[Type == "http://TESTDOMAIN/phase3"]
 => add(Type = "http://TESTDOMAIN/phase4", Value = regexreplace(c.Value, "^CN=", ""));
```

### 🔹 Rule 5: Issue groups as role claims (filtered by prefix)
```adfs
c:[Type == "http://TESTDOMAIN/phase4", Value =~ "(?i)^Group-XX"]
 => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
          Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = c.Value, ValueType = c.ValueType);
```

> 💡 You can customize the regex in Rule 5 or remove the condition to include all group claims.

---

## 🧪 Test Case: Querying Groups from Trusted Forest RED

To retrieve groups from a second trusted forest (e.g. `RED`) and issue them similarly, use the same logic with updated identifiers:

### 🔹 Phase 1: Get user SID
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://RED/phase1"),
          query = "objectSid={0};distinguishedName;RED\username", param = c.Value);
```

### 🔹 Phase 2: Resolve group memberships recursively
```adfs
c:[Type == "http://RED/phase1"]
 => issue(store = "Active Directory", types = ("http://RED/phase2"),
          query = "(member:1.2.840.113556.1.4.1941:={0});distinguishedName;RED\username", param = c.Value);
```

### 🔹 Phase 3: Clean up the DN
```adfs
c:[Type == "http://RED/phase2"]
 => issue(Type = "http://RED/phase3", Value = regexreplace(c.Value, ",[^
]*", ""));
```

### 🔹 Phase 4: Remove the "CN=" prefix
```adfs
c:[Type == "http://RED/phase3"]
 => issue(Type = "http://RED/phase4", Value = regexreplace(c.Value, "^CN=", ""));
```

### 🔹 Final Step: Issue as group claims
```adfs
c:[Type == "http://RED/phase4"]
 => issue(Type = "http://schemas.xmlsoap.org/claims/Group", Value = c.Value);
```

---

## 📚 Sources

- [GI Architects – ADFS Claim Rules for Groups and Cross Forest](http://www.gi-architects.co.uk/2016/09/adfs-claim-rules-for-groups-and-cross-forest/)
- [Microsoft TechNet – Grant Access to Read Foreign Group Membership](https://social.technet.microsoft.com/Forums/windowsserver/en-US/bda33eb9-ff6e-4e79-967d-f5430ade7310/give-access-to-account-to-view-member-of-attribute-on-foreign-security-principal)

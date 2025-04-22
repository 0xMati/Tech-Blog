---
title: "Tracking down a duplicate ObjectSid in MIM"
date: 2025-04-22
---

## 🧩 Tracking down a duplicate ObjectSid in MIM

Most people working with **Microsoft Identity Manager (MIM)** will be familiar with the dreaded _"Value Violates Uniqueness"_ errors during export via the **FIM MA** (Management Agent). When the conflict is with a simple string attribute like `AccountName`, it’s straightforward to track it down in the MIM Portal.

However, when the conflict is with a binary attribute like `ObjectSID`, things get trickier:

> **Attribute Failure Code**: `ValueViolatesUniqueness`  
> **Attribute Name**: `ObjectSID`

Searching for a **binary SID** value through the Portal or using XPath isn’t possible. So you’ll need to inspect the FIM Service **SQL database** directly.

---

## 🔍 Step-by-Step Resolution

### 1. Identify the SID
First, locate the **conflicting SID** in the **Pending Export** object of the **FIM MA Connector Space**. You’ll find it represented as a hex string (e.g. `01 05 00 00 ...`).

![](assets/Tracking%20duplicate%20ObjectSID/2025-04-22-15-45-36.png)

Strip out the spaces to get a clean string:

```
010500000000000515000000AD2CB2AE9F3EB92608ED3E3016C00500
```

---

### 2. Query the FIMService Database
Run the following SQL query against the **FIMService** database:

```sql
SELECT * 
FROM [FIMService].[fim].[ObjectValueString] s
JOIN [FIMService].[fim].[ObjectValueBinary] b
  ON s.ObjectKey = b.ObjectKey
WHERE CONVERT(VARCHAR(MAX), ValueBinary, 2) = '010500000000000515000000AD2CB2AE9F3EB92608ED3E3016C00500'
```

---

### 3. Analyze Results
The output of the query should reveal enough metadata to identify the conflicting object in the Portal or via PowerShell. You’ll be able to locate and remediate the issue by editing or removing the duplicate.

---

## 📝 Notes
- Direct database access should be done **with caution** and preferably in read-only scenarios.
- Always consider taking a backup before querying or modifying anything directly.

---

**Source**: https://www.wapshere.com/missmiis/tracking-down-a-duplicate-objectsid


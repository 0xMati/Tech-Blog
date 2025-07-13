# Understanding and Configuring Name Identifiers in SAML 2.0 with AD FS  
🗓️ Published: 2025-05-06

In SAML-based federation, the *Name Identifier* (NameID) is a critical element used by service providers (SPs) and identity providers (IdPs) to uniquely identify users across trust boundaries. This article explains the purpose of different NameID formats, how to configure AD FS 2.0 to request a specific NameID format during SAML 2.0 SSO, and how to issue persistent or transient NameIDs through claim rules.

---

## What is a Name Identifier?

A Name Identifier (NameID) is a string that represents a user in a federated environment. It's used by the SP and IdP to refer to the same subject across SSO sessions, logout requests, or attribute exchanges.

Common formats include:

| Format URI | Description |
|------------|-------------|
| `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | Default, flexible format. |
| `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | Email address format. |
| `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | Persistent pseudonymous identifier. |
| `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` | Session-scoped ephemeral identifier. |

> 🔗 [StackOverflow: What are the different NameID formats used for?](http://stackoverflow.com/questions/11693297/what-are-the-different-nameid-format-used-for)

---

## Requesting a Specific NameID Format in AD FS 2.0

AD FS 2.0 allows you to define a preferred NameID format to request from a claims provider (CP) via the `NameIDPolicy` element in the SAML `AuthnRequest`.

### Configuration Steps

1. Identify the required `NameIDPolicy` Format URI.
2. Open a PowerShell session as Administrator on the AD FS server.
3. Run the following commands:
```powershell
Add-PsSnapin Microsoft.Adfs.Powershell
Set-AdfsClaimsProviderTrust -TargetName "Contoso CP Trust" `
  -RequiredNameIDFormat "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
```

This configuration causes AD FS to generate the following SAML snippet during authentication:
```xml
<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true" />
```

> 🔗 [Microsoft Technet Article](https://social.technet.microsoft.com/wiki/contents/articles/4038.ad-fs-2-0-how-to-request-a-specific-name-id-format-from-a-claims-provider-cp-during-saml-2-0-single-sign-on-sso.aspx)

---

## Issuing Persistent and Transient Name Identifiers in AD FS

In AD FS 2.0, the NameID is simply another claim. You can use custom issuance rules to generate and transform persistent or transient NameIDs.

### Persistent Name Identifier

Used to issue a consistent, pseudonymous identifier across sessions and relying parties.

#### Step 1: Generate the persistent ID
```csharp
c:[type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"]
 => add(store = "_OpaqueIdStore",
        types = ("http://mycompany/internal/persistentId"),
        query = "{0};{1};{2}",
        param = "ppid",
        param = c.Value,
        param = c.OriginalIssuer);
```

#### Step 2: Transform into Name Identifier
Use the built-in transformation rule to map `persistentId` to a `NameID` claim with the `persistent` format.

![](assets/How%20to%20Request%20a%20Specific%20Name%20ID%20Format%20from%20a%20Claims%20Provider%20During%20SAML%202.0%20SSO/2025-05-06-14-10-21.png)

---

### Transient Name Identifier

Used for per-session identifiers that change on each login.

#### Step 1: Generate the session ID
```csharp
c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"] &&
c2:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant"]
 => add(store = "_OpaqueIdStore",
        types = ("http://mycompany/internal/sessionid"),
        query = "{0};{1};{2};{3};{4}",
        param = "useEntropy",
        param = c1.Value,
        param = c1.OriginalIssuer,
        param = "",
        param = c2.Value);
```

#### Step 2: Transform into transient Name Identifier
Map the `sessionid` claim to a NameID with the `transient` format, similar to the persistent example.

![](assets/How%20to%20Request%20a%20Specific%20Name%20ID%20Format%20from%20a%20Claims%20Provider%20During%20SAML%202.0%20SSO/2025-05-06-14-10-41.png)


> 🔗 [Microsoft Identity Blog: Name Identifiers in SAML Assertions](https://learn.microsoft.com/en-us/archive/blogs/card/name-identifiers-in-saml-assertions)

---

## ✅ Summary

| NameID Format | Scope | Use Case |
|---------------|-------|----------|
| Unspecified | Flexible | General use, least strict |
| Email | Global | Used when the user's email is their primary ID |
| Persistent | Cross-session | Long-term pseudonymous identity |
| Transient | Per-session | Anonymous sessions, logout support |

AD FS gives you full control over what kind of NameID to issue or request — giving flexibility to comply with partner requirements or privacy regulations.

---

## 📚 References

- [AD FS 2.0 - Name ID Format with CP Trust (Technet)](https://social.technet.microsoft.com/wiki/contents/articles/4038.ad-fs-2-0-how-to-request-a-specific-name-id-format-from-a-claims-provider-cp-during-saml-2-0-single-sign-on-sso.aspx)
- [StackOverflow – NameID Format Overview](http://stackoverflow.com/questions/11693297/what-are-the-different-nameid-format-used-for)
- [Microsoft Blog – Name Identifiers in SAML Assertions](https://learn.microsoft.com/en-us/archive/blogs/card/name-identifiers-in-saml-assertions)

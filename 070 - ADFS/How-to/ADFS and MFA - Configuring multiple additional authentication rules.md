
# AD FS and MFA – Configuring Multiple Additional Authentication Rules
🗓️ Published: 2025-05-06

Ever since Microsoft bought PhoneFactor, they have been heavily investing in incorporating it into different products, both on-prem and in the cloud.
We have no intention of slowing down - ADFS has now 'native' integration with Azure MFA, eliminating the need to deploy the on-prem MFA server for organizations that sync to Azure AD.
Apart from that, additional improvements have been made on how the authentication process works, with the switch to Modern authentication and the introduction of Access control policies for AD FS.
Even with AD FS 3.0, it's just a matter of a few simple clicks to set up AD FS to require MFA only when accessing resources from outside of the corporate network, and things get even better.
So, there is no more need to play with those pesky claims rules?

## Claims Rules in Older Versions of AD FS
For those that will stick to an older version of AD FS, and for people who want even more customization, the claims rules are here to stay. In this post, I will briefly discuss how we can configure multiple additional authentication rules to achieve different MFA behaviors based on the device or client used, the location of the user, or any other information presented as a claim.

The **AdditionalAuthenticationRules** were introduced with AD FS 3.0, using the familiar claims rules syntax. These rules can be applied globally or per specific Relying Party trust. As the name suggests, they execute after the initial authentication takes place. This process is described in detail in this excellent post by Ramiro Calderon.

## Overview of Additional Authentication Rules
Essentially, the additional authentication rules work similarly to 'regular' claims rules, and we can use any claim about the user/device with them. These claims could include UPN, group membership, user-agent string, IP address, protocol, etc. Multiple rules can be enforced, but we will have to rely on PowerShell for most scenarios.  

When using the GUI to configure the additional authentication rules, a new rule is created for each of the selected conditions, resulting in an OR configuration. For example, enabling a rule might result in something like this:

```powershell
PS C:\> (Get-AdfsRelyingPartyTrust "O365").AdditionalAuthenticationRules
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-1315440946-3826617302-920981253-512"]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");
```

## Using PowerShell for Custom Authentication Rules
If we want to combine multiple criteria into a single rule, PowerShell stores rules as strings, each representing a separate rule. For example, extracting rules can be done as follows:

```powershell
PS C:\> $rules = (Get-AdfsRelyingPartyTrust "O365").AdditionalAuthenticationRules -split "`r`n`r`n"
PS C:\> $rules[0]
```

To change the rules, PowerShell is not the best tool for text editing, so it's recommended to use a proper editor for this. Once changes are decided, PowerShell will be needed to set or update the rules.

## Example: Enforcing MFA for Specific Browsers
For a scenario where we want to force MFA for Chrome and Opera on requests coming outside the corporate network, we would configure a rule as follows:

```powershell
'c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"]
&& c1:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent", Value =~ "(Opera)|(Chrome)"]
&& c2:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value =~ "(/adfs/ls)|(/adfs/oauth2)"]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");'
```

## Applying the Rules via PowerShell
Once we have decided on the rule, we can apply it using PowerShell:

```powershell
PS C:\> Set-AdfsRelyingPartyTrust -TargetName "O365" -AdditionalAuthenticationRules 'c:[Type == "http://schemas.microsoft.com/ws/2012/01/insidecorporatenetwork", Value == "false"] && c1:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-client-user-agent", Value =~ "(Opera)|(Chrome)"] && c2:[Type == "http://schemas.microsoft.com/2012/01/requestcontext/claims/x-ms-endpoint-absolute-path", Value =~ "(/adfs/ls)|(/adfs/oauth2)"] => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");'
```

## Enforcing MFA for Specific Users or Groups
Next, we may want a specific user or a group (e.g., "Gosho") to always be subjected to MFA, regardless of other conditions. This rule would look like:

```powershell
'c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "(?i)gosho@sts.michev.info"]
&& c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-1315440946-3826617302-920981253-512"]
=> issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");'
```

## Combining Old and New Rules
To append the new rule to the existing set of rules, we store the old rules in a variable and then combine them:

```powershell
PS C:\> $old = (Get-AdfsRelyingPartyTrust "O365").AdditionalAuthenticationRules
PS C:\> $new = $old + 'c:[Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", Value =~ "(?i)gosho@sts.michev.info"] && c1:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value == "S-1-5-21-1315440946-3826617302-920981253-512"] => issue(Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod", Value = "http://schemas.microsoft.com/claims/multipleauthn");'
```

## Finalizing and Applying the Rules
Finally, the new set of rules is prepared and applied:

```powershell
PS C:\> $newset = New-AdfsClaimRuleSet -ClaimRule $new
PS C:\> Set-AdfsRelyingPartyTrust -TargetName "O365" -AdditionalAuthenticationRules $newset.ClaimRulesString
```

## Backup and Restore
Before making any changes, it's always a good idea to back up the current rules:

```powershell
PS C:\> (Get-AdfsRelyingPartyTrust "O365").AdditionalAuthenticationRules | Out-File "C:\Users\vasil\Desktop\AAR.txt"
```

To restore from a backup:

```powershell
PS C:\> Set-AdfsRelyingPartyTrust -TargetName "Device Registration Service" -AdditionalAuthenticationRulesFile "C:\Users\vasil\Desktop\AAR.txt"
```

## Recap of the Steps to Configure Multiple Additional Authentication Rules
To summarize, here are the steps needed:

1. **Save the existing rules to a variable**  
   ```powershell
   $old = (Get-AdfsRelyingPartyTrust "O365").AdditionalAuthenticationRules
   ```

2. **Append new rules to the variable**  
   ```powershell
   $new = $old + 'new claims rule goes here'
   ```

3. **Prepare the new set of rules**  
   ```powershell
   $newset = New-AdfsClaimRuleSet -ClaimRule $new
   ```

4. **Set the new rules**  
   ```powershell
   Set-AdfsRelyingPartyTrust -TargetName "O365" -AdditionalAuthenticationRules $newset.ClaimRulesString
   ```

And, of course, don't forget to back up your rules before making changes!  


***Source*** : https://www.michev.info/Blog/Post/1393/ad-fs-and-mfa-configuring-multiple-additional-authentication-rules


# Common\Finding.ps1
# MATI - Microsoft Active Directory Threat Inspector
# Standard finding object for all MATI modules

function New-Finding {
    param(
        [string]$Id,           # e.g. MATI-ADMIN-001
        [string]$Category,     # e.g. PrivilegedAccounts, Kerberos, ACLs, ADCS...
        [string]$Severity,     # Low / Medium / High / Critical
        [string]$Title,        # Short human-readable title
        [string]$Description,  # Explanation of the issue
        [string]$Remediation,  # Recommended remediation action
        [string]$ObjectDN,     # DN of the main AD object concerned
        [string]$Domain,       # DNS domain name (e.g. corp.contoso.com)
        [string]$Source,       # Module/script name (e.g. 20-MATI-PrivilegedAccounts)
        [string]$Details       # Free text: key=value; key2=value2; ...
    )

    [PSCustomObject]@{
        Id          = $Id
        Category    = $Category
        Severity    = $Severity
        Title       = $Title
        Description = $Description
        Remediation = $Remediation
        ObjectDN    = $ObjectDN
        Domain      = $Domain
        Source      = $Source
        Details     = $Details
    }
}

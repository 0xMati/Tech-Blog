# Rules\ACL\DCSyncRights.rule.ps1
# Flags non-privileged accounts with DCSync rights.

@{
    Id          = 'MATI-ACL-002'
    Title       = 'DCSync rights granted to non-privileged principal'
    Severity    = 'Critical'
    Description = "A non-default principal has both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All permissions on a domain root. This combination allows the principal to replicate all password hashes from the domain (DCSync attack)."
    Remediation = "Remove the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All extended rights from the non-privileged principal on the domain root object."
    Collectors  = @('ACLInfo')
    References  = @('https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($entry in $Data.ACLInfo.DCSyncRights) {
            $findings += @{
                ObjectDN = $entry.TargetDN
                Domain   = $entry.Domain
                Details  = @{
                    IdentityReference = $entry.IdentityRef
                    IdentitySID       = $entry.IdentitySID
                    Right             = 'DCSync (Get-Changes + Get-Changes-All)'
                }
            }
        }
        return $findings
    }
}

# Rules\Hardening\DenyUnauthenticatedBind.rule.ps1
# Flags when DenyUnauthenticatedBind is not enabled on the Directory Service object.

@{
    Id          = 'MATI-HARD-026'
    Title       = 'Anonymous LDAP bind not denied (DenyUnauthenticatedBind)'
    Severity    = 'Medium'
    Description = "The DenyUnauthenticatedBind=1 setting is not configured on the Directory Service object. Anonymous LDAP clients can still query RootDSE without authentication, exposing AD metadata (naming contexts, LDAP capabilities, GC readiness)."
    Remediation = "Set DenyUnauthenticatedBind=1 in the msDS-Other-Settings attribute on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration. This blocks all anonymous LDAP operations including RootDSE lookups. Test for legacy LDAP clients that rely on anonymous discovery before enabling."
    Collectors  = @('SecurityConfig')
    References  = @('PingCastle: A-DenyUnauthenticatedBind', 'Blog: DenyUnauthenticatedBind Hardening in Active Directory')
    Condition   = {
        param($Data, $Config)
        $findings = @()

        $value = $Data.SecurityConfig.DenyUnauthenticatedBind
        if ($value -ne '1') {
            $findings += @{
                ObjectDN = 'CN=Directory Service,CN=Windows NT,CN=Services'
                Domain   = (Get-ADForest -ErrorAction SilentlyContinue).RootDomain
                Details  = @{
                    CurrentValue = if ($null -eq $value) { '(not configured)' } else { "DenyUnauthenticatedBind=$value" }
                    Expected     = 'DenyUnauthenticatedBind=1'
                }
            }
        }
        return $findings
    }
}

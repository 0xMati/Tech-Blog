# Rules\Hardening\DangerousDisplaySpecifiers.rule.ps1
# ORADAD: vuln_display_specifier
# Flags Display Specifiers with executable/script references.

@{
    Id          = 'MATI-HARD-039'
    Title       = 'Dangerous Display Specifier detected'
    Severity    = 'Critical'
    Description = "A Display Specifier object in the Configuration partition contains a reference to an executable, script, or UNC path in a context menu attribute (adminContextMenu, contextMenu, shellContextMenu). Display Specifiers control the context menus shown in AD management tools (ADUC, ADSI Edit). An attacker who modifies Display Specifiers can inject arbitrary code execution that triggers when an administrator right-clicks an object — this is a highly stealthy persistence mechanism."
    Remediation = "Immediately investigate the affected Display Specifier object. Remove any suspicious executable or script references from adminContextMenu, contextMenu, and shellContextMenu attributes. Audit who modified these objects (check replication metadata). Restore from a known-good backup if compromise is confirmed."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://learn.microsoft.com/en-us/windows/win32/ad/display-specifiers'
        'https://www.anssi.fr/uploads/2025/01/ad_checklist-v2.0.2.html'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()

        foreach ($spec in $Data.SecurityConfig.DangerousDisplaySpecifiers) {
            $findings += @{
                ObjectDN = $spec.DistinguishedName
                Domain   = 'Configuration'
                Details  = @{
                    Attribute = $spec.Attribute
                    Value     = $spec.Value
                    Risk      = 'Executable or script reference in Display Specifier context menu'
                }
            }
        }
        return $findings
    }
}

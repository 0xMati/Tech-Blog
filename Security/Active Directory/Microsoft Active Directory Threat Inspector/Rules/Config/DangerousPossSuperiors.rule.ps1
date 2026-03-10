# Rules\Config\DangerousPossSuperiors.rule.ps1
# Flags dangerous schema possSuperiors allowing object creation in unexpected places. [PingCastle: S-ADRegistrationSchema]

@{
    Id          = 'MATI-CONFIG-032'
    Title       = 'Dangerous schema possSuperiors allowing computer creation'
    Severity    = 'Medium'
    Description = "The AD schema has been modified to allow computer objects to be created as children of unexpected container types (beyond organizationalUnit, container, domainDNS, builtinDomain). This can be exploited to create rogue computer objects in locations where they bypass security policies."
    Remediation = "Review and remove the unexpected possSuperiors entries from the 'computer' schema class. Use Schema Manager (schmmgmt.msc) or ADSI Edit to verify the allowed parent classes."
    Collectors  = @('SecurityConfig')
    References  = @('https://learn.microsoft.com/en-us/windows/win32/ad/characteristics-of-attributes')
    Condition   = {
        param($Data, $Config)
        $findings = @()
        foreach ($risk in $Data.SecurityConfig.SchemaClassRisks) {
            $findings += @{
                ObjectDN = "CN=$($risk.ClassName),<Schema>"
                Domain   = 'Forest'
                Details  = @{
                    ClassName    = $risk.ClassName
                    PossSuperior = $risk.PossSuperior
                    Risk         = $risk.Risk
                }
            }
        }
        return $findings
    }
}

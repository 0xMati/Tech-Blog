# Rules\Config\JavaSchemaExtension.rule.ps1
# Flags presence of Java schema extension RFC 2713. [PingCastle: S-JavaSchema]

@{
    Id          = 'MATI-CONFIG-030'
    Title       = 'Java schema extension (RFC 2713) detected'
    Severity    = 'Medium'
    Description = "The Java schema extension (javaSerializedObject class from RFC 2713) is present in the AD schema. This extension allows storing serialized Java objects in LDAP. Attackers can exploit this to inject malicious serialized objects that execute arbitrary code when deserialized by Java applications (JNDI injection attacks)."
    Remediation = "If no Java/JNDI application uses Active Directory as a naming provider, consider deactivating the schema class. Monitor for objects of class javaSerializedObject in the directory."
    Collectors  = @('SecurityConfig')
    References  = @(
        'https://www.blackhat.com/docs/us-16/materials/us-16-Munoz-A-Journey-From-JNDI-LDAP-Manipulation-To-RCE.pdf'
        'https://tools.ietf.org/html/rfc2713'
    )
    Condition   = {
        param($Data, $Config)
        $findings = @()
        if ($Data.SecurityConfig.JavaSchemaDetected) {
            $findings += @{
                ObjectDN = 'CN=javaSerializedObject,<Schema>'
                Domain   = 'Forest'
                Details  = @{
                    SchemaClass = 'javaSerializedObject'
                    Issue       = 'Java schema extension RFC 2713 present — potential JNDI injection vector'
                }
            }
        }
        return $findings
    }
}

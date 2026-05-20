<#
.SYNOPSIS
    Generates a unique Object Identifier (OID) under the Microsoft-issued
    base prefix for extending the Active Directory schema (new attributes
    or new object classes).

.DESCRIPTION
    Builds an OID derived from a freshly generated GUID, prefixed with the
    Microsoft non-registered OID arc `1.2.840.113556.1.8000.2554`.

    Use this OID when defining `attributeID` or `governsID` values for
    custom schema extensions. The OID is statistically unique and avoids
    collisions with Microsoft and third-party schemas.

.NOTES
    Source: Microsoft Learn — "Obtain or generate an OID for your AD
    schema extensions"
    https://learn.microsoft.com/en-us/windows/win32/ad/obtaining-an-object-identifier-from-microsoft

.EXAMPLE
    PS> .\GenerateOID.ps1
    1.2.840.113556.1.8000.2554.45123.55001.39842.10923.20011.501234.871123
#>

 $Prefix="1.2.840.113556.1.8000.2554" 
 $GUID=[System.Guid]::NewGuid().ToString() 
 $Parts=@() 
 $Parts+=[UInt64]::Parse($guid.SubString(0,4),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(4,4),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(9,4),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(14,4),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(19,4),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(24,6),"AllowHexSpecifier") 
 $Parts+=[UInt64]::Parse($guid.SubString(30,6),"AllowHexSpecifier") 
 $OID=[String]::Format("{0}.{1}.{2}.{3}.{4}.{5}.{6}.{7}",$prefix,$Parts[0],$Parts[1],$Parts[2],$Parts[3],$Parts[4],$Parts[5],$Parts[6]) 
 $oid
# Collectors\Get-MATICertificateServices.ps1
# MATIv2 - Collects AD Certificate Services (ADCS) configuration from AD.

function Get-MATICertificateServices {
    <#
    .SYNOPSIS
        Reads ADCS configuration from the Configuration partition:
        enrollment services, certificate templates, and their permissions.
    .OUTPUTS
        [hashtable] with keys: EnrollmentServices, Templates, IsADCSDeployed
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $forest = $Config['_ForestCache'] ?? (Get-ADForest -ErrorAction Stop)
    $directoryServer = $Config['_DirectoryServer'] ?? $forest.RootDomain
    $rootDSE  = $Config['_RootDSECache'] ?? (Get-ADRootDSE -Server $directoryServer -ErrorAction Stop)
    $configDN = $rootDSE.configurationNamingContext
    $pkiDN    = "CN=Public Key Services,CN=Services,$configDN"

    # Check if ADCS is deployed
    $isDeployed = $false
    try {
        $null = Get-ADObject -Identity $pkiDN -Server $directoryServer -ErrorAction Stop
        $isDeployed = $true
    } catch {
        Write-Verbose "    ADCS Public Key Services container not found."
        return @{
            EnrollmentServices = @()
            Templates          = @()
            IsADCSDeployed     = $false
        }
    }

    # ---- Enrollment Services (CAs) ----
    $enrollmentServices = @()
    try {
        $esDN = "CN=Enrollment Services,$pkiDN"
        $cas = Get-ADObject -SearchBase $esDN -Filter { objectClass -eq 'pKIEnrollmentService' } `
            -Server $directoryServer `
            -Properties dNSHostName, cACertificate, certificateTemplates, 'msPKI-Enrollment-Servers' `
            -ErrorAction Stop

        foreach ($ca in $cas) {
            # Parse certificate for algorithm info
            $certAlgo = 'Unknown'
            $certKeyLength = 0
            $certExpiry = $null
            if ($ca.cACertificate) {
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ca.cACertificate[0])
                    $certAlgo = $cert.SignatureAlgorithm.FriendlyName
                    $certKeyLength = $cert.PublicKey.Key.KeySize
                    $certExpiry = $cert.NotAfter
                } catch { }
            }

            # Check for HTTP enrollment endpoints
            $hasHttpEnrollment = $false
            $enrollServers = $ca.'msPKI-Enrollment-Servers'
            if ($enrollServers) {
                foreach ($es in $enrollServers) {
                    if ($es -match 'http://') { $hasHttpEnrollment = $true }
                }
            }

            $enrollmentServices += [PSCustomObject]@{
                Name              = $ca.Name
                DNSHostName       = $ca.dNSHostName
                DistinguishedName = $ca.DistinguishedName
                Domain            = 'Forest'
                CertAlgorithm     = $certAlgo
                CertKeyLength     = $certKeyLength
                CertExpiry        = $certExpiry
                Templates         = @($ca.certificateTemplates)
                HasHttpEnrollment = $hasHttpEnrollment
            }
        }
    } catch {
        Write-Warning "    Cannot read Enrollment Services: $($_.Exception.Message)"
    }

    # ---- Certificate Templates ----
    $templates = @()
    try {
        $templatesDN = "CN=Certificate Templates,$pkiDN"
        $tmplObjects = Get-ADObject -SearchBase $templatesDN -Filter { objectClass -eq 'pKICertificateTemplate' } `
            -Server $directoryServer `
            -Properties * -ErrorAction Stop

        # Well-known SIDs
        $privilegedSIDs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($domainDns in $forest.Domains) {
            try {
                $domSID = Get-MATIDomainSidString (($Config['_DomainCache'][$domainDns] ?? (Get-ADDomain -Server $domainDns -ErrorAction Stop)).DomainSID)
                if (-not $domSID) { continue }
                $null = $privilegedSIDs.Add("$domSID-512")  # Domain Admins
                $null = $privilegedSIDs.Add("$domSID-519")  # Enterprise Admins
            } catch { }
        }
        $null = $privilegedSIDs.Add('S-1-5-32-544')  # Administrators
        $null = $privilegedSIDs.Add('S-1-5-18')       # SYSTEM

        foreach ($tmpl in $tmplObjects) {
            # msPKI-Certificate-Name-Flag: 1 = ENROLLEE_SUPPLIES_SUBJECT
            $enrolleeSuppliesSubject = ($tmpl.'msPKI-Certificate-Name-Flag' -band 1) -ne 0

            # msPKI-Enrollment-Flag
            $enrollmentFlag = $tmpl.'msPKI-Enrollment-Flag'
            $noSecurityExtension = ($enrollmentFlag -band 0x80000) -ne 0

            # Check if template enables client authentication (EKU)
            $ekuOIDs = @($tmpl.'pKIExtendedKeyUsage')
            $isAuthTemplate = ($ekuOIDs.Count -eq 0) -or  # No EKU = any purpose
                              ($ekuOIDs -contains '1.3.6.1.5.5.7.3.2') -or  # Client Auth
                              ($ekuOIDs -contains '1.3.6.1.5.2.3.4') -or    # PKINIT Client Auth
                              ($ekuOIDs -contains '1.3.6.1.4.1.311.20.2.2') -or # Smart Card Logon
                              ($ekuOIDs -contains '2.5.29.37.0')             # Any Purpose

            # ESC2: Any Purpose or no EKU (SubCA)
            $isAnyPurpose = ($ekuOIDs.Count -eq 0) -or ($ekuOIDs -contains '2.5.29.37.0')

            # ESC3: Certificate Request Agent (enrollment agent)
            $isCertRequestAgent = ($ekuOIDs -contains '1.3.6.1.4.1.311.20.2.1')  # Certificate Request Agent OID

            # Check ACL for enrollment rights by low-priv groups
            $lowPrivEnrollment = $false
            $lowPrivFullControl = $false
            try {
                $acl = Get-MATIObjectAcl -DistinguishedName $tmpl.DistinguishedName -Server $directoryServer
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $sidStr = try {
                        $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch { $ace.IdentityReference.ToString() }

                    # Skip privileged principals
                    if ($privilegedSIDs.Contains($sidStr)) { continue }

                    $rights = $ace.ActiveDirectoryRights.ToString()
                    # Check for Enroll / AutoEnroll (ExtendedRight with specific GUIDs)
                    if ($rights -match 'ExtendedRight') {
                        $objType = $ace.ObjectType.ToString().ToLower()
                        # Certificate-Enrollment = 0e10c968-78fb-11d2-90d4-00c04f79dc55
                        # Certificate-AutoEnrollment = a05b8cc2-17bc-4802-a710-e7c15ab866a2
                        if ($objType -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55' -or
                            $objType -eq 'a05b8cc2-17bc-4802-a710-e7c15ab866a2' -or
                            $objType -eq '00000000-0000-0000-0000-000000000000') {

                            # Check if it's a well-known broad group
                            if ($sidStr -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-7') -or
                                $sidStr -match '-513$' -or   # Domain Users
                                $sidStr -match '-515$') {    # Domain Computers
                                $lowPrivEnrollment = $true
                            }
                        }
                    }
                    if ($rights -match 'GenericAll|WriteDacl|WriteOwner') {
                        if ($sidStr -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-7') -or
                            $sidStr -match '-513$' -or $sidStr -match '-515$') {
                            $lowPrivFullControl = $true
                        }
                    }
                }
            } catch { }

            # Published on at least one CA?
            $publishedOnCAs = @()
            foreach ($es in $enrollmentServices) {
                if ($tmpl.Name -in $es.Templates) {
                    $publishedOnCAs += $es.Name
                }
            }

            $templates += [PSCustomObject]@{
                Name                     = $tmpl.Name
                DisplayName              = $tmpl.DisplayName
                DistinguishedName        = $tmpl.DistinguishedName
                Domain                   = 'Forest'
                EnrolleeSuppliesSubject  = $enrolleeSuppliesSubject
                IsAuthTemplate           = $isAuthTemplate
                IsAnyPurpose             = $isAnyPurpose
                IsCertRequestAgent       = $isCertRequestAgent
                EKUs                     = $ekuOIDs
                LowPrivEnrollment        = $lowPrivEnrollment
                LowPrivFullControl       = $lowPrivFullControl
                PublishedOnCAs           = @($publishedOnCAs)
                IsPublished              = ($publishedOnCAs.Count -gt 0)
                ManagerApproval          = ($enrollmentFlag -band 2) -ne 0  # CT_FLAG_PEND_ALL_REQUESTS
                AuthorizedSignatures     = $tmpl.'msPKI-RA-Signature'
                EnrollmentFlags          = $enrollmentFlag
                NoSecurityExtension      = $noSecurityExtension
            }
        }
    } catch {
        Write-Warning "    Cannot read Certificate Templates: $($_.Exception.Message)"
    }

    # ---- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag on CAs ----
    # ---- ESC7: ManageCA ACL for low-priv principals ----
    # ---- CA cert expiration ----
    $caSecurityInfo = @()
    foreach ($ca in $enrollmentServices) {
        try {
            $editfFlag = $null  # null = unknown (cannot read remotely)
            if ($ca.DNSHostName) {
                try {
                    $regVal = Invoke-Command -ComputerName $ca.DNSHostName -ScriptBlock {
                        try {
                            $val = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\*' `
                                -Name 'EditFlags' -ErrorAction Stop
                            return $val.EditFlags
                        } catch { return $null }
                    } -ErrorAction Stop
                    if ($null -ne $regVal) {
                        $editfFlag = ($regVal -band 0x00040000) -ne 0
                    }
                } catch { }
            }

            # ESC7: Check CA AD object ACL for ManageCA rights by low-priv principals
            $lowPrivManageCA = $false
            try {
                $acl = Get-MATIObjectAcl -DistinguishedName $ca.DistinguishedName -Server $directoryServer
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -ne 'Allow') { continue }
                    $sidStr = try {
                        $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    } catch { $ace.IdentityReference.ToString() }
                    if ($privilegedSIDs.Contains($sidStr)) { continue }
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    if ($rights -match 'GenericAll|WriteDacl|WriteOwner') {
                        if ($sidStr -in @('S-1-1-0', 'S-1-5-11', 'S-1-5-7') -or
                            $sidStr -match '-513$' -or $sidStr -match '-515$') {
                            $lowPrivManageCA = $true
                        }
                    }
                }
            } catch { }

            $caSecurityInfo += [PSCustomObject]@{
                CAName             = $ca.Name
                DNSHostName        = $ca.DNSHostName
                EditfSANEnabled    = $editfFlag
                LowPrivManageCA    = $lowPrivManageCA
                CertExpiry         = $ca.CertExpiry
                CertExpiresInDays  = if ($ca.CertExpiry) {
                    [math]::Round(($ca.CertExpiry - (Get-Date)).TotalDays)
                } else { $null }
            }
        } catch { }
    }

    return @{
        EnrollmentServices = @($enrollmentServices)
        Templates          = @($templates)
        IsADCSDeployed     = $isDeployed
        CASecurityInfo     = @($caSecurityInfo)
    }
}

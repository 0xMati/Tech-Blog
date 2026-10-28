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
        if ($_.Exception.GetType().Name -ne 'ADIdentityNotFoundException') {
            throw "Cannot determine AD CS deployment: $($_.Exception.Message)"
        }
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
                } catch {
                    Write-Warning "Cannot decode CA certificate for $($ca.Name): $($_.Exception.Message)"
                }
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
            } catch {
                Write-Warning "Cannot resolve privileged CA principals in ${domainDns}: $($_.Exception.Message)"
            }
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
            } catch {
                Write-Warning "Cannot read template ACL for $($tmpl.DistinguishedName): $($_.Exception.Message)"
            }

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
    $collectionErrors = [System.Collections.Generic.List[object]]::new()
    foreach ($ca in $enrollmentServices) {
        $editfFlag = $null
        $lowPrivManageCA = $null
        $managementACEs = @()
        try {
            if (-not $ca.DNSHostName) { throw 'CA host name is missing.' }
            $remote = Invoke-Command -ComputerName $ca.DNSHostName -ArgumentList $ca.Name -ErrorAction Stop -ScriptBlock {
                param([string]$CAName)
                $caPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAName"
                $result = @{ EditFlags = $null; SecurityRead = $false; ManagementACEs = @(); Errors = @() }
                try {
                    $policyPath = "$caPath\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
                    $result.EditFlags = (Get-ItemProperty -LiteralPath $policyPath -Name EditFlags -ErrorAction Stop).EditFlags
                } catch { $result.Errors += "CA policy: $($_.Exception.Message)" }
                try {
                    $bytes = (Get-ItemProperty -LiteralPath $caPath -Name Security -ErrorAction Stop).Security
                    $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new([byte[]]$bytes, 0)
                    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'CA has a null DACL; explicit review is required.' }
                    $denied = @{}
                    # Windows PowerShell 5.1 requires integer operands for these enum flags.
                    foreach ($ace in $descriptor.DiscretionaryAcl) {
                        if ($ace -isnot [System.Security.AccessControl.QualifiedAce] -or
                            ([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
                        $sid = $ace.SecurityIdentifier.Value
                        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) {
                            $denied[$sid] = [int]$denied[$sid] -bor $ace.AccessMask
                        }
                    }
                    foreach ($ace in $descriptor.DiscretionaryAcl) {
                        if ($ace -isnot [System.Security.AccessControl.QualifiedAce] -or
                            $ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed -or
                            ([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
                        $sid = $ace.SecurityIdentifier.Value
                        $mask = $ace.AccessMask -band (-bnot [int]$denied[$sid])
                        if (($mask -band 3) -eq 0) { continue }
                        if ($sid -notin @('S-1-1-0', 'S-1-5-11', 'S-1-5-7') -and $sid -notmatch '^S-1-5-21-.+-(513|515)$') { continue }
                        $result.ManagementACEs += [pscustomobject]@{
                            SID = $sid
                            ManageCA = ($mask -band 1) -ne 0
                            ManageCertificates = ($mask -band 2) -ne 0
                        }
                    }
                    $result.SecurityRead = $true
                } catch { $result.Errors += "CA security descriptor: $($_.Exception.Message)" }
                $result
            }
            if ($null -ne $remote.EditFlags) { $editfFlag = ($remote.EditFlags -band 0x00040000) -ne 0 }
            if ($remote.SecurityRead) {
                $managementACEs = @($remote.ManagementACEs)
                $lowPrivManageCA = $managementACEs.Count -gt 0
            }
            foreach ($message in $remote.Errors) {
                $collectionErrors.Add([pscustomobject]@{ Domain = 'Forest'; DC = $ca.DNSHostName; Error = $message })
            }
        } catch {
            $collectionErrors.Add([pscustomobject]@{ Domain = 'Forest'; DC = $ca.DNSHostName; Error = $_.Exception.Message })
        }
        $caSecurityInfo += [PSCustomObject]@{
            CAName             = $ca.Name
            DNSHostName        = $ca.DNSHostName
            EditfSANEnabled    = $editfFlag
            LowPrivManageCA    = $lowPrivManageCA
            ManagementACEs     = $managementACEs
            CertExpiry         = $ca.CertExpiry
            CertExpiresInDays  = if ($ca.CertExpiry) {
                [math]::Round(($ca.CertExpiry - (Get-Date)).TotalDays)
            } else { $null }
        }
    }

    return @{
        EnrollmentServices = @($enrollmentServices)
        Templates          = @($templates)
        IsADCSDeployed     = $isDeployed
        CASecurityInfo     = @($caSecurityInfo)
        Errors             = @($collectionErrors)
    }
}

<#############################################################
 #  Copyright (c) Microsoft Corporation.  All rights reserved.
 ############################################################>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="High", DefaultParameterSetName="Default")]
Param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelinebyPropertyName=$true)]
    [string] $Path,
    
    [Parameter(Mandatory=$false)]
    [string] $ComputerName,

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential] $Credential,
    
    [Parameter(Mandatory=$false)]
    [switch] $Force,

    [Parameter(Mandatory=$false)]
    [string] $LogPath,

    [Parameter(Mandatory=$false)]
    [System.Security.SecureString] $CertificatePassword,

    [Parameter(Mandatory=$false, ParameterSetName="Id")]
    [string[]] $RelyingPartyTrustIdentifier,

    [Parameter(Mandatory=$false, ParameterSetName="Id")]
    [string[]] $ClaimsProviderTrustIdentifier,

    [Parameter(Mandatory=$false, ParameterSetName="Name")]
    [string[]] $RelyingPartyTrustName,

    [Parameter(Mandatory=$false, ParameterSetName="Name")]
    [string[]] $ClaimsProviderTrustName
)

<#################################################################
 # Localizable strings.
 ################################################################>
Data _system_translations 
{ 
    ConvertFrom-StringData @'
# Fallback text
# Copy all the strings in the psd1 file here

InvalidPathError = '{0}' is not a valid path.
PathNotFoundError = The path '{0}' does not exist.

RegistryPathNotFoundError = The AD FS installation registry key '{0}' does not exist.
InvalidRegistryPathError = The AD FS installation registry key '{0}' does not point to a valid registry key.
RegistryKeyReadError = Failed to read the AD FS installation registry key '{0}'.
RegistryValueReadError = Failed to read value '{0}' from AD FS installation registry key '{1}'.
InvalidInstallationPathError = The path to the Federation Service '{0}' is not valid.
ConfigFileNotFoundError = The AD FS service configuration file '{0}' does not exist.
ConfigFileReadError = Failed to read the AD FS configuration file '{0}'.
ConnectionStringReadError = Failed to read the policy store connection string from the AD FS service configuration file '{0}'.
ServiceSettingsReadError = Failed to read service setting data from the AD FS configuration database '{0}'.
ServiceSettingsReadException = Failed to read service setting data from the AD FS configuration database '{0}'. Exception: {1}
ServiceSettingsDataError = The service settings data is not a valid XML document.
ServiceSettingsWriteError = The service settings data in the AD FS configuration database '{0}' could not be updated. Error code: '{1}'.
ServiceSettingsWriteException = The service settings data in the AD FS configuration database '{0}' could not be updated. Exception: {1}

CertificatePasswordError = The password to import/export certificates is not specified or empty.
ExportCertificatePasswordPrompt = Enter a password to export certificates
ImportCertificatePasswordPrompt = Enter a password to import certificates

ExportCertificateWarning = The '{0}' certificate '{1}' in '{2}/{3}' could not be exported.
ImportCertificateError = The certificate with thumbprint '{0}' could not be imported. Make sure the password is correct. You can also import this certificate to '{1}/{2}' and run this tool again. Exception: {3}
SaveCertificateError = The certificate with thumbprint '{0}' could not be saved to '{1}/{2}'. You can import this certificate to '{1}/{2}' and run this tool again. Exception: {3}
OpenCertStoreError = The certificate store '{0}/{1}' could not be opened. Exception: {2}
MissingCertWarning = The certificate '{0}' is not in store '{1}/{2}'. The exported files do not have its content. Make sure to import it into '{1}/{2}'. Otherwise, your STS service may not function properly.
InvalidCertPfxError = The certificate '{0}' contains invalid exported Personal Information Exchange (pfx) data.

ExportConfirmMessageCaption = Export Federation Configurations.
ImportConfirmMessageCaption = Import Federation Configurations.
ExportConfirmMessage = The folder '{0}' is not empty. If you choose to export configurations to this folder, all files and directories in it will be deleted. Do you want to continue?
ImportConfirmMessage = If you choose to import federation configurations, existing claims provider and relying party trusts on the target server will be overwritten. Do you want to continue?
ImportConfirmMessageDeleteAll = If you choose to import federation configurations, all existing claims provider and relying party trusts on the target server will be deleted. Do you want to continue?

SummaryInvalidElement = {0}: Invalid element '{1}'.
SummaryRequiredElementNotFound = {0}: The required element '{2}' cannot be found under element '{1}'.
SummaryRequiredAttributeNotFound = {0}: The required attribute '{2}' cannot be found in element '{1}'.

ExportStsVersionNotSupported = This version of the Federation service is not supported. Exiting...
ImportStsVersionNotSupported = The files are exported from Federation Services version {0}. This tool does not support importing files from that version.
ImportToolVersionNotSupported = The files are exported by Federation Services Migration Tool version {0}. This tool does not support importing files exported by that version.

ExportConfigurations = Exporting federation services configurations from server '{0}'...
ExportSavingFiles = Saving configuration files...
ExportFinished = The following AD FS configuration has been exported to '{0}':

EncryptionToken = Token-decrypting certificate
SigningToken = Token-signing certificate

CertNotExportedWarning = Warning: Ensure that you have the following certificates and private keys available in a Personal Information Exchange (.pfx) file or on each server in the new farm. The same certificates must be used on the destination farm, otherwise each trust partner must be updated with the new certificate:
AttrStoreWarning = Warning: The following custom attribute stores were not exported and must be migrated manually:

ImportConfigInfo = Use '{0}' to import this configuration to another AD FS farm.
TargetFarmRequirement = Ensure that the destination farm has the farm name '{0}' and uses service account '{1}'.

ServiceSettingsImported = The federation service settings data were successfully imported.
ImportReadingFiles = Reading configurations from folder '{0}'...
ImportConfigurations = Importing federation services configurations to server '{0}'...
ImportFinished = The configuration was successfully imported.

AddRelyingPartyTrust = Creating relying party trust '{0}'...
AddClaimsProviderTrust = Creating claims provider trust '{0}'...
SkipClaimDescription = The claim description '{0}' already exists. Skipping...
ImportClaimDescription = Creating claim description '{0}'...

MoreHelpMessage = For help with AD FS migration, see {0}.

ErrorLog = Error: {0}
WarningLog = Warning: {0}

# In the following group of strings, parameter {0} is always empty. It is used to mark the start of the string.
TrustExported = {0}    Claims provider and relying party trust relationships
CertExported = {0}    {1} with thumbprint '{2}'
CertTypeInfo = {0}    Certificate: {1}
ThumbprintInfo = {0}    Thumbprint: {1}
CertStoreInfo = {0}    Certificate store: {1}/{2}
AttrStoreName = {0}    {1}

SetCertificatePermissionsError = Failed to grant the AD FS service account read permissions to the private key of certificate with thumbprint '{0}' in store '{1}/{2}'. You can grant read permissions to the AD FS service account and run this tool again. Exception: {3}
SetCertificatePermissionsSuccess = The AD FS service account was granted read permissions to the private key of certificate with thumbprint '{0}'.
CertificateImported = The certificate with thumbprint '{0}' was successfully imported to '{1}/{2}'.

ComfirmExportCertificatePasswordPrompt = Re-enter password
MismatchedExportCertificatePasswordPrompt = The repeat password you typed does not match. {0}

TestImportError = The exported object of type ‘{0}’ with name ‘{1}’ could not be imported. Check the file ‘{2}’ for details about the object. Exception: {3}
TestExportError = The object of type ‘{0}’ with name ‘{1}’ could not be exported. Check the file ‘{2}’ for details about the object. Exception: {3}

'@
}

<#################################################################
 # Non-localizable strings.
 ################################################################>
$HelpFwLink = 'http://go.microsoft.com/fwlink/?LinkId=294108'

Function Main
{
    Begin
    {
        ## this is to support localization
        Import-LocalizedData -BindingVariable _system_translations -fileName Migrate-FederationConfiguration.psd1

        $activity = $_system_translations.ImportConfirmMessageCaption
        $ErrorActionPreference = 'Stop'
    }
    
    Process
    {
        Check-Path

        $logPath = Create-LogFile

        try
        {
            $fileParserScript = Parse-Summary $logPath

            $deleteAll = ($PsCmdlet.ParameterSetName -eq "Default")
            if ($deleteAll)
            {
                $warningMessage = $_system_translations.ImportConfirmMessageDeleteAll
            }
            else
            {
                $warningMessage = $_system_translations.ImportConfirmMessage
            }

            if ($Force -or ($PSCmdlet.ShouldProcess('', $warningMessage, $_system_translations.ImportConfirmMessageCaption)))
            {
                if ($ComputerName)
                {
                    $status = $_system_translations.ImportConfigurations -f $ComputerName
                }
                else
                {
                    $status = $_system_translations.ImportConfigurations -f $env:ComputerName
                }

                [System.IO.DirectoryInfo]$folder = (Get-Item -Path $Path)
                $operation = ($_system_translations.ImportReadingFiles -f $folder.FullName)
                Write-Progress -Activity $activity -Status $status -CurrentOperation $operation -PercentComplete 0
                Add-Content -Path $logPath -Value $operation -PassThru | Out-Host

                $configData = Invoke-Command -ScriptBlock $fileParserScript -ArgumentList $Path
                $rpTrusts = $configData.rpTrusts
                $cpTrusts = $configData.cpTrusts
                $claimDescriptions = $configData.claimDescriptions
                $certificates = $configData.certificates
                $adfsProperties = $configData.adfsProperties

                if ($deleteAll -eq $false)
                {
                    $selectData = Select-Trusts $RelyingPartyTrustIdentifier $ClaimsProviderTrustIdentifier $RelyingPartyTrustName $ClaimsProviderTrustName $rpTrusts $cpTrusts
                    $rpTrusts = $selectData.rpSelected
                    $cpTrusts = $selectData.cpSelected
                }

                Write-Progress -Activity $activity -Status $status -CurrentOperation $status -PercentComplete 5
                Add-Content -Path $logPath -Value $status -PassThru | Out-Host

                $arguments = @($deleteAll, $rpTrusts, $cpTrusts, $claimDescriptions, $certificates, $adfsProperties, $CertificatePassword, $Force, $_system_translations, $HelpFwLink, $Credential, $VerbosePreference)
                if ($ComputerName)
                {
                    $arguments += $true
                    if ($Credential)
                    {
                        Invoke-Command -ScriptBlock $setConfig -ArgumentList $arguments -ComputerName $ComputerName -Credential $Credential | Add-Content -Path $logPath | Out-Null
                    }
                    else
                    {
                        Invoke-Command -ScriptBlock $setConfig -ArgumentList $arguments -ComputerName $ComputerName | Add-Content -Path $logPath | Out-Null
                    }

                }
                else
                {
                    $arguments += $false
                    Invoke-Command -ScriptBlock $setConfig -ArgumentList $arguments | Add-Content -Path $logPath | Out-Null
                }

                $msg = ($_system_translations.ImportFinished)
                Add-Content -Path $logPath -Value $msg -PassThru | Out-Host
                Write-Progress -Activity $activity -Status $msg -PercentComplete 100 -Completed
            }
        }
        catch
        {
            Out-File -FilePath $logPath -InputObject $_ -Append -Force
            throw
        }
    }
}

$FileParserV1 = {
    Param (
        [string] $sourcePath
    )

    [System.IO.DirectoryInfo]$folder = (Get-Item -Path $sourcePath)
    $rpPath = $folder.FullName + '\rp.xml'
    $rpTrusts = Import-Clixml -Path $rpPath

    $cpPath = $folder.FullName + '\cp.xml'
    $cpTrusts = Import-Clixml -Path $cpPath
    
    $claimPath = $folder.FullName + '\claim.xml'
    $claimDescriptions = Import-Clixml -Path $claimPath

    $certPath = $folder.FullName + '\cert.xml'
    $certificates = Import-Clixml -Path $certPath

    $propertiesPath = $folder.FullName + '\properties.xml'
    $adfsProperties = Import-Clixml -Path $propertiesPath

    $result = New-Object PSObject -Property @{
        'rpTrusts' = $rpTrusts;
        'cpTrusts' = $cpTrusts;
        'claimDescriptions' = $claimDescriptions;
        'certificates' = $certificates;
        'adfsProperties' = $adfsProperties
    }

    Write-Output $result
}

$SetConfig = {
    Param (
        [bool] $deleteAll,
        [System.Object[]] $rpTrusts,
        [System.Object[]] $cpTrusts,
        [System.Object[]] $claimDescriptions,
        [PSObject] $certificates,
        $adfsProperties,
        [System.Security.SecureString] $certPassword,
        [bool] $forced,
        $_system_translations,
        [string]$HelpFwLink,
        [System.Management.Automation.PSCredential] $credential,
        $verbose,
        [bool] $isRemote
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = $verbose
    $ImpersonationContext = [System.Security.Principal.WindowsImpersonationContext]$null

    Function ThrowAndLog
    {
        Param([string]$obj)
        Process
        {
            Write-Output ($_system_translations.ErrorLog -f $obj)
            Write-Output ($_system_translations.MoreHelpMessage -f $HelpFwLink)
            throw ("{0}`n{1}" -f $obj, ($_system_translations.MoreHelpMessage -f $HelpFwLink))
        }
    }

    Function WarnAndLog
    {
        Param([string]$obj)
        Process
        {
            Write-Output ($_system_translations.WarningLog -f $obj)
            Write-Output ($_system_translations.MoreHelpMessage -f $HelpFwLink)
            Write-Warning ("{0}`n{1}" -f $obj, ($_system_translations.MoreHelpMessage -f $HelpFwLink))
        }
    }

    <#################################################################
     # Get the path to the ADFS config file
     ################################################################>
    Function Get-AdfsInstallationConfigFromRegistry
    {
        Param()

        Process
        {
            $FederationServiceConfigFilePath = "Microsoft.IdentityServer.Servicehost.exe.config"
            $MSISInstallRegistryPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\adfssrv'
            $MSISInstallRegistryValue = 'ImagePath'
            $ServiceAccountRegistryValue = 'ObjectName'

            if ((Test-Path -Path $MSISInstallRegistryPath -PathType Container) -eq $false)
            {
                throw ($_system_translations.RegistryPathNotFoundError -f $MSISInstallRegistryPath)
            }
            else
            {
                $key = Get-Item -Path $MSISInstallRegistryPath
                if (!($key -is [Microsoft.Win32.RegistryKey]))
                {
                    throw ($_system_translations.RegistryKeyReadError -f $MSISInstallRegistryPath)
                }
                else
                {
                    $configFilePath = $null
                    $imagePath = $key.GetValue($MSISInstallRegistryValue)
                    if ($imagePath -eq $null)
                    {
                        throw ($_system_translations.RegistryValueReadError -f $MSISInstallRegistryValue,$MSISInstallRegistryPath)
                    }
                    else
                    {
                        $index = $imagePath.LastIndexOf('\')
                        if ($index -eq -1)
                        {
                            throw ($_system_translations.InvalidInstallationPathError -f $imagePath)
                        }
                        else
                        {
                            if ($imagePath.StartsWith('"', [System.StringComparison]::OrdinalIgnoreCase))
                            {
                                #start at index 1 if this image path is surrounded in quotes
                                $installPath = $imagePath.Substring(1, $index)
                            }
                            else
                            {
                                $installPath = $imagePath.Substring(0, $index)
                            }

                            $configFilePath = ($installPath + '\' + $FederationServiceConfigFilePath)
                        }
                    }

                    $svcAcct = $key.GetValue($ServiceAccountRegistryValue)
                    if ($svcAcct -eq $null)
                    {
                        throw ($_system_translations.RegistryValueReadError -f $MSISInstallRegistryValue, $ServiceAccountRegistryValue)
                    }

                    $result = New-Object PSObject -Property @{ 'ConfigFilePath' = $configFilePath; 'ServiceAccount' = $svcAcct }
                    Write-Output $result
                }
            }
        }
    }

    <#################################################################
     # Get SQL policy database connection string
     ################################################################>
    Function Get-PolicyConnectionString
    {
        Param([string] $configFilePath)

        Process
        {
            if ((Test-Path -Path $configFilePath -PathType Leaf) -eq $false)
            {
                ThrowAndLog ($_system_translations.ConfigFileNotFoundError -f $configFilePath)
            }
            else
            {
                $configFile = [xml] (Get-Content -Path $configFilePath)
                if ($configFile -eq $null)
                {
                    ThrowAndLog ($_system_translations.ConfigFileReadError -f $configFilePath)
                }
                else
                {
                    $policyStore = $configFile.SelectSingleNode('//policyStore')
                    if ($policyStore -ne $null)
                    {
                        $connectionString = $policyStore.connectionString
                    }

                    if ($connectionString -eq $null)
                    {
                        ThrowAndLog ($_system_translations.ConnectionStringReadError -f $configFilePath)
                    }
                    else
                    {
                        Write-Output $connectionString
                    }
                }
            }
        }
    }

    <#################################################################
     # Execute a SQL query
     ################################################################>
    Function Execute-SqlQuery
    {
        Param(
            [string] $connectionString,
            [string] $query
            )

        Process
        {
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = $connectionString
            
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.CommandText = $query
            $cmd.Connection = $conn
            
            $adapter = New-Object System.Data.SqlClient.SqlDataAdapter
            $adapter.SelectCommand = $cmd
            
            $dataSet = New-Object System.Data.DataSet
            $adapter.Fill($dataSet)
            
            $conn.Close()
            if (($dataSet.Tables -ne $null) -and ($dataSet.Tables.Count -gt 0))
            {
                Write-Output $dataSet.Tables[0]
            }
        }
    }

    <#################################################################
     # Execute a non-query SQL statement
     ################################################################>
    Function Execute-SqlNonQuery
    {
        Param(
            [string] $connectionString,
            [string] $statement
            )

        Process
        {
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = $connectionString
            
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.CommandText = $statement
            $cmd.Connection = $conn

            $conn.Open()
            $result = $cmd.ExecuteNonQuery()
            $conn.Close()
        }
    }

    <#################################################################
     # Execute a SQL stored procedure
     ################################################################>
    Function Execute-SqlStoredProcedure
    {
        Param(
            [string] $connectionString,
            [string] $procedure,
            [System.Data.SqlClient.SqlParameter[]] $parameters
            )

        Process
        {
            $conn = New-Object System.Data.SqlClient.SqlConnection
            $conn.ConnectionString = $connectionString
            
            $cmd = New-Object System.Data.SqlClient.SqlCommand
            $cmd.CommandText = $procedure
            $cmd.Connection = $conn
            $cmd.CommandType = [System.Data.CommandType]::StoredProcedure

            foreach($p in $parameters)
            {
                if ($p -ne $null)
                {
                    $cmd.Parameters.Add($p) | Out-Null
                }
            }

            $conn.Open()
            $result = $cmd.ExecuteNonQuery()
            $conn.Close()

            Write-Output $result
        }
    }

    <#################################################################
     # Output exception information
     ################################################################>
    Function Get-ExceptionString
    {
        Param($ErrorRecord)
        Process
        {
            $exceptionStr = ''
            if (($ErrorRecord -ne $null) -and ($ErrorRecord.Exception -ne $null))
            {
                $exceptionStr = $ErrorRecord.Exception.Message
            }
            Write-Output $exceptionStr
        }
    }

    <#################################################################
     # Import an ADFS certificate if necessary
     ################################################################>
    Function Import-AdfsCertificate
    {
        Param(
            [ref] $certRef,
            [string] $svcAcct,
            [ref] $certPasswordRef,
            [bool] $forced
            )

        Process
        {
            $cert = $null
            if ($certRef -ne $null)
            {
                $cert = $certRef.Value
            }

            if (($cert -ne $null) -and ($cert.EncryptedPfx -eq $null))
            {
                # Search for the certificate in the local store
                # Do not search the CurrentUser store since we may not be in the service account context.
                # Also, a user created certificate should not be in the FS service account's CurrentUser store.
                $localCertCollection = $null

                if (($cert.StoreNameValue -ne $null) -and ($cert.StoreLocationValue -ne $null) -and ($cert.X509FindTypeValue -ne $null) -and ($cert.FindValue -ne $null))
                {
                    # Search in 'LocalMachine' only
                    $storeLocation = 'LocalMachine'
                    $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ([System.Security.Cryptography.X509Certificates.StoreName] ($cert.StoreNameValue)), ([System.Security.Cryptography.X509Certificates.StoreLocation] ($storeLocation))

                    try
                    {
                        $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                        if ($certStore.Certificates -ne $null)
                        {
                            $localCertCollection = $certStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType] ($cert.X509FindTypeValue), $cert.FindValue, $false)
                        }
                        $certStore.Close()
                    }
                    catch
                    {
                        WarnAndLog ($_system_translations.OpenCertStoreError -f $storeLocation, $cert.StoreNameValue, (Get-ExceptionString $_))
                    }
                }

                $certificate = $null

                if (($localCertCollection -ne $null) -and ($localCertCollection.Count -gt 0))
                {
                    # If the certificate is in 'LocalMachine', do not import it.
                    # Update the cert reference to point to 'LocalMachine'.
                    $certRef.Value.StoreLocationValue = $storeLocation
                    $certificate = $localCertCollection[0]
                }
                else
                {
                    # Import the certificate if it is not in the local store
                    if ($cert.ExportedPfx -eq $null)
                    {
                        WarnAndLog ($_system_translations.MissingCertWarning -f $cert.FindValue, $cert.StoreLocationValue, $cert.StoreNameValue)
                    }
                    else
                    {
                        $exportedPfx = [System.Convert]::FromBase64String($cert.ExportedPfx)
                        if ($exportedPfx -eq $null)
                        {
                            ThrowAndLog ($_system_translations.InvalidCertPfxError -f $cert.FindValue)
                        }
                        else
                        {
                            if (($certPasswordRef.Value -eq $null) -or ($certPasswordRef.Value.Length -eq 0))
                            {
                                # The password is not specified or empty
                                if ($forced -eq $true)
                                {
                                    # Output is suppressed
                                    ThrowAndLog ($_system_translations.CertificatePasswordError)
                                }
                                else
                                {
                                    while (($certPasswordRef.Value -eq $null) -or ($certPasswordRef.Value.Length -eq 0))
                                    {
                                        # Prompting the user to enter a non-empty password
                                        $certPasswordRef.Value = Read-Host -Prompt ($_system_translations.ImportCertificatePasswordPrompt) -AsSecureString
                                    }
                                }
                            }

                            if (($certPasswordRef.Value -ne $null) -and ($certPasswordRef.Value.Length -gt 0))
                            {
                                $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                                try
                                {
                                    $certificate.Import($exportedPfx, $certPasswordRef.Value, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
                                }
                                catch
                                {
                                    ThrowAndLog ($_system_translations.ImportCertificateError -f $cert.FindValue, 'LocalMachine', 'My', (Get-ExceptionString $_))
                                }

                                if ($certificate.PublicKey -ne $null)
                                {
                                    # Save the certificate in LocalMachine/My
                                    $certStore = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList ([System.Security.Cryptography.X509Certificates.StoreName]::My), ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)

                                    try
                                    {
                                        $certStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                                    }
                                    catch
                                    {
                                        ThrowAndLog ($_system_translations.OpenCertStoreError -f 'LocalMachine', 'My', (Get-ExceptionString $_))
                                    }

                                    try
                                    {
                                        $certStore.Add($certificate)
                                    }
                                    catch [System.Security.Cryptography.CryptographicException]
                                    {
                                        ThrowAndLog ($_system_translations.SaveCertificateError -f $cert.FindValue, 'LocalMachine', 'My', (Get-ExceptionString $_))
                                    }

                                    $certStore.Close()

                                    # Update the cert object's location info
                                    $certRef.Value.StoreLocationValue = 'LocalMachine'
                                    $certRef.Value.StoreNameValue = 'My'
                                }
                            }
                        }

                        $msg = ($_system_translations.CertificateImported -f $cert.FindValue, 'LocalMachine', 'My')
                        Write-Output $msg
                        Write-Verbose $msg
                    }
                }
            }

            if ($certificate -ne $null)
            {
                try
                {
                    Set-CertificatePermissions $certificate 'nt service\adfssrv'
                    Set-CertificatePermissions $certificate 'nt service\drs'
                }
                catch
                {
                    ThrowAndLog ($_system_translations.SetCertificatePermissionsError -f $cert.FindValue, 'LocalMachine', 'My', (Get-ExceptionString $_))
                }
            }
        }
    }

    <#################################################################
     # Set the given value to the specified XML element
     ################################################################>
    Function Set-XmlElementValue
    {
        Param(
            [xml] $doc,
            [System.Xml.XmlElement] $parentElement,
            [string] $tag,
            [PSObject] $targetValue,
            $defaultValue
            )

        Process
        {
            $namespace_default = $doc.ServiceSettingsData.GetNamespaceOfPrefix('')
            $namespace_i = $doc.ServiceSettingsData.GetNamespaceOfPrefix('i')

            $nsMgr = New-Object System.Xml.XmlNamespaceManager -ArgumentList $doc.NameTable
            $nsMgr.AddNamespace('ns', $namespace_default)
            $nsMgr.AddNamespace('i', $namespace_i)

            $targetElement = $parentElement.SelectSingleNode("ns:$tag", $nsMgr)
            if ($targetElement -eq $null)
            {
                # Create the element if it does not exist
                $targetElement = $doc.CreateElement($tag, $namespace_default)
                $parentElement.AppendChild($targetElement) | Out-Null
            }

            $targetElement.RemoveAll()

            if (($targetValue -eq $null) -or ($targetValue."$tag" -eq $null))
            {
                # Use the default value if it is not null, otherwise, generate a nil attribute
                if ($defaultValue -eq $null)
                {
                    $targetElement.SetAttribute('nil', $namespace_i, 'true') | Out-Null
                }
                else
                {
                    $targetElement.InnerText = $defaultValue
                }
            }
            else
            {
                $targetElement.InnerText = $targetValue."$tag"
            }
        }
    }

    <#################################################################
     # Given a certificate, update the corresponding element in the service settings XML
     ################################################################>
    Function Set-CertificateInServiceSettingsXml
    {
        Param(
            [xml] $serviceSettingsData,
            [System.Xml.XmlElement] $parentElement,
            [string] $tag,
            [bool] $matchCertFindValue,
            [PSObject] $cert,
            [ref] $certPasswordRef,
            [bool] $importPfx,
            [bool] $forced,
            [string] $svcAcct
            )

        Process
        {
            $namespace_default = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('')
            $namespace_i = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('i')

            $nsMgr = New-Object System.Xml.XmlNamespaceManager -ArgumentList $serviceSettingsData.NameTable
            $nsMgr.AddNamespace('ns', $namespace_default)
            $nsMgr.AddNamespace('i', $namespace_i)

            if ($matchCertFindValue -eq $true)
            {
                $targetElement = $parentElement.SelectSingleNode("ns:$tag[FindValue ='$($cert.FindValue)']", $nsMgr)
            }
            else
            {
                $targetElement = $parentElement.SelectSingleNode("ns:$tag", $nsMgr)
            }

            if ($targetElement -eq $null)
            {
                # The cert element is missing. Create a new one.
                $targetElement = $serviceSettingsData.CreateElement($tag, $namespace_default)
                $parentElement.AppendChild($targetElement) | Out-Null
            }

            Set-XmlElementValue $serviceSettingsData $targetElement 'ObjectVersion' $cert '0'
            Set-XmlElementValue $serviceSettingsData $targetElement 'IsChainIncluded' $cert 'false'
            Set-XmlElementValue $serviceSettingsData $targetElement 'IsChainIncludedSpecified' $cert 'false'
            Set-XmlElementValue $serviceSettingsData $targetElement 'FindValue' $cert $null
            Set-XmlElementValue $serviceSettingsData $targetElement 'RawCertificate' $cert $null
            Set-XmlElementValue $serviceSettingsData $targetElement 'EncryptedPfx' $cert $null
            Set-XmlElementValue $serviceSettingsData $targetElement 'StoreNameValue' $cert 'My'
            Set-XmlElementValue $serviceSettingsData $targetElement 'StoreLocationValue' $cert 'CurrentUser'
            Set-XmlElementValue $serviceSettingsData $targetElement 'X509FindTypeValue' $cert 'FindByThumbprint'

            if ($importPfx -eq $true)
            {
                Import-AdfsCertificate ([ref] $cert) $svcAcct $certPasswordRef $forced
            }
        }
    }

    <#################################################################
     # Import primary and additional certificates into the service settings XML
     ################################################################>
    Function Set-AdfsCertificatesInServiceSettingsXml
    {
        Param(
            [xml] $serviceSettingsData,
            [System.Xml.XmlElement] $parentElement,
            [string] $primaryTag,
            [string] $additionalTag,
            [PSObject] $certData,
            [ref] $certPasswordRef,
            [bool] $forced,
            [string] $svcAcct
            )

        Process
        {
            $namespace_default = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('')
            $namespace_i = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('i')

            $nsMgr = New-Object System.Xml.XmlNamespaceManager -ArgumentList $serviceSettingsData.NameTable
            $nsMgr.AddNamespace('ns', $namespace_default)
            $nsMgr.AddNamespace('i', $namespace_i)

            # Get the additional certificates element
            $additionalElement = $parentElement.SelectSingleNode("ns:$additionalTag", $nsMgr)
            if ($additionalElement -eq $null)
            {
                # The additional certificates element is missing. Create a new one.
                $additionalElement = $serviceSettingsData.CreateElement($additionalTag, $namespace_default)
                $parentElement.AppendChild($additionalElement) | Out-Null
            }
            
            # Import additional certificates
            $additionalElement.RemoveAll()
            foreach ($cert in $certData."$additionalTag")
            {
                if ($cert -ne $null)
                {
                    Set-CertificateInServiceSettingsXml $serviceSettingsData $additionalElement 'CertificateReference' $true $cert $certPasswordRef $true $forced $svcAcct
                }
            }

            # Set the primary certificate
            # No need to import the primary certificate since it should have been imported as an additional certificate
            Set-CertificateInServiceSettingsXml $serviceSettingsData $parentElement $primaryTag $false $certData."$primaryTag" $certPasswordRef $false $forced $svcAcct
        }
    }

    <#################################################################
     # Update the DKM settings element in the service settings XML
     ################################################################>
    Function Set-DkmSettingsInServiceSettingsXml
    {
        Param(
            [xml] $serviceSettingsData,
            [System.Xml.XmlElement] $parentElement,
            [string] $tag,
            [PSObject] $dkmSettings
            )

        Process
        {
            $namespace_default = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('')
            $namespace_i = $serviceSettingsData.ServiceSettingsData.GetNamespaceOfPrefix('i')

            $nsMgr = New-Object System.Xml.XmlNamespaceManager -ArgumentList $serviceSettingsData.NameTable
            $nsMgr.AddNamespace('ns', $namespace_default)
            $nsMgr.AddNamespace('i', $namespace_i)

            $targetElement = $parentElement.SelectSingleNode("ns:$tag", $nsMgr)
            if ($targetElement -eq $null)
            {
                # The DKM element is missing. Create a new one.
                $targetElement = $serviceSettingsData.CreateElement($tag, $namespace_default)
                $parentElement.AppendChild($targetElement) | Out-Null
            }

            Set-XmlElementValue $serviceSettingsData $targetElement 'ObjectVersion' $dkmSettings '0'
            Set-XmlElementValue $serviceSettingsData $targetElement 'Group' $dkmSettings $nul
            Set-XmlElementValue $serviceSettingsData $targetElement 'ContainerName' $dkmSettings $nul
            Set-XmlElementValue $serviceSettingsData $targetElement 'ParentContainerDn' $dkmSettings $nul
            Set-XmlElementValue $serviceSettingsData $targetElement 'PreferredReplica' $dkmSettings $nul
            Set-XmlElementValue $serviceSettingsData $targetElement 'Enabled' $dkmSettings 'true'
        }
    }

    <#################################################################
     # Output a hashtable
     ################################################################>
    Function Output-Hash
    {
        Param(
            [HashTable] $hash
        )

        Process
        {
            $obj = New-Object PSObject -Property $hash
            Write-Output $obj
        }
    }

    <#################################################################
     # Execute a command with the specified parameters.
     #
     # For non-mandatory parameters, if the value if empty, ignore
     # the parameter, i.e., it will not be passed to the command.
     # This is to deal with the case that the command might block
     # empty parameters.
     #
     # For example, the SamlAuthenticationRequestProtocolBinding
     # parameter of the Add-ADFSClaimsProviderTrust cmdlet cannot
     # be null or empty.
     ################################################################>
    Function Execute-Command
    {
        Param(
            [Parameter(Mandatory=$true)]
            [string] $Command,
            [Parameter(Mandatory=$false)]
            [HashTable] $Parameters
        )

        Process
        {
            $cmdInfo = Get-Command -Name $Command
            $cmd = $Command

            if ($Parameters)
            {
                foreach ($k in $Parameters.Keys)
                {
                    if ($k -eq $null)
                    {
                        continue
                    }

                    $paraInfo = $cmdInfo.Parameters[$k]

                    $includePara = $true

                    $isMandatory = $false
                    foreach ($att in $paraInfo.Attributes)
                    {
                        if (($att -ne $null) -and ($att -is [System.Management.Automation.ParameterAttribute]))
                        {
                            $isMandatory = $att.Mandatory
                            break
                        }
                    }

                    if (!$isMandatory)
                    {
                        # For non-mandatory parameters, only include them with non-empty values

                        $value = $Parameters[$k]

                        if ($value)
                        {
                            $includePara = $true
                        }
                        elseif ($value -eq $false)
                        {
                            $includePara = $true
                        }
                        else
                        {
                            $includePara = $false
                        }
                    }

                    if ($includePara)
                    {
                        if ($paraInfo.SwitchParameter)
                        {
                            $cmd += " -$($k):"
                        }
                        else
                        {
                            $cmd += " -$($k) " 
                        }

                        $cmd += '$Parameters["'
                        $cmd += "$($k)"
                        $cmd += '"]'
                    }
                }
            }

            $wmsg = $null
            try
            {
                Invoke-Expression -Command $cmd -WarningVariable wmsg
            }
            catch
            {
                Write-Output $wmsg
                Write-Output $cmd
                Output-Hash $Parameters
                throw
            }
            
            Write-Output $wmsg
        }
    }

    <#################################################################
     # Determine if a claims provider trust is the default ADAuthority
     # trust.
     ################################################################>
    Function Check-ADClaimsProvider
    {
        Param(
            $claimProviderTrust
        )

        Process
        {
            $result = $false;

            if ($claimProviderTrust)
            {
                if ($claimProviderTrust.Identifier -eq 'AD AUTHORITY')
                {
                    $result = $true
                }
            }

            Write-Output $result
        }
    }

    <#################################################################
     # Determine if a relying party trust is the default device registration
     # service trust.
     ################################################################>
    Function Check-DrsRelyingParty
    {
        Param(
            $relyingParty
        )

        Process
        {
            $result = $false;

            if ($relyingParty)
            {
                if ($relyingParty.Name -eq 'Device Registration Service')
                {
                    $result = $true
                }
            }

            Write-Output $result
        }
    }

    <#################################################################
     # Load native functions
     ################################################################>
    Function Add-MigrationUtilites
    {
        Param()

        Process
        {
            $signature = @'

    public const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
    public const uint CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000;
    public const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;
    public const string NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr";
    public const uint DACL_SECURITY_INFORMATION = 4;
    public const uint PP_KEYSET_SEC_DESCR = 8;
    public const int ERROR_NOT_ENOUGH_MEMORY = 8;

    [DllImport("crypt32.dll", SetLastError = true)]
    public static extern
    bool CryptAcquireCertificatePrivateKey(
        [In] IntPtr pCert,
        [In] uint dwFlags,
        [In] IntPtr pvReserved,
        [Out] out SafeNCryptKeyHandle hCryptProv,
        [Out] out uint pdwKeySpec,
        [Out] [MarshalAs(UnmanagedType.Bool)] out bool pfCallerFreeProv
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    public extern static
    bool CryptGetProvParam(
        [In] IntPtr hProv,
        [In] uint dwParam,
        [In] [MarshalAs(UnmanagedType.LPArray)] byte[] pbData,
        [In] ref uint pdwDataLen,
        [In] uint dwFlags
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern
    bool CryptSetProvParam(
        [In] IntPtr hProv,
        [In] uint dwParam,
        [In] [MarshalAs(UnmanagedType.LPArray)] byte[] pbData,
        [In] uint dwFlags
        );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern
    bool CryptReleaseContext(
        [In] IntPtr hCryptProv,
        [In] uint dwFlags
        );

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool LogonUser(
        string username,
        string domain,
        IntPtr password,
        int logonType,
        int logonProvider,
        out IntPtr token
        );

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public extern static bool CloseHandle(IntPtr handle);

    public const int LOGON32_PROVIDER_DEFAULT = 0;
    public const int LOGON32_PROVIDER_WINNT40 = 2;
    public const int LOGON32_PROVIDER_WINNT50 = 3;
    public const int LOGON32_LOGON_INTERACTIVE = 2;
    public const int LOGON32_LOGON_NETWORK = 3;
    public const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    public const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
 
'@
        Add-Type -MemberDefinition $signature -Name ScriptUtilities -Namespace Microsoft.IdentityServer.Migration -UsingNamespace Microsoft.Win32.SafeHandles -PassThru
        }
    }

    <#################################################################
     # Split the combined username string into user and domain
     ################################################################>
    Function SplitUserDomain
    {
        Param(
            [string] $combined,
            [ref] $domain,
            [ref] $user
        )

        Process
        {
            if ($combined -eq $null)
            {
                $user.Value = $null
                $domain.Value = $null
            }
            else
            {
                $i = $combined.IndexOf('\')
                if ($i -ge 0)
                {
                    $user.Value = $combined.Substring($i + 1)
                    $domain.Value = $combined.Substring(0, $i)
                }
                else
                {
                    $user.Value = $combined
                    $domain.Value = ''
                }
            }
        }
    }

    <#################################################################
     # Do a LogonUser then an impersonation
     ################################################################>
    Function ImpersonateUser
    {
        Param(
            [System.Management.Automation.PSCredential] $cred
        )

        Process
        {
            $token = [System.IntPtr]::Zero
            $password = [System.IntPtr]::Zero
            $ret = $flase
            $identity = $null
            $user = $null
            $domain = $null

            SplitUserDomain $cred.UserName ([ref] $domain) ([ref] $user)

            try
            {
                $password = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($cred.Password)
                $ret = [Microsoft.IdentityServer.Migration.ScriptUtilities]::LogonUser($user, $domain, $password, [Microsoft.IdentityServer.Migration.ScriptUtilities]::LOGON32_LOGON_NETWORK_CLEARTEXT, [Microsoft.IdentityServer.Migration.ScriptUtilities]::LOGON32_PROVIDER_DEFAULT, [ref] $token)
            }
            finally
            {
                # erase password
                [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($password)
                $password = $null
            }

            if ($ret -eq $false)
            {
                $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                $ex = New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode
                $msg = ("{0}`n{1}" -f ($_system_translations.ErrorLog -f 'LogonUser'), $ex.Message)
                throw (New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode, $msg)
            }

            try
            {
                $identity = New-Object Security.Principal.WindowsIdentity $token
                $identity.Impersonate()
            }
            catch
            {
                if ($identity)
                {
                    $identity.Dispose()
                    $identity = $null
                }

                if ($token -ne [System.IntPtr]::Zero)
                {
                    [Microsoft.IdentityServer.Migration.ScriptUtilities]::CloseHandle($token) | Out-Null
                }

                throw
            }
        }
    }

    <#################################################################
     # Grant a user read permission to the private key of a certifcate
     ################################################################>
    Function Set-CertificatePermissions
    {
        Param(
            [System.Security.Cryptography.X509Certificates.X509Certificate2] $cert,
            [string] $user
        )

        Process
        {
            [Microsoft.Win32.SafeHandles.SafeNCryptKeyHandle] $safeKeyHandle = $null
            [bool] $freeHandle = $false
            [uint32] $pdwKeySpec = 0

            $ret = [Microsoft.IdentityServer.Migration.ScriptUtilities]::CryptAcquireCertificatePrivateKey($cert.Handle, (([Microsoft.IdentityServer.Migration.ScriptUtilities]::CRYPT_ACQUIRE_SILENT_FLAG) -bor ([Microsoft.IdentityServer.Migration.ScriptUtilities]::CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG)), [System.IntPtr]::Zero, ([ref] $safeKeyHandle), ([ref] $pdwKeySpec), ([ref] $freeHandle))
            if ($ret -eq $false)
            {
                $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw (New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode)
            }

            $isCngKey = ($pdwKeySpec -eq [Microsoft.IdentityServer.Migration.ScriptUtilities]::CERT_NCRYPT_KEY_SPEC)
            $privateKeyHandle = $safeKeyHandle.DangerousGetHandle()

            $cngKey = $null

            try
            {
                if ($isCngKey -eq $true)
                {
                    $cngKey = [System.Security.Cryptography.CngKey]::Open($safeKeyHandle, [System.Security.Cryptography.CngKeyHandleOpenOptions]::None)
                    $prop = $cngKey.GetProperty([Microsoft.IdentityServer.Migration.ScriptUtilities]::NCRYPT_SECURITY_DESCR_PROPERTY, [System.Security.Cryptography.CngPropertyOptions]([Microsoft.IdentityServer.Migration.ScriptUtilities]::DACL_SECURITY_INFORMATION))
                    $existingSecurity = $prop.GetValue()
                    $securityDescriptor = Add-ReadOnlyPermission $user $existingSecurity
                    $prop = New-Object -TypeName System.Security.Cryptography.CngProperty -ArgumentList ([Microsoft.IdentityServer.Migration.ScriptUtilities]::NCRYPT_SECURITY_DESCR_PROPERTY, $securityDescriptor, [System.Security.Cryptography.CngPropertyOptions]([Microsoft.IdentityServer.Migration.ScriptUtilities]::DACL_SECURITY_INFORMATION))
                    $cngKey.SetProperty($prop)
                }
                else
                {
                    $buffer = New-Object byte[] 4096
                    $size = [uint32]($buffer.Length)
                    $ret = [Microsoft.IdentityServer.Migration.ScriptUtilities]::CryptGetProvParam($privateKeyHandle, [Microsoft.IdentityServer.Migration.ScriptUtilities]::PP_KEYSET_SEC_DESCR, $buffer, ([ref] $size), [Microsoft.IdentityServer.Migration.ScriptUtilities]::DACL_SECURITY_INFORMATION)
                    $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    if ($ret -eq $false)
                    {
                        if ($errCode -eq [Microsoft.IdentityServer.Migration.ScriptUtilities]::ERROR_NOT_ENOUGH_MEMORY)
                        {
                            $buffer = New-Object byte[] $size
                            $ret = [Microsoft.IdentityServer.Migration.ScriptUtilities]::CryptGetProvParam($privateKeyHandle, [Microsoft.IdentityServer.Migration.ScriptUtilities]::PP_KEYSET_SEC_DESCR, $buffer, ([ref] $size), [Microsoft.IdentityServer.Migration.ScriptUtilities]::DACL_SECURITY_INFORMATION)
                            if ($ret -eq $false)
                            {
                                $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                                throw (New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode) 
                            }
                        }
                        else
                        {
                            throw (New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode)
                        }
                    }

                    $existingSecurity = $buffer
                    if ($existingSecurity.Length -ne $size)
                    {
                        $existingSecurity = New-Object byte[] $size
                        [System.Array]::Copy($buffer, $existingSecurity, $size)
                    }

                    $securityDescriptor = Add-ReadOnlyPermission $user $existingSecurity
                    $ret = [Microsoft.IdentityServer.Migration.ScriptUtilities]::CryptSetProvParam($privateKeyHandle, [Microsoft.IdentityServer.Migration.ScriptUtilities]::PP_KEYSET_SEC_DESCR, $securityDescriptor, [Microsoft.IdentityServer.Migration.ScriptUtilities]::DACL_SECURITY_INFORMATION)
                    if ($ret -eq $false)
                    {
                        $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw (New-Object -TypeName System.ComponentModel.Win32Exception -ArgumentList $errCode) 
                    }
                }

                $msg = ($_system_translations.SetCertificatePermissionsSuccess -f $cert.Thumbprint)
                Write-Output $msg
                Write-Verbose $msg
            }
            finally
            {
                if ($cngKey -ne $null)
                {
                    $cngKey.Dispose()
                }

                if ($freeHandle -eq $true)
                {
                    if ($isCngKey -eq $true)
                    {
                        $safeKeyHandle.Close()
                    }
                    else
                    {
                        [Microsoft.IdentityServer.Migration.ScriptUtilities]::CryptReleaseContext($privateKeyHandle, 0) | Out-Null
                        $safeKeyHandle.SetHandleAsInvalid()
                    }
                }
            }
        }
    }

    <#################################################################
     # Add a read ACL to a security descriptor.
     ################################################################>
    Function Add-ReadOnlyPermission
    {
        Param(
            [string] $user,
            $existingSecurityDescriptor
        )

        Process
        {
            $security = New-Object -TypeName System.Security.AccessControl.FileSecurity
            $security.SetSecurityDescriptorBinaryForm($existingSecurityDescriptor) | Out-Null
            $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($user, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow)
            $security.SetAccessRule($rule) | Out-Null
            $security.GetSecurityDescriptorBinaryForm()
        }
    }

    <#################################################################
     # Processing starts
     ################################################################>

    try
    {
        $ErrorActionPreference = 'Stop'
        $activity = $_system_translations.ImportConfirmMessageCaption
        $status = $_system_translations.ImportConfigurations -f $env:ComputerName

        try
        {
            Add-MigrationUtilites | Out-Null
        }
        catch
        {
            if (($_.FullyQualifiedErrorId -ne $null) -and ($_.FullyQualifiedErrorId.StartsWith('TYPE_ALREADY_EXISTS', [System.StringComparison]::OrdinalIgnoreCase)))
            {
                # The type already exists. Ignore the exception.
            }
            else
            {
                throw
            }
        }

        # Impersonate user
        if ($credential)
        {
            $ImpersonationContext = ImpersonateUser $credential
        }

        # Load ADFS snapin or modules
        Import-Module ADFS | Out-Null

        # Read certificates from the configuration database
        $registryData = Get-AdfsInstallationConfigFromRegistry
        $configPath = $null
        $svcAcct = $null
        if ($registryData -ne $null)
        {
            $configPath = $registryData.ConfigFilePath
            $svcAcct = $registryData.ServiceAccount
        }

        if ($configPath -ne $null)
        {
            $policyStoreConnStr = Get-PolicyConnectionString $configPath
        }
        if ($policyStoreConnStr -ne $null)
        {
            $sqlQuery = 'SELECT TOP 1 [ServiceSettingId],[ServiceSettingsData],[LastUpdateTime],[ServiceSettingsVersion] FROM [AdfsConfiguration].[IdentityServerPolicy].[ServiceSettings]'
            try
            {
                $dataRows = Execute-SqlQuery $policyStoreConnStr $sqlQuery
            }
            catch
            {
                ThrowAndLog ($_system_translations.ServiceSettingsReadException -f $policyStoreConnStr, (Get-ExceptionString $_))
            }

            if (($dataRows -eq $null) -or ($dataRows[0] -ne 1) -or ($dataRows[1] -eq $null))
            {
                ThrowAndLog ($_system_translations.ServiceSettingsReadError -f $policyStoreConnStr)
            }
            else
            {
                $serviceSettingsData = [xml] ($dataRows[1].ServiceSettingsData)
                $serviceSettingId = [Guid] ($dataRows[1].ServiceSettingId)
                $serviceSettingsVersion = [Int64] ($dataRows[1].ServiceSettingsVersion)
                if (($serviceSettingsData -eq $null) -or ($serviceSettingId -eq $null))
                {
                    ThrowAndLog ($_system_translations.ServiceSettingsDataError)
                }
            }
        }

        # Import certificates and DKM settings
        if (($serviceSettingsData -ne $null) -and ($serviceSettingId -ne $null))
        {
            Set-AdfsCertificatesInServiceSettingsXml $serviceSettingsData $serviceSettingsData.ServiceSettingsData.SecurityTokenService 'EncryptionToken' 'AdditionalEncryptionTokens' $certificates.EncryptionToken ([ref] $certPassword) $forced $svcAcct
            Set-AdfsCertificatesInServiceSettingsXml $serviceSettingsData $serviceSettingsData.ServiceSettingsData.SecurityTokenService 'SigningToken' 'AdditionalSigningTokens' $certificates.SigningToken ([ref] $certPassword) $forced $svcAcct

            Set-DkmSettingsInServiceSettingsXml $serviceSettingsData $serviceSettingsData.ServiceSettingsData.PolicyStore 'DkmSettings' $certificates.DkmSettings

            $stringWriter = New-Object System.IO.StringWriter
            $xmlWriter = New-Object System.XMl.XmlTextWriter $stringWriter
            $xmlWriter.Formatting = "None"
            $serviceSettingsData.WriteContentTo($xmlWriter) | Out-Null
            $xmlWriter.Flush() | Out-Null
            $stringWriter.Flush() | Out-Null
            $serviceSettingsDataString = $stringWriter.ToString()
        }

        if (($serviceSettingsDataString -ne $null) -and ($serviceSettingId -ne $null))
        {
            $sqlProcedure = '[IdentityServerPolicy].[UpdateServiceSettings]'

            $objectIdPara = New-Object System.Data.SqlClient.SqlParameter
            $objectIdPara.ParameterName = '@ObjectId'
            $objectIdPara.Direction = [System.Data.ParameterDirection]::Input
            $objectIdPara.SqlDbType = [System.Data.SqlDbType]::UniqueIdentifier
            $objectIdPara.SqlValue = $serviceSettingId

            $serviceSettingsDataPara = New-Object System.Data.SqlClient.SqlParameter
            $serviceSettingsDataPara.ParameterName = '@ServiceSettingsData'
            $serviceSettingsDataPara.Direction = [System.Data.ParameterDirection]::Input
            $serviceSettingsDataPara.SqlDbType = [System.Data.SqlDbType]::NVarChar
            $serviceSettingsDataPara.SqlValue = $serviceSettingsDataString

            $serviceSettingsVersionPara = New-Object System.Data.SqlClient.SqlParameter
            $serviceSettingsVersionPara.ParameterName = '@ServiceSettingsVersion'
            $serviceSettingsVersionPara.Direction = [System.Data.ParameterDirection]::Input
            $serviceSettingsVersionPara.SqlDbType = [System.Data.SqlDbType]::BigInt
            if ($serviceSettingsVersion -eq $null)
            {
                $serviceSettingsVersion = [Int64]0
            }
            $serviceSettingsVersionPara.SqlValue = $serviceSettingsVersion

            $returnCodePara = New-Object System.Data.SqlClient.SqlParameter
            $returnCodePara.ParameterName = '@returnCode'
            $returnCodePara.Direction = [System.Data.ParameterDirection]::ReturnValue
            $returnCodePara.SqlDbType = [System.Data.SqlDbType]::Int
            $returnCodePara.SqlValue = $null

            try
            {
                Execute-SqlStoredProcedure $policyStoreConnStr $sqlProcedure @($objectIdPara, $serviceSettingsDataPara, $serviceSettingsVersionPara, $returnCodePara) | Out-Null
            }
            catch
            {
                ThrowAndLog ($_system_translations.ServiceSettingsWriteException -f $policyStoreConnStr, (Get-ExceptionString $_))
            }

            $returnCode = [int] ($returnCodePara.SqlValue)
            if ($returnCode -eq 0)
            {
                $msg = ($_system_translations.ServiceSettingsImported)
                Write-Output $msg
                Write-Verbose $msg
            }
            else
            {
                ThrowAndLog ($_system_translations.ServiceSettingsWriteError -f $policyStoreConnStr, $returnCode)
            }
        }

        # Import ADFS properties
        $parameters = @{
            "AutoCertificateRollover" = $adfsProperties.AutoCertificateRollover;
            "CertificateCriticalThreshold" = $adfsProperties.CertificateCriticalThreshold;
            "CertificateDuration" = $adfsProperties.CertificateDuration;
            "CertificateGenerationThreshold" = $adfsProperties.$CertificateGenerationThreshold;
            "CertificatePromotionThreshold" = $adfsProperties.CertificatePromotionThreshold;
            "CertificateRolloverInterval" = $adfsProperties.CertificateRolloverInterval;
            "CertificateThresholdMultiplier" = $adfsProperties.CertificateThresholdMultiplier;
        }

        Execute-Command -Command "Set-ADFSProperties" -Parameters $parameters

        Write-Progress -Activity $activity -Status $status -CurrentOperation ($_system_translations.ImportClaimDescription -f '*') -PercentComplete 8

        # Import all claim descriptions
        foreach ($claim in $claimDescriptions)
        {
            if ($claim -eq $null)
            {
                continue
            }

            $wmsg = $null
            $c = Get-ADFSClaimDescription -ClaimType $claim.ClaimType -WarningVariable wmsg
            Write-Output $wmsg

            if ($c)
            {
                $msg = ($_system_translations.SkipClaimDescription -f $claim.ClaimType)
                Write-Output $msg
                Write-Verbose $msg
            }
            else
            {
                $msg = ($_system_translations.ImportClaimDescription -f $claim.ClaimType)
                Write-Output $msg
                Write-Verbose $msg

                $parameters = @{
                    "ClaimType" = $claim.ClaimType;
                    "IsAccepted" = $claim.IsAccepted;
                    "IsOffered" = $claim.IsOffered;
                    "IsRequired" = $claim.$IsRequired;
                    "Name" = $claim.Name;
                    "Notes" = $claim.Notes;
                }
                Execute-Command -Command "Add-ADFSClaimDescription" -Parameters $parameters
            }
        }

        if ($deleteAll)
        {
            # Remove all relying parties and claims providers

            Write-Progress -Activity $activity -Status $status -CurrentOperation "Get-ADFSRelyingPartyTrust" -PercentComplete 9
            $wmsg = $null
            $rpAll = Get-ADFSRelyingPartyTrust -WarningVariable wmsg
            Write-Output $wmsg

            Write-Progress -Activity $activity -Status $status -CurrentOperation "Get-ADFSClaimsProviderTrust" -PercentComplete 10
            $wmsg = $null
            $cpAll = Get-ADFSClaimsProviderTrust -WarningVariable wmsg
            Write-Output $wmsg

            $totalNum = 0
            $currentNum = 0
            $base = 10

            # Count number of removals. Each removal has a weight of 1.
            if ($rpAll -ne $null)
            {
                $totalNum += $rpAll.Count
            }
            if ($cpAll -ne $null)
            {
                $totalNum += $cpAll.Count
            }

            # Count number of additions. Each addition has a weight of 2.
            if ($rpTrusts -ne $null)
            {
                $totalNum += $rpTrusts.Count * 2
            }
            if ($cpTrusts -ne $null)
            {
                $totalNum += $cpTrusts.Count * 2
            }

            if ($totalNum -eq 0)
            {
                $totalNum = 1
            }

            if ($rpAll -ne $null)
            {
                foreach ($rp in $rpAll)
                {
                    if ($rp -eq $null)
                    {
                        continue
                    }

                    # The DRS RP should not be removed
                    if (!(Check-DrsRelyingParty $rp))
                    {
                        Write-Progress -Activity $activity -Status $status -CurrentOperation "Remove-ADFSRelyingPartyTrust $($rp.Name)" -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
                        $wmsg = $null
                        Remove-ADFSRelyingPartyTrust -TargetName $rp.Name -WarningVariable wmsg | Out-Null
                        Write-Output $wmsg
                    }
                    $currentNum += 1
                }
            }

            if ($cpAll -ne $null)
            {
                foreach ($cp in $cpAll)
                {
                    if ($cp -eq $null)
                    {
                        continue
                    }

                    # The ADAuthority claims provider trust cannot be removed
                    if (!(Check-ADClaimsProvider $cp))
                    {
                        Write-Progress -Activity $activity -Status $status -CurrentOperation "Remove-ADFSClaimsProviderTrust $($cp.Name)" -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
                        $wmsg = $null
                        Remove-ADFSClaimsProviderTrust -TargetName $cp.Name -WarningVariable wmsg | Out-Null
                        Write-Output $wmsg
                    }
                    $currentNum += 1
                }
            }
        }
        else
        {
            $totalNum = 0
            $currentNum = 0
            $base = 10

            # Count number of additions and removals. Each removal has a weight of 1. Each addition has a weight of 2.
            if ($rpTrusts -ne $null)
            {
                $totalNum += $rpTrusts.Count
            }
            if ($cpTrusts -ne $null)
            {
                $totalNum += $cpTrusts.Count
            }
            $totalNum *= 3
            if ($totalNum -eq 0)
            {
                $totalNum = 1
            }

            # Remove selected relying parties and their claims
            foreach ($rp in $rpTrusts)
            {
                if ($rp -eq $null)
                {
                    continue
                }

                # The DRS RP should not be removed
                if (Check-DrsRelyingParty $rp)
                {
                    $currentNum += 1
                    continue
                }

                Write-Progress -Activity $activity -Status $status -CurrentOperation "Remove-ADFSRelyingPartyTrust $($rp.Name)" -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
                $currentNum += 1

                try
                {
                    $wmsg = $null
                    $obj = Get-ADFSRelyingPartyTrust -Name $rp.Name -WarningVariable wmsg
                    Write-Output $wmsg

                    if ($obj)
                    {
                        $wmsg = $null
                        Remove-ADFSRelyingPartyTrust -TargetRelyingParty $obj -WarningVariable wmsg | Out-Null
                        Write-Output $wmsg
                    }
                }
                catch
                {
                    Write-Output "Remove-ADFSRelyingPartyTrust: $($rp.Name)"
                    throw
                }
            }

            # Remove selected claims providers and their claims
            foreach ($cp in $cpTrusts)
            {
                if ($cp -eq $null)
                {
                    continue
                }

                # The ADAuthority claims provider cannot be modified
                if (Check-ADClaimsProvider $cp)
                {
                    $currentNum += 1
                    continue
                }

                Write-Progress -Activity $activity -Status $status -CurrentOperation "Remove-ADFSClaimsProviderTrust $($cp.Name)" -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
                $currentNum += 1

                try
                {
                    $wmsg = $null
                    $obj = Get-ADFSClaimsProviderTrust -Name $cp.Name -WarningVariable wmsg
                    Write-Output $wmsg

                    if ($obj)
                    {
                        $wmsg = $null
                        Remove-ADFSClaimsProviderTrust -TargetClaimsProviderTrust $obj -WarningVariable wmsg | Out-Null
                        Write-Output $wmsg
                    }
                }
                catch
                {
                    Write-Output "Remove-ADFSClaimsProviderTrust: $($cp.Name)"
                    throw
                }
            }
        }

        # Create relying parties
        foreach ($rp in $rpTrusts)
        {
            if ($rp -eq $null)
            {
                continue
            }

            # The DRS RP should not be removed
            if (Check-DrsRelyingParty $rp)
            {
                # Each addition has a weight of 2.
                $currentNum += 2
                continue
            }

            $msg = ($_system_translations.AddRelyingPartyTrust -f $rp.Name)
            Write-Output $msg
            Write-Progress -Activity $activity -Status $status -CurrentOperation $msg -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
            Write-Verbose $msg

            # Each addition has a weight of 2.
            $currentNum += 2

            $claimArray = [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]@()
            foreach ($c in $rp.ClaimsAccepted)
            {
                if ($c -eq $null)
                {
                    continue
                }

                $wmsg = $null
                $claim = Get-ADFSClaimDescription -ClaimType $c.ClaimType -WarningVariable wmsg
                Write-Output $wmsg

                if ($claim)
                {
                    $claimArray += $claim
                }
            }

            $samlEndpointArray = [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]@()
            foreach ($ep in $rp.SamlEndpoints)
            {
                if ($ep -eq $null)
                {
                    continue
                }

                try
                {
                    $wmsg = $null
                    $point = New-ADFSSamlEndpoint -Binding $ep.Binding -Protocol $ep.Protocol -Uri $ep.Location -Index $ep.Index -IsDefault $ep.IsDefault -ResponseUri $ep.ResponseLocation -WarningVariable wmsg
                    Write-Output $wmsg
                }
                catch
                {
                    Write-Output 'New-ADFSSamlEndpoint -Binding $ep.Binding -Protocol $ep.Protocol -Uri $ep.Location -Index $ep.Index -IsDefault $ep.IsDefault -ResponseUri $ep.ResponseLocation'
                    Write-Output $ep
                    throw
                }

                $samlEndpointArray += $point
            }

            $parameters = @{
                "Identifier" = $rp.Identifier;
                "Name" = $rp.Name;
                "AutoUpdateEnabled" = $rp.AutoUpdateEnabled;
                "ClaimAccepted" = $claimArray;
                "DelegationAuthorizationRules" = $rp.DelegationAuthorizationRules;
                "Enabled" = $rp.Enabled;
                "EncryptClaims" = $rp.EncryptClaims;
                "EncryptionCertificate" = $rp.EncryptionCertificate;
                "EncryptionCertificateRevocationCheck" = $rp.EncryptionCertificateRevocationCheck;
                "IsInternal" = $rp.IsInternal;
                "ImpersonationAuthorizationRules" = $rp.ImpersonationAuthorizationRules;
                "IssuanceAuthorizationRules" = $rp.IssuanceAuthorizationRules;
                "IssuanceTransformRules" = $rp.IssuanceTransformRules;
                "NotBeforeSkew" = $rp.NotBeforeSkew;
                "EnableJWT" = $rp.EnableJWT;
                "Notes" = $rp.Notes;
                "ProtocolProfile" = $rp.ProtocolProfile;
                "EncryptedNameIdRequired" = $rp.EncryptedNameIdRequired;
                "RequestSigningCertificate" = $rp.RequestSigningCertificate;
                "SamlEndpoint" = $samlEndpointArray;
                "SamlResponseSignature" = $rp.SamlResponseSignature;
                "SignatureAlgorithm" = $rp.SignatureAlgorithm;
                "SignedSamlRequestsRequired" = $rp.SignedSamlRequestsRequired;
                "SigningCertificateRevocationCheck" = $rp.SigningCertificateRevocationCheck;
                "TokenLifetime" = $rp.TokenLifetime;
                "WSFedEndpoint" = $rp.WSFedEndpoint;
                "AllowedAuthenticationClassReferences" = $rp.AllowedAuthenticationClassReferences;
                "ClaimsProviderName" = $rp.ClaimsProviderName;
                "AdditionalAuthenticationRules" = $rp.AdditionalAuthenticationRules;
                "AdditionalWSFedEndpoint" = $rp.AdditionalWSFedEndpoint;
                "AlwaysRequireAuthentication" = $rp.AlwaysRequireAuthentication;
                "AllowedClientTypes" = $rp.AllowedClientTypes;
                "IssueOAuthRefreshTokensTo" = $rp.IssueOAuthRefreshTokensTo;

                # MonitoringEnabled requires a valid metadata URL. Set it to $false first.
                "MonitoringEnabled" = $false
            }

            Execute-Command -Command "Add-ADFSRelyingPartyTrust" -Parameters $parameters

            if ($rp.MetadataUrl)
            {
                # Set meta data URL
                # Add-ADFSRelyingPartyTrust -MetadataURL <...> would fail if the URL cannot be accessed

                $parameters = @{
                    "TargetName" = $rp.Name;
                    "MetadataUrl" = $rp.MetadataUrl;
                    "MonitoringEnabled" = $rp.MonitoringEnabled;
                }

                Execute-Command -Command "Set-ADFSRelyingPartyTrust" -Parameters $parameters
            }
        }

        # Create claims providers
        foreach ($cp in $cpTrusts)
        {
            if ($cp -eq $null)
            {
                continue
            }

            # The ADAuthority claims provider cannot be modified
            if (Check-ADClaimsProvider $cp)
            {
                # Each addition has a weight of 2.
                $currentNum += 2
                continue
            }

            $msg = ($_system_translations.AddClaimsProviderTrust -f $cp.Name)
            Write-Output $msg
            Write-Progress -Activity $activity -Status $status -CurrentOperation $msg -PercentComplete ($currentNum / $totalNum * (100 - $base) + $base)
            Write-Verbose $msg

            # Each addition has a weight of 2.
            $currentNum += 2

            $claimArray = [Microsoft.IdentityServer.Management.Resources.ClaimDescription[]]@()
            foreach ($c in $cp.ClaimsOffered)
            {
                if ($c -eq $null)
                {
                    continue
                }

                $wmsg = $null
                $claim = Get-ADFSClaimDescription -ClaimType $c.ClaimType -WarningVariable wmsg
                Write-Output $wmsg

                if ($claim)
                {
                    $claimArray += $claim
                }
            }

            $samlEndpointArray = [Microsoft.IdentityServer.Management.Resources.SamlEndpoint[]]@()
            foreach ($ep in $cp.SamlEndpoints)
            {
                if ($ep -eq $null)
                {
                    continue
                }

                try
                {
                    $wmsg = $null
                    $point = New-ADFSSamlEndpoint -Binding $ep.Binding -Protocol $ep.Protocol -Uri $ep.Location -Index $ep.Index -IsDefault $ep.IsDefault -ResponseUri $ep.ResponseLocation -WarningVariable wmsg
                    Write-Output $wmsg
                }
                catch
                {
                    Write-Output 'New-ADFSSamlEndpoint -Binding $ep.Binding -Protocol $ep.Protocol -Uri $ep.Location -Index $ep.Index -IsDefault $ep.IsDefault -ResponseUri $ep.ResponseLocation'
                    Write-Output $ep
                    throw
                }

                $samlEndpointArray += $point
            }

            $parameters = @{
                "Identifier" = $cp.Identifier;
                "Name" = $cp.Name;
                "AcceptanceTransformRules" = $cp.AcceptanceTransformRules;
                "AllowCreate" = $cp.AllowCreate;
                "AutoUpdateEnabled" = $cp.AutoUpdateEnabled;
                "ClaimOffered" = $claimArray;
                "Enabled" = $cp.Enabled;
                "EncryptionCertificate" = $cp.EncryptionCertificate;
                "EncryptionCertificateRevocationCheck" = $cp.EncryptionCertificateRevocationCheck;
                "EncryptedNameIdRequired" = $cp.EncryptedNameIdRequired;
                "Notes" = $cp.Notes;
                "ProtocolProfile" = $cp.ProtocolProfile;
                "RequiredNameIdFormat" = $cp.RequiredNameIdFormat;
                "SamlAuthenticationRequestIndex" = $cp.SamlAuthenticationRequestIndex;
                "SamlAuthenticationRequestParameters" = $cp.SamlAuthenticationRequestParameters;
                "SamlAuthenticationRequestProtocolBinding" = $cp.SamlAuthenticationRequestProtocolBinding;
                "SamlEndpoint" = $samlEndpointArray;
                "SignatureAlgorithm" = $cp.SignatureAlgorithm;
                "SignedSamlRequestsRequired" = $cp.SignedSamlRequestsRequired;
                "SigningCertificateRevocationCheck" = $cp.SigningCertificateRevocationCheck;
                "TokenSigningCertificate" = $cp.TokenSigningCertificates;
                "OrganizationalAccountSuffix" = $cp.OrganizationalAccountSuffix;
                "WSFedEndpoint" = $cp.WSFedEndpoint;

                # MonitoringEnabled requires a valid metadata URL. Set it to $false first.
                "MonitoringEnabled" = $false
            }

            Execute-Command -Command "Add-ADFSClaimsProviderTrust" -Parameters $parameters

            if ($cp.MetadataUrl)
            {
                # Set meta data URL
                # Add-ADFSClaimsProviderTrust -MetadataURL <...> would fail if the URL cannot be accessed

                $parameters = @{
                    "TargetName" = $cp.Name;
                    "MetadataUrl" = $cp.MetadataUrl;
                    "MonitoringEnabled" = $cp.MonitoringEnabled
                }

                Execute-Command -Command "Set-ADFSClaimsProviderTrust" -Parameters $parameters
            }
        }
    }
    catch
    {
        if ($isRemote -eq $true)
        {
            # If running on a remote PS session, output the error record we caught on the remote machine,
            # because the error record we caught on the remote machine contains more information than the
            # error record we caught on the local machine later.
            Write-Output $_
        }

        throw
    }
    finally
    {
        if ($ImpersonationContext)
        {
            $ImpersonationContext.Undo()
            $ImpersonationContext.Dispose()
            $ImpersonationContext = $null
        }
    }
}

Function Select-Trusts
{
    Param (
        [string[]] $rpId,
        [string[]] $cpId,
        [string[]] $rpName,
        [string[]] $cpName,
        [System.Object[]]$rpTrusts,
        [System.Object[]]$cpTrusts
    )

    Process
    {
        $rpNameHash = @{}
        foreach ($name in $rpName)
        {
            if ($name -ne $null)
            {
                $rpNameHash[$name] = $true
            }
        }

        $rpIdHash = @{}
        foreach ($id in $rpId)
        {
            if ($id -ne $null)
            {
                $rpIdHash[$id] = $true
            }
        }

        $cpNameHash = @{}
        foreach ($name in $cpName)
        {
            if ($name -ne $null)
            {
                $cpNameHash[$name] = $true
            }
        }

        $cpIdHash = @{}
        foreach ($id in $cpId)
        {
            if ($id -ne $null)
            {
                $cpIdHash[$id] = $true
            }
        }

        $rpSelected = @()
        foreach ($rp in $rpTrusts)
        {
            if ($rp -eq $null)
            {
                continue
            }

            if ($rpNameHash[$rp.Name])
            {
                $rpSelected += $rp
            }
            else
            {
                foreach ($id in $rp.Identifier)
                {
                    if (($id -ne $null) -and ($rpIdHash[$id] -ne $null))
                    {
                        $rpSelected += $rp
                        break
                    }
                }
            }
        }

        $cpSelected = @()
        foreach ($cp in $cpTrusts)
        {
            if ($cp -eq $null)
            {
                continue
            }

            if ($cpNameHash[$cp.Name])
            {
                $cpSelected += $cp
            }
            else
            {
                foreach ($id in $cp.Identifier)
                {
                    if (($id -ne $null) -and ($cpIdHash[$id] -ne $null))
                    {
                        $cpSelected += $cp
                        break
                    }
                }
            }
        }

        $result = New-Object PSObject -Property @{
            'rpSelected' = $rpSelected;
            'cpSelected' = $cpSelected
        }

        Write-Output $result
    }
}

<#################################################################
 # Check the import path
 ################################################################>
Function Check-Path
{
    Param()

    Process
    {
        if ((Test-Path -Path $Path -PathType Container -IsValid) -eq $false)
        {
            throw ($_system_translations.InvalidPathError -f $Path)
        }
        elseif ((Test-Path -Path $Path -PathType Container) -eq $false)
        {
            throw ($_system_translations.PathNotFoundError -f $Path)
        }
        elseif (!((Get-Item -Path $Path) -is [System.IO.DirectoryInfo]))
        {
            throw ($_system_translations.InvalidPathError -f $Path)
        }
    }
}

Function ThrowAndLog
{
    Param(
        [string] $logPath,
        [string] $obj
        )

    Process
    {
        Add-Content -Path $logPath -Value ($_system_translations.ErrorLog -f $obj) | Out-Null
        Add-Content -Path $logPath -Value ($_system_translations.MoreHelpMessage -f $HelpFwLink) | Out-Null
        throw ("{0}`n{1}" -f $obj, ($_system_translations.MoreHelpMessage -f $HelpFwLink))
    }
}

<#################################################################
 # Parse the summary file.
 # Return a script block that can parse the files to be imported
 # based on the versions of the files.
 ################################################################>
Function Parse-Summary
{
    Param([string] $logPath)

    Process
    {
        $summaryFile = "Summary.xml"
        [System.IO.DirectoryInfo]$folder = (Get-Item -Path $Path)
        $summaryPath = $folder.FullName + '\' + $summaryFile

        $summary = [xml] (Get-Content -Path $summaryPath)
        $root = $summary.DocumentElement

        if ($root.LocalName -ne "AdfsMigrationTool")
        {
            ThrowAndLog $logPath ($_system_translations.SummaryInvalidElement -f $summaryFile, $root.LocalName)
        }

        $att = "Version"
        if (($root.HasAttribute($att)) -eq $false)
        {
            ThrowAndLog $logPath ($_system_translations.SummaryRequiredAttributeNotFound -f $summaryFile, $root.LocalName, $att)
        }

        $toolVersion = $root.GetAttribute($att)

        $ele = "STS"
        $e = $root.SelectSingleNode($ele)
        if (!$e)
        {
            ThrowAndLog $logPath ($_system_translations.SummaryRequiredElementNotFound -f $summaryFile, $root.LocalName, $ele)
        }

        $att = "Version"
        if (($e.HasAttribute($att)) -eq $false)
        {
            ThrowAndLog $logPath ($_system_translations.SummaryRequiredAttributeNotFound -f $summaryFile, $e.LocalName, $att)
        }

        $stsVersion = $e.GetAttribute($att)

        if ($toolVersion -eq "1.0")
        {
            if (($stsVersion -eq "2.0") -or `
                ($stsVersion -eq "2.1") -or `
                ($stsVersion -eq "3.0"))
            {
                Write-Output $FileParserV1
            }
            else
            {
                ThrowAndLog $logPath ($_system_translations.ImportStsVersionNotSupported -f $stsVersion)
            }
        }
        else
        {
            ThrowAndLog $logPath ($_system_translations.ImportToolVersionNotSupported -f $toolVersion)
        }
    }
}

<#################################################################
 # Create an empty log file. If the file already exists, remove
 # its content.
 #
 # Return the full path of the log file.
 ################################################################>
Function Create-LogFile
{
    Param()

    Process
    {
        if ($LogPath)
        {
            $filePath = $LogPath
        }
        else
        {
            $fileName = "import.log"
            [System.IO.DirectoryInfo]$folder = (Get-Item -Path $Path)
            $filePath = $folder.FullName + '\' + $fileName
        }

        New-Item $filePath -ItemType File -Force | Out-Null
        Write-Output $filePath
    }
}

# Execute Main
Main
<#############################################################
 #  Copyright (c) Microsoft Corporation.  All rights reserved.
 ############################################################>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium", DefaultParameterSetName="Default")]
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
$ToolVersion = '1.0'
$HelpFwLink = 'http://go.microsoft.com/fwlink/?LinkId=294108'


Function Main
{
    Begin
    {
        ## this is to support localization
        Import-LocalizedData -BindingVariable _system_translations -fileName Migrate-FederationConfiguration.psd1

        $activity = $_system_translations.ExportConfirmMessageCaption
        $ErrorActionPreference = 'Stop'
    }
    
    Process
    {
        if (Prepare-Folder -eq $true)
        {
            $summary = Create-Summary

            if ($ComputerName)
            {
                $status = $_system_translations.ExportConfigurations -f $ComputerName
            }
            else
            {
                $status = $_system_translations.ExportConfigurations -f $env:ComputerName
            }

            Write-Progress -Activity $activity -Status $status -CurrentOperation $status -PercentComplete 0
            Write-Host $status | Out-Null

            $arguments = @($RelyingPartyTrustIdentifier, $ClaimsProviderTrustIdentifier, $RelyingPartyTrustName, $ClaimsProviderTrustName, $CertificatePassword, $Force, $_system_translations, $Credential, $VerbosePreference)
            if ($ComputerName)
            {
                if ($Credential)
                {
                    $configData = Invoke-Command -ScriptBlock $GetConfig -ArgumentList $arguments -ComputerName $ComputerName -Credential $Credential
                }
                else
                {
                    $configData = Invoke-Command -ScriptBlock $GetConfig -ArgumentList $arguments -ComputerName $ComputerName
                }
            }
            else
            {
                $configData = Invoke-Command -ScriptBlock $GetConfig -ArgumentList $arguments
            }

            $rpTrusts = $configData.rpTrusts
            $cpTrusts = $configData.cpTrusts
            $claims = $configData.claimDescriptions
            $certificates = $configData.certificates
            $adfsProperties = $configData.adfsProperties
            $attributeStores = $configData.attrStores
            $serviceAccount = $configData.svcAcct

            # If the $GetConfig script block is invoked on a remote computer, the relying party objects will be deserailized.
            # It is possible that the content of the claim descriptions are not restored during deserialization.
            # Only the type of the claim descriptions are stored, e.g., the value of $rpTrusts[0].ClaimsAccepted[0] would be
            # "Microsoft.IdentityServer.PowerShell.Resources.ClaimDescription".
            #
            # If the script block is invoked locally, we won't have this problem. The value of $rpTrusts[0].ClaimsAccepted[0]
            # would be of type ClaimDescription.
            #
            # SamlEndpoints are similar.
            # We need to restore claim descriptions and saml endpoints here.

            # We can check if the objects are deserialized by check the type of any value in ClaimsAccepted or SamlEndpoints.
            # If the type is ClaimDescription, then it is not deserialized.
            # If the type is String, then it is deserialized.

            $deserialized = $false
            $checked = $false
            foreach ($rp in $rpTrusts)
            {
                if ($rp -ne $null)
                {
                    foreach ($c in $rp.ClaimsAccepted)
                    {
                        if ($c -ne $null)
                        {
                            if ($c -is [System.String])
                            {
                                $deserialized = $true
                            }

                            $checked = $true
                            break
                        }
                    }

                    if ($checked)
                    {
                        # checking one claim description object is good enough
                        break
                    }

                    foreach ($se in $rp.SamlEndpoints)
                    {
                        if ($se -ne $null)
                        {
                            if ($se -is [System.String])
                            {
                                $deserialized = $true
                            }

                            $checked = $true
                            break
                        }
                    }
                }

                if ($checked)
                {
                    break
                }
            }

            if ($deserialized)
            {
                # Restore claim descriptions and saml endpoints using the hash tables returned

                Write-Progress -Activity $activity -Status $status -CurrentOperation 'Deserialized.ClaimDescription' -PercentComplete 65

                $totalNum = 0
                $currentNum = 0
                $base = 65
                $totalWeight = 5

                if ($rpTrusts -ne $null)
                {
                    $totalNum += $rpTrusts.Count
                }
                if ($cpTrusts -ne $null)
                {
                    $totalNum += $cpTrusts.Count
                }

                if ($totalNum -eq 0)
                {
                    $totalNum = 1
                }

                $rpClaimsHash = $configData.rpClaimsHash
                $rpSamlEnpointsHash = $configData.rpSamlEnpointsHash
                foreach ($rp in $rpTrusts)
                {
                    if ($rp -ne $null)
                    {
                        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Deserialized.ClaimDescription' -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                        $currentNum += 1
                        $rp.ClaimsAccepted = $rpClaimsHash[$rp.Name]
                        $rp.SamlEndpoints = $rpSamlEnpointsHash[$rp.Name]
                    }
                }

                $cpClaimsHash = $configData.cpClaimsHash
                $cpSamlEnpointsHash = $configData.cpSamlEnpointsHash
                foreach ($cp in $cpTrusts)
                {
                    if ($cp -ne $null)
                    {
                        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Deserialized.ClaimDescription' -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                        $currentNum += 1
                        $cp.ClaimsOffered = $cpClaimsHash[$cp.Name]
                        $cp.SamlEndpoints = $cpSamlEnpointsHash[$cp.Name]
                    }
                }
            }

            Write-Progress -Activity $activity -Status $status -CurrentOperation 'Test-CliXml' -PercentComplete 70

            $totalNum = 0
            $currentNum = 0
            $base = 70
            $totalWeight = 20

            if ($rpTrusts -ne $null)
            {
                $totalNum += $rpTrusts.Count
            }
            if ($cpTrusts -ne $null)
            {
                $totalNum += $cpTrusts.Count
            }
            if ($claims -ne $null)
            {
                $totalNum += $claims.Count
            }

            if ($totalNum -eq 0)
            {
                $totalNum = 1
            }

            [System.IO.DirectoryInfo]$folder = (Get-Item -Path $Path)

            $testPath = $folder.FullName + '\object.xml'

            # Test RPs to make sure their exports can be imported
            foreach ($obj in $rpTrusts)
            {
                if ($obj -ne $null)
                {
                    Write-Progress -Activity $activity -Status $status -CurrentOperation 'Test-CliXml RelyingPartyTrust' -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                    $currentNum += 1
                    Test-CliXml $obj 'RelyingPartyTrust' $testPath
                }
            }

            # Test CPs to make sure their exports can be imported
            foreach ($obj in $cpTrusts)
            {
                if ($obj -ne $null)
                {
                    Write-Progress -Activity $activity -Status $status -CurrentOperation 'Test-CliXml ClaimsProviderTrust' -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                    $currentNum += 1
                    Test-CliXml $obj 'ClaimsProviderTrust' $testPath
                }
            }

            # Test claim descriptions to make sure their exports can be imported
            foreach ($obj in $claims)
            {
                if ($obj -ne $null)
                {
                    Write-Progress -Activity $activity -Status $status -CurrentOperation 'Test-CliXml ClaimDescription' -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                    $currentNum += 1
                    Test-CliXml $obj 'ClaimDescription' $testPath
                }
            }

            Write-Progress -Activity $activity -Status $status -CurrentOperation ($_system_translations.ExportSavingFiles) -PercentComplete 90

            Write-Host ($_system_translations.ExportSavingFiles) | Out-Null

            $rpPath = $folder.FullName + '\rp.xml'
            Export-Clixml -Path $rpPath -InputObject $rpTrusts -Force | Out-Null

            $cpPath = $folder.FullName + '\cp.xml'
            Export-Clixml -Path $cpPath -InputObject $cpTrusts -Force | Out-Null

            $claimPath = $folder.FullName + '\claim.xml'
            Export-Clixml -Path $claimPath -InputObject $claims -Force | Out-Null
            
            $certPath = $folder.FullName + '\cert.xml'
            Export-Clixml -Path $certPath -InputObject $certificates -Force | Out-Null

            $propertiesPath = $folder.FullName + '\properties.xml'
            Export-Clixml -Path $propertiesPath -InputObject $adfsProperties -Force | Out-Null

            $summaryPath = $folder.FullName + '\summary.xml'
            $summary.Save($summaryPath) | Out-Null

            Write-Host
            Write-Host ($_system_translations.ExportFinished -f $folder.FullName) | Out-Null
            Write-Host ($_system_translations.TrustExported -f '') | Out-Null

            $missingEncryptionTokens = @()
            if (($certificates -ne $null) -and ($certificates.EncryptionToken -ne $null) -and ($certificates.EncryptionToken.AdditionalEncryptionTokens -ne $null))
            {
                foreach ($c in $certificates.EncryptionToken.AdditionalEncryptionTokens)
                {
                    if ($c -ne $null)
                    {
                        if ((($c.EncryptedPfx -ne $null) -and ($c.EncryptedPfx.Length -gt 0)) -or (($c.ExportedPfx -ne $null) -and ($c.ExportedPfx.Length -gt 0)))
                        {
                            Write-Host ($_system_translations.CertExported -f '', $_system_translations.EncryptionToken, $c.FindValue) | Out-Null
                        }
                        else
                        {
                            $missingEncryptionTokens += $c
                        }
                    }
                }
            }

            $missingSigningTokens = @()
            if (($certificates -ne $null) -and ($certificates.SigningToken -ne $null) -and ($certificates.SigningToken.AdditionalSigningTokens -ne $null))
            {
                foreach ($c in $certificates.SigningToken.AdditionalSigningTokens)
                {
                    if ($c -ne $null)
                    {
                        if ((($c.EncryptedPfx -ne $null) -and ($c.EncryptedPfx.Length -gt 0)) -or (($c.ExportedPfx -ne $null) -and ($c.ExportedPfx.Length -gt 0)))
                        {
                            Write-Host ($_system_translations.CertExported -f '', $_system_translations.SigningToken, $c.FindValue) | Out-Null
                        }
                        else
                        {
                            $missingSigningTokens += $c
                        }
                    }
                }
            }

            Write-Host
            Write-Host ($_system_translations.ImportConfigInfo -f 'Import-FederationConfiguration') | Out-Null
            Write-Host ($_system_translations.TargetFarmRequirement -f $adfsProperties.HostName, $serviceAccount) | Out-Null
            Write-Host

            if (($missingEncryptionTokens.Count -gt 0) -or ($missingSigningTokens.Count -gt 0))
            {
                Write-Host $_system_translations.CertNotExportedWarning
                Write-Host

                foreach ($c in $missingEncryptionTokens)
                {
                    if ($c -ne $null)
                    {
                        Write-Host ($_system_translations.CertTypeInfo -f '', $_system_translations.EncryptionToken)
                        Write-Host ($_system_translations.ThumbprintInfo -f '', $c.FindValue)
                        Write-Host ($_system_translations.CertStoreInfo -f '', $c.StoreLocationValue, $c.StoreNameValue)
                        Write-Host
                    }
                }

                foreach ($c in $missingSigningTokens)
                {
                    if ($c -ne $null)
                    {
                        Write-Host ($_system_translations.CertTypeInfo -f '', $_system_translations.SigningToken)
                        Write-Host ($_system_translations.ThumbprintInfo -f '', $c.FindValue)
                        Write-Host ($_system_translations.CertStoreInfo -f '', $c.StoreLocationValue, $c.StoreNameValue)
                        Write-Host
                    }
                }
            }

            if ($attributeStores -ne $null)
            {
                $storeWarningShown = $false
                foreach ($store in $attributeStores)
                {
                    if (($store -ne $null) -and ($store.StoreClassification -ne 'ActiveDirectory'))
                    {
                        if ($storeWarningShown -eq $false)
                        {
                            Write-Host ($_system_translations.AttrStoreWarning)
                            $storeWarningShown = $true
                        }
                        Write-Host ($_system_translations.AttrStoreName -f '', $store.Name)
                    }
                }

                if ($storeWarningShown -eq $true)
                {
                    Write-Host
                }
            }

            Write-Host ($_system_translations.MoreHelpMessage -f $HelpFwLink)
            Write-Host

            Write-Progress -Activity $activity -Status ($_system_translations.ExportFinished) -PercentComplete 100 -Completed

            Write-Output $folder.FullName
        }
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
 # Test an object using Export-CliXml and Import-CliXml
 ################################################################>
Function Test-CliXml
{
    Param(
        $obj,
        [string] $type,
        [string] $path
    )

    Process
    {
        try
        {
            Export-Clixml -Path $path -InputObject $obj -Force | Out-Null
        }
        catch
        {
            throw ($_system_translations.TestExportError -f $type, $obj.Name, $path, (Get-ExceptionString $_))
        }

        try
        {
            Import-Clixml -Path $path | Out-Null
        }
        catch
        {
            throw ($_system_translations.TestImportError -f $type, $obj.Name, $path, (Get-ExceptionString $_))
        }
    }
}

$GetConfig = {
    
    Param (
        [string[]] $rpId,
        [string[]] $cpId,
        [string[]] $rpName,
        [string[]] $cpName,
        [System.Security.SecureString] $certPassword,
        [bool] $forced,
        $_system_translations,
        [System.Management.Automation.PSCredential] $credential,
        $verbose
    )

    $ErrorActionPreference = 'Stop'
    $VerbosePreference = $verbose

    $ImpersonationContext = [System.Security.Principal.WindowsImpersonationContext]$null
    $activity = $_system_translations.ExportConfirmMessageCaption
    $status = $_system_translations.ExportConfigurations -f $env:ComputerName

    <#################################################################
     # Load native functions
     ################################################################>
    Function Add-MigrationUtilites
    {
        Param()

        Process
        {
            $signature = @'

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
        Add-Type -MemberDefinition $signature -Name ExportUtilities -Namespace Microsoft.IdentityServer.Migration -UsingNamespace Microsoft.Win32.SafeHandles -PassThru
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
                $ret = [Microsoft.IdentityServer.Migration.ExportUtilities]::LogonUser($user, $domain, $password, [Microsoft.IdentityServer.Migration.ExportUtilities]::LOGON32_LOGON_NETWORK_CLEARTEXT, [Microsoft.IdentityServer.Migration.ExportUtilities]::LOGON32_PROVIDER_DEFAULT, [ref] $token)
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
                    [Microsoft.IdentityServer.Migration.ExportUtilities]::CloseHandle($token) | Out-Null
                }

                throw
            }
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
                throw ($_system_translations.ConfigFileNotFoundError -f $configFilePath)
            }
            else
            {
                $configFile = [xml] (Get-Content -Path $configFilePath)
                if ($configFile -eq $null)
                {
                    throw ($_system_translations.ConfigFileReadError -f $configFilePath)
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
                        throw ($_system_translations.ConnectionStringReadError -f $configFilePath)
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
     # Compare two secure strings
     ################################################################>
    Function Compare-SecureString
    {
        Param(
            [System.Security.SecureString] $left,
            [System.Security.SecureString] $right
            )

        Process
        {
            $result = $false

            if (($left.Length -eq 0) -and ($right.Length -eq 0))
            {
                $result = $true
            }
            elseif ($left.Length -eq $right.Length)
            {
                $bstr1 = $null
                $bstr2 = $null
                try
                {
                    $bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($left)
                    $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($right)
                    $tmp1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr1)
                    $tmp2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr2)
                    $result = ($tmp1 -ceq $tmp2)
                }
                finally
                {
                    if ($bstr1 -ne $null)
                    {
                        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr1)
                    }
                    if ($bstr2 -ne $null)
                    {
                        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
                    } 
                }
            }

            Write-Output $result
        }
    }

    <#################################################################
     # Parse a Certificate Refrence from SeviceSettingsData
     ################################################################>
    Function Get-CertificateFromServiceSettingsXml
    {
        Param(
            [System.Xml.XmlElement] $cert,
            $svcCerts,
            [bool] $exportPfx,
            [ref] $certPasswordRef,
            [bool] $forced
            )

        Process
        {
            if ($cert -ne $null)
            {
                $properties = @{'StoreNameValue' = $cert.StoreName; 'StoreLocationValue' = $cert.StoreLocation; 'X509FindTypeValue' = $cert.X509FindType; 'FindValue' = $cert.FindValue; 'RawCertificate' = $cert.RawCertificate; 'EncryptedPfx' = $cert.EncryptedPfx }

                if (($exportPfx -eq $true) -and ($cert.EncryptedPfx -eq $null))
                {
                    # The certificate is in local store. Try exporting it into pfx.
                    $svcCert = $svcCerts |? {$_.Thumbprint -eq $cert.FindValue}

                    if ($svcCert -ne $null)
                    {
                        if (($certPasswordRef.Value -eq $null) -or ($certPasswordRef.Value.Length -eq 0))
                        {
                            # The password is not specified or empty
                            if ($forced -eq $true)
                            {
                                # Output is suppressed
                                throw ($_system_translations.CertificatePasswordError)
                            }
                            else
                            {
                                $firstTime = $true
                                while (($certPasswordRef.Value -eq $null) -or ($certPasswordRef.Value.Length -eq 0))
                                {
                                    # Prompting the user to enter a non-empty password
                                    $p1 = $null
                                    if ($firstTime)
                                    {
                                        $prompt = ($_system_translations.ExportCertificatePasswordPrompt)
                                    }
                                    else
                                    {
                                        $prompt = ($_system_translations.MismatchedExportCertificatePasswordPrompt -f ($_system_translations.ExportCertificatePasswordPrompt))
                                    }
                                    while (($p1 -eq $null) -or ($p1.Length -eq 0))
                                    {
                                        $p1 = Read-Host -Prompt $prompt -AsSecureString
                                    }

                                    # Prompting the user to confirm the password
                                    $p2 = $null
                                    while (($p2 -eq $null) -or ($p2.Length -eq 0))
                                    {
                                        $p2 = Read-Host -Prompt ($_system_translations.ComfirmExportCertificatePasswordPrompt) -AsSecureString
                                    }

                                    # Compare user inputs
                                    $matched = (Compare-SecureString $p1 $p2)
                                    if ($matched -eq $true)
                                    {
                                        $certPasswordRef.Value = $p1
                                    }
                                    $firstTime = $flase
                                }
                            }
                        }

                        if (($certPasswordRef.Value -ne $null) -and ($certPasswordRef.Value.Length -gt 0))
                        {
                            $exportedPfx = $null
                            try
                            {
                                $exportedPfx = $svcCert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $certPasswordRef.Value)
                            }
                            catch
                            {
                                Write-Warning ($_system_translations.ExportCertificateWarning -f $svcCert.CertificateType, $svcCert.Thumbprint, $svcCert.StoreLocation, $svcCert.StoreName)
                                Write-Verbose $_
                            }
                            
                            if ($exportedPfx -ne $null)
                            {
                                $encodedPfx = [System.Convert]::ToBase64String($exportedPfx)
                                $properties.Add('ExportedPfx', $encodedPfx)
                            }
                        }
                    }
                }

                $certRef = New-Object PSObject -Property $properties

                Write-Output $certRef
            }
        }
    }

    <#################################################################
     # Parse ADFS certificates refrences from SeviceSettingsData using CertificateType
     ################################################################>
    Function Get-AdfsCertificatesFromServiceSettingsXml
    {
        Param(
            [xml] $serviceSettingsXml,
            [string] $certificateType,
            [ref] $certPasswordRef,
            [bool] $forced
            )

        Process
        {
            $svcCerts = $null
            $primaryTag = $null
            $additionalTag = $null

            $svcCerts = Get-AdfsCertificate -CertificateType $certificateType

            switch ($certificateType)
            {
                'Token-Decrypting'
                {
                    $primaryTag = 'EncryptionToken'
                    $additionalTag = 'AdditionalEncryptionTokens'
                }

                'Token-Signing'
                {
                    $primaryTag = 'SigningToken'
                    $additionalTag = 'AdditionalSigningTokens'
                }

                default { throw "Unsupported certificate type: '{0}'" -f $certificateType }
            }

            $additionalCerts = [PSObject[]] @()
            $primaryCert = [PSObject] $null
            
            if (($svcCerts -ne $null) -and ($primaryTag -ne $null) -and ($additionalTag -ne $null))
            {
                # Export additional certificates
                foreach ($cert in $serviceSettingsXml.SelectNodes("/ServiceSettingsData/SecurityTokenService/$additionalTag/Token"))
                {
                    if ($cert -ne $null)
                    {
                        $certRef = Get-CertificateFromServiceSettingsXml $cert $svcCerts $true $certPasswordRef $forced
                        if ($certRef -ne $null)
                        {
                            $additionalCerts += $certRef
                        }
                    }
                }

                # Export primary cert
                $cert = $null
                $cert = $serviceSettingsXml.SelectSingleNode("/ServiceSettingsData/SecurityTokenService/$primaryTag")
                if ($cert -ne $null)
                {
                    # No need to export the primary cert's pfx because it has already been exported in additional certs
                    $certRef = Get-CertificateFromServiceSettingsXml $cert $svcCerts $false $certPasswordRef $forced
                    if ($certRef -ne $null)
                    {
                        $primaryCert = $certRef
                    }
                }

                $result = New-Object PSObject -Property @{ "$additionalTag" = $additionalCerts; "$primaryTag" = $primaryCert }
                Write-Output $result
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
     # Processing starts
     ################################################################>

    try
    {
        $ErrorActionPreference = 'Stop'

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

        <#################################################################
         # Load ADFS snapin or modules
         ################################################################>
        $snapin = Get-PSSnapin | Where {$_.Name -eq "Microsoft.Adfs.PowerShell"}
        if (!$snapin)
        {
            $availableSnapin = Get-PSSnapin -Registered | Where {$_.Name -eq "Microsoft.Adfs.PowerShell"}
            if ($availableSnapin -ne $null)
            {
                Add-PSSnapin Microsoft.Adfs.PowerShell | Out-Null
            }
            else
            {
                $adfsModule = Get-Module -ListAvailable | Where {$_.Name -eq "ADFS"}
                if ($adfsModule -ne $null)
                {
                    Import-Module ADFS
                }
                else
                {
                    Add-PSSnapin Microsoft.Adfs.PowerShell | Out-Null
                }
            }
        }

        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Get-ADFSProperties' -PercentComplete 5

        <#################################################################
        # Read certificates from the configuration database
        ################################################################>
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
                throw ($_system_translations.ServiceSettingsReadException -f $policyStoreConnStr, (Get-ExceptionString $_))
            }

            if (($dataRows -eq $null) -or ($dataRows[0] -ne 1) -or ($dataRows[1] -eq $null))
            {
                throw ($_system_translations.ServiceSettingsReadError -f $policyStoreConnStr)
            }
            else
            {
                $serviceSettingsData = [xml] ($dataRows[1].ServiceSettingsData)
                if ($serviceSettingsData -eq $null)
                {
                    throw ($_system_translations.ServiceSettingsDataError)
                }
            }
        }
        if ($serviceSettingsData -ne $null)
        {
            $EncryptionToken = Get-AdfsCertificatesFromServiceSettingsXml $serviceSettingsData 'Token-Decrypting' ([ref] $certPassword) $forced
            $SigningToken = Get-AdfsCertificatesFromServiceSettingsXml $serviceSettingsData 'Token-Signing' ([ref] $certPassword) $forced
            $dkmSettings = $serviceSettingsData.serviceSettingsData.PolicyStore.DkmSettings
            if ($dkmSettings -ne $null)
            {
                $dkm = New-Object PSObject -Property @{'Enabled' = $dkmSettings.Enabled; 'Group' = $dkmSettings.Group; 'ContainerName' = $dkmSettings.ContainerName}
            }
        }

        $certificates = New-Object PSObject -Property @{'EncryptionToken' = $EncryptionToken; 'SigningToken' = $SigningToken; 'DkmSettings' = $dkm}

        <#################################################################
        # Read ADFS properties
        ################################################################>
        $adfsProperties = Get-ADFSProperties

        <#################################################################
        # Read ADFS attribute stores
        ################################################################>
        $attrStores = Get-ADFSAttributeStore
        if ($attrStores -eq $null)
        {
            $attrStores = @()
        }

        <#################################################################
        # Read RP trusts and CP trusts
        ################################################################>
        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Get-ADFSRelyingPartyTrust' -PercentComplete 10

        #$rpTrusts = [Microsoft.IdentityServer.PowerShell.Resources.RelyingPartyTrust[]]@()
        $rpTrusts = @()

        if ($rpId)
        {
            $rpTrusts = Get-ADFSRelyingPartyTrust -Identifier $rpId
        }
        elseif ($rpName)
        {
            $rpTrusts = Get-ADFSRelyingPartyTrust -Name $rpName
        }
        else
        {
            $rpTrusts = Get-ADFSRelyingPartyTrust
        }

        if ($rpTrusts -eq $null)
        {
            #$rpTrusts = [Microsoft.IdentityServer.PowerShell.Resources.RelyingPartyTrust[]]@()
            $rpTrusts = @()
        }

        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Get-ADFSClaimsProviderTrust' -PercentComplete 25

        #$cpTrusts = [Microsoft.IdentityServer.PowerShell.Resources.ClaimsProviderTrust[]]@()
        $cpTrusts =@()

        if ($cpId)
        {
            $cpTrusts = Get-ADFSClaimsProviderTrust -Identifier $cpId
        }
        elseif ($cpName)
        {
            $cpTrusts = Get-ADFSClaimsProviderTrust -Name $cpName
        }
        else
        {
            $cpTrusts = Get-ADFSClaimsProviderTrust
        }

        if ($cpTrusts -eq $null)
        {
            #$cpTrusts = [Microsoft.IdentityServer.PowerShell.Resources.ClaimsProviderTrust[]]@()
            $cpTrusts = @()
        }

        <#################################################################
        # If this script block is invoked on a remote computer, the claim descriptions and SAML endpoints in the
        # trust objects returned could be lost during deserialization.
        #
        # For example, rpTrusts[0].ClaimsAccepted[0] is of type ClaimDescription. But after deserialization, the
        # value could become a string which is the value returned by rpTrusts[0].ClaimsAccepted[0].ToString().
        #
        # In this case, the content of the claim description and SAML endpoints would be lost during deserialization.
        # In order to preserve them, we return separate hash tables for claims and endpoints.
        ################################################################>

        Write-Progress -Activity $activity -Status $status -CurrentOperation 'ClaimDescription' -PercentComplete 40

        $totalNum = 0
        $currentNum = 0
        $base = 40
        $totalWeight = 10

        if ($rpTrusts -ne $null)
        {
            $totalNum += $rpTrusts.Count
        }
        if ($cpTrusts -ne $null)
        {
            $totalNum += $cpTrusts.Count
        }

        if ($totalNum -eq 0)
        {
            $totalNum = 1
        }

        $rpClaimsHash = @{}
        $cpClaimsHash = @{}
        $rpSamlEnpointsHash = @{}
        $cpSamlEnpointsHash = @{}

        foreach ($rp in $rpTrusts)
        {
            if ($rp -ne $null)
            {
                Write-Progress -Activity $activity -Status $status -CurrentOperation "ClaimDescription" -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                $currentNum += 1
                $rpClaimsHash[$rp.Name] = $rp.ClaimsAccepted
                $rpSamlEnpointsHash[$rp.Name] = $rp.SamlEndpoints
            }
        }

        foreach ($cp in $cpTrusts)
        {
            if ($cp -ne $null)
            {
                Write-Progress -Activity $activity -Status $status -CurrentOperation "ClaimDescription" -PercentComplete ($currentNum / $totalNum * $totalWeight + $base)
                $currentNum += 1
                $cpClaimsHash[$cp.Name] = $cp.ClaimsOffered
                $cpSamlEnpointsHash[$cp.Name] = $cp.SamlEndpoints
            }
        }

        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Get-ADFSClaimDescription' -PercentComplete 50

        #$claimDescriptions = [Microsoft.IdentityServer.PowerShell.Resources.ClaimDescription[]]@()
        $claimDescriptions = @()
        $claimDescriptions = Get-ADFSClaimDescription
        if ($claimDescriptions -eq $null)
        {
            #$claimDescriptions = [Microsoft.IdentityServer.PowerShell.Resources.ClaimDescription[]]@()
            $claimDescriptions = @()
        }

        Write-Progress -Activity $activity -Status $status -CurrentOperation 'Write-Output' -PercentComplete 55

        $result = New-Object PSObject -Property @{
            'rpTrusts' = $rpTrusts;
            'cpTrusts' = $cpTrusts;
            'claimDescriptions' = $claimDescriptions;
            'rpClaimsHash' = $rpClaimsHash;
            'cpClaimsHash' = $cpClaimsHash;
            'rpSamlEnpointsHash' = $rpSamlEnpointsHash;
            'cpSamlEnpointsHash' = $cpSamlEnpointsHash;
            'certificates' = $certificates;
            'adfsProperties' = $adfsProperties;
            'attrStores' = $attrStores;
            'svcAcct' = $svcAcct
        }

        Write-Output $result
    }
    catch
    {
        # If running locally in Power 2.0 or running in a remote PS session, output the error record we
        # caught on the remote machine, because the error record we caught on the remote machine contains
        # more information than the error record we caught on the local machine later.
        Write-Host
        Out-String -InputObject $_ | Write-Host -ForegroundColor Red -BackgroundColor Black
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

<#################################################################
 # Check the export path and clear the folder
 ################################################################>
Function Prepare-Folder
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
        elseif ((Get-ChildItem -Path $Path) -ne $null)
        {
            [bool]$prepared = $false
            $confirmMessage = ($_system_translations.ExportConfirmMessage -f $Path)

            if ($Force -or $pscmdlet.ShouldContinue($confirmMessage, $_system_translations.ExportConfirmMessageCaption))
            {
                # Clear the folder
                [System.IO.DirectoryInfo]$folder = (Get-Item -Path $Path)
                $subPath = $folder.FullName + '\*'
                Remove-Item -Path $subPath -Recurse
                $prepared = $true
            }

            Write-Output $prepared
        }
        else
        {
            # The folder is empty
            Write-Output $true
        }
    }
}

Function Create-Summary
{
    Param()

    Process
    {
        $summary = [xml] "<AdfsMigrationTool/>"
        $root = $summary.DocumentElement
        $root.SetAttribute("Version", $ToolVersion) | Out-Null

        if ($ComputerName)
        {
            if ($Credential)
            {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credential
            }
            else
            {
                $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName
            }
        }
        else
        {
            $os = Get-WmiObject -Class Win32_OperatingSystem
        }

        $supported = $true

        if ($os.Version)
        {
            if ($os.Version.StartsWith("6.0"))
            {
                $version = "2.0"
            }
            elseif ($os.Version.StartsWith("6.1"))
            {
                $version = "2.0"
            }
            elseif ($os.Version.StartsWith("6.2"))
            {
                $version = "2.1"
            }
            elseif ($os.Version.StartsWith("6.3"))
            {
                $version = "3.0"
                $supported = $false
            }
            else
            {
                $version = "Unknown"
                $supported = $false
            }
        }
        else
        {
            $version = "Unknown"
            $supported = $false
        }

        if (!$supported)
        {
            #throw ($_system_translations.ExportStsVersionNotSupported)
        }

        $e = $summary.CreateElement("STS")
        $e.SetAttribute("Version", $version) | Out-Null

        $root.AppendChild($e) | Out-Null

        $e = $summary.CreateElement("Export")
        $root.AppendChild($e) | Out-Null

        $e2 = $summary.CreateElement("File")
        $e2.SetAttribute("Name", "rp.xml") | Out-Null
        $e.AppendChild($e2) | Out-Null

        $e2 = $summary.CreateElement("File")
        $e2.SetAttribute("Name", "cp.xml") | Out-Null
        $e.AppendChild($e2) | Out-Null

        $e2 = $summary.CreateElement("File")
        $e2.SetAttribute("Name", "claim.xml") | Out-Null
        $e.AppendChild($e2) | Out-Null

        $e2 = $summary.CreateElement("File")
        $e2.SetAttribute("Name", "cert.xml") | Out-Null
        $e.AppendChild($e2) | Out-Null

        $e2 = $summary.CreateElement("File")
        $e2.SetAttribute("Name", "properties.xml") | Out-Null
        $e.AppendChild($e2) | Out-Null

        Write-Output $summary
    }
}
# Execute Main
Main
#------------------------------------------------------------------------------ 
# 
# Copyright © 2013 Microsoft Corporation.  All rights reserved. 
# 
# THIS CODE AND ANY ASSOCIATED INFORMATION ARE PROVIDED “AS IS” WITHOUT 
# WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT 
# LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS 
# FOR A PARTICULAR PURPOSE. THE ENTIRE RISK OF USE, INABILITY TO USE, OR  
# RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 
# 
#------------------------------------------------------------------------------ 
# 
# PowerShell Source Code 
# 
# NAME: 
#    ADFS2.xChangeSvcAcct.ps1 
# 
# VERSION: 
#    1.1
# 
#------------------------------------------------------------------------------ 

	
# Adds user rights for new account
Function AddUserRights
	{	
		$RightsFailed =  $false
        NTRights.Exe -u $NewName +r SeServiceLogonRight | Out-File $LogPath -Append
		
		If (!$?)
			{
				$RightsFailed =  $true
				Write-Host "`tFailed to add user rights for $NewName`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
				($ElapsedTime.Elapsed.ToString())+ "[WARN]      Failed to add user rights for ${NewName}: 'Log on as a service', 'Generate security audits'" | Out-File $LogPath -Append
				Return $RightsFailed
			}
		
        NTRights.Exe -u $NewName +r SeAuditPrivilege | Out-File $LogPath -Append
        If (!$?)
			{
				$RightsFailed =  $true
				Write-Host "`tFailed to add user rights for $NewName`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
				($ElapsedTime.Elapsed.ToString())+ "[WARN]      Failed to add user rights for ${NewName}: 'Log on as a service', 'Generate security audits'" | Out-File $LogPath -Append
				Return $RightsFailed
			} 
		Else
			{
				GPUpdate /Force | Out-File $LogPath -Append
				$RightsFailed = $false
				Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [INFO]      User rights 'Log on as a service', 'Generate security audits' added for $NewName" | Out-File $LogPath -Append
			}
            
            Return $RightsFailed
	}

# Converts account name to SID
Function ConvertTo-Sid ($Account)
    {

		$SID = (New-Object system.security.principal.NtAccount($Account)).translate([system.security.principal.securityidentifier])
        Return $SID
    }


# ACLs a certificate private key
Function Set-CertificateSecurity
    {

        param([String]$certThumbprint,[String]$NewAccount)
		$FailedCertPerms = $false
        $certKeyPath = $env:ProgramData + "\Microsoft\Crypto\RSA\MachineKeys\"
        $certsCollection = @(dir cert:\ -recurse | ? { $_.Thumbprint -eq $certThumbprint })
        $certToSecure = $certsCollection[0]
        $uniqueKeyName = $certToSecure.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
		
        If ($uniqueKeyname -is [Object])
            {
				$Acl = Get-Acl $certKeyPath$uniqueKeyName
				$Arguments = $NewAccount,"Read","Allow"
				$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Arguments
				$Acl.SetAccessRule($AccessRule)
				$Acl | Set-Acl $certKeyPath$uniqueKeyName
				
				If (!$?)
					{
						Write-Host "`t`tFailed to set private key permissions.`n`t`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on key for thumbprint $certThumbprint - Setting the ACL did not succeed" | Out-File $LogPath -Append
						$CertPerms = $false
					}
				Else
					{
						Write-Host "`t`tSuccess" -ForegroundColor "green" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [INFO]      Set permissions on key for thumbprint $certThumbprint" | Out-File $LogPath -Append
						$CertPerms = $true
					}
            }
		Else
			{
				Write-Host "`t`tFailed to set private key permissions.`n`t`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on key for thumbprint $certThumbprint - Unique key container did not exist" | Out-File $LogPath -Append
				$CertPerms = $false
			}
		Return $CertPerms
    }


# ACLs the CertificateSharingContainer
Function Set-CertificateSharingContainerSecurity
    {
        param([String]$NewSID)
		$FailedLdap = $false
    
        # Get the new SID as a SID object and create AD Access Rules
        $objNewSID = [System.Security.Principal.SecurityIdentifier]$NewSID
        $RuleCreateChild = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'CreateChild','Allow','All')
        $RuleSelf = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'Self','Allow','All')
        $RuleWriteProperty = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'WriteProperty','Allow','All')
        $RuleGenericRead = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objNewSID,'GenericRead','Allow','All')


        # Get the LDAP object based on the certificate sharing container and add the AD Access Rules to the object
        $DN = ($ADFSProperties.CertificateSharingContainer).ToString()
        $objLDAP = [ADSI] "LDAP://$DN"
        $objLDAP.get_ObjectSecurity().AddAccessRule($RuleCreateChild)
        $objLDAP.get_ObjectSecurity().AddAccessRule($RuleSelf)
        $objLDAP.get_ObjectSecurity().AddAccessRule($RuleWriteProperty)
        $objLDAP.get_ObjectSecurity().AddAccessRule($RuleGenericRead)


        # Commit the AD Access rule changes to the LDAP object
        $objLDAP.CommitChanges()
		
		If (!$?)
			{
				Write-Host "`tFailed to set permissions on the Certificate Sharing Container.`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed setting permissions on AD cert sharing container: $DN. $NewName needs 'Create Child', 'Write', 'Read'." | Out-File $LogPath -Append
				$FailedLdap = $true
			}
		Else
			{
				Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [INFO]      Set permissions on cert sharing container: $DN" | Out-File $LogPath -Append
			}
    }


# Generates SQL scripts for database and service permissions
Function GenerateSQLScripts
    {
        # Generate SetPermissions.sql
        If (!(Test-Path $env:Temp\ADFSSQLScripts)) { New-Item $env:Temp\ADFSSQLScripts -type directory | Out-Null }
        If (Test-Path $env:Temp\ADFSSQLScripts) { Remove-Item $env:Temp\ADFSSQLScripts\* | Out-Null }
        Write-Host "`n Generating SQL scripts"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Generating SQL scripts ($env:Temp\ADFSSQLScripts)" | Out-File $LogPath -Append
		
		#check for Vista, 7, or 8
		$OSVersion = [System.Environment]::OSVersion.Version

		If (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
		{
		       #this is win8 and AD FS 2.1 is a server role
			   $WinDir = (Get-ChildItem Env:WinDir).Value
				Start-Process $WinDir\"ADFS\fsconfig.exe" -ArgumentList "GenerateSQLScripts /ServiceAccount $NewName /ScriptDestinationFolder $env:Temp\ADFSSQLScripts" -Wait -WindowStyle Hidden
		}
		Else
		{
		       	#this is win vista or 7 and AD FS 2.0 is an installed product
			   	$ProgramFiles = (Get-ChildItem Env:ProgramFiles).Value
        		Start-Process $ProgramFiles\"Active Directory Federation Services 2.0"\fsconfig.exe -ArgumentList "GenerateSQLScripts /ServiceAccount $NewName /ScriptDestinationFolder $env:Temp\ADFSSQLScripts" -Wait -WindowStyle Hidden

		}

		

        
		If (!$?)
			{
				Write-Host "`tFailed to generate SQL scripts. Exiting" -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to generate SQL scripts" | Out-File $LogPath -Append
				Return $false
			}

        # Generate UpdateServiceSettings.sql, but not for secondary WID. Secondary SQL never gets to this function
		
		If (!(($Role -eq "SecondaryComputer") -and ($DBMode -eq "WID")))
			{
        		"USE AdfsConfiguration" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql"
				"SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append
        		"UPDATE IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append
        		"SET ServiceSettingsData=REPLACE((SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings),'$OldSID','$NewSID')" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append
				"SELECT ServiceSettingsData from IdentityServerPolicy.ServiceSettings" | Out-File "$env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -append
		
				If (!$?)
					{
						Write-Host "`tFailed to generate UpdateServiceSettings.sql. Exiting" -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to generate UpdateServiceSettings.sql" | Out-File $LogPath -Append
						Return $false
					}
			}
		
		# Clean up the CreateDB.sql file
		If (Test-Path "$env:Temp\ADFSSQLScripts\CreateDB.sql")
			{
				Remove-Item "$env:Temp\ADFSSQLScripts\CreateDB.sql"
			}
		
		Return $true
		
    }
    
    
# Executes the SQL scripts generated by GenerateSQLScripts
Function ExecuteSQLScripts
    {
		Start sqlcmd.exe -ArgumentList "-S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o $env:Temp\ADFSSQLScripts\SetPermissions.log" -Wait -WindowStyle Hidden | Out-File $LogPath -Append
	   
		If (!$?)
			{
				Write-Host "`tFailed to execute SetPermissions.sql. Exiting" -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to execute SetPermissions.sql" | Out-File $LogPath -Append
				Return $false
			}
	   
	   # Execute UpdateServiceSettings.sql, but not for secondary WID. Secondary SQL never gets to this function.
	   
	   If (!(($Role -eq "SecondaryComputer") -and ($DBMode -eq "WID")))
	   		{
	   			Start sqlcmd.exe -ArgumentList "-S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings.log" -Wait -WindowStyle Hidden | Out-File $LogPath -Append
	   
				If (!$?)
					{
						Write-Host "`tFailed to execute UpdateServiceSettings.sql. Exiting...." -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed to execute UpdateServiceSettings.sql" | Out-File $LogPath -Append
						Return $false
					}
			}
		Return $true
    }


#############################

#### BEGIN MAIN EXECUTION

$ErrorActionPreference = "silentlycontinue"
$MachineFQDN = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName
$MachineDomainSlash = ((((($MachineFQDN).ToString()).Split(".",2)[1])+"\"+((($MachineFQDN).ToString()).Split(".",2)[0])).ToUpper())
#check for Vista, 7, or 8
$OSVersion = [System.Environment]::OSVersion.Version
 
If (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
{
       #this is win8 and AD FS 2.1 is a server role
       #import the AD FS 2.1 module
       Import-Module ADFS -ErrorAction SilentlyContinue
}
Else
{
       #this is win vista or 7 and AD FS 2.0 is an installed product
       #add the AD FS 2.0 snap-in
       Add-PsSnapin Microsoft.Adfs.Powershell -ErrorAction SilentlyContinue
}


# Show header, show AS-IS statement, detail sample changes made, prompt if ready to continue
Write-Host "`n IMPORTANT: This sample is provided AS-IS with no warranties and confers no rights." -ForegroundColor "yellow"
Write-Host "`n This sample is intended only for Federation Server farms. If your AD FS 2.x deployment type is Standalone," -ForegroundColor "yellow"
Write-Host " this sample does not apply to your Federation Service." -ForegroundColor "yellow"
Write-Host "`n The following changes will occur as a result of executing this sample:`n`t1. The AD FS service will be stopped"
write-host "`t2. The AD FS database permissions will be altered to allow access for the new account"
Write-Host "`t3. A servicePrincipalName registration will be removed from the old account and registered to the new account"
Write-Host "`t4. The AD FS service and AdfsAppPool identity will be changed to the new account"
Write-Host "`t5. Certificate private key permissions will be modified to allow access for the new account"
Write-Host "`t6. The new account will be allowed user rights: `"Log on as a service`" and `"Generate security audits`""
Write-Host "`n PRE-EXECUTION TASKS" -ForegroundColor "yellow"
Write-Host " 1. Create the new service account in Active Directory" -ForegroundColor "yellow"
Write-Host " 2. Install SQLCmd.exe on each Federation Server in the farm" -ForegroundColor "yellow"
Write-Host "`tSQLCmd.exe requires the SQL Native Client to be installed" -ForegroundColor "yellow"
Write-Host "`tAfter SQLCmd.exe has been installed, all Powershell windows must be" -ForegroundColor "yellow"
Write-Host "`tclosed and re-opened to continue with execution of this sample." -ForegroundColor "yellow"
Write-Host "`n`tDownload both installers from the following location`:`n`thttp://www.microsoft.com/download/en/details.aspx?id=15748" -ForegroundColor "yellow"

Write-Host "`n If you are ready to proceed, type capital C and press Enter to continue: " -NoNewline
$Answer = "notready"
$LogPath = "$pwd\ADFS_Change_Service_Account.log"
$Answer = Read-Host

If ($Answer -cne "C") 
	{ 
		Write-Host "`tExiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     Bad selection at the prompt to continue with sample execution" | Out-File $LogPath
		exit
	}

#write timing info to the log file and start a stopwatch to capture elapsed time
"[START TIME] $(Get-Date)" | Out-File $LogPath
$ElapsedTime = [System.Diagnostics.Stopwatch]::StartNew()
$OpMode1 = "Federation Server"
$OpMode2 = "Final Federation Server"

Write-Host "`n Note: The sample must be executed against each Federation Server in the farm." -ForegroundColor "yellow"
Write-Host " Windows Internal Database (WID) and SQL farms are supported. Before execution can" -ForegroundColor "yellow"
Write-Host " begin, an operating mode must be selected. Careful consideration of the following" -ForegroundColor "yellow"
Write-Host " guidance is necessary to ensure the sample is executed properly on each server." -ForegroundColor "yellow"
Write-Host "`n GUIDANCE FOR SELECTING AN OPERATING MODE:" -ForegroundColor "yellow"
Write-Host "`n WID FARM:`n The sample must be executed on all Secondary servers before execution should" -ForegroundColor "yellow"
Write-Host " occur on the Primary server. The Primary server is the only server with Write access to the" -ForegroundColor "yellow"
Write-Host " configuration database. The Primary server must be used as the 'Final Federation Server'" -ForegroundColor "yellow"
Write-Host "`n Powershell command to determine whether a server is Primary or Secondary:" -ForegroundColor "yellow"
#check for Vista, 7, or 8
$OSVersion = [System.Environment]::OSVersion.Version
 
If (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
{
       #this is win8 and AD FS 2.1 is a server role
       Write-Host "`tImport-Module ADFS" -ForegroundColor "yellow"
}
Else
{
       #this is win vista or 7 and AD FS 2.0 is an installed product
       Write-Host "`tAdd-PsSnapin Microsoft.Adfs.Powershell" -ForegroundColor "yellow"
}

Write-Host "`tGet-AdfsSyncProperties" -ForegroundColor "yellow"
Write-Host "`n SQL FARM:`n Any one server in the farm should be selected as the 'Final Federation Server'." -ForegroundColor "yellow"
Write-Host " All servers in a SQL farm have Write access to the configuration database. Execute the sample on all other" -ForegroundColor "yellow"
Write-Host " servers in the farm before executing the sample on the server selected as the 'Final Federation Server'" -ForegroundColor "yellow"


Write-Host "`n Select operating mode:`n`t1 - $OpMode1`n`t2 - $OpMode2"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Getting operating mode" | Out-File $LogPath -Append

While (($Mode -ne 1) -and ($Mode -ne 2))
    {
        $Mode = Read-Host "`tSelection"
		
		If (($Mode -ne 1) -and ($Mode -ne 2))
			{
				Write-Host "`t$Mode is not a valid selection" -ForegroundColor "yellow"
			}
    }

if ($Mode -eq 1)
	{
		$SelOpMode = $OpMode1
	}
else
	{
		$SelOpMode = $OpMode2
	}

Write-Host "`tOperating mode: $SelOpMode" -ForegroundColor "green"
($ElapsedTime.Elapsed.ToString())+" [INFO]      Operating mode: $SelOpMode" | Out-File $LogPath -Append

# Check for the AD FS service

Write-Host " Checking the AD FS service"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking for service installation (adfssrv)" | Out-File $LogPath -Append
$ADFSInstalled = Get-Service adfssrv

If (!$ADFSInstalled)
	{
		Write-Host "`tThe AD FS service was not found. Exiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv is not installed" | Out-File $LogPath -Append
		Exit
	}
Else
	{
		($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is installed" | Out-File $LogPath -Append
		
		# Check to see if adfssrv is running. If stopped, attempt to start. If start fails, exit.
		If ($ADFSInstalled.Status -ceq "Stopped")
			{
				Write-Host "`tThe AD FS service is stopped. Starting the service`n" -ForegroundColor "yellow" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [WARN]      adfssrv is stopped. Attempting to start" | Out-File $LogPath -Append
				$ADFSInstalled.Start()
				$ADFSInstalled.WaitForStatus("Running",[System.TimeSpan]::FromSeconds(25))
				
				If (!$?)
					{
						Write-Host "`tThe AD FS service could not be started. Exiting" -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv failed to start" | Out-File $LogPath -Append
						Exit
					}
			}
		Else
			{
				($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is running" | Out-File $LogPath -Append
			}
			
		Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
	}

# Check for the AD FS 2.x application pool
	
Write-Host "`n Checking the application pool"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking for AdfsAppPool" | Out-File $LogPath -Append

If (([Environment]::OSVersion.Version.Major -eq "6") -band ([Environment]::OSVersion.Version.Minor -eq "1"))
	{
		($ElapsedTime.Elapsed.ToString())+" [INFO]      This is Windows Server 2008 R2" | Out-File $LogPath -Append
		Import-Module WebAdministration
	}
ElseIf (([Environment]::OSVersion.Version.Major -eq "6") -band ([Environment]::OSVersion.Version.Minor -eq "2"))
	{
		($ElapsedTime.Elapsed.ToString())+" [INFO]      This is Windows Server 2012" | Out-File $LogPath -Append
		Import-Module WebAdministration
	}
ElseIf (([Environment]::OSVersion.Version.Major -eq "6") -band ([Environment]::OSVersion.Version.Minor -eq "0"))
	{
		($ElapsedTime.Elapsed.ToString())+" [INFO]      This is Windows Server 2008" | Out-File $LogPath -Append
		Add-PSSnapin WebAdministration
		
		If (!((Get-PSSnapin WebAdministration).Name))
			{
				Write-Host "`tThe IIS Powershell snap-in was not loaded" -ForegroundColor "yellow"
				Write-Host "`n`tInstall from:" -ForegroundColor "Gray"
				Write-Host "`tx86`: http`://go.microsoft.com/`?linkid=9655703" -ForegroundColor "Gray"
				Write-Host "`tx64`: http://go.microsoft.com/?linkid=9655704" -ForegroundColor "Gray"
				($ElapsedTime.Elapsed.ToString())+" [WARN]      The IIS Powershell snap-in was not found" | Out-File $LogPath -Append
				($ElapsedTime.Elapsed.ToString())+" [WARN]      Download and install from:" | Out-File $LogPath -Append
				($ElapsedTime.Elapsed.ToString())+" [WARN]      http`://www.microsoft.com/download/en/search.aspx`?q=IIS Powershell Snap-in" | Out-File $LogPath -Append
				
				Write-Host "`n`tType capital C and press Enter once the IIS Powershell snap-in"
				Write-Host "`thas been installed, or type X to exit" -NoNewline
				$IISPSHSnapin = "foo"
				While (($IISPSHSnapin -cne "C") -and ($IISPSHSnapin -ne "X"))
					{
						$IISPSHSnapin = Read-Host "`t"
						If (($IISPSHSnapin -cne "C") -and ($IISPSHSnapin -ne "X"))
							{
								Write-Host "`tInvalid input. Try again" -NoNewline -ForegroundColor "yellow"
								($ElapsedTime.Elapsed.ToString())+" [WARN]      Invalid input for IIS PSH snap-in answer. Re-prompting" | Out-File $LogPath -Append
							}
					}
					
				If ($IISPSHSnapin -eq "X")
					{
						Write-Host "`tExiting`n" -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [INFO]      User chose to exit. Exiting" | Out-File $LogPath -Append
						Exit
					}
				
				Add-PSSnapin WebAdministration
				
				If (!((Get-PSSnapin WebAdministration).Name))
					{
						Write-Host "`tThe IIS Powershell snap-in was not loaded. Exiting" -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     The IIS Powershell snap-in was not found even after installation was suggested. Exiting" | Out-File $LogPath -Append
						Exit
					}
			}
	}
Else
	{
		Write-Host "`tUnsupported operating system. Exiting`n" -ForegroundColor "red"
		Exit
		
	}

$ADFSAppPoolPresent = (Test-Path IIS:\AppPools\ADFSAppPool)

If (!$ADFSAppPoolPresent)
	{
        Write-Host "`tThe AD FS application pool was not found. Exiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     AdfsAppPool is not installed" | Out-File $LogPath -Append
		Exit
    }
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      AdfsAppPool pool found" | Out-File $LogPath -Append
	}
	
# Check if Fed Svc Name equals machine FQDN. This is not supported for farms. Breaks Kerberos.
Write-Host "`n Checking the Federation Service Name"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking Federation Service Name" | Out-File $LogPath -Append

$ADFSProperties = Get-ADFSProperties
$FederationServiceName = ((($ADFSProperties.HostName).ToString()).ToUpper())

If ($FederationServiceName -eq $MachineFQDN)
	{
		Write-Host "`tFederation Service Name: $FederationServiceName`n`tFederation Service Name must not equal the qualified`n`tcomputer name in an AD FS farm." -ForegroundColor "red"
		Write-Host "`thttp://social.technet.microsoft.com/wiki/contents/articles/ad-fs-2-0-how-to-change-the-federation-service-name.aspx" -ForegroundColor "gray"
		Write-Host "`tExiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     Federation Service Name: $FederationServiceName equals the qualified computer name. This is not supported in a farm deployment" | Out-File $LogPath -Append
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     http://social.technet.microsoft.com/wiki/contents/articles/ad-fs-2-0-how-to-change-the-federation-service-name.aspx" | Out-File $LogPath -Append
		Exit
	}
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green"
		($ElapsedTime.Elapsed.ToString())+" [INFO]      Federation Service Name is OK" | Out-File $LogPath -Append
	}

$CredsNotValidated = $true

While ($CredsNotValidated)
	{
		# Collect creds for new service account
				$NewName = "foo"
		While (($NewName -match " ") -or ($NewName -match "networkservice") -or ($NewName -match "localsystem") -or (($NewName -notmatch "\\") -and ($NewName -notmatch "`@")))
			{
				Write-Host " Collecting credentials for the new account"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Collecting new credentials" | Out-File $LogPath -Append
				$NewName = (Read-Host "`tUsername (domain\user)").ToUpper()
				($ElapsedTime.Elapsed.ToString())+" [INFO]      New user name: $NewName" | Out-File $LogPath -Append
		
				If (($NewName -match " ") -or ($NewName -match "networkservice") -or ($NewName -match "localsystem") -or (($NewName -notmatch "\\") -and ($NewName -notmatch "`@")))
					{
						Write-Host "`t$NewName is not supported. AD FS farms require a domain user account (domain\user)" -ForegroundColor "red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     Unsupported new name entry: $NewName. Service account must be domain user" | Out-File $LogPath -Append
					}
			}

		$NewPassword = Read-Host -assecurestring "`tPassword"
		$objNewCreds = New-Object Management.Automation.PSCredential $NewName, $NewPassword
		$NewPassword = $objNewCreds.GetNetworkCredential().Password
	
		# Check for UPN style new name and convert to domain\username for SPN work items
		If ($NewName.ToString() -match "`@")
			{
				$NewName = ((($NewName.Split("`@")[1]).ToString() + "\" + ($NewName.Split("`@")[0]).ToString()).ToUpper())
				Write-Host "`n`tUsing $NewName in order to meet SPN requirements" -ForegroundColor "gray"
				($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $NewName in order to meet SPN requirements" | Out-File $LogPath -Append
			}
	
		# Validating credentials
				Write-Host " Validating credentials"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Validating credentials" | Out-File $LogPath -Append
		$Domain = "LDAP://" + ([ADSI]"").distinguishedName
		$DomainObject = New-Object System.DirectoryServices.DirectoryEntry($Domain,$NewName,$NewPassword)

		`$DomainObject.Name = `$DomainObject.Name
		If ($DomainObject.Name -eq $null)
			{
				Write-Host "`tFailed credential validation" -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     Failed credential validation" | Out-File $LogPath -Append
			}
		Else
			{
				Write-Host "`tSuccess" -ForegroundColor "green"
				($ElapsedTime.Elapsed.ToString())+" [INFO]      Credentials validated" | Out-File $LogPath -Append
				$CredsNotValidated = $false
			}
	}

# Getting current identity for the AD FS 2.x Windows Service

Write-Host " Discovering current account name"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Getting old name" | Out-File $LogPath -Append
$ADFSSvc = gwmi win32_service -filter "name='adfssrv'"

If (!$ADFSSvc)
	{
	    Write-Host "`tFailed to get the current account name. Exiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     Could not get old name from WMI service information for adfssrv" | Out-File $LogPath -Append
        exit
	}
Else
	{
	    $OldName = ((($ADFSSvc.StartName).ToString()).ToUpper())
		Write-Host "`t$OldName" -ForegroundColor "Green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      Old name: $OldName" | Out-File $LogPath -Append
		
		If ($Mode -eq 2)
			{
				# Check for network service and local system and set a variable to use the domain\computername for SPN work items
				If ((($OldName).ToString() -eq "NT AUTHORITY\NETWORK SERVICE") -or (($OldName).ToString() -eq "NT AUTHORITY\LOCAL SYSTEM"))
					{
						Write-Host "`tUsing $MachineDomainSlash in order to meet SPN requirements" -ForegroundColor "gray"
						($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $MachineDomainSlash in order to meet SPN requirements" | Out-File $LogPath -Append
						$UseMachineFQDN = $true
					}
					
				# Check for UPN style old name and convert to domain\username for SPN work items
				If ($OldName.ToString() -match "`@")
					{
						$OldName = ($OldName.Split("`@")[1]).ToString() + "\" + ($OldName.Split("`@")[0]).ToString()
						Write-Host "`tUsing $OldName in order to meet SPN requirements" -ForegroundColor "gray"
						($ElapsedTime.Elapsed.ToString())+" [INFO]      Using $OldName in order to meet SPN requirements" | Out-File $LogPath -Append
					}
			}
	}
	
####ADD NEEDED MODULES####

$ADFSCertificate = Get-ADFSCertificate
$ADFSSyncProperties = Get-ADFSSyncProperties
$Role = (($ADFSSyncProperties.Role).ToString())
	
####STOP THE AD FS WINDOWS SERVICE####
   
Write-Host "`n Stopping the AD FS service"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Stopping adfssrv" | Out-File $LogPath -Append

# Stop the AD FS Windows service. No need to check status since Stop-Service does not throw if service is currently stopped.
$ADFSInstalled.Stop()
$ADFSInstalled.WaitForStatus("Stopped",[System.TimeSpan]::FromSeconds(15))

If (!$?)
	{
	    Write-Host "`tThe AD FS service could not be stopped.`n`tExiting`n" -ForegroundColor "red"
		($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv could not be stopped" | Out-File $LogPath -Append
        exit
	}
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv is stopped" | Out-File $LogPath -Append
	}

	    ####GETTING THE SQL HOST NAME####

        # Getting SQL host name
		Write-Host "`n Discovering SQL host"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Discovering SQL host" | Out-File $LogPath -Append
        $SQLHost = ((($ADFSProperties.ArtifactDbConnection).ToString()).split("=")[1]).Split(";")[0]
		Write-Host "`t$SQLHost" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL host: $SQLHost" | Out-File $LogPath -Append
    
        ####DETECT DATABASE TYPE####
    
        # Detect WID or SQL
		Write-Host "`n Detecting database type"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Detecting database type" | Out-File $LogPath -Append
		
		
		#check for Vista, 7, or 8
		$OSVersion = [System.Environment]::OSVersion.Version
		 
		If (($OSVersion.Major -eq 6) -and ($OSVersion.Minor -eq 2))
		{
		    #this is win8 and AD FS 2.1 is a server role
		    if ($ADFSProperties.ArtifactDbConnection.contains('Data Source=\\.\pipe\Microsoft##WID'))
			{
				$DBMode = "WID"
			}
       		else
			{
				$DBMode = "SQL"
			}
		}
		Else
		{
		    #this is win vista or 7 and AD FS 2.0 is an installed product
		    if ($ADFSProperties.ArtifactDbConnection.contains('Data Source=\\.\pipe\mssql$microsoft##ssee'))
			{
				$DBMode = "WID"
			}
        	else
			{
				$DBMode = "SQL"
			}
		}

		

		
		Write-Host "`t$DBMode" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      Database type: $DBMode" | Out-File $LogPath -Append
		
		#check to be sure that the admin isn't attempting a mode that isn't suitable for the current FS's role
		
		If ($DBMode -eq "WID")
			{
				Write-Host "`n Checking operating mode against server role"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Checking op mode against server role" | Out-File $LogPath -Append
		
				If ((($Mode -eq 2) -and ($Role -eq "SecondaryComputer")) -or (($Mode -eq 1) -and ($Role -eq "PrimaryComputer")))
					{
						Write-Host "`tError: Operating mode and role mismatch. Operating mode $Mode cannot be executed`n`ton a server with role $Role`n`tAction: Select a valid operating mode for this server.`n`tExiting" -ForegroundColor "Red"
						($ElapsedTime.Elapsed.ToString())+" [ERROR]     Op mode does not match server role. Mode: $Mode. Role: $Role" | Out-File $LogPath -Append
						exit
					}
				Write-Host "`tSuccess" -ForegroundColor "Green" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [INFO]      Op mode matches server role" | Out-File $LogPath -Append
			}
		
        # Detect SQLCmd.exe, but not for secondary SQL
		
		If (!(($Mode -eq 1) -and ($DBMode -eq "SQL")))
			{
				Write-Host "`n Detecting SQLCmd.exe"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Detecting SQLCMD.exe" | Out-File $LogPath -Append
				$SQLCmdPresent = $false
				sqlcmd.exe /? | Out-Null
		
				If (!$?)
					{
						Write-Host "`tSQLCmd.exe was not found`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY." -ForegroundColor "yellow" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [WARN]      SQLCMD.exe not found. SQL scripts must be manually executed." | Out-File $LogPath -Append
					}
				Else
					{
						Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [INFO]      SQLCMD.exe found" | Out-File $LogPath -Append
						$SQLCmdPresent = $true
					}
			}

        ####CONVERTING NAMES TO SIDS####
        Write-Host "`n Converting $OldName to SID"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Convert $OldName to SID" | Out-File $LogPath -Append
		
        # Get SID for the old account into a variable
		$OldSID = ConvertTo-Sid -Account $OldName
		
		If (!$OldSID)
			{
			    Write-Host "`tName to SID translation failed for `"$OldName`".`n`tExiting`n" -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     $OldName SID translation failed" | Out-File $LogPath -Append
                exit
			}
		Else
			{
				Write-Host "`t$OldSID" -ForegroundColor "green" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [INFO]      Old SID: $OldSID" | Out-File $LogPath -Append
			}
			
        Write-Host "`n Converting $NewName to SID"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Convert $NewName to SID" | Out-File $LogPath -Append

        #Get SID for the new account into a variable
		$NewSID = ConvertTo-Sid -Account $NewName
		
		If (!$NewSID)
			{
			    Write-Host "`tName to SID translation failed for `"$NewName`".`n`tEnsure that the new service account name is typed correctly. Exiting`n" -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     $NewName SID translation failed" | Out-File $LogPath -Append
                exit
			}
		Else
			{
				Write-Host "`t$NewSID" -ForegroundColor "green" -NoNewline
				($ElapsedTime.Elapsed.ToString())+" [INFO]      New SID: $NewSID" | Out-File $LogPath -Append
			}
			
		If ($NewSID -eq $OldSID)
			{
				Write-Host "`n The old and new accounts are the same, do you wish to proceed?" -ForegroundColor "yellow"
				$SameAccountAnswer = Read-Host "`t(Y/N)"
				
				If ($SameAccountAnswer -ne "y")
					{
						Write-Host "`tExiting`n" -ForegroundColor "red"
						Exit
					}
			}
			
        ####GENERATE SQL SCRIPTS, BUT NOT FOR SECONDARY SQL####
    	
		If (!(($Mode -eq 1) -and ($DBMode -eq "SQL")))
			{
        		$GenerateSQLScripts = GenerateSQLScripts
				If (!$GenerateSQLScripts)
					{
						exit
					}
				Else
					{
						Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts generated" | Out-File $LogPath -Append
					}
				}

        ####PERFORM ACTIONS FOR SQL DATABASE TYPE####
    
        if (($DBMode -eq "SQL") -and ($Mode -eq 2))
            {
                Write-Host "`n Does the currently logged on user have administrative access to the AD FS databases within SQL server`?"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Discovering if current user is SQL admin" | Out-File $LogPath -Append
                $SQLAnswser = "foo"
                
                while (($SQLAnswer -ne "Y") -and ($SQLAnswer -ne "N"))
                { $SQLAnswer = Read-Host "`t(Y/N)" }
        		
				($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL admin answer: $SQLAnswer" | Out-File $LogPath -Append
        
                # If the user has permissions in SQL and SQLCmd.exe is present, run the scripts, otherwise, explain how they must perform this step manually.
                if (($SQLAnswer -eq "Y") -and ($SQLCmdPresent))
                    {
						Write-Host " Executing SQL scripts"
						($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Executing SQL scripts using SQLCMD.exe" | Out-File $LogPath -Append
                        $ExecuteSQLScripts = ExecuteSQLScripts
						
						If (!$ExecuteSQLScripts)
							{
								exit
							}
						Else
							{
								Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts executed successfully" | Out-File $LogPath -Append
							}
                    }
                else
                    {
						$NeedsSQLWarning = $true
						($ElapsedTime.Elapsed.ToString())+" [WARN]      Admin must execute SQL scripts manually:" | Out-File $LogPath -Append
						($ElapsedTime.Elapsed.ToString())+" [WARN]      sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log,0,True" | Out-File $LogPath -Append
						($ElapsedTime.Elapsed.ToString())+" [WARN]      sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log,0,True" | Out-File $LogPath -Append

                    }
			}
        
		If ($DBMode -eq "WID")
            {
    
                ####PERFORM STEPS FOR WID DATABASE TYPE####
    
                # We don't care if they are an admin in SQL Server, so only need to check to see if SQLCmd.exe is installed. Run the scripts, otherwise, explain how they must perform steps manually
				if ($SQLCmdPresent)
                    {
						Write-Host "`n Executing SQL scripts"
						($ElapsedTime.Elapsed.ToString())+" [INFO]      Executing SQL scripts using SQLCMD.exe" | Out-File $LogPath -Append
                        $ExecuteSQLScripts = ExecuteSQLScripts
						
						If (!$ExecuteSQLScripts)
							{
								exit
							}
						Else
							{
								Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [INFO]      SQL scripts executed successfully" | Out-File $LogPath -Append
							}
                    }
                else
                    {
						$NeedsSQLWarning = $true
                    }
        }
	
    
	If ($Mode -eq 2)
			{
        		####REMOVE THE SPN FROM THE OLD SERVICE ACCOUNT####
    	
				If ($UseMachineFQDN)
					{
						Write-Host "`n Removing SPN HOST/$FederationServiceName from $MachineDomainSlash"
						($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Removing SPN HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append
	   					setspn.exe -D HOST/$FederationServiceName $MachineDomainSlash | Out-File $LogPath -Append
				
						If (!$?)
							{
								Write-Host "`tRemoving SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY." -ForegroundColor "yellow" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [WARN]      Removing SPN failed: HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append
								($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -D HOST/$FederationServiceName $MachineDomainSlash" | Out-File $LogPath -Append
								$FailedSpn = $true
							}
						Else
							{
								Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN removed: HOST/$FederationServiceName from $MachineDomainSlash" | Out-File $LogPath -Append
							}
					}
				Else
					{
						Write-Host "`n Removing SPN HOST/$FederationServiceName from $OldName"
						($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Removing SPN HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append
	   					setspn.exe -D HOST/$FederationServiceName $OldName | Out-File $LogPath -Append
				
						If (!$?)
							{
								Write-Host "`tRemoving SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [WARN]      Removing SPN failed: HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append
								($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -D HOST/$FederationServiceName $OldName" | Out-File $LogPath -Append
								$FailedSpn = $true
							}
						Else
							{
								Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
								($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN removed: HOST/$FederationServiceName from $OldName" | Out-File $LogPath -Append
							}
					}

        		####ADD THE SPN TO THE NEW SERVICE ACCOUNT####
    
				Write-Host "`n Registering SPN HOST/$FederationServiceName to $NewName"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Registering SPN HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append
				setspn.exe -S HOST/$FederationServiceName $NewName | Out-File $LogPath -Append

				If (!$?)
					{
						Write-Host "`tRegistering SPN failed`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [WARN]      Registering SPN failed: HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append
						($ElapsedTime.Elapsed.ToString())+" [WARN]      setspn.exe -S HOST/$FederationServiceName $NewName" | Out-File $LogPath -Append
						$FailedSpn = $true
					}
				Else
					{
						Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
						($ElapsedTime.Elapsed.ToString())+" [INFO]      SPN registered: HOST/$FederationServiceName to $NewName" | Out-File $LogPath -Append
					}
			}

####SET THE IDENTITY OF THE AD FS WINDOWS SERVICE TO THE NEW SERVICE ACCOUNT####

# Setting identity for the AD FS Windows Service to the new service account
Write-Host "`n Setting the AD FS service identity to $NewName"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Setting new service identity for adfssrv to $NewName" | Out-File $LogPath -Append

$ADFSSvc = gwmi win32_service -filter "name='adfssrv'"

If (!$ADFSSvc)
	{
        Write-Host "`tFailed to get information about the AD FS service." -ForegroundColor "yellow" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to get WMI information for adfssrv from WMI" | Out-File $LogPath -Append
	}

$ADFSSvc.Change($null,$null,$null,$null,$null,$null,$NewName,$NewPassword,$null,$null,$null) | Out-Null

If (!$?)
	{
		Write-Host "`tFailed to set the identity of the AD FS service`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to set identity for adfssrv to $NewName" | Out-File $LogPath -Append
		$FailedServiceIdentity = $true
	}
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      Set identity of adfssrv to $NewName" | Out-File $LogPath -Append
	}
        
# Setting identity for the IIS AD FS Application Pool to the new service account

Write-Host "`n Setting the identity for the AD FS Application Pool to $NewName"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Setting identity for AdfsAppPool to $NewName" | Out-File $LogPath -Append
Set-ItemProperty iis:\apppools\ADFSAppPool -name processModel -value @{userName="$NewName";password="$NewPassword";identitytype=3}

If (!$?)
	{
        Write-Host "`tFailed to set identity for the AD FS Application Pool`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to set identity for AdfsAppPool to $NewName" | Out-File $LogPath -Append
		$FailedAppPoolIdentity = $true
    }
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [INFO]      Set identity of AdfsAppPool to $NewName" | Out-File $LogPath -Append
	}

# Recycle the application pool
Write-Host "`n Recycling the application pool"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Recycling AdfsAppPool" | Out-File $LogPath -Append
Restart-WebAppPool adfsapppool

If (!$?)
	{
		Write-Host "`tFailed to restart the application pool`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY`n" -ForegroundColor "yellow" -NoNewline
		($ElapsedTime.Elapsed.ToString())+" [WARN]      Failed to restart AdfsAppPool" | Out-File $LogPath -Append
		$FailedAppPoolRestart = $true
	}
Else
	{
		Write-Host "`tSuccess" -ForegroundColor "green"
		($ElapsedTime.Elapsed.ToString())+" [INFO]      AdfsAppPool recycled" | Out-File $LogPath -Append
	}

####ACL PRIVATE KEYS FOR THE NEW SERVICE ACCOUNT####

		$SCCertACL = $true
		$TSCertACL = $true
		$TDCertACL = $true
		
        Write-Host " Providing $NewName access to certificate private keys"
		($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Providing $NewName access to cert private keys" | Out-File $LogPath -Append

        # Get thumbprint for relevant certs and ACL the private keys for the new service account
        # SC cert gets ACL'd always. TS and TD certs are ACL'd only if AutoCertificateRollover is disabled.
        # If AutoCertificateRollover is enabled for a farm, the TS and TD certs will be ACL'd when we ACL the certificate sharing container
        # If AutoCertificateRollover is enabled for a standalone server, this sample will not ACL the private keys. Not supported in this sample.
        Write-Host "`tService Communications"
		($ElapsedTime.Elapsed.ToString())+" [SUB ITEM]  Service Communiations" | Out-File $LogPath -Append
        $SCCertThumb = ($ADFSCertificate | Where-Object {(($_.CertificateType -eq "Service-Communications") -and ($_.IsPrimary -eq "True"))}).Thumbprint
        $SCCertACL = Set-CertificateSecurity -certThumbprint $SCCertThumb -NewAccount $NewName
		
        If (($ADFSProperties.AutocertificateRollover).ToString() -eq "False")
            {
                Write-Host "`n`tToken-signing"
				($ElapsedTime.Elapsed.ToString())+" [SUB ITEM]  Token-signing" | Out-File $LogPath -Append
                $TSCertThumb = ($ADFSCertificate | Where-Object {(($_.CertificateType -eq "Token-Signing") -and ($_.IsPrimary -eq "True"))}).Thumbprint
                $TSCertACL = Set-CertificateSecurity -certThumbprint $TSCertThumb -NewAccount $NewName
                Write-Host "`n`tToken-decrypting"
				($ElapsedTime.Elapsed.ToString())+" [SUB ITEM]  Token-decrypting" | Out-File $LogPath -Append
                $TDCertThumb = ($ADFSCertificate | Where-Object {(($_.CertificateType -eq "Token-Decrypting") -and ($_.IsPrimary -eq "True"))}).Thumbprint
                $TDCertACL = Set-CertificateSecurity -certThumbprint $TDCertThumb -NewAccount $NewName
            }



####ACL THE CERTIFICATE SHARING CONTAINER FOR THE NEW SERVICE ACCOUNT####

# Only execute if this is the first federation server
if ($Mode -eq 2)
    {
        # Check if CertificateSharingContainer has a value. If it does, ACL the container for the new service account.
        If ($ADFSProperties.CertificateSharingContainer -ne $null)
            {
                Write-Host "`n Providing $NewName access to the Certificate Sharing Container"
				($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Providing $NewName access to ($ADFSProperties.CertificateSharingContainer).ToString()" | Out-File $LogPath -Append
                Set-CertificateSharingContainerSecurity -NewSID $NewSID
            }
    }
	
####ADD USER RIGHTS####

Write-Host "`n Adding user rights for $NewName"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Adding user rights for $NewName" | Out-File $LogPath -Append

# Execute for all opmodes
$FailedUserRights = AddUserRights

####START THE AD FS WINDOWS SERVICE####
   
Write-Host "`n Starting the AD FS service"
($ElapsedTime.Elapsed.ToString())+" [WORK ITEM] Starting adfssrv" | Out-File $LogPath -Append

#check to see if SQL scripts need run. If yes, skip this step
If (($Mode -eq 1) -or $NeedsSQLWarning -or $FailedAppPoolIdentity -or $FailedAppPoolRestart -or !($SCCertACL) -or !($TSCertACL) -or !($TDCertACL) -or $FailedLdap -or $FailedServiceIdentity -or $FailedServiceStart -or $FailedSpn -or $FailedUserRights)
	{
		Write-Host "`tSkipped`n`tSee: POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow"
		($ElapsedTime.Elapsed.ToString())+" [WARN]      Skipped starting adfssrv due to post-sample needs" | Out-File $LogPath -Append
		$SkipServiceStart = $true
	}
Else
	{
		# Start the AD FS Windows service. No need to check status since Start-Service does not throw if service is currently started.
		$ADFSInstalled.Start()
		$ADFSInstalled.WaitForStatus("Running",[System.TimeSpan]::FromSeconds(25))

		If (!$?)
			{
				Write-Host "`tFailed: The AD FS service could not be started.`n`tExamine the AD FS 2.0/Admin and AD FS 2.0 Tracing/Debug event logs for details." -ForegroundColor "red"
				($ElapsedTime.Elapsed.ToString())+" [ERROR]     adfssrv service failed to start. See Admin and Debug logs for details." | Out-File $LogPath -Append
				$FailedServiceStart = $true
			}
		Else
			{
				Write-Host "`tSuccess" -ForegroundColor "green"
				($ElapsedTime.Elapsed.ToString())+" [INFO]      adfssrv started" | Out-File $LogPath -Append
			}
	}

####NOTIFY ABOUT MANUALLY SETTING ITEMS

$NotifyCount = 1
Write-Host "`n`n`n POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" -ForegroundColor "yellow"
"`n`n`n POST-SAMPLE ITEMS THAT MUST BE EXECUTED MANUALLY" | Out-File $LogPath -Append

If ($FailedUserRights)
	{
		Write-Host "`n`n $NotifyCount. You must manually set User Rights Assigment for $NewName" -ForegroundColor "yellow"
		Write-Host "    to allow `"Generate Security Audits`" and `"Log On As a Service`"." -ForegroundColor "yellow"
		Write-Host "`n    Steps:`n    Start -> Run -> GPEdit.msc -> Computer Configuration -> Windows Settings ->" -ForegroundColor "yellow"
		Write-Host "    Security Settings -> Local Policies -> User Rights Assignment" -ForegroundColor "yellow"
		"`n`n $NotifyCount. You must manually set User Rights Assigment for $NewName" | Out-File $LogPath -Append
		"    to allow `"Generate Security Audits`" and `"Log On As a Service`"." | Out-File $LogPath -Append
		"`n    Steps:`n    Start -> Run -> GPEdit.msc -> Computer Configuration -> Windows Settings ->" | Out-File $LogPath -Append
		"    Security Settings -> Local Policies -> User Rights Assignment" | Out-File $LogPath -Append
		$NotifyCount += 1
	}

If (!($SCCertACL) -or !($TSCertACL) -or !($TDCertACL))
	{
		Write-Host "`n`n $NotifyCount. $NewName must have Read permission to the certificate private keys`n    used for Service Communications, Token-signing, and Token-decrypting" -ForegroundColor "yellow"
		Write-Host "    These permissions were not set during execution and must be set manually." -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. $NewName must have Read permission to the certificate private keys`n    used for Service Communications, Token-signing, and Token-decrypting" | Out-File $LogPath -Append
		"    These permissions were not set during execution and must be set manually." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($FailedLdap)
	{
		Write-Host "`n`n $NotifyCount. $NewName must have Read, Write, and Create Child permissions to the certificate" -ForegroundColor "yellow"
		Write-Host "    sharing container in AD. These permissions were not set during execution and must be set manually." -ForegroundColor "yellow"
		Write-Host "    LDAP path: $DN" -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. $NewName must have Read, Write, and Create Child permissions to the certificate" | Out-File $LogPath -Append
		"    sharing container in AD. These permissions were not set during execution and must be set manually." | Out-File $LogPath -Append
		"    LDAP path: $DN" | Out-File $LogPath -Append
		$NotifyCount += 1
	}

If ($NeedsSQLWarning)
	{
		If ($DBMode -eq "SQL")
			{
				Write-Host "`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," -ForegroundColor "yellow"
				Write-Host "    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" -ForegroundColor "yellow"
				Write-Host "    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts." -ForegroundColor "yellow"
				Write-Host "    The DBA should execute these scripts on the SQL Server where the AD FS" -ForegroundColor "yellow"
				Write-Host "    Configuration and Artifact databases reside." -ForegroundColor "yellow"
				Write-Host "`n    Syntax:" -ForegroundColor "yellow" 
				Write-Host "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql" -ForegroundColor "yellow"
				Write-Host "    -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log" -ForegroundColor "yellow"
				Write-Host "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -ForegroundColor "yellow"
				Write-Host "    -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" -ForegroundColor "yellow"
		
				"`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," | Out-File $LogPath -Append
				"    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" | Out-File $LogPath -Append
				"    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts. The DBA should execute these" | Out-File $LogPath -Append
				"    scripts on the SQL Server where the AD FS Configuration and Artifact databases reside." | Out-File $LogPath -Append
				"`n    Syntax:" | Out-File $LogPath -Append
				"    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o" | Out-File $LogPath -Append
				"    $env:Temp\ADFSSQLScripts\SetPermissions-output.log" | Out-File $LogPath -Append
				"`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o" | Out-File $LogPath -Append
				"    $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" | Out-File $LogPath -Append
			}
		Else
			{
				Write-Host "`n`n $NotifyCount. SQLCmd.exe was not found on this system. The SQL scripts must be executed" -ForegroundColor "yellow"
				Write-Host "    manually using either SQL Management Studio or SQLCmd.exe. The scripts currently reside" -ForegroundColor "yellow"
				Write-Host "    in $env:Temp\ADFSSQLScripts." -ForegroundColor "yellow"
				Write-Host "`n    Syntax:" -ForegroundColor "yellow" 
				Write-Host "    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql" -ForegroundColor "yellow"
				Write-Host "    -o $env:Temp\ADFSSQLScripts\SetPermissions-output.log" -ForegroundColor "yellow"
				Write-Host "`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql" -ForegroundColor "yellow"
				Write-Host "    -o $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" -ForegroundColor "yellow"
		
				"`n`n $NotifyCount. Either the currently logged on user does not have appropriate permissions on the SQL Server," | Out-File $LogPath -Append
				"    or SQLCmd.exe was not found on this system. You must provide your SQL DBA with the SetPermissions.sql" | Out-File $LogPath -Append
				"    and UpdateServiceSettings.sql fileslocated in $env:Temp\ADFSSQLScripts. The DBA should execute these" | Out-File $LogPath -Append
				"    scripts on the SQL Server where the AD FS Configuration and Artifact databases reside." | Out-File $LogPath -Append
				"`n    Syntax:" | Out-File $LogPath -Append
				"    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\SetPermissions.sql -o" | Out-File $LogPath -Append
				"    $env:Temp\ADFSSQLScripts\SetPermissions-output.log" | Out-File $LogPath -Append
				"`n    sqlcmd.exe -S $SQLHost -i $env:Temp\ADFSSQLScripts\UpdateServiceSettings.sql -o" | Out-File $LogPath -Append
				"    $env:Temp\ADFSSQLScripts\UpdateServiceSettings-output.log" | Out-File $LogPath -Append
			}
				
				$NotifyCount += 1
	}
	
If ($FailedSpn)
	{
		Write-Host "`n`n $NotifyCount. $NewName must have the SPN HOST/$FederationServiceName registered.`n    SPN registration failed during execution and must be handled manually.`n" -ForegroundColor "yellow"
		Write-Host "    Syntax:`n    setspn -S HOST/$FederationServiceName $NewName" -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. $NewName must have the SPN HOST/$FederationServiceName registered.`n    SPN registration failed during execution and must be handled manually.`n" | Out-File $LogPath -Append
		"    Syntax:`n    setspn -S HOST/$FederationServiceName $NewName" | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($FailedServiceIdentity)
	{
		Write-Host "`n`n $NotifyCount. Failed setting the AD FS service identity to $NewName during execution.`n    This must be set manually in the Services console." -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. Failed setting the AD FS service identity to $NewName during execution.`n    This must be set manually in the Services console." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($FailedAppPoolIdentity)
	{
		Write-Host "`n`n $NotifyCount. Failed setting the AdfsAppPool application pool identity to $NewName during execution.`n    This must be set manually in the IIS console." -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. Failed setting the AdfsAppPool application pool identity to $NewName during execution.`n    This must be set manually in the IIS console." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($FailedAppPoolRestart)
	{
		Write-Host "`n`n $NotifyCount. Failed AdfsAppPool application pool restart during execution.`n    This must be started manually in the IIS console." -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. Failed AdfsAppPool application pool restart during execution.`n    This must be started manually in the IIS console." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($Mode -eq 1)
	{
		Write-Host "`n`n $NotifyCount. Operating Mode $Mode was selected for this server, which means this sample must be executed`n    in Operating Mode 2 on the final server before the AD FS service is started on this server.`n    Once the sample has been run on the final server in Operating Mode 2, return to this server`n    to start the AD FS service." -ForegroundColor "yellow"
		"`n`n $NotifyCount. Operating Mode $Mode was selected for this server, which means this sample must be executed`n    in Operating Mode 2 on the final server before the AD FS service is started on this server.`n    Once the sample has been run on the final server in Operating Mode 2, return to this server`n    to start the AD FS service." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($SkipServiceStart)
	{
		Write-Host "`n`n $NotifyCount. Service start was skipped during execution due to post-sample needs. The service must be manually started.`n`n    Syntax:`n    net start adfssrv" -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. Service start was skipped during execution due to post-sample needs.`n    The service must be manually started." | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($FailedServiceStart)
	{
		Write-Host "`n`n $NotifyCount. Failed service start during execution.`n    The service must be manually started." -ForegroundColor "yellow"
		Write-Host "    Syntax: net start adfssrv" -ForegroundColor "yellow"
		
		"`n`n $NotifyCount. Failed service start during execution.`n    The service must be manually started." | Out-File $LogPath -Append
		"    Syntax: net start adfssrv" | Out-File $LogPath -Append
		$NotifyCount += 1
	}
	
If ($NotifyCount -eq 1)
	{
		Write-Host "`n No post-sample items" -ForegroundColor "green"
		"No post-sample items" | Out-File $LogPath -Append
	}

Write-Host "`n`n Sample completed successfully. See ADFS_Change_Service_Account.log in the current directory for detail`n" -ForegroundColor "green"
"[END TIME] $(Get-Date)" | Out-File $LogPath -Append

$ErrorActionPreference = "continue"



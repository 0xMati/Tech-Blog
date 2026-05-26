# Azure AD Connect – Copy ImmutableID to On-Prem ConsistencyGuid  
🗓️ Published: 2021-02-05  

---

## Description

This script is used to **synchronize the Azure AD `ImmutableID`** value into the **on-prem Active Directory `ms-DS-ConsistencyGuid`** attribute. It is typically executed **when changing the anchor** used by Azure AD Connect from `ObjectGUID` to `ms-DS-ConsistencyGuid`.

This is often required during **AAD Connect migrations**, or when aligning existing objects for hybrid join scenarios.

The script covers:
- User accounts across multiple OUs (EN, FR, US, NC)
- Azure AD Groups (Office 365 groups)
- Logging for trace, errors, updates, backups
- Alert email generation

---

## Features

- Reads on-prem accounts from various OUs
- Converts ObjectGUID to base64 (ImmutableID format)
- Writes value into `ms-DS-ConsistencyGuid` if empty or mismatched
- Logs:
  - Trace file
  - Error file
  - Update log
  - Backup file
  - System error log
- Email alert with logs as attachments

---

## ✅ Verification Points

- The script properly checks whether `ms-DS-ConsistencyGuid` is already set
- If the existing value matches, no changes are made
- If the value differs, it is flagged as inconsistent (and not overwritten automatically)
- Errors are logged and counted
- SMTP config and mail alert logic are working and customizable

---

## Script Entry Points

- Loop through predefined OUs: `EN`, `FR`, `US`, `NC`
- For each user:
  - Fetch `ObjectGUID`
  - Convert to base64 as ImmutableID
  - Compare with existing `ms-DS-ConsistencyGuid`
  - Update if null, log otherwise
- Same process applied to Office 365 groups

---

## Email Alert Behavior

If any errors are detected during processing:
- The email subject includes **KO** status
- Else, subject indicates **OK** status

Logs are attached to help admins review the processing status.

---

## Recommendations

- Test on a sample OU before applying to all environments
- Ensure `ms-DS-ConsistencyGuid` is not in use before script runs
- Backup AD objects or log snapshots before write operations
- Adapt SMTP and OU paths to your environment

---

## 💡 Notes

- Script assumes PowerShell modules `ActiveDirectory` and `AzureAD` are available
- The logic is defensive: it doesn't overwrite mismatched GUIDs automatically — logs instead
- Logging and alerting can be centralized with a monitoring system (e.g., SCOM, Splunk)

---

## Full PowerShell Script

```powershell
# Description : Copie ImmutableID Utilisateurs contoso.com 
# Description : dans mS-DS-ConsistencyGuid
# Version 1.0 : Start Version

$error.Clear()

# Import des modules utiles
Import-Module ActiveDirectory

$MyDate = (get-date -uformat "%Y%m%d_%H%M%S").ToString()
$MyOUArray = "EN","FR","US","NC"


# Parametrage SMTP
$SmtpServer = "smtp-int"
$MailFromGeneral = "exploit@contoso.com"
$RecipientGeneral = "admin@contoso.com"
$MailSubjectGeneral = "[AD][USERS & GROUPS][IMMUTABLEID][SET ATTRIBUTE]. TRAITEMENT QUOTIDIEN"

# Variables globales
$NbErreursTotal = 0

# Parametrage Fichiers et repertoires logs
$MyDirectory = "F:\Scripts\Office 365\ImmutableID"
$MyLogDirectory = "$($MyDirectory)\Logs"
$MyGeneralTraceFile = "$($MyLogDirectory)\General\General_Trace_$MyDate.log"
$MyErrorTraceFile = "$($MyLogDirectory)\Error\Error_Trace_$MyDate.log"
$MySystemErrorTraceFile = "$($MyLogDirectory)\Error\System_Error_Trace_$MyDate.log"
$MyUpdateTraceFile = "$($MyLogDirectory)\Update\Update_Trace_$MyDate.log"
$MyBackupTraceFile = "$($MyLogDirectory)\Backup\Backup_Trace_$MyDate.log"

Add-content -path $MyGeneralTraceFile "#-----------------------------------------------------------"
Add-content -path $MyGeneralTraceFile "#                       Trace Generale                      "
Add-content -path $MyGeneralTraceFile "#  Copy guid Utilisateur contoso.com vers ms-ds-consistencyguid  "
Add-content -path $MyGeneralTraceFile "#-----------------------------------------------------------"
Add-content -path $MyGeneralTraceFile ""
Add-content -path $MyGeneralTraceFile "Date et heure de debut $(Get-Date)"
Add-content -path $MyGeneralTraceFile "`r"
Add-content -path $MyGeneralTraceFile "Demarrage traitement"
Add-content -path $MyGeneralTraceFile "`r"

Add-content -path $MyErrorTraceFile "#-----------------------------------------------------------"
Add-content -path $MyErrorTraceFile "#                       Trace Erreurs                       "
Add-content -path $MyErrorTraceFile "#  Copy guid Utilisateur contoso.com vers ms-ds-consistencyguid  "
Add-content -path $MyErrorTraceFile "#-----------------------------------------------------------"
Add-content -path $MyErrorTraceFile ""
Add-content -path $MyErrorTraceFile "Date et heure de debut $(Get-Date)"
Add-content -path $MyErrorTraceFile "`r"
Add-content -path $MyErrorTraceFile "Demarrage traitement"
Add-content -path $MyErrorTraceFile "`r"

Add-content -path $MySystemErrorTraceFile "#-----------------------------------------------------------"
Add-content -path $MySystemErrorTraceFile "#                   Trace Erreurs System                    "
Add-content -path $MySystemErrorTraceFile "#  Copy guid Utilisateur contoso.com vers ms-ds-consistencyguid  "
Add-content -path $MySystemErrorTraceFile "#-----------------------------------------------------------"
Add-content -path $MySystemErrorTraceFile ""
Add-content -path $MySystemErrorTraceFile "Date et heure de debut $(Get-Date)"
Add-content -path $MySystemErrorTraceFile "`r"
Add-content -path $MySystemErrorTraceFile "Demarrage traitement"
Add-content -path $MySystemErrorTraceFile "`r"


Add-content -path $MyUpdateTraceFile "#-----------------------------------------------------------"
Add-content -path $MyUpdateTraceFile "#                        Trace Update                       "
Add-content -path $MyUpdateTraceFile "#  Copy guid Utilisateur contoso.com vers ms-ds-consistencyguid  "
Add-content -path $MyUpdateTraceFile "#-----------------------------------------------------------"
Add-content -path $MyUpdateTraceFile ""
Add-content -path $MyUpdateTraceFile "Date et heure de debut $(Get-Date)"
Add-content -path $MyUpdateTraceFile "`r"
Add-content -path $MyUpdateTraceFile "Demarrage traitement"
Add-content -path $MyUpdateTraceFile "`r"

Add-content -path $MyBackupTraceFile "#-----------------------------------------------------------"
Add-content -path $MyBackupTraceFile "#                        Trace Backup                       "
Add-content -path $MyBackupTraceFile "#  Copy guid Utilisateur contoso.com vers ms-ds-consistencyguid  "
Add-content -path $MyBackupTraceFile "#-----------------------------------------------------------"
Add-content -path $MyBackupTraceFile ""
Add-content -path $MyBackupTraceFile "Date et heure de debut $(Get-Date)"
Add-content -path $MyBackupTraceFile "`r"
Add-content -path $MyBackupTraceFile "Demarrage traitement"
Add-content -path $MyBackupTraceFile "`r"

# Traitement par OU Pays contoso.com
# Tous Utilisateurs
foreach ($OU in $MyOUArray) {
	$OU1 = "OU=OU1,OU=Utilisateurs,OU=$($OU),DC=CONTOSO,DC=com"
	$OU2 = "OU=OU2,OU=Utilisateurs,OU=$($OU),DC=CONTOSO,DC=com"
	$OU3 = "OU=OU3,OU=Utilisateurs,OU=$($OU),DC=CONTOSO,DC=com"
	
	$ListUsersOU1 = get-aduser -filter * -searchbase "$($OU1)" -properties samaccountname,objectguid,ms-ds-consistencyguid | select samaccountname,objectguid,ms-ds-consistencyguid | sort-object samaccountname
	$ListUsersOU2 = get-aduser -filter * -searchbase "$($OU2)" -properties samaccountname,objectguid,ms-ds-consistencyguid | select samaccountname,objectguid,ms-ds-consistencyguid | sort-object samaccountname
	$ListUsersOU3 = get-aduser -filter * -searchbase "$($OU3)" -properties samaccountname,objectguid,ms-ds-consistencyguid | select samaccountname,objectguid,ms-ds-consistencyguid | sort-object samaccountname
	
	$NBListUsersOU1 = (get-aduser -filter * -searchbase "$($OU1)" -properties samaccountname,objectguid,ms-ds-consistencyguid | measure-object).count
	$NBListUsersOU2 = (get-aduser -filter * -searchbase "$($OU2)" -properties samaccountname,objectguid,ms-ds-consistencyguid | measure-object).count
	$NBListUsersOU3 = (get-aduser -filter * -searchbase "$($OU3)" -properties samaccountname,objectguid,ms-ds-consistencyguid | measure-object).count
	
	$NbUsersDefaut = 0
	$NbUsersDSI = 0
	$NbUsersHisto = 0
	$NbUsersHistoT = 0
	$NbUsersOffshore = 0
	
	$NbErreursDefaut = 0
	$NbErreursDSI = 0
	$NbErreursHisto = 0
	$NbErreursHistoT = 0
	$NbErreursOffshore = 0
	
	$NbUpdateDefaut = 0
	$NbUpdateDSI = 0
	$NbUpdateHisto = 0
	$NbUpdateHistoT = 0
	$NbUpdateOffshore = 0
	
	Add-content -path $MyGeneralTraceFile "OU traitee : $($OU1)"
	Add-content -path $MyUpdateTraceFile "OU traitee : $($OU1)"
	Add-content -path $MyErrorTraceFile "OU traitee : $($OU1)"
	Add-content -path $MyBackupTraceFile "OU traitee : $($OU1)"
	
	if ($NBListUsersOU1 -gt 0){
		foreach ($UsersDefaut in $ListUsersOU1) {
			$CurrentUserSAMA = $UsersDefaut.samaccountname
			$CurrentUserGuid = $UsersDefaut.objectguid
			$CurrentUserConsistencyGuid = $UsersDefaut."ms-ds-consistencyguid"
			Add-content -path $MyBackupTraceFile "Utilisateur : $($CurrentUserSAMA), Guid : $($CurrentUserGuid), ms-DS-ConsistencyGuid : $($CurrentUserConsistencyGuid)."
			$CurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserGuid)).tobytearray())
			# write-host $CurrentUserSAMA,$CurrentUserGuid,$CurrentUserConsistencyGuid,$CurrentUserIimmutableid
			if ($CurrentUserConsistencyGuid -eq $null) {
				set-aduser $CurrentUserSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentUserGuid}
				Add-content -path $MyUpdateTraceFile "Utilisateur $($CurrentUserSAMA) modifie."
				$NbUpdateDefaut++
				}
				else {
					$OldCurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserConsistencyGuid)).tobytearray())
					if ($OldCurrentUserIimmutableid -eq $CurrentUserIimmutableid) {
						Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA).Valeur deja positionnee."
						}
						else {
						Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA).Valeur incoherente. Erreur !"
						$NbErreursDefaut++
					}
				}
			Add-content -path $MyGeneralTraceFile "Utilisateur $($CurrentUserSAMA) traite."
			$NbUsersDefaut++
			}
	}
	
	Add-content -path $MyGeneralTraceFile "Nb Users traites : $($NbUsersDefaut)"
	Add-content -path $MyGeneralTraceFile "`r"
	
	Add-content -path $MyUpdateTraceFile "Nb Users mis a jour : $($NbUpdateDefaut)"
	Add-content -path $MyUpdateTraceFile "`r"
	
	Add-content -path $MyErrorTraceFile "Nb Users en erreur : $($NbErreursDefaut)"
	Add-content -path $MyErrorTraceFile "`r"
		
	Add-content -path $MyGeneralTraceFile "OU traitee : $($OU2)"
	Add-content -path $MyUpdateTraceFile "OU traitee : $($OU2)"
	Add-content -path $MyErrorTraceFile "OU traitee : $($OU2)"
	Add-content -path $MyBackupTraceFile "OU traitee : $($OU2)"
	
	if ($NBListUsersOU2 -gt 0){
		foreach ($UsersHisto in $ListUsersOU2) {
			$CurrentUserSAMA = $UsersHisto.samaccountname
			$CurrentUserGuid = $UsersHisto.objectguid
			$CurrentUserConsistencyGuid = $UsersHisto."ms-ds-consistencyguid"
			Add-content -path $MyBackupTraceFile "Utilisateur : $($CurrentUserSAMA), Guid : $($CurrentUserGuid), ms-DS-ConsistencyGuid : $($CurrentUserConsistencyGuid)."
			$CurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserGuid)).tobytearray())
			if ($CurrentUserConsistencyGuid -eq $null) {
				set-aduser $CurrentUserSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentUserGuid}
				Add-content -path $MyUpdateTraceFile "Utilisateur $($CurrentUserSAMA) modifie."
				$NbUpdateHisto++
				}
				else {
					$OldCurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserConsistencyGuid)).tobytearray())
					if ($OldCurrentUserIimmutableid -eq $CurrentUserIimmutableid) {
						Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur deja positionnee."
						}
						else {
						Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur incoherente. Erreur !"
						$NbErreursHisto++
					}
				}
			Add-content -path $MyGeneralTraceFile "Utilisateur $($CurrentUserSAMA) traite."
			$NbUsersHisto++
			}
	}
	
	Add-content -path $MyGeneralTraceFile "Nb Users traites : $($NbUsersHisto)"
	Add-content -path $MyGeneralTraceFile "`r"
	
	Add-content -path $MyUpdateTraceFile "Nb Users mis a jour : $($NbUpdateHisto)"
	Add-content -path $MyUpdateTraceFile "`r"
	
	Add-content -path $MyErrorTraceFile "Nb Users en erreur : $($NbErreursHisto)"
	Add-content -path $MyErrorTraceFile "`r"
	
	Add-content -path $MyGeneralTraceFile "OU traitee : $($OU3)"
	Add-content -path $MyUpdateTraceFile "OU traitee : $($OU3)"
	Add-content -path $MyErrorTraceFile "OU traitee : $($OU3)"
	Add-content -path $MyBackupTraceFile "OU traitee : $($OU3)"

	if ($NBListUsersOU3 -gt 0){
		foreach ($UsersHistoT in $ListUsersOU3) {
			$CurrentUserSAMA = $UsersHistoT.samaccountname
			$CurrentUserGuid = $UsersHistoT.objectguid
			$CurrentUserConsistencyGuid = $UsersHistoT."ms-ds-consistencyguid"
			Add-content -path $MyBackupTraceFile "Utilisateur : $($CurrentUserSAMA), Guid : $($CurrentUserGuid), ms-DS-ConsistencyGuid : $($CurrentUserConsistencyGuid)."
			$CurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserGuid)).tobytearray())
			if ($CurrentUserConsistencyGuid -eq $null) {
				set-aduser $CurrentUserSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentUserGuid}
				Add-content -path $MyUpdateTraceFile "Utilisateur $($CurrentUserSAMA) modifie."
				$NbUpdateHistoT++
				}
				else {
					$OldCurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserConsistencyGuid)).tobytearray())
					if ($OldCurrentUserIimmutableid -eq $CurrentUserIimmutableid) {
						Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur deja positionnee."
						}
						else {
						Add-content -path $MyErrorTraceFile "Utilisateur $($CurrentUserSAMA). Valeur incoherente. Erreur !"
						$NbErreursHistoT++
					}
				}
			Add-content -path $MyGeneralTraceFile "Utilisateur $($CurrentUserSAMA) traite."
			$NbUsersHistoT++
		}
	}
	
	Add-content -path $MyGeneralTraceFile "Nb Users traites : $($NbUsersHistoT)"
	Add-content -path $MyGeneralTraceFile "`r"
	
	Add-content -path $MyUpdateTraceFile "Nb Users mis a jour : $($NbUpdateHistoT)"
	Add-content -path $MyUpdateTraceFile "`r"
	
	Add-content -path $MyErrorTraceFile "Nb Users en erreur : $($NbErreursHistoT)"
	Add-content -path $MyErrorTraceFile "`r"
	
	if ($OU -eq "FR") {
		$OUDSI = "OU=DSI,OU=Utilisateurs,OU=FR,DC=CONTOSO,DC=com"
		$OUOffShore = "OU=OffShore,OU=Utilisateurs,OU=FR,DC=CONTOSO,DC=com"
		
		$ListUsersDSI = get-aduser -filter * -searchbase "$($OUDSI)" -properties samaccountname,objectguid,ms-ds-consistencyguid | select samaccountname,objectguid,ms-ds-consistencyguid | sort-object samaccountname
		$ListUsersOffShore = get-aduser -filter * -searchbase "$($OUOffShore)" -properties samaccountname,objectguid,ms-ds-consistencyguid | select samaccountname,objectguid,ms-ds-consistencyguid | sort-object samaccountname
		
		$NBListUsersDSI = (get-aduser -filter * -searchbase "$($OUDSI)" -properties samaccountname,objectguid,ms-ds-consistencyguid | measure-object).count
		$NBListUsersOffshore = (get-aduser -filter * -searchbase "$($OUOffShore)" -properties samaccountname,objectguid,ms-ds-consistencyguid | measure-object).count
		
		Add-content -path $MyGeneralTraceFile "OU traitee : $($OUDSI)"
		Add-content -path $MyUpdateTraceFile "OU traitee : $($OUDSI)"
		Add-content -path $MyErrorTraceFile "OU traitee : $($OUDSI)"
		Add-content -path $MyBackupTraceFile "OU traitee : $($OUDSI)"
		
		if ($NBListUsersDSI -gt 0){
			foreach ($UsersDSI in $ListUsersDSI) {
				$CurrentUserSAMA = $UsersDSI.samaccountname
				$CurrentUserGuid = $UsersDSI.objectguid
				$CurrentUserConsistencyGuid = $UsersDSI."ms-ds-consistencyguid"
				Add-content -path $MyBackupTraceFile "Utilisateur : $($CurrentUserSAMA), Guid : $($CurrentUserGuid), ms-DS-ConsistencyGuid : $($CurrentUserConsistencyGuid)."
				$CurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserGuid)).tobytearray())
				if ($CurrentUserConsistencyGuid -eq $null) {
					set-aduser $CurrentUserSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentUserGuid}
					Add-content -path $MyUpdateTraceFile "Utilisateur $($CurrentUserSAMA) modifie."
					$NbUpdateDSI++
					}
					else {
						$OldCurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserConsistencyGuid)).tobytearray())
						if ($OldCurrentUserIimmutableid -eq $CurrentUserIimmutableid) {
							Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur deja positionnee."
							}
							else {
							Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur incoherente. Erreur !"
							$NbErreursDSI++
							}
					}
				Add-content -path $MyGeneralTraceFile "Utilisateur $($CurrentUserSAMA) traite."
				$NbUsersDSI++
			}
		}
		
		Add-content -path $MyGeneralTraceFile "Nb Users traites : $($NbUsersDSI)"
		Add-content -path $MyGeneralTraceFile "`r"
		
		Add-content -path $MyUpdateTraceFile "Nb Users mis a jour : $($NbUpdateDSI)"
		Add-content -path $MyUpdateTraceFile "`r"
		
		Add-content -path $MyErrorTraceFile "Nb Users en erreur : $($NbErreursDSI)"
		Add-content -path $MyErrorTraceFile "`r"
		
		Add-content -path $MyGeneralTraceFile "OU traitee : $($OUOffshore)"
		Add-content -path $MyUpdateTraceFile "OU traitee : $($OUOffshore)"
		Add-content -path $MyErrorTraceFile "OU traitee : $($OUOffshore)"
		Add-content -path $MyBackupTraceFile "OU traitee : $($OUOffshore)"
		
		if ($NBListUsersOffshore -gt 0){
			foreach ($UsersOffShore in $ListUsersOffShore) {
				$CurrentUserSAMA = $UsersOffShore.samaccountname
				$CurrentUserGuid = $UsersOffShore.objectguid
				$CurrentUserConsistencyGuid = $UsersOffShore."ms-ds-consistencyguid"
				Add-content -path $MyBackupTraceFile "Utilisateur : $($CurrentUserSAMA), Guid : $($CurrentUserGuid), ms-DS-ConsistencyGuid : $($CurrentUserConsistencyGuid)."
				$CurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserGuid)).tobytearray())
				if ($CurrentUserConsistencyGuid -eq $null) {
					set-aduser $CurrentUserSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentUserGuid}
					Add-content -path $MyUpdateTraceFile "Utilisateur $($CurrentUserSAMA) modifie."
					$NbUpdateOffshore++
					}
					else {
						$OldCurrentUserIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentUserConsistencyGuid)).tobytearray())
						if ($OldCurrentUserIimmutableid -eq $CurrentUserIimmutableid) {
							Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur deja positionnee."
							}
							else {
							Add-content -path $MyErrorTraceFile "Utilisateur : $($CurrentUserSAMA). Valeur incoherente. Erreur !"
							$NbErreursOffshore++
							}
					}
				Add-content -path $MyGeneralTraceFile "Utilisateur $($CurrentUserSAMA) traite."
				$NbUsersOffshore++
				}
			}
		
		Add-content -path $MyGeneralTraceFile "Nb Users traites : $($NbUsersOffshore)"
		Add-content -path $MyGeneralTraceFile "`r"
		
		Add-content -path $MyUpdateTraceFile "Nb Users mis a jour : $($NbUpdateOffshore)"
		Add-content -path $MyUpdateTraceFile "`r"
		
		Add-content -path $MyErrorTraceFile "Nb Users en erreur : $($NbErreursOffshore)"
		Add-content -path $MyErrorTraceFile "`r"
		
		}
		$NbErreursTotal = $NbErreursTotal  + $NbErreursDefaut + $NbErreursDSI + $NbErreursHisto + $NbErreursHistoT + $NbErreursOffshore
}


# Tous Groupes Office365

$OUOffice365 = "OU=Groupes,OU=Office 365,DC=CONTOSO,DC=com"
$ListGroupsOff365 = get-adgroup -filter * -searchbase "$($OUOffice365)" -properties distinguishedName,objectguid,ms-ds-consistencyguid | select distinguishedName,objectguid,ms-ds-consistencyguid | sort-object distinguishedName


$NbGroupsOff365 = 0
$NbUpdateOff365 = 0
$NbErreursOff365 = 0

Add-content -path $MyGeneralTraceFile "OU traitee : $($OUOffice365)"
Add-content -path $MyUpdateTraceFile "OU traitee : $($OUOffice365)"
Add-content -path $MyErrorTraceFile "OU traitee : $($OUOffice365)"
Add-content -path $MyBackupTraceFile "OU traitee : $($OUOffice365)"

foreach ($GroupsOff365 in $ListGroupsOff365) {
			$CurrentGroupSAMA = $GroupsOff365.distinguishedName
			$CurrentGroupGuid = $GroupsOff365.objectguid
			$CurrentGroupConsistencyGuid = $GroupsOff365."ms-ds-consistencyguid"
			Add-content -path $MyBackupTraceFile "Groupe : $($CurrentGroupSAMA), Guid : $($CurrentGroupGuid), ms-DS-ConsistencyGuid : $($CurrentGroupConsistencyGuid)."
			$CurrentGroupIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentGroupGuid)).tobytearray())
			# write-host $CurrentGroupSAMA,$CurrentGroupGuid,$CurrentGroupConsistencyGuid,$CurrentGroupIimmutableid
			if ($CurrentGroupConsistencyGuid -eq $null) {
				set-adgroup $CurrentGroupSAMA -add @{"mS-DS-ConsistencyGuid"=$CurrentGroupGuid}
				Add-content -path $MyUpdateTraceFile "Groupe $($CurrentGroupSAMA) modifie."
				$NbUpdateOff365++
				}
				else {
					$OldCurrentGroupIimmutableid = [system.convert]::ToBase64String(([GUID]($CurrentGroupConsistencyGuid)).tobytearray())
					if ($OldCurrentGroupIimmutableid -eq $CurrentGroupIimmutableid) {
						Add-content -path $MyErrorTraceFile "Groupe : $($CurrentGroupSAMA). Valeur deja positionnee."
						}
						else {
						Add-content -path $MyErrorTraceFile "Groupe : $($CurrentGroupSAMA). Valeur incoherente. Erreur !"
						$NbErreursOff365++
					}
				}
			Add-content -path $MyGeneralTraceFile "Groupe $($CurrentGroupSAMA) traite."
			$NbGroupsOff365++
			}

if ($error.count -gt 0) {
	Add-content -path $MySystemErrorTraceFile $($error)
	Add-content -path $MySystemErrorTraceFile "`r"
	Add-content -path $MySystemErrorTraceFile "Total nb erreurs systeme : $($error.count)."
	Add-content -path $MySystemErrorTraceFile "`r"
	}
	else {
	Add-content -path $MySystemErrorTraceFile "Aucun erreur system signalee."
	Add-content -path $MySystemErrorTraceFile "`r"
}
Add-content -path $MySystemErrorTraceFile "`r"
Add-content -path $MySystemErrorTraceFile "Traitement termine."


Add-content -path $MyUpdateTraceFile "Nb groupes mis a jour : $($NbUpdateOff365)"
Add-content -path $MyUpdateTraceFile "`r"

$NbErreursTotal = $NbErreursTotal + $NbErreursOff365

Add-content -path $MyGeneralTraceFile "`r"
Add-content -path $MyGeneralTraceFile "Traitement termine."

Add-content -path $MyErrorTraceFile "`r"
Add-content -path $MyErrorTraceFile "Total nb erreurs : $($NbErreursTotal)."
Add-content -path $MyErrorTraceFile "`r"
Add-content -path $MyErrorTraceFile "Traitement termine."

Add-content -path $MyUpdateTraceFile "`r"
Add-content -path $MyUpdateTraceFile "Traitement termine."

Add-content -path $MyBackupTraceFile "`r"
Add-content -path $MyBackupTraceFile "Traitement termine."

# Generation Message Alerte

if ($NbErreursTotal -gt 0) {
	$MailSubjectGeneral = "[AD][USERS & GROUPS][IMMUTABLEID][SET ATTRIBUTE]. TRAITEMENT QUOTIDIEN. TRAITEMENT KO"}
	else {
	$MailSubjectGeneral = "[AD][USERS & GROUPS][IMMUTABLEID][SET ATTRIBUTE]. TRAITEMENT QUOTIDIEN. TRAITEMENT OK"
}
	$mailbodyGeneral = "Bonjour,"
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "Merci de trouver ci joints les logs du traitement de mise a jour de l'ImmutableID (Users & Groups) du domaine contoso.com."
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "Cordialement."
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "`r"
	$mailbodyGeneral += "La DOI/DSI."
	Send-MailMessage -From $MailFromGeneral -To $RecipientGeneral -Subject $MailSubjectGeneral -Body $MailbodyGeneral -SmtpServer $SmtpServer  -Attachments $MyGeneralTraceFile, $MyErrorTraceFile, $MySystemErrorTraceFile, $MyUpdateTraceFile, $MyBackupTraceFile
	Add-content -path $MyErrorTraceFile "`r"
	Add-content -path $MyErrorTraceFile "Message d alerte envoye."
#	}

```
# AD SmartCard and Secure Channel Incident Runbook

Date: 2026-04-26

Ce document est une checklist de troubleshooting pur, utilisee en live pendant l investigation.

Regles de travail:
- Une seule variable changee a la fois.
- Un test = un resultat = une interpretation = une action.
- Pas de remediation lourde sans preuve technique.

---

## 1) Preparatifs de session

- [ ] Choisir les machines de reference [Cible: session]
	- [ ] 1 DC impacte
	- [ ] 1 poste sain (secure channel OK)
	- [ ] 2 postes en echec
- [ ] Verifier les acces [Cible: DC + postes]
	- [ ] droits admin local sur postes
	- [ ] droits admin sur DC
	- [ ] acces Event Viewer DC
	- [ ] acces PKIView
- [ ] Ouvrir les consoles GUI [Cible: DC + postes]
	- [ ] Event Viewer (KDC Operational, CAPI2, System)
	- [ ] certlm.msc sur DC
	- [ ] services.msc (DC + postes)
	- [ ] pkiview.msc

---

## 2) Etape prioritaire: valider PKI/KDC avant tout

Objectif: prouver que la smart card peut fonctionner sur un poste sain.

- [ ] Verifier certificat DC utilisable KDC [Cible: DC]
	- Commande: `certutil -store my`
	- GUI: `certlm.msc > Personal > Certificates`
	- Verifier: cert non expire, cle privee, EKU coherent, chaine complete
	- Si KO: reenroler cert DC et verifier template

- [ ] Verifier revocation et sante KDC [Cible: DC]
	- Commande: `certutil -dcinfo verify`
	- GUI: Event Viewer KDC/Kerberos
	- Verifier: plus d erreur revocation offline
	- Si KO: corriger CRL/delta/AIA/CDP

- [ ] Verifier coherence CRL/delta [Cible: DC/PKI]
	- Commande: pas necessaire (outil GUI principal)
	- GUI: `pkiview.msc`
	- Verifier: CDP/AIA en vert, dates valides, coherence base/delta
	- Si KO: republier CRL + delta, verifier replication

- [ ] Verifier chaine/revocation du cert DC [Cible: DC]
	- Commande: `certutil -urlfetch -verify <DCcert.cer>`
	- GUI: Ouvrir cert > Certification Path
	- Verifier: chaque maillon valide
	- Si KO: corriger stores Root/CA + publication CRL

- [ ] Verifier NTAuth [Cible: DC/PKI]
	- Commande: `certutil -enterprise -viewstore NTAuth`
	- GUI: PKI MMC / ADSIEdit
	- Verifier: CA smart card presente
	- Si KO: publier CA dans NTAuth

- [ ] Capturer erreurs KDC/CAPI2 pendant un test smart card [Cible: DC + poste sain]
	- Commandes:
		- `Get-WinEvent -LogName "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" -MaxEvents 200`
		- `Get-WinEvent -LogName "Microsoft-Windows-CAPI2/Operational" -MaxEvents 200`
	- GUI: Event Viewer (KDC Operational + CAPI2)
	- Verifier: erreur de mapping, revocation, cert KDC
	- Si KO: corriger d abord ce bloc avant de toucher aux postes KO

Decision immediate:
- Si smart card KO sur poste sain -> rester en bloc PKI/KDC.
- Si smart card OK sur poste sain -> passer au bloc secure channel.

---

## 3) Troubleshoot postes en echec (secure channel)

Objectif: retablir la relation de confiance machine/DC.

- [ ] Verifier DNS client AD [Cible: poste en echec]
	- Commande: `ipconfig /all`
	- GUI: `ncpa.cpl` (DNS IPv4)
	- Verifier: DNS AD uniquement
	- Si KO: corriger DNS puis retester

- [ ] Verifier DC locator [Cible: poste en echec]
	- Commandes:
		- `nslookup -type=srv _ldap._tcp.dc._msdcs.<domaine>`
		- `nltest /dsgetdc:<domaine>`
	- GUI: DNS Manager + test `\\<domaine>\SYSVOL`
	- Verifier: DC trouve et joignable
	- Si KO: corriger DNS/reseau/site AD

- [ ] Verifier synchronisation horaire [Cible: poste en echec]
	- Commande: `w32tm /query /status`
	- GUI: `timedate.cpl`
	- Verifier: offset faible
	- Si KO: resync temps

- [ ] Verifier secure channel [Cible: poste en echec]
	- Commandes:
		- `Test-ComputerSecureChannel -Verbose`
		- `nltest /sc_verify:<domaine>`
	- GUI: Event Viewer System (Netlogon)
	- Verifier: secure channel True
	- Si KO: lancer reparation

- [ ] Reparer secure channel (sans rejoin d abord) [Cible: poste en echec]
	- Commandes:
		- `Test-ComputerSecureChannel -Repair -Credential <DOM\\Admin>`
		- `Reset-ComputerMachinePassword -Server <DC_FQDN> -Credential <DOM\\Admin>`
	- GUI: pas d equivalent direct fiable
	- Verifier: reboot puis secure channel True
	- Si KO: faire rejoin propre

- [ ] Rejoin domaine (dernier recours) [Cible: poste en echec + AD]
	- Commande: optionnel
	- GUI: `sysdm.cpl > Computer Name > Change`
	- Verifier: domaine OK apres reboot + objet AD propre
	- Si KO: recreer objet ordinateur et revalider DNS/time

---

## 4) Tests avances (si causes non evidentes)

- [ ] Connectivite ports AD/Kerberos [Cible: poste sain + poste en echec vers DC]
	- Commande:
		- `Test-NetConnection <DC_FQDN> -Port 88`
		- `Test-NetConnection <DC_FQDN> -Port 389`
		- `Test-NetConnection <DC_FQDN> -Port 445`
		- `Test-NetConnection <DC_FQDN> -Port 53`
	- GUI: PortQryUI / firewall logs
	- Pourquoi: eliminer blocage reseau L4

- [ ] Cache Kerberos utilisateur et SYSTEM [Cible: poste en echec]
	- Commandes:
		- `klist`
		- `klist purge`
		- `klist -li 0x3e7`
		- `klist -li 0x3e7 purge`
	- GUI: pas de GUI fiable
	- Pourquoi: eliminer tickets stale

- [ ] Services Netlogon/KDC [Cible: DC + poste en echec]
	- Commande: `sc query netlogon` ; `sc query kdc`
	- GUI: `services.msc`
	- Pourquoi: verifier etat service et demarrage

- [ ] Debug Netlogon temporaire [Cible: poste en echec + DC]
	- Commande: `nltest /dbflag:0x2080ffff`
	- GUI: Event Viewer System
	- Pourquoi: obtenir detail cause trust
	- Cleanup obligatoire: `nltest /dbflag:0x0`

- [ ] Validation CRL en contexte SYSTEM [Cible: DC]
	- Commande: `psexec -s cmd /c certutil -urlfetch -verify <DCcert.cer>`
	- GUI: Task Scheduler (Run as SYSTEM)
	- Pourquoi: detecter ecart User vs SYSTEM

- [ ] Verifier durcissement mapping certificat [Cible: DC]
	- Commandes:
		- `reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement`
		- `reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v CertificateBackdating`
	- GUI: `regedit`
	- Pourquoi: confirmer niveau enforcement PKINIT/mapping

- [ ] Verifier coherence multi-DC [Cible: tous les DC]
	- Commandes:
		- `certutil -store my`
		- `certutil -dcinfo verify`
	- GUI: `certlm.msc` sur chaque DC
	- Pourquoi: detecter heterogeneite entre DC

- [ ] Comparatif poste sain vs poste en echec [Cible: poste sain + poste en echec]
	- Commandes:
		- `ipconfig /all`
		- `w32tm /query /status`
		- `klist`
		- `sc query netlogon`
		- `gpresult /r`
	- GUI: `ncpa.cpl`, `timedate.cpl`, `services.msc`, `rsop.msc`
	- Pourquoi: isoler la premiere difference technique reelle entre un poste qui marche et un poste qui casse

- [ ] Verification replication AD [Cible: DC]
	- Commandes:
		- `repadmin /replsummary`
		- `repadmin /showrepl`
	- GUI: `dssite.msc` (Sites and Services)
	- Pourquoi: detecter un DC en retard ou en echec de replication qui provoque des comportements incoherents

- [ ] Verification sante DNS AD [Cible: DC]
	- Commande: `dcdiag /test:DNS /v`
	- GUI: `dnsmgmt.msc` + Event Viewer DNS Server
	- Pourquoi: valider enregistrements SRV et resolution AD, souvent causes racines cachees

- [ ] Test force sur DC specifique [Cible: poste sain + poste en echec]
	- Commandes:
		- `nltest /server:<POSTE> /sc_reset:<domaine>\<DC_NETBIOS>`
		- `nltest /server:<POSTE> /dsgetdc:<domaine> /force`
	- GUI: pas de GUI simple
	- Pourquoi: verifier si le probleme est global domaine ou limite a un DC particulier

- [ ] Correlation test smart card client + DC [Cible: poste sain + DC]
	- Commandes:
		- (client) tentative logon smart card
		- (DC) `Get-WinEvent` KDC/CAPI2 sur la meme minute
	- GUI: Event Viewer client et DC ouverts en parallele
	- Pourquoi: prouver precisement ou la chaine casse (client, mapping KDC, revocation, certificat)

- [ ] Verification middleware / minidriver YubiKey [Cible: poste sain + poste en echec]
	- Commandes:
		- `certutil -scinfo`
		- `Get-PnpDevice | findstr /i yubikey`
	- GUI: Device Manager + YubiKey Manager
	- Pourquoi: eliminer un probleme poste local (driver/KSP) qui peut mimer un probleme AD

---

## 5) Collecte technique minimale (pendant le troubleshooting)

- [ ] Export logs KDC Operational [Cible: DC]
- [ ] Export logs CAPI2 Operational [Cible: DC]
- [ ] Export logs System/Netlogon [Cible: poste en echec + DC]
- [ ] Capture PKIView [Cible: PKI/DC]
- [ ] Capture `ipconfig /all` et `w32tm /query /status` [Cible: poste en echec]

But: pouvoir prouver la cause racine et eviter les hypotheses non verifiees.

---

## 6) Validation finale et non-regression

- [ ] Smart card login OK [Cible: poste sain]
- [ ] Smart card login OK [Cible: au moins un poste repare]
- [ ] `Test-ComputerSecureChannel -Verbose` = True [Cible: poste 1 en echec]
- [ ] `Test-ComputerSecureChannel -Verbose` = True [Cible: poste 2 en echec]
- [ ] `gpupdate /force` OK [Cible: postes repares]
- [ ] `nltest /dsgetdc:<domaine>` OK [Cible: postes repares]
- [ ] Verification apres reboot: toujours OK [Cible: DC + postes testes]
- [ ] Verification J+1: toujours OK [Cible: echantillon postes + au moins 1 DC]

Si rechute apres reboot/J+1:
- suspecter replication AD/DNS/PKI ou heterogeneite multi-DC.

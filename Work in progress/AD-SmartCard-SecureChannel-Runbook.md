# AD SmartCard and Secure Channel Incident Runbook

Date: 2026-04-26

Ce document est une checklist de troubleshooting pur, utilisee en live pendant l investigation.

Regles de travail:
- Une seule variable changee a la fois.
- Un test = un resultat = une interpretation = une action.
- Pas de remediation lourde sans preuve technique.

---

## 1) Preparatifs de session

- [ ] Choisir les machines de reference:
	- [ ] 1 DC impacte
	- [ ] 1 poste sain (secure channel OK)
	- [ ] 2 postes en echec
- [ ] Verifier les acces:
	- [ ] droits admin local sur postes
	- [ ] droits admin sur DC
	- [ ] acces Event Viewer DC
	- [ ] acces PKIView
- [ ] Ouvrir les consoles GUI:
	- [ ] Event Viewer (KDC Operational, CAPI2, System)
	- [ ] certlm.msc sur DC
	- [ ] services.msc (DC + postes)
	- [ ] pkiview.msc

---

## 2) Etape prioritaire: valider PKI/KDC avant tout

Objectif: prouver que la smart card peut fonctionner sur un poste sain.

- [ ] Verifier certificat DC utilisable KDC
	- Commande: `certutil -store my`
	- GUI: `certlm.msc > Personal > Certificates`
	- Verifier: cert non expire, cle privee, EKU coherent, chaine complete
	- Si KO: reenroler cert DC et verifier template

- [ ] Verifier revocation et sante KDC
	- Commande: `certutil -dcinfo verify`
	- GUI: Event Viewer KDC/Kerberos
	- Verifier: plus d erreur revocation offline
	- Si KO: corriger CRL/delta/AIA/CDP

- [ ] Verifier coherence CRL/delta
	- Commande: pas necessaire (outil GUI principal)
	- GUI: `pkiview.msc`
	- Verifier: CDP/AIA en vert, dates valides, coherence base/delta
	- Si KO: republier CRL + delta, verifier replication

- [ ] Verifier chaine/revocation du cert DC
	- Commande: `certutil -urlfetch -verify <DCcert.cer>`
	- GUI: Ouvrir cert > Certification Path
	- Verifier: chaque maillon valide
	- Si KO: corriger stores Root/CA + publication CRL

- [ ] Verifier NTAuth
	- Commande: `certutil -enterprise -viewstore NTAuth`
	- GUI: PKI MMC / ADSIEdit
	- Verifier: CA smart card presente
	- Si KO: publier CA dans NTAuth

- [ ] Capturer erreurs KDC/CAPI2 pendant un test smart card
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

- [ ] Verifier DNS client AD
	- Commande: `ipconfig /all`
	- GUI: `ncpa.cpl` (DNS IPv4)
	- Verifier: DNS AD uniquement
	- Si KO: corriger DNS puis retester

- [ ] Verifier DC locator
	- Commandes:
		- `nslookup -type=srv _ldap._tcp.dc._msdcs.<domaine>`
		- `nltest /dsgetdc:<domaine>`
	- GUI: DNS Manager + test `\\<domaine>\SYSVOL`
	- Verifier: DC trouve et joignable
	- Si KO: corriger DNS/reseau/site AD

- [ ] Verifier synchronisation horaire
	- Commande: `w32tm /query /status`
	- GUI: `timedate.cpl`
	- Verifier: offset faible
	- Si KO: resync temps

- [ ] Verifier secure channel
	- Commandes:
		- `Test-ComputerSecureChannel -Verbose`
		- `nltest /sc_verify:<domaine>`
	- GUI: Event Viewer System (Netlogon)
	- Verifier: secure channel True
	- Si KO: lancer reparation

- [ ] Reparer secure channel (sans rejoin d abord)
	- Commandes:
		- `Test-ComputerSecureChannel -Repair -Credential <DOM\\Admin>`
		- `Reset-ComputerMachinePassword -Server <DC_FQDN> -Credential <DOM\\Admin>`
	- GUI: pas d equivalent direct fiable
	- Verifier: reboot puis secure channel True
	- Si KO: faire rejoin propre

- [ ] Rejoin domaine (dernier recours)
	- Commande: optionnel
	- GUI: `sysdm.cpl > Computer Name > Change`
	- Verifier: domaine OK apres reboot + objet AD propre
	- Si KO: recreer objet ordinateur et revalider DNS/time

---

## 4) Tests avances (si causes non evidentes)

- [ ] Connectivite ports AD/Kerberos
	- Commande:
		- `Test-NetConnection <DC_FQDN> -Port 88`
		- `Test-NetConnection <DC_FQDN> -Port 389`
		- `Test-NetConnection <DC_FQDN> -Port 445`
		- `Test-NetConnection <DC_FQDN> -Port 53`
	- GUI: PortQryUI / firewall logs
	- Pourquoi: eliminer blocage reseau L4

- [ ] Cache Kerberos utilisateur et SYSTEM
	- Commandes:
		- `klist`
		- `klist purge`
		- `klist -li 0x3e7`
		- `klist -li 0x3e7 purge`
	- GUI: pas de GUI fiable
	- Pourquoi: eliminer tickets stale

- [ ] Services Netlogon/KDC
	- Commande: `sc query netlogon` ; `sc query kdc`
	- GUI: `services.msc`
	- Pourquoi: verifier etat service et demarrage

- [ ] Debug Netlogon temporaire
	- Commande: `nltest /dbflag:0x2080ffff`
	- GUI: Event Viewer System
	- Pourquoi: obtenir detail cause trust
	- Cleanup obligatoire: `nltest /dbflag:0x0`

- [ ] Validation CRL en contexte SYSTEM
	- Commande: `psexec -s cmd /c certutil -urlfetch -verify <DCcert.cer>`
	- GUI: Task Scheduler (Run as SYSTEM)
	- Pourquoi: detecter ecart User vs SYSTEM

- [ ] Verifier durcissement mapping certificat
	- Commandes:
		- `reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement`
		- `reg query HKLM\SYSTEM\CurrentControlSet\Services\Kdc /v CertificateBackdating`
	- GUI: `regedit`
	- Pourquoi: confirmer niveau enforcement PKINIT/mapping

- [ ] Verifier coherence multi-DC
	- Commandes:
		- `certutil -store my`
		- `certutil -dcinfo verify`
	- GUI: `certlm.msc` sur chaque DC
	- Pourquoi: detecter heterogeneite entre DC

---

## 5) Collecte technique minimale (pendant le troubleshooting)

- [ ] Export logs KDC Operational (DC)
- [ ] Export logs CAPI2 Operational (DC)
- [ ] Export logs System/Netlogon (poste KO + DC)
- [ ] Capture PKIView
- [ ] Capture `ipconfig /all` et `w32tm /query /status` sur poste KO

But: pouvoir prouver la cause racine et eviter les hypotheses non verifiees.

---

## 6) Validation finale et non-regression

- [ ] Smart card login OK sur poste sain
- [ ] Smart card login OK sur au moins un poste repare
- [ ] Poste 1: `Test-ComputerSecureChannel -Verbose` = True
- [ ] Poste 2: `Test-ComputerSecureChannel -Verbose` = True
- [ ] `gpupdate /force` OK sur postes repares
- [ ] `nltest /dsgetdc:<domaine>` OK sur postes repares
- [ ] Verification apres reboot: toujours OK
- [ ] Verification J+1: toujours OK

Si rechute apres reboot/J+1:
- suspecter replication AD/DNS/PKI ou heterogeneite multi-DC.

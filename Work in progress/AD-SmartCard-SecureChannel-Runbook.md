# AD SmartCard and Secure Channel Incident Runbook

Date: 2026-04-26

## 1) Vue globale

| Phase | Probleme cible | Objectif | Machine | Outils | Critere de sortie |
|---|---|---|---|---|---|
| 1 | PKI/KDC smart card | Prouver que le domaine peut a nouveau authentifier en carte a puce | DC + 1 poste sain | certutil, Event Viewer, PKIView | Smart card OK sur poste sain + logs KDC propres |
| 2 | Secure channel postes inactifs | Retablir trust machine/DC | 2 postes en echec | Test-ComputerSecureChannel, nltest, GPO | Secure channel = True + gpupdate OK |
| 3 | Validation croisee | Verifier la stabilite globale | DC + 1 poste repare | Login smart card + logs | Smart card OK sur poste repare |

---

## 2) Runbook detaille (commande + GUI + verification + action)

| ID | Ce qu on teste | Ou (machine + console) | Commande | Equivalent GUI | Verifier precisement | Attendu | Si KO |
|---|---|---|---|---|---|---|---|
| A1 | Certificat DC exploitable KDC | DC, PowerShell admin | certutil -store my | certlm.msc > Personal > Certificates | Cert non expire, cle privee presente, EKU coherent (KDC/Smart Card/Kerberos selon template), chaine complete | Cert DC valide | Reenroler cert DC, verifier template et auto-enrollment |
| A2 | Sante revocation cote DC | DC, CMD admin | certutil -dcinfo verify | Event Viewer (KDC/Kerberos) + details cert | Plus d erreur revocation offline, pas d erreur selection cert KDC | Verification OK | Corriger CRL/delta, AIA/CDP, republier CRL |
| A3 | Coherence CRL/delta | DC, MMC | (outil principal GUI) | pkiview.msc | Tous les points CDP/AIA en vert, base CRL/delta coherentes, dates valides | PKIView sans alerte critique | Republier CRL + delta, verifier replication LDAP/HTTP |
| A4 | Validation chaine/revocation cert DC | DC, CMD admin | certutil -urlfetch -verify <DCcert.cer> | Ouvrir le certificat > Certification Path | Chaque maillon valide, CDP joignables, pas d echec revocation | Verify OK | Corriger publication CRL/CDP et intermediaires |
| A5 | NTAuth correct | DC, CMD admin | certutil -enterprise -viewstore NTAuth | ADSIEdit / PKI MMC | CA emettrice smart card presente dans NTAuth | CA presente | Publier la CA dans NTAuth |
| A6 | Stores Root/CA entreprise | DC, CMD admin | certutil -store -enterprise root puis ... ca | certlm.msc > Trusted Root / Intermediate | Racine + intermediaires attendus presents | Chaine trust OK | Importer certs manquants (GPO/enterprise store) |
| A7 | Logs KDC pendant test smart card | DC, Event Viewer | Get-WinEvent -LogName "Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational" -MaxEvents 200 | Event Viewer > KDC Operational | Erreurs mapping/cert/revocation au timestamp du test | Pas d erreur bloquante | Corriger selon ID evenement |
| A8 | Logs crypto detailles | DC, Event Viewer | Get-WinEvent -LogName "Microsoft-Windows-CAPI2/Operational" -MaxEvents 200 | Event Viewer > CAPI2 Operational | Erreurs de build chaine, fetch CRL, AIA/CDP | CAPI2 propre | Corriger path confiance/revocation |
| B1 | DNS client AD correct | Poste sain, CMD admin | ipconfig /all | ncpa.cpl > IPv4 DNS | DNS vers serveurs AD uniquement, suffixe domaine correct | DNS AD correct | Corriger DNS client, vider cache DNS |
| B2 | Decouverte DC via DNS | Poste sain, CMD admin | nslookup -type=srv _ldap._tcp.dc._msdcs.<domaine> | DNS Manager cote serveur | SRV renvoient les DC attendus | Resolution OK | Corriger SRV/zone DNS |
| B3 | DC locator | Poste sain, CMD admin | nltest /dsgetdc:<domaine> | Test UNC \\<domaine>\SYSVOL et \\<DC>\NETLOGON | DC trouve, site correct, accessibilite | DC trouve | Verifier reseau/firewall/DNS/site AD |
| B4 | Time sync Kerberos | Poste sain, CMD admin | w32tm /query /status | timedate.cpl | Source NTP correcte, offset faible | Heure coherente | w32tm /resync |
| B5 | Test smart card reel | Poste sain, ecran logon | (action utilisateur) | Ecran de connexion Windows | Login smart card reussi + correlation logs DC | Login OK | Revenir bloc A |
| C1 | Etat secure channel poste KO | Poste KO, PowerShell admin | Test-ComputerSecureChannel -Verbose | Event Viewer System + symptomes GPO | True/False + message detaille | True | Passer en reparation trust |
| C2 | Verif trust Netlogon | Poste KO, CMD admin | nltest /sc_verify:<domaine> | Event Viewer System (Netlogon) | Secure channel verifie avec DC | Success | Verifier DNS/time/DC locator puis reparer trust |
| C3 | Test politique domaine | Poste KO, CMD admin | gpupdate /force | rsop.msc | Plus d erreur pas de DC joignable | Succes | Continuer diag DNS/DC/trust |
| C4 | Reparation secure channel | Poste KO, PowerShell admin | Test-ComputerSecureChannel -Repair -Credential <DOM\\Admin> | Pas d equivalent GUI direct | Repair completed + reboot | Secure channel retabli | Enchainer reset password machine |
| C5 | Reset password machine | Poste KO, PowerShell admin | Reset-ComputerMachinePassword -Server <DC_FQDN> -Credential <DOM\\Admin> | ADUC (approche indirecte) | Apres reboot, trust stable | True apres reboot | Rejoin complet domaine |
| C6 | Rejoin domaine (dernier recours) | Poste KO, GUI ou PS | (GUI recommande) | sysdm.cpl > Computer Name > Change | Sortie domaine, reboot, rejoin, reboot, objet AD propre | Domaine + GPO OK | Recreer objet AD ordinateur, revalider DNS/time |
| D1 | Certificat YubiKey lisible | Poste test, CMD admin | certutil -scinfo | Middleware YubiKey / certmgr user | Cert present, PIN ok, lecture smart card ok | Lecture OK | Verifier middleware/driver/carte |
| D2 | Cert utilisateur/mapping | Poste test, CMD admin | certutil -store user my | certmgr.msc (Current User\Personal) | UPN/SAN, EKU smart card, chaine valide | Cert conforme | Reenroler cert utilisateur / corriger mapping |

---

## 3) Decision rapide (branching)

| Situation observee | Conclusion | Prochaine action |
|---|---|---|
| Smart card echoue sur poste sain | Probleme prioritaire PKI/KDC domaine | Rester sur A1-A8 |
| Smart card OK sur poste sain, mais 2 postes KO | Probleme majoritairement trust machine/DNS/time | Executer C1-C6 |
| Secure channel repare mais smart card KO | Deux incidents existent en parallele | Traiter PKI/KDC puis revalider |
| Tout passe sauf mapping cert | Sujet mapping/cert policy specifique | Focus D1-D2 + evenements KDC |

---

## 4) Checklist finale Go/No-Go

| Controle | Statut |
|---|---|
| Smart card OK sur poste sain | Yes/No |
| Plus d erreur KDC/revocation cote DC pendant test | Yes/No |
| Poste 1 secure channel True + gpupdate OK | Yes/No |
| Poste 2 secure channel True + gpupdate OK | Yes/No |
| Smart card OK sur au moins un poste repare | Yes/No |

Regle de decision:
- Si la ligne 1 est No, rester en filiere PKI/KDC.
- Si la ligne 1 est Yes mais lignes 3-4 sont No, rester en filiere trust machine.

# Secure Channel cassé sur un DC fraîchement repromu — Checklist de troubleshooting

Date : 2026-05-17

## Contexte

- 2 DC (DC1, DC2), même site AD, virtualisés sur VMware.
- DC2 démoté → repromu → restauration autoritaire DFSR depuis DC1.
- `dcdiag` / `repadmin` paraissent OK.
- Symptômes côté poste client :
  - `nltest /SC_VERIFY:<domaine>` → **1786 / 0x6fa ERROR_NO_TRUST_LSA_SECRET**
  - `Test-ComputerSecureChannel` → `False`
  - `nltest /SC_QUERY:<domaine>` → **1311 ERROR_NO_LOGON_SERVERS** quand le poste tape DC2
  - Logon smart card KO, logon par cache OK
- Workaround temporaire : couper ADDS sur DC2, forcer le poste sur DC1, `Reset-ComputerMachinePassword`, reboot.
- Pas de firewall entre DC1/DC2. Plages RPC dynamiques non restreintes.

Hypothèses à tester dans l'ordre :

1. **USN rollback sur DC2** (VMware snapshot/clone/restore).
2. **Réplication AD partielle** (le password machine ne traverse pas vers DC2).
3. **DC2 « zombie »** (restes de l'ancien DC2 : NTDS Settings, SPN, DNS CNAME).
4. **SYSVOL/DFSR** post-restauration autoritaire incomplet.

---

## 0. Préparation

- [ ] Identifier les machines de référence
  - [ ] DC1 (sain, source de vérité)
  - [ ] DC2 (suspect)
  - [ ] 1 poste sain (secure channel OK)
  - [ ] 1 ou 2 postes en échec
- [ ] Vérifier les accès
  - [ ] Admin de domaine
  - [ ] Admin local sur DC1 et DC2
  - [ ] Admin local sur les postes
  - [ ] Console vCenter sur la VM DC2 (lecture mini)
  - [ ] Accès Event Viewer distant sur DC1 et DC2
- [ ] Outils sur le poste d'analyse
  - [ ] RSAT (AD, DNS)
  - [ ] Module PowerShell `ActiveDirectory` (`Import-Module ActiveDirectory`)
  - [ ] `repadmin`, `dcdiag`, `nltest`, `ntdsutil`, `setspn`, `w32tm`, `dnscmd`
- [ ] Ouvrir une transcription PowerShell
  ```powershell
  $Log = "C:\Temp\SC-Investigation-$(Get-Date -Format yyyyMMdd-HHmmss).log"
  New-Item -ItemType Directory -Path C:\Temp -Force | Out-Null
  Start-Transcript -Path $Log
  ```
- [ ] Variables de session
  ```powershell
  $DC1    = 'DC01.dr.tfn.intra'
  $DC2    = 'DC02.dr.tfn.intra'
  $Domain = 'dr.tfn.intra'
  $Poste  = 'PCXXXX'
  ```
- [ ] Règles
  - [ ] Une variable à la fois.
  - [ ] Aucune action destructive sans preuve (pas de metadata cleanup, pas de seizing FSMO, pas de re-démotion à chaud).
  - [ ] **Backup System State** de DC1 avant toute action lourde.
  - [ ] **Pas de snapshot VMware** pendant l'investigation.

---

## 1. État global — santé AD

- [ ] `dcdiag` complet sur les 2 DC
  ```powershell
  dcdiag /s:$DC1 /v /c /e > C:\Temp\dcdiag-DC1.txt
  dcdiag /s:$DC2 /v /c /e > C:\Temp\dcdiag-DC2.txt
  ```
  - [ ] Vérifier : `Replications`, `KccEvent`, `MachineAccount`, `NetLogons`, `SysVolCheck`, `FrsEvent`/`DFSREvent`, `Advertising`, `KnowsOfRoleHolders`, `Services`.
  - [ ] Tout `failed test` est noté mais ne stoppe pas l'investigation.

- [ ] Tests ciblés
  ```powershell
  dcdiag /s:$DC2 /test:replications /v
  dcdiag /s:$DC2 /test:netlogons   /v
  dcdiag /s:$DC2 /test:machineaccount /v
  dcdiag /s:$DC2 /test:advertising /v
  dcdiag /s:$DC2 /test:kccevent    /v
  dcdiag /s:$DC2 /test:sysvolcheck /v
  dcdiag /s:$DC2 /test:dfsrevent   /v
  dcdiag /test:dns /dnsall /s:$DC2 /v
  ```

- [ ] Réplication globale
  ```powershell
  repadmin /replsummary
  repadmin /showrepl * /csv | ConvertFrom-Csv | Out-GridView
  repadmin /queue $DC1
  repadmin /queue $DC2
  repadmin /bind $DC2
  ```
  - [ ] `LastReplicationSuccess` récent sur **toutes** les partitions (`DC=`, `CN=Configuration`, `CN=Schema`, NCs DNS).
  - [ ] Files vides ou décroissantes.
  - [ ] Pas de `LastReplicationResult != 0`.

- [ ] Échecs de réplication
  ```powershell
  Get-ADReplicationFailure -Scope Forest | Format-Table -AutoSize
  Get-ADReplicationPartnerMetadata -Target $DC1 -Scope Server | Format-List
  Get-ADReplicationPartnerMetadata -Target $DC2 -Scope Server | Format-List
  Get-ADReplicationUpToDatenessVectorTable -Target $DC1 | Format-Table -AutoSize
  Get-ADReplicationUpToDatenessVectorTable -Target $DC2 | Format-Table -AutoSize
  ```

- [ ] Services critiques sur DC2
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      Get-Service NTDS, Netlogon, kdc, DFSR, DNS, w32time, IsmServ |
          Select-Object Name, Status, StartType
  }
  ```
  - [ ] Tous `Running` + `Automatic`.

- [ ] Horloge (Kerberos = 5 min max de skew)
  ```powershell
  w32tm /query /computer:$DC1 /status
  w32tm /query /computer:$DC2 /status
  w32tm /monitor /computers:"$DC1,$DC2"
  ```

- [ ] FSMO
  ```powershell
  netdom query fsmo
  ```
  - [ ] Noter qui détient quoi. Toute interaction avec PDC suspecte si PDC = DC2.

---

## 2. Détection d'un USN rollback sur DC2 (priorité haute — VMware)

### 2.1 Events Directory Service

- [ ] Chercher les événements critiques
  ```powershell
  Get-WinEvent -ComputerName $DC2 -FilterHashtable @{
      LogName   = 'Directory Service'
      Id        = 2095, 2103, 1113, 1115, 2173, 2174, 1109, 1393
      StartTime = (Get-Date).AddDays(-60)
  } -ErrorAction SilentlyContinue |
      Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap
  ```
  - [ ] **2095** : USN rollback détecté → CRITIQUE.
  - [ ] **2103** : DSA passé en read-only.
  - [ ] **1113 / 1115** : réplication entrante/sortante désactivée.
  - [ ] **2173 / 2174** : échec d'écriture base AD.

- [ ] Vérifier flags `DSA Not Writable` / `Replications Disabled`
  ```powershell
  repadmin /options $DC2
  repadmin /options $DC1
  ```
  - [ ] `IS_GC` attendu si DC2 est GC.
  - [ ] **Pas de** `DISABLE_INBOUND_REPL`, `DISABLE_OUTBOUND_REPL`, `DISABLE_NTDSCONN_XLATE`.

### 2.2 InvocationID

- [ ] Récupérer l'InvocationID de DC2 vu par lui-même et par DC1
  ```powershell
  repadmin /showrepl $DC2 /verbose | Select-String 'invocationID', 'DSA object GUID'
  repadmin /showrepl $DC1 /verbose | Select-String 'invocationID', 'DSA object GUID'

  $NtdsDN = "CN=NTDS Settings,CN=DC02,CN=Servers,CN=<Site>,CN=Sites,CN=Configuration,DC=dr,DC=tfn,DC=intra"
  Get-ADObject -Server $DC1 -Identity $NtdsDN -Properties invocationId, msDS-GenerationId, objectGUID | Format-List
  Get-ADObject -Server $DC2 -Identity $NtdsDN -Properties invocationId, msDS-GenerationId, objectGUID | Format-List
  ```
  - [ ] Les deux `invocationId` doivent être **identiques**.
  - [ ] Vérifier aussi l'up-to-dateness vector : plusieurs InvocationID pour un même DC = trace d'USN rollback.

### 2.3 VMware

- [ ] Demander à l'équipe virtualisation
  - [ ] Liste des snapshots actuels sur la VM DC2 : `Get-Snapshot` côté PowerCLI ou onglet Snapshots vCenter.
  - [ ] Historique : un `Revert to snapshot` a-t-il eu lieu depuis le repromote ?
  - [ ] La VM a-t-elle été clonée, restaurée depuis backup (Veeam / Networker / Avamar / VDP) ?
  - [ ] Présence de `vm.genid` / `vm.genidX` dans les **Advanced Configuration Parameters** de la VM (vSphere 6.7+).
  - [ ] Date de création de la VM (cohérente avec date du DCpromo ?).
- [ ] Si snapshot revert / clone / restore confirmé → DC2 non fiable, voir section 7.3 (reconstruction).

---

## 3. Réplication réelle du compte machine impacté

### 3.1 Métadonnées de l'objet ordinateur

- [ ] Récupérer le DN du poste
  ```powershell
  $DN = (Get-ADComputer $Poste -Server $DC1).DistinguishedName
  $DN
  ```
- [ ] Comparer les métadonnées sur DC1 et DC2
  ```powershell
  repadmin /showobjmeta $DC1 "$DN" > C:\Temp\meta-$Poste-DC1.txt
  repadmin /showobjmeta $DC2 "$DN" > C:\Temp\meta-$Poste-DC2.txt
  Compare-Object (Get-Content C:\Temp\meta-$Poste-DC1.txt) (Get-Content C:\Temp\meta-$Poste-DC2.txt)
  ```
- [ ] Attributs à comparer (mêmes valeurs `Loc.USN`, `Originating DSA`, `Org.Time/Date`, `Ver`) :
  - [ ] `pwdLastSet`
  - [ ] `unicodePwd`
  - [ ] `ntPwdHistory`
  - [ ] `lmPwdHistory`
  - [ ] `dBCSPwd`
  - [ ] `supplementalCredentials`
  - [ ] `servicePrincipalName`
  - [ ] `userAccountControl`
- [ ] Divergence sur un seul de ces attributs = preuve d'une réplication password partielle/cassée vers DC2.

### 3.2 Forcer un changement et tracer

- [ ] Sur le poste sain, ancré sur DC1
  ```powershell
  nltest /sc_reset:$Domain\DC01
  nltest /sc_query:$Domain
  nltest /sc_change_pwd:$Domain
  ```
- [ ] Immédiatement, vérifier la propagation
  ```powershell
  $DN2 = (Get-ADComputer <PosteSain> -Server $DC1).DistinguishedName
  repadmin /showobjmeta $DC1 "$DN2" | findstr /i "pwdLastSet unicodePwd"
  repadmin /showobjmeta $DC2 "$DN2" | findstr /i "pwdLastSet unicodePwd"
  ```
- [ ] Re-tester à T+30 sec, T+5 min, T+15 min.
  - [ ] Réplication intra-site attendue : < 15 sec via notifications.
  - [ ] Si DC2 ne voit jamais le nouveau `pwdLastSet` → réplication cassée pour ces attributs.

### 3.3 Forcer la réplication explicitement

- [ ] Synchroniser tous les NC
  ```powershell
  repadmin /syncall $DC2 /AdeP
  repadmin /syncall $DC1 /AdeP
  ```
  - [ ] Tout code retour `!= 0` à analyser (`8453` access denied, `8606` lingering, `8451` aborted, etc.).

- [ ] Forcer la réplication d'une partition spécifique
  ```powershell
  repadmin /replicate $DC2 $DC1 "DC=dr,DC=tfn,DC=intra" /full /async
  repadmin /replicate $DC2 $DC1 "CN=Configuration,DC=dr,DC=tfn,DC=intra" /full /async
  ```

- [ ] Lingering objects
  ```powershell
  repadmin /removelingeringobjects $DC2 <GUID-DC1> "DC=dr,DC=tfn,DC=intra" /advisory_mode
  ```
  - [ ] Mode advisory uniquement en premier passage. Lire la sortie avant d'enlever le `/advisory_mode`.

---

## 4. Propreté du repromote — DC2 zombie ?

### 4.1 Unicité des objets NTDS Settings

- [ ] Lister tous les NTDS Settings de la forêt
  ```powershell
  Get-ADObject -Server $DC1 `
      -SearchBase "CN=Sites,CN=Configuration,DC=dr,DC=tfn,DC=intra" `
      -Filter 'objectClass -eq "nTDSDSA"' `
      -Properties whenCreated, invocationId, objectGUID, distinguishedName |
      Format-Table whenCreated, distinguishedName, invocationId
  ```
  - [ ] Un seul `CN=NTDS Settings,CN=DC02,...`.
  - [ ] Si deux apparaissent → ancien fantôme à nettoyer via `ntdsutil metadata cleanup`.

- [ ] Objet `CN=DC02` dans `Domain Controllers` unique et récent
  ```powershell
  Get-ADComputer DC02 -Server $DC1 -Properties whenCreated, pwdLastSet, servicePrincipalName, msDS-SupportedEncryptionTypes
  Get-ADComputer DC02 -Server $DC2 -Properties whenCreated, pwdLastSet, servicePrincipalName, msDS-SupportedEncryptionTypes
  ```
  - [ ] `whenCreated` cohérent avec la date du DCpromo.
  - [ ] `pwdLastSet` aligné entre les 2 vues.

### 4.2 SPN du DC2

- [ ] Lister les SPN
  ```powershell
  setspn -L DC02$
  ```
- [ ] SPN obligatoires à vérifier :
  - [ ] `HOST/DC02`
  - [ ] `HOST/DC02.dr.tfn.intra`
  - [ ] `ldap/DC02`
  - [ ] `ldap/DC02.dr.tfn.intra`
  - [ ] `ldap/DC02.dr.tfn.intra/dr.tfn.intra`
  - [ ] `ldap/<DSA-GUID>._msdcs.dr.tfn.intra`
  - [ ] `GC/DC02.dr.tfn.intra/dr.tfn.intra` (si GC)
  - [ ] `E3514235-4B06-11D1-AB04-00C04FC2DCD2/<DSA-GUID>/dr.tfn.intra` ← **SPN de réplication, critique**

- [ ] Détection de doublons
  ```powershell
  setspn -X -F
  ```

### 4.3 DNS

- [ ] SRV records
  ```powershell
  nslookup -type=SRV _ldap._tcp.dc._msdcs.$Domain $DC1
  nslookup -type=SRV _ldap._tcp.dc._msdcs.$Domain $DC2
  nslookup -type=SRV _kerberos._tcp.dc._msdcs.$Domain $DC1
  nslookup -type=SRV _kerberos._tcp.dc._msdcs.$Domain $DC2
  nslookup -type=SRV _ldap._tcp.<SiteName>._sites.dc._msdcs.$Domain $DC1
  ```
  - [ ] DC2 présent dans les listes retournées par les **deux** serveurs DNS.

- [ ] Records A et CNAME
  ```powershell
  nslookup -type=A     $DC2 $DC1
  nslookup -type=A     $DC2 $DC2
  nslookup -type=CNAME <DSA-GUID-DC2>._msdcs.$Domain $DC1
  nslookup -type=CNAME <DSA-GUID-DC2>._msdcs.$Domain $DC2
  ```
  - [ ] CNAME `<DSA-GUID>` pointe sur le **nouveau** GUID issu du repromote, pas l'ancien.

- [ ] Lister tous les CNAME `_msdcs`
  ```powershell
  dnscmd $DC1 /enumrecords _msdcs.$Domain "@" /type CNAME
  ```

- [ ] Forcer enregistrement DNS depuis DC2
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      ipconfig /registerdns
      Restart-Service Netlogon
  }
  ```

### 4.4 Secure channel DC↔DC

- [ ] Tester depuis DC2 vers le domaine
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      nltest /sc_verify:dr.tfn.intra
      Test-ComputerSecureChannel -Verbose
      nltest /dsgetdc:dr.tfn.intra
  }
  ```
- [ ] Tester depuis DC1
  ```powershell
  Invoke-Command -ComputerName $DC1 -ScriptBlock {
      nltest /sc_verify:dr.tfn.intra
      Test-ComputerSecureChannel -Verbose
  }
  ```

### 4.5 Chiffrement Kerberos

- [ ] Comparer `msDS-SupportedEncryptionTypes` DC1/DC2
  ```powershell
  Get-ADComputer DC01 -Server $DC1 -Properties msDS-SupportedEncryptionTypes
  Get-ADComputer DC02 -Server $DC1 -Properties msDS-SupportedEncryptionTypes
  Get-ADComputer DC02 -Server $DC2 -Properties msDS-SupportedEncryptionTypes
  ```
- [ ] Vérifier la GPO Kerberos qui s'applique aux DC (Default Domain Controllers Policy → `Network security: Configure encryption types allowed for Kerberos`).

---

## 5. SYSVOL / DFSR (post-restauration autoritaire)

### 5.1 État DFSR

- [ ] Backlog et state
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      dfsrdiag replicationstate /member:DC02
      dfsrdiag backlog /rgname:'Domain System Volume' /rfname:'SYSVOL Share' /smem:DC01 /rmem:DC02
      dfsrdiag backlog /rgname:'Domain System Volume' /rfname:'SYSVOL Share' /smem:DC02 /rmem:DC01
  }
  ```

- [ ] Events DFSR à valider sur DC2
  ```powershell
  Get-WinEvent -ComputerName $DC2 -LogName 'DFS Replication' -MaxEvents 100 |
      Where-Object Id -in 4602, 4604, 4614, 4624, 5002, 5004, 5008, 5012, 6804 |
      Format-Table TimeCreated, Id, Message -Wrap
  ```
  - [ ] **4602** : initialisation SYSVOL terminée.
  - [ ] **4604 / 4614** : initial sync depuis le membre autoritaire.
  - [ ] **5002 / 5004 / 5008** : pas d'erreur de connexion.
  - [ ] **6804** : pas de DC en quarantaine (loss of connectivity prolongé).

### 5.2 Partages

- [ ] NETLOGON et SYSVOL publiés
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      Get-SmbShare | Where-Object Name -in 'NETLOGON','SYSVOL'
  }
  ```
- [ ] Registry `SysvolReady`
  ```powershell
  Invoke-Command -ComputerName $DC2 -ScriptBlock {
      Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' SysvolReady
  }
  ```
  - [ ] Doit être à `1`.

### 5.3 Consistance des GPO entre DC1 et DC2

- [ ] Comparer les hash des `GPT.INI`
  ```powershell
  $g1 = Get-ChildItem "\\$DC1\SYSVOL\$Domain\Policies" -Recurse -Filter GPT.INI | Get-FileHash
  $g2 = Get-ChildItem "\\$DC2\SYSVOL\$Domain\Policies" -Recurse -Filter GPT.INI | Get-FileHash
  Compare-Object $g1 $g2 -Property Hash, Path
  ```
- [ ] Comparer les versions AD vs SYSVOL d'une GPO sensible
  ```powershell
  Get-GPO -All -Server $DC1 | Select-Object DisplayName, Id,
      @{N='AD';E={$_.User.DSVersion + $_.Computer.DSVersion}},
      @{N='SYSVOL';E={$_.User.SysvolVersion + $_.Computer.SysvolVersion}}
  Get-GPO -All -Server $DC2 | Select-Object DisplayName, Id,
      @{N='AD';E={$_.User.DSVersion + $_.Computer.DSVersion}},
      @{N='SYSVOL';E={$_.User.SysvolVersion + $_.Computer.SysvolVersion}}
  ```

---

## 6. Côté poste client

### 6.1 Capture initiale

- [ ] Sur le poste impacté
  ```powershell
  nltest /sc_query:$Domain
  nltest /dsgetdc:$Domain
  nltest /dsgetdc:$Domain /force
  Test-ComputerSecureChannel -Verbose
  klist
  klist -li 0x3e7
  ```
- [ ] Noter le `DC Site Name` et `Client Site Name`.

### 6.2 Tests ciblés par DC

- [ ] Forcer le secure channel vers chaque DC séparément
  ```powershell
  nltest /sc_reset:$Domain\DC01
  nltest /sc_verify:$Domain
  nltest /sc_reset:$Domain\DC02
  nltest /sc_verify:$Domain
  ```
  - [ ] Résultat attendu pour valider l'hypothèse :
    - [ ] `sc_reset` DC1 → OK
    - [ ] `sc_reset` DC2 → 1786 → confirme divergence base AD côté DC2.

### 6.3 Trace Netlogon

- [ ] Activer le debug
  ```powershell
  nltest /dbflag:0x2080FFFF
  ```
- [ ] Reproduire l'échec (logon, `nltest /sc_verify`, etc.).
- [ ] Récupérer
  - [ ] `C:\Windows\Debug\netlogon.log`
  - [ ] `C:\Windows\Debug\netlogon.bak`
- [ ] À chercher
  - [ ] `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT` (0xc0000199)
  - [ ] `NlSessionSetup`, `Cannot allocate session`
  - [ ] Quel DC est sollicité au moment exact de l'échec.
- [ ] Désactiver le debug
  ```powershell
  nltest /dbflag:0x0
  ```

### 6.4 Events côté poste

- [ ] Event log `System` source `NETLOGON`
  ```powershell
  Get-WinEvent -LogName System -MaxEvents 200 |
      Where-Object ProviderName -eq 'NETLOGON' |
      Format-Table TimeCreated, Id, Message -Wrap
  ```
  - [ ] **3210** : échec d'authentification machine.
  - [ ] **5719** : DC introuvable.
  - [ ] **5722** : compte machine refusé.
  - [ ] **5805** : session setup KO.

---

## 7. Synthèse / arbre de décision

- [ ] **Phase 2** trouve event 2095 ou snapshot/revert/clone confirmé côté VMware
  - [ ] → USN rollback. **Ne pas** faire de metadata cleanup ni de reset password en boucle. Aller à **7.3** (reconstruction de DC2).
- [ ] **Phase 3** montre `pwdLastSet` / `unicodePwd` divergent entre DC1 et DC2
  - [ ] sans erreur dans `repadmin /syncall` → réplication password silencieusement cassée, USN rollback masqué probable, **7.3**.
- [ ] **Phase 4** détecte SPN `E3514235-...` manquant, doublon NTDS Settings, ou CNAME DSA GUID obsolète
  - [ ] → Remédiation ciblée **7.2** avant toute action lourde.
- [ ] **Phase 5** détecte SYSVOL/DFSR incohérent ou `SysvolReady=0`
  - [ ] → Refaire un **non-authoritative DFSR** sur DC2 (voir `Active Directory/Common/DSFR - Authoritative and NON Authoritative restore.md`).
- [ ] Tout vert
  - [ ] → Trace Wireshark sur DC2 pendant un `sc_reset` vers DC2 + ouverture cas Microsoft (section 8).

### 7.2 Remédiations ciblées (non destructives)

- [ ] SPN manquant
  ```powershell
  setspn -S "E3514235-4B06-11D1-AB04-00C04FC2DCD2/<DSA-GUID>/$Domain" DC02
  ```
- [ ] CNAME DSA GUID obsolète
  ```powershell
  dnscmd $DC1 /enumrecords _msdcs.$Domain "<old-guid>"
  dnscmd $DC1 /recorddelete _msdcs.$Domain "<old-guid>" CNAME /f
  Invoke-Command -ComputerName $DC2 -ScriptBlock { ipconfig /registerdns; Restart-Service Netlogon }
  ```
- [ ] NTDS Settings résiduel
  ```text
  ntdsutil
    metadata cleanup
      connections
        connect to server DC01
        quit
      select operation target
        list sites
        select site <n>
        list servers in site
        select server <n>
        quit
      remove selected server
      quit
    quit
  ```
  - [ ] Cibler **uniquement** l'ancien objet, jamais le nouveau.

### 7.3 Reconstruction propre de DC2 (en cas d'USN rollback confirmé)

- [ ] **Backup** System State de DC1 + export DNS + export GPO.
- [ ] Démotion DC2
  - [ ] Si DC2 répond : `Uninstall-ADDSDomainController` (sans `-ForceRemoval` si possible).
  - [ ] Sinon : démotion forcée puis `ntdsutil metadata cleanup` depuis DC1.
- [ ] Nettoyage DNS
  - [ ] Records A, AAAA, CNAME, SRV pointant sur DC2.
  - [ ] CNAME `<old-DSA-GUID>._msdcs`.
- [ ] Nettoyage AD
  - [ ] Objet ordinateur `CN=DC02,OU=Domain Controllers,...` si subsistant.
  - [ ] Objet `CN=DC02,CN=Servers,CN=<Site>,CN=Sites,CN=Configuration,...`.
- [ ] **Supprimer la VM** côté VMware (pas juste l'OS) pour casser tout snapshot/VM-GenID résiduel.
- [ ] Créer une **nouvelle VM** (pas un clone, pas un template "DC ready").
- [ ] OS frais, patché, joint au domaine.
- [ ] `Install-ADDSDomainController` puis revalider sections 4 et 5 avant remise en production.

---

## 8. Collecte pour escalade Microsoft

- [ ] Sorties brutes
  - [ ] `dcdiag /v /c /e` DC1 et DC2.
  - [ ] `repadmin /showrepl * /verbose`.
  - [ ] `repadmin /showobjmeta` du compte machine impacté sur les 2 DC.
  - [ ] `repadmin /showbackup *`.
  - [ ] `repadmin /replsummary`.
- [ ] Events
  - [ ] Export `Directory Service`, `DNS Server`, `DFS Replication`, `System`, `Security` (filtré Kerberos / Netlogon) sur DC1 et DC2.
- [ ] Poste
  - [ ] `netlogon.log` du poste avec `dbflag 0x2080FFFF`.
  - [ ] Trace réseau Wireshark sur DC2 pendant `nltest /sc_reset:$Domain\DC02` depuis le poste (filtrer sur IP du poste).
- [ ] VMware
  - [ ] Liste des snapshots, clones, restores, présence `vm.genid`, date de création VM.
- [ ] Infos schéma / forêt
  - [ ] Version de schéma, dernier upgrade, FFL/DFL.
  - [ ] `Get-ADForest`, `Get-ADDomain`.

---

## Annexe — Codes d'erreur utiles

| Code | Nom | Sens |
|---|---|---|
| 1311 | ERROR_NO_LOGON_SERVERS | Aucun DC trouvé / joignable pour ce flux. |
| 1786 / 0x6fa | ERROR_NO_TRUST_LSA_SECRET | Le DC interrogé n'a pas le secret machine attendu. |
| 1787 / 0x6fb | ERROR_TRUSTED_DOMAIN_FAILURE | Trust inter-domaine cassé. |
| 0xc0000199 | STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT | Équivalent NTSTATUS de 1786. |
| 8453 | ERROR_DS_REPLICATION_ACCESS_DENIED | Réplication refusée — souvent SPN ou ACL. |
| 8606 | ERROR_DS_OBJ_TOO_MANY_FOR_LIST | Lingering objects probable. |
| 8451 | ERROR_DS_REPLICATION_ABORTED | USN rollback déclenche souvent ce code. |
| 5722 | NETLOGON 5722 | Compte machine refusé côté DC (équivalent serveur du 1786). |
| 5719 | NETLOGON 5719 | DC introuvable. |
| 5805 | NETLOGON 5805 | Session setup KO (secret machine divergent). |
| 2095 | NTDS Replication 2095 | USN rollback détecté. |
| 2103 | NTDS Replication 2103 | DSA en read-only suite à 2095. |

---

## Annexe — Pièges connus

- [ ] Ne **jamais** faire `Reset-ComputerMachinePassword` en masse pour masquer le problème — ça multiplie les 1786 ailleurs et masque la cause racine.
- [ ] Ne **pas** snapshoter un DC pour « essayer », c'est la cause numéro 1 d'USN rollback. Backup System State uniquement.
- [ ] Si un deuxième site AD existe avec d'autres DC, refaire **sections 3 et 4** contre eux : le problème peut être plus large.
- [ ] `dcdiag` peut être vert avec une réplication password partiellement cassée — ne pas s'arrêter à `dcdiag`.
- [ ] Vérifier le **site AD** du poste : si le poste est dans un site sans DC, le DC Locator peut envoyer aléatoirement vers DC1 ou DC2 selon le `try_next_closest_site`.
- [ ] `msDS-SupportedEncryptionTypes` divergent entre DC1 et DC2 → Kerberos peut échouer silencieusement et ressembler à un secure channel KO.
- [ ] `Restart-Service Netlogon` côté DC est non-disruptif et utile pour forcer la ré-publication des SRV / re-bind avec le PDC après modification.

# Strong Authentication Methods in Entra ID
**Guide pratique: quoi choisir, pourquoi, et quand (sans blabla marketing)**
Published: 2026-05-04

---

## TL;DR (version admin presse)

Si tu veux une version courte:

- Priorite 1: **Phishing-resistant MFA** (FIDO2/Passkeys, Windows Hello for Business, CBA)
- Priorite 2: **Microsoft Authenticator push** (avec number matching)
- Priorite 3: **TOTP** (utile, mais plus vulnerable au phishing)
- A limiter au maximum: **SMS/Voice** (fallback temporaire, pas une strategie)
- **Temporary Access Pass (TAP)**: excellent pour bootstrap/onboarding, pas pour usage quotidien

---

## 1. C'est quoi une methode d'authentification forte dans Entra ID?

Dans Entra ID, on parle souvent de MFA en mode "yes/no". En pratique, toutes les methodes MFA ne se valent pas.

Deux utilisateurs peuvent tous les deux "faire du MFA", mais:

- l'un avec une cle FIDO2 resistante au phishing,
- l'autre avec un code SMS facilement interceptable.

Techniquement, c'est du MFA dans les deux cas. Niveau securite, ce n'est pas le meme sport.

L'objectif d'une bonne architecture Entra ID:

- autoriser les bonnes methodes (Authentication Methods Policy),
- imposer la bonne force selon le contexte (Authentication Strengths + Conditional Access),
- garder une experience utilisateur supportable pour ne pas transformer le helpdesk en call center de crise.

---

## 2. Tableau comparatif rapide

| Methode | Niveau de resistance phishing | Experience utilisateur | Prerequis | Avantages | Inconvenients | Cas ideal |
|---|---|---|---|---|---|---|
| FIDO2 Security Keys / Passkeys | Tres eleve | Rapide (tap + PIN/biometric) | Cle compatible, navigateur/OS a jour, policy FIDO2 | Tres fort, pas de secret partage, excellent pour admins | Cout materiel, logistique de distribution, gestion perte/vol | Admins, acces privilegies, environnements a risque |
| Windows Hello for Business (WHfB) | Tres eleve | Excellente sur poste manage | Device compliant/joined, TPM recommande, config Intune/GPO | Passwordless, tres bon UX, device-bound | Dependance posture device, rollout plus long | Utilisateurs internes sur devices entreprise |
| Certificate-Based Authentication (CBA) | Eleve a tres eleve | Variable selon setup | PKI, certificats utilisateurs, lifecycle certs | Robuste, conforme dans secteurs reguliers | Complexite PKI, operations lourdes | Environnements regulation forte, smartcard/CAC |
| Microsoft Authenticator (push + number matching) | Moyen a eleve | Tres bon pour la majorite | Smartphone, app Authenticator, policy adaptee | Facile a deployer, adoption rapide, bon compromis | Fatigue MFA possible si mal configure, dependance mobile | Population large, transition vers passwordless |
| OATH TOTP (app/hardware token) | Moyen | Correct | App TOTP ou token hardware, enrollment | Offline possible, simple | Phishable, friction plus haute, support resets | Backup method, users sans data mobile |
| Temporary Access Pass (TAP) | Usage temporaire | Bon pour onboarding | Activation TAP policy, process RH/IT | Super pour bootstrap passwordless et recovery | Temporaire par design, risque si duree trop large | Onboarding, break-fix, reset securise |
| SMS / Voice OTP | Faible a moyen | Familier mais fragile | Numero tel valide, couverture telecom | Compatibilite maximale | SIM swap, interception, faible niveau de confiance | Fallback temporaire uniquement |

---

## 3. Detail methode par methode (version terrain)

## 3.1 FIDO2 Security Keys et Passkeys

### Pourquoi c'est top

- Protection native contre le phishing
- Pas de mot de passe a saisir
- Tres adapte aux comptes privilegies

### Ce qui pique

- Gestion physique des cles (stock, perte, remplacement)
- Besoin d'un process de secours propre

### Bon usage

- Equipes admin, IT, SecOps
- Acces admin portal, PIM activation, consoles critiques

---

## 3.2 Windows Hello for Business (WHfB)

### Pourquoi c'est top

- Excellent confort utilisateur (PIN local/biometric)
- Credential lie au device
- Tres bonne resistance aux attaques classiques

### Ce qui pique

- Demande une hygiene device serieuse
- Projet d'implementation plus structurant que "juste activer MFA"

### Bon usage

- Population interne sur laptops manages
- Strategie passwordless long terme

---

## 3.3 Certificate-Based Authentication (CBA)

### Pourquoi c'est top

- Tres solide quand la PKI est mature
- Bon fit pour exigences compliance

### Ce qui pique

- PKI = operations, procedures, lifecycle, support
- Mauvais design PKI = dette technique rapide

### Bon usage

- Secteurs reguliers, smartcards, federation historique

---

## 3.4 Microsoft Authenticator (push + number matching)

### Pourquoi c'est top

- Equilibre securite / UX tres efficace
- Adoption utilisateur rapide
- Compatible avec une migration progressive

### Ce qui pique

- Peut subir du MFA fatigue si policies trop permissives
- Dependance au smartphone personnel/pro

### Bon usage

- Base utilisateur large
- Etape intermediaire avant phishing-resistant everywhere

---

## 3.5 OATH TOTP (apps tierces ou token hardware)

### Pourquoi c'est utile

- Fonctionne meme sans data mobile
- Alternative simple en environnement contraint

### Ce qui pique

- Plus vulnerable au phishing (code rejouable dans une fenetre temporelle)
- UX moins fluide que push/passkeys

### Bon usage

- Methode de backup
- Cas particuliers sans push notification

---

## 3.6 Temporary Access Pass (TAP)

### Pourquoi c'est genial

- Bootstrap ideal pour passer au passwordless
- Aide recovery sans contourner la securite

### Ce qui pique

- Si duree de validite trop longue: surface de risque inutile
- Necessite gouvernance stricte

### Bon usage

- Onboarding jour 1
- Recovery controle (support + verification identite)

---

## 3.7 SMS et Voice OTP

### Pourquoi c'est encore la

- Accessible presque partout
- Tres facile a expliquer

### Ce qui pique

- Niveau de securite faible compare aux alternatives modernes
- Vulnerable a SIM swap et attaques telephonie

### Bon usage

- Fallback temporaire, scope limite, plan de sortie defini

---

## 4. Comment choisir sans regretter dans 6 mois

Utilise ce principe simple:

- Plus la ressource est sensible, plus la methode doit etre phishing-resistant.
- Plus l'utilisateur est privilegie, plus l'exception doit etre rare.
- Plus la methode est faible, plus son scope doit etre petit et temporaire.

### Recommandation pragmatique (ordre de rollout)

1. Activer et imposer Microsoft Authenticator (number matching, geolocalisation coherent si possible).
2. Deployer WHfB pour les devices manages internes.
3. Cibler FIDO2/Passkeys pour admins et populations a haut risque.
4. Garder TOTP comme backup limite.
5. Reduire SMS/Voice au strict minimum.
6. Utiliser TAP pour onboarding/recovery, jamais comme methode permanente.

---

## 5. Exemple de matrice "methode par population"

| Population | Methode principale | Methode secondaire | A eviter |
|---|---|---|---|
| Admins cloud/tenant | FIDO2 ou WHfB | Authenticator push | SMS/Voice |
| Utilisateurs internes manages | WHfB | Authenticator push | SMS en methode par defaut |
| Utilisateurs externes/B2B | Selon trust cross-tenant + Auth Strength | Authenticator/TOTP selon politique partenaire | Exceptions non tracees |
| Equipes terrain sans smartphone pro | TOTP hardware ou FIDO2 | TAP pour recovery | Dependance complete au SMS |

---

## 6. Checklist implementation Entra ID

- Verifier le statut de migration Authentication Methods vers le mode moderne complet
- Nettoyer les anciennes options legacy MFA
- Definir des Authentication Strengths claires (standard vs phishing-resistant)
- Associer les bonnes strengths aux bonnes policies Conditional Access
- Proteger les user actions sensibles (MFA registration, device registration)
- Definir un process de recovery (TAP, verification identite, delais)
- Mettre en place des exclusions break-glass strictement controlees
- Superviser les logs de sign-in et les changements de methodes

---

## 7. Conclusion

Toutes les methodes MFA ne se valent pas. Le vrai sujet n'est pas "MFA active: oui/non". Le vrai sujet est:

- quelle methode,
- pour qui,
- dans quel contexte,
- avec quelle gouvernance.

Si tu veux une ligne directrice simple:

- vise phishing-resistant par defaut,
- garde les methodes faibles en exception,
- traite onboarding/recovery comme des operations de securite a part entiere.

C'est la que Entra ID passe de "MFA de checkbox" a "authentification forte de production".

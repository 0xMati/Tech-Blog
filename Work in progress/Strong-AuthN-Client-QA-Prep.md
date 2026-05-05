# Strong AuthN — Préparation client Q&A 🎯
**Sujets: 3MFA / Strong AuthN, Windows Hello for Business, Trusted Signals, Passwordless, Password Never Expires**
Préparé le: 2026-05-05

---

## 3MFA / Strong AuthN

| # | Question probable du client | Réponse courte | Référence article |
|---|---|---|---|
| 1 | C'est quoi le "3MFA" dont parle la Sécu groupe ? | La Sécu groupe parle de **3 facteurs d'authentification** (have/know/are) combinés — ce qui correspond à **AAL3** dans NIST SP 800-63B, ou **phishing-resistant MFA** dans le vocabulaire Microsoft. | Section 1.1 + Section 3.2 |
| 2 | Est-ce que "Require MFA" dans Conditional Access suffit pour satisfaire la demande 3MFA ? | **Non.** "Require MFA" accepte n'importe quelle combinaison, y compris SMS + password. Pour respecter l'exigence Sécu groupe, il faut une **Authentication Strength = Phishing-resistant MFA** dans la politique CA. | Section 1.1 + Section 4.1 |
| 3 | Quelles méthodes satisfont le critère 3MFA / AAL3 ? | **FIDO2 / Passkeys**, **Windows Hello for Business** (avec TPM + PIN/biométrie), **Certificate-Based Authentication (CBA)**. Aucune autre méthode Microsoft n'atteint AAL3. | Section 2 — tableau de comparaison |
| 4 | Authenticator push satisfait-il le 3MFA ? | **Non.** Authenticator push est AAL2 — c'est du MFA solide, mais phishable via attaque AiTM. Il peut servir de **transition**, pas de cible finale. | Section 3.4 |

---

## Windows Hello for Business

| # | Question probable du client | Réponse courte | Référence article |
|---|---|---|---|
| 5 | Windows Hello for Business, c'est quoi exactement ? | WHfB remplace le mot de passe par une **clé asymétrique liée au TPM du device**. L'utilisateur déverrouille avec PIN ou biométrie localement — aucun secret ne transite sur le réseau. | Section 3.2 |
| 6 | WHfB = combien de facteurs ? TPM, PIN, Biométrie = 3 facteurs ? | **Oui, les 3 types de facteurs sont présents par design** : TPM = **have**, PIN = **know**, biométrie = **are**. Mais ce ne sont pas 3 prompts séquentiels — PIN et biométrie sont des **méthodes alternatives** pour déverrouiller la même clé TPM. | Section 3.2 — WHfB factor model |
| 7 | Pourquoi WHfB ne demande pas PIN + biométrie + TPM en même temps ? | Parce que **PIN et biométrie déverrouillent le même objet** (la clé privée dans le TPM). Le TPM est **toujours actif** (have), et l'utilisateur utilise soit PIN soit biométrie pour l'activer. La sécurité vient de l'**architecture**, pas d'un empilement de prompts. | Section 3.2 — "Why not 3 sequential prompts" |
| 8 | La Sécu groupe veut PIN + Biométrie + TPM simultanément — est-ce techniquement possible ? | **Pas comme 3 prompts séquentiels.** Ce que la Sécu veut probablement dire : s'assurer que les **3 facteurs sont présents dans l'architecture** — ce que WHfB avec TPM + biométrie garantit déjà. Il faut clarifier si l'exigence est architecturale (✅ déjà satisfaite) ou opérationnelle (3 saisies distinctes — techniquement non natif dans WHfB). | Section 3.2 |
| 9 | Peut-on configurer WHfB pour forcer TPM + PIN + biométrie via policy ? | **Partiellement.** On peut forcer : TPM obligatoire (Intune/GPO), PIN avec complexité (WHfB policy), biométrie comme méthode principale. Mais on **ne peut pas forcer PIN + biométrie comme 2 prompts séquentiels** dans le même flow d'authentification — ce n'est pas natif dans WHfB. Ce qui est configurable, c'est la **présence des 3 facteurs dans l'architecture**, pas leur cumul en saisies distinctes. | Section 3.2 — Implementation notes |
| 10 | WHfB est-il AAL3 ? | **Oui**, à condition que le TPM soit enforced et que le device soit compliant. Sans TPM, la clé n'est pas hardware-bound et l'assurance baisse. | Section 2 — tableau AAL |

---

## Trusted Signals

| # | Question probable du client | Réponse courte | Référence article |
|---|---|---|---|
| 11 | C'est quoi un Trusted Signal ? | Un **signal de confiance** dans Conditional Access = évaluation composée de 4 dimensions : **Qui** (identité), **Comment** (méthode AAL), **Device** (compliance/TPM), **Contexte** (risque/location). L'accès est accordé seulement si les 4 dimensions sont satisfaites. | Section 4.4 |
| 12 | Quelle différence avec juste "Require MFA" ? | "Require MFA" ne regarde que la méthode. **Trusted Signals** regardent **méthode + device + risque + contexte** simultanément — c'est la différence entre un checkpoint unique et un système de défense en profondeur. | Section 4.4 |
| 13 | Comment configurer les Trusted Signals dans Entra ID ? | Via **Conditional Access** : Authentication Strength (méthode), Device Compliance (Intune), Identity Protection risk conditions, Named Locations. Ils se combinent dans une même politique CA. | Section 4.4 |
| 14 | Un utilisateur avec FIDO2 sur un device non géré = AAL3 ? | **Non, pas complètement.** La méthode est AAL3, mais sans device compliance le Trusted Signal est incomplet. La politique CA doit exiger **méthode phishing-resistant + device compliant** pour une assurance maximale. | Section 4.4 |

---

## Passwordless — intégration

| # | Question probable du client | Réponse courte | Référence article |
|---|---|---|---|
| 15 | Passwordless, ça veut dire quoi concrètement dans Entra ID ? | L'utilisateur **ne saisit plus de mot de passe** lors de l'authentification. WHfB, FIDO2, et Authenticator phone sign-in sont les 3 méthodes passwordless supportées. | Section 3.1 / 3.2 / 3.5 |
| 16 | Passwordless = le mot de passe est supprimé du directory ? | **Non.** Le mot de passe reste dans Entra ID. Ce qui change : le flux d'authentification le **bypass**. Mais il existe encore et a un cycle de vie à gérer. | Section 6 |
| 17 | Authenticator phone sign-in vs FIDO2 — c'est pareil en passwordless ? | **Non.** Authenticator phone sign-in = passwordless **AAL2** (phishable). FIDO2/WHfB = passwordless **AAL3** (phishing-resistant). La cible doit être AAL3 ; phone sign-in est une transition. | Section 3.5 |
| 18 | Comment déployer le passwordless progressivement ? | Phase 1: Authenticator push (AAL2 baseline) → Phase 2: WHfB sur endpoints gérés → Phase 3: FIDO2/Passkeys pour admins et populations non-Windows → TAP pour onboarding/recovery à chaque phase. | Section 4.3 |

---

## Password Never Expires

| # | Question probable du client | Réponse courte | Référence article |
|---|---|---|---|
| 19 | Si on déploie WHfB, les utilisateurs ne tapent plus leur mot de passe — faut-il quand même gérer l'expiration ? | **Oui, absolument.** Si le mot de passe expire alors que l'utilisateur ne le connaît plus, les flows de fallback et d'auth legacy cassent — incidents helpdesk garantis. | Section 6 |
| 20 | Microsoft recommande quoi pour les comptes cloud-only en mode passwordless ? | **Password Never Expires** une fois l'enrollment passwordless confirmé. Le mot de passe existe en backstop silencieux, jamais surfacé à l'utilisateur. | Section 6 |
| 21 | Et pour les comptes hybrides synchronisés depuis AD ? | Il faut coordonner avec l'équipe AD et utiliser des **Fine-Grained Password Policies (FGPP)** pour exclure les populations passwordless du cycle d'expiration standard. | Section 6 |
| 22 | Password Never Expires = moins sécurisé ? | **Non, dans un contexte passwordless correctement déployé.** Le mot de passe n'est plus le vecteur d'authentification — son expiration n'a plus de valeur sécurité mais génère des incidents opérationnels. | Section 6 |
| 23 | Que se passe-t-il si WHfB ou FIDO2 est indisponible ? | Le fallback doit être **TAP** (Temporary Access Pass) — pas l'ancien mot de passe. TAP permet une récupération contrôlée avec vérification d'identité, sans réouvrir le vecteur password. | Section 6 — checklist + Section 3.7 |

---

## ⚠️ Point clé à préparer pour la Sécu groupe

> La Sécu groupe veut **"3MFA"** = ils cherchent **AAL3 / phishing-resistant MFA**.
>
> Il faut leur montrer que WHfB **satisfait architecturalement** leur exigence (TPM + PIN/biométrie = have + know/are), mais que la conversation sur **"3 prompts séquentiels"** est un **malentendu de design** à clarifier :
>
> - La sécurité de WHfB vient de l'**architecture** (clé liée au TPM, geste local, aucun secret en transit), pas du nombre de saisies.
> - Les 3 facteurs sont **présents simultanément** dans chaque authentification WHfB — l'utilisateur ne les voit pas comme 3 étapes, mais ils sont tous actifs.
> - Si la Sécu groupe exige 3 prompts distincts, c'est techniquement non natif dans WHfB et nécessite une discussion sur le **risque opérationnel** (friction, adoption, help desk) vs le **gain sécurité réel** (marginal si TPM + biométrie + device compliance sont déjà en place).

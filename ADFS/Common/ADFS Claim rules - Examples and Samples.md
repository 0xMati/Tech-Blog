# 🎯 ADFS Claim Rules — Exemples pratiques

Ce document illustre des règles d’émission de claims (Claim Rules) dans un contexte ADFS (Active Directory Federation Services). Chaque exemple est décrit avec son objectif, sa règle complète, et une brève explication.

---

## 🛡️ 1. Send Linux Root Role if Admin

**Objectif :**  
Attribuer un rôle `Root` spécifique à un utilisateur membre du groupe Administrateurs (SID `...-512`), typiquement pour des systèmes Linux.

**Règle :**
```adfs
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/groupsid", Value =~ "^(?i)S-1-5-21-2462332226-1795882094-2017209951-512$"]
 => issue(Type = "http://mathiasmotron.com/LinuxRole", Issuer = c.Issuer, OriginalIssuer = c.OriginalIssuer, Value = "Root", ValueType = c.ValueType);
```

**Explication :**
- Vérifie si l'utilisateur est membre du groupe Administrateurs (SID du groupe).
- Émet un rôle personnalisé avec une valeur "Root".

---

## 🖥️ 2. Send ADFSServerName

**Objectif :**  
Émettre le nom du serveur ADFS qui a traité la requête. Utile pour l'audit ou le débogage.

**Règle :**
```adfs
=> issue(store = "Internal WID", types = ("http://mathiasmotron.com/AdfsServerName"), query = "SELECT HOST_NAME() AS HostName");
```

**Explication :**
- Utilise une requête SQL contre la base WID locale pour récupérer le nom d’hôte.
- Émet le nom du serveur comme une réclamation personnalisée.

---

## 🎩 3. Magic Claim Rule (tout transmettre)

**Objectif :**  
Transmettre tous les claims reçus, sans filtre ni transformation. Pratique pour les diagnostics ou le debug.

**Règle :**
```adfs
c:[]
 => issue(claim = c);
```

**Explication :**
- Capture tous les claims d'entrée.
- Les réémet tels quels vers la partie consommatrice (Relying Party).

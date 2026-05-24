---
title: "Event ID Windows 4624 : décoder chaque connexion réussie"
description: "Ce que contient réellement un enregistrement 4624, pourquoi le champ LogonType compte plus que l'événement lui-même, et comment les lire à grande échelle."
date: "2026-05-17"
---

L'event ID 4624 — « Un compte s'est connecté avec succès » — est journalisé sur le canal `Security` chaque fois que Windows authentifie une identité. C'est l'enregistrement le plus volumineux sur la plupart des postes de travail et l'épine dorsale de presque toutes les enquêtes IR. Savoir le lire n'est pas négociable.

## Ce que contient un enregistrement 4624

Les parties intéressantes vivent dans `<EventData>` :

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Les champs `Subject*` correspondent au contexte de sécurité qui a *demandé* la connexion (souvent `S-1-5-18` pour SYSTEM lors d'un démarrage de service). Les champs `Target*` désignent l'identité finalement authentifiée. Les confondre coûte des heures à un analyste.

## LogonType est le champ qui compte

Windows définit dix types de connexion ; en pratique, seuls quelques-uns dominent le triage :

- **2 — Interactive** : connexion physique ou console.
- **3 — Network** : SMB, RPC, WinRM, tout ce qui passe par le réseau. La grande majorité du trafic normal.
- **4 — Batch** : tâche planifiée s'exécutant sous un compte utilisateur.
- **5 — Service** : un service démarré sous un compte donné.
- **7 — Unlock** : déverrouillage après un écran de veille.
- **8 — NetworkCleartext** : rare, suspect — identifiants en clair (Basic auth sur IIS, vieux périphériques).
- **9 — NewCredentials** : `runas /netonly`, souvent utilisé par les attaquants pour porter des identifiants de domaine sur une machine où ils n'ont que des droits locaux.
- **10 — RemoteInteractive** : RDP. Se couple à `IpAddress` pour l'attribution source.
- **11 — CachedInteractive** : compte de domaine avec identifiants en cache (aucun DC joignable).

Un 4624 avec LogonType **10** depuis une IP externe à 3 h un dimanche raconte autre chose que 50 LogonType **3** depuis un serveur de backup à 2 h.

## À quoi le chaîner

Un 4624 réussi seul est rarement une découverte. Il en devient une lorsqu'il est associé à :

- **4625** précédant depuis la même source — un succès après une rafale d'échecs est la signature manuel du brute-force-réussi.
- **4672** (privilèges spéciaux attribués) — marque les connexions ayant accordé des privilèges comme `SeDebugPrivilege`, utile pour repérer les usages de comptes privilégiés.
- **4648** (connexion avec identifiants explicites) — capture `runas` et autres patterns de passage d'identifiants.

## Lire ça à grande échelle

L'analyseur sur cette page extrait ces champs directement du XML de l'enregistrement et les expose dans le tableau. Filtrez par `LogonType` via les buckets de la timeline et le filtre texte (`4624` dans la recherche), exportez l'ensemble filtré en CSV, puis pivotez sur `SubjectUserSid` + `IpAddress` dans l'outil de votre choix. Le XML complet de chaque enregistrement est à un clic.

---
title: "Event ID 4625 expliqué : détecter brute force, sprays et énumération"
description: "4625 est l'enregistrement d'échec de logon. Lisez-le correctement et vous repérez les password sprays, le credential stuffing et l'abus de Kerberos avant qu'ils ne réussissent."
date: "2026-05-17"
---

L'Event ID 4625, « Un compte n'a pas réussi à se connecter », se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'une tentative d'authentification est rejetée. C'est l'enregistrement unique le plus utile pour attraper les attaques sur identifiants en plein vol. C'est aussi celui que les analystes lisent mal le plus souvent, parce que le message de tête est générique et la réponse vit deux champs plus bas.

## Les champs qui décident l'appel

Un enregistrement typique :

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` et `SubStatus` ensemble vous disent pourquoi le logon a échoué. La paire qui vous importe vraiment est `SubStatus`. Les codes à mémoriser :

- `0xC0000064` : le compte n'existe pas. Énumération de noms d'utilisateur.
- `0xC000006A` : mauvais mot de passe. Le classique.
- `0xC0000234` : compte verrouillé.
- `0xC0000072` : compte désactivé.
- `0xC0000071` : mot de passe expiré.
- `0xC0000133` : décalage d'horloge sur Kerberos. Courant lors de tentatives d'AS-REP roasting où l'attaquant a forgé une heure.
- `0xC000018B` : mauvais SID, le poste pense être dans un domaine où il n'est pas. Rare et intéressant.

Une rafale de `0xC0000064` sur un mélange de noms d'utilisateur valides et invalides est de la reconnaissance. Une rafale de `0xC000006A` contre un compte est de la brute force. Une rafale de `0xC000006A` contre beaucoup de comptes avec le *même* mot de passe est un spray. Même Event ID, trois incidents différents.

## Les requêtes de triage qui gagnent leur place

1. Détection de spray. Groupez 4625 par `IpAddress` (ou `WorkstationName` si le champ IP est vide), comptez les `TargetUserName` distincts sur 10 minutes. Plus de cinq comptes par source dans cette fenêtre est suspect presque partout.
2. Brute force. Groupez par `TargetUserName`, comptez les échecs par minute. Plus de dix par minute contre un compte est presque toujours automatisé.
3. Cause racine du verrouillage. Associez 4740 (compte verrouillé) avec les 4625 précédents. Le champ `WorkstationName` vous dira quel appareil a déclenché le verrouillage. La plupart du temps c'est un serveur joint au domaine avec un identifiant en cache obsolète, pas un attaquant. Le triage compte parce que le helpdesk traite les deux pareil et le SOC doit choisir lequel escalader.

## L'« après » décide la réponse

Une rafale de 4625 suivie d'un [4624](/fr/blog/understanding-event-id-4624) depuis la même `IpAddress` est le cas actionnable. L'attaquant a trouvé un identifiant qui marche. La progression dans la timeline est sans équivoque : échecs denses, silence soudain, succès unique.

## Sigma : password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL : brute force contre un compte

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk : énumération conduisant à la brute force

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Le signal est la *progression* : énumération d'abord pour trouver des noms d'utilisateur valides, puis tentatives ciblées de mot de passe. Un vrai opérateur avec une liste d'utilisateurs fraîche produira les deux formes en quelques minutes.

## Mapping ATT&CK

- T1110.001 Brute Force: Password Guessing. Un seul compte, beaucoup d'échecs `0xC000006A`.
- T1110.003 Brute Force: Password Spraying. Beaucoup de comptes, une source, peu d'échecs chacun.
- T1110.004 Credential Stuffing. Beaucoup de comptes, une source, mélange de `0xC0000064` (compte inexistant, raté de liste fuitée) et `0xC000006A` (touché).
- T1078 Valid Accounts. Rafale 4625 suivie d'un succès [4624](/fr/blog/understanding-event-id-4624) depuis la même source. Compromission.
- T1556 Modify Authentication Process. `LogonProcessName` anormal (autre que `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) suggère une altération.

## Faux positifs qui en portent le costume

- Identifiants stockés qui deviennent obsolètes après un changement de mot de passe. Les lecteurs mappés, tâches planifiées ou configs de services de l'utilisateur retentent l'ancien mot de passe. La forme est un `TargetUserName`, une `IpAddress`, cadence constante de `0xC000006A`. Trouvez l'hôte avec l'identifiant obsolète et corrigez-le avant d'alerter.
- Automatisation mal configurée. Un script avec le mauvais mot de passe qui retente en boucle. Même forme que la brute force. Parlez d'abord au propriétaire.
- Les scanners de vulnérabilités lors de scans authentifiés produisent du trafic 4625 dense. Étiquetez les IP du scanner.
- Churn de politique de verrouillage. Les procédures helpdesk qui déverrouillent agressivement créent des cycles répétés 4625 vers 4740 vers 4624. Énervant. Pas malveillant.

## Ce que 4625 cache

Les échecs Kerberos et NTLMv2 qui passent par un DC ne portent pas toujours une `IpAddress` utile. Le champ peut être vide ou `-`. Pour ceux-là, vous pivotez vers les enregistrements du DC : [4768](/fr/blog/event-id-4768-kerberos-tgt) et 4771 pour les échecs de pré-authentification Kerberos. « Pas d'IP source, pas d'enquête » est le mauvais instinct. Regardez plutôt le log du DC.

Les champs `LogonProcessName` et `AuthenticationPackageName` vous disent quelle pile d'auth a géré la tentative. Valeurs utiles : `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (choisit l'un des deux), `User32` (console locale), `Schannel` (basé TLS). Tout le reste, regardez de plus près.

## Pour aller plus loin

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

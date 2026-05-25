---
title: "Event ID 4625 expliqué : détecter brute force, sprays et énumération"
description: "Le 4625 est l'enregistrement d'échec de connexion. Bien lu, il révèle password sprays, credential stuffing et abus Kerberos avant qu'ils ne réussissent."
date: "2026-05-17"
---

L'Event ID 4625 — « Échec d'ouverture de session d'un compte » — se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'une tentative d'authentification est rejetée. C'est l'enregistrement le plus utile pour repérer l'activité d'attaques sur les identifiants, mais uniquement si vous lisez les bons champs.

## Les champs qui comptent vraiment

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

La combinaison de `Status` et `SubStatus` indique *pourquoi* la connexion a échoué :

- `0xc0000064` — le compte n'existe pas (énumération de noms d'utilisateur).
- `0xc000006a` — mot de passe incorrect (le classique).
- `0xc0000234` — compte verrouillé.
- `0xc0000072` — compte désactivé.
- `0xc0000071` — mot de passe expiré.
- `0xc0000133` — décalage d'horloge sur un ticket Kerberos (fréquent lors d'AS-REP roasting).
- `0xc000018b` — mauvais SID — le poste n'est pas dans le domaine qu'il pense.

Une rafale de `0xc0000064` contre des noms valides et invalides est de la reconnaissance. Une rafale de `0xc000006a` contre un seul compte est du brute force. Une rafale de `0xc000006a` contre de nombreux comptes avec le *même mot de passe* est un password spray.

## Les patterns

Les requêtes de triage les plus simples :

1. **Détection de spray** : grouper les 4625 par `IpAddress` (ou `WorkstationName` si l'IP n'est pas enregistrée), compter les `TargetUserName` distincts sur 10 minutes. >5 comptes par source sur cette fenêtre est suspect presque partout.
2. **Brute force** : grouper par `TargetUserName`, compter les échecs par minute. >10 par minute contre un compte est généralement un bot.
3. **Cause racine de verrouillage** : associer 4740 (compte verrouillé) aux 4625 qui précèdent — le champ `WorkstationName` montrera quel appareil a déclenché le verrouillage, ce qui est crucial parce qu'il s'agit souvent d'un serveur joint au domaine avec une credential stockée périmée, pas d'un attaquant.

## L'« après » compte autant que l'« avant »

Une rafale de 4625 suivie d'un [4624](/fr/blog/understanding-event-id-4624) depuis la même `IpAddress` est le cas actionnable — l'attaquant a trouvé une credential fonctionnelle. Le parseur sur cette page permet de filtrer la table sur une IP source et d'observer les transitions de level et d'event-ID dans la timeline. Le motif rafale-puis-pic est sans équivoque.

## Exemple de règle Sigma — password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
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

## Exemple KQL — brute force contre un compte

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Exemple Splunk — énumération avant brute force

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Le signal est la *progression* — énumération pour trouver des noms valides, puis brute force contre ceux-ci.

## Cartographie ATT&CK

- **T1110.001 — Brute Force: Password Guessing** : un compte, beaucoup d'échecs `0xC000006A`.
- **T1110.003 — Brute Force: Password Spraying** : beaucoup de comptes, peu d'échecs par compte, une source.
- **T1110.004 — Brute Force: Credential Stuffing** : beaucoup de comptes, une source, souvent des `0xC0000064` (compte inexistant) pour les manques de listes leakées entrelacés avec des `0xC000006A` qui touchent.
- **T1078 — Valid Accounts** : 4625 suivi d'un succès [4624](/fr/blog/understanding-event-id-4624) depuis la même source = compromission.
- **T1556 — Modify Authentication Process** : `LogonProcessName` anormal (autre que `User32`, `NtLmSsp`, `Kerberos`, `Advapi` ou `Schannel`) suggère un tampering d'authentification.

## Faux positifs qui ressemblent à des attaques

- **Credentials stockées périmées** après un changement de mot de passe. Les lecteurs montés, tâches planifiées ou configs de comptes de service continuent à retenter l'ancien. Le motif : un `TargetUserName`, une `IpAddress` (parfois un `WorkstationName`), cadence stable de `0xC000006A`. Trouvez l'hôte à la credential périmée et corrigez.
- **Automatisation mal configurée** : un script avec un mauvais mot de passe en boucle. Même forme que le brute force ; parlez au propriétaire avant d'alerter.
- **Scanners de vulnérabilités** lors de scans authentifiés produisent un trafic 4625 dense. Taguez les IP de scanners.
- **Mauvaise politique de verrouillage** : des procédures helpdesk qui déverrouillent trop agressivement peuvent produire des cycles répétés 4625 → 4740 → 4624.

## Ce qu'on ne voit pas dans 4625

Les échecs NTLMv2 et Kerberos venant d'un contrôleur de domaine ne portent pas toujours une `IpAddress` utile — le champ peut être vide ou `-`. Pour ceux-là, il faut les événements DC correspondants ([4768](/fr/blog/event-id-4768-kerberos-tgt)/4771 pour les échecs de pré-authentification Kerberos) ou des données au niveau réseau. Ne concluez pas « pas d'IP source, pas d'enquête » — pivotez vers le canal DC.

Les champs `LogonProcessName` et `AuthenticationPackageName` indiquent quelle pile d'authentification a traité la tentative. Les plus utiles sont `NtLmSsp` (NTLM), `Kerberos` et `Negotiate` (qui choisit l'un des deux). `User32` est la console locale ; `Schannel` est basé sur TLS.

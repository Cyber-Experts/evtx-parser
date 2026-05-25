---
title: "Event ID 4769 expliqué : tickets service Kerberos et kerberoasting"
description: "4769 est l'enregistrement DC de chaque demande de ticket service. Lu via le type de chiffrement, il révèle le kerberoasting ; lu avec 4768, il révèle le pass-the-ticket."
date: "2026-05-24"
---

L'Event ID **4769** — « Un ticket service Kerberos a été demandé » — se déclenche sur chaque contrôleur de domaine chaque fois qu'un compte demande un ticket TGS (Ticket Granting Service) pour un service. Chaque connexion SMB, chaque login SQL, chaque hit SSO web produit l'un d'eux sur le DC qui a traité la demande. C'est l'enregistrement au plus haut volume du [canal Security](/fr/blog/what-is-an-evtx-file) sur un DC chargé — et le seul endroit où le kerberoasting apparaît de façon fiable avant que les credentials ne soient craquées hors ligne.

Si vous n'instrumentez que trois enregistrements Security depuis vos contrôleurs de domaine, c'est l'un d'eux.

## Où il vit

`4769` est écrit sur le canal `Security` du **contrôleur de domaine émetteur** — pas le client et pas le service cible. Pour voir tous les 4769 d'un domaine, vous devez collecter depuis chaque DC. La target `EventLogs` de KAPE sur un DC, ou le forwarding `Security` via WEF vers un collecteur, fonctionnent tous les deux ; la voie WEF est ce que la plupart des structures matures utilisent.

## Ce que contient l'enregistrement

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

Les champs qui pilotent le triage :

- **`TargetUserName`** — le *demandeur* (le compte utilisateur, en forme `user@DOMAIN`).
- **`ServiceName`** — le SPN demandé. Un compte utilisateur ici (plutôt que `host/...` ou une classe de service) est suspect.
- **`TicketEncryptionType`** — la valeur qui décide si cet enregistrement compte. Les domaines modernes tournent `0x12` (AES-256-CTS-HMAC-SHA1-96) ou `0x11` (AES-128). **`0x17` est RC4-HMAC** — legacy, faible, et le *seul* type de chiffrement que le mode `kerberoast` de Mimikatz/Rubeus demande. Un 4769 pour un ticket de compte de service avec `0x17` est une empreinte textbook de kerberoasting.
- **`Status`** — `0x0` est succès ; tout autre signifie refusé (codes status documentés dans `[MS-KILE]`).
- **`IpAddress`** — l'hôte demandeur. Couplez avec [4624](/fr/blog/understanding-event-id-4624) sur cet hôte pour voir la connexion qui a produit la session.

## TicketEncryptionType — le champ qui compte

La table complète, abrégée :

| Valeur | Algorithme | Statut |
|---|---|---|
| 0x01 | DES-CBC-CRC | Désactivé par défaut depuis Win7 |
| 0x03 | DES-CBC-MD5 | Désactivé par défaut depuis Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderne |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderne (défaut pour la plupart des comptes) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Requis pour le kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 export-grade, extrêmement rare |

Si le domaine a été baseliné et `msDS-SupportedEncryptionTypes` posé en AES-only sur les comptes de service, `0x17` ne devrait pas du tout apparaître pour ces comptes. Les attaquants demandent `0x17` explicitement parce que craquer des tickets service chiffrés RC4 est peu coûteux ; AES non. L'outil de cracking a besoin du hash RC4, donc la demande *doit* être 0x17.

C'est le champ unique au plus fort signal de l'enregistrement.

## Le pattern kerberoasting

Le kerberoasting (MITRE T1558.003) fonctionne comme suit :

1. L'attaquant s'authentifie avec n'importe quel compte utilisateur du domaine (aucun droit admin requis).
2. L'attaquant énumère les SPN enregistrés sur des comptes utilisateurs (pas des comptes machines), typiquement via LDAP `(servicePrincipalName=*)` filtré aux objets user.
3. L'attaquant demande un TGS pour chaque SPN avec `etype=23` (RC4) via le protocole Kerberos standard. **C'est le 4769 que vous cherchez.**
4. Le DC émet joyeusement le ticket, chiffré avec le hash NTLM du *compte de service*.
5. L'attaquant tire le blob chiffré de la mémoire (ou du wire) et le craque hors ligne avec Hashcat (`-m 13100`).

L'empreinte 4769 :

- `ServiceName` est `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` ou tout SPN pointant sur un compte *utilisateur* (pas `host/...` ou `cifs/...` qui sont des comptes machines).
- `TicketEncryptionType` est `0x17`.
- Une rafale de ces demandes sur une courte fenêtre, depuis la même source, pour beaucoup de SPN, est la preuve flagrante.

Un second pattern apparenté — **AS-REP roasting** (T1558.004) — utilise [4768](/fr/blog/event-id-4768-kerberos-tgt) à la place (la demande TGT), ciblant les comptes avec `DONT_REQUIRE_PREAUTH` posé. Enregistrement différent, même famille d'attaques.

## Pass-the-ticket / golden / silver tickets

4769 révèle aussi la forge de tickets, mais le signal est plus subtil.

- Un 4769 *sans* 4768 (demande TGT) précédent pour le même `LogonGuid` depuis le même hôte sur une fenêtre raisonnable — suspicion **golden ticket**. L'attaquant a présenté un TGT forgé et est passé directement aux demandes TGS sans jamais demander un vrai TGT.
- Un 4769 *et* l'authentification service résultante sur la cible *sans* 4769 visible sur aucun DC — suspicion **silver ticket**. L'attaquant a forgé le TGS lui-même ; le DC n'a jamais été interrogé.
- Mismatch de `LogonGuid` entre 4624 sur le service cible et le 4769 censé émettre le ticket — ticket forgé.

Ce sont des patterns de détection par absence, ce qui signifie qu'ils requièrent une couverture log complète sur tous les DC et les services cibles. Les trous dans la couverture WEF produisent des faux positifs identiques ; caractérisez votre collecte avant d'alerter.

## Workflow de triage

1. Filtrez tous les 4769 du corpus DC pour `TicketEncryptionType == 0x17`.
2. Groupez par `IpAddress` et par `TargetUserName` sur des fenêtres de 30 minutes. Comptez les `ServiceName` distincts par source.
3. >3 SPN distincts demandés en 0x17 depuis une source en 30 minutes est du kerberoasting presque partout.
4. Pivotez l'IP source vers son [4624](/fr/blog/understanding-event-id-4624) sur l'hôte d'origine — trouvez la credential qui a initié l'attaque.
5. Pivotez les SPN demandés vers les comptes de service qui les possèdent. Rotez ces mots de passe. Réinitialisez les hashes craqués en heures, pas en jours.

## Exemple de règle Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

La clause `filter_machine` exclut les SPN de comptes machines (qui finissent toujours par `$`) ; le kerberoasting ne cible que les SPN de comptes utilisateurs.

## Exemple KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`) :

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

Splunk :

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Cartographie ATT&CK

Le corpus 4769 couvre :

- **T1558.003 — Kerberoasting** : le cas d'usage phare.
- **T1558.001 — Golden Ticket** : 4769 sans 4768 du même `LogonGuid`.
- **T1558.002 — Silver Ticket** : 4769 absent pour une authentification service observée sur la cible.
- **T1078 — Valid Accounts** : 4769 depuis une IP inattendue pour un compte de service connu.
- **T1550.003 — Pass the Ticket** : 4769 suivi de [4624](/fr/blog/understanding-event-id-4624) LogonType 3 avec `LogonProcessName: Kerberos`.

## Faux positifs que vous verrez

- **Applications legacy** (certains anciens connecteurs SQL Server, certaines apps Java/JBoss) demandent explicitement RC4. Elles apparaissent comme un trafic 0x17 stable, en journée, depuis un petit ensemble d'hôtes stables. Baselinez et excluez.
- **Domaines pré-AES** pendant une transition de durcissement Kerberos émettront 0x17 largement jusqu'à ce que `msDS-SupportedEncryptionTypes` soit posé sur chaque compte. Pénible, pas malveillant.
- **Scanners de vulnérabilités** (Tenable, Qualys, scripts d'énumération BloodHound) répliquent le trafic kerberoasting. Taguez les hôtes scanners.
- **Outils de migration de compte** pendant des déplacements cross-forest peuvent demander des combinaisons de tickets inhabituelles.

Le signal est le pattern *rafale*, pas l'enregistrement individuel. Un 0x17 stable depuis un hôte est de la configuration ; un 0x17 bursty vers beaucoup de SPN depuis un hôte en minutes est l'attaque.

## Ce que 4769 ne dit pas

L'enregistrement n'inclut pas le ticket chiffré lui-même — le cracking se passe sur ce que l'attaquant a exfiltré, pas sur le wire depuis le DC. Vous ne pouvez pas, à partir de 4769 seul, distinguer « ticket émis et jamais utilisé » de « ticket craqué, credentials réutilisées ». Pour la seconde moitié de la chaîne, il faut le [4624](/fr/blog/understanding-event-id-4624) résultant sur le service cible (LogonType 3, AuthenticationPackage Kerberos), et idéalement [4688](/fr/blog/event-id-4688-process-creation) ou [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) montrant ce qui a tourné après que la credential a été réutilisée. Traitez 4769 comme le canari, pas l'alarme.

## Où 4769 s'inscrit dans une timeline

Chaîne classique de kerberoasting post-exploitation :

1. [**4624**](/fr/blog/understanding-event-id-4624) sur un poste — accès initial via credentials d'utilisateur phishé.
2. **4769** ×N depuis cette IP de poste vers un DC, toutes `etype=0x17`, toutes ciblant des comptes de service user-SPN en 5 minutes — kerberoasting.
3. *(Hors ligne, invisible)* — l'attaquant craque le hash du compte de service le plus faible dans Hashcat.
4. **4768** — demande TGT comme le compte de service compromis, depuis un autre hôte.
5. **4624** LogonType 3 sur un serveur de forte valeur, AuthenticationPackage Kerberos, utilisant le compte de service.
6. [**7045**](/fr/blog/service-creation-event-id-7045) — service installé pour la persistance sous le compte compromis.

La rafale 4769 à l'étape 2 est votre point de détection le plus précoce et le moins cher — heures ou jours avant que l'attaquant ne revienne comme compte de service.

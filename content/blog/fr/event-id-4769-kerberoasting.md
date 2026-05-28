---
title: "Event ID 4769 expliqué : tickets de service Kerberos et kerberoasting"
description: "4769 est l'enregistrement DC de chaque demande de ticket de service. Lisez-le via le type de chiffrement et vous repérez le kerberoasting. Lisez-le avec 4768 et vous repérez le pass-the-ticket."
date: "2026-05-24"
---

L'Event ID **4769**, « Un ticket de service Kerberos a été demandé », se déclenche sur chaque Domain Controller chaque fois qu'un compte demande un ticket TGS (Ticket Granting Service) pour un service. Chaque connexion SMB, chaque login SQL, chaque hit SSO web en produit un sur le DC qui a géré la demande. C'est l'enregistrement au plus haut volume dans le [canal Security](/fr/blog/what-is-an-evtx-file) sur un DC chargé, et le seul endroit où le kerberoasting apparaît de manière fiable avant que les identifiants ne soient craqués hors ligne.

Si vous n'instrumentez que trois enregistrements Security depuis vos DC, celui-ci en fait partie.

## Où il vit

`4769` est écrit dans le canal Security du **Domain Controller émetteur** uniquement. Pas le client, pas le service cible. Pour voir tous les enregistrements 4769 d'un domaine, il faut collecter depuis chaque DC. Le target `EventLogs` de KAPE sur un DC, ou transférer Security via WEF vers un collecteur, marchent les deux. WEF est ce qu'utilisent les boutiques matures.

## Ce que l'enregistrement contient

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

- `TargetUserName`. Le demandeur (le compte utilisateur, en format `user@DOMAIN`).
- `ServiceName`. Le SPN demandé. Un compte utilisateur ici (au lieu de `host/...` ou d'une classe de service) est suspect.
- `TicketEncryptionType`. Le champ qui décide si cet enregistrement compte. Les domaines modernes tournent en `0x12` (AES-256-CTS-HMAC-SHA1-96) ou `0x11` (AES-128). **`0x17` est RC4-HMAC** : legacy, faible et le *seul* type de chiffrement que Mimikatz et le mode `kerberoast` de Rubeus demandent. Un 4769 pour un ticket de compte de service en `0x17` est une empreinte de kerberoasting de manuel.
- `Status`. `0x0` est succès. Tout le reste est refusé (codes documentés dans `[MS-KILE]`).
- `IpAddress`. Hôte demandeur. Associez à [4624](/fr/blog/understanding-event-id-4624) sur cet hôte pour voir le logon qui a produit la session.

## TicketEncryptionType : le champ qui décide

| Valeur | Algorithme | Statut |
|---|---|---|
| 0x01 | DES-CBC-CRC | Désactivé par défaut depuis Win7 |
| 0x03 | DES-CBC-MD5 | Désactivé par défaut depuis Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderne |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderne (défaut pour la plupart des comptes) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Nécessaire au kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 grade export, infiniment rare |

Si le domaine a été baseliné et `msDS-SupportedEncryptionTypes` posé sur AES-only sur les comptes de service, `0x17` ne devrait pas apparaître pour ces comptes du tout. Les attaquants demandent `0x17` explicitement parce que craquer des tickets de service chiffrés en RC4 est computationnellement bon marché. AES non. L'outil de craquage *doit* demander 0x17.

C'est le champ le plus signalant de l'enregistrement.

## Le motif de kerberoasting

Le kerberoasting (T1558.003) fonctionne ainsi :

1. L'attaquant s'authentifie avec n'importe quel utilisateur de domaine (pas besoin de droits admin).
2. L'attaquant énumère les SPN enregistrés sur des comptes utilisateurs (pas des comptes ordinateurs), typiquement via un LDAP `(servicePrincipalName=*)` filtré sur les objets utilisateurs.
3. L'attaquant demande un TGS pour chaque SPN avec `etype=23` (RC4) via le protocole Kerberos standard. Le 4769 que vous cherchez.
4. Le DC émet joyeusement le ticket, chiffré avec le hash NTLM du compte de service.
5. L'attaquant tire le blob chiffré et le craque hors ligne dans Hashcat (`-m 13100`).

L'empreinte 4769 :

- `ServiceName` est `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` ou tout SPN pointant vers un compte utilisateur (pas `host/...` ou `cifs/...`, qui sont des comptes ordinateurs).
- `TicketEncryptionType` est `0x17`.
- Une rafale dans une fenêtre courte, depuis la même source, pour de nombreux SPN.

Un motif voisin, **l'AS-REP roasting** (T1558.004), utilise [4768](/fr/blog/event-id-4768-kerberos-tgt) à la place, en visant les comptes avec `DONT_REQUIRE_PREAUTH`. Enregistrement différent, même famille.

## Pass-the-ticket, golden, silver

4769 révèle aussi la forge de tickets, mais le signal est plus subtil.

- Un 4769 *sans* un 4768 précédent pour le même `LogonGuid` depuis le même hôte dans une fenêtre raisonnable : suspicion de golden ticket. L'attaquant a présenté un TGT forgé et est passé direct aux demandes TGS.
- Un 4769 *et* l'authentification de service résultante sur la cible *sans* un 4769 visible sur un DC : suspicion de silver ticket. L'attaquant a forgé le TGS lui-même. Le DC n'a jamais été sollicité.
- Mismatch de `LogonGuid` entre le 4624 sur la cible et le 4769 qui aurait émis le ticket : ticket forgé.

Ce sont des motifs de détection par absence. Ils exigent une couverture log complète sur tous les DC et services cibles. Les trous de couverture WEF produisent des faux positifs identiques. Caractérisez votre collecte avant d'alerter.

## Workflow de triage

1. Filtrez tous les 4769 sur le corpus DC pour `TicketEncryptionType == 0x17`.
2. Groupez par `IpAddress` et `TargetUserName` sur des fenêtres de 30 minutes. Comptez les `ServiceName` distincts par source.
3. Plus de 3 SPN distincts demandés en 0x17 depuis une source en 30 minutes, c'est du kerberoasting presque partout.
4. Pivotez l'IP source vers son [4624](/fr/blog/understanding-event-id-4624) pour trouver l'identifiant qui a initié l'attaque.
5. Pivotez les SPN demandés vers les comptes de service propriétaires. Rotez ces mots de passe. Réinitialisez les hashes craqués en heures, pas en jours.

## Sigma

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

`filter_machine` exclut les SPN de compte ordinateur (qui se terminent toujours par `$`). Le kerberoasting ne vise que les SPN de comptes utilisateurs.

## KQL et Splunk

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

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapping ATT&CK

- T1558.003 Kerberoasting. Le titre.
- T1558.001 Golden Ticket. 4769 sans 4768 depuis le même `LogonGuid`.
- T1558.002 Silver Ticket. 4769 absent pour une auth de service observée sur la cible.
- T1078 Valid Accounts. 4769 depuis une IP inattendue pour un compte de service connu.
- T1550.003 Pass the Ticket. 4769 suivi d'un [4624](/fr/blog/understanding-event-id-4624) LogonType 3 avec `LogonProcessName: Kerberos`.

## Faux positifs que vous verrez

- Les applications legacy (certains connecteurs SQL Server anciens, certaines apps Java/JBoss) demandent explicitement RC4. Du `0x17` régulier en journée depuis un petit ensemble d'hôtes stables. Baseline et exclu.
- Les domaines pré-AES durant une transition de durcissement Kerberos émettent du `0x17` largement jusqu'à ce que `msDS-SupportedEncryptionTypes` soit posé sur chaque compte. Énervant. Pas malveillant.
- Les scanners de vulnérabilités (Tenable, Qualys, scripts d'énumération BloodHound) reproduisent du trafic de kerberoasting. Étiquetez les hôtes scanner.
- Les outils de migration de compte lors de déplacements cross-forest peuvent demander des combinaisons inhabituelles.

Le signal est le motif en *rafale*, pas l'enregistrement individuel. Du `0x17` constant depuis un hôte, c'est de la configuration. Du `0x17` en rafale vers plusieurs SPN depuis un hôte en quelques minutes, c'est l'attaque.

## Ce que 4769 ne vous dit pas

L'enregistrement n'inclut pas le ticket chiffré lui-même. Le craquage se produit sur ce que l'attaquant a exfiltré, pas sur le câble depuis le DC. Vous ne pouvez pas, depuis 4769 seul, distinguer « ticket émis et jamais utilisé » de « ticket craqué, identifiants réutilisés ». Pour la seconde moitié de la chaîne, il vous faut le [4624](/fr/blog/understanding-event-id-4624) résultant sur le service cible (LogonType 3, AuthenticationPackage Kerberos), et idéalement [4688](/fr/blog/event-id-4688-process-creation) ou [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) montrant ce qui a tourné après réutilisation de l'identifiant. Traitez 4769 comme le canari, pas comme l'alarme.

## Où 4769 s'insère dans une timeline

Chaîne classique de kerberoasting post-exploitation :

1. [4624](/fr/blog/understanding-event-id-4624) sur un poste. Accès initial via identifiants utilisateur phishés.
2. **4769** ×N depuis ce poste vers un DC, tous `etype=0x17`, tous ciblant des comptes de service à SPN-utilisateur en 5 minutes. Kerberoasting.
3. *(Hors ligne, invisible)*. L'attaquant craque le hash du compte de service le plus faible dans Hashcat.
4. [4768](/fr/blog/event-id-4768-kerberos-tgt). Demande TGT en tant que compte de service compromis, depuis un autre hôte.
5. 4624 LogonType 3 sur un serveur de grande valeur, AuthenticationPackage Kerberos.
6. [7045](/fr/blog/service-creation-event-id-7045). Service installé pour la persistance sous le compte compromis.

La rafale de 4769 à l'étape 2 est votre point de détection le plus précoce et le moins cher. Des heures ou des jours avant que l'attaquant ne revienne en tant que compte de service.

## Pour aller plus loin

- [Documentation Microsoft pour 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf : Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)

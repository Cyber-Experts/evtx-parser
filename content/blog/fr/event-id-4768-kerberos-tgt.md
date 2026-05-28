---
title: "Event ID 4768 expliqué : requêtes TGT Kerberos et AS-REP roasting"
description: "4768 est l'enregistrement DC de chaque TGT émis. Lisez-le via le code de résultat et le flag pre-auth et vous repérez l'AS-REP roasting, la brute force et l'abus d'unconstrained delegation."
date: "2026-05-24"
---

L'Event ID **4768**, « Un ticket d'authentification Kerberos (TGT) a été demandé », se déclenche sur un Domain Controller chaque fois que quelqu'un demande un Ticket Granting Ticket. Tout logon de domaine commence par l'un de ceux-ci. Associez-le à [4769](/fr/blog/event-id-4769-kerberoasting) (ticket de service) et vous voyez tout le cycle de vie Kerberos de chaque compte de la forêt.

Sur un DC, 4768 est l'enregistrement au plus haut volume dans le [canal Security](/fr/blog/what-is-an-evtx-file) après 4624. La plupart est du bruit. Les tranches à fort signal vivent dans deux champs spécifiques, et l'un d'eux est l'empreinte d'AS-REP roasting.

## Où il se déclenche

Comme [4769](/fr/blog/event-id-4769-kerberoasting), 4768 atterrit uniquement sur le **Domain Controller** émetteur. Le client ne le voit pas. Le service cible ne le voit pas. Pour détecter quoi que ce soit depuis 4768, il vous faut une collecte Security depuis chaque DC. Style KAPE pour des missions ponctuelles, WEF en régime permanent.

## Ce que l'enregistrement contient

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

Les champs qui comptent :

- `TargetUserName`. Le compte demandant un TGT. Toujours un compte utilisateur ou ordinateur. `ServiceName` est toujours `krbtgt`.
- `Status`. Code de résultat Kerberos. `0x0` est un succès. Les échecs sont ce qui rend 4768 utile : `0x6` utilisateur inconnu, `0x12` client verrouillé, `0x17` mot de passe expiré, `0x18` mauvais mot de passe.
- `TicketEncryptionType`. Même encodage que 4769 : `0x12` et `0x11` AES (moderne), **`0x17` RC4** (legacy, aussi l'empreinte d'AS-REP roasting).
- `PreAuthType`. `2` est la pre-auth standard à horodatage chiffré. `0` signifie **aucune pre-auth utilisée** (le prérequis d'AS-REP roasting). `15`, `16`, `17` sont des valeurs de pre-auth PKINIT basée sur certificat.
- `IpAddress`. Hôte demandeur. Associez au [4624](/fr/blog/understanding-event-id-4624) côté client pour le contexte complet.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Renseignés pour PKINIT (logon par carte à puce ou certificat). Vides pour les logons par mot de passe.

## Les deux motifs d'attaque que 4768 révèle

### AS-REP roasting (T1558.004)

L'usage phare. Certains comptes ont `DONT_REQUIRE_PREAUTH` posé dans `userAccountControl` (bit UAC 22 = `0x400000`). Pour ces comptes, le DC répond à une demande TGT **sans** exiger la pre-auth à horodatage chiffré. L'AS-REP qu'il renvoie contient du matériel qu'un attaquant peut craquer hors ligne pour récupérer le hash du mot de passe du compte.

L'empreinte 4768 d'un AS-REP roast en cours :

- `PreAuthType = 0` (pas de pre-auth).
- `TicketEncryptionType = 0x17` (RC4, ce que l'outil de craquage attend).
- `Status = 0x0` (le DC a émis l'AS-REP joyeusement).
- Souvent groupé. Un attaquant traite des dizaines de comptes par lot pour tester lesquels ont la pre-auth désactivée.

Les vrais comptes avec `DONT_REQUIRE_PREAUTH` existent presque exclusivement pour la compatibilité legacy : très vieux clients Kerberos Unix, quelques appliances ancestrales. Ils sont minuscules en nombre et prévisibles en localisation. Un 4768 avec `PreAuthType=0` pour un compte qui n'a aucune raison d'utiliser du Kerberos sans pre-auth est le signal.

### Brute force ou spray de mot de passe

Une pre-auth Kerberos échouée produit 4768 avec `Status=0x18` (« mauvais mot de passe »). Contrairement à [4625](/fr/blog/detecting-4625-brute-force) (qui capture les échecs NTLM), 4768 est là où atterrissent les attaques de mots de passe Kerberos. Les outils modernes (Rubeus, kerbrute) parlent Kerberos directement parce que le DC échoue silencieusement sur les tentatives NTLM plus vite qu'il ne répond aux Kerberos, et beaucoup de SOC ne surveillent que 4625.

L'empreinte de brute force 4768 :

- Beaucoup d'enregistrements `Status=0x18` pour le même `TargetUserName` depuis la même IP source dans une fenêtre courte. Brute force.
- Beaucoup d'enregistrements `Status=0x18` sur de nombreuses valeurs `TargetUserName` depuis une IP source, chacune touchée une ou deux fois. Password spray.
- Une rafale de `Status=0x6` (« utilisateur inconnu ») précédant `Status=0x18` depuis la même source. Énumération d'utilisateurs confirmée avant que la brute ne commence.

## Codes de statut qui pilotent le triage

| Status | Sens | Lecture du champ |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Succès. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Nom d'utilisateur inexistant. Rafales = énumération. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Compte verrouillé, désactivé ou expiré. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Mot de passe expiré. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Mauvais mot de passe. Rafales = brute force ou spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Renvoyé au client en premier sur une nouvelle demande TGT. Le vrai succès suit. N'alertez pas sur ceux-là seuls. |
| `0x25` | KRB_AP_ERR_SKEW | Décalage d'horloge > 5 min. Souvent des tentatives d'AS-REP roasting depuis un hôte avec une horloge délibérément fausse. |

## Workflow de triage : AS-REP roasting

1. Filtrez 4768 sur tous les DC pour `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Groupez par `IpAddress`. Un compte unique depuis un hôte de migration connu est de la configuration. Plusieurs comptes depuis une source est l'attaque.
3. Pivotez chaque `TargetUserName` vers son `userAccountControl`. `DONT_REQUIRE_PREAUTH` a-t-il vraiment besoin d'être posé ? Presque certainement pas.
4. IP source dans [4624](/fr/blog/understanding-event-id-4624) sur cet hôte pour trouver l'identifiant qui s'est authentifié pour lancer l'attaque.
5. Rotez le mot de passe de chaque compte craqué. Retirez `DONT_REQUIRE_PREAUTH` des comptes qui n'en ont pas besoin.

## Workflow de triage : brute force Kerberos

1. Filtrez 4768 par `Status == 0x18`.
2. Groupez par `IpAddress` sur des fenêtres de 15 minutes. Comptez les `TargetUserName` distincts.
3. Plus de 5 comptes depuis une source en 15 minutes, c'est du spray. Plus de 10 échecs contre un compte dans la même fenêtre, c'est de la brute force.
4. Croisez avec `Status == 0x6` depuis la même source. L'énumération avant la brute est l'ordre de manuel.

## Sigma : AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL : password spray Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk : AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapping ATT&CK

- T1558.004 AS-REP Roasting. Détection phare sur `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force et sous-techniques `.001` Password Guessing et `.003` Password Spraying. Motifs `Status=0x18`.
- T1558.001 Golden Ticket. Un TGT forgé contourne entièrement 4768. La détection ici est par *absence* : un [4769](/fr/blog/event-id-4769-kerberoasting) sans un 4768 précédent depuis la même source et la même fenêtre est le soupçon.
- T1187 Forced Authentication. Pas directement visible dans 4768 mais les demandes TGT résultantes le seront.

## Faux positifs qui ressemblent à des attaques

- Vieilles piles Java ou Unix Kerberos dans des silos d'app legacy se mettent parfois par défaut en RC4 sans pre-auth. Elles apparaissent comme du trafic 4768 régulier en journée depuis un hôte stable. Baseline.
- Migration PKINIT lors de déploiements de cartes à puce. Des bascules `PreAuthType=15/16/17` légitimes paraissent anormales si vous ne les avez pas vues avant. Surveillez la fenêtre de déploiement.
- Bugs de bibliothèques Kerberos. Certains clients redemandent les TGT agressivement en cas de décalage d'horloge, générant du bruit. Croisez avec `Status=0x25`.
- Traversée de trust de domaine. L'authentification cross-forest produit 4768 de chaque côté. L'`IpAddress` est un DC de l'autre forêt. Étiquetez-le.

## Ce que 4768 ne vous dit pas

L'enregistrement n'inclut pas le matériel AS-REP réel que l'attaquant a capturé (ce qu'il craque hors ligne). Vous voyez que la demande a été émise. Vous ne voyez pas quelles données ont été renvoyées au-delà des métadonnées. Vous ne voyez pas non plus la perspective client : quelle application a lancé la demande, dans quel contexte utilisateur elle tournait. Pour cela, il vous faut le [4624](/fr/blog/understanding-event-id-4624) côté client, et [4688](/fr/blog/event-id-4688-process-creation) si `kerbrute.exe` ou Rubeus a tourné localement.

Notez aussi que 4768 ne se déclenche que pour la demande TGT initiale et lors des renouvellements. Une fois qu'un client a un TGT valide en cache, il ne reparle pas au KDC pour TGT jusqu'au renouvellement. Les tickets de service qu'il dérive génèrent [4769](/fr/blog/event-id-4769-kerberoasting), pas 4768. Un attaquant qui vole un TGT à longue durée de vie (golden ticket) peut émettre des 4769 arbitraires sans jamais produire un autre 4768.

## Où 4768 s'insère dans une timeline

AS-REP roasting du début à la fin :

1. [4624](/fr/blog/understanding-event-id-4624). Logon initial de domaine à bas privilège (identifiant phishé).
2. *(LDAP, parfois un 4662 si la SACL est posée)*. L'attaquant énumère `userAccountControl` pour les comptes avec `DONT_REQUIRE_PREAUTH`.
3. Rafale **4768**. `PreAuthType=0`, `etype=0x17`, `Status=0x0` pour chaque compte candidat. Le point de détection.
4. *(Hors ligne, invisible)*. L'attaquant craque le matériel AS-REP récupéré dans Hashcat (mode 18200).
5. **4768**. Nouvelle demande TGT en tant que compte compromis, cette fois pré-authentifiée normalement.
6. [4769](/fr/blog/event-id-4769-kerberoasting). Tickets de service pour tout ce que le compte compromis peut atteindre.
7. [4624](/fr/blog/understanding-event-id-4624) LogonType 3 sur le service cible.

L'étape 3 est le canari. L'étape 5 et suivantes sont la compromission réelle. La fenêtre entre les deux, minutes à jours, est la seule fenêtre où un défenseur peut agir avant que l'identifiant ne soit vivant dans la nature.

## Pour aller plus loin

- [Documentation Microsoft pour 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf : AS-REP Roasting](https://adsecurity.org/?p=3293)

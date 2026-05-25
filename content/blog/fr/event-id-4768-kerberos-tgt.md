---
title: "Event ID 4768 expliqué : demandes de TGT Kerberos et AS-REP roasting"
description: "4768 est l'enregistrement DC de chaque TGT émis. Lu via le code de résultat et le flag de pré-authentification, il révèle AS-REP roasting, brute force et abus de délégation non contrainte."
date: "2026-05-24"
---

L'Event ID **4768** — « Un ticket d'authentification Kerberos (TGT) a été demandé » — se déclenche sur un contrôleur de domaine chaque fois que quiconque demande un Ticket Granting Ticket. Chaque connexion domaine commence par l'un d'eux. Couplez-le à [4769](/fr/blog/event-id-4769-kerberoasting) (ticket de service) et vous voyez tout le cycle de vie Kerberos de chaque compte de la forêt.

Sur un DC, 4768 est l'enregistrement au plus haut volume du [canal Security](/fr/blog/what-is-an-evtx-file) après 4624. La plupart est du bruit ; les tranches à fort signal vivent dans deux champs spécifiques — et l'un d'eux est l'empreinte de l'AS-REP roasting.

## Où il se déclenche

Comme [4769](/fr/blog/event-id-4769-kerberoasting), 4768 atterrit sur le **contrôleur de domaine** émetteur uniquement. Le client ne le voit pas ; le service cible ne le voit pas. Pour détecter quoi que ce soit depuis 4768, il faut une collecte Security depuis chaque DC — style KAPE pour des missions ponctuelles, WEF en régime stable.

## Ce que contient l'enregistrement

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

- **`TargetUserName`** — le compte demandant un TGT. Toujours un compte utilisateur ou machine ; `ServiceName` est toujours `krbtgt`.
- **`Status`** — code de résultat Kerberos. `0x0` est succès. Les échecs sont ce qui rend 4768 utile : `0x6` = utilisateur inconnu, `0x12` = client verrouillé, `0x17` = mot de passe expiré, `0x18` = mauvais mot de passe.
- **`TicketEncryptionType`** — même encodage que 4769 : `0x12`/`0x11` AES (moderne), **`0x17` RC4** (legacy, aussi l'empreinte d'AS-REP roasting).
- **`PreAuthType`** — `2` est la pré-auth horodatage chiffré standard ; `0` signifie **aucune pré-auth utilisée** (la pré-condition d'AS-REP roasting) ; `15`/`16`/`17` sont les valeurs de pré-auth PKINIT (certificat).
- **`IpAddress`** — hôte demandeur. Couplez avec le [4624](/fr/blog/understanding-event-id-4624) côté client pour le contexte complet.
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — peuplés pour PKINIT (logon smart-card / certificat). Vides pour les logons par mot de passe.

## Les deux patterns d'attaque que 4768 révèle

### 1. AS-REP roasting (T1558.004)

L'usage phare. Certains comptes ont le flag `DONT_REQUIRE_PREAUTH` posé dans `userAccountControl` (bit UAC 22 = `0x400000`). Pour ces comptes, le DC répond à une demande de TGT **sans** exiger la pré-auth horodatage chiffré — ce qui signifie que l'AS-REP qu'il retourne contient du matériel qu'un attaquant peut craquer hors ligne pour récupérer le hash du mot de passe du compte.

L'empreinte 4768 d'un AS-REP roast en cours :

- `PreAuthType` est `0` (pas de pré-auth).
- `TicketEncryptionType` est `0x17` (RC4 — ce dont l'outil de cracking a besoin).
- `Status` est `0x0` (le DC a émis joyeusement l'AS-REP).
- Souvent en clusters : un attaquant batche des dizaines de comptes pour tester lesquels ont la pré-auth désactivée.

Les vrais comptes avec `DONT_REQUIRE_PREAUTH` existent presque exclusivement pour la compatibilité legacy (très anciens clients Unix Kerberos, quelques anciens appliances). Ils sont peu nombreux et prévisibles dans leur emplacement. Un 4768 avec `PreAuthType=0` pour un compte qui n'a *aucune raison* d'utiliser du Kerberos sans pré-auth est le signal.

### 2. Brute force / spray basé mot de passe

L'échec de pré-auth Kerberos produit un 4768 avec `Status=0x18` (« mauvais mot de passe »). Contrairement à [4625](/fr/blog/detecting-4625-brute-force) (qui capture les échecs NTLM), 4768 est l'endroit où atterrissent les attaques de mot de passe basées Kerberos. Les toolkits modernes (Rubeus, kerbrute) parlent directement Kerberos parce que le DC échoue silencieusement aux tentatives NTLM plus vite qu'il ne répond aux Kerberos — et beaucoup de SOC ne regardent que 4625.

L'empreinte brute-force 4768 :

- Beaucoup d'enregistrements `Status=0x18` pour le même `TargetUserName` depuis la même IP source sur une courte fenêtre — brute force classique.
- Beaucoup d'enregistrements `Status=0x18` à travers de nombreuses valeurs de `TargetUserName` depuis la même IP source, chaque compte touché une ou deux fois — password spray.
- Une rafale de `Status=0x6` (« utilisateur inconnu ») précédant un `Status=0x18` depuis la même source — énumération d'utilisateurs confirmée avant le démarrage du brute.

## Les codes Status que vous verrez

La liste complète est large ; ceux qui pilotent le triage :

| Status | Signification | Ce que cela veut dire d'habitude dans la nature |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Succès. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Nom d'utilisateur inexistant. Rafales = énumération. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Compte verrouillé / désactivé / expiré. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Mot de passe expiré. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Mauvais mot de passe. Rafales = brute force ou spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Retourné au client *en premier* sur une demande TGT fraîche ; un vrai succès suit. N'alertez pas sur ceux-ci seuls. |
| `0x25` | KRB_AP_ERR_SKEW | Décalage d'horloge > 5 min entre client et DC. Souvent des tentatives d'AS-REP roasting depuis un hôte avec une horloge délibérément erronée. |

## Workflow de triage — AS-REP roasting

1. Filtrez 4768 sur tous les DC pour `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Groupez par `IpAddress`. Un seul compte depuis un hôte de migration connu est de la configuration ; plusieurs comptes depuis une source est l'attaque.
3. Pivotez chaque `TargetUserName` vers son `userAccountControl` — `DONT_REQUIRE_PREAUTH` a-t-il vraiment besoin d'être posé ? Presque certainement non.
4. IP source → [4624](/fr/blog/understanding-event-id-4624) sur cet hôte pour trouver la credential qui s'est authentifiée pour lancer l'attaque.
5. Rotez le mot de passe de chaque compte craqué ; retirez `DONT_REQUIRE_PREAUTH` des comptes qui n'en ont pas besoin.

## Workflow de triage — brute force Kerberos

1. Filtrez 4768 pour `Status == 0x18`.
2. Groupez par `IpAddress` sur des fenêtres de 15 minutes ; comptez les `TargetUserName` distincts.
3. >5 comptes depuis une source en 15 minutes est spray ; >10 échecs contre un compte sur la même fenêtre est brute force.
4. Croisez avec `Status == 0x6` depuis la même source — l'énumération avant le brute est l'ordre textbook.

## Exemple de règle Sigma — AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## Exemple KQL — password spray Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Exemple Splunk — AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Cartographie ATT&CK

- **T1558.004 — AS-REP Roasting** : la détection phare sur `PreAuthType=0 + etype=0x17`.
- **T1110 — Brute Force** et sous-techniques `.001` Password Guessing et `.003` Password Spraying — patterns `Status=0x18`.
- **T1558.001 — Golden Ticket** : un TGT forgé contourne 4768 entièrement. La détection ici est par *absence* — un [4769](/fr/blog/event-id-4769-kerberoasting) (demande TGS) sans 4768 précédant depuis la même source/fenêtre est la suspicion.
- **T1187 — Forced Authentication** : pas directement visible dans 4768 mais les demandes TGT résultantes le seront.

## Faux positifs qui ressemblent à des attaques

- **Anciennes piles Java / Unix Kerberos** dans des silos d'applications legacy par défaut RC4 sans pré-auth parfois. Elles apparaissent comme un trafic 4768 stable, en journée, depuis un hôte stable. Baselinez.
- **Migration PKINIT** pendant les rollouts smart-card : des passages légitimes en `PreAuthType=15/16/17` paraissent anormaux si vous ne les avez jamais vus. Surveillez la fenêtre de rollout.
- **Bugs de bibliothèques Kerberos** : certains clients redemandent agressivement des TGT sur le skew horaire, générant du bruit. Croisez avec `Status=0x25`.
- **Traversée de trust de domaine** : l'authentification cross-forest produit 4768 de chaque côté. L'`IpAddress` sera un DC de l'autre forêt ; taguez-le.

## Ce que 4768 ne dit pas

L'enregistrement n'inclut **pas** le matériel AS-REP réel que l'attaquant a capturé (ce qu'ils craquent hors ligne). Vous voyez que la demande a été émise ; vous ne voyez pas quelles données ont été retournées au-delà des métadonnées. Vous ne voyez pas non plus la perspective *client* — quelle application a lancé la demande, sous quel contexte utilisateur, etc. Pour ça, il faut le [4624](/fr/blog/understanding-event-id-4624) côté client (et [4688](/fr/blog/event-id-4688-process-creation) si `kerbrute.exe` a tourné localement).

Notez aussi que 4768 ne se déclenche que pour la demande *initiale* de TGT et lors des renouvellements. Une fois qu'un client a un TGT valide en cache, il ne reparle pas au KDC pour TGT jusqu'au renouvellement ; les tickets *service* qu'il dérive génèrent [4769](/fr/blog/event-id-4769-kerberoasting), pas 4768. Les deux enregistrements décrivent des étapes différentes du même protocole — et un attaquant qui vole un TGT longue durée (golden ticket) peut émettre des 4769 arbitraires sans jamais produire un autre 4768.

## Où 4768 s'inscrit dans une timeline

La chaîne AS-REP roasting du début à la fin :

1. [**4624**](/fr/blog/understanding-event-id-4624) — connexion domaine initiale peu privilégiée (credential phishée).
2. *(LDAP, parfois un 4662 si la SACL est posée)* — l'attaquant énumère les flags `userAccountControl` pour des comptes avec `DONT_REQUIRE_PREAUTH`.
3. **4768** en rafale — `PreAuthType=0`, `etype=0x17`, `Status=0x0` pour chaque compte candidat. **C'est le point de détection.**
4. *(Hors ligne, invisible)* — l'attaquant craque le matériel AS-REP récupéré dans Hashcat (mode 18200) et récupère le mot de passe en clair.
5. **4768** — nouvelle demande TGT comme le compte compromis, cette fois pré-auth normalement.
6. [**4769**](/fr/blog/event-id-4769-kerberoasting) — tickets service pour tout ce que le compte compromis peut atteindre.
7. [**4624**](/fr/blog/understanding-event-id-4624) LogonType 3 sur le service cible.

L'étape 3 est le canari. L'étape 5 et la suite est la compromission réelle. La fenêtre entre les deux — minutes à jours — est la seule fenêtre où un défenseur peut agir avant que la credential ne soit vivante dans la nature.

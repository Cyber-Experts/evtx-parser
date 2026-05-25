---
title: "Event ID 4672 expliqué : détecter les connexions privilégiées sous Windows"
description: "4672 se déclenche dès qu'une connexion reçoit des privilèges sensibles comme SeDebugPrivilege. C'est le signal « cette session est admin-équivalent »."
date: "2026-05-24"
---

L'Event ID **4672** — « Privilèges spéciaux affectés à la nouvelle session » — se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'une session de connexion reçoit l'un d'un ensemble fixe de privilèges Windows sensibles. En pratique cela signifie : chaque connexion administrateur-équivalente réussie produit un 4672, immédiatement après le [4624](/fr/blog/understanding-event-id-4624) correspondant. Sur la plupart des postes, 4672 est rare ; sur les contrôleurs de domaine et les jumpboxes admin, il est constant. C'est cette asymétrie qui le rend utile.

Si vous ne filtrez les enregistrements Security que sur un seul champ, « donne-moi tous les 4672 de la dernière semaine » est la requête la moins chère pour « montre-moi toutes les sessions privilégiées du parc ».

## Où il se déclenche

Toujours sur l'hôte où la connexion a réellement eu lieu — comme [4624](/fr/blog/understanding-event-id-4624). Une connexion réseau à `SERVER01` produit le 4624 et (si privilégié) le 4672 sur `SERVER01`, pas sur le poste d'origine. Pour détecter quoi que ce soit à partir de 4672 à grande échelle, il faut une collecte Security depuis les serveurs et les DC au minimum ; depuis les postes admin et jumphosts si le volume vous le permet.

## Ce que contient l'enregistrement

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

Les champs :

- **`SubjectLogonId`** — le même `LogonId` qui apparaît sur le [4624](/fr/blog/understanding-event-id-4624) correspondant. C'est votre pivot : chaque 4672 lie exactement un 4624 (et tous les enregistrements ultérieurs de cette session) à l'ensemble de privilèges que cette connexion a obtenus.
- **`PrivilegeList`** — le sac de privilèges réel. Windows ne journalise ici qu'un ensemble fixe de privilèges « sensibles » (définis dans la politique d'audit) ; une session peut détenir plus de privilèges que ce que l'enregistrement montre. Ceux omis — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc. — sont non pertinents pour la sécurité et volontairement élagués.
- **`Subject*`** — à qui appartient la connexion. Presque toujours identiques aux mêmes champs sur le 4624 correspondant.

Il n'y a pas d'`IpAddress`, ni de `LogonType`, ni de `WorkstationName` sur 4672 lui-même. Pour les obtenir, joignez le 4624 via `SubjectLogonId`.

## Les privilèges et leur signification

| Privilège | Nom affiché | Pourquoi ça compte |
|---|---|---|
| `SeDebugPrivilege` | Déboguer des programmes | Lire/écrire la mémoire de n'importe quel processus — y compris `lsass.exe`. Mimikatz en a besoin. |
| `SeTcbPrivilege` | Agir en tant que partie du système d'exploitation | Effectivement `LocalSystem`. Ne devrait apparaître que pour LocalSystem lui-même. |
| `SeImpersonatePrivilege` | Emprunter l'identité d'un client après authentification | Le privilège utilisé par les familles d'exploits SeImpersonatePrivilege (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Remplacer un jeton au niveau processus | Outillage d'usurpation de token. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Sauvegarder/restaurer fichiers | Contourner les ACL pour lire/écrire des fichiers arbitraires — y compris les hives de registre. `reg save HKLM\SAM` fonctionne avec eux. |
| `SeTakeOwnershipPrivilege` | Prendre la propriété de fichiers | Outrepasser les ACL fichier. |
| `SeLoadDriverPrivilege` | Charger et décharger des pilotes | Requis pour les attaques BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Gérer l'audit et le journal Security | Lire/effacer le journal Security. Requis pour déclencher [1102](/fr/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modifier les valeurs d'environnement firmware | Bootkits, tampering EFI. |
| `SeChangeNotifyPrivilege` | Contourner la vérification de traversée | Commun sur la plupart des connexions ; pas un signal de triage. |

Certains de ceux-là, vous les attendez sur chaque connexion admin (`SeDebugPrivilege`, `SeBackupPrivilege`). D'autres devraient être plus rares (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Le signal est dans le privilège *inattendu* qui apparaît sur le *mauvais* compte.

## Les patterns de triage

### 1. Baseline de qui obtient 4672

Dans un parc sain, les producteurs de 4672 forment un ensemble *petit et connu* :

- `LocalSystem` (S-1-5-18) — chaque hôte, tout le temps, au démarrage de service.
- `NetworkService` (S-1-5-20) — fréquent sur les serveurs faisant tourner des services capables d'impersonation.
- Une poignée d'administrateurs, identifiés par SID plutôt que par nom.

Quiconque d'autre génère un 4672 est soit : un nouvel admin que vous ne connaissiez pas, un événement d'élévation de privilèges, ou un compte mal configuré.

La requête baseline la moins chère : `SubjectUserSid` distincts depuis 4672 sur les 30 derniers jours, triés par fréquence. Tout ce qui sort des top N producteurs mérite un regard.

### 2. SeImpersonatePrivilege sur un compte non privilégié

Si un 4672 montre `SeImpersonatePrivilege` sur un compte qui n'est ni admin ni un SID `*Service`, c'est presque certainement une escalade de la famille « Potato » (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). Ces exploits donnent à un appelant token `IIS_IUSRS` ou service-token la qualité `SYSTEM`. Le 4672 se déclenche *au moment où le privilège est acquis* — plus tôt que tout processus visible spawné avec le nouveau privilège.

### 3. SeDebugPrivilege sans groupe admin

`SeDebugPrivilege` est accordé aux admins locaux par politique. Le voir sur un compte non-admin est signe que la politique a été modifiée — généralement par un attaquant pour permettre l'accès LSASS — ou qu'un attaquant s'est injecté dans un processus admin.

### 4. Connexion privilégiée hors heures de bureau

Un 4672 pour un vrai compte admin à 03:00 un dimanche est l'alerte « activité admin hors heures » la moins chère qui soit. Combinez avec le `LogonType` et l'`IpAddress` du 4624 correspondant pour le contexte.

### 5. Dérive de compte de service

Un compte de service qui historiquement ne déclenche que `SeImpersonatePrivilege` et `SeAssignPrimaryTokenPrivilege` qui se met soudain à produire des 4672 avec `SeBackupPrivilege` et `SeDebugPrivilege` signifie que quelqu'un a changé ses appartenances de groupe. Couplez avec 4732/4728 pour trouver le changement d'appartenance.

## Exemple de règle Sigma — SeDebugPrivilege sur un non-admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Ajustez `filter_known_admins` par environnement ; certaines structures utilisent une liste de SID plutôt qu'un motif de nom.

## Exemple KQL — escalade famille Potato

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Exemple Splunk — baseline des connexions admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Lancez-le chaque semaine ; les anomalies apparaissent comme de nouveaux comptes dans le top 50.

## Cartographie ATT&CK

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft** : SeImpersonatePrivilege sur des comptes non privilégiés.
- **T1003.001 — OS Credential Dumping: LSASS Memory** : SeDebugPrivilege est la précondition.
- **T1068 — Exploitation for Privilege Escalation** : tout gain de privilège inattendu.
- **T1078 — Valid Accounts** : 4672 pour des comptes admin légitimes depuis des sources inhabituelles.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging** : SeSecurityPrivilege est requis pour appeler `ClearEventLog` ; un 4672 avec ce privilège immédiatement avant [1102](/fr/blog/event-id-1102-cleared-log) est la trace de pas.

## Faux positifs qui ressemblent exactement à des attaques

- **Logiciels de backup** (Veeam, Commvault) déclenchent routinièrement 4672 avec `SeBackupPrivilege` + `SeRestorePrivilege` depuis des comptes de service. Baseline par SID de compte de service.
- **Agents de monitoring** (SCOM, collecteurs WMI custom) qui lisent des données pertinentes pour la sécurité déclenchent largement 4672. Taguez l'hôte de l'agent.
- **Certains scripts de logon** sous contextes privilégiés produisent des chaînes de 4672 au logon.
- **Hôtes Hyper-V / VMM / containers** génèrent un trafic 4672 dense depuis `LocalSystem` et les comptes de service managés.

Le signal est dans le *nouveau* producteur, pas dans celui *récurrent*. Un producteur 4672 qui s'est déclenché tous les jours pendant la dernière année est de la configuration ; un qui vient d'apparaître cette semaine est la piste.

## Ce que 4672 ne dit pas

- **Pas d'information sur les processus** : vous voyez l'attribution du privilège, pas ce que le processus privilégié a fait. Pour suivre l'avant, pivotez `SubjectLogonId` vers les enregistrements [4688](/fr/blog/event-id-4688-process-creation) / [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) de la même session.
- **Pas d'IP source** directement : il faut joindre [4624](/fr/blog/understanding-event-id-4624) via `SubjectLogonId` pour l'obtenir.
- **Pas chaque action privilégiée** : seule l'*attribution au logon* est enregistrée. Les usages ultérieurs (par ex. `RtlAdjustPrivilege` qui bascule `SeDebugPrivilege` on/off) produisent des enregistrements 4673/4674, pas un autre 4672.
- **Manqué si l'audit Special Logon est désactivé** : la sous-catégorie d'audit est *Audit Special Logon*, qui doit être activée pour les succès. Activée par défaut sur Windows moderne mais à vérifier.

## Où 4672 s'inscrit dans une timeline

La chaîne textbook d'escalade et nettoyage :

1. [**4624**](/fr/blog/understanding-event-id-4624) — LogonType 3 depuis une IP contrôlée par l'attaquant, utilisateur peu privilégié.
2. *(silencieux)* — escalade basée sur `SeImpersonatePrivilege` (PrintSpoofer ou similaire).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` accordés à une nouvelle session tournant sous `LocalSystem`. **Escalade visible ici.**
4. [**4688**](/fr/blog/event-id-4688-process-creation) — `cmd.exe` ou `powershell.exe` tournant en SYSTEM via le token impersonné.
5. [**4104**](/fr/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` ou `comsvcs.dll MiniDump` contre LSASS — SeDebugPrivilege est ce qui rend ça possible.
6. [**1102**](/fr/blog/event-id-1102-cleared-log) — log Security effacé. SeSecurityPrivilege de l'étape 3 a permis cela.
7. **4672** — deuxième session privilégiée comme un domain admin extrait de la mémoire LSASS.

Les 4672 aux étapes 3 et 7 sont les points de détection les moins chers de la chaîne. Sans eux, vous reconstituez l'impersonation à partir des seuls événements de processus — plus lent, et plus facile à manquer.

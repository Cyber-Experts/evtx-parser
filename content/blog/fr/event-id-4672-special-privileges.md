---
title: "Event ID 4672 expliqué : détecter les logons privilégiés sous Windows"
description: "4672 se déclenche dès qu'un logon se voit accorder des privilèges sensibles comme SeDebugPrivilege ou SeTcbPrivilege. Lisez-le comme le signal « ce logon est équivalent admin » et le reste de la stratégie d'audit tombe en place."
date: "2026-05-24"
---

L'Event ID **4672**, « Privilèges spéciaux assignés à un nouveau logon », se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'une session de logon se voit accorder l'un d'un ensemble fixe de privilèges Windows sensibles. En pratique, chaque logon réussi équivalent à administrateur produit un 4672, écrit immédiatement après le [4624](/fr/blog/understanding-event-id-4624) correspondant. Sur la plupart des postes 4672 est rare. Sur les contrôleurs de domaine et les jumpboxes admin il est constant. Cette asymétrie est ce qui le rend utile.

Si vous filtrez Security par un champ cette semaine, lancez « tous les 4672 des sept derniers jours ». C'est la requête « montre-moi chaque session privilégiée du parc » la moins chère que vous puissiez écrire.

## Où il se déclenche

Sur l'hôte où le logon a réellement eu lieu, comme [4624](/fr/blog/understanding-event-id-4624). Un logon réseau vers `SERVER01` produit le 4624 et le 4672 sur `SERVER01`, pas sur le poste d'origine. Pour détecter quoi que ce soit depuis 4672 à l'échelle, il vous faut au minimum la collecte de Security depuis les serveurs et les DC. Postes admin et jumphosts si vous pouvez vous offrir le volume.

## Ce que l'enregistrement contient

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

- `SubjectLogonId`. Le même `LogonId` du [4624](/fr/blog/understanding-event-id-4624) correspondant. C'est votre pivot. Chaque 4672 lie exactement un 4624 (et chaque enregistrement suivant de cette session) à l'ensemble de privilèges que le logon a obtenu.
- `PrivilegeList`. Le sac de privilèges réel. Windows ne journalise que les privilèges « sensibles » définis dans la stratégie d'audit. Un logon peut détenir plus de privilèges que ce que l'enregistrement montre. Les omis (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc.) ne sont pas pertinents pour la sécurité et sont élagués de cet enregistrement à dessein.
- `Subject*`. À qui appartient le logon. Presque toujours identique au 4624 correspondant.

Il n'y a pas d'`IpAddress`, pas de `LogonType`, pas de `WorkstationName` sur le 4672 lui-même. Pour les obtenir, joignez au 4624 via `SubjectLogonId`. Les analystes qui essaient d'alerter sur 4672 seul ratent souvent cela et finissent avec des enregistrements qu'ils ne peuvent pas enrichir.

## Les privilèges et ce qu'ils signifient

| Privilège | Nom affiché | Pourquoi ça compte |
|---|---|---|
| `SeDebugPrivilege` | Déboguer les programmes | Lire/écrire la mémoire de n'importe quel processus, y compris `lsass.exe`. Mimikatz en a besoin. |
| `SeTcbPrivilege` | Agir en tant que partie de l'OS | Effectivement `LocalSystem`. Ne devrait apparaître que pour LocalSystem. |
| `SeImpersonatePrivilege` | Usurper un client après auth | Le privilège utilisé par la famille Potato (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). |
| `SeAssignPrimaryTokenPrivilege` | Remplacer un token de processus | Outillage d'impersonation de token. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Sauvegarde/Restauration | Contourner les ACL pour lire/écrire des fichiers arbitraires, y compris des hives de registre. `reg save HKLM\SAM` fonctionne avec ceux-ci. |
| `SeTakeOwnershipPrivilege` | Prendre possession | Outrepasser les ACL des fichiers. |
| `SeLoadDriverPrivilege` | Charger des pilotes | Requis pour BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Gérer le journal d'audit | Lire ou effacer Security. Requis pour déclencher [1102](/fr/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modifier le firmware | Bootkits, altération EFI. |
| `SeChangeNotifyPrivilege` | Outrepasser la vérification de traversée | Courant sur la plupart des logons. Pas un signal de triage. |

Certains, vous les attendez à chaque logon admin (`SeDebugPrivilege`, `SeBackupPrivilege`). D'autres devraient être plus rares (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Le signal est le privilège *inattendu* sur le *mauvais* compte.

## Les motifs

### Baseline de qui obtient 4672

Dans un parc sain, les producteurs de 4672 forment un ensemble petit et connu :

- `LocalSystem` (S-1-5-18). Chaque hôte, tout le temps, au démarrage des services.
- `NetworkService` (S-1-5-20). Courant sur des serveurs exécutant des services capables d'impersonation.
- Une poignée d'administrateurs, identifiés par SID plutôt que par nom.

Tout autre est un nouvel admin que vous ne connaissiez pas, un événement d'escalade de privilèges, ou un compte mal configuré.

La requête baseline la moins chère : `SubjectUserSid` distinct de 4672 sur les 30 derniers jours, trié par fréquence. Tout ce qui sort du top N mérite un coup d'œil.

### SeImpersonatePrivilege sur un compte non privilégié

Si un 4672 montre `SeImpersonatePrivilege` sur un compte qui n'est pas admin et pas un SID `*Service`, c'est presque sûrement une escalade Potato. Ces exploits donnent à un appelant `IIS_IUSRS` ou à token de service `SYSTEM`. Le 4672 se déclenche *au moment de l'acquisition du privilège*. C'est plus tôt que tout processus visible engendré avec le nouveau privilège.

### SeDebugPrivilege sans groupe admin

`SeDebugPrivilege` est accordé aux admins locaux par stratégie. Sur un compte non admin, soit la stratégie a été modifiée (généralement par un attaquant pour activer l'accès à LSASS), soit un attaquant s'est injecté dans un processus admin.

### Logon privilégié hors heures de bureau

Un 4672 pour un vrai compte admin à 03:00 un dimanche est l'alerte hors-heures la moins chère qui soit. Combinez avec `LogonType` et `IpAddress` du 4624 correspondant pour le contexte.

### Dérive de compte de service

Un compte de service qui historiquement ne déclenche que `SeImpersonatePrivilege` et `SeAssignPrimaryTokenPrivilege` qui se met soudain à produire des 4672 avec `SeBackupPrivilege` et `SeDebugPrivilege` signifie que quelqu'un a modifié ses appartenances de groupe. Associez à 4732 ou 4728 pour trouver le changement d'appartenance.

## Sigma : SeDebugPrivilege sur un non-admin

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
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Ajustez `filter_known_admins` par environnement. Certaines boutiques utilisent une liste de SID plutôt qu'un motif de noms.

## KQL : escalade famille Potato

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

## Splunk : baseline des logons admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Lancez-le hebdomadairement. Les anomalies apparaissent sous forme de nouveaux comptes dans le top 50.

## Mapping ATT&CK

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege sur comptes non privilégiés.
- T1003.001 LSASS Memory. SeDebugPrivilege est la précondition.
- T1068 Exploitation for Privilege Escalation. Toute acquisition inattendue de privilège.
- T1078 Valid Accounts. 4672 pour comptes admin légitimes depuis des sources inhabituelles.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege est requis pour appeler `ClearEventLog`. Un 4672 portant ce privilège juste avant [1102](/fr/blog/event-id-1102-cleared-log) est le sentier de miettes.

## Faux positifs qui ressemblent à des attaques

- Les logiciels de sauvegarde (Veeam, Commvault) déclenchent régulièrement 4672 avec `SeBackupPrivilege` + `SeRestorePrivilege` depuis des comptes de service. Baseline par SID de compte de service.
- Les agents de monitoring (SCOM, collecteurs WMI maison) déclenchent 4672 largement. Étiquetez l'hôte de l'agent.
- Certains runners de scripts de logon sous contextes privilégiés produisent des chaînes de 4672 au moment du logon.
- Hyper-V, VMM, hôtes de conteneurs génèrent des 4672 denses depuis `LocalSystem` et des comptes de service managés.

Le signal est le producteur *nouveau*, pas le *récurrent*. Un producteur de 4672 qui déclenche quotidiennement depuis un an, c'est de la configuration. Un qui vient d'apparaître cette semaine, c'est la piste.

## Ce que 4672 ne vous dit pas

- Pas d'info de processus. Vous voyez l'octroi de privilège, pas ce que le processus privilégié a fait. Pour le suivre vers l'avant, pivotez `SubjectLogonId` vers les enregistrements [4688](/fr/blog/event-id-4688-process-creation) ou [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) de la même session.
- Pas d'IP source directement. Vous joignez au [4624](/fr/blog/understanding-event-id-4624) via `SubjectLogonId`.
- Pas chaque action privilégiée. Seul l'*octroi au logon* est enregistré. Les usages ultérieurs (par exemple `RtlAdjustPrivilege` qui bascule `SeDebugPrivilege` on et off) produisent des enregistrements 4673/4674, pas un autre 4672.
- Manqué si l'audit Special Logon est éteint. La sous-stratégie d'audit est *Audit Special Logon*. Activée par défaut dans Windows moderne, mais vaut la peine de vérifier.

## Où 4672 s'insère dans une timeline

La chaîne d'escalade-et-nettoyage de manuel :

1. [4624](/fr/blog/understanding-event-id-4624). LogonType 3 depuis une IP contrôlée par l'attaquant, utilisateur à faible privilège.
2. *(silencieux)*. Escalade basée sur SeImpersonatePrivilege (PrintSpoofer ou similaire).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege accordés à une nouvelle session de logon tournant en LocalSystem. Escalade visible ici.
4. [4688](/fr/blog/event-id-4688-process-creation). `cmd.exe` ou `powershell.exe` en SYSTEM via le token usurpé.
5. [4104](/fr/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` ou `comsvcs.dll MiniDump` contre LSASS. SeDebugPrivilege est ce qui rend cela possible.
6. [1102](/fr/blog/event-id-1102-cleared-log). Journal Security effacé. SeSecurityPrivilege de l'étape 3 l'a permis.
7. **4672**. Deuxième session privilégiée en tant que domain admin extraite de la mémoire de LSASS.

Les 4672 aux étapes 3 et 7 sont les points de détection les moins chers. Sans eux, vous reconstruisez l'impersonation à partir d'événements de processus seuls. Plus lent, plus facile à rater.

## Pour aller plus loin

- [Documentation Microsoft pour 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps : An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)

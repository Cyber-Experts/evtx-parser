---
title: "Event ID 1102 expliqué : journal d'audit Security effacé (et ce qui survit)"
description: "1102 est le seul événement qu'on ne peut pas supprimer sans laisser plus de traces. Voici ce qu'il vous dit et ce qui survit à l'effacement."
date: "2026-05-17"
---

L'Event ID **1102** est l'enregistrement que Windows écrit sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) quand le journal d'audit est effacé. C'est — par conception — l'un des enregistrements les plus difficiles à supprimer pour un attaquant, parce que cela impose soit de remplacer le service EventLog avant son démarrage, soit d'accepter que l'acte d'effacement laisse son propre 1102.

Pour les défenseurs, cela signifie : si vous voyez un 1102, quelqu'un avec suffisamment de privilèges a délibérément effacé la piste d'audit. Ce n'est presque jamais une action admin normale.

## Ce que contient l'enregistrement

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Notez le bloc `UserData` au lieu de l'habituel `EventData` — 1102 fait partie des enregistrements qui utilisent un schéma user-data structuré. Les champs vous disent *qui* a effacé le journal sous quelle session. Pivotez sur le `SubjectLogonId` pour trouver le [4624](/fr/blog/understanding-event-id-4624) correspondant et vous aurez l'IP source et le type de connexion qui ont produit la session privilégiée.

## Ce qui se déclenche aussi quand 1102 se déclenche

Un effacement de journal est rarement la *seule* action anti-forensique. Compagnons fréquents, dans un ordre chronologique grossier :

- **104** sur le canal `System` — même acte, enregistré par le SCM. Si 104 est présent mais 1102 manque, l'attaquant n'a effacé que le journal Security et a oublié System.
- **4719** — « Stratégie d'audit système modifiée ». Parfois un attaquant réduit la couverture d'audit *avant* d'effacer, pour laisser moins d'enregistrements au prochain tour.
- **4616** — « L'heure système a été modifiée ». Un décalage horaire avant l'effacement rend la reconstruction de timeline plus difficile.
- **Un trou dans les 4624** pendant une heure ou deux avant le 1102 — l'attaquant a peut-être utilisé un canal latéral non journalisé.

## Ce qui survit à un effacement

Effacer le journal en mémoire ne touche pas :

- **Les autres canaux** : `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, les canaux d'événements transférés — aucun n'est effacé par un wipe Security.
- **Les événements transférés** : si Windows Event Forwarding (WEF) est configuré vers un collecteur central, les enregistrements effacés sont déjà sur un autre hôte.
- **Le fichier sur disque lui-même** : un `Security.evtx` effacé est remplacé par un nouveau fichier ; les clusters du fichier *supprimé* persistent souvent dans l'espace non alloué et peuvent être carvés avec un outil NTFS.
- **Les entrées USN journal** pour le remplacement du fichier : même l'opération d'effacement laisse des artefacts au niveau du système de fichiers.

Un effacement de log « réussi » est rarement aussi propre que l'attaquant l'espère.

## Exemple de règle Sigma — log effacé

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

Si vous voyez un 1102 hors d'une fenêtre de maintenance approuvée, traitez comme un incident — point final.

## Exemple KQL — corrélation effacement + session privilégiée

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Chaque 1102 remonte à un [4672](/fr/blog/event-id-4672-special-privileges) qui a accordé `SeSecurityPrivilege` — qui remonte à un [4624](/fr/blog/understanding-event-id-4624). La jointure complète le tableau.

## Exemple Splunk — chaîne anti-forensique avec compagnons

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un `LogonId` qui a touché à la politique d'audit (4719) ou à l'heure système (4616) puis effacé un log (1102/104) est la chaîne de tampering.

## Cartographie ATT&CK

- **T1070.001 — Indicator Removal: Clear Windows Event Logs** : la technique principale. 1102 *est* l'indicateur primaire de cette technique.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging** : 4719 (politique d'audit modifiée) précédant 1102 colle ici.
- **T1070.006 — Indicator Removal: Timestomp** : couplé à 4616 (heure système modifiée) dans la même chaîne.
- **T1078.003 — Valid Accounts: Local Accounts** : 1102 par un Administrator local qui n'aurait pas dû être connecté à cet instant.

## Faux positifs — rares mais réels

- **Workflows de migration / décommissionnement** : des techs effacent le log sur un hôte en cours de décommissionnement. Devrait toujours être ticketé.
- **Labos forensique / test** : workflows d'effacement-puis-reproduction pendant le développement de détections.
- **Certains outils legacy** effacent le log pour réinitialiser des baselines — presque toujours une erreur procédurale, mais réelle.

Le signal est si directement anti-forensique que même des 1102 légitimes devraient être enquêtés et documentés a posteriori. Il n'y a pas de raison « sûre » à un 1102 en opérations normales.

## Pourquoi cela compte pour le parsing

Quand vous [chargez un fichier .evtx dans un outil forensique](/fr/blog/how-to-open-an-evtx-file), la *première* recherche à lancer est `EventID:1102` et `EventID:104`. Si l'un ou l'autre est présent, le log que vous tenez a des trous connus et toute timeline que vous en construirez est incomplète. Notez-le bruyamment dans le rapport.

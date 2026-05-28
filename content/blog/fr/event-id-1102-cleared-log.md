---
title: "Event ID 1102 expliqué : journal d'audit Security effacé (et ce qui survit)"
description: "1102 est le seul événement que vous ne pouvez pas supprimer sans laisser plus de preuves derrière. Voici ce qu'il vous dit, ce qui survit à l'effacement et où chercher quand vous le voyez."
date: "2026-05-17"
---

L'Event ID **1102** est ce que Windows écrit dans le [canal `Security`](/fr/blog/what-is-an-evtx-file) quand quelqu'un efface le journal d'audit. Par conception, c'est l'un des enregistrements les plus difficiles à supprimer pour un attaquant. Le supprimer proprement nécessite soit de remplacer le binaire du service EventLog avant qu'il ne démarre, soit d'accepter que l'acte même d'effacer laisse son propre 1102. La plupart des opérateurs choisissent la seconde option, en espérant que personne ne fasse attention.

Si vous voyez 1102, quelqu'un avec un privilège suffisant a délibérément essuyé la piste d'audit. Ce n'est essentiellement jamais une action admin de routine, et quand ça l'est, ça devrait être ticketé. Traitez chaque 1102 hors d'une fenêtre de maintenance approuvée comme un incident jusqu'à preuve du contraire.

## Ce qui est dans l'enregistrement

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

Notez le bloc `UserData` au lieu du `EventData` habituel. 1102 utilise un schéma user-data structuré, qui fait trébucher certains parsers naïfs qui ne regardent que `EventData`. Les champs vous disent qui a effacé le journal sous quelle session de logon. Pivotez sur `SubjectLogonId` vers le [4624](/fr/blog/understanding-event-id-4624) correspondant et vous avez l'IP source, le type de logon et l'identifiant qui ont produit la session privilégiée.

## Ce qui chevauche à côté

Un effacement de journal est rarement la seule action anti-forensique de la chaîne. Les enregistrements qui ont tendance à se déclencher près de lui, en ordre chronologique approximatif :

- **104** sur le canal `System`. Même acte que 1102 mais enregistré par le SCM pour les canaux non-Security. Si 104 est présent et 1102 absent, l'attaquant n'a effacé que Security et a oublié System.
- **4719**, « la stratégie d'audit système a été modifiée ». Parfois l'attaquant réduit la couverture d'audit *avant* d'effacer, pour laisser moins d'enregistrements la prochaine fois.
- **4616**, « l'heure système a été modifiée ». Le timestomping avant effacement rend la reconstruction de timeline plus difficile.
- Un trou dans les 4624 dans l'heure ou les deux précédant 1102. L'attaquant peut avoir utilisé un canal latéral non journalisé pour entrer.

## Ce qui survit à un effacement

Effacer le journal d'événements en mémoire ne touche pas :

- D'autres canaux. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canaux d'événements transférés. Aucun n'est effacé par un wipe de Security.
- Les événements transférés. Si Windows Event Forwarding envoie Security vers un collecteur, les enregistrements effacés sont déjà sur un autre hôte. Les RecordIDs et horodatages d'origine sont préservés.
- Le fichier sur disque lui-même. Une `Security.evtx` effacée est remplacée par un fichier frais. Les clusters du fichier précédent persistent souvent dans l'espace non alloué. Les enregistrements EVTX [se carvent proprement](/fr/blog/carve-deleted-evtx-records) depuis ces clusters.
- Les entrées du [journal USN](https://www.usnparser.com) pour le remplacement du fichier. Même l'acte d'effacer laisse des artefacts niveau système de fichiers.
- L'entrée [MFT](https://www.mftparser.com) pour le nouveau fichier, qui porte un horodatage de création qui devrait correspondre au 1102 à la seconde près.

Un effacement de journal « réussi » est rarement aussi propre que l'attaquant l'espère.

## Sigma : journal effacé

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
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

## KQL : effacement corrélé à une session privilégiée

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

Chaque 1102 remonte à un [4672](/fr/blog/event-id-4672-special-privileges) accordant `SeSecurityPrivilege`, qui remonte à un [4624](/fr/blog/understanding-event-id-4624). La jointure complète l'image.

## Splunk : la chaîne d'altération

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un LogonId qui a touché à la stratégie d'audit (4719) ou à l'heure système (4616) puis a effacé un journal (1102/104) est la chaîne d'altération.

## Mapping ATT&CK

- T1070.001 Indicator Removal: Clear Windows Event Logs. Le titre. 1102 *est* l'indicateur principal.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 précédant 1102 mappe ici.
- T1070.006 Indicator Removal: Timestomp. Associé à 4616 dans la même chaîne.
- T1078.003 Valid Accounts: Local Accounts. 1102 par un Administrateur local qui n'aurait pas dû être connecté à ce moment-là.

## Faux positifs, rares mais réels

- Workflows de migration ou de decom. Des techniciens qui effacent les journaux sur un hôte en cours de mise hors service. Devrait toujours être ticketé.
- Laboratoires forensiques exécutant des boucles effacer-et-reproduire pendant le développement de détection.
- Certains outils legacy effacent le journal pour « réinitialiser les baselines ». Presque toujours une erreur procédurale, mais réelle.

Il n'y a pas de raison sûre pour un 1102 en opérations normales. Même les légitimes devraient être enquêtés et documentés après coup.

## Quand vous en trouvez un dans le bundle

Quand vous chargez un [fichier .evtx dans un outil forensique](/fr/blog/how-to-open-an-evtx-file), les deux premières recherches qui valent la peine sont `EventID:1102` et `EventID:104`. Si l'un est présent, le journal que vous avez en main a des trous connus. Toute timeline construite dessus est incomplète. Notez-le bruyamment dans le rapport. Puis allez voir ce qui a survécu : le [registre](https://www.registryparser.com), le [journal USN](https://www.usnparser.com), la [MFT](https://www.mftparser.com), le [prefetch](https://www.prefetchparser.com) et l'[AmCache](https://www.amcacheparser.com). Ensemble, ils reconstruisent l'essentiel de ce que 1102 a tenté d'effacer.

Des outils comme `Invoke-Phant0m` sautent 1102 entièrement en suspendant les threads du service d'événements au lieu d'effacer. Si vous voyez un silence de plusieurs heures dans Security sans 1102 et sans arrêt système, c'est l'autre forme du même problème.

## Pour aller plus loin

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Documentation Microsoft pour 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)

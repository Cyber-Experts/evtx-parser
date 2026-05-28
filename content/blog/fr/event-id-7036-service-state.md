---
title: "Event ID 7036 expliqué : changements d'état de service pour le triage DFIR"
description: "7036 se déclenche chaque fois qu'un service démarre ou s'arrête. Associé à 7045, il confirme si la persistance a vraiment tourné. Seul, il révèle l'abus de service, l'évasion de défense et les anomalies de boot."
date: "2026-05-24"
---

L'Event ID **7036**, « Le service {service} est passé à l'état {state} », se déclenche sur le [canal `System`](/fr/blog/what-is-an-evtx-file) chaque fois que le Service Control Manager voit une transition de service. Chaque démarrage, arrêt, pause et reprise en produit un. Seul, c'est à fort volume et facile à écarter. Associé à [7045](/fr/blog/service-creation-event-id-7045), c'est la différence entre « un backdoor a été installé » et « un backdoor a été installé et a tourné ».

Pour la réponse à incident, c'est l'enregistrement « a-t-il exécuté ? » le moins cher que l'OS vous donne.

## Où il vit

Canal `System` sur l'hôte où le service a tourné. Pas d'implication DC, pas de souci de transfert par canal. C'est juste là dans `System.evtx`. Provider : `Service Control Manager`.

## Ce que l'enregistrement contient

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

C'est tout. Deux paramètres et un tag binaire. Beaucoup plus petit que la plupart des enregistrements Security, c'est pour ça que les analystes le sautent.

- `param1`. Le *nom d'affichage* du service (pas le nom court). `Background Intelligent Transfer Service` ici est le nom orienté utilisateur de `BITS`. Pour pivoter vers la définition du service, il vous faut généralement le nom court. Le SCM le tamponne dans `Binary` sous forme de blob UTF-16 (`42 00 49 00 54 00 53 00` décode en `BITS`).
- `param2`. Le nouvel état : `running`, `stopped`, `paused`, `resumed` ou des intermédiaires en attente (`start pending`, `stop pending`). `running` et `stopped` sont sur quoi la plupart des règles s'appuient.

Il n'y a pas d'`AccountName`, pas d'`ImagePath`, pas de `ProcessId`. 7036 vous dit *quoi* a changé d'état, pas *qui* l'a déclenché. Pour le pourquoi, associez à d'autres enregistrements.

## 7036, 7045, 7035, 7034 : qui est qui

Quatre événements canal System liés aux services sont confondus en permanence :

| Événement | Quand | Ce qu'il vous donne |
|---|---|---|
| **7045** | Service installé | Nom d'affichage, nom court, `ImagePath`, `AccountName`, `StartType`. Le point de persistance. |
| **7036** | Démarrage/arrêt de service | Nom d'affichage seulement. Le point d'exécution. |
| **7035** | Contrôle de service envoyé | Qui a initié start/stop (SID), quel contrôle a été envoyé. Rarement actif par défaut. |
| **7034** | Service crashé inopinément | Service terminé sans arrêt propre. |

Le motif compte : un 7045 suivi quelques secondes plus tard d'un 7036 `running` pour le même nom d'affichage est la séquence de manuel « installé et tourné ». Un 7045 *sans* 7036 correspondant signifie que le service a été enregistré mais jamais exécuté : soit l'attaquant a nettoyé, soit l'installeur a abandonné, soit le démarrage a été différé.

## Les motifs de triage

### Vérification de persistance : associer à 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Trois enregistrements, un événement d'exécution latérale PsExec. La paire 7036 vous dit que le service a effectivement tourné (pas seulement été installé). Pour un backdoor *persistant* le second 7036 (stopped) peut manquer ou apparaître des heures plus tard quand l'hôte redémarre.

Un 7045 sans 7036 `running` dans les minutes est une anomalie en soi. Enquêtez pourquoi l'installation n'a pas tiré. Causes courantes : préparé pour le prochain reboot, mis en démarrage manuel et l'attaquant ne l'avait pas déclenché, démarrage échoué (cherchez des erreurs 7034 / 7000).

### Évasion de défense : arrêter les services de sécurité

Le motif le plus abusé. Un attaquant arrête `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` ou le service d'un produit EDR. Chacun génère un 7036 `stopped` pour le nom d'affichage correspondant. Si une altération de la politique d'audit ou de Defender est tentée, c'est l'un des enregistrements qui survit.

Noms qui méritent une alerte (noms d'affichage ; varient selon la version de Defender ou d'EDR) :

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Tout ce qui matche `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` pour l'un d'eux, surtout hors d'une fenêtre de maintenance planifiée, devrait être une alerte dure. Beaucoup d'attaquants utilisent `sc stop`, `net stop`, `Stop-Service`, ou `taskkill /im`. Les quatre produisent un 7036.

### Typosquatting de nom de service

7036 se déclenche pour le nom d'affichage même quand le service sous-jacent est malveillant. Surveillez les noms d'affichage qui semblent légitimes mais ne correspondent à aucun service Microsoft installé : `Windows Update Service` (le vrai nom est `Windows Update`), `Windows Defender Service` (le vrai nom est `Windows Defender Antivirus Service`), `Microsoft Telemetry` (aucun tel service). Baselinez les noms d'affichage d'un hôte connu bon et faites diff.

### Anomalies de boot

Après un reboot, le SCM remonte les services en démarrage automatique dans un ordre globalement stable. Un nouveau service en démarrage automatique apparaissant dans la séquence 7036 de boot, surtout un qui n'était pas dans le boot précédent, est un nouveau point de persistance. Croisez avec le 7045 correspondant à ou avant l'arrêt précédent.

## Sigma : service de sécurité arrêté

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL : séquence 7045 vers 7036

Le pivot phare. Installation de persistance suivie d'exécution dans les 5 minutes sur le même hôte :

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

`DisplayName` de 7036 ne sera pas toujours littéralement égal à `ServiceName` de 7045 (l'un est display, l'autre est short). Matchez heuristiquement ou pré-calculez une map pour le petit ensemble de services qui comptent.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapping ATT&CK

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` pour les services de sécurité.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` associé à 7045 pour le même service.
- T1569.002 System Services: Service Execution. 7036 `running` pour un `ImagePath` pointant vers un binaire non standard, souvent partie d'un mouvement latéral (PsExec, exécution distante basée sur SCM, Impacket `psexec.py`).
- T1489 Service Stop. Visant la disponibilité (rançongiciel arrêtant SQL Server avant de chiffrer les bases).

## Faux positifs qui ressemblent exactement à des attaques

- Windows Update redémarre une douzaine de services dans une séquence prévisible. Récurrent et rapide.
- Les mises à jour de signatures Defender redémarrent parfois `WinDefend` lui-même. Un `stopped` rapidement suivi d'un `running` depuis `MsSecFlt.exe` est le motif normal. Le malveillant, c'est *pas* de `running` après le `stopped`.
- Les upgrades d'EDR arrêtent et redémarrent le service EDR. Étiquetez les fenêtres d'upgrade du vendeur.
- La mise en veille et l'hibernation du système génèrent des lots de `stopped` à l'endormissement et `running` au réveil. N'alertez pas sur ceux-ci en isolation.
- Les charges de travail conteneurs et Hyper-V montent et descendent des services en permanence.

## Ce que 7036 ne vous dit pas

- Pas d'`AccountName`. Sortez-le du 7045 correspondant ou de la base SCM.
- Pas de PID. Vous ne pouvez pas mapper un 7036 directement à un enregistrement [4688](/fr/blog/event-id-4688-process-creation) ou [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) sans corréler par `ImagePath` et horodatage. Le cache [prefetch](https://www.prefetchparser.com) est la corroboration secondaire quand 4688 était éteint.
- Pas d'initiateur. Vous ne voyez pas qui a appelé Stop-Service. Pour cela il vous faut 7035 (souvent désactivé par défaut), [4688](/fr/blog/event-id-4688-process-creation) pour le `net stop` / `sc stop` / `taskkill` appelant, ou [4104](/fr/blog/powershell-4104-scriptblock) pour `Stop-Service`.
- Mapping du nom court de service. Le nom d'affichage est dans `param1`. Le nom court est dans le blob binaire et doit être décodé. La plupart des parsers le font automatiquement. Si vous requêtez du `EventData` brut, vous devez le gérer vous-même.

## Où 7036 s'insère dans une timeline

Exécution latérale plus évasion de défense :

1. [4624](/fr/blog/understanding-event-id-4624). LogonType 3 depuis un hôte contrôlé par l'attaquant, AuthenticationPackage Kerberos.
2. [4688](/fr/blog/event-id-4688-process-creation). `services.exe` engendrant un enfant pour des opérations SCM (ou le `psexesvc.exe` de PsExec).
3. [7045](/fr/blog/service-creation-event-id-7045). Service installé, `ImagePath` hors des chemins d'installation standard.
4. **7036 `running`**. L'installation a effectivement tiré. Confirmation d'exécution.
5. **7036 `stopped`** pour `WinDefend` ou EDR. Évasion de défense avant que la payload ne tourne.
6. [4688](/fr/blog/event-id-4688-process-creation). Processus payload sous le compte du service.
7. **7036 `stopped`** pour le service installeur. Nettoyage.

7036 apparaît aux étapes 4, 5 et 7. Trois stades différents de la même intrusion. Seul, il est dur à utiliser. En contexte, il lie l'enregistrement de persistance (7045) à l'exécution réelle et aux actions d'évasion de défense alentour.

## Pour aller plus loin

- [Documentation Microsoft : 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

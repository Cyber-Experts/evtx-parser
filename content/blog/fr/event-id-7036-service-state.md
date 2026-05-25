---
title: "Event ID 7036 expliqué : changements d'état de service pour le triage DFIR"
description: "7036 se déclenche à chaque démarrage ou arrêt de service. Couplé à 7045, il confirme si la persistance a réellement tourné — et seul, il révèle abus de service, évasion défensive et anomalies de boot."
date: "2026-05-24"
---

L'Event ID **7036** — « Le service {service} est entré dans l'état {state} » — se déclenche sur le [canal `System`](/fr/blog/what-is-an-evtx-file) chaque fois que le Service Control Manager (SCM) voit une transition de service. Chaque démarrage, arrêt, pause et reprise de service produit l'un d'eux. Seul, il est à haut volume et facile à écarter ; couplé à [7045](/fr/blog/service-creation-event-id-7045) (service installé), il fait la différence entre *une backdoor a été installée* et *une backdoor a été installée et a tourné*.

Pour la réponse à incident, c'est l'enregistrement « est-ce que ça a exécuté ? » le moins cher que l'OS donne.

## Où il vit

Toujours le **canal `System`** sur l'hôte où le service a tourné. Pas d'implication DC, pas de forwarding par canal à gérer — il est directement là dans `System.evtx`. Le provider est `Service Control Manager`.

## Ce que contient l'enregistrement

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

C'est tout. Deux paramètres et un tag binaire — beaucoup plus petit que la plupart des enregistrements Security, ce qui explique pourquoi les analystes le sautent.

- **`param1`** — le *nom d'affichage* du service (pas le nom court). `Background Intelligent Transfer Service` ici est le nom user-facing pour `BITS`. Pour pivoter vers la définition du service, vous aurez souvent besoin du nom court ; le SCM le tamponne aussi dans `Binary` sous forme de blob encodé UTF-16 (le `42 00 49 00 54 00 53 00` ici décode en `BITS`).
- **`param2`** — le nouvel état : `running`, `stopped`, `paused`, `resumed`, ou l'un d'une poignée d'intermédiaires pending (`start pending`, `stop pending`). Les transitions `running` et `stopped` sont sur lesquelles la plupart des règles s'appuient.

Il n'y a pas d'`AccountName`, pas d'`ImagePath`, pas de `ProcessId` — 7036 vous dit *quoi* a changé d'état, pas *qui* a déclenché le changement. Pour le pourquoi, couplez avec d'autres enregistrements (voir ci-dessous).

## 7036 vs 7045 vs 7035 vs 7034

Quatre événements liés aux services du canal System sont constamment confondus :

| Événement | Quand | Ce qu'il vous donne |
|---|---|---|
| **7045** | Service installé | Nom d'affichage, nom court, `ImagePath`, `AccountName`, `StartType`. Le point de persistance. |
| **7036** | Démarrage/arrêt de service | Nom d'affichage seulement. Le point d'exécution. |
| **7035** | Contrôle de service envoyé | Qui a initié le start/stop (SID), quel contrôle a été envoyé. Rarement activé par défaut ; précieux quand il l'est. |
| **7034** | Service crashé de façon inattendue | Service qui s'est terminé sans arrêt propre. Action de recovery. |

Le pattern compte : **un 7045 suivi quelques secondes plus tard d'un 7036 `running` pour le même nom d'affichage est la séquence textbook « installé et a tourné ».** Un 7045 *sans* 7036 correspondant signifie que le service a été enregistré mais n'a jamais exécuté — soit l'attaquant a nettoyé, soit l'installeur a abandonné, soit le start a été reporté.

## Les patterns de triage

### 1. Vérification de persistance — couplage avec 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Trois enregistrements, un événement d'exécution latérale PsExec. La paire 7036 vous dit que le service a réellement tourné (pas juste été installé). Pour une backdoor *persistante*, le second 7036 (stopped) peut manquer ou apparaître heures/jours plus tard quand l'hôte redémarre.

Un 7045 sans 7036 `running` en minutes est sa propre anomalie — investiguez pourquoi l'install ne s'est pas déclenchée. Causes courantes : l'installeur est stagé pour le prochain reboot, le service était positionné en démarrage manuel et l'attaquant ne l'avait pas encore déclenché, ou le start a échoué (cherchez les erreurs 7034 / 7000).

### 2. Signal d'évasion défensive — arrêt de services de sécurité

Le pattern le plus abusé : un attaquant arrête `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` ou le service d'un produit EDR. Chacun génère un 7036 `stopped` pour le nom d'affichage correspondant. Si un tampering audit-policy / Defender est tenté, c'est l'un des enregistrements qui survit.

Les noms sur lesquels alerter (noms d'affichage ; varient selon la version Defender / EDR) :

- `Windows Defender Antivirus Service` → service `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- Tout ce qui correspond à `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` pour l'un de ceux-ci — surtout hors d'une fenêtre de maintenance planifiée — devrait être une alerte dure. Beaucoup d'attaquants utilisent `sc stop`, `net stop`, `Stop-Service` ou `taskkill /im` — les quatre produisent un 7036.

### 3. Typosquatting de nom de service

7036 se déclenche pour le nom d'affichage même quand le service sous-jacent est malveillant. Surveillez les noms d'affichage qui ont l'air légitimes mais ne correspondent à aucun service Microsoft installé : `Windows Update Service` (le vrai nom est `Windows Update`), `Windows Defender Service` (le vrai nom est `Windows Defender Antivirus Service`), `Microsoft Telemetry` (pas de tel service). Baselinez les noms d'affichage d'un hôte sain connu et faites un diff.

### 4. Anomalies de boot

Après un reboot, le SCM remonte les services auto-start dans un ordre à peu près stable. Un nouveau service auto-start apparaissant dans la séquence boot 7036 — surtout un qui n'était pas là au boot précédent — est un nouveau point de persistance. Croisez avec le 7045 correspondant à ou avant le shutdown précédent.

## Exemple de règle Sigma — service de sécurité arrêté

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

## Exemple KQL — séquence 7045 → 7036

Le pivot phare. Install de persistance suivi d'exécution en 5 minutes sur le même hôte :

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

Le `DisplayName` de 7036 ne sera pas toujours littéralement égal au `ServiceName` de 7045 (l'un est display, l'autre est court) — matchez heuristiquement ou pré-calculez une map pour le petit ensemble de services qui comptent.

## Exemple Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Cartographie ATT&CK

- **T1562.001 — Impair Defenses: Disable or Modify Tools** : 7036 `stopped` pour services de sécurité.
- **T1543.003 — Create or Modify System Process: Windows Service** : 7036 `running` couplé à 7045 pour le même service.
- **T1569.002 — System Services: Service Execution** : 7036 `running` pour un `ImagePath` pointant sur un binaire non standard, souvent dans le cadre d'un mouvement latéral (PsExec, exécution distante via SCM).
- **T1489 — Service Stop** : ciblé sur la disponibilité — arrêter des services pour permettre d'autres actions (ransomware arrêtant SQL Server avant de chiffrer les bases).

## Faux positifs qui ressemblent exactement à des attaques

- **Windows Update routinier** redémarre une douzaine de services dans une séquence prévisible. Le pattern est récurrent et rapide.
- **Mises à jour de signatures Defender** redémarrent parfois `WinDefend` lui-même — un `stopped` rapidement suivi de `running` depuis `MsSecFlt.exe` est le pattern normal. Le malveillant est *pas de* `running` après le `stopped`.
- **Upgrades d'EDR** stoppent et redémarrent le service EDR. Taguez les fenêtres d'upgrade du vendeur.
- **Sleep / hibernation système** génèrent des batches d'enregistrements `stopped` au sleep et `running` au wake. Combinés aux événements `wake source`, ils sont évidents ; n'alertez pas dessus en isolation.
- **Workloads container / Hyper-V** font monter et descendre des services constamment.

## Ce que 7036 ne dit pas

- **Pas d'`AccountName`** : l'enregistrement ne dit pas sous quel contexte de sécurité le service tourne. Tirez ça du 7045 correspondant ou de la base SCM.
- **Pas de PID** : vous ne pouvez pas mapper un 7036 directement à un enregistrement [4688](/fr/blog/event-id-4688-process-creation) / [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) sans corréler par `ImagePath` et timestamp.
- **Pas d'initiateur** : vous ne voyez pas *qui* a appelé Stop-Service. Pour ça, il faut 7035 (souvent désactivé par défaut), [4688](/fr/blog/event-id-4688-process-creation) pour l'appel `net stop` / `sc stop` / `taskkill`, ou [4104](/fr/blog/powershell-4104-scriptblock) pour `Stop-Service`.
- **Mapping nom court de service** : le nom d'affichage est dans `param1` ; le nom court est dans le blob binaire et doit être décodé. La plupart des parseurs le font automatiquement ; si vous interrogez `EventData` brut, vous devez gérer ça.

## Où 7036 s'inscrit dans une timeline

Le combo exécution latérale + évasion défensive :

1. [**4624**](/fr/blog/understanding-event-id-4624) — LogonType 3 depuis un hôte contrôlé par l'attaquant, AuthenticationPackage Kerberos.
2. [**4688**](/fr/blog/event-id-4688-process-creation) — `services.exe` spawnant un enfant pour des opérations SCM (ou `psexesvc.exe` de PsExec).
3. [**7045**](/fr/blog/service-creation-event-id-7045) — service installé, `ImagePath` hors des chemins d'install standards.
4. **7036** `running` — l'install s'est réellement déclenchée. **C'est votre confirmation d'exécution.**
5. **7036** `stopped` pour `WinDefend` / EDR — évasion défensive avant que la payload ne tourne.
6. [**4688**](/fr/blog/event-id-4688-process-creation) — processus payload sous le compte de service.
7. **7036** `stopped` pour le service installeur — nettoyage.

7036 apparaît aux étapes 4, 5 et 7 — trois étapes différentes de la même intrusion. Seul, il est difficile à utiliser ; en contexte, il lie l'enregistrement de persistance (7045) à l'exécution réelle et aux actions d'évasion défensive environnantes.

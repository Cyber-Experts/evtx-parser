---
title: "Event ID 7045 expliqué : installation de service comme signal de persistance"
description: "La création de service est l'une des techniques de persistance les plus bruyantes. L'événement 7045 capture chaque install — lisez ces trois champs et vous en attraperez l'essentiel."
date: "2026-05-17"
---

L'Event ID **7045** — « Un service a été installé dans le système » — se déclenche sur le [canal `System`](/fr/blog/what-is-an-evtx-file) chaque fois que le Service Control Manager enregistre un nouveau service. Il est bruyant sur une build de base (installs de pilotes, mises à jour) mais en régime stable d'environnements d'entreprise, il est suffisamment silencieux pour que les anomalies ressortent. C'est aussi l'une des techniques de persistance les plus citées de MITRE ATT&CK : T1543.003.

## Ce que contient l'enregistrement

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinq champs, dont trois comptent pour l'IR.

## Les trois champs à lire en premier

**`ImagePath`** est le champ unique le plus utile. Les services légitimes vivent sous `C:\Windows\System32\`, `C:\Program Files\` ou `C:\Program Files (x86)\`. Tout service dont le binaire se trouve dans `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` ou un répertoire au nom aléatoire mérite un regard. `ImagePath` peut aussi être une ligne `cmd.exe /c …` ou `powershell.exe -e …` — celles-ci sont presque toujours malveillantes ; les services légitimes ne shellent pas.

**`AccountName`** est généralement `LocalSystem`. Un service installé sous un utilisateur de domaine ou un compte de service spécifique qui ne correspond pas au pattern de l'organisation est inhabituel.

**`StartType`** à `auto start` signifie que le service tourne à chaque boot. `demand start` signifie manuel. La persistance veut presque toujours `auto start` ; une exécution latérale one-shot peut utiliser `demand start` et nettoyer derrière elle — laissant le 7045 comme seul artefact.

## Le pattern d'exécution latérale

Quand un attaquant lance `PsExec` ou tout outil qui utilise le SCM pour exécuter à distance sur un autre hôte, vous obtenez un 7045 sur l'hôte *cible* avec un `ImagePath` comme `%SystemRoot%\PSEXESVC.exe` (défaut) ou un équivalent renommé. Le service apparaît, tourne, et est souvent supprimé en quelques secondes. Le 7045 est l'empreinte survivante longtemps après que le service lui-même a disparu.

Un 7045 avec `ImagePath` finissant par `.exe` suivi quelques secondes plus tard de [4624 LogonType **3**](/fr/blog/understanding-event-id-4624) depuis un hôte source spécifique est la signature textbook de PsExec. Les variantes comme SMBExec, WMIExec et `psexec.py` d'Impacket produisent des valeurs `ImagePath` légèrement différentes mais le même pattern global.

## Ce que 7045 ne dit pas

7045 se déclenche à l'*installation*, pas à chaque démarrage subséquent. Pour voir le service réellement tourner, il faut 7036 (« service entré dans l'état running »). Pour voir le processus sous-jacent, il faut [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create) ou [4688](/fr/blog/event-id-4688-process-creation) avec le chemin `Image` correspondant.

Pour les services installés *avant* le démarrage du log d'audit (par ex. pendant l'install OS), il n'y a pas de 7045 — ils existent dans le registre sous `HKLM\SYSTEM\CurrentControlSet\Services\` et doivent y être énumérés, pas depuis les logs d'événements.

## Workflow de triage

1. Filtrez le canal System pour `EventID:7045`.
2. Triez ou pivotez par `ImagePath` — tout hors des chemins d'install standards est suspect.
3. Pour chaque suspect, tirez le 4624 correspondant par timestamp + hôte source — trouvez la credential qui l'a installé.
4. Tirez Sysmon event 1 par `Image` correspondant à `ImagePath` pour voir les exécutions réelles.
5. Notez si une séquence [**7036**](/fr/blog/event-id-7036-service-state) / 7034 / 7035 montre un run one-shot ou un service persistant.

## Exemple de règle Sigma — service installé depuis un chemin non standard

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## Exemple KQL — empreinte d'exécution latérale PsExec

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

Un 4624 LogonType-3 dans les 30 secondes d'un 7045 sur le même hôte est la signature textbook de PsExec.

## Exemple Splunk — installeur de service anormal

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Cartographie ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service** : le mapping principal. Services à longue durée démarrés sous des binaires contrôlés par l'attaquant.
- **T1569.002 — System Services: Service Execution** : services à courte durée utilisés purement comme véhicule d'exécution distante (PsExec, SMBExec, mouvement latéral basé SCM).
- **T1078 — Valid Accounts** : quand le principal qui installe est un domain admin dont les credentials ont été volées.
- **T1036.005 — Masquerading: Match Legitimate Name or Location** : services avec des noms d'affichage mimant de vrais services Microsoft mais des binaires ailleurs.

## Faux positifs qui ressemblent exactement à des attaques

- **Installeurs de logiciels** (Chocolatey, bootstrappers MSI) installent fréquemment des services depuis un répertoire de staging avant de déplacer le binaire. Le 7045 se déclenche depuis le chemin de staging même si l'install finale est propre.
- **Agents EDR / AV** installent des services dans le cadre de leur setup. L'`ImagePath` du vendeur sera stable et signé ; baselinez.
- **Certaines mises à jour Microsoft** installent des services de servicing temporaires ; ils sont à courte durée et depuis `LocalSystem`.
- **Workloads container / Hyper-V** enregistrent parfois des services transitoires par-VM.

Le signal est *install ponctuelle* vers des chemins user-writable par des installeurs *non-admin ou non standard*. Un service d'installeur signé dans `C:\Program Files\` n'est pas l'attaque.

---
title: "Event ID 7045 expliqué : installation de service comme signal de persistance"
description: "La création de service est l'une des techniques de persistance les plus bruyantes. L'événement 7045 capture chaque installation. Lisez ces trois champs et vous attrapez la plupart."
date: "2026-05-17"
---

L'event ID **7045**, "Un service a été installé dans le système", se déclenche sur le [canal `System`](/en/blog/what-is-an-evtx-file) chaque fois que le Service Control Manager enregistre un nouveau service. C'est bruyant sur une build stock (installations de drivers, mises à jour Windows) mais dans un environnement d'entreprise en régime permanent ça devient assez silencieux pour que les anomalies ressortent. C'est aussi une des techniques de persistance les plus citées de MITRE ATT&CK : T1543.003. Vaut la peine de connaître par cœur.

## Ce qu'il y a dans l'enregistrement

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinq champs. Trois comptent pour l'IR.

## Les trois champs à lire d'abord

**`ImagePath`** est le champ le plus utile. Les services légitimes vivent sous `C:\Windows\System32\`, `C:\Program Files\` ou `C:\Program Files (x86)\`. Tout service dont le binaire est dans `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` ou un répertoire au nom aléatoire mérite un regard plus rapproché. `ImagePath` peut aussi être `cmd.exe /c ...` ou `powershell.exe -e ...`. Ceux-là sont presque toujours malveillants. Les services légitimes ne sortent pas en shell.

**`AccountName`** est généralement `LocalSystem`. Un service installé sous un utilisateur de domaine, ou un compte de service spécifique qui ne correspond pas au pattern de l'organisation, est inhabituel.

**`StartType`** de `auto start` signifie que le service tourne à chaque boot. `demand start` signifie manuel. La persistance veut presque toujours `auto start`. L'exécution latérale one-shot peut utiliser `demand start` et se nettoyer après. Ça fait du 7045 le seul artefact restant.

## Le pattern d'exécution latérale

Quand un attaquant lance PsExec ou tout outil utilisant le SCM pour exécuter à distance sur un autre hôte, vous obtenez un 7045 sur l'hôte *cible* avec un `ImagePath` comme `%SystemRoot%\PSEXESVC.exe` (par défaut) ou un équivalent renommé. Le service apparaît, tourne, et est souvent supprimé en secondes. Le 7045 est l'empreinte survivante longtemps après que le service lui-même soit parti.

Un 7045 avec `ImagePath` se terminant par `.exe` suivi secondes plus tard par un [4624 LogonType **3**](/en/blog/understanding-event-id-4624) depuis un hôte source spécifique est la signature de manuel PsExec. Les variantes comme Impacket `psexec.py`, `smbexec.py`, `wmiexec.py` produisent des valeurs `ImagePath` légèrement différentes mais le même pattern global. La variante Impacket renommée est généralement le traître : un nom de service comme `wfDsaQbA` (huit lettres aléatoires) ne vient pas d'un sysadmin.

## Ce que 7045 ne vous dit pas

7045 se déclenche sur *installation*, pas sur chaque démarrage subséquent. Pour voir le service réellement tourner vous avez besoin de [7036](/en/blog/event-id-7036-service-state) ("le service est entré dans l'état running"). Pour voir le processus sous-jacent vous avez besoin de [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) ou [4688](/en/blog/event-id-4688-process-creation) avec le chemin `Image` correspondant.

Pour les services installés *avant* que l'audit log ne commence (par exemple pendant l'installation OS), il n'y a pas de 7045. Ils existent dans le [registre](https://www.registryparser.com) sous `HKLM\SYSTEM\CurrentControlSet\Services\` et doivent être énumérés là, pas depuis les event logs. Le hive [AmCache](https://www.amcacheparser.com) et le cache [prefetch](https://www.prefetchparser.com) corroborent souvent une exécution qui n'a pas produit de 4688.

## Workflow de triage

1. Filtrez le canal System pour `EventID:7045`.
2. Triez ou pivotez par `ImagePath`. Tout en dehors des chemins d'installation standard est suspect.
3. Pour chaque suspect, tirez le 4624 correspondant par timestamp et hôte source. Trouvez le credential qui l'a installé.
4. Tirez Sysmon 1 par `Image` matchant l'`ImagePath` pour voir les exécutions réelles.
5. Notez si une séquence [7036](/en/blog/event-id-7036-service-state) / 7034 / 7035 montre un run one-shot ou un service persistant.

## Sigma : service installé depuis un chemin non-standard

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory. Common for persistence and PsExec-style execution.
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

## KQL : empreinte d'exécution latérale PsExec

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

Un 4624 LogonType-3 dans les 30 secondes d'un 7045 sur le même hôte est la signature de manuel PsExec.

## Splunk : installateur de service anormal

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mapping ATT&CK

- T1543.003 Create or Modify System Process : Windows Service. Services de longue durée démarrés sous des binaires contrôlés par l'attaquant.
- T1569.002 System Services : Service Execution. Services à courte durée utilisés purement comme véhicule pour l'exécution distante (PsExec, SMBExec, lateral movement basé sur SCM).
- T1078 Valid Accounts. Quand le principal qui installe est un admin de domaine dont les credentials ont été volés.
- T1036.005 Masquerading : Match Legitimate Name or Location. Services avec des noms d'affichage imitant de vrais services Microsoft mais binaires ailleurs.

## Faux positifs qui ressemblent exactement à des attaques

- Les installateurs de logiciel (Chocolatey, bootstrappers MSI) installent fréquemment des services depuis un répertoire de staging avant de déplacer le binaire. Le 7045 se déclenche depuis le chemin de staging même si l'installation finale est propre.
- Les agents EDR et AV installent des services dans le cadre de leur setup. L'`ImagePath` du vendor sera stable et signé. Baselinez.
- Certaines mises à jour Microsoft installent des services de servicing temporaires. Courts, depuis `LocalSystem`.
- Les workloads container ou Hyper-V enregistrent parfois des services transitoires par VM.

Le signal sont les installations *one-off* vers des chemins inscriptibles utilisateur par des installateurs *non-admin ou non-standard*. Un service d'installateur signé dans `C:\Program Files\` n'est pas l'attaque.

## Pour aller plus loin

- [Documentation Microsoft pour 7045](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7045)
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [JPCERT/CC : Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

---
title: "Sysmon Event ID 1 expliqué : création de processus pour le triage DFIR"
description: "L'événement 1 de Sysmon est l'enregistrement de création de processus le plus riche que Windows peut produire. Voici ce qu'il contient et comment le trier rapidement."
date: "2026-05-17"
---

Sysmon est un outil gratuit Microsoft qui augmente le [journal d'événements Windows](/en/blog/what-is-an-evtx-file) avec de la télémétrie que l'OS de base ne capture pas sous forme utilisable. Son event ID 1, `ProcessCreate`, est l'enregistrement Sysmon le plus cité dans les playbooks IR. Si vous n'extrayez jamais qu'un canal Sysmon d'un hôte, c'est celui-là.

Je dirai ce que je dis dans chaque writeup Sysmon : un déploiement sans vraie config est principalement du théâtre. Lisez [sysmon-modular](https://github.com/olafhartong/sysmon-modular) ou le `sysmon-config` de SwiftOnSecurity avant de décider ce que vos enregistrements event 1 contiennent réellement.

## Où il vit et ce qu'il capture

Sysmon écrit dans `Microsoft-Windows-Sysmon/Operational` (sur disque : `Microsoft-Windows-Sysmon%4Operational.evtx`). Un enregistrement ProcessCreate contient :

```xml
<Data Name="UtcTime">2026-05-17 14:02:11.123</Data>
<Data Name="ProcessGuid">{...}</Data>
<Data Name="ProcessId">7842</Data>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="CommandLine">powershell -enc SQBFAFgA...</Data>
<Data Name="CurrentDirectory">C:\Users\alice\</Data>
<Data Name="User">CORP\alice</Data>
<Data Name="LogonId">0x3e7</Data>
<Data Name="Hashes">SHA256=...</Data>
<Data Name="ParentProcessGuid">{...}</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\winword.exe</Data>
<Data Name="ParentCommandLine">"winword.exe" /n /dde</Data>
```

Les champs qui mènent les investigations :

- `CommandLine`. Le argv complet, pas juste le binaire.
- `Image` et `Hashes`. Le binaire exact qui a tourné, hash utilisable dans VirusTotal ou Hybrid Analysis.
- L'ensemble `Parent*`. Le processus appelant. Critique pour trouver les chaînes de macro et LOLBin. `ParentCommandLine` en particulier est ce que [4688](/en/blog/event-id-4688-process-creation) ne peut pas vous donner.

## Triage en trois pivots

Trois requêtes couvrent la plupart des cas :

1. **Parents suspects.** Filtrez pour `ParentImage` se terminant par `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, ou un navigateur, avec `Image` étant un shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Une application de document qui spawn un shell est presque toujours malveillante.
2. **PowerShell encodé.** `Image` se terminant par `powershell.exe` et `CommandLine` contenant `-enc`, `-encodedcommand`, ou `FromBase64String`. Décodez le payload, vérifiez ce qu'il fait. Cross-checkez le [scriptblock PowerShell 4104](/en/blog/powershell-4104-scriptblock) sur le même hôte pour voir ce qui s'est réellement exécuté.
3. **LOLBins depuis des endroits bizarres.** Binaires Microsoft signés (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) tournant depuis `C:\Users\`, `%TEMP%`, ou `C:\ProgramData\`.

## Pourquoi la chaîne parent compte

Un seul ProcessCreate est un snapshot. La chaîne est l'histoire. `ProcessGuid` et `ParentProcessGuid` sont des GUIDs que Sysmon assigne pour tracer la lignée à travers les sorties de processus. Ils sont plus fiables que les PIDs parce que les PIDs sont réutilisés. Reconstruisez l'arbre (le `ParentProcessGuid` de chaque enregistrement est le `ProcessGuid` d'un autre enregistrement) et la kill chain devient évidente : Outlook vers Word vers PowerShell vers cmd vers certutil vers mshta. Lire l'arbre en ordre chronologique est généralement comment un writeup s'écrit tout seul.

## Sigma : app Office spawnant un shell

```yaml
title: Office Application Spawning Shell or Scripting Host (Sysmon)
id: 7a4c1f2b-6e3d-4a5f-9c2a-1b3d4e5f6a7c
status: stable
description: A Microsoft Office or document-rendering process spawned cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
      - '\acrord32.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Office add-ins running approved scripts
  - Document automation pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
```

## KQL : PowerShell encodé avec contexte parent

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` est l'équivalent Defender XDR du `ParentCommandLine` de Sysmon 1, que [4688](/en/blog/event-id-4688-process-creation) ne fournit pas.

## Splunk : LOLBins depuis des chemins inscriptibles utilisateur

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## Mapping ATT&CK

- T1059 Command and Scripting Interpreter et sous-techniques `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- T1566.001 Phishing : Spearphishing Attachment. Chaînes Office vers shell.
- T1218 System Binary Proxy Execution et sous-techniques `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- T1036.003 Masquerading : Rename System Utilities. `OriginalFileName` != nom de fichier de `Image`.
- T1055 Process Injection. Le `IntegrityLevel` et la chaîne parent de Sysmon 1 aident à repérer des parents anormaux pour des processus comme `lsass.exe` ou `services.exe`.

## Faux positifs qui ressemblent à des attaques

- Les agents de mise à jour de logiciel spawnent routinièrement des shells sous SYSTEM (Chocolatey, WinGet, MSI vendor). Taguez les hôtes auto-update connus.
- Les scanners de vulnérabilité imitent les arbres de processus offensifs pendant les scans authentifiés. Taguez les IPs de scanner.
- Les hôtes Citrix et RDS multi-session génèrent un trafic dense de création de processus qui chevauche les patterns d'attaquants. Filtrez par plage source.
- Les scans Defender ou EDR exécutent des binaires Microsoft signés depuis des chemins inhabituels durant les scans on-demand.

## Mises en garde sur la couverture

Sysmon ne capture que ce que sa config lui dit. La config par défaut logge presque rien. Les références canoniques sont `sysmon-config` de SwiftOnSecurity et `sysmon-modular` d'Olaf Hartong. Sans vraie config en place, vos enregistrements event 1 seront clairsemés, `CommandLine` peut être redacté par une règle `<CommandLine onmatch="exclude">`, et `Hashes` peut manquer. Lisez la config Sysmon de l'hôte à côté de ses logs. Le décalage entre ce qu'un analyste pense que Sysmon logge et ce qu'il logge réellement m'a coûté des heures plus d'une fois.

Quand Sysmon n'est pas installé du tout, repliez-vous sur [4688](/en/blog/event-id-4688-process-creation) avec audit de ligne de commande, puis [prefetch](https://www.prefetchparser.com), [AmCache](https://www.amcacheparser.com), et le [journal USN](https://www.usnparser.com) pour la preuve d'exécution.

## Pour aller plus loin

- [Documentation Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

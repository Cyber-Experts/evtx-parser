---
title: "Event ID 4688 expliqué : audit de création de processus Windows pour le DFIR"
description: "4688 est l'enregistrement de création de processus du système de base, à condition que l'audit de la ligne de commande soit activé. Voici ce qu'il contient, en quoi il diffère de Sysmon 1 et les motifs de triage qui gagnent leur place."
date: "2026-05-24"
---

L'Event ID **4688**, « Un nouveau processus a été créé », se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un processus est lancé. C'est ce qui se rapproche le plus, dans l'OS de base, de la télémétrie que fournit [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create), et sur les hôtes où Sysmon n'est pas déployé, c'est la seule source de `CommandLine` dont vous disposez. Sur un parc bien configuré, chaque création de processus est l'un d'eux. Lisez-le bien et vous pouvez répondre à « qu'est-ce qui a tourné » sans jamais ouvrir un EDR.

## L'activer, parce que le défaut est à moitié aveugle

Par défaut, 4688 est activé et `CommandLine` n'est **pas** capturé. Sans les lignes de commande, l'enregistrement vous indique un chemin de binaire, un PID, un PID parent et rien sur les arguments. Pour le triage, c'est presque inutile. `powershell.exe` est OK. `powershell.exe -enc SQBFAFgA...` non.

Le correctif est un paramètre de stratégie de groupe :

*Configuration ordinateur / Modèles d'administration / Système / Audit de la création de processus / Inclure la ligne de commande dans les événements de création de processus*

Ou l'équivalent registre : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Une fois posé, chaque 4688 porte le champ `CommandLine` complet. Le coût est le volume de logs. Le bénéfice est toute la surface d'enquête qui existe sous le nom du binaire. Activez-le.

Il vous faut aussi la sous-stratégie d'audit activée : `auditpol /set /subcategory:"Process Creation" /success:enable`. Beaucoup d'hôtes ont la stratégie activée et la ligne de commande éteinte. Vérifiez les deux.

## Ce que l'enregistrement contient

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

Les champs qui pilotent toute enquête :

- `CommandLine`. argv complet (quand la GPO est activée).
- `NewProcessName`. Le chemin du binaire. Combiné à `CommandLine` c'est l'exécution complète.
- `ParentProcessName`. Le processus appelant. Office vers cmd, navigateur vers powershell, services vers unsigned.exe sont les chaînes de manuel.
- `SubjectUserName` et `SubjectLogonId`. Qui l'a lancé, sous quelle session. `SubjectLogonId` pivote vers le [4624](/fr/blog/understanding-event-id-4624) qui a créé la session.
- `TokenElevationType`. `%%1936` Default (pas d'élévation), `%%1937` Full (consentement UAC), `%%1938` Limited (filtré). Un `1937` dans une session non-admin est une transition de privilège qui mérite un regard plus attentif.
- `MandatoryLabel`. SID du niveau d'intégrité. `S-1-16-12288` est High (élevé), `8192` Medium, `16384` System.

## 4688 contre Sysmon 1

Ils se recoupent. Ils ne sont pas identiques.

| Champ | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Oui (si GPO activée) | Oui |
| Image / NewProcessName | Oui | Oui |
| Image parente | Oui (chemin) | Oui (chemin + CommandLine) |
| ParentCommandLine | Non | Oui |
| Hashes d'image (SHA/MD5/IMPHASH) | Non | Oui |
| ProcessGuid (stable cross-host) | Non (PIDs réutilisés) | Oui |
| SID + nom utilisateur | Oui | Oui |
| LogonId | Oui | Oui |
| CurrentDirectory | Non | Oui |
| Niveau d'intégrité | Oui | Oui |
| Disponible sans installation | Oui | Nécessite Sysmon |

Quand les deux sont présents, [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) est l'enregistrement le plus riche. `ParentCommandLine`, hashes d'image, `ProcessGuid` pour des chaînes parent-enfant stables. Quand seul 4688 est présent, vous construisez des chaînes avec des PIDs, que Windows réutilise, donc une longue timeline peut contenir de faux appariements. Vérifiez toujours les liens parent-enfant par horodatage. Quand vous n'avez ni l'un ni l'autre (pas de Sysmon, pas d'audit de ligne de commande), [AmCache](https://www.amcacheparser.com), le [prefetch](https://www.prefetchparser.com) et le [journal USN](https://www.usnparser.com) sont la meilleure preuve d'exécution suivante.

## Les motifs qui gagnent leur place

1. **Office vers shell**. `ParentProcessName` finissant par `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe`, ou `mshta.exe`, avec `NewProcessName` étant `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, ou `regsvr32.exe`. Les applications de documents engendrant des shells, c'est la chaîne macro/phishing classique.
2. **PowerShell encodé**. `NewProcessName` finissant par `powershell.exe` et `CommandLine` correspondant à `-enc`, `-encodedcommand`, `-e ` (lettre unique), `frombase64string`, `iex `, ou `invoke-expression`. Décodez la payload. Croisez avec l'[enregistrement scriptblock 4104](/fr/blog/powershell-4104-scriptblock) pour la même session.
3. **LOLBins depuis des chemins inscriptibles par l'utilisateur**. Des binaires Microsoft signés (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lancés depuis `C:\Users\`, `%TEMP%`, ou `C:\ProgramData\`. L'usage légitime à ces endroits est rare.
4. **Orphelins svchost**. `svchost.exe` avec un `ParentProcessName` autre que `services.exe` (ou `wininit.exe` pour le boot très précoce). Le vrai `svchost` est toujours engendré par `services.exe`. Les imposteurs ressortent.
5. **Binaires renommés**. `NewProcessName` finissant par quelque chose de neutre (`update.exe`, `svc.exe`, `data.exe`) sous des chemins non standard. Associez au champ `OriginalFileName` de Sysmon 1 quand disponible. Ce champ attrape les binaires PsExec, Mimikatz, Impacket renommés qui contournent la détection simple basée sur le nom.

## Sigma : Office vers shell

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
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
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL et Splunk

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Mapping ATT&CK

La majorité de la couverture 4688 tombe sous T1059 Command and Scripting Interpreter et ses sous-techniques (.001 PowerShell, .003 Windows Command Shell, .005 Visual Basic, .007 JavaScript). Les motifs LOLBin mappent à T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32). Les chaînes Office-vers-shell mappent à T1566.001 Phishing: Spearphishing Attachment combiné à T1059. Les détections de binaires renommés mappent à T1036.003 Masquerading: Rename System Utilities.

## Faux positifs, à lire avant d'alerter

- Les agents de mise à jour logicielle engendrent légitimement des shells : Chocolatey, WinGet, wrappers MSI vendeurs. Whitelistez par `SubjectUserSid` (LocalSystem) plus des motifs `ParentProcessName` stables plutôt que par compte utilisateur.
- Les scanners de vulnérabilités et les produits EDR génèrent des arborescences de processus qui ressemblent exactement à un attaquant faisant de la recon : `net.exe`, `whoami.exe`, `systeminfo.exe`. Étiquetez les IP et hôtes de scanner.
- Les boîtiers Citrix et RDS multi-sessions voient des chaînes légitimes `runas /netonly` pour l'accès cross-domain. Enquêtez sur l'utilisateur, pas sur le motif.
- Les scripts de logon (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) se déclenchent à chaque logon et apparaissent comme une chaîne récurrente. Baselinez avant d'alerter.

## Ce que 4688 ne vous dit pas

Pas de hash de fichier. Pas de `ParentCommandLine`. Pas d'`ImageLoaded` (l'injection DLL n'est pas une création de processus). Pas de comportement réseau. Pour ces choses, il vous faut [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create) (le 4688 plus riche), Sysmon 7 (chargement d'image), Sysmon 3/22 (réseau/DNS), et la télémétrie comportementale d'un EDR. 4688 est le plancher de la visibilité processus. Le minimum que tout hôte Windows devrait avoir. Pas un substitut à un EDR correct plus Sysmon sur les hôtes qui comptent.

## Où 4688 s'insère dans une timeline

Pour une chaîne post-exploitation typique sur un hôte sans Sysmon :

1. [4624](/fr/blog/understanding-event-id-4624). Logon initial, LogonType 3 depuis une IP externe.
2. 4624 à nouveau. LogonType 9 (`runas /netonly`) sous le même `SubjectLogonId`. Pivot d'identifiant.
3. **4688**. `powershell.exe -enc ...` sous cette session.
4. [4104](/fr/blog/powershell-4104-scriptblock). Corps de script décodé, allant chercher une payload de seconde étape.
5. **4688**. Binaire de seconde étape tournant depuis `%TEMP%`.
6. [7045](/fr/blog/service-creation-event-id-7045). Service installé pour la persistance.

Six enregistrements racontent toute l'histoire. Les PIDs en (3) et (5) se connectent via `ProcessId` et `NewProcessId` de 4688, mais vérifiez par horodatage parce que Windows recycle les PIDs. Avec Sysmon présent, la chaîne `ProcessGuid` remplace cet appariement fragile.

## Pour aller plus loin

- [Documentation Microsoft pour 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

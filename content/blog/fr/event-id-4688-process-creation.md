---
title: "Event ID 4688 expliqué : audit de création de processus Windows pour le DFIR"
description: "4688 est l'enregistrement de création de processus de l'OS — à condition d'activer l'audit de ligne de commande. Contenu, différences avec Sysmon 1 et patterns de triage."
date: "2026-05-24"
---

L'Event ID **4688** — « Un nouveau processus a été créé » — se déclenche sur le [canal `Security`](/fr/blog/what-is-an-evtx-file) chaque fois qu'un processus est lancé. C'est ce qui se rapproche le plus, côté OS de base, de la télémétrie que fournit [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create) — et sur les hôtes où Sysmon n'est pas déployé, c'est la seule source de `CommandLine` dont vous disposez. Sur un parc correctement configuré, chaque création de processus est l'un de ces enregistrements. Bien lu, vous pouvez répondre à « qu'est-ce qui a tourné ? » sans jamais ouvrir un EDR.

## L'activer (parce que le défaut est à moitié aveugle)

Par défaut, 4688 est activé mais `CommandLine` n'est **pas** capturé. Sans `CommandLine`, l'enregistrement vous dit le chemin d'un binaire, un PID, un PID parent — et rien sur les arguments. Pour le triage, c'est presque inutile : `powershell.exe` n'est pas un problème ; `powershell.exe -enc SQBFAFgA…` en est un.

Le remède est un paramètre Group Policy :

*Configuration ordinateur → Modèles d'administration → Système → Audit Process Creation → Inclure la ligne de commande dans les événements de création de processus*

Ou l'équivalent registre : `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Une fois activé, chaque 4688 porte le champ `CommandLine` complet. Le coût est le volume de logs ; le bénéfice est toute la surface d'investigation qui existe sous le nom de binaire. Activez-le.

Il faut aussi que la politique d'audit sous-jacente soit active : `auditpol /set /subcategory:"Process Creation" /success:enable`. Beaucoup d'hôtes ont la politique on mais command-line off — vérifiez les deux.

## Ce que contient l'enregistrement

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

Champs qui pilotent chaque investigation :

- **`CommandLine`** — argv complet (quand le GPO est on).
- **`NewProcessName`** — le chemin du binaire. Combiné à `CommandLine`, c'est l'exécution complète.
- **`ParentProcessName`** — le processus appelant. Office → cmd, navigateur → powershell, services → unsigned.exe sont les chaînes textbook.
- **`SubjectUserName` / `SubjectLogonId`** — qui l'a lancé, sous quelle session. `SubjectLogonId` pivote vers le [4624](/fr/blog/understanding-event-id-4624) qui a créé la session et vers les autres enregistrements de la même session.
- **`TokenElevationType`** — `%%1936` Default (pas d'élévation), `%%1937` Full (consentement UAC accordé), `%%1938` Limited (filtré). Un `1937` dans une session non-admin est une transition de privilège qui mérite un regard.
- **`MandatoryLabel`** — SID de niveau d'intégrité. `S-1-16-12288` est High (élevé), `8192` est Medium, `16384` System.

## 4688 vs. Sysmon 1

Ils se recouvrent ; ils ne sont pas identiques.

| Champ | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Oui (si GPO on) | Oui |
| Image / NewProcessName | Oui | Oui |
| Image parent | Oui (chemin) | Oui (chemin + CommandLine) |
| ParentCommandLine | Non | Oui |
| ImageHash (SHA/MD5/IMPHASH) | Non | Oui |
| ProcessGuid (stable cross-host) | Non (PID seuls, réutilisés) | Oui |
| User SID + nom | Oui | Oui |
| Logon ID | Oui | Oui |
| CurrentDirectory | Non | Oui |
| Niveau d'intégrité | Oui | Oui |
| Disponible sans installation | Oui | Requiert Sysmon |

Quand les deux sont présents, [Sysmon 1](/fr/blog/sysmon-event-id-1-process-create) est l'enregistrement le plus riche — `ParentCommandLine`, hashes d'image, ProcessGuid pour des chaînes parent-enfant stables. Quand seul 4688 est présent, vous construisez des chaînes avec les PID (que Windows réutilise), donc une longue timeline peut contenir de faux matches ; vérifiez toujours les liens parent-enfant contre les timestamps.

## Les patterns de triage

Dans un corpus d'enregistrements 4688, ces patterns gagnent leur place :

1. **Office → shell** : `ParentProcessName` finissant par `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` ou `mshta.exe`, avec `NewProcessName` étant `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` ou `regsvr32.exe`. Des applications documentaires spawnant des shells est la chaîne classique macro / phishing.
2. **PowerShell encodé** : `NewProcessName` finissant par `powershell.exe` et `CommandLine` correspondant à `-enc`, `-encodedcommand`, `-e ` (une lettre), `frombase64string`, `iex ` ou `invoke-expression`. Décodez la payload ; croisez avec l'[enregistrement scriptblock 4104](/fr/blog/powershell-4104-scriptblock) pour la même session.
3. **LOLBins depuis des chemins utilisateurs** : binaires Microsoft signés (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lancés depuis `C:\Users\`, `%TEMP%` ou `C:\ProgramData\`. Un usage légitime de ceux-ci dans ces emplacements est rare.
4. **Orphelins de service host** : `svchost.exe` avec `ParentProcessName` ≠ `services.exe` (ou `wininit.exe` pour un boot très précoce). Le vrai `svchost` est toujours spawné par `services.exe` ; les imposteurs sortent du lot.
5. **Binaires renommés** : `NewProcessName` finissant par quelque chose de neutre (`update.exe`, `svc.exe`, `data.exe`) sous des chemins non standard. Couplez avec le champ `OriginalFileName` de Sysmon 1 quand disponible — c'est celui qui attrape les PsExec, Mimikatz, etc. renommés.

## Exemple de règle Sigma (office → shell)

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
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## Exemple KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`) :

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

Splunk :

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Cartographie ATT&CK

Le gros de la couverture de détection 4688 tombe sous **T1059 — Command and Scripting Interpreter** et ses sous-techniques (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). Les patterns LOLBin correspondent à **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Les chaînes Office → shell correspondent à **T1566.001 — Phishing: Spearphishing Attachment** combinées à T1059. Les détections de binaires renommés tombent sous **T1036.003 — Masquerading: Rename System Utilities**.

## Faux positifs (lisez ceci avant d'alerter)

- **Agents de mise à jour logicielle** spawnent légitimement des shells : Chocolatey, WinGet, wrappers MSI fournisseurs. Whitelistez par `SubjectUserSid` (LocalSystem) plus motifs stables de `ParentProcessName` plutôt que par comptes utilisateurs.
- **Scanners de vulnérabilités et produits EDR** génèrent des arbres de processus qui ressemblent exactement à un attaquant faisant de la reco : net.exe, whoami.exe, systeminfo.exe. Taguez les IP/hôtes scanners et excluez.
- **Boîtes Citrix / RDS multi-sessions** voient des chaînes `runas /netonly` légitimes pour l'accès cross-domain. Investiguez l'utilisateur, pas le pattern.
- **Scripts de logon** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) se déclenchent à chaque logon et apparaîtront comme une chaîne récurrente. Identifiez et baselinez avant d'alerter.

## Ce que 4688 ne dit pas

Pas de hash de fichier. Pas de `ParentCommandLine`. Pas d'`ImageLoaded` (l'injection de DLL n'est pas une création de processus). Pas de comportement réseau. Pour ceux-là il faut [Sysmon event 1](/fr/blog/sysmon-event-id-1-process-create) (le 4688 enrichi), Sysmon 7 (image load), Sysmon 3/22 (réseau/DNS) et, quand présent, les données comportementales d'un EDR. 4688 est le plancher de la visibilité processus — le minimum que chaque hôte Windows devrait avoir. Ce n'est pas un substitut à un vrai EDR + Sysmon sur les hôtes qui comptent.

## Où 4688 s'inscrit dans une timeline

Pour une chaîne typique post-exploitation sur un hôte sans Sysmon, votre timeline se lira :

1. [**4624**](/fr/blog/understanding-event-id-4624) — connexion initiale, LogonType 3 depuis une IP externe.
2. **4624** — seconde connexion, LogonType 9 (`runas /netonly`) sous le même `SubjectLogonId` — pivot de credentials.
3. **4688** — `powershell.exe -enc ...` sous cette session.
4. [**4104**](/fr/blog/powershell-4104-scriptblock) — corps de script décodé, fetchant une payload second-stage.
5. **4688** — binaire second-stage tournant depuis `%TEMP%`.
6. [**7045**](/fr/blog/service-creation-event-id-7045) — service installé pour la persistance.

Six enregistrements racontent toute l'histoire. Les PID en (3) et (5) se connectent via `ProcessId`/`NewProcessId` de 4688 — mais vérifiez par timestamp parce que Windows recycle les PID. Avec Sysmon présent, la chaîne `ProcessGuid` remplace ce match fragile.

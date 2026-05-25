---
title: "Sysmon Event ID 1 spiegato: process creation per il triage DFIR"
description: "L'evento 1 di Sysmon è il record di process creation più ricco che Windows possa produrre. Ecco cosa contiene e come triarlo velocemente."
date: "2026-05-17"
---

Sysmon è un tool Microsoft gratuito che arricchisce il [Windows Event Log](/it/blog/what-is-an-evtx-file) con telemetria che il SO di base non cattura in forma usabile. Il suo Event ID 1 — `ProcessCreate` — è il record Sysmon più citato nei playbook IR. Se devi mai estrarre un solo canale Sysmon da un host, è questo.

## Dove vive e cosa cattura

Sysmon scrive sul canale `Microsoft-Windows-Sysmon/Operational` (su disco: `Microsoft-Windows-Sysmon%4Operational.evtx`). Un record ProcessCreate contiene:

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

I campi che guidano le indagini: `CommandLine` (l'argv completo, non solo il binario), `Image` + `Hashes` (il binario esatto che è girato, hash utilizzabile in VT/Hybrid Analysis) e il set `Parent*` (il processo chiamante — critico per trovare catene di macro e LOLBin).

## Triage in tre pivot

Quando hai un file Sysmon di triage, tre query coprono la maggior parte dei casi:

1. **Parent sospetti**: filtra per `ParentImage` che finisce in `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe` o un browser, con `Image` che è una shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Un'app documento che spawna una shell è quasi sempre maliziosa.
2. **PowerShell encoded**: `Image` che finisce in `powershell.exe` e `CommandLine` che contiene `-enc`, `-encodedcommand` o `FromBase64String`. Decodifica il payload, controlla cosa fa — e cross-check il record [PowerShell 4104 scriptblock](/it/blog/powershell-4104-scriptblock) sullo stesso host per vedere cosa è effettivamente eseguito.
3. **LOLBin da posizioni strane**: binari Microsoft firmati (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) in esecuzione da `C:\Users\`, `%TEMP%` o `C:\ProgramData\`.

## Perché la catena dei parent conta

Un singolo ProcessCreate è un'istantanea; la catena è la storia. `ProcessGuid` e `ParentProcessGuid` sono GUID che Sysmon assegna per tracciare la lineage attraverso gli exit di processo — sono più affidabili dei PID perché i PID vengono riutilizzati. Ricostruisci l'albero (il `ParentProcessGuid` di ciascun record è il `ProcessGuid` di qualche altro record) e la kill-chain diventa ovvia: Outlook → Word → PowerShell → cmd → certutil → mshta.

## Esempio di regola Sigma — app Office che spawna shell

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

## Esempio KQL — PowerShell encoded con contesto parent

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` è l'equivalente Defender XDR del `ParentCommandLine` di Sysmon 1 — che il [4688](/it/blog/event-id-4688-process-creation) non fornisce.

## Esempio Splunk — LOLBin da path scrivibili dall'utente

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## Mappatura ATT&CK

- **T1059 — Command and Scripting Interpreter** e sub-techniques `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- **T1566.001 — Phishing: Spearphishing Attachment**: catene Office → shell.
- **T1218 — System Binary Proxy Execution** e sub-techniques `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- **T1036.003 — Masquerading: Rename System Utilities**: `OriginalFileName` ≠ filename di `Image`.
- **T1055 — Process Injection**: `IntegrityLevel` di Sysmon 1 e la catena dei parent aiutano a individuare parent anomali per processi come `lsass.exe` o `services.exe`.

## Falsi positivi che sembrano attacchi

- **Agenti di aggiornamento software** spawnano di routine shell sotto SYSTEM (Chocolatey, WinGet, MSI di vendor). Tagga gli host auto-update noti.
- **Vulnerability scanner** mimano alberi di processo offensivi durante scansioni autenticate. Tagga gli IP degli scanner.
- **Host multi-sessione Citrix / RDS** generano traffico denso di process-create che si sovrappone a pattern di attaccante. Filtra per range sorgente.
- **Scan Defender / EDR** eseguono binari Microsoft firmati da path inusuali durante scan on-demand.

## Caveat di copertura

Sysmon cattura solo ciò che la sua config gli dice. La config di default non logga nulla; le reference canoniche sono `sysmon-config` di SwiftOnSecurity e `sysmon-modular` di Olaf Hartong. Senza una config reale in posto, i tuoi record evento 1 saranno scarsi, il campo `CommandLine` può essere redatto e gli `Hashes` possono mancare. Leggi la config Sysmon dell'host insieme ai suoi log.

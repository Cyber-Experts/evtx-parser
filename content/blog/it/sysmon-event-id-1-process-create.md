---
title: "Sysmon Event ID 1 spiegato: creazione processo per triage DFIR"
description: "L'evento 1 di Sysmon è il record di creazione processo più ricco che Windows può produrre. Ecco cosa contiene e come fare triage velocemente."
date: "2026-05-17"
---

Sysmon è uno strumento gratuito Microsoft che aumenta il [Windows Event Log](/en/blog/what-is-an-evtx-file) con telemetria che l'OS base non cattura in forma usabile. Il suo event ID 1, `ProcessCreate`, è il record Sysmon più citato nei playbook IR. Se estraete un solo canale Sysmon da un host, è questo.

Dirò ciò che dico in ogni writeup Sysmon: un deployment senza una config vera è per lo più teatro. Leggete [sysmon-modular](https://github.com/olafhartong/sysmon-modular) o `sysmon-config` di SwiftOnSecurity prima di decidere cosa i vostri record event 1 contengono davvero.

## Dove vive e cosa cattura

Sysmon scrive a `Microsoft-Windows-Sysmon/Operational` (su disco: `Microsoft-Windows-Sysmon%4Operational.evtx`). Un record ProcessCreate contiene:

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

I campi che guidano le indagini:

- `CommandLine`. L'argv completo, non solo il binario.
- `Image` e `Hashes`. Il binario esatto che è girato, hash usabile in VirusTotal o Hybrid Analysis.
- Il set `Parent*`. Il processo chiamante. Critico per trovare catene macro e LOLBin. `ParentCommandLine` in particolare è ciò che [4688](/en/blog/event-id-4688-process-creation) non può darvi.

## Triage in tre pivot

Tre query coprono la maggior parte dei casi:

1. **Padri sospetti.** Filtrate per `ParentImage` che finisce in `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, o un browser, con `Image` che è una shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Un'app documento che spawna una shell è quasi sempre malevola.
2. **PowerShell encodato.** `Image` che finisce in `powershell.exe` e `CommandLine` che contiene `-enc`, `-encodedcommand`, o `FromBase64String`. Decodate il payload, controllate cosa fa. Cross-check lo [scriptblock PowerShell 4104](/en/blog/powershell-4104-scriptblock) sullo stesso host per vedere cosa è eseguito davvero.
3. **LOLBin da posti strani.** Binari Microsoft firmati (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) che girano da `C:\Users\`, `%TEMP%`, o `C:\ProgramData\`.

## Perché la catena padre conta

Un singolo ProcessCreate è uno snapshot. La catena è la storia. `ProcessGuid` e `ParentProcessGuid` sono GUID che Sysmon assegna per tracciare il lineage attraverso le uscite di processo. Sono più affidabili dei PID perché i PID vengono riutilizzati. Ricostruite l'albero (il `ParentProcessGuid` di ogni record è il `ProcessGuid` di qualche altro record) e la kill chain diventa ovvia: Outlook a Word a PowerShell a cmd a certutil a mshta. Leggere l'albero in ordine cronologico è di solito come un writeup si scrive da solo.

## Sigma: app Office che spawna shell

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

## KQL: PowerShell encodato con contesto padre

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` è l'equivalente Defender XDR di `ParentCommandLine` di Sysmon 1, che [4688](/en/blog/event-id-4688-process-creation) non fornisce.

## Splunk: LOLBin da path scrivibili dall'utente

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

- T1059 Command and Scripting Interpreter e sotto-tecniche `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- T1566.001 Phishing: Spearphishing Attachment. Catene Office a shell.
- T1218 System Binary Proxy Execution e sotto-tecniche `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- T1036.003 Masquerading: Rename System Utilities. `OriginalFileName` != nome del file di `Image`.
- T1055 Process Injection. L'`IntegrityLevel` e la catena padre di Sysmon 1 aiutano a individuare padri anomali per processi come `lsass.exe` o `services.exe`.

## Falsi positivi che sembrano attacchi

- Gli agenti di aggiornamento software regolarmente spawnano shell sotto SYSTEM (Chocolatey, WinGet, MSI vendor). Taggate host auto-update conosciuti.
- I vulnerability scanner imitano alberi di processo offensivi durante scan autenticati. Taggate IP scanner.
- Host Citrix e RDS multi-sessione generano traffico denso di creazione processi che si sovrappone con pattern di attaccante. Filtrate per range sorgente.
- Scan Defender o EDR eseguono binari Microsoft firmati da path inusuali durante scan on-demand.

## Caveat di copertura

Sysmon cattura solo ciò che la sua config gli dice. La config di default logga quasi niente. I riferimenti canonici sono `sysmon-config` di SwiftOnSecurity e `sysmon-modular` di Olaf Hartong. Senza una config vera in posto, i vostri record event 1 saranno scarsi, `CommandLine` può essere redatto da una regola `<CommandLine onmatch="exclude">`, e `Hashes` può mancare. Leggete la config Sysmon dell'host accanto ai suoi log. Il disallineamento tra ciò che un analista pensa che Sysmon stia loggando e ciò che logga davvero mi è costato ore più di una volta.

Quando Sysmon non è installato affatto, ripiegate su [4688](/en/blog/event-id-4688-process-creation) con auditing di command line, poi [prefetch](https://www.prefetchparser.com), [AmCache](https://www.amcacheparser.com), e l'[USN journal](https://www.usnparser.com) per evidenza di esecuzione.

## Per approfondire

- [Documentazione Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

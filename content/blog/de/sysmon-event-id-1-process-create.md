---
title: "Sysmon Event ID 1 erklärt: Prozesserstellung für DFIR-Triage"
description: "Sysmons Event 1 ist der reichste Prozesserstellungs-Record, den Windows produzieren kann. Hier ist, was darin steht und wie man es schnell triagiert."
date: "2026-05-17"
---

Sysmon ist ein kostenloses Microsoft-Tool, das das [Windows Event Log](/en/blog/what-is-an-evtx-file) mit Telemetrie ergänzt, die das Basis-OS nicht in nutzbarer Form erfasst. Sein Event ID 1, `ProcessCreate`, ist der meistzitierte Sysmon-Record in IR-Playbooks. Wenn Sie jemals nur einen Sysmon-Channel von einem Host extrahieren, ist das der.

Ich sage, was ich in jedem Sysmon-Writeup sage: ein Deployment ohne echte Config ist meistens Theater. Lesen Sie [sysmon-modular](https://github.com/olafhartong/sysmon-modular) oder SwiftOnSecurity's `sysmon-config`, bevor Sie entscheiden, was Ihre Event-1-Records tatsächlich enthalten.

## Wo es lebt und was es erfasst

Sysmon schreibt nach `Microsoft-Windows-Sysmon/Operational` (auf der Disk: `Microsoft-Windows-Sysmon%4Operational.evtx`). Ein ProcessCreate-Record enthält:

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

Die Felder, die Untersuchungen treiben:

- `CommandLine`. Die volle argv, nicht nur die Binärdatei.
- `Image` und `Hashes`. Die exakte Binärdatei, die lief, Hash verwendbar in VirusTotal oder Hybrid Analysis.
- Das `Parent*`-Set. Der aufrufende Prozess. Kritisch für das Finden von Makro- und LOLBin-Ketten. `ParentCommandLine` insbesondere ist, was [4688](/en/blog/event-id-4688-process-creation) Ihnen nicht geben kann.

## Triage in drei Pivots

Drei Queries decken die meisten Fälle ab:

1. **Verdächtige Eltern.** Filtern Sie nach `ParentImage` endend auf `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe` oder einem Browser, wobei `Image` eine Shell ist (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Eine Dokumenten-App, die eine Shell spawnt, ist fast immer bösartig.
2. **Codiertes PowerShell.** `Image` endend auf `powershell.exe` und `CommandLine` enthält `-enc`, `-encodedcommand` oder `FromBase64String`. Decodieren Sie den Payload, prüfen Sie, was er tut. Cross-checken Sie den [PowerShell 4104 Script-Block](/en/blog/powershell-4104-scriptblock) auf demselben Host, um zu sehen, was tatsächlich ausgeführt wurde.
3. **LOLBins von ungewöhnlichen Orten.** Signierte Microsoft-Binärdateien (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`), die aus `C:\Users\`, `%TEMP%` oder `C:\ProgramData\` laufen.

## Warum die Elternkette wichtig ist

Ein einzelnes ProcessCreate ist ein Snapshot. Die Kette ist die Story. `ProcessGuid` und `ParentProcessGuid` sind GUIDs, die Sysmon zuweist, um Abstammung über Prozess-Exits hinweg zu verfolgen. Sie sind zuverlässiger als PIDs, weil PIDs wiederverwendet werden. Rekonstruieren Sie den Tree (jeder Record's `ParentProcessGuid` ist die `ProcessGuid` eines anderen Records) und die Kill Chain wird offensichtlich: Outlook zu Word zu PowerShell zu cmd zu certutil zu mshta. Den Tree in chronologischer Reihenfolge zu lesen ist üblicherweise, wie sich ein Writeup selbst schreibt.

## Sigma: Office-App spawnt Shell

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

## KQL: codiertes PowerShell mit Elternkontext

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` ist das Defender XDR-Äquivalent zu Sysmon 1's `ParentCommandLine`, das [4688](/en/blog/event-id-4688-process-creation) nicht bereitstellt.

## Splunk: LOLBins aus benutzerbeschreibbaren Pfaden

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## ATT&CK-Zuordnung

- T1059 Command and Scripting Interpreter und Unter-Techniken `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- T1566.001 Phishing: Spearphishing Attachment. Office-zu-Shell-Ketten.
- T1218 System Binary Proxy Execution und Unter-Techniken `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- T1036.003 Masquerading: Rename System Utilities. `OriginalFileName` != Dateiname von `Image`.
- T1055 Process Injection. Sysmon 1's `IntegrityLevel` und Elternkette helfen, anomale Eltern für Prozesse wie `lsass.exe` oder `services.exe` zu erkennen.

## Falschpositive, die wie Angriffe aussehen

- Software-Update-Agenten spawnen routinemäßig Shells unter SYSTEM (Chocolatey, WinGet, Vendor-MSI). Taggen Sie bekannte Auto-Update-Hosts.
- Schwachstellen-Scanner imitieren offensive Prozessbäume während authentifizierter Scans. Taggen Sie Scanner-IPs.
- Citrix- und RDS-Multi-Session-Hosts erzeugen dichten Process-Create-Traffic, der sich mit Angreifermustern überschneidet. Filtern Sie nach Quellbereich.
- Defender- oder EDR-Scans laufen signierte Microsoft-Binärdateien aus ungewöhnlichen Pfaden während On-Demand-Scans.

## Coverage-Vorbehalte

Sysmon erfasst nur, was seine Config ihm sagt. Die Standard-Config loggt fast nichts. Die kanonischen Referenzen sind SwiftOnSecurity's `sysmon-config` und Olaf Hartongs `sysmon-modular`. Ohne eine echte Config an Ort und Stelle werden Ihre Event-1-Records spärlich sein, `CommandLine` kann durch eine `<CommandLine onmatch="exclude">`-Regel redaktiert sein, und `Hashes` können fehlen. Lesen Sie die Sysmon-Config des Hosts neben seinen Logs. Die Diskrepanz zwischen dem, was ein Analyst denkt, dass Sysmon loggt, und dem, was es tatsächlich loggt, hat mich schon mehr als einmal Stunden gekostet.

Wenn Sysmon überhaupt nicht installiert ist, greifen Sie zurück auf [4688](/en/blog/event-id-4688-process-creation) mit Command-Line-Auditing, dann [Prefetch](https://www.prefetchparser.com), [AmCache](https://www.amcacheparser.com) und das [USN-Journal](https://www.usnparser.com) für Ausführungsbeweise.

## Weiterführende Literatur

- [Sysmon-Dokumentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

---
title: "Sysmon-Event-ID 1 erklärt: Prozesserstellung für die DFIR-Triage"
description: "Sysmons Event 1 ist der reichhaltigste Prozesserstellungs-Datensatz, den Windows produzieren kann. Hier steht, was drin ist und wie man ihn schnell triagiert."
date: "2026-05-17"
---

Sysmon ist ein kostenloses Microsoft-Tool, das das [Windows-Event-Log](/de/blog/what-is-an-evtx-file) um Telemetrie ergänzt, die das Base-OS nicht in nutzbarer Form erfasst. Sein Event-ID 1 — `ProcessCreate` — ist der meistzitierte Sysmon-Datensatz in IR-Playbooks. Wenn du nur einen einzigen Sysmon-Kanal aus einem Host extrahierst, dann diesen.

## Wo es lebt und was es erfasst

Sysmon schreibt auf den Kanal `Microsoft-Windows-Sysmon/Operational` (auf Disk: `Microsoft-Windows-Sysmon%4Operational.evtx`). Ein ProcessCreate-Datensatz enthält:

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

Die Felder, die Untersuchungen tragen: `CommandLine` (die volle argv, nicht nur die Binary), `Image` + `Hashes` (die exakte Binary, die lief, Hash in VT/Hybrid Analysis nutzbar) und das `Parent*`-Set (der aufrufende Prozess — kritisch für Makro- und LOLBin-Ketten).

## Triage in drei Pivots

Wenn du eine Triage-Sysmon-Datei hast, decken drei Queries die meisten Fälle ab:

1. **Verdächtige Parents**: filtere auf `ParentImage`, das auf `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe` oder einen Browser endet, mit `Image` als Shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Eine Dokumenten-App, die eine Shell spawnt, ist fast immer bösartig.
2. **Encoded PowerShell**: `Image` endet auf `powershell.exe` und `CommandLine` enthält `-enc`, `-encodedcommand` oder `FromBase64String`. Dekodiere die Payload, schau, was sie tut — und quergleiche den [PowerShell-4104-Scriptblock](/de/blog/powershell-4104-scriptblock)-Datensatz auf demselben Host, um zu sehen, was tatsächlich lief.
3. **LOLBins aus ungewöhnlichen Orten**: signierte Microsoft-Binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`), die aus `C:\Users\`, `%TEMP%` oder `C:\ProgramData\` laufen.

## Warum die Parent-Kette zählt

Ein einzelner ProcessCreate ist ein Snapshot; die Kette ist die Geschichte. `ProcessGuid` und `ParentProcessGuid` sind GUIDs, die Sysmon vergibt, um Abstammung über Prozessende hinweg zu verfolgen — sie sind zuverlässiger als PIDs, weil PIDs wiederverwendet werden. Rekonstruiere den Baum (jedes `ParentProcessGuid` eines Datensatzes ist das `ProcessGuid` eines anderen) und die Kill Chain wird offensichtlich: Outlook → Word → PowerShell → cmd → certutil → mshta.

## Beispiel-Sigma-Regel — Office-App spawnt Shell

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

## Beispiel-KQL — encodierte PowerShell mit Parent-Kontext

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` ist das Defender-XDR-Äquivalent zu Sysmons `ParentCommandLine` — die [4688](/de/blog/event-id-4688-process-creation) nicht liefert.

## Beispiel-Splunk — LOLBins aus user-schreibbaren Pfaden

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## ATT&CK-Mapping

- **T1059 — Command and Scripting Interpreter** und Subtechniken `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- **T1566.001 — Phishing: Spearphishing Attachment**: Office-→-Shell-Ketten.
- **T1218 — System Binary Proxy Execution** und Subtechniken `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- **T1036.003 — Masquerading: Rename System Utilities**: `OriginalFileName` ≠ Dateiname von `Image`.
- **T1055 — Process Injection**: Sysmons `IntegrityLevel` und Parent-Kette helfen, anomale Parents für Prozesse wie `lsass.exe` oder `services.exe` zu erkennen.

## False Positives, die wie Angriffe aussehen

- **Software-Update-Agenten** spawnen routinemäßig Shells unter SYSTEM (Chocolatey, WinGet, Vendor-MSI). Markiere bekannte Auto-Update-Hosts.
- **Vulnerability-Scanner** imitieren während authentifizierter Scans offensive Prozessbäume. Markiere Scanner-IPs.
- **Citrix / RDS** Multi-Session-Hosts erzeugen dichten Process-Create-Traffic, der mit Angreifermustern überlappt. Filtere nach Source Range.
- **Defender- / EDR**-Scans laufen signierte Microsoft-Binaries aus ungewöhnlichen Pfaden während On-Demand-Scans.

## Coverage-Vorbehalte

Sysmon erfasst nur, was seine Config ihm sagt. Die Default-Config protokolliert nichts; die kanonischen Referenzen sind SwiftOnSecurity's `sysmon-config` und Olaf Hartongs `sysmon-modular`. Ohne eine echte Config im Einsatz sind deine Event-1-Datensätze spärlich, das `CommandLine`-Feld kann redacted sein und `Hashes` kann fehlen. Lies die Sysmon-Config des Hosts neben seinen Logs.

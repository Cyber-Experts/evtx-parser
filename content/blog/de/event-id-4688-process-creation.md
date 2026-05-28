---
title: "Event ID 4688 erklärt: Windows-Prozesserstellungs-Auditing für DFIR"
description: "4688 ist der Prozesserstellungs-Datensatz des Basis-OS, vorausgesetzt Command-Line-Auditing ist an. Hier ist, was drinsteht, wie er sich von Sysmon 1 unterscheidet und welche Triage-Muster sich lohnen."
date: "2026-05-24"
---

Event ID **4688**, „Ein neuer Prozess wurde erstellt", feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn ein Prozess gestartet wird. Es ist das, was das Basis-OS der Telemetrie, die [Sysmon Event 1](/de/blog/sysmon-event-id-1-process-create) liefert, am nächsten kommt, und auf Hosts ohne Sysmon ist es die einzige `CommandLine`-Quelle, die du bekommst. In einer richtig konfigurierten Umgebung ist jeder Prozess-Create einer davon. Lies es gut, und du kannst „was lief" beantworten, ohne je ein EDR zu öffnen.

## Es einschalten, weil der Default halbblind ist

Standardmäßig ist 4688 aktiviert und `CommandLine` wird **nicht** erfasst. Ohne Command-Lines sagt dir der Datensatz einen Binary-Pfad, eine PID, eine Parent-PID und nichts zu den Argumenten. Für Triage ist das fast nutzlos. `powershell.exe` ist okay. `powershell.exe -enc SQBFAFgA...` nicht.

Die Lösung ist eine Gruppenrichtlinien-Einstellung:

*Computerkonfiguration / Administrative Vorlagen / System / Audit Process Creation / Befehlszeile in Prozesserstellungs-Ereignisse einbeziehen*

Oder das Registry-Äquivalent: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Einmal gesetzt, trägt jedes 4688 das volle `CommandLine`-Feld. Der Preis ist Log-Volumen. Der Nutzen ist die gesamte Untersuchungsoberfläche, die unterhalb des Binärnamens existiert. Schalte es ein.

Du brauchst auch die zugrundeliegende Audit-Richtlinie an: `auditpol /set /subcategory:"Process Creation" /success:enable`. Viele Hosts haben die Policy an und Command-Line aus. Beides verifizieren.

## Was der Datensatz enthält

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

Die Felder, die jede Untersuchung treiben:

- `CommandLine`. Volle argv (wenn die GPO an ist).
- `NewProcessName`. Der Binary-Pfad. Kombiniert mit `CommandLine` ist das die volle Ausführung.
- `ParentProcessName`. Der aufrufende Prozess. Office zu cmd, Browser zu PowerShell, Services zu unsigned.exe sind die Lehrbuch-Ketten.
- `SubjectUserName` und `SubjectLogonId`. Wer es gestartet hat, unter welcher Sitzung. `SubjectLogonId` pivotiert zurück zum [4624](/de/blog/understanding-event-id-4624), das die Sitzung erstellt hat.
- `TokenElevationType`. `%%1936` Default (keine Elevation), `%%1937` Full (UAC-Zustimmung), `%%1938` Limited (gefiltert). Ein `1937` in einer Nicht-Admin-Sitzung ist ein Privilege-Übergang, der einen genaueren Blick wert ist.
- `MandatoryLabel`. Integritäts-Level-SID. `S-1-16-12288` ist High (elevated), `8192` Medium, `16384` System.

## 4688 gegen Sysmon 1

Sie überlappen. Sie sind nicht dasselbe.

| Feld | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Ja (wenn GPO an) | Ja |
| Image / NewProcessName | Ja | Ja |
| Parent-Image | Ja (Pfad) | Ja (Pfad + CommandLine) |
| ParentCommandLine | Nein | Ja |
| Image-Hashes (SHA/MD5/IMPHASH) | Nein | Ja |
| ProcessGuid (host-stabil) | Nein (PIDs werden wiederverwendet) | Ja |
| User-SID + Name | Ja | Ja |
| LogonId | Ja | Ja |
| CurrentDirectory | Nein | Ja |
| Integritätslevel | Ja | Ja |
| Ohne Installation verfügbar | Ja | Benötigt Sysmon |

Wenn beide vorhanden sind, ist [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) der reichere Datensatz. `ParentCommandLine`, Image-Hashes, `ProcessGuid` für stabile Parent-Child-Ketten. Wenn nur 4688 da ist, baust du Ketten mit PIDs, die Windows wiederverwendet, also kann eine lange Timeline falsche Treffer enthalten. Querprüfe Parent-Child-Links immer gegen Zeitstempel. Wenn du keins von beiden hast (kein Sysmon, kein Command-Line-Auditing), sind [AmCache](https://www.amcacheparser.com), [Prefetch](https://www.prefetchparser.com) und das [USN-Journal](https://www.usnparser.com) die nächstbesten Ausführungsbeweise.

## Die Muster, die sich lohnen

1. **Office zu Shell**. `ParentProcessName` endet mit `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` oder `mshta.exe`, mit `NewProcessName` als `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` oder `regsvr32.exe`. Dokumenten-Apps, die Shells starten, ist die klassische Makro/Phishing-Kette.
2. **Encoded PowerShell**. `NewProcessName` endet mit `powershell.exe` und `CommandLine` matcht `-enc`, `-encodedcommand`, `-e ` (Einzelbuchstabe), `frombase64string`, `iex ` oder `invoke-expression`. Dekodiere die Payload. Querprüfe den [4104-Scriptblock-Datensatz](/de/blog/powershell-4104-scriptblock) für dieselbe Sitzung.
3. **LOLBins aus benutzerbeschreibbaren Pfaden**. Signierte Microsoft-Binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`), die aus `C:\Users\`, `%TEMP%` oder `C:\ProgramData\` starten. Legitime Nutzung an diesen Orten ist selten.
4. **svchost-Waisen**. `svchost.exe` mit `ParentProcessName` außer `services.exe` (oder `wininit.exe` für sehr frühen Boot). Echtes `svchost` wird immer von `services.exe` gestartet. Hochstapler fallen auf.
5. **Umbenannte Binaries**. `NewProcessName` endet mit etwas Neutralem (`update.exe`, `svc.exe`, `data.exe`) unter nicht-standardisierten Pfaden. Paare mit Sysmon 1s `OriginalFileName`-Feld, wenn verfügbar. Das Feld erwischt umbenannte PsExec-, Mimikatz-, Impacket-Binaries, die einfache namensbasierte Erkennung umgehen.

## Sigma: Office zu Shell

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

## KQL und Splunk

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

## ATT&CK-Mapping

Die meiste 4688-Abdeckung fällt unter T1059 Command and Scripting Interpreter und seine Sub-Techniken (.001 PowerShell, .003 Windows Command Shell, .005 Visual Basic, .007 JavaScript). LOLBin-Muster mappen auf T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32). Office-zu-Shell-Ketten mappen auf T1566.001 Phishing: Spearphishing Attachment, kombiniert mit T1059. Umbenannte-Binary-Detektionen mappen auf T1036.003 Masquerading: Rename System Utilities.

## False Positives, vor dem Alarmieren lesen

- Software-Update-Agenten starten legitim Shells: Chocolatey, WinGet, Vendor-MSI-Wrapper. Whitelist per `SubjectUserSid` (LocalSystem) plus stabilen `ParentProcessName`-Mustern statt User-Accounts.
- Vulnerability Scanner und EDR-Produkte erzeugen Prozessbäume, die genau wie ein Angreifer aussehen, der Recon macht: `net.exe`, `whoami.exe`, `systeminfo.exe`. Markiere Scanner-IPs und -Hosts.
- Citrix- und RDS-Multi-Session-Kisten sehen legitime `runas /netonly`-Ketten für Cross-Domain-Zugriff. Untersuche den Benutzer, nicht das Muster.
- Logon-Skripte (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) feuern bei jedem Logon und erscheinen als wiederkehrende Kette. Baseline, bevor du alarmierst.

## Was 4688 dir nicht sagt

Keinen Datei-Hash. Keine `ParentCommandLine`. Kein `ImageLoaded` (DLL-Injection ist kein Prozess-Create). Kein Netzwerkverhalten. Dafür brauchst du [Sysmon Event 1](/de/blog/sysmon-event-id-1-process-create) (das reichere 4688), Sysmon 7 (Image Load), Sysmon 3/22 (Netzwerk/DNS) und die Verhaltens-Telemetrie eines EDR. 4688 ist der Boden der Prozess-Sichtbarkeit. Das Minimum, das jeder Windows-Host haben sollte. Kein Ersatz für ordentliches EDR plus Sysmon auf Hosts, die zählen.

## Wo 4688 in eine Timeline passt

Für eine typische Post-Exploitation-Kette auf einem Sysmon-losen Host:

1. [4624](/de/blog/understanding-event-id-4624). Erstanmeldung, LogonType 3 von einer externen IP.
2. 4624 erneut. LogonType 9 (`runas /netonly`) unter derselben `SubjectLogonId`. Credential-Pivot.
3. **4688**. `powershell.exe -enc ...` unter dieser Sitzung.
4. [4104](/de/blog/powershell-4104-scriptblock). Dekodierter Skript-Body, der ein Second-Stage-Payload holt.
5. **4688**. Second-Stage-Binary läuft aus `%TEMP%`.
6. [7045](/de/blog/service-creation-event-id-7045). Dienst zur Persistenz installiert.

Sechs Datensätze erzählen die ganze Geschichte. Die PIDs in (3) und (5) verbinden sich über 4688s `ProcessId` und `NewProcessId`, aber verifiziere per Zeitstempel, weil Windows PIDs recycelt. Mit Sysmon ersetzt die `ProcessGuid`-Kette diese fragile Übereinstimmung.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

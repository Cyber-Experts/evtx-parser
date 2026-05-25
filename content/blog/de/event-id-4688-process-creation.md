---
title: "Event-ID 4688 erklärt: Windows-Prozesserstellung für DFIR auditieren"
description: "4688 ist der Base-OS-Prozesserstellungs-Datensatz — vorausgesetzt, Command-Line-Auditing ist an. Hier steht, was drin ist, wie es sich von Sysmon 1 unterscheidet und welche Triage-Muster sich lohnen."
date: "2026-05-24"
---

Event-ID **4688** — „Ein neuer Prozess wurde erstellt" — feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn ein Prozess gestartet wird. Es ist das Nächste, was das Base-OS an die Telemetrie von [Sysmon-Event 1](/de/blog/sysmon-event-id-1-process-create) heranreicht — und auf Hosts ohne Sysmon ist es die einzige `CommandLine`-Quelle, die du bekommst. In einem ordentlich konfigurierten Estate ist jedes Process-Create einer dieser Datensätze. Lies ihn gut und du kannst „was lief" beantworten, ohne je ein EDR zu öffnen.

## Einschalten (weil der Default halbblind ist)

Per Default ist 4688 aktiviert, aber `CommandLine` wird **nicht** erfasst. Ohne `CommandLine` sagt der Datensatz dir einen Binärpfad, eine PID, eine Parent-PID — und nichts über die Argumente. Für Triage ist das fast nutzlos: `powershell.exe` ist okay; `powershell.exe -enc SQBFAFgA…` ist es nicht.

Die Lösung ist eine Group-Policy-Einstellung:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

Oder das Registry-Äquivalent: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Einmal gesetzt, trägt jedes 4688 das volle `CommandLine`-Feld. Die Kosten sind Log-Volumen; der Nutzen ist die gesamte Untersuchungsfläche unterhalb des Binärnamens. Mach es an.

Du brauchst auch die zugrundeliegende Audit-Policy: `auditpol /set /subcategory:"Process Creation" /success:enable`. Viele Hosts haben die Policy an, aber Command-Line aus — überprüfe beides.

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

Felder, die jede Untersuchung tragen:

- **`CommandLine`** — vollständige argv (wenn die GPO an ist).
- **`NewProcessName`** — der Binärpfad. Kombiniert mit `CommandLine` ist das die vollständige Ausführung.
- **`ParentProcessName`** — der aufrufende Prozess. Office → cmd, Browser → powershell, services → unsigned.exe sind die Lehrbuchketten.
- **`SubjectUserName` / `SubjectLogonId`** — wer ihn gestartet hat, unter welcher Sitzung. `SubjectLogonId` pivotiert zurück auf das [4624](/de/blog/understanding-event-id-4624), das die Sitzung erzeugte, und auf andere Datensätze derselben Sitzung.
- **`TokenElevationType`** — `%%1936` Default (keine Erhöhung), `%%1937` Full (UAC-Einwilligung erteilt), `%%1938` Limited (gefiltert). Ein `1937` in einer Nicht-Admin-Sitzung ist ein Privilege-Übergang, den man genauer ansehen sollte.
- **`MandatoryLabel`** — Integrity-Level-SID. `S-1-16-12288` ist High (elevated), `8192` ist Medium, `16384` System.

## 4688 vs. Sysmon 1

Sie überlappen; sie sind nicht identisch.

| Feld | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Ja (wenn GPO an) | Ja |
| Image / NewProcessName | Ja | Ja |
| Parent Image | Ja (Pfad) | Ja (Pfad + CommandLine) |
| ParentCommandLine | Nein | Ja |
| ImageHash (SHA/MD5/IMPHASH) | Nein | Ja |
| ProcessGuid (host-übergreifend stabil) | Nein (nur PIDs, recycelt) | Ja |
| User-SID + Name | Ja | Ja |
| Logon-ID | Ja | Ja |
| CurrentDirectory | Nein | Ja |
| Integrity Level | Ja | Ja |
| Verfügbar ohne Installation | Ja | Sysmon erforderlich |

Wenn beide vorhanden sind, ist [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) der reichere Datensatz — `ParentCommandLine`, Image-Hashes, ProcessGuid für stabile Parent-Child-Ketten. Wenn nur 4688 vorhanden ist, baust du Ketten mit PIDs (die Windows wiederverwendet), sodass eine lange Timeline falsche Matches enthalten kann; quergleiche Parent-Child-Links immer mit Zeitstempeln.

## Die Triage-Muster

In einem Korpus von 4688-Datensätzen lohnen sich diese Muster:

1. **Office → Shell**: `ParentProcessName` endet auf `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` oder `mshta.exe`, mit `NewProcessName` als `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` oder `regsvr32.exe`. Dokument-Apps, die Shells spawnen, sind die klassische Makro-/Phishing-Kette.
2. **Encoded PowerShell**: `NewProcessName` endet auf `powershell.exe` und `CommandLine` matcht `-enc`, `-encodedcommand`, `-e ` (Einzelbuchstabe), `frombase64string`, `iex ` oder `invoke-expression`. Dekodiere die Payload; quergleiche den [4104-Scriptblock-Datensatz](/de/blog/powershell-4104-scriptblock) derselben Sitzung.
3. **LOLBins aus user-schreibbaren Pfaden**: signierte Microsoft-Binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`), die aus `C:\Users\`, `%TEMP%` oder `C:\ProgramData\` starten. Legitime Nutzung dieser ist in solchen Pfaden selten.
4. **Service-Host-Waisen**: `svchost.exe` mit `ParentProcessName` ≠ `services.exe` (oder `wininit.exe` ganz früh beim Boot). Echter `svchost` wird immer von `services.exe` gespawnt; Impostor stechen hervor.
5. **Umbenannte Binaries**: `NewProcessName` endet auf etwas Neutrales (`update.exe`, `svc.exe`, `data.exe`) unter ungewöhnlichen Pfaden. Paare mit Sysmons `OriginalFileName`-Feld, falls verfügbar — das fängt umbenannten PsExec, Mimikatz usw.

## Beispiel-Sigma-Regel (Office → Shell)

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

## Beispiel-KQL / Splunk

KQL (Defender XDR / Sentinel über `SecurityEvent`):

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

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK-Mapping

Der Großteil der 4688-Detection-Abdeckung fällt unter **T1059 — Command and Scripting Interpreter** und seine Subtechniken (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). LOLBin-Muster mappen auf **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Office-→-Shell-Ketten entsprechen **T1566.001 — Phishing: Spearphishing Attachment** in Kombination mit T1059. Detektionen umbenannter Binaries fallen unter **T1036.003 — Masquerading: Rename System Utilities**.

## False Positives (lies das, bevor du alarmierst)

- **Software-Update-Agenten** spawnen legitimerweise Shells: Chocolatey, WinGet, Vendor-MSI-Wrapper. Whitelisten per `SubjectUserSid` (LocalSystem) plus stabile `ParentProcessName`-Muster statt User-Konten.
- **Vulnerability-Scanner und EDR-Produkte** erzeugen Prozessbäume, die exakt wie ein Angreifer aussehen, der Recon macht: net.exe, whoami.exe, systeminfo.exe. Markiere Scanner-IPs / -Hosts und schließe aus.
- **Citrix / RDS Multi-Session-Boxen** sehen legitime `runas /netonly`-Ketten für Cross-Domain-Zugriff. Untersuche den Benutzer, nicht das Muster.
- **Logon-Skripte** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) feuern bei jedem Logon und erscheinen als wiederkehrende Kette. Identifiziere und baseline, bevor du alarmierst.

## Was 4688 dir nicht sagt

Kein File-Hash. Keine `ParentCommandLine`. Kein `ImageLoaded` (DLL-Injection ist kein Process-Create). Kein Netzwerkverhalten. Dafür brauchst du [Sysmon-Event 1](/de/blog/sysmon-event-id-1-process-create) (das reichere 4688), Sysmon 7 (Image Load), Sysmon 3/22 (Netzwerk/DNS) und, wo vorhanden, die Verhaltensdaten eines EDR. 4688 ist die Untergrenze der Prozess-Sichtbarkeit — das Minimum, das jeder Windows-Host haben sollte. Es ist kein Ersatz für ordentliches EDR + Sysmon auf relevanten Hosts.

## Wo 4688 in eine Timeline passt

Für eine typische Post-Exploitation-Kette auf einem Sysmon-losen Host liest sich deine Timeline so:

1. [**4624**](/de/blog/understanding-event-id-4624) — initiale Anmeldung, LogonType 3 von einer externen IP.
2. **4624** — zweite Anmeldung, LogonType 9 (`runas /netonly`) unter derselben `SubjectLogonId` — Credential-Pivot.
3. **4688** — `powershell.exe -enc ...` unter dieser Sitzung.
4. [**4104**](/de/blog/powershell-4104-scriptblock) — dekodierter Script-Body, holt eine Second-Stage-Payload.
5. **4688** — Second-Stage-Binary läuft aus `%TEMP%`.
6. [**7045**](/de/blog/service-creation-event-id-7045) — Dienst zur Persistenz installiert.

Sechs Datensätze erzählen die ganze Geschichte. Die PIDs in (3) und (5) verbinden sich über die `ProcessId`/`NewProcessId` von 4688 — verifiziere aber per Zeitstempel, weil Windows PIDs recycelt. Mit Sysmon ersetzt die `ProcessGuid`-Kette diesen fragilen Match.

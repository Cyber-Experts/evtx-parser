---
title: "Event-ID 4663 erklärt: Datei- und Registry-Zugriff per SACL auditieren"
description: "4663 ist der Per-Access-Objekt-Audit-Datensatz. SACLs auf den richtigen Dateien und Schlüsseln geben ein Per-Byte-Log, wer was angefasst hat — gegen Ransomware, Exfil und Credential-Diebstahl."
date: "2026-05-24"
---

Event-ID **4663** — „Es wurde versucht, auf ein Objekt zuzugreifen" — feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn ein auditierte Datei, ein Registry-Schlüssel oder ein Kernel-Objekt so zugegriffen wird, dass es zur System Access Control List (SACL) passt. Anders als die meisten Security-Datensätze produziert 4663 von sich aus nichts — du musst die SACL am Objekt, das dich interessiert, *konfigurieren*, bevor irgendwelche 4663-Datensätze existieren. Das macht es per Default günstig und nach Tuning verheerend effektiv.

Wenn du mit 4663 nur eine Sache auditierst, audite Zugriffe auf Credential-Stores und hochwertige Daten-Shares. Das Signal-zu-Rausch-Verhältnis gehört zu den besten im gesamten Audit-Katalog.

## Wo es feuert

Immer auf dem Host, der das Objekt besitzt — der Fileserver bei einer Datei-SACL, die Workstation bei einer lokalen Registry-SACL, der DC bei einer AD-Objekt-SACL. Es gibt keinen zentralen Datensatz; wenn du estate-weite Sichtbarkeit auf einen sensiblen Share willst, musst du `Security` vom hostenden Fileserver forwarden.

## Was der Datensatz enthält

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

Die Felder:

- **`ObjectType`** — `File`, `Key` (Registry), `Process`, `Token`, `Directory`, `Section` oder jede Objektklasse, die SACLs unterstützt.
- **`ObjectName`** — der volle Pfad. Bei Dateien ein Windows-Pfad; bei Registry-Schlüsseln der volle Pfad unter `\REGISTRY\MACHINE\…` (Hinweis: nicht die `HKLM\…`-Schreibweise, die du in regedit tippen würdest).
- **`AccessList`** — was versucht wurde, als Liste dekodierter Zugriffsrecht-Namen (einer pro `%%NNNN`-Token). Die üblichen dekodierten Werte:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — die rohe Bitmaske der tatsächlich angeforderten `STANDARD_RIGHTS_*`- und objektspezifischen Rechte.
- **`ProcessName`** + **`ProcessId`** — der Prozess, der das Handle geöffnet hat. Der Pivot zu [4688](/de/blog/event-id-4688-process-creation) / [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) für den vollen Prozesskontext.
- **`SubjectLogonId`** — Pivot zu [4624](/de/blog/understanding-event-id-4624) für die ursprüngliche Sitzung, die Quell-IP bei Netzwerk-Anmeldung und den Benutzer.

## 4663 konfigurieren — der Teil, der wirklich Arbeit ist

Es gibt drei Konfigurationsebenen; fehlt eine, gibt es keine Datensätze.

1. **Audit Policy**: aktiviere *Object Access → Audit File System* und/oder *Audit Registry* für Success und/oder Failure. Entweder per Group Policy oder `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL auf dem Objekt**: Rechtsklick → Eigenschaften → Sicherheit → Erweitert → Reiter Überwachung (Windows-GUI), oder per `Set-Acl` / `icacls /audit`. Du gibst an *welches Principal* (oft `Everyone` oder `Authenticated Users`), *welche Rechte* und *ob Success, Failure oder beides* auditiert wird.
3. **Für Registry**: gleicher Flow, erreichbar über `regedit` → Schlüssel → Berechtigungen → Erweitert → Überwachung.

Ohne (1) werden die Datensätze nie geschrieben. Ohne (2) hat Windows keine Ahnung, dass du etwas auditieren willst. Ohne (3) auditierst du nur Dateien.

Die SACLs, die auf jedem Server gesetzt sein sollten:

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — lokale Credential-Stores. Audit `Everyone : ReadData : Success`. Alles außer `LocalSystem`, das diese liest, ist ein Credential-Dumping-Versuch.
- **`%TEMP%\lsass.dmp`** und jede `*.dmp` in `C:\Windows\Temp` — Prozess-Minidumps. Audit `Everyone : WriteData : Success`. Ein Prozess, der hier eine `.dmp` schreibt, ist entweder ein Crash Dump (Windows) oder ein Mimikatz-Operator (alle anderen).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** und **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — DPAPI-Masterkey-Verzeichnisse. Audit `ReadData : Success`. Wer immer diese außerhalb der eigenen Sitzung liest, stiehlt geschützte Geheimnisse.
- **`HKLM\SECURITY`** und **`HKLM\SAM`** — Registry-Äquivalente. Audit `ReadData : Success`.
- **Sensible Datei-Shares** — Finance, Legal, Payroll. Audit `WriteData + DELETE : Success`, um Ransomware-Verschlüsselungs-Sweeps und Massenlöschungen abzufangen.

## Die Triage-Muster

### 1. SAM- / SYSTEM-Hive-Read

Jedes 4663 mit `ObjectName`, das auf `\config\SAM`, `\config\SECURITY` oder `\config\SYSTEM` endet, bei dem `ProcessName` nicht `services.exe` / `lsass.exe` / `wininit.exe` und `SubjectUserSid` nicht `S-1-5-18` ist. Das ist `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy` oder irgendein Credential-Dumping-Tool mit Hive-Zugriff auf Dateiebene.

### 2. LSASS-Dump-Datei geschrieben

Ein 4663 `WriteData` für eine `.dmp`-Datei in `C:\Windows\Temp\`, `C:\ProgramData\` oder `%TEMP%`, mit `ProcessName` von `rundll32.exe`, `procdump*.exe`, `comsvcs.dll`-bezogenen Callern oder einem umbenannten Binary. Das ist das LSASS-Minidump-Muster. Quergleichen mit [4688](/de/blog/event-id-4688-process-creation) für die `CommandLine` — `comsvcs.dll MiniDump` ist die häufigste Kodierung.

### 3. Ransomware-Verschlüsselungs-Sweep

Viele 4663 mit `AccessMask` inklusive `WriteData + DELETE` gegen Dateien in einem sensiblen Share innerhalb von Sekunden, alle von derselben `SubjectLogonId` und `ProcessName`. Ein echter Backup-Prozess fasst Dateien in einem messbaren, gedrosselten Muster an; Ransomware fegt einen Verzeichnisbaum durch, so schnell die Disk es zulässt.

### 4. DPAPI-Masterkey-Diebstahl

4663 `ReadData` auf Dateien unter `\AppData\Roaming\Microsoft\Protect\<sid>\` durch jeden Prozess außerhalb der eigenen Sitzung des Benutzers. Das klassische Muster: `SubjectUserSid` ist ein *anderer* SID als der im Pfad.

### 5. Group Policy Preference Passwortdatei gelesen

4663 `ReadData` auf Dateien, die `\SYSVOL\<domain>\Policies\*\Groups.xml` (oder `Services.xml`, `Drives.xml`) matchen. Das ist der `Get-GPPPassword`-Angriff — alt, aber die SYSVOL-Dateien existieren in Legacy-Domänen oft noch.

## Beispiel-Sigma-Regel — SAM-Hive-Read

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## Beispiel-KQL — Ransomware-Verschlüsselungs-Sweep

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

100 distinkte Dateien pro Minute, geschrieben oder gelöscht unter einer Anmeldesitzung, sind ein Sweep — Punkt.

## Beispiel-Splunk — DPAPI-Masterkey-Zugriff

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK-Mapping

- **T1003.002 — OS Credential Dumping: Security Account Manager**: SAM-Hive-Reads.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: SECURITY-Hive-Reads.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: `.dmp`-Writes (kombiniert mit Prozesskontext).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**: Zugriff auf `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**: SYSVOL-`Groups.xml`-Reads.
- **T1486 — Data Encrypted for Impact**: Bulk-WriteData-+-DELETE-Muster (Ransomware).
- **T1565.001 — Stored Data Manipulation**: beliebige Datei-Writes in überwachte Daten-Shares.

## Volumen-Management — die SACL-Falle

Naiv `Everyone : All access : Success+Failure` auf ein viel genutztes Verzeichnis zu setzen produziert hunderttausende 4663-Datensätze pro Minute und begräbt deine Sammlung. SACLs sind Präzisionsinstrumente. Audite:

- **Nur die Zugriffsarten, die dich interessieren** (`ReadData` für Credential-Stores; `WriteData + DELETE` für Daten-Shares; selten beides).
- **Nur Success** — Failures sind seltener und selten interessant.
- **Spezifische Dateien**, nicht ganze Laufwerke. Die SAM-Datei, nicht ganz `C:\Windows\System32\config\`. Den HR-Share, nicht ganz `D:\`.
- **Spezifische Principals**, wo möglich — für SAM-Klassen-Objekte ist `Everyone` okay, weil legitime Zugriffe sowieso über `LocalSystem` laufen; für geteilte Daten audite nur die Principals, die die Daten tatsächlich anfassen.

Eine gut getunte SACL auf fünf hochwertigen Objekten produziert 50-200 Datensätze pro Tag pro Host — vollkommen handhabbar.

## False Positives, die genau wie Angriffe aussehen

- **Volume Shadow Copy** (VSS) Backups erzeugen während eines Backup-Fensters dichten 4663-Traffic. Markiere die `ProcessName` des Backup-Orchestrators.
- **Antivirus-On-Access-Scans** öffnen jede Datei in einem Zielverzeichnis; AV-Produkt-Service-Konten dominieren jede naive 4663-Regel. Per SID whitelisten.
- **Indexierungsdienste** (Windows Search, Spotlight-artig) treffen Metadaten über `ReadAttributes` — meist per `AccessList` filterbar.
- **Backup-staged Restores** sehen aus wie Ransomware-Writes (viele Dateien, ein Prozess, in einem Verzeichnis), aber der Prozess ist dein Backup-Agent.
- **Defender-Echtzeit-Scanning** liest alles; wenn du zu breit auditierst, ist es die dominierende Rauschquelle.

## Was 4663 dir nicht sagt

- **Inhalt des Zugriffs**: du siehst, dass eine Datei gelesen/geschrieben wurde, nicht was gelesen/geschrieben wurde. Für letzteres brauchst du ein EDR oder FIM-Produkt (File Integrity Monitoring).
- **Warum der Zugriff passierte**: nur das Syscall-Ergebnis. Um auf User-Intent zu korrelieren, paare mit [4688](/de/blog/event-id-4688-process-creation) / [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) für den vollen Kontext des aufrufenden Prozesses.
- **Geschlossene Handles**: 4663 feuert beim Handle-*Open*. Close-Events sind 4658, selten für Angriffserkennung nützlich.
- **Netzwerk-Pfade transparent**: SMB-Zugriff auf einen Share feuert 4663 auf dem *Server*; der Client sieht nichts. Du brauchst serverseitige Sammlung.
- **Fehlgeschlagene Zugriffe per Default**: viele Shops auditieren nur `Success`; konfiguriere `Failure` nur, wenn dich vereitelte Zugriffsversuche wirklich interessieren.

## Wo 4663 in eine Timeline passt

Klassische LSASS-Credential-Dump-Kette:

1. [**4624**](/de/blog/understanding-event-id-4624) — Admin-Anmeldung (LogonType 3 oder 10).
2. [**4672**](/de/blog/event-id-4672-special-privileges) — SeDebugPrivilege mit der Sitzung gewährt.
3. [**4688**](/de/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` auf `C:\Windows\Temp\lsass.dmp` durch `rundll32.exe`. **Forensisches Gold — Beweis für Exfil-Staging.**
5. [**4688**](/de/blog/event-id-4688-process-creation) — Datei-Move / Archivierung (der Operator extrahiert den Dump).
6. [**1102**](/de/blog/event-id-1102-cleared-log) — Security-Log gelöscht (manche Operatoren tun das; viele vergessen es).

Das 4663 in Schritt 4 ist das günstigste, spezifischste Signal in der Kette — es identifiziert das Credential-Theft-Artefakt direkt namentlich, auf der Disk, mit angehängtem aufrufendem Prozess. SAM-Hive-Reads, DPAPI-Masterkey-Zugriff und SYSVOL-Groups.xml-Reads funktionieren genauso.

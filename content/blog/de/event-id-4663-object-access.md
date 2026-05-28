---
title: "Event ID 4663 erklärt: Datei- und Registry-Zugriffsauditing mit SACLs"
description: "4663 ist der Objekt-Audit-Datensatz pro Zugriff. Konfiguriere SACLs auf den richtigen Dateien und Schlüsseln, und du bekommst ein Byte-genaues Log darüber, wer was berührt hat. Nützlich für Ransomware, Exfil und Credential-Store-Diebstahl."
date: "2026-05-24"
---

Event ID **4663**, „Es wurde versucht, auf ein Objekt zuzugreifen", feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn eine auditierte Datei, ein Registry-Schlüssel oder Kernel-Objekt auf eine Weise berührt wird, die seiner System Access Control List entspricht. Anders als die meisten Security-Datensätze produziert 4663 standardmäßig nichts. Du musst die SACL auf dem Objekt zuerst *konfigurieren*. Deshalb haben die meisten Umgebungen sie nicht. Deshalb haben auch die, die sie haben, bei einer kleinen Menge von Techniken einen fast unfairen Erkennungsvorteil.

Wenn du 4663 auf genau fünf Dingen instrumentierst und den Rest ignorierst, fängst du Credential-Dump-Staging, Ransomware-Sweeps und DPAPI-Diebstahl billiger ab, als jedes EDR es kann.

## Wo es feuert

Auf dem Host, dem das Objekt gehört. Datei-SACLs feuern auf dem Fileserver. Lokale Registry-SACLs feuern auf der Workstation. AD-Objekt-SACLs feuern auf dem DC. Es gibt keinen zentralen Datensatz. Um umgebungsweite Sichtbarkeit auf einen sensiblen Share zu bekommen, musst du Security vom Fileserver, der ihn hostet, weiterleiten. Das erwischt die Leute ständig kalt.

## Die Datensatzfelder

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

Die, die zählen:

- `ObjectType`. `File`, `Key` (Registry), `Process`, `Token`, `Directory`, `Section`. Jede Objektklasse, die SACLs unterstützt.
- `ObjectName`. Vollständiger Pfad. Für Dateien ein Windows-Pfad. Für Registry-Schlüssel der vollständige Pfad unter `\REGISTRY\MACHINE\...` (nicht das `HKLM\...`, das du in regedit tippen würdest).
- `AccessList`. Was versucht wurde, als dekodierte Access-Right-Tokens. Die häufigen:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Rohe Bitmaske von `STANDARD_RIGHTS_*` und objektspezifischen Rechten, die tatsächlich angefordert wurden.
- `ProcessName` und `ProcessId`. Der Prozess, der den Handle geöffnet hat. Pivotiere zu [4688](/de/blog/event-id-4688-process-creation) oder [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) für den vollen Prozesskontext.
- `SubjectLogonId`. Pivotiere zu [4624](/de/blog/understanding-event-id-4624) für die ursprüngliche Sitzung, die Quell-IP bei Netzwerk-Logon und den Benutzer.

## 4663 einzuschalten sind drei Schritte und die Leute überspringen einen

1. **Audit-Richtlinie**. Aktiviere *Objekt-Zugriff*-Unter-Richtlinien für Dateisystem und/oder Registry, Erfolg und/oder Fehlschlag. Gruppenrichtlinie oder `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL auf dem Objekt**. Eigenschaften, Sicherheit-Tab, Erweitert, Überwachungs-Tab in der GUI. Oder `Set-Acl`, `icacls /audit`. Du gibst an, welcher Principal, welche Rechte und ob Success, Failure oder beides auditiert werden soll.
3. **Für Registry**, derselbe Flow über die Berechtigungen des regedit-Schlüssels, Erweitert, Überwachung.

Ohne (1) schreiben die Datensätze nie. Ohne (2) hat Windows keine Ahnung, dass du etwas auditieren wolltest. Ohne (3) auditierst du nur Dateien. Die Leute überspringen meistens (2), weil sich Schritt (1) anfühlt, als müsste er reichen. Tut er nicht.

Die SACLs, die sich auf jedem Server lohnen:

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Auditiere `Jeder : ReadData : Success`. Alles, was diese außer `LocalSystem` liest, ist Credential Dumping.
- `*.dmp`-Dateien in `C:\Windows\Temp` und `%TEMP%`. Auditiere `Jeder : WriteData : Success`. Ein Prozess, der hier eine `.dmp` schreibt, ist entweder Windows nach einem Absturz oder ein Mimikatz-Operator.
- `C:\ProgramData\Microsoft\Crypto\RSA` und `C:\Users\*\AppData\Roaming\Microsoft\Protect`. DPAPI-Master-Key-Verzeichnisse. Auditiere `ReadData : Success`. Alles, was diese außerhalb der eigenen Sitzung des Benutzers liest, stiehlt Geheimnisse.
- `HKLM\SECURITY` und `HKLM\SAM`. Registry-Äquivalente. Gleicher Audit.
- Sensible Dateifreigaben: Finanzen, Recht, Personal. Auditiere `WriteData + DELETE : Success`, um Ransomware-Sweeps und Massenlöschungen zu fangen.

## Die Muster, die du tatsächlich fängst

### Lesen des SAM- oder SYSTEM-Hives

Jedes 4663 mit `ObjectName`, der mit `\config\SAM`, `\config\SECURITY` oder `\config\SYSTEM` endet, wo `ProcessName` nicht `services.exe`, `lsass.exe` oder `wininit.exe` ist und `SubjectUserSid` nicht `S-1-5-18` ist. Das ist `reg save HKLM\SAM`, `esentutl /y` gegen eine Shadow Copy oder jedes Credential-Dumping-Tool mit dateiebenem Hive-Zugriff. Vergleiche mit der [Registry](https://www.registryparser.com) für etwaige hinterlassene Backup-Hive-Dateien.

### LSASS-Minidump geschrieben

Ein 4663 `WriteData` für eine `.dmp`-Datei in `C:\Windows\Temp\`, `C:\ProgramData\` oder `%TEMP%`, mit `ProcessName` von `rundll32.exe`, `procdump*.exe` oder allem, was `comsvcs.dll` aufruft. Lehrbuch ist `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Vergleiche [4688](/de/blog/event-id-4688-process-creation) für die `CommandLine`. Das 4663 fängt das, auch wenn das EDR geschlafen hat.

### Ransomware-Verschlüsselungs-Sweep

Viele 4663 mit `AccessMask` einschließlich `WriteData + DELETE` gegen Dateien in einem sensiblen Share innerhalb von Sekunden, alle vom selben `SubjectLogonId` und `ProcessName`. Ein echter Backup-Prozess berührt Dateien in einem gedrosselten, messbaren Muster. Ransomware sweept einen Verzeichnisbaum so schnell, wie es die Festplatte erlaubt. Die Form verrät es.

### DPAPI-Master-Key-Diebstahl

4663 `ReadData` auf Dateien unter `\AppData\Roaming\Microsoft\Protect\<sid>\` durch irgendeinen Prozess außer der eigenen Sitzung des Benutzers. Das tote Zeichen ist, dass `SubjectUserSid` eine *andere* SID ist als die im Pfad eingebettete.

### Lesen der Group-Policy-Preferences-Passwortdatei

4663 `ReadData` auf Dateien, die zu `\SYSVOL\<domain>\Policies\*\Groups.xml` oder `Services.xml`, `Drives.xml`, `ScheduledTasks.xml` passen. Das ist `Get-GPPPassword`. Die Technik ist alt. Die SYSVOL-Dateien existieren oft noch in Legacy-Domänen, und du wärst überrascht, wie oft jemand den obfuskierten AES-Key von MSDN pickt und mit einer Domain-Credential davonläuft.

## Sigma: SAM-Hive lesen

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

## KQL: Ransomware-Verschlüsselungs-Sweep

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

100 distinkte beschriebene oder gelöschte Dateien pro Minute unter einer Logon-Session ist ein Sweep. Punkt.

## Splunk: DPAPI-Master-Key-Zugriff

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK-Mapping

- T1003.002 OS Credential Dumping: Security Account Manager. SAM-Hive-Lesevorgänge.
- T1003.004 LSA Secrets. SECURITY-Hive-Lesevorgänge.
- T1003.001 LSASS Memory. `.dmp`-Schreibvorgänge (kombiniert mit Prozesskontext).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Zugriff auf `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. SYSVOL `Groups.xml`-Lesevorgänge.
- T1486 Data Encrypted for Impact. Massen-`WriteData + DELETE`-Muster.
- T1565.001 Stored Data Manipulation. Beliebige Schreibvorgänge auf überwachte Daten-Shares.

## Die SACL-Volumen-Falle

`Jeder : Voller Zugriff : Success+Failure` auf einem stark genutzten Verzeichnis zu setzen, produziert hunderttausende 4663 pro Minute und begräbt die Sammlung. SACLs sind Präzisionsinstrumente. Auditiere:

- Nur die Zugriffstypen, die dich interessieren. ReadData für Credential-Stores. WriteData + DELETE für Daten-Shares. Selten beides gleichzeitig.
- Nur Success. Failures sind seltener und in diesem Korpus selten interessant.
- Spezifische Dateien, nicht ganze Laufwerke. Die SAM-Datei, nicht ganz `C:\Windows\System32\config\`. Der HR-Share, nicht ganz `D:\`.
- Spezifische Principals, wenn du kannst. Für SAM-Klasse-Objekte ist `Jeder` in Ordnung, weil legitimer Zugriff sowieso durch `LocalSystem` erfolgt. Für gemeinsame Daten auditiere nur die Principals, die die Daten tatsächlich berühren.

Eine gut abgestimmte SACL auf fünf hochwertige Objekte produziert 50 bis 200 Datensätze pro Tag pro Host. Vollständig handhabbar.

## False Positives, die identisch zu Angriffen aussehen

- Volume-Shadow-Copy-Backups erzeugen während eines Backup-Fensters dichten 4663-Verkehr. Markiere den `ProcessName` des Backup-Orchestrators.
- Antiviren-On-Access-Scans öffnen jede Datei in einem Zielverzeichnis. Die Dienstkonten des AV-Produkts dominieren jede naive 4663-Regel. Whitelist per SID.
- Indizierungsdienste (Windows Search) treffen Metadaten über `ReadAttributes`. Üblicherweise per `AccessList` filterbar.
- Backup-gestaged Restores sehen aus wie Ransomware-Schreibvorgänge (viele Dateien, ein Prozess, in einem Verzeichnis). Der Prozess sagt dir den Unterschied.
- Defender-Echtzeit-Scanning liest alles. Wenn du zu breit auditierst, dominiert es das Rauschen.

## Was 4663 dir nicht sagt

- Den Inhalt des Zugriffs. Du siehst, dass eine Datei gelesen oder geschrieben wurde, nicht was gelesen oder geschrieben wurde. Dafür EDR oder FIM.
- Warum der Zugriff passierte. Um es mit Nutzerabsicht zu korrelieren, paare mit [4688](/de/blog/event-id-4688-process-creation) oder [Sysmon 1](/de/blog/sysmon-event-id-1-process-create) für den vollen Kontext des aufrufenden Prozesses.
- Geschlossene Handles. 4663 feuert beim *Öffnen* des Handles. Close-Events sind 4658, selten nützlich für Angriffserkennung.
- Netzwerkpfade transparent. SMB-Zugriff auf einen Share feuert 4663 auf dem *Server*. Der Client sieht nichts. Du brauchst serverseitige Sammlung.
- Fehlgeschlagenen Zugriff standardmäßig. Viele Shops auditieren nur Success. Konfiguriere Failure nur, wenn dich vereitelte Versuche wirklich interessieren.

## Wo 4663 in eine Timeline passt

Klassische LSASS-Credential-Dump-Kette:

1. [4624](/de/blog/understanding-event-id-4624). Admin-Logon, LogonType 3 oder 10.
2. [4672](/de/blog/event-id-4672-special-privileges). SeDebugPrivilege mit der Sitzung gewährt.
3. [4688](/de/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` auf `C:\Windows\Temp\lsass.dmp` durch `rundll32.exe`. Forensisches Gold. Beweis für gestagete Exfiltration.
5. [4688](/de/blog/event-id-4688-process-creation). Dateiverschiebung oder Archiv (Operator extrahiert den Dump).
6. [1102](/de/blog/event-id-1102-cleared-log). Security-Log geleert. Manche Operatoren tun das. Viele vergessen es.

Schritt 4 ist das billigste, spezifischste Signal in der Kette. Es identifiziert das Credential-Theft-Artefakt direkt per Name, auf der Festplatte, mit angehängtem aufrufenden Prozess. SAM-Hive-Lesevorgänge, DPAPI-Master-Key-Zugriff und SYSVOL-Groups.xml-Lesevorgänge funktionieren genauso.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)

---
title: "Event-ID 1102 erklärt: Sicherheits-Audit-Log gelöscht (und was übrig bleibt)"
description: "1102 ist das eine Event, das man nicht unterdrücken kann, ohne mehr Beweise zu hinterlassen. Hier steht, was es dir sagt und was den Clear überlebt."
date: "2026-05-17"
---

Event-ID **1102** ist der Datensatz, den Windows in den [`Security`-Kanal](/de/blog/what-is-an-evtx-file) schreibt, wenn das Audit-Log gelöscht wird. Es ist — by design — einer der für Angreifer am schwersten zu unterdrückenden Datensätze, weil das Unterdrücken entweder erfordert, den EventLog-Dienst vor dem Boot erfolgreich zu ersetzen, oder zu akzeptieren, dass das Löschen selbst ein eigenes 1102 hinterlässt.

Für Defender heißt das: Wenn du 1102 siehst, hat jemand mit ausreichender Berechtigung den Audit-Trail vorsätzlich gewischt. Das ist fast nie eine normale Admin-Aktion.

## Was im Datensatz steht

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Beachte den `UserData`-Block statt dem üblichen `EventData` — 1102 ist einer der Datensätze, die ein strukturiertes User-Data-Schema verwenden. Die Felder sagen dir, *wer* das Log unter welcher Anmeldesitzung gelöscht hat. Pivotiere über `SubjectLogonId`, um das passende [4624](/de/blog/understanding-event-id-4624) zu finden, und du erhältst die Quell-IP und den Anmeldetyp, der die privilegierte Sitzung erzeugt hat.

## Was zusammen mit 1102 auch feuert

Ein Log-Clear ist selten die *einzige* anti-forensische Aktion. Häufige Begleiter, grob chronologisch:

- **104** auf dem `System`-Kanal — gleicher Akt, vom SCM aufgezeichnet. Wenn 104 vorhanden ist, aber 1102 fehlt, hat der Angreifer nur das Security-Log gelöscht und System vergessen.
- **4719** — „Systemauditrichtlinie wurde geändert". Manchmal reduziert ein Angreifer die Audit-Abdeckung *vor* dem Clear, um in der nächsten Runde weniger Datensätze zu hinterlassen.
- **4616** — „Die Systemzeit wurde geändert". Ein Time-Skew vor dem Clear erschwert die Timeline-Rekonstruktion.
- **Eine Lücke in 4624s** für eine bis zwei Stunden vor 1102 — der Angreifer hat möglicherweise einen nicht protokollierten Seitenkanal verwendet.

## Was einen Clear überlebt

Das Leeren des In-Memory-Eventlogs berührt nicht:

- **Andere Kanäle**: `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, weitergeleitete Kanäle — keiner davon wird durch einen Security-Wipe gelöscht.
- **Weitergeleitete Events**: wenn Windows Event Forwarding (WEF) zu einem zentralen Kollektor konfiguriert ist, sind die gelöschten Datensätze bereits auf einem anderen Host.
- **Die On-Disk-Datei selbst**: eine gelöschte `Security.evtx` wird durch eine neue Datei ersetzt; die Cluster der *gelöschten* Vordatei bleiben oft im unallokierten Bereich erhalten und können mit NTFS-Tooling gecarved werden.
- **USN-Journal-Einträge** für die Dateiersetzung: selbst die Clear-Operation hinterlässt Artefakte auf Dateisystem-Ebene.

Ein „erfolgreicher" Log-Clear ist selten so sauber, wie der Angreifer hofft.

## Beispiel-Sigma-Regel — Log gelöscht

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

Wenn du 1102 außerhalb eines genehmigten Wartungsfensters siehst, behandle es als Incident — Punkt.

## Beispiel-KQL — Log-Clear + privilegierte Sitzung korrelieren

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Jedes 1102 führt zurück auf ein [4672](/de/blog/event-id-4672-special-privileges), das `SeSecurityPrivilege` gewährt — das wiederum auf ein [4624](/de/blog/understanding-event-id-4624). Der Join vervollständigt das Bild.

## Beispiel-Splunk — Begleitkette der Anti-Forensik

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Eine `LogonId`, die Audit-Policy (4719) oder Systemzeit (4616) angefasst und dann ein Log gelöscht hat (1102/104), ist die Tampering-Kette.

## ATT&CK-Mapping

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**: die Schlagzeilentechnik. 1102 *ist* der primäre Indikator dieser Technik.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: 4719 (Audit-Policy geändert) vor 1102 mappt hierauf.
- **T1070.006 — Indicator Removal: Timestomp**: gepaart mit 4616 (Systemzeit geändert) in derselben Kette.
- **T1078.003 — Valid Accounts: Local Accounts**: 1102 durch einen lokalen Administrator, der zu dieser Zeit nicht hätte angemeldet sein dürfen.

## False Positives — selten, aber real

- **Migration / Decom-Workflows**: Techniker, die das Log auf einem außer Betrieb gehenden Host löschen. Sollte immer geticketet sein.
- **Forensik- / Test-Labore**: Clear-and-Reproduce-Workflows während der Detection-Entwicklung.
- **Einige Legacy-Tools** löschen das Log, um Baselines zurückzusetzen — fast immer ein Prozessfehler, aber ein realer.

Das Signal ist so direkt anti-forensisch, dass selbst legitime 1102s im Nachgang untersucht und dokumentiert werden sollten. Es gibt keinen „sicheren" Grund für ein 1102 im normalen Betrieb.

## Warum das fürs Parsen wichtig ist

Wenn du [eine .evtx-Datei in ein forensisches Tool lädst](/de/blog/how-to-open-an-evtx-file), ist die *erste* Suche, die sich lohnt, `EventID:1102` und `EventID:104`. Wenn eines davon vorhanden ist, hat das Log, das du in den Händen hältst, bekannte Lücken, und jede Timeline, die du daraus baust, ist unvollständig. Vermerke es deutlich im Bericht.

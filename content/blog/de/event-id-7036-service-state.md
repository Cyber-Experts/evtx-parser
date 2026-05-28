---
title: "Event ID 7036 erklärt: Dienstzustandsänderungen für die DFIR-Triage"
description: "7036 feuert jedes Mal, wenn ein Dienst startet oder stoppt. Gepaart mit 7045 bestätigt es, ob die Persistenz tatsächlich gelaufen ist. Allein offenbart es Dienstmissbrauch, Defense Evasion und Boot-Anomalien."
date: "2026-05-24"
---

Event ID **7036**, „Der Dienst {service} ist in den Status {state} übergegangen", feuert auf dem [`System`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn der Service Control Manager einen Dienstwechsel sieht. Jeder Start, Stop, Pause und Resume produziert eins. Allein ist es volumenstark und leicht abzutun. Gepaart mit [7045](/de/blog/service-creation-event-id-7045) ist es der Unterschied zwischen „eine Backdoor wurde installiert" und „eine Backdoor wurde installiert und lief".

Für Incident Response ist das der billigste „lief es?"-Datensatz, den das OS dir gibt.

## Wo es lebt

`System`-Kanal auf dem Host, auf dem der Dienst lief. Keine DC-Beteiligung, kein Per-Kanal-Forwarding zur Sorge. Es ist direkt da in `System.evtx`. Provider: `Service Control Manager`.

## Was der Datensatz enthält

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

Das war's. Zwei Parameter und ein binäres Tag. Viel kleiner als die meisten Security-Datensätze, weshalb Analysten ihn überspringen.

- `param1`. Der *Anzeigename* des Dienstes (nicht der Kurzname). `Background Intelligent Transfer Service` hier ist der benutzerseitige Name für `BITS`. Um zur Dienstdefinition zu pivotieren, brauchst du normalerweise den Kurznamen. Der SCM stempelt das in `Binary` als UTF-16-Blob (`42 00 49 00 54 00 53 00` dekodiert zu `BITS`).
- `param2`. Der neue Zustand: `running`, `stopped`, `paused`, `resumed` oder ausstehende Zwischenzustände (`start pending`, `stop pending`). `running` und `stopped` sind das, worauf die meisten Regeln abzielen.

Es gibt keinen `AccountName`, keinen `ImagePath`, keine `ProcessId`. 7036 sagt dir *was* den Zustand gewechselt hat, nicht *wer* es ausgelöst hat. Um das Warum zu bekommen, paare mit anderen Datensätzen.

## 7036, 7045, 7035, 7034: was ist was

Vier dienstbezogene System-Kanal-Ereignisse werden ständig verwechselt:

| Event | Wann | Was es dir gibt |
|---|---|---|
| **7045** | Dienst installiert | Anzeigename, Kurzname, `ImagePath`, `AccountName`, `StartType`. Der Persistenzpunkt. |
| **7036** | Dienststart/-stop | Nur Anzeigename. Der Ausführungspunkt. |
| **7035** | Dienst-Control gesendet | Wer Start/Stop initiiert hat (SID), welche Control gesendet wurde. Selten standardmäßig an. |
| **7034** | Dienst unerwartet abgestürzt | Dienst ohne sauberen Stop beendet. |

Das Muster zählt: ein 7045, gefolgt Sekunden später von einem 7036 `running` für denselben Anzeigenamen, ist die Lehrbuch-„installiert und lief"-Sequenz. Ein 7045 ohne passendes 7036 bedeutet, dass der Dienst registriert, aber nie ausgeführt wurde: entweder hat der Angreifer aufgeräumt, der Installer abgebrochen oder der Start wurde verzögert.

## Die Triage-Muster

### Persistenz-Verifizierung: mit 7045 paaren

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Drei Datensätze, ein PsExec-Lateral-Execution-Ereignis. Das 7036-Paar sagt dir, dass der Dienst tatsächlich lief (nicht nur installiert wurde). Für eine *persistente* Backdoor kann das zweite 7036 (stopped) fehlen oder Stunden später erscheinen, wenn der Host neu startet.

Ein 7045 ohne 7036 `running` innerhalb von Minuten ist eine eigene Anomalie. Untersuche, warum die Installation nicht feuerte. Häufige Gründe: gestaged für den nächsten Reboot, auf manuellen Start gesetzt und der Angreifer hatte es noch nicht ausgelöst, Start fehlgeschlagen (sieh nach 7034- / 7000-Fehlern).

### Defense Evasion: Sicherheitsdienste stoppen

Das meistmissbrauchte Muster. Ein Angreifer stoppt `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` oder den Dienst eines EDR-Produkts. Jeder erzeugt ein 7036 `stopped` für den entsprechenden Anzeigenamen. Wenn Audit-Richtlinien- oder Defender-Manipulation versucht wird, ist das einer der Datensätze, die überleben.

Namen, die einen Alarm wert sind (Anzeigenamen; variieren je nach Defender- oder EDR-Version):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Alles, das `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*` matcht

Ein 7036 `stopped` für irgendeinen davon, besonders außerhalb eines geplanten Wartungsfensters, sollte ein harter Alarm sein. Viele Angreifer nutzen `sc stop`, `net stop`, `Stop-Service` oder `taskkill /im`. Alle vier produzieren ein 7036.

### Service-Name-Typosquatting

7036 feuert für den Anzeigenamen, auch wenn der zugrundeliegende Dienst bösartig ist. Achte auf Anzeigenamen, die legitim aussehen, aber keinem installierten Microsoft-Dienst entsprechen: `Windows Update Service` (echter Name ist `Windows Update`), `Windows Defender Service` (echter Name ist `Windows Defender Antivirus Service`), `Microsoft Telemetry` (kein solcher Dienst). Baseline Anzeigenamen von einem bekannt-guten Host und diff.

### Boot-Anomalien

Nach einem Reboot bringt der SCM Auto-Start-Dienste in einer grob stabilen Reihenfolge hoch. Ein neuer Auto-Start-Dienst, der in der Boot-7036-Sequenz auftaucht, besonders einer, der im vorherigen Boot nicht da war, ist ein neuer Persistenzpunkt. Querverweise mit dem passenden 7045 am oder vor dem vorherigen Shutdown.

## Sigma: Sicherheitsdienst gestoppt

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL: 7045-zu-7036-Sequenz

Der Schlagzeilen-Pivot. Persistenz-Installation gefolgt von Ausführung innerhalb von 5 Minuten auf demselben Host:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

`DisplayName` von 7036 ist nicht immer wörtlich gleich `ServiceName` von 7045 (einer ist Display, einer ist short). Matche heuristisch oder berechne eine Map für die kleine Menge an Diensten, die zählen, vor.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK-Mapping

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` für Sicherheitsdienste.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` gepaart mit 7045 für denselben Dienst.
- T1569.002 System Services: Service Execution. 7036 `running` für einen `ImagePath`, der auf ein nicht-standardmäßiges Binary zeigt, oft Teil von Lateral Movement (PsExec, SCM-basierte Remote-Ausführung, Impacket `psexec.py`).
- T1489 Service Stop. Auf Verfügbarkeit abzielend (Ransomware, die SQL Server vor dem Verschlüsseln von Datenbanken stoppt).

## False Positives, die genau wie Angriffe aussehen

- Windows Update startet ein Dutzend Dienste in einer vorhersehbaren Sequenz neu. Wiederkehrend und schnell.
- Defender-Signatur-Updates starten manchmal `WinDefend` selbst neu. Ein `stopped`, das schnell von `running` aus `MsSecFlt.exe` gefolgt wird, ist das normale Muster. Das bösartige ist *kein* `running` nach dem `stopped`.
- EDR-Upgrades stoppen und starten den EDR-Dienst neu. Markiere die Upgrade-Fenster des Anbieters.
- System-Sleep und Hibernate erzeugen Stapel von `stopped` beim Schlafen und `running` beim Aufwachen. Alarmiere darauf nicht isoliert.
- Container- und Hyper-V-Workloads bringen Dienste ständig hoch und runter.

## Was 7036 dir nicht sagt

- Kein `AccountName`. Hol das aus dem passenden 7045 oder aus der SCM-Datenbank.
- Keine PID. Du kannst ein 7036 nicht direkt auf einen [4688](/de/blog/event-id-4688-process-creation)- oder [Sysmon-1](/de/blog/sysmon-event-id-1-process-create)-Datensatz mappen, ohne nach `ImagePath` und Zeitstempel zu korrelieren. Der [Prefetch](https://www.prefetchparser.com)-Cache ist die sekundäre Bestätigung, wenn 4688 aus war.
- Kein Initiator. Du siehst nicht, wer Stop-Service aufgerufen hat. Dafür brauchst du 7035 (oft standardmäßig deaktiviert), [4688](/de/blog/event-id-4688-process-creation) für das aufrufende `net stop` / `sc stop` / `taskkill` oder [4104](/de/blog/powershell-4104-scriptblock) für `Stop-Service`.
- Dienst-Kurzname-Mapping. Anzeigename ist in `param1`. Kurzname ist im Binär-Blob und muss dekodiert werden. Die meisten Parser tun das automatisch. Wenn du rohes `EventData` abfragst, musst du es selbst handhaben.

## Wo 7036 in eine Timeline passt

Lateral Execution plus Defense Evasion:

1. [4624](/de/blog/understanding-event-id-4624). LogonType 3 von einem angreifer-kontrollierten Host, AuthenticationPackage Kerberos.
2. [4688](/de/blog/event-id-4688-process-creation). `services.exe`, das ein Child für SCM-Operationen startet (oder PsExecs `psexesvc.exe`).
3. [7045](/de/blog/service-creation-event-id-7045). Dienst installiert, `ImagePath` außerhalb der Standard-Installationspfade.
4. **7036 `running`**. Die Installation hat tatsächlich gefeuert. Ausführungsbestätigung.
5. **7036 `stopped`** für `WinDefend` oder EDR. Defense Evasion, bevor das Payload läuft.
6. [4688](/de/blog/event-id-4688-process-creation). Payload-Prozess unter dem Dienstkonto.
7. **7036 `stopped`** für den Installer-Dienst. Cleanup.

7036 erscheint in den Schritten 4, 5 und 7. Drei verschiedene Phasen derselben Intrusion. Allein ist es schwer zu nutzen. Im Kontext bindet es den Persistenz-Datensatz (7045) an die tatsächliche Ausführung und an die umliegenden Defense-Evasion-Aktionen.

## Weiterführende Lektüre

- [Microsoft-Dokumentation: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

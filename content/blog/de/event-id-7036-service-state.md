---
title: "Event-ID 7036 erklärt: Dienst-Zustandswechsel für die DFIR-Triage"
description: "7036 feuert bei jedem Start oder Stopp eines Dienstes. Mit 7045 gepaart bestätigt es, ob Persistenz tatsächlich lief — und allein deckt es Dienstmissbrauch, Defense Evasion und Boot-Anomalien auf."
date: "2026-05-24"
---

Event-ID **7036** — „Der Dienst {service} hat den Status {state} angenommen" — feuert auf dem [`System`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn der Service Control Manager (SCM) einen Dienstübergang sieht. Jeder Dienststart, -stopp, jedes Pausieren und Fortsetzen erzeugt eines. Für sich genommen ist es volumenstark und leicht zu ignorieren; gepaart mit [7045](/de/blog/service-creation-event-id-7045) (Dienst installiert) ist es der Unterschied zwischen *eine Backdoor wurde installiert* und *eine Backdoor wurde installiert und lief*.

Für Incident Response ist das der günstigste „lief es?"-Datensatz, den das OS dir gibt.

## Wo es lebt

Immer der **`System`-Kanal** auf dem Host, auf dem der Dienst lief. Keine DC-Beteiligung, kein per-Kanal-Forwarding zu beachten — es liegt direkt in `System.evtx`. Der Provider ist `Service Control Manager`.

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

Das war's. Zwei Parameter und ein Binary-Tag — deutlich kleiner als die meisten Security-Datensätze, weshalb Analysten es überspringen.

- **`param1`** — der *Anzeigename* des Dienstes (nicht der Kurzname). `Background Intelligent Transfer Service` ist hier der nach außen sichtbare Name für `BITS`. Um auf die Dienstdefinition zu pivotieren, brauchst du oft den Kurznamen; der SCM stempelt den auch in `Binary` als UTF-16-kodiertes Blob ein (das `42 00 49 00 54 00 53 00` hier dekodiert zu `BITS`).
- **`param2`** — der neue Status: `running`, `stopped`, `paused`, `resumed` oder einer von einer Handvoll Pending-Intermediates (`start pending`, `stop pending`). Die Übergänge `running` und `stopped` sind das, worauf die meisten Regeln aufsetzen.

Es gibt keinen `AccountName`, keinen `ImagePath`, keine `ProcessId` — 7036 sagt dir *was* den Zustand änderte, nicht *wer* die Änderung auslöste. Für das Warum paarst du mit anderen Datensätzen (siehe unten).

## 7036 vs 7045 vs 7035 vs 7034

Vier dienstbezogene System-Kanal-Events werden ständig verwechselt:

| Event | Wann | Was es dir gibt |
|---|---|---|
| **7045** | Dienst installiert | Anzeigename, Kurzname, `ImagePath`, `AccountName`, `StartType`. Der Persistenz-Punkt. |
| **7036** | Dienst Start/Stopp | Nur Anzeigename. Der Ausführungs-Punkt. |
| **7035** | Service-Control gesendet | Wer Start/Stopp initiiert hat (SID), welche Control gesendet wurde. Per Default selten an; wertvoll, wenn ja. |
| **7034** | Dienst unerwartet abgestürzt | Dienst, der ohne sauberen Stopp beendet wurde. Recovery-Aktion. |

Das Muster zählt: **ein 7045 gefolgt von einem 7036 `running` für denselben Anzeigenamen Sekunden später ist die Lehrbuch-„installiert und gelaufen"-Sequenz.** Ein 7045 *ohne* passendes 7036 bedeutet, der Dienst wurde registriert, aber nie ausgeführt — entweder der Angreifer hat aufgeräumt, der Installer brach ab oder der Start wurde verzögert.

## Die Triage-Muster

### 1. Persistenz-Verifikation — mit 7045 paaren

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Drei Datensätze, ein PsExec-Lateral-Execution-Event. Das 7036-Paar sagt dir, dass der Dienst tatsächlich lief (nicht nur installiert wurde). Für eine *persistente* Backdoor fehlt das zweite 7036 (stopped) möglicherweise oder erscheint Stunden/Tage später beim Reboot des Hosts.

Ein 7045 ohne 7036 `running` innerhalb von Minuten ist seine eigene Anomalie — untersuche, warum der Install nicht feuerte. Häufige Ursachen: Der Installer ist für den nächsten Reboot gestaged, der Dienst war auf Manual gesetzt und der Angreifer hatte ihn noch nicht getriggert, oder der Start scheiterte (suche nach 7034- / 7000-Fehlern).

### 2. Defense-Evasion-Signal — Stoppen von Security-Diensten

Das am meisten missbrauchte Muster: ein Angreifer stoppt `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` oder den Dienst eines EDR-Produkts. Jeder erzeugt ein 7036 `stopped` für den entsprechenden Anzeigenamen. Wenn Audit-Policy- / Defender-Tampering versucht wird, ist das einer der Datensätze, die überleben.

Die Namen, auf die zu alarmieren ist (Anzeigenamen; je nach Defender- / EDR-Version unterschiedlich):

- `Windows Defender Antivirus Service` → Dienst `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- Alles, was `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*` matcht

Ein 7036 `stopped` für irgendeinen davon — besonders außerhalb eines geplanten Wartungsfensters — sollte ein Hard Alert sein. Viele Angreifer nutzen `sc stop`, `net stop`, `Stop-Service` oder `taskkill /im` — alle vier erzeugen ein 7036.

### 3. Service-Name-Typosquatting

7036 feuert für den Anzeigenamen, selbst wenn der zugrundeliegende Dienst bösartig ist. Achte auf Anzeigenamen, die legitim aussehen, aber zu keinem installierten Microsoft-Dienst passen: `Windows Update Service` (echter Name ist `Windows Update`), `Windows Defender Service` (echter Name ist `Windows Defender Antivirus Service`), `Microsoft Telemetry` (kein solcher Dienst). Erstelle eine Baseline von Anzeigenamen eines known-good Hosts und diff.

### 4. Boot-Anomalien

Nach einem Reboot fährt der SCM die Auto-Start-Dienste in einer ungefähr stabilen Reihenfolge hoch. Ein neuer Auto-Start-Dienst, der in der Boot-7036-Sequenz auftaucht — besonders einer, der im vorherigen Boot nicht da war — ist ein neuer Persistenz-Punkt. Quergleiche mit dem passenden 7045 am oder vor dem vorherigen Shutdown.

## Beispiel-Sigma-Regel — Security-Dienst gestoppt

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

## Beispiel-KQL — 7045 → 7036 Sequenz

Der Schlagzeilen-Pivot. Persistenz-Install gefolgt von Ausführung innerhalb von 5 Minuten auf demselben Host:

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

Der `DisplayName` aus 7036 entspricht nicht immer wörtlich dem `ServiceName` aus 7045 (einer ist Display, einer Kurzname) — matche heuristisch oder prebuild eine Map für das kleine Set wichtiger Dienste.

## Beispiel-Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK-Mapping

- **T1562.001 — Impair Defenses: Disable or Modify Tools**: 7036 `stopped` für Security-Dienste.
- **T1543.003 — Create or Modify System Process: Windows Service**: 7036 `running` gepaart mit 7045 für denselben Dienst.
- **T1569.002 — System Services: Service Execution**: 7036 `running` für einen `ImagePath`, der auf eine non-standard Binary zeigt, oft als Teil von Lateral Movement (PsExec, SCM-basierte Remote-Execution).
- **T1489 — Service Stop**: zielt auf Verfügbarkeit — Stoppen von Diensten, um andere Aktionen zu ermöglichen (Ransomware stoppt SQL Server, bevor Datenbanken verschlüsselt werden).

## False Positives, die genau wie Angriffe aussehen

- **Routine Windows Update** startet ein Dutzend Dienste in einer vorhersagbaren Sequenz neu. Das Muster ist wiederkehrend und schnell.
- **Defender-Signatur-Updates** starten manchmal `WinDefend` selbst neu — ein `stopped`, schnell gefolgt von `running` aus `MsSecFlt.exe`, ist das normale Muster. Das bösartige ist *kein* `running` nach dem `stopped`.
- **EDR-Upgrades** stoppen und restarten den EDR-Dienst. Markiere die Upgrade-Fenster des Vendors.
- **System Sleep / Hibernate** erzeugt Batches von `stopped`-Datensätzen beim Sleep und `running`-Datensätzen beim Wake. Mit `wake source`-Events zusammen offensichtlich; alarmiere nicht isoliert darauf.
- **Container- / Hyper-V**-Workloads bringen Dienste konstant hoch und runter.

## Was 7036 dir nicht sagt

- **Kein `AccountName`**: der Datensatz sagt nicht, unter welchem Security-Kontext der Dienst läuft. Hol das aus dem passenden 7045 oder aus der SCM-Datenbank.
- **Keine PID**: du kannst ein 7036 ohne Korrelation per `ImagePath` und Zeitstempel nicht direkt auf einen [4688](/de/blog/event-id-4688-process-creation)- / [Sysmon 1](/de/blog/sysmon-event-id-1-process-create)-Datensatz mappen.
- **Kein Initiator**: du siehst nicht, *wer* Stop-Service aufgerufen hat. Dafür brauchst du 7035 (per Default oft deaktiviert), [4688](/de/blog/event-id-4688-process-creation) für die aufrufende `net stop` / `sc stop` / `taskkill` oder [4104](/de/blog/powershell-4104-scriptblock) für `Stop-Service`.
- **Service-Kurznamen-Mapping**: der Anzeigename steht in `param1`; der Kurzname steht im Binary-Blob und muss dekodiert werden. Die meisten Parser tun das automatisch; wenn du rohes `EventData` abfragst, musst du das selbst behandeln.

## Wo 7036 in eine Timeline passt

Die Lateral-Execution-+-Defense-Evasion-Kombi:

1. [**4624**](/de/blog/understanding-event-id-4624) — LogonType 3 von einem angreifer-kontrollierten Host, AuthenticationPackage Kerberos.
2. [**4688**](/de/blog/event-id-4688-process-creation) — `services.exe` spawnt ein Kind für SCM-Operationen (oder PsExecs `psexesvc.exe`).
3. [**7045**](/de/blog/service-creation-event-id-7045) — Dienst installiert, `ImagePath` außerhalb der Standard-Install-Pfade.
4. **7036** `running` — der Install hat tatsächlich gefeuert. **Das ist deine Ausführungsbestätigung.**
5. **7036** `stopped` für `WinDefend` / EDR — Defense Evasion, bevor die Payload läuft.
6. [**4688**](/de/blog/event-id-4688-process-creation) — Payload-Prozess unter dem Service-Account.
7. **7036** `stopped` für den Installer-Dienst — Cleanup.

7036 erscheint in den Schritten 4, 5 und 7 — drei verschiedenen Stadien desselben Einbruchs. Für sich genommen ist es schwer zu nutzen; im Kontext bindet es den Persistenz-Datensatz (7045) an die tatsächliche Ausführung und an die umliegenden Defense-Evasion-Aktionen.

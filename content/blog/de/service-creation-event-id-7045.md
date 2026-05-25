---
title: "Event-ID 7045 erklärt: Dienstinstallation als Persistenzsignal"
description: "Die Erstellung von Diensten ist eine der lautesten Persistenztechniken. Event 7045 erfasst jede Installation — lies diese drei Felder und du fängst das meiste davon."
date: "2026-05-17"
---

Event-ID **7045** — „Ein Dienst wurde im System installiert" — feuert auf dem [`System`-Kanal](/de/blog/what-is-an-evtx-file), sobald der Service Control Manager einen neuen Dienst registriert. Auf einem Stock-Build ist es laut (Treiber-Installs, Updates), aber in stabilen Corporate-Umgebungen leise genug, dass Anomalien herausstechen. Es ist außerdem eine der meistzitierten Persistenztechniken aus MITRE ATT&CK: T1543.003.

## Was der Datensatz enthält

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Fünf Felder, drei davon zählen für IR.

## Die drei Felder, die zuerst zu lesen sind

**`ImagePath`** ist das mit Abstand nützlichste Feld. Legitime Dienste leben unter `C:\Windows\System32\`, `C:\Program Files\` oder `C:\Program Files (x86)\`. Jeder Dienst, dessen Binary in `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` oder einem zufällig benannten Verzeichnis liegt, verdient einen genaueren Blick. `ImagePath` kann auch eine `cmd.exe /c …`- oder `powershell.exe -e …`-Zeile sein — die sind fast immer bösartig; legitime Dienste shellen nicht aus.

**`AccountName`** ist meist `LocalSystem`. Ein Dienst, der unter einem Domänenbenutzer oder einem spezifischen Service-Account installiert wurde, der nicht zum Muster der Organisation passt, ist ungewöhnlich.

**`StartType`** von `auto start` heißt, dass der Dienst bei jedem Boot läuft. `demand start` heißt manuell. Persistenz will fast immer `auto start`; einmalige Lateral Execution nutzt manchmal `demand start` und räumt nach sich auf — wodurch das 7045 das einzige verbleibende Artefakt ist.

## Das Lateral-Execution-Muster

Wenn ein Angreifer `PsExec` oder ein anderes Tool nutzt, das den SCM zur Remote-Ausführung auf einem anderen Host verwendet, erhältst du ein 7045 auf dem *Ziel*-Host mit einem `ImagePath` wie `%SystemRoot%\PSEXESVC.exe` (Default) oder einem umbenannten Äquivalent. Der Dienst erscheint, läuft und wird oft innerhalb von Sekunden gelöscht. Das 7045 ist der überlebende Fingerprint lange, nachdem der Dienst selbst weg ist.

Ein 7045 mit `ImagePath`, das auf `.exe` endet, gefolgt Sekunden später von [4624 LogonType **3**](/de/blog/understanding-event-id-4624) aus einem bestimmten Quell-Host ist die Lehrbuch-PsExec-Signatur. Varianten wie SMBExec, WMIExec und Impackets `psexec.py` produzieren leicht unterschiedliche `ImagePath`-Werte, aber dasselbe Gesamtmuster.

## Was 7045 dir nicht sagt

7045 feuert bei der *Installation*, nicht bei jedem Folgestart. Um zu sehen, dass der Dienst tatsächlich läuft, brauchst du 7036 („Dienst hat den Status running angenommen"). Um den zugrundeliegenden Prozess zu sehen, brauchst du [Sysmon-Event 1](/de/blog/sysmon-event-id-1-process-create) oder [4688](/de/blog/event-id-4688-process-creation) mit passendem `Image`-Pfad.

Für Dienste, die *vor* dem Start des Audit-Logs installiert wurden (z. B. während der OS-Installation), gibt es kein 7045 — sie existieren in der Registry unter `HKLM\SYSTEM\CurrentControlSet\Services\` und müssen dort enumeriert werden, nicht aus Event-Logs.

## Triage-Workflow

1. Filtere den System-Kanal nach `EventID:7045`.
2. Sortiere oder pivotiere nach `ImagePath` — alles außerhalb der Standard-Install-Pfade ist verdächtig.
3. Für jeden Verdacht hole das passende 4624 per Zeitstempel + Quell-Host — finde das Credential, das es installiert hat.
4. Hole Sysmon-Event 1 per `Image`, das `ImagePath` matcht, um tatsächliche Ausführungen zu sehen.
5. Notiere, ob eine [**7036**](/de/blog/event-id-7036-service-state) / 7034 / 7035-Sequenz einen One-Shot-Lauf oder einen persistenten Dienst zeigt.

## Beispiel-Sigma-Regel — Dienst aus non-standard Pfad installiert

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## Beispiel-KQL — PsExec-Lateral-Execution-Fingerprint

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

Ein 4624 LogonType-3 innerhalb von 30 Sekunden eines 7045 auf demselben Host ist die Lehrbuch-PsExec-Signatur.

## Beispiel-Splunk — anomaler Dienst-Installer

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## ATT&CK-Mapping

- **T1543.003 — Create or Modify System Process: Windows Service**: das Schlagzeilen-Mapping. Langlaufende Dienste, gestartet unter angreifer-kontrollierten Binaries.
- **T1569.002 — System Services: Service Execution**: kurzlebige Dienste, die nur als Vehikel für Remote-Ausführung dienen (PsExec, SMBExec, SCM-basiertes Lateral Movement).
- **T1078 — Valid Accounts**: wenn das installierende Principal ein Domain-Admin ist, dessen Credentials gestohlen wurden.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: Dienste mit Anzeigenamen, die echte Microsoft-Dienste nachahmen, aber Binaries woanders haben.

## False Positives, die genau wie Angriffe aussehen

- **Software-Installer** (Chocolatey, MSI-Bootstrapper) installieren häufig Dienste aus einem Staging-Verzeichnis, bevor die Binary verschoben wird. Das 7045 feuert vom Staging-Pfad, obwohl die finale Installation sauber ist.
- **EDR- / AV-Agenten** installieren Dienste als Teil ihres Setups. Der `ImagePath` des Vendors ist stabil und signiert; baseline.
- **Manche Microsoft-Updates** installieren temporäre Servicing-Dienste; die sind kurzlebig und aus `LocalSystem`.
- **Container- / Hyper-V**-Workloads registrieren manchmal transiente Dienste pro VM.

Das Signal sind *einmalige* Installations in user-schreibbare Pfade durch *Nicht-Admin- oder non-standard* Installer. Ein signierter Installer-Dienst in `C:\Program Files\` ist nicht der Angriff.

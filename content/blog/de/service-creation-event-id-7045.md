---
title: "Event ID 7045 erklärt: Service-Installation als Persistenzsignal"
description: "Service-Erstellung ist eine der lautesten Persistenztechniken. Event 7045 fängt jede Installation. Lesen Sie diese drei Felder und Sie fangen das meiste davon."
date: "2026-05-17"
---

Event-ID **7045**, "Ein Dienst wurde im System installiert", feuert auf dem [`System`-Channel](/en/blog/what-is-an-evtx-file), wann immer der Service Control Manager einen neuen Dienst registriert. Es ist auf einem Stock-Build laut (Treiber-Installationen, Windows-Updates), aber in einer steady-state Unternehmensumgebung wird es leise genug, dass Anomalien auffallen. Es ist auch eine der meistzitierten Persistenztechniken von MITRE ATT&CK: T1543.003. Es lohnt sich, das auswendig zu kennen.

## Was im Record steht

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Fünf Felder. Drei sind wichtig für IR.

## Die drei Felder, die zuerst zu lesen sind

**`ImagePath`** ist das einzige nützlichste Feld. Legitime Dienste leben unter `C:\Windows\System32\`, `C:\Program Files\` oder `C:\Program Files (x86)\`. Jeder Dienst, dessen Binärdatei in `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` oder einem zufällig benannten Verzeichnis sitzt, verdient einen näheren Blick. `ImagePath` kann auch `cmd.exe /c ...` oder `powershell.exe -e ...` sein. Diese sind fast immer bösartig. Legitime Dienste shellen nicht aus.

**`AccountName`** ist üblicherweise `LocalSystem`. Ein Dienst, der unter einem Domain-Benutzer oder einem spezifischen Service-Konto installiert wird, das nicht zum Muster der Organisation passt, ist ungewöhnlich.

**`StartType`** von `auto start` bedeutet, dass der Dienst bei jedem Boot läuft. `demand start` bedeutet manuell. Persistenz will fast immer `auto start`. One-Shot-Lateral-Execution kann `demand start` verwenden und sich danach selbst aufräumen. Das macht das 7045 zum einzigen verbliebenen Artefakt.

## Das Lateral-Execution-Muster

Wenn ein Angreifer PsExec oder ein Tool ausführt, das den SCM verwendet, um auf einem anderen Host remote auszuführen, bekommen Sie ein 7045 auf dem *Ziel*-Host mit einem `ImagePath` wie `%SystemRoot%\PSEXESVC.exe` (Standard) oder einem umbenannten Äquivalent. Der Dienst erscheint, läuft und wird oft innerhalb von Sekunden gelöscht. Das 7045 ist der überlebende Fingerabdruck lange nachdem der Dienst selbst weg ist.

Ein 7045 mit `ImagePath` endend auf `.exe` gefolgt Sekunden später von [4624 LogonType **3**](/en/blog/understanding-event-id-4624) von einem spezifischen Quell-Host ist die Lehrbuch-PsExec-Signatur. Varianten wie Impacket `psexec.py`, `smbexec.py`, `wmiexec.py` produzieren leicht unterschiedliche `ImagePath`-Werte, aber dasselbe Gesamtmuster. Die umbenannte Impacket-Variante ist üblicherweise der Verräter: ein Dienstname wie `wfDsaQbA` (acht zufällige Buchstaben) kommt nicht von einem Sysadmin.

## Was 7045 Ihnen nicht sagt

7045 feuert auf *Installation*, nicht auf jeden nachfolgenden Start. Um den Dienst tatsächlich laufen zu sehen, brauchen Sie [7036](/en/blog/event-id-7036-service-state) ("Dienst ist in den running-Zustand übergegangen"). Um den zugrundeliegenden Prozess zu sehen, brauchen Sie [Sysmon-Event 1](/en/blog/sysmon-event-id-1-process-create) oder [4688](/en/blog/event-id-4688-process-creation) mit dem passenden `Image`-Pfad.

Für Dienste, die *vor* dem Start des Audit-Logs installiert wurden (z. B. während der OS-Installation), gibt es kein 7045. Sie existieren in der [Registry](https://www.registryparser.com) unter `HKLM\SYSTEM\CurrentControlSet\Services\` und müssen dort aufgezählt werden, nicht aus Event-Logs. Der [AmCache](https://www.amcacheparser.com)-Hive und der [Prefetch](https://www.prefetchparser.com)-Cache bestätigen oft Ausführungen, die kein 4688 produziert haben.

## Triage-Workflow

1. Filtern Sie den System-Channel nach `EventID:7045`.
2. Sortieren oder pivotieren Sie nach `ImagePath`. Alles außerhalb der Standard-Installationspfade ist verdächtig.
3. Für jedes verdächtige, holen Sie das passende 4624 per Zeitstempel und Source-Host. Finden Sie die Credential, die es installiert hat.
4. Holen Sie Sysmon 1 per `Image` passend zum `ImagePath`, um tatsächliche Ausführungen zu sehen.
5. Notieren Sie, ob eine [7036](/en/blog/event-id-7036-service-state) / 7034 / 7035 Sequenz einen One-Shot-Lauf oder einen persistenten Dienst zeigt.

## Sigma: Dienst aus Nicht-Standard-Pfad installiert

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory. Common for persistence and PsExec-style execution.
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

## KQL: PsExec Lateral-Execution-Fingerabdruck

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

## Splunk: anomaler Service-Installer

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## ATT&CK-Zuordnung

- T1543.003 Create or Modify System Process: Windows Service. Long-running Dienste, die unter angreifer-kontrollierten Binärdateien gestartet werden.
- T1569.002 System Services: Service Execution. Kurzlebige Dienste, die rein als Vehikel für Remote-Ausführung verwendet werden (PsExec, SMBExec, SCM-basiertes Lateral Movement).
- T1078 Valid Accounts. Wenn der installierende Principal ein Domain-Admin ist, dessen Credentials gestohlen wurden.
- T1036.005 Masquerading: Match Legitimate Name or Location. Dienste mit Anzeigenamen, die echte Microsoft-Dienste nachahmen, aber Binärdateien anderswo haben.

## Falschpositive, die genau wie Angriffe aussehen

- Software-Installer (Chocolatey, MSI-Bootstrapper) installieren häufig Dienste aus einem Staging-Verzeichnis, bevor sie die Binärdatei verschieben. Das 7045 feuert vom Staging-Pfad, obwohl die finale Installation sauber ist.
- EDR- und AV-Agenten installieren Dienste als Teil ihres Setups. Der `ImagePath` des Anbieters wird stabil und signiert sein. Baselinen Sie.
- Einige Microsoft-Updates installieren temporäre Servicing-Dienste. Kurzlebig, von `LocalSystem`.
- Container- oder Hyper-V-Workloads registrieren manchmal transiente Dienste pro VM.

Das Signal sind *einmalige* Installationen zu benutzerbeschreibbaren Pfaden durch *Nicht-Admin- oder Nicht-Standard-* Installer. Ein signierter Installer-Dienst in `C:\Program Files\` ist nicht der Angriff.

## Weiterführende Literatur

- [Microsoft-Dokumentation für 7045](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7045)
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

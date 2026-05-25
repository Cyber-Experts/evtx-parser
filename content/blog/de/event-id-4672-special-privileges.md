---
title: "Event-ID 4672 erklärt: privilegierte Anmeldungen unter Windows erkennen"
description: "4672 feuert, sobald einer Anmeldung sensible Rechte wie SeDebugPrivilege zugewiesen werden. Lies es als 'admin-äquivalente Sitzung' und der Rest der Audit-Policy fügt sich."
date: "2026-05-24"
---

Event-ID **4672** — „Einer neuen Anmeldung wurden besondere Rechte zugewiesen" — feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn einer Anmeldesitzung eines aus einer festen Menge sensibler Windows-Privilegien zugewiesen wird. In der Praxis heißt das: jede erfolgreiche admin-äquivalente Anmeldung produziert ein 4672, unmittelbar nach dem zugehörigen [4624](/de/blog/understanding-event-id-4624). Auf den meisten Workstations ist 4672 selten; auf Domain Controllern und Admin-Jumphosts dauerhaft präsent. Diese Asymmetrie macht es nützlich.

Wenn du Security-Datensätze nur nach einem Feld filterst, ist „zeig mir alle 4672 der letzten Woche" die günstigste „zeig mir jede privilegierte Sitzung im Estate"-Query, die du fahren kannst.

## Wo es feuert

Immer auf dem Host, auf dem die Anmeldung tatsächlich stattfand — wie bei [4624](/de/blog/understanding-event-id-4624). Eine Netzwerkanmeldung an `SERVER01` produziert das 4624 und (falls privilegiert) das 4672 auf `SERVER01`, nicht auf der Ursprungs-Workstation. Um aus 4672 etwas im großen Maßstab zu erkennen, brauchst du mindestens Security-Sammlung von Servern und DCs; von Admin-Workstations und Jumphosts, wenn du dir das Volumen leisten kannst.

## Was der Datensatz enthält

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

Die Felder:

- **`SubjectLogonId`** — dieselbe `LogonId`, die auf dem passenden [4624](/de/blog/understanding-event-id-4624) erscheint. Das ist dein Pivot: jedes 4672 bindet genau ein 4624 (und jeden Folgedatensatz dieser Sitzung) an die Rechtemenge, die diese Anmeldung erhalten hat.
- **`PrivilegeList`** — der eigentliche Rechtebeutel. Windows protokolliert hier nur eine feste Menge „sensibler" Privilegien (definiert in der Audit-Policy); eine Anmeldung kann mehr Rechte halten, als der Datensatz zeigt. Die ausgelassenen — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege` usw. — sind nicht sicherheitsrelevant und werden bewusst aus diesem Datensatz herausgefiltert.
- **`Subject*`** — wem die Anmeldung gehört. Fast immer identisch mit denselben Feldern auf dem passenden 4624.

Auf 4672 selbst gibt es keine `IpAddress`, keinen `LogonType`, keinen `WorkstationName`. Um die zu bekommen, joinst du via `SubjectLogonId` an das 4624.

## Die Privilegien und was sie bedeuten

| Privileg | Anzeigename | Warum es zählt |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Speicher jedes Prozesses lesen/schreiben — auch `lsass.exe`. Mimikatz braucht das. |
| `SeTcbPrivilege` | Act as part of the operating system | Effektiv `LocalSystem`. Sollte nur für LocalSystem selbst erscheinen. |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | Das Privileg, das von `SeImpersonatePrivilege`-Exploit-Familien genutzt wird (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Token-Impersonation-Tooling. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | ACLs umgehen, um beliebige Dateien zu lesen/schreiben — auch Registry-Hives. `reg save HKLM\SAM` funktioniert damit. |
| `SeTakeOwnershipPrivilege` | Take ownership of files | Datei-ACLs überschreiben. |
| `SeLoadDriverPrivilege` | Load and unload device drivers | Erforderlich für BYOVD-Angriffe (Bring Your Own Vulnerable Driver). |
| `SeSecurityPrivilege` | Manage auditing and security log | Security-Eventlog lesen/löschen. Erforderlich, um [1102](/de/blog/event-id-1102-cleared-log) auszulösen. |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkits, EFI-Tampering. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Häufig bei den meisten Anmeldungen; kein Triage-Signal. |

Einige davon erwartest du bei jeder Admin-Anmeldung (`SeDebugPrivilege`, `SeBackupPrivilege`). Andere sollten seltener sein (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Das Signal liegt im *unerwarteten* Privileg auf dem *falschen* Konto.

## Die Triage-Muster

### 1. Baseline, wer 4672 produziert

In einem gesunden Estate sind 4672-Erzeuger eine *kleine, bekannte* Menge:

- `LocalSystem` (S-1-5-18) — jeder Host, jederzeit, bei Dienststart.
- `NetworkService` (S-1-5-20) — häufig auf Servern mit impersonations-fähigen Diensten.
- Eine Handvoll Administratoren, identifiziert per SID statt Name.

Alle anderen, die ein 4672 erzeugen, sind entweder: ein neuer Admin, von dem du nichts wusstest, ein Privilege-Escalation-Event oder ein fehlkonfiguriertes Konto.

Die günstigste Baseline-Query: distinct `SubjectUserSid` aus 4672 über die letzten 30 Tage, sortiert nach Häufigkeit. Alles außerhalb der Top-N-Erzeuger verdient einen Blick.

### 2. SeImpersonatePrivilege auf einem unprivilegierten Konto

Wenn ein 4672 `SeImpersonatePrivilege` auf einem Konto zeigt, das kein Admin und keine `*Service`-SID ist, ist das fast sicher eine Eskalation aus der „Potato"-Familie (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). Diese Exploits geben einem `IIS_IUSRS`- oder Service-Token-Caller `SYSTEM`. Das 4672 feuert *im Moment der Rechte-Akquisition* — früher als jeder sichtbare Prozess, der mit dem neuen Privileg gespawnt wird.

### 3. SeDebugPrivilege ohne Admin-Gruppe

`SeDebugPrivilege` wird per Policy an lokale Admins vergeben. Es auf einem Nicht-Admin-Konto zu sehen, ist ein Zeichen, dass die Policy verändert wurde — meist durch einen Angreifer, um LSASS-Zugriff zu ermöglichen — oder dass ein Angreifer in einen Admin-Prozess injiziert hat.

### 4. Privilegierte Anmeldung außerhalb der Geschäftszeit

Ein 4672 für ein echtes Admin-Konto um 03:00 an einem Sonntag ist der günstigste „After-Hours-Admin-Aktivität"-Alarm, den es gibt. Kombiniere mit `LogonType` und `IpAddress` des zugehörigen 4624 für Kontext.

### 5. Service-Account-Drift

Ein Service-Account, der historisch nur `SeImpersonatePrivilege` und `SeAssignPrimaryTokenPrivilege` feuert und plötzlich 4672 mit `SeBackupPrivilege` und `SeDebugPrivilege` produziert, bedeutet, dass jemand seine Gruppenmitgliedschaften geändert hat. Paare mit 4732/4728, um die Mitgliedschaftsänderung zu finden.

## Beispiel-Sigma-Regel — SeDebugPrivilege auf einem Nicht-Admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Tune `filter_known_admins` pro Umgebung; manche Shops nutzen eine SID-Liste statt eines Name-Patterns.

## Beispiel-KQL — Eskalation aus der Potato-Familie

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Beispiel-Splunk — Baseline Admin-Anmeldungen

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Fahre das wöchentlich; Anomalien tauchen als neue Konten in den Top 50 auf.

## ATT&CK-Mapping

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**: SeImpersonatePrivilege auf unprivilegierten Konten.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: SeDebugPrivilege ist die Voraussetzung.
- **T1068 — Exploitation for Privilege Escalation**: jeder unerwartete Rechtegewinn.
- **T1078 — Valid Accounts**: 4672 für legitime Admin-Konten aus ungewöhnlichen Quellen.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: SeSecurityPrivilege ist Voraussetzung für `ClearEventLog`; ein 4672 mit diesem Privileg unmittelbar vor [1102](/de/blog/event-id-1102-cleared-log) ist die Brotkrumen-Spur.

## False Positives, die genau wie Angriffe aussehen

- **Backup-Software** (Veeam, Commvault) feuert routinemäßig 4672 mit `SeBackupPrivilege` + `SeRestorePrivilege` aus Service-Konten. Baseline per Service-Account-SID.
- **Monitoring-Agenten** (SCOM, eigene WMI-Collectors), die sicherheitsrelevante Daten lesen, triggern 4672 breit. Markiere den Agent-Host.
- **Manche Logon-Skripte** unter privilegierten Kontexten erzeugen 4672-Ketten zur Logon-Zeit.
- **Hyper-V / VMM / Container-Hosts** erzeugen dichten 4672-Traffic von `LocalSystem` und Managed Service Accounts.

Das Signal liegt im *neuen* Erzeuger, nicht im *wiederkehrenden*. Ein 4672-Erzeuger, der täglich seit einem Jahr feuert, ist Konfiguration; einer, der diese Woche neu auftaucht, ist die Spur.

## Was 4672 dir nicht sagt

- **Keine Prozessinformation**: du siehst die Rechtevergabe, nicht was der privilegierte Prozess gemacht hat. Um ihm nachzugehen, pivotiere `SubjectLogonId` auf [4688](/de/blog/event-id-4688-process-creation)- / [Sysmon 1](/de/blog/sysmon-event-id-1-process-create)-Datensätze derselben Sitzung.
- **Keine direkte Quell-IP**: du musst per `SubjectLogonId` an [4624](/de/blog/understanding-event-id-4624) joinen, um sie zu bekommen.
- **Nicht jede privilegierte Aktion**: nur die *Vergabe bei der Anmeldung* wird aufgezeichnet. Spätere Nutzungen (z. B. `RtlAdjustPrivilege`, das `SeDebugPrivilege` ein-/ausschaltet) erzeugen 4673/4674-Datensätze, nicht noch ein 4672.
- **Übersehen, wenn Special-Logon-Auditing aus ist**: die Audit-Unterkategorie ist *Audit Special Logon*, die für Success-Events aktiv sein muss. In modernen Windows-Versionen per Default an, aber überprüfenswert.

## Wo 4672 in eine Timeline passt

Die Lehrbuchkette aus Eskalation und Aufräumen:

1. [**4624**](/de/blog/understanding-event-id-4624) — LogonType 3 aus einer angreifer-kontrollierten IP, niedrig-privilegierter Benutzer.
2. *(stumm)* — `SeImpersonatePrivilege`-basierte Eskalation (PrintSpoofer oder Ähnliches).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` einer neuen Anmeldesitzung als `LocalSystem` gewährt. **Eskalation hier sichtbar.**
4. [**4688**](/de/blog/event-id-4688-process-creation) — `cmd.exe` oder `powershell.exe` läuft als SYSTEM über das impersonierte Token.
5. [**4104**](/de/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` oder `comsvcs.dll MiniDump` gegen LSASS — SeDebugPrivilege macht das möglich.
6. [**1102**](/de/blog/event-id-1102-cleared-log) — Security-Log gelöscht. SeSecurityPrivilege aus Schritt 3 hat das ermöglicht.
7. **4672** — zweite privilegierte Sitzung als aus LSASS-Speicher extrahierter Domain-Admin.

Die 4672 in den Schritten 3 und 7 sind die günstigsten Detection-Punkte in der Kette. Ohne sie setzt du Impersonation aus reinen Prozess-Events zusammen — langsamer und leichter zu übersehen.

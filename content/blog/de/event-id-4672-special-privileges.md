---
title: "Event ID 4672 erklärt: privilegierte Anmeldungen in Windows erkennen"
description: 'Event ID 4672 feuert, sobald einer Anmeldung sensible Privilegien wie SeDebugPrivilege oder SeTcbPrivilege gewährt werden. Lies es als das Signal admin-äquivalenter Sitzungen.'
date: "2026-05-24"
---

Event ID **4672**, „Besondere Rechte einer neuen Anmeldung zugewiesen", feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn einer Anmeldesitzung eines aus einer festen Menge sensibler Windows-Privilegien gewährt wird. In der Praxis erzeugt jede erfolgreiche admin-äquivalente Anmeldung ein 4672, das sofort nach dem entsprechenden [4624](/de/blog/understanding-event-id-4624) geschrieben wird. Auf den meisten Workstations ist 4672 selten. Auf Domain Controllern und Admin-Jumpboxes ist es konstant. Diese Asymmetrie ist es, was es nützlich macht.

Wenn du Security diese Woche nach einem Feld filterst, lass „alle 4672s der letzten sieben Tage" laufen. Es ist die billigste „zeig mir jede privilegierte Sitzung in der Umgebung"-Abfrage, die du schreiben kannst.

## Wo es feuert

Auf dem Host, auf dem die Anmeldung tatsächlich stattfand, genau wie [4624](/de/blog/understanding-event-id-4624). Ein Netzwerk-Logon auf `SERVER01` produziert das 4624 und das 4672 auf `SERVER01`, nicht auf der ursprünglichen Workstation. Um irgendetwas aus 4672 in großem Stil zu erkennen, brauchst du mindestens Security-Sammlung von Servern und DCs. Admin-Workstations und Jumphosts, wenn du dir das Volumen leisten kannst.

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

- `SubjectLogonId`. Dieselbe `LogonId` aus dem passenden [4624](/de/blog/understanding-event-id-4624). Das ist dein Pivot. Jedes 4672 verknüpft genau ein 4624 (und jeden nachfolgenden Datensatz in dieser Sitzung) mit dem Privilegien-Set, das die Anmeldung bekommen hat.
- `PrivilegeList`. Der eigentliche Privilegien-Beutel. Windows loggt nur die in der Audit-Richtlinie definierten „sensiblen" Privilegien. Eine Anmeldung kann mehr Privilegien halten, als der Datensatz zeigt. Die ausgelassenen (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege` usw.) sind nicht sicherheitsrelevant und werden aus diesem Datensatz absichtlich gekürzt.
- `Subject*`. Wem die Anmeldung gehört. Fast immer identisch mit dem passenden 4624.

Es gibt keine `IpAddress`, keinen `LogonType`, keinen `WorkstationName` auf dem 4672 selbst. Um diese zu bekommen, joinst du auf das 4624 per `SubjectLogonId`. Analysten, die versuchen, allein auf 4672 zu alarmieren, übersehen das oft und enden mit Datensätzen, die sie nicht anreichern können.

## Die Privilegien und was sie bedeuten

| Privileg | Anzeigename | Warum es zählt |
|---|---|---|
| `SeDebugPrivilege` | Programme debuggen | Speicher beliebiger Prozesse lesen/schreiben, einschließlich `lsass.exe`. Mimikatz braucht das. |
| `SeTcbPrivilege` | Als Teil des Betriebssystems agieren | Effektiv `LocalSystem`. Sollte nur für LocalSystem erscheinen. |
| `SeImpersonatePrivilege` | Client nach Authentifizierung imitieren | Das Privileg, das die Potato-Familie (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato) nutzt. |
| `SeAssignPrimaryTokenPrivilege` | Prozess-Token ersetzen | Token-Impersonation-Tooling. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Wiederherstellung | ACLs umgehen, um beliebige Dateien einschließlich Registry-Hives zu lesen/schreiben. `reg save HKLM\SAM` funktioniert damit. |
| `SeTakeOwnershipPrivilege` | Besitz übernehmen | Datei-ACLs überschreiben. |
| `SeLoadDriverPrivilege` | Treiber laden | Erforderlich für BYOVD (Bring Your Own Vulnerable Driver). |
| `SeSecurityPrivilege` | Audit-Log verwalten | Security lesen oder leeren. Erforderlich, um [1102](/de/blog/event-id-1102-cleared-log) zu feuern. |
| `SeSystemEnvironmentPrivilege` | Firmware modifizieren | Bootkits, EFI-Manipulation. |
| `SeChangeNotifyPrivilege` | Traverse-Prüfung umgehen | Häufig bei den meisten Anmeldungen. Kein Triage-Signal. |

Einige erwartest du bei jeder Admin-Anmeldung (`SeDebugPrivilege`, `SeBackupPrivilege`). Andere sollten seltener sein (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). Das Signal ist das *unerwartete* Privileg auf dem *falschen* Konto.

## Die Muster

### Baseline, wer 4672 bekommt

In einer gesunden Umgebung sind 4672-Produzenten eine kleine, bekannte Menge:

- `LocalSystem` (S-1-5-18). Jeder Host, immer, beim Dienststart.
- `NetworkService` (S-1-5-20). Häufig auf Servern, die impersonation-fähige Dienste laufen lassen.
- Eine Handvoll Administratoren, per SID statt per Name identifiziert.

Jeder andere ist ein neuer Admin, von dem du nichts wusstest, ein Privilege-Escalation-Ereignis oder ein falsch konfiguriertes Konto.

Die billigste Baseline-Abfrage: distinct `SubjectUserSid` von 4672 über die letzten 30 Tage, nach Frequenz sortiert. Alles außerhalb der Top N ist einen Blick wert.

### SeImpersonatePrivilege auf einem unprivilegierten Konto

Wenn ein 4672 `SeImpersonatePrivilege` auf einem Konto zeigt, das kein Admin und keine `*Service`-SID ist, ist es fast sicher eine Potato-Eskalation. Diese Exploits geben einem `IIS_IUSRS`- oder Service-Token-Aufrufer `SYSTEM`. Das 4672 feuert *bei der Privilegien-Erlangung*. Das ist früher als jeder sichtbare Prozess, der mit dem neuen Privileg gestartet wird.

### SeDebugPrivilege ohne Admin-Gruppe

`SeDebugPrivilege` wird lokalen Admins per Richtlinie gewährt. Auf einem Nicht-Admin-Konto wurde entweder die Richtlinie geändert (meist von einem Angreifer, um LSASS-Zugriff zu ermöglichen) oder ein Angreifer hat sich in einen Admin-Prozess injiziert.

### Privilegierte Anmeldung außerhalb der Geschäftszeiten

Ein 4672 für ein echtes Admin-Konto um 03:00 Uhr an einem Sonntag ist der billigste After-Hours-Alarm überhaupt. Kombiniere mit `LogonType` und `IpAddress` des passenden 4624 für Kontext.

### Service-Account-Drift

Ein Service-Konto, das historisch nur `SeImpersonatePrivilege` und `SeAssignPrimaryTokenPrivilege` feuert, das plötzlich 4672s mit `SeBackupPrivilege` und `SeDebugPrivilege` produziert, bedeutet, dass jemand seine Gruppenmitgliedschaften geändert hat. Paare mit 4732 oder 4728, um die Mitgliedschaftsänderung zu finden.

## Sigma: SeDebugPrivilege auf einem Nicht-Admin

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
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Stimme `filter_known_admins` pro Umgebung ab. Einige Shops nutzen eine SID-Liste statt eines Namensmusters.

## KQL: Potato-Familie-Eskalation

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

## Splunk: Admin-Anmeldungen-Baseline

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Wöchentlich laufen lassen. Anomalien tauchen als neue Konten in den Top 50 auf.

## ATT&CK-Mapping

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege auf unprivilegierten Konten.
- T1003.001 LSASS Memory. SeDebugPrivilege ist die Voraussetzung.
- T1068 Exploitation for Privilege Escalation. Jeder unerwartete Privilegien-Gewinn.
- T1078 Valid Accounts. 4672 für legitime Admin-Konten von ungewöhnlichen Quellen.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege ist erforderlich, um `ClearEventLog` aufzurufen. Ein 4672, das dieses Privileg trägt, unmittelbar vor [1102](/de/blog/event-id-1102-cleared-log) ist die Brotkrumenspur.

## False Positives, die wie Angriffe aussehen

- Backup-Software (Veeam, Commvault) feuert routinemäßig 4672 mit `SeBackupPrivilege` + `SeRestorePrivilege` von Service-Konten. Baseline per Service-Konto-SID.
- Monitoring-Agenten (SCOM, eigene WMI-Collectors) triggern 4672 breitflächig. Markiere den Agent-Host.
- Einige Logon-Skript-Runner unter privilegierten Kontexten erzeugen 4672-Ketten zur Logon-Zeit.
- Hyper-V, VMM, Container-Hosts erzeugen dichte 4672 von `LocalSystem` und Managed Service Accounts.

Das Signal ist der *neue* Produzent, nicht der *wiederkehrende*. Ein 4672-Produzent, der das letzte Jahr täglich gefeuert hat, ist Konfiguration. Einer, der erst diese Woche aufgetaucht ist, ist der Lead.

## Was 4672 dir nicht sagt

- Keine Prozessinformation. Du siehst die Privilegien-Gewährung, nicht, was der privilegierte Prozess getan hat. Um ihm vorwärts zu folgen, pivotiere `SubjectLogonId` zu [4688](/de/blog/event-id-4688-process-creation)- oder [Sysmon-1](/de/blog/sysmon-event-id-1-process-create)-Datensätzen in derselben Sitzung.
- Keine direkte Quell-IP. Du joinst auf [4624](/de/blog/understanding-event-id-4624) per `SubjectLogonId`.
- Nicht jede privilegierte Aktion. Nur die *Gewährung beim Logon* wird aufgezeichnet. Spätere Nutzungen (z. B. `RtlAdjustPrivilege`, das `SeDebugPrivilege` an- und ausschaltet) produzieren 4673/4674-Datensätze, nicht ein weiteres 4672.
- Verpasst, wenn Special-Logon-Auditing aus ist. Die Audit-Unter-Richtlinie heißt *Audit Special Logon*. Standardmäßig an in modernem Windows, aber das Verifizieren wert.

## Wo 4672 in eine Timeline passt

Die Lehrbuch-Eskalations- und Cleanup-Kette:

1. [4624](/de/blog/understanding-event-id-4624). LogonType 3 von einer angreifer-kontrollierten IP, niedrig-privilegierter Benutzer.
2. *(still)*. SeImpersonatePrivilege-basierte Eskalation (PrintSpoofer oder ähnlich).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege gewährt einer neuen Logon-Sitzung, die als LocalSystem läuft. Eskalation hier sichtbar.
4. [4688](/de/blog/event-id-4688-process-creation). `cmd.exe` oder `powershell.exe` als SYSTEM über das imitierte Token.
5. [4104](/de/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` oder `comsvcs.dll MiniDump` gegen LSASS. SeDebugPrivilege macht das möglich.
6. [1102](/de/blog/event-id-1102-cleared-log). Security-Log geleert. SeSecurityPrivilege aus Schritt 3 hat das ermöglicht.
7. **4672**. Zweite privilegierte Sitzung als Domain-Admin, aus dem LSASS-Speicher extrahiert.

Die 4672s in den Schritten 3 und 7 sind die billigsten Erkennungspunkte. Ohne sie setzt du die Impersonation aus Prozess-Ereignissen allein zusammen. Langsamer, leichter zu übersehen.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)

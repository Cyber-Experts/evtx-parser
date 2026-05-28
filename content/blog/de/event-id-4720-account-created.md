---
title: "Event ID 4720 erklärt: bösartige Kontoerstellung in AD erkennen"
description: "4720 feuert jedes Mal, wenn ein Benutzerkonto erstellt wird, lokal oder Domäne. Lies es mit 4722, 4724 und 4732, und du fängst Persistenz- und Lateral-Movement-Konten innerhalb von Minuten."
date: "2026-05-24"
---

Event ID **4720**, „Ein Benutzerkonto wurde erstellt", landet auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn ein neuer Benutzer bereitgestellt wird. Auf einem Domain Controller feuert es für jeden neuen AD-Benutzer. Auf einer Workstation oder einem Member-Server feuert es für jedes neue lokale Konto. In einem reifen Shop ist 4720-Verkehr überwiegend HR-getrieben und vorhersehbar. Diese Vorhersehbarkeit ist es, was es nützlich macht. Ein Angreifer, der ein Backdoor-Konto erstellt, sticht genau deshalb heraus, weil der legitime Verkehr so regelmäßig ist.

Das ist einer der billigsten Persistenz-Erkennungs-Datensätze, die die Plattform liefert. Ich habe Fälle allein damit geschlossen.

## Wo es feuert

- Domänen-Konten: 4720 landet auf dem DC, der den Create behandelt hat. Sammle über alle DCs.
- Lokale Konten: 4720 landet auf dem Host, auf dem das Konto erstellt wurde. Das von Member-Workstations zu fangen, benötigt WEF oder Per-Host-Sammlung. Viele Shops überspringen das Workstation-Security-Forwarding und verlieren dieses Signal komplett.

Wenn der Angreifer ein *lokales* Konto auf einem schon kompromittierten Server erstellt (oft als Backup-Credential), ist das 4720 nur auf diesem Server. Abdeckung zählt mehr als Regeln.

## Was im Datensatz steht

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

Die Felder, die Untersuchungen treiben:

- `TargetUserName`. Das neue Konto. Der wörtliche Name ist das erste Triage-Signal: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, Lookalikes legitimer Konten (`administrator`, `administr0r`) und kurze Random-Strings rechtfertigen alle einen genaueren Blick.
- `SubjectUserName` und `SubjectLogonId`. Wer es erstellt hat. Pivotiere zum [4624](/de/blog/understanding-event-id-4624), das diese Sitzung erstellt hat. Ein 4720 von `LocalSystem` auf einer Workstation außerhalb der Geschäftszeiten ist kein echter Provisioning-Workflow.
- `UserAccountControl`. Der *initiale* Satz von UAC-Flags. `0x10` (im Beispiel) ist `NORMAL_ACCOUNT`. Die gefährlichen Flags erscheinen in nachfolgenden 4738-Datensätzen.
- `PrimaryGroupId`. 513 (Domain Users) ist normal. 512 (Domain Admins) auf einem neuen Konto ist laut schreiend und sollte nie in einem echten Provisioning-Workflow passieren.
- `SidHistory`. Nicht-leer auf einem neu erstellten Konto ist entweder ein Migrationstool oder, im falschen Kontext, ein gefälschtes Authentifizierungsartefakt.

## 4720 kommt nie allein

Kontoerstellung ist fast nie ein einzelnes Ereignis. Die Mindestsequenz:

| Event | Bedeutung | Warum es zählt |
|---|---|---|
| **4720** | Benutzerkonto erstellt | Die Schlagzeile. |
| **4722** | Benutzerkonto aktiviert | Das Konto ist auf Anmeldung gesetzt. Wenn 4722 fehlt, existiert das Konto, kann sich aber noch nicht anmelden. |
| **4724** | Passwort-Reset (admin-getrieben) | Jemand, möglicherweise nicht der Ersteller, hat das Passwort gesetzt oder zurückgesetzt. |
| **4738** | Benutzerkonto geändert | UAC-Flags, Ablauf, Gruppe, Attributänderungen. |
| **4732** | Mitglied zu einer sicherheitsaktivierten lokalen Gruppe hinzugefügt | Wenn die lokale Gruppe `Administrators` ist, ist das die Privilegien-Gewährung. |
| **4728** | Mitglied zu einer sicherheitsaktivierten globalen Gruppe hinzugefügt | Wenn die globale Gruppe `Domain Admins` oder `Enterprise Admins` ist, Eskalation. |
| **4756** | Mitglied zu einer sicherheitsaktivierten universellen Gruppe hinzugefügt | `Schema Admins`, `Enterprise Admins`, eigene Delegationen. |

Ein Backdoor-Konto wird selten erstellt und bei Default-Privileg gelassen. Die volle Kette (4720, 4722, 4724, 4738, 4732/4728) wird in Sekunden abgeschlossen und ist das eigentliche Persistenz-Ereignis.

## Triage-Muster

1. **Neues Konto in Admin-Gruppe innerhalb von Minuten**. 4720 gefolgt von 4732 oder 4728 zu einer privilegierten Gruppe innerhalb einer Stunde, wobei dem privilegierten Gruppen-Add kein Ticket vorausging. Paare `TargetSid` aus 4720 mit `MemberSid` auf 4732/4728.
2. **Erstellung außerhalb der Geschäftszeiten**. 4720 außerhalb der Geschäftszeiten durch einen `SubjectUserName`, der kein Service-Konto ist, das automatisiertes Provisioning fährt.
3. **Lookalike-Name**. `Levenshtein(TargetUserName, real_admin_name) <= 2` gegen die existierende Benutzertabelle. `administrato`, `administr0r`, `helpd3sk`. Alle real.
4. **Erstellt durch ein kürzlich kompromittiertes Konto**. 4720, wo `SubjectLogonId` zurück zu einem 4624 von einer ungewöhnlichen IP führt, oder einem 4624 LogonType 3 von einer Workstation, die das Subjekt normalerweise nicht nutzt.
5. **Erstellt durch LocalSystem auf einer Workstation**. 4720 mit `SubjectUserSid = S-1-5-18` auf etwas anderem als einem Domain Controller oder bekannten Provisioning-Server. Fast immer bösartig.
6. **PrimaryGroupId == 512**. Passiert nie im normalen Provisioning. Harter Alarm.

## Sigma

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

Eine hochkonfidenten Variante kombiniert 4720 mit einem 4732 oder 4728 in eine privilegierte Gruppe innerhalb einer Stunde, gescoped per `TargetSid`.

## KQL: 4720 plus Privilegien-Gewährung

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Splunk

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## ATT&CK-Mapping

- T1136.001 Create Account: Local Account. Workstation- und Server-Lokal-Konten.
- T1136.002 Create Account: Domain Account. DC-aufgezeichnete Erstellungen.
- T1136.003 Create Account: Cloud Account. Feuert *kein* 4720. Cloud-Creates leben in Entra-ID-Audit-Logs / Unified Audit Log.
- T1098 Account Manipulation. Wenn 4720 von Gruppen-Eskalation oder Attribut-Änderungen gefolgt wird.

## False Positives, die wie Angriffe aussehen

- Bulk-Migrationstools (ADMT, Quest Migration Manager) erstellen Konten in hohem Tempo mit `SidHistory` gesetzt. Die Form ist identisch zu einem schnellen Angreifer. Baseline bekannte Migrationsfenster.
- Joiner-Pipelines in HR-getriebenen Provisioning-Workflows feuern 4720 zu vorhersehbaren Zeiten. Auf jedes 4720 außerhalb der Geschäftszeiten zu alarmieren begräbt dich in HR-Läufen, die nach Mitternacht überlaufen.
- SCCM-, Intune- und Jamf-artige Management-Tools erstellen lokale Konten für die OS-Bereitstellung. `SubjectUserSid` ist `S-1-5-18` auf bekannten Build-Hosts. Markiere diese.
- Service-Installer für einige Legacy-Produkte erstellen beim ersten Lauf ein lokales Servicekonto. Baseline den Installer.

Solide 4720-Detektionen kombinieren immer den Create mit einem Folge-Signal (Gruppen-Add, Passwortwechsel zu einem bekannten schwachen Muster, sofortiges Login von einem ungewöhnlichen Host). Der einsame Create ist zu laut.

## Was 4720 dir nicht sagt

Der Datensatz enthält nicht das Passwort des neuen Kontos (Windows loggt das nirgends). Er enthält auch nicht die SID der Ziel-Domäne explizit. Du liest die Domäne aus `TargetDomainName` oder leitest sie aus dem Domänen-Teil von `TargetSid` ab.

Lokal-Konten-Creates auf Member-Workstations sind für den DC unsichtbar. Wenn du Security nicht von Workstations sammelst (die meisten Shops tun das nicht), verfehlst du jedes lokale Backdoor-Konto. Sysmon und ein echtes EDR füllen einen Teil der Lücke (File-Create- und Registry-Change-Muster, wenn das lokale SAM berührt wird), aber 4720-Weiterleitung ist die billigste Kontrolle. Der [Registry](https://www.registryparser.com)-Hive-Snapshot ist die Bestätigung, wenn das Log-Forwarding aus war.

## Wo 4720 in eine Timeline passt

Die Lehrbuch-Persistenz-Kette:

1. [4624](/de/blog/understanding-event-id-4624). Erstes Domain-Logon durch einen gephishten Benutzer.
2. [4769](/de/blog/event-id-4769-kerberoasting)-Burst. Kerberoasting gegen Domain-Service-Konten.
3. 4624 als kompromittiertes Service-Konto auf einem Member-Server.
4. [4688](/de/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (oder `New-ADUser` via PowerShell).
5. **4720**. Konto auf dem DC erstellt.
6. 4724. Passwort gesetzt.
7. 4722. Konto aktiviert.
8. 4728. Zu Domain Admins hinzugefügt.
9. [7045](/de/blog/service-creation-event-id-7045). Dienst auf einem Server installiert, läuft unter dem neuen Konto.

Instrumentiere 4720 allein und du fängst die Persistenz in Schritt 5, bevor die Schritte 6 bis 9 irgendeinen Schaden anrichten. Das ist der Wert.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)

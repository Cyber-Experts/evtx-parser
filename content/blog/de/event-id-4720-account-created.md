---
title: "Event-ID 4720 erklärt: heimliche Kontoerstellung in AD erkennen"
description: "4720 feuert jedes Mal, wenn ein Benutzerkonto erstellt wird — lokal oder in AD. Liest du es mit 4722/4724/4732, findest du Persistenz- und Lateral-Movement-Konten innerhalb von Minuten."
date: "2026-05-24"
---

Event-ID **4720** — „Ein Benutzerkonto wurde erstellt" — wird auf den [`Security`-Kanal](/de/blog/what-is-an-evtx-file) geschrieben, sobald ein neues Benutzerkonto angelegt wird. Auf einem Domain Controller feuert es bei jedem neuen AD-Benutzer; auf einer Workstation oder einem Member Server bei jedem neuen lokalen Konto. In einem reifen Shop ist 4720-Traffic überwiegend HR-getrieben und vorhersehbar. Diese Vorhersehbarkeit macht es nützlich: ein Angreifer, der ein Backdoor-Konto anlegt, sticht genau deshalb hervor, weil der legitime Traffic so regelmäßig ist.

Das ist einer der günstigsten Persistenz-Detection-Datensätze, die die Plattform produziert.

## Wo es feuert

- **Domänenkonten**: 4720 landet auf dem DC, der den Create bearbeitet hat. Sammle über alle DCs.
- **Lokale Konten**: 4720 landet auf dem Host, auf dem das Konto erstellt wurde. Das von Member-Workstations einzufangen erfordert WEF oder per-Host-Sammlung — viele Shops überspringen das Workstation-Security-Forwarding und verlieren dieses Signal komplett.

Wenn der Angreifer ein *lokales* Konto auf einem bereits kompromittierten Server anlegt (oft als Backup-Credential), liegt das 4720 nur auf diesem Server. Abdeckung zählt.

## Was der Datensatz enthält

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

Die Felder, die Untersuchungen tragen:

- **`TargetUserName`** — das neue Konto. Der Name selbst ist das erste Triage-Signal: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, Lookalikes legitimer Konten (`administrator`, `administr0r`) und kurze Zufallsstrings verdienen alle einen genaueren Blick.
- **`SubjectUserName` / `SubjectLogonId`** — *wer* es erstellt hat. Pivotiere auf das [4624](/de/blog/understanding-event-id-4624), das diese Sitzung erzeugte. Ein 4720 von `LocalSystem` auf einer Workstation außerhalb der Geschäftszeit ist kein echter Provisioning-Workflow.
- **`UserAccountControl`** — die *initialen* UAC-Flags. `0x10` (im Beispiel) ist `NORMAL_ACCOUNT`; die gefährlichen Flags erscheinen in nachfolgenden 4738 (Konto geändert) Datensätzen. Die volle UAC-Bitmap steht in MS-SAMR.
- **`PrimaryGroupId`** — 513 (Domain Users) ist normal; 512 (Domain Admins) bei einem neuen Konto ist eine schreiend laute Anomalie, die in keinem echten Provisioning-Workflow vorkommen sollte.
- **`SidHistory`** — eine nicht leere `SidHistory` auf einem *neu erstellten* Konto ist ein starkes Zeichen für ein Migrations-Tool — oder, im falschen Kontext, ein gefälschtes Authentifizierungs-Artefakt.

## Die Datensätze, mit denen 4720 nicht allein kommt

Kontoerstellung ist fast nie ein einzelnes Event. Die Mindestsequenz:

| Event | Bedeutung | Warum es zählt |
|---|---|---|
| **4720** | Benutzerkonto erstellt | Die Schlagzeile. |
| **4722** | Benutzerkonto aktiviert | Das Konto ist zum Logon freigegeben. Fehlt 4722, existiert das Konto, kann sich aber noch nicht anmelden. |
| **4724** | Passwort zurückgesetzt (admin-gesteuert) | Jemand — möglicherweise nicht der Ersteller — hat das Passwort gesetzt oder zurückgesetzt. |
| **4738** | Benutzerkonto geändert | UAC-Flags, Ablauf, Gruppe, Attributänderungen. |
| **4732** | Mitglied einer sicherheits-aktivierten lokalen Gruppe hinzugefügt | Wenn die lokale Gruppe `Administrators` ist, ist das die Rechtevergabe. |
| **4728** | Mitglied einer sicherheits-aktivierten globalen Gruppe hinzugefügt | Wenn die globale Gruppe `Domain Admins` oder `Enterprise Admins` ist: Eskalation. |
| **4756** | Mitglied einer sicherheits-aktivierten Universalgruppe hinzugefügt | `Schema Admins`, `Enterprise Admins`, eigene Delegierungen. |

Ein Backdoor-Konto wird selten erstellt und auf Default-Privilegien belassen. Die volle Kette — `4720 → 4722 → 4724 → 4738 (UAC-Flags) → 4732/4728 (Gruppenzugehörigkeit)` — schließt sich innerhalb von Sekunden und ist das eigentliche Persistenz-Event.

## Triage-Muster

1. **Neues Konto → Admin-Gruppe innerhalb von Minuten**: 4720 gefolgt von 4732/4728 in eine privilegierte Gruppe innerhalb einer Stunde, wobei der privilegierten Gruppenhinzunahme *kein* Ticket im Change-Management-System voranging. Paare die `TargetSid` aus 4720 mit `MemberSid` auf 4732/4728.
2. **Außerhalb der Geschäftszeit erstellt**: 4720 außerhalb der Geschäftszeit durch einen `SubjectUserName`, der kein Service-Account mit automatisierter Provisionierung ist.
3. **Lookalike-Name**: `Levenshtein(TargetUserName, real_admin_name) <= 2` gegen die existierende Benutzertabelle. `administrato`, `administr0r`, `helpd3sk` — alles reale Fälle.
4. **Erstellt durch ein kürzlich kompromittiertes Konto**: 4720, dessen `SubjectLogonId` auf ein 4624 von einer ungewöhnlichen IP zurückgeht, oder auf ein 4624 LogonType 3 von einer Workstation, die das Subjekt normalerweise nicht nutzt.
5. **Erstellt durch `LocalSystem` auf einer Workstation**: 4720 mit `SubjectUserSid = S-1-5-18` auf allem außer einem Domain Controller oder bekannten Provisioning-Server. Fast immer bösartig.
6. **`PrimaryGroupId == 512`**: kommt in normaler Provisionierung nie vor. Hard Alert.

## Beispiel-Sigma-Regel

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

Eine High-Confidence-Variante: 4720 mit einem 4732/4728 in eine privilegierte Gruppe innerhalb von 1 Stunde kombinieren, eingegrenzt durch `TargetSid`.

## Beispiel-KQL — 4720 + Rechtevergabe

KQL (Sentinel) — der „neues Konto → Admin-Gruppe"-Pivot:

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

## Beispiel-Splunk

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

- **T1136.001 — Create Account: Local Account** für lokale Konten auf Workstations/Servern.
- **T1136.002 — Create Account: Domain Account** für DC-aufgezeichnete Erstellungen.
- **T1136.003 — Create Account: Cloud Account** — feuert *kein* 4720 (Cloud-Account-Creates liegen in Azure-AD-Audit-Logs / Unified Audit Log, nicht im Windows Security).
- **T1098 — Account Manipulation**, wenn 4720 von Gruppen-Eskalation oder Attributänderungen gefolgt wird.

## False Positives, die genau wie Angriffe aussehen

- **Bulk-Migrationstools** (ADMT, Quest Migration Manager) erstellen Konten schnell mit gesetzter `SidHistory`. Die Traffic-Form ist identisch zu einem schnellen Angreifer; baseline bekannte Migrationsfenster.
- **Joiner-Pipelines** in HR-gesteuerten Provisioning-Workflows feuern 4720 zu vorhersehbaren Zeiten. Wenn du auf jedes Off-Hours-4720 alarmierst, begräbst du dich unter HR-System-Läufen, die über Mitternacht driften.
- **SCCM / Intune / Jamf-artige** Management-Tools erstellen lokale Konten für OS-Provisionierung. Die `SubjectUserSid` ist `S-1-5-18` (LocalSystem) auf bekannten Build-Hosts; markiere diese Hosts.
- **Service-Installer** mancher Legacy-Produkte erstellen beim Erststart ein lokales Service-Account. Baseline den Installer.

Solide 4720-Detections kombinieren den Create immer mit einem Folge-Signal (Gruppen-Hinzunahme, Passwortänderung auf ein bekanntes schwaches Muster, sofortiger Login von einem ungewöhnlichen Host). Der standalone Create ist zu laut.

## Was 4720 dir nicht sagt

Der Datensatz enthält nicht das *Passwort* des neuen Kontos (Windows protokolliert das nirgendwo). Er enthält auch nicht den SID der *Zieldomäne* explizit; die Domäne liest man aus `TargetDomainName` oder leitet sie aus dem Domain-Anteil von `TargetSid` ab.

Lokale Konto-Creates auf Member-Workstations sind für den DC unsichtbar. Wenn du Security von Workstations nicht sammelst (was die meisten Shops nicht tun), entgeht dir jedes lokale Backdoor-Konto. Sysmon und ein echtes EDR füllen einen Teil der Lücke (File-Create- / Registry-Change-Muster, wenn die lokale SAM angefasst wird), aber 4720-Forwarding ist der günstigste Weg.

## Wo 4720 in eine Timeline passt

Die Lehrbuch-Persistenzkette:

1. [**4624**](/de/blog/understanding-event-id-4624) — initiale Domänenanmeldung eines gephishten Benutzers.
2. [**4769**](/de/blog/event-id-4769-kerberoasting)-Burst — Kerberoasting gegen Domänen-Service-Accounts.
3. **4624** als kompromittierter Service-Account auf einem Member Server.
4. [**4688**](/de/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain` (oder dasselbe per PowerShell `New-ADUser`).
5. **4720** — Konto auf dem DC erstellt.
6. **4724** — Passwort gesetzt.
7. **4722** — Konto aktiviert.
8. **4728** — zu Domain Admins hinzugefügt.
9. [**7045**](/de/blog/service-creation-event-id-7045) — Dienst auf einem Server installiert, läuft unter dem neuen Konto.

Wenn du 4720 allein instrumentierst, fängst du die Persistenz in Schritt 5 — bevor Schritte 6-9 Schaden anrichten. Das ist der Wert.

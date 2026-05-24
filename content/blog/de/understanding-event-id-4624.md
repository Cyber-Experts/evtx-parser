---
title: "Windows-Event-ID 4624: jede Anmeldung entschlüsselt"
description: "Was ein 4624-Datensatz wirklich enthält, warum das Feld LogonType wichtiger ist als das Ereignis selbst, und wie man sie skaliert liest."
date: "2026-05-17"
---

Event-ID 4624 — „Ein Konto wurde erfolgreich angemeldet" — wird auf dem `Security`-Kanal jedes Mal protokolliert, wenn Windows eine Identität authentifiziert. Es ist auf den meisten Arbeitsplätzen der häufigste Datensatz und das Rückgrat fast jeder IR-Untersuchung. Ihn lesen zu können ist Pflicht.

## Was steckt in einem 4624-Datensatz

Das Relevante lebt in `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Die `Subject*`-Felder sind der Sicherheitskontext, der die Anmeldung *angefordert* hat (oft `S-1-5-18` für SYSTEM beim Dienststart). Die `Target*`-Felder sind die Identität, die letztlich authentifiziert wurde. Sie zu verwechseln kostet Analysten Stunden.

## LogonType ist das Feld, das zählt

Windows kennt zehn Anmeldetypen; in der Praxis bestimmen nur wenige die Triage:

- **2 — Interactive**: physische oder Konsolen-Anmeldung.
- **3 — Network**: SMB, RPC, WinRM, alles übers Netzwerk. Der Großteil des normalen Traffics.
- **4 — Batch**: geplante Aufgaben unter einem Benutzerkonto.
- **5 — Service**: ein Dienst, der unter einem bestimmten Konto gestartet wurde.
- **7 — Unlock**: Workstation nach Bildschirmsperre entsperrt.
- **8 — NetworkCleartext**: selten, verdächtig — Anmeldedaten im Klartext (Basic auth auf IIS, alte Drucker).
- **9 — NewCredentials**: `runas /netonly`, oft von Angreifern verwendet, um Domänen-Credentials auf einen Host zu tragen, auf dem sie nur lokale Rechte haben.
- **10 — RemoteInteractive**: RDP. Paart sich mit `IpAddress` für die Quellzuordnung.
- **11 — CachedInteractive**: Domänen-Konto mit zwischengespeicherten Credentials (kein DC erreichbar).

Ein 4624 mit LogonType **10** von einer externen IP um 03:00 Uhr an einem Sonntag erzählt eine andere Geschichte als 50 LogonType **3** von einem Backup-Server um 02:00.

## Womit man es verkettet

Ein erfolgreicher 4624 allein ist selten ein Befund. Er wird zu einem in Kombination mit:

- **4625** davor von derselben Quelle — ein Erfolg nach einer Reihe von Fehlversuchen ist die Lehrbuchsignatur für „Brute-Force, dann Erfolg".
- **4672** (besondere Rechte zugewiesen) — markiert Anmeldungen, die Rechte wie `SeDebugPrivilege` gewährt haben; nützlich, um privilegierte Konto-Nutzung zu finden.
- **4648** (Anmeldung mit expliziten Anmeldedaten) — fängt `runas` und andere Credential-Passing-Muster ein.

## Sie skaliert lesen

Der Parser auf dieser Seite extrahiert diese Felder direkt aus dem XML des Datensatzes und stellt sie in der Tabelle dar. Filtere nach `LogonType` über die Zeitleisten-Buckets und den Textfilter (`4624` in der Suche), exportiere das gefilterte Set als CSV und pivotiere in deinem Tool der Wahl auf `SubjectUserSid` + `IpAddress`. Das vollständige XML jedes Datensatzes ist einen Klick entfernt.

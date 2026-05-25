---
title: "Event-ID 4769 erklärt: Kerberos-Service-Tickets und Kerberoasting"
description: "4769 ist die DC-Aufzeichnung jeder Service-Ticket-Anfrage. Lies sie über den Verschlüsselungstyp und du erkennst Kerberoasting; lies sie mit 4768 und du erkennst Pass-the-Ticket."
date: "2026-05-24"
---

Event-ID **4769** — „Ein Kerberos-Service-Ticket wurde angefordert" — feuert auf jedem Domain Controller jedes Mal, wenn ein Konto ein TGS-Ticket (Ticket Granting Service) für einen Service anfordert. Jede SMB-Verbindung, jeder SQL-Login, jeder Web-SSO-Hit produziert eines auf dem DC, der die Anfrage bearbeitet hat. Es ist der Datensatz mit dem höchsten Volumen im [Security-Kanal](/de/blog/what-is-an-evtx-file) auf einem stark genutzten DC — und der einzige Ort, an dem Kerberoasting zuverlässig auftaucht, bevor die Credentials offline geknackt werden.

Wenn du nur drei Security-Datensätze von deinen Domain Controllern instrumentieren darfst, ist das einer davon.

## Wo es lebt

`4769` wird auf den `Security`-Kanal des **ausstellenden Domain Controllers** geschrieben — nicht des Clients und nicht des Zielservice. Um alle 4769-Datensätze einer Domäne zu sehen, musst du von jedem DC sammeln. KAPEs `EventLogs`-Target auf einem DC oder das Forwarden von `Security` per WEF an einen Collector funktionieren beide; die WEF-Route nutzen die meisten reifen Shops.

## Was der Datensatz enthält

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

Die Felder, die die Triage tragen:

- **`TargetUserName`** — der *Anfragende* (das Benutzerkonto in Form `user@DOMAIN`).
- **`ServiceName`** — die angefragte SPN. Ein Benutzerkonto hier (statt `host/...` oder einer Service-Klasse) ist verdächtig.
- **`TicketEncryptionType`** — der Wert, der entscheidet, ob dieser Datensatz zählt. Moderne Domänen fahren `0x12` (AES-256-CTS-HMAC-SHA1-96) oder `0x11` (AES-128). **`0x17` ist RC4-HMAC** — Legacy, schwach und der *einzige* Verschlüsselungstyp, den Mimikatz/Rubeus' `kerberoast`-Modus anfordert. Ein 4769 für ein Service-Account-Ticket mit `0x17` ist ein Lehrbuch-Kerberoasting-Fingerprint.
- **`Status`** — `0x0` ist Erfolg; alles andere bedeutet abgelehnt (Status-Codes dokumentiert in `[MS-KILE]`).
- **`IpAddress`** — der anfragende Host. Paare mit [4624](/de/blog/understanding-event-id-4624) auf diesem Host, um die Anmeldung zu sehen, die die Sitzung erzeugt hat.

## TicketEncryptionType — das Feld, das zählt

Die volle Tabelle, gekürzt:

| Wert | Algorithmus | Status |
|---|---|---|
| 0x01 | DES-CBC-CRC | Per Default deaktiviert seit Win7 |
| 0x03 | DES-CBC-MD5 | Per Default deaktiviert seit Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Modern |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Modern (Default für die meisten Konten) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Für Kerberoasting erforderlich.** |
| 0x18 | RC4-HMAC-EXP | Export-Grade-RC4, extrem selten |

Wenn die Domäne baselined wurde und `msDS-SupportedEncryptionTypes` auf Service-Accounts auf AES-only gesetzt ist, sollte `0x17` für diese Konten gar nicht erscheinen. Angreifer fordern `0x17` explizit an, weil das Knacken RC4-verschlüsselter Service-Tickets rechnerisch billig ist; AES nicht. Das Cracking-Tool braucht den RC4-Hash, also *muss* die Anfrage 0x17 sein.

Das ist das Feld mit dem höchsten Signal im gesamten Datensatz.

## Das Kerberoasting-Muster

Kerberoasting (MITRE T1558.003) funktioniert so:

1. Angreifer authentifiziert sich mit irgendeinem Domänen-Benutzerkonto (keine Admin-Rechte nötig).
2. Angreifer enumeriert SPNs, die an Benutzerkonten (nicht Computer-Konten) registriert sind, typischerweise per LDAP `(servicePrincipalName=*)` gefiltert auf User-Objekte.
3. Angreifer fordert für jedes SPN ein TGS mit `etype=23` (RC4) über das Standard-Kerberos-Protokoll an. **Das ist das 4769, nach dem du suchst.**
4. Der DC stellt das Ticket bereitwillig aus, verschlüsselt mit dem NTLM-Hash des *Service-Accounts*.
5. Angreifer zieht das verschlüsselte Blob aus dem Speicher (oder vom Draht) und knackt es offline mit Hashcat (`-m 13100`).

Der 4769-Fingerprint:

- `ServiceName` ist `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` oder eine beliebige SPN, die auf ein *Benutzerkonto* zeigt (nicht `host/...` oder `cifs/...`, die Computer-Konten sind).
- `TicketEncryptionType` ist `0x17`.
- Ein Burst dieser Anfragen in kurzer Zeit aus derselben Quelle für viele SPNs ist das eindeutige Indiz.

Ein zweites, verwandtes Muster — **AS-REP-Roasting** (T1558.004) — nutzt stattdessen [4768](/de/blog/event-id-4768-kerberos-tgt) (die TGT-Anfrage) und zielt auf Konten mit gesetztem `DONT_REQUIRE_PREAUTH`. Anderer Datensatz, dieselbe Angriffsfamilie.

## Pass-the-Ticket / Golden / Silver Tickets

4769 enthüllt auch Ticket-Fälschungen, aber das Signal ist subtiler.

- Ein 4769 *ohne* vorausgehendes 4768 (TGT-Request) für dieselbe `LogonGuid` aus demselben Host in einem vernünftigen Zeitraum — **Golden-Ticket**-Verdacht. Der Angreifer präsentierte ein gefälschtes TGT und ging direkt zu TGS-Requests über, ohne je ein echtes TGT zu erfragen.
- Ein 4769 *und* die resultierende Service-Authentifizierung am Ziel *ohne* ein auf irgendeinem DC sichtbares 4769 — **Silver-Ticket**-Verdacht. Der Angreifer fälschte das TGS selbst; der DC wurde nie gefragt.
- `LogonGuid`-Mismatch zwischen dem 4624 am Zielservice und dem 4769, das das Ticket angeblich ausgestellt hat — gefälschtes Ticket.

Das sind Detection-by-Absence-Muster, was komplette Log-Abdeckung über alle DCs und Zielservices voraussetzt. Lücken in der WEF-Abdeckung produzieren identisch aussehende False Positives; charakterisiere deine Sammlung, bevor du alarmierst.

## Triage-Workflow

1. Filtere alle 4769 über das DC-Korpus auf `TicketEncryptionType == 0x17`.
2. Gruppiere nach `IpAddress` und nach `TargetUserName` über 30-Minuten-Fenster. Zähle distinct `ServiceName` pro Quelle.
3. >3 distinkte SPNs als 0x17 aus einer Quelle innerhalb von 30 Minuten ist fast überall Kerberoasting.
4. Pivotiere die Quell-IP auf ihr [4624](/de/blog/understanding-event-id-4624) auf dem Ursprungshost — finde das Credential, das den Angriff initiierte.
5. Pivotiere die angefragten SPNs auf die Service-Accounts, denen sie gehören. Rotiere deren Passwörter. Reset geknackter Hashes binnen Stunden, nicht Tagen.

## Beispiel-Sigma-Regel

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

Die `filter_machine`-Klausel schließt Computer-Account-SPNs aus (die immer auf `$` enden); Kerberoasting zielt nur auf User-Account-SPNs.

## Beispiel-KQL / Splunk

KQL (Defender XDR / Sentinel über `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK-Mapping

Das 4769-Korpus deckt ab:

- **T1558.003 — Kerberoasting**: der Schlagzeilen-Use-Case.
- **T1558.001 — Golden Ticket**: 4769 ohne 4768 aus derselben `LogonGuid`.
- **T1558.002 — Silver Ticket**: 4769 fehlt bei beobachteter Service-Auth am Ziel.
- **T1078 — Valid Accounts**: 4769 aus einer unerwarteten IP für ein bekanntes Service-Konto.
- **T1550.003 — Pass the Ticket**: 4769 gefolgt von [4624](/de/blog/understanding-event-id-4624) LogonType 3 mit `LogonProcessName: Kerberos`.

## False Positives, die du sehen wirst

- **Legacy-Anwendungen** (manche alte SQL-Server-Konnektoren, manche Java-/JBoss-Apps) fordern explizit RC4 an. Sie tauchen als stetiger, tagsüber laufender 0x17-Traffic von einem kleinen Set stabiler Hosts auf. Baseline und ausschließen.
- **Pre-AES-Domänen** während eines Kerberos-Hardening-Übergangs emittieren 0x17 breit, bis `msDS-SupportedEncryptionTypes` auf jedem Konto gesetzt ist. Lästig; nicht bösartig.
- **Vulnerability-Scanner** (Tenable, Qualys, BloodHound-Enumeration-Skripte) replizieren Kerberoasting-Traffic. Markiere Scanner-Hosts.
- **Account-Migrationstools** während Cross-Forest-Moves können ungewöhnliche Ticket-Kombinationen anfordern.

Das Signal ist das *Burst*-Muster, nicht der einzelne Datensatz. Stetiges 0x17 von einem Host ist Konfiguration; burstiges 0x17 zu vielen SPNs von einem Host innerhalb von Minuten ist der Angriff.

## Was 4769 dir nicht sagt

Der Datensatz enthält nicht das verschlüsselte Ticket selbst — das Cracking passiert auf dem, was der Angreifer exfiltriert hat, nicht auf dem Draht vom DC. Du kannst aus 4769 allein nicht unterscheiden zwischen „Ticket wurde ausgestellt und nie verwendet" und „Ticket wurde geknackt, Credentials wiederverwendet". Für die zweite Hälfte der Kette brauchst du das resultierende [4624](/de/blog/understanding-event-id-4624) am Zielservice (LogonType 3, AuthenticationPackage Kerberos) und idealerweise [4688](/de/blog/event-id-4688-process-creation) oder [Sysmon 1](/de/blog/sysmon-event-id-1-process-create), die zeigen, was nach der Wiederverwendung des Credentials lief. Behandle 4769 als Kanari, nicht als Alarm.

## Wo 4769 in eine Timeline passt

Klassische Post-Exploitation-Kerberoasting-Kette:

1. [**4624**](/de/blog/understanding-event-id-4624) auf einer Workstation — initialer Zugang über gephishte Benutzer-Credentials.
2. **4769** ×N von dieser Workstation-IP zu einem DC, alle `etype=0x17`, alle gegen User-SPN-Service-Accounts innerhalb von 5 Minuten — Kerberoasting.
3. *(Offline, unsichtbar)* — Angreifer knackt den Hash des schwächsten Service-Accounts in Hashcat.
4. **4768** — TGT-Request als kompromittiertes Service-Account, von einem anderen Host.
5. **4624** LogonType 3 auf einem hochwertigen Server, AuthenticationPackage Kerberos, mit dem Service-Account.
6. [**7045**](/de/blog/service-creation-event-id-7045) — Dienst zur Persistenz unter dem kompromittierten Konto installiert.

Der 4769-Burst in Schritt 2 ist dein frühester, günstigster Detection-Punkt — Stunden oder Tage, bevor der Angreifer als das Service-Account zurückkehrt.

---
title: "Event ID 4769 erklärt: Kerberos-Service-Tickets und Kerberoasting"
description: "4769 ist der DC-Datensatz jeder Service-Ticket-Anfrage. Lies ihn über den Verschlüsselungstyp und du erkennst Kerberoasting. Lies ihn mit 4768 und du erkennst Pass-the-Ticket."
date: "2026-05-24"
---

Event ID **4769**, „Ein Kerberos-Service-Ticket wurde angefordert", feuert auf jedem Domain Controller jedes Mal, wenn ein Konto ein TGS (Ticket Granting Service)-Ticket für einen Dienst anfordert. Jede SMB-Verbindung, jede SQL-Anmeldung, jeder Web-SSO-Treffer erzeugt eins auf dem DC, der die Anfrage behandelt hat. Es ist der volumenstärkste Datensatz im [Security-Kanal](/de/blog/what-is-an-evtx-file) auf einem ausgelasteten DC und der einzige Ort, an dem Kerberoasting zuverlässig auftaucht, bevor die Credentials offline gecrackt werden.

Wenn du nur drei Security-Datensätze von deinen DCs instrumentierst, ist das einer davon.

## Wo es lebt

`4769` wird nur in den Security-Kanal des **ausstellenden Domain Controllers** geschrieben. Nicht der Client, nicht der Zieldienst. Um alle 4769-Datensätze für eine Domäne zu sehen, musst du von jedem DC sammeln. KAPEs `EventLogs`-Target auf einem DC oder das Weiterleiten von Security per WEF an einen Collector funktionieren beide. WEF ist das, was reife Shops nutzen.

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

Die Felder, die Triage treiben:

- `TargetUserName`. Der Anforderer (das Benutzerkonto in `user@DOMAIN`-Form).
- `ServiceName`. Der angeforderte SPN. Ein Benutzerkonto hier (statt `host/...` oder einer Service-Klasse) ist verdächtig.
- `TicketEncryptionType`. Das Feld, das entscheidet, ob dieser Datensatz zählt. Moderne Domänen laufen mit `0x12` (AES-256-CTS-HMAC-SHA1-96) oder `0x11` (AES-128). **`0x17` ist RC4-HMAC**: Legacy, schwach und der *einzige* Verschlüsselungstyp, den Mimikatz und Rubeus' `kerberoast`-Modus anfordern. Ein 4769 für ein Service-Konto-Ticket mit `0x17` ist ein Lehrbuch-Kerberoasting-Fingerabdruck.
- `Status`. `0x0` ist Erfolg. Alles andere ist abgelehnt (Codes in `[MS-KILE]` dokumentiert).
- `IpAddress`. Anfordernder Host. Paare mit [4624](/de/blog/understanding-event-id-4624) auf diesem Host, um die Anmeldung zu sehen, die die Sitzung erzeugt hat.

## TicketEncryptionType: das entscheidende Feld

| Wert | Algorithmus | Status |
|---|---|---|
| 0x01 | DES-CBC-CRC | Standardmäßig seit Win7 deaktiviert |
| 0x03 | DES-CBC-MD5 | Standardmäßig seit Win7 deaktiviert |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Modern |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Modern (Default für die meisten Konten) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Für Kerberoasting erforderlich.** |
| 0x18 | RC4-HMAC-EXP | Export-Grade-RC4, verschwindend selten |

Wenn die Domäne baselined und `msDS-SupportedEncryptionTypes` auf Service-Konten auf AES-only gesetzt ist, sollte `0x17` für diese Konten überhaupt nicht erscheinen. Angreifer fordern `0x17` explizit an, weil das Cracken RC4-verschlüsselter Service-Tickets rechnerisch billig ist. AES nicht. Das Cracking-Tool *muss* 0x17 anfordern.

Das ist das einzelne signalstärkste Feld auf dem Datensatz.

## Das Kerberoasting-Muster

Kerberoasting (T1558.003) funktioniert so:

1. Angreifer authentifiziert sich mit irgendeinem Domain-User (keine Admin-Rechte nötig).
2. Angreifer enumeriert auf Benutzerkonten registrierte SPNs (nicht Computer-Konten), typischerweise per LDAP-`(servicePrincipalName=*)`, gefiltert auf User-Objekte.
3. Angreifer fordert ein TGS für jeden SPN mit `etype=23` (RC4) über das Standard-Kerberos-Protokoll an. Das 4769, nach dem du suchst.
4. Der DC stellt das Ticket fröhlich aus, verschlüsselt mit dem NTLM-Hash des Service-Kontos.
5. Angreifer zieht das verschlüsselte Blob und crackt es offline in Hashcat (`-m 13100`).

Der 4769-Fingerabdruck:

- `ServiceName` ist `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` oder irgendein SPN, der auf ein Benutzerkonto zeigt (nicht `host/...` oder `cifs/...`, was Computer-Konten sind).
- `TicketEncryptionType` ist `0x17`.
- Ein Burst innerhalb eines kurzen Fensters, von derselben Quelle, für viele SPNs.

Ein verwandtes Muster, **AS-REP-Roasting** (T1558.004), nutzt stattdessen [4768](/de/blog/event-id-4768-kerberos-tgt) und zielt auf Konten mit `DONT_REQUIRE_PREAUTH`. Anderer Datensatz, dieselbe Familie.

## Pass-the-Ticket, Golden, Silver

4769 enthüllt auch Ticket-Fälschung, aber das Signal ist subtiler.

- Ein 4769 *ohne* ein vorausgehendes 4768 für dieselbe `LogonGuid` vom selben Host in einem vernünftigen Fenster: Golden-Ticket-Verdacht. Der Angreifer hat ein gefälschtes TGT präsentiert und ist direkt zu TGS-Anfragen gegangen.
- Ein 4769 *und* die resultierende Service-Authentifizierung am Ziel *ohne* sichtbares 4769 auf irgendeinem DC: Silver-Ticket-Verdacht. Der Angreifer hat das TGS selbst gefälscht. Der DC wurde nie gefragt.
- `LogonGuid`-Mismatch zwischen 4624 am Ziel und dem 4769, das das Ticket angeblich ausgestellt hat: gefälschtes Ticket.

Das sind Detection-by-Absence-Muster. Sie erfordern vollständige Log-Abdeckung über alle DCs und Zieldienste. Lücken in der WEF-Abdeckung erzeugen identisch aussehende False Positives. Charakterisiere deine Sammlung, bevor du alarmierst.

## Triage-Workflow

1. Filtere alle 4769 über das DC-Korpus für `TicketEncryptionType == 0x17`.
2. Gruppiere nach `IpAddress` und `TargetUserName` über 30-Minuten-Fenster. Zähle distinct `ServiceName` pro Quelle.
3. Mehr als 3 distinct SPNs als 0x17 von einer Quelle innerhalb von 30 Minuten ist fast überall Kerberoasting.
4. Pivotiere die Quell-IP zu ihrem [4624](/de/blog/understanding-event-id-4624), um die Credential zu finden, die den Angriff gestartet hat.
5. Pivotiere die angeforderten SPNs zu den besitzenden Service-Konten. Rotiere diese Passwörter. Setze gecrackte Hashes innerhalb von Stunden, nicht Tagen, zurück.

## Sigma

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

`filter_machine` schließt Computer-Konto-SPNs aus (die immer mit `$` enden). Kerberoasting zielt nur auf User-Konto-SPNs.

## KQL und Splunk

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

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## ATT&CK-Mapping

- T1558.003 Kerberoasting. Die Schlagzeile.
- T1558.001 Golden Ticket. 4769 ohne 4768 von derselben `LogonGuid`.
- T1558.002 Silver Ticket. 4769 fehlt für eine beobachtete Service-Auth am Ziel.
- T1078 Valid Accounts. 4769 von einer unerwarteten IP für ein bekanntes Service-Konto.
- T1550.003 Pass the Ticket. 4769 gefolgt von [4624](/de/blog/understanding-event-id-4624) LogonType 3 mit `LogonProcessName: Kerberos`.

## False Positives, die du sehen wirst

- Legacy-Anwendungen (einige alte SQL-Server-Connectors, bestimmte Java/JBoss-Apps) fordern explizit RC4 an. Stetiges, tagsüber `0x17` von einer kleinen Menge stabiler Hosts. Baseline und ausschließen.
- Pre-AES-Domänen während einer Kerberos-Härtungs-Transition emittieren breit `0x17`, bis `msDS-SupportedEncryptionTypes` auf jedem Konto gesetzt ist. Nervig. Nicht bösartig.
- Vulnerability Scanner (Tenable, Qualys, BloodHound-Enumerationsskripte) replizieren Kerberoasting-Verkehr. Markiere Scanner-Hosts.
- Konten-Migrationstools können während Cross-Forest-Moves ungewöhnliche Kombinationen anfordern.

Das Signal ist das *Burst*-Muster, nicht der einzelne Datensatz. Stetiges 0x17 von einem Host ist Konfiguration. Burstiges 0x17 zu vielen SPNs von einem Host innerhalb von Minuten ist der Angriff.

## Was 4769 dir nicht sagt

Der Datensatz enthält nicht das verschlüsselte Ticket selbst. Das Cracken passiert auf was auch immer der Angreifer exfiltriert hat, nicht auf der Leitung vom DC. Du kannst aus 4769 allein nicht unterscheiden „Ticket ausgestellt und nie genutzt" von „Ticket gecrackt, Credentials wiederverwendet". Für die zweite Hälfte der Kette brauchst du das resultierende [4624](/de/blog/understanding-event-id-4624) am Zieldienst (LogonType 3, AuthenticationPackage Kerberos) und idealerweise [4688](/de/blog/event-id-4688-process-creation) oder [Sysmon 1](/de/blog/sysmon-event-id-1-process-create), die zeigen, was nach der Credential-Wiederverwendung lief. Behandle 4769 als Kanarienvogel, nicht als Alarm.

## Wo 4769 in eine Timeline passt

Klassische Post-Exploitation-Kerberoasting-Kette:

1. [4624](/de/blog/understanding-event-id-4624) auf einer Workstation. Initial Access über gephishte Benutzer-Credentials.
2. **4769** ×N von dieser Workstation zu einem DC, alle `etype=0x17`, alle gegen User-SPN-Service-Konten innerhalb von 5 Minuten. Kerberoasting.
3. *(Offline, unsichtbar)*. Angreifer crackt den schwächsten Service-Konto-Hash in Hashcat.
4. [4768](/de/blog/event-id-4768-kerberos-tgt). TGT-Anfrage als das kompromittierte Service-Konto, von einem anderen Host.
5. 4624 LogonType 3 auf einem hochwertigen Server, AuthenticationPackage Kerberos.
6. [7045](/de/blog/service-creation-event-id-7045). Dienst zur Persistenz unter dem kompromittierten Konto installiert.

Der 4769-Burst in Schritt 2 ist dein frühester, billigster Detektionspunkt. Stunden oder Tage bevor der Angreifer als Service-Konto zurückkommt.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)

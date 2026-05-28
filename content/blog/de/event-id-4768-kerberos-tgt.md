---
title: "Event ID 4768 erklärt: Kerberos-TGT-Anfragen und AS-REP-Roasting"
description: "4768 ist der DC-Datensatz jedes ausgestellten TGT. Lies ihn über den Result-Code und das Pre-Auth-Flag, und du erkennst AS-REP-Roasting, Brute Force und Missbrauch unconstrained delegation."
date: "2026-05-24"
---

Event ID **4768**, „Ein Kerberos-Authentifizierungsticket (TGT) wurde angefordert", feuert auf einem Domain Controller jedes Mal, wenn jemand ein Ticket Granting Ticket anfordert. Jede Domain-Anmeldung beginnt mit einem davon. Paare es mit [4769](/de/blog/event-id-4769-kerberoasting) (Service Ticket) und du siehst den gesamten Kerberos-Lebenszyklus jedes Kontos im Forest.

Auf einem DC ist 4768 der volumenstärkste Datensatz im [Security-Kanal](/de/blog/what-is-an-evtx-file) nach 4624. Das meiste ist Rauschen. Die hochsignalhaften Scheiben leben in zwei spezifischen Feldern, und eines davon ist der AS-REP-Roasting-Fingerabdruck.

## Wo es feuert

Wie [4769](/de/blog/event-id-4769-kerberoasting) landet 4768 nur auf dem ausstellenden **Domain Controller**. Der Client sieht es nicht. Der Zieldienst sieht es nicht. Um irgendetwas aus 4768 zu erkennen, brauchst du Security-Sammlung von jedem DC. KAPE-Stil für einmalige Engagements, WEF für den Dauerbetrieb.

## Was der Datensatz enthält

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

Die Felder, die zählen:

- `TargetUserName`. Das Konto, das ein TGT anfordert. Immer ein User- oder Computer-Konto. `ServiceName` ist immer `krbtgt`.
- `Status`. Kerberos-Result-Code. `0x0` ist Erfolg. Die Fehlschläge machen 4768 nützlich: `0x6` unbekannter Benutzer, `0x12` Client gesperrt, `0x17` Passwort abgelaufen, `0x18` falsches Passwort.
- `TicketEncryptionType`. Dieselbe Codierung wie 4769: `0x12` und `0x11` AES (modern), **`0x17` RC4** (Legacy, auch der AS-REP-Roasting-Fingerabdruck).
- `PreAuthType`. `2` ist die Standard-Encrypted-Timestamp-Pre-Auth. `0` bedeutet **keine Pre-Auth wurde verwendet** (die AS-REP-Roasting-Voraussetzung). `15`, `16`, `17` sind PKINIT-zertifikatbasierte Pre-Auth-Werte.
- `IpAddress`. Anfordernder Host. Paare mit der clientseitigen [4624](/de/blog/understanding-event-id-4624) für vollen Kontext.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Bei PKINIT (Smartcard- oder Zertifikat-Logon) befüllt. Leer bei passwortbasierten Logons.

## Die zwei Angriffsmuster, die 4768 enthüllt

### AS-REP-Roasting (T1558.004)

Die Schlagzeile. Einige Konten haben `DONT_REQUIRE_PREAUTH` in `userAccountControl` gesetzt (UAC-Bit 22 = `0x400000`). Für diese Konten antwortet der DC auf eine TGT-Anforderung **ohne** die Encrypted-Timestamp-Pre-Auth zu verlangen. Die AS-REP, die er zurückgibt, enthält Material, das ein Angreifer offline cracken kann, um den Passwort-Hash des Kontos wiederherzustellen.

Der 4768-Fingerabdruck eines AS-REP-Roasts im Gange:

- `PreAuthType = 0` (keine Pre-Auth).
- `TicketEncryptionType = 0x17` (RC4, was das Cracking-Tool braucht).
- `Status = 0x0` (der DC hat die AS-REP fröhlich ausgestellt).
- Oft Cluster. Ein Angreifer batched Dutzende Konten, um zu testen, welche Pre-Auth deaktiviert haben.

Echte Konten mit `DONT_REQUIRE_PREAUTH` existieren fast ausschließlich für Legacy-Kompatibilität: sehr alte Unix-Kerberos-Clients, einige uralte Appliances. Sie sind zahlenmäßig winzig und in der Position vorhersehbar. Ein 4768 mit `PreAuthType=0` für ein Konto, das nichts damit zu tun haben sollte, Pre-Auth-loses Kerberos zu nutzen, ist das Signal.

### Passwort-Brute-Force oder Spray

Fehlgeschlagene Kerberos-Pre-Auth produziert 4768 mit `Status=0x18` („falsches Passwort"). Anders als [4625](/de/blog/detecting-4625-brute-force) (das NTLM-Fehler erfasst) ist 4768 dort, wo Kerberos-basierte Passwort-Angriffe landen. Moderne Toolkits (Rubeus, kerbrute) sprechen Kerberos direkt, weil der DC bei NTLM-Versuchen still schneller fehlschlägt, als er Kerberos-Versuche beantwortet, und viele SOCs nur 4625 beobachten.

Der 4768-Brute-Force-Fingerabdruck:

- Viele `Status=0x18`-Datensätze für denselben `TargetUserName` von derselben Quell-IP in einem kurzen Fenster. Brute Force.
- Viele `Status=0x18`-Datensätze über viele `TargetUserName`-Werte von einer Quell-IP, jeder ein- oder zweimal getroffen. Password Spray.
- Ein Burst von `Status=0x6` („unbekannter Benutzer") vor `Status=0x18` von derselben Quelle. User-Enumeration bestätigt, bevor die Brute beginnt.

## Status-Codes, die Triage treiben

| Status | Bedeutung | Lesart |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Erfolg. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Benutzername existiert nicht. Bursts = Enumeration. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Konto gesperrt, deaktiviert oder abgelaufen. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Passwort abgelaufen. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Falsches Passwort. Bursts = Brute Force oder Spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Wird dem Client zuerst auf eine frische TGT-Anfrage zurückgegeben. Echter Erfolg folgt. Allein darauf nicht alarmieren. |
| `0x25` | KRB_AP_ERR_SKEW | Clock-Skew > 5 min. Oft AS-REP-Roasting-Versuche von einem Host mit absichtlich falscher Uhr. |

## Triage-Workflow: AS-REP-Roasting

1. Filtere 4768 über alle DCs für `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Gruppiere nach `IpAddress`. Einzelnes Konto von einem bekannten Migrations-Host ist Konfiguration. Mehrere Konten von einer Quelle ist der Angriff.
3. Pivotiere jeden `TargetUserName` zu seinem `userAccountControl`. Muss `DONT_REQUIRE_PREAUTH` wirklich gesetzt sein? Fast sicher nicht.
4. Quell-IP in [4624](/de/blog/understanding-event-id-4624) auf diesem Host, um die Credential zu finden, die authentifiziert hat, um den Angriff zu starten.
5. Rotiere das Passwort jedes gecrackten Kontos. Entferne `DONT_REQUIRE_PREAUTH` von Konten, die es nicht brauchen.

## Triage-Workflow: Kerberos-Brute-Force

1. Filtere 4768 nach `Status == 0x18`.
2. Gruppiere nach `IpAddress` über 15-Minuten-Fenster. Zähle distinct `TargetUserName`.
3. Mehr als 5 Konten von einer Quelle in 15 Minuten ist Spray. Mehr als 10 Fehler gegen ein Konto im selben Fenster ist Brute Force.
4. Querprüfe gegen `Status == 0x6` von derselben Quelle. Enumeration vor der Brute ist die Lehrbuch-Reihenfolge.

## Sigma: AS-REP-Roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: Kerberos-Password-Spray

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP-Roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK-Mapping

- T1558.004 AS-REP Roasting. Schlagzeilen-Detektion auf `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force und Sub-Techniken `.001` Password Guessing und `.003` Password Spraying. `Status=0x18`-Muster.
- T1558.001 Golden Ticket. Ein gefälschtes TGT umgeht 4768 vollständig. Detektion hier ist per *Abwesenheit*: ein [4769](/de/blog/event-id-4769-kerberoasting) ohne ein vorheriges 4768 von derselben Quelle und im selben Fenster ist der Verdacht.
- T1187 Forced Authentication. In 4768 nicht direkt sichtbar, aber die resultierenden TGT-Anfragen schon.

## False Positives, die wie Angriffe aussehen

- Alte Java- oder Unix-Kerberos-Stacks in Legacy-App-Silos defaulten manchmal auf RC4 ohne Pre-Auth. Sie tauchen als stetiger Tag-Verkehr von einem stabilen Host auf. Baseline.
- PKINIT-Migration während Smartcard-Rollouts. Legitime `PreAuthType=15/16/17`-Wechsel sehen anomal aus, wenn du sie noch nicht gesehen hast. Beobachte das Rollout-Fenster.
- Kerberos-Library-Bugs. Bestimmte Clients fordern TGTs bei Zeit-Skew aggressiv neu an und erzeugen Rauschen. Querprüfe mit `Status=0x25`.
- Domain-Trust-Traversal. Cross-Forest-Authentifizierung produziert 4768 auf jeder Seite. Die `IpAddress` ist ein DC des anderen Forests. Markiere es.

## Was 4768 dir nicht sagt

Der Datensatz enthält nicht das tatsächliche AS-REP-Material, das der Angreifer erbeutet hat (was er offline crackt). Du siehst, dass die Anfrage ausgestellt wurde. Du siehst nicht, welche Daten über die Metadaten hinaus zurückgegeben wurden. Du siehst auch nicht die Client-Perspektive: welche Anwendung die Anfrage gestartet hat, in welchem User-Kontext sie lief. Dafür brauchst du das clientseitige [4624](/de/blog/understanding-event-id-4624) und [4688](/de/blog/event-id-4688-process-creation), wenn `kerbrute.exe` oder Rubeus lokal lief.

Beachte auch, dass 4768 nur für die initiale TGT-Anfrage und bei Erneuerungen feuert. Sobald ein Client ein gültiges TGT gecacht hat, spricht er nicht wieder mit dem KDC für TGT bis zur Erneuerung. Die abgeleiteten Service-Tickets erzeugen [4769](/de/blog/event-id-4769-kerberoasting), nicht 4768. Ein Angreifer, der ein langlebiges TGT stiehlt (Golden Ticket), kann beliebige 4769 ausstellen, ohne je ein weiteres 4768 zu produzieren.

## Wo 4768 in eine Timeline passt

AS-REP-Roasting von Anfang bis Ende:

1. [4624](/de/blog/understanding-event-id-4624). Initiale niedrig-privilegierte Domain-Anmeldung (gephishte Credential).
2. *(LDAP, manchmal ein 4662, wenn SACL gesetzt ist)*. Angreifer enumeriert `userAccountControl` für Konten mit `DONT_REQUIRE_PREAUTH`.
3. **4768**-Burst. `PreAuthType=0`, `etype=0x17`, `Status=0x0` für jedes Kandidatenkonto. Der Detektionspunkt.
4. *(Offline, unsichtbar)*. Angreifer crackt das wiederhergestellte AS-REP-Material in Hashcat (Modus 18200).
5. **4768**. Neue TGT-Anfrage als kompromittiertes Konto, diesmal normal pre-authed.
6. [4769](/de/blog/event-id-4769-kerberoasting). Service-Tickets für alles, was das kompromittierte Konto erreichen kann.
7. [4624](/de/blog/understanding-event-id-4624) LogonType 3 auf dem Zieldienst.

Schritt 3 ist der Kanarienvogel. Schritt 5 und folgende sind die eigentliche Kompromittierung. Das Fenster dazwischen, Minuten bis Tage, ist das einzige Fenster, in dem ein Verteidiger handeln kann, bevor die Credential im freien Lauf lebt.

## Weiterführende Lektüre

- [Microsoft-Dokumentation für 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)

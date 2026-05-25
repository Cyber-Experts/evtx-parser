---
title: "Event-ID 4768 erklärt: Kerberos-TGT-Requests und AS-REP-Roasting"
description: "4768 ist die DC-Aufzeichnung jedes ausgestellten TGT. Lies sie über den Result-Code und das Pre-Auth-Flag und du erkennst AS-REP-Roasting, Brute Force und Missbrauch unconstrained Delegation."
date: "2026-05-24"
---

Event-ID **4768** — „Ein Kerberos-Authentifizierungsticket (TGT) wurde angefordert" — feuert auf einem Domain Controller jedes Mal, wenn jemand ein Ticket Granting Ticket anfordert. Jede Domänenanmeldung beginnt mit einem solchen. Paare es mit [4769](/de/blog/event-id-4769-kerberoasting) (Service Ticket) und du siehst den vollständigen Kerberos-Lebenszyklus jedes Kontos im Forest.

Auf einem DC ist 4768 nach 4624 der Datensatz mit dem höchsten Volumen im [Security-Kanal](/de/blog/what-is-an-evtx-file). Das meiste ist Rauschen; die High-Signal-Slices liegen in zwei bestimmten Feldern — und eines davon ist der AS-REP-Roasting-Fingerprint.

## Wo es feuert

Wie [4769](/de/blog/event-id-4769-kerberoasting) landet 4768 ausschließlich auf dem **ausstellenden Domain Controller**. Der Client sieht es nicht; der Zielservice sieht es nicht. Um aus 4768 etwas zu erkennen, brauchst du Security-Sammlung von jedem DC — KAPE-Style für Einzel-Engagements, WEF für Steady State.

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

- **`TargetUserName`** — das Konto, das ein TGT anfordert. Immer ein Benutzer- oder Computer-Konto; `ServiceName` ist immer `krbtgt`.
- **`Status`** — Kerberos-Result-Code. `0x0` ist Erfolg. Die Fehler machen 4768 nützlich: `0x6` = unbekannter Benutzer, `0x12` = Client gesperrt, `0x17` = Passwort abgelaufen, `0x18` = falsches Passwort.
- **`TicketEncryptionType`** — gleiche Kodierung wie 4769: `0x12`/`0x11` AES (modern), **`0x17` RC4** (Legacy, auch der AS-REP-Roasting-Fingerprint).
- **`PreAuthType`** — `2` ist die Standard-Pre-Auth per verschlüsseltem Zeitstempel; `0` heißt **keine Pre-Auth verwendet** (die AS-REP-Roasting-Voraussetzung); `15`/`16`/`17` sind PKINIT-zertifikatsbasierte Pre-Auth-Werte.
- **`IpAddress`** — anfragender Host. Paare mit dem client-seitigen [4624](/de/blog/understanding-event-id-4624) für vollen Kontext.
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — gefüllt bei PKINIT (Smartcard- / Zertifikatsanmeldung). Leer bei passwortbasierten Anmeldungen.

## Die zwei Angriffsmuster, die 4768 enthüllt

### 1. AS-REP-Roasting (T1558.004)

Der Schlagzeilen-Use-Case. Manche Konten haben das `DONT_REQUIRE_PREAUTH`-Flag im `userAccountControl` gesetzt (UAC-Bit 22 = `0x400000`). Für diese Konten antwortet der DC auf eine TGT-Anfrage **ohne** verschlüsselte Zeitstempel-Pre-Auth zu verlangen — was bedeutet, dass das zurückgegebene AS-REP Material enthält, das ein Angreifer offline knacken kann, um den Passwort-Hash des Kontos zu erhalten.

Der 4768-Fingerprint eines laufenden AS-REP-Roasts:

- `PreAuthType` ist `0` (keine Pre-Auth).
- `TicketEncryptionType` ist `0x17` (RC4 — was das Cracking-Tool braucht).
- `Status` ist `0x0` (der DC hat das AS-REP bereitwillig ausgestellt).
- Oft Cluster: ein Angreifer testet im Batch dutzende Konten, um zu sehen, welche Pre-Auth deaktiviert haben.

Reale Konten mit `DONT_REQUIRE_PREAUTH` existieren fast ausschließlich aus Gründen der Legacy-Kompatibilität (sehr alte Unix-Kerberos-Clients, manche uralten Appliances). Sie sind in der Anzahl winzig und in der Verortung vorhersehbar. Ein 4768 mit `PreAuthType=0` für ein Konto, das *nichts* mit Pre-Auth-loser Kerberos zu tun hat, ist das Signal.

### 2. Passwortbasierte Brute Force / Spray

Fehlgeschlagene Kerberos-Pre-Auth erzeugt 4768 mit `Status=0x18` („falsches Passwort"). Anders als [4625](/de/blog/detecting-4625-brute-force) (das NTLM-Fehler einfängt) ist 4768 dort, wo kerberos-basierte Passwortangriffe landen. Moderne Toolkits (Rubeus, kerbrute) sprechen direkt Kerberos, weil der DC NTLM-Versuche stiller schneller scheitern lässt, als er Kerberos-Antworten gibt — und viele SOCs beobachten nur 4625.

Der 4768-Brute-Force-Fingerprint:

- Viele `Status=0x18`-Datensätze für denselben `TargetUserName` aus derselben Quell-IP in kurzer Zeit — klassische Brute Force.
- Viele `Status=0x18`-Datensätze über viele `TargetUserName`-Werte aus derselben Quell-IP, jedes Konto ein- oder zweimal getroffen — Password Spray.
- Ein Burst von `Status=0x6` („unbekannter Benutzer") vor einem `Status=0x18` aus derselben Quelle — Benutzer-Enumeration bestätigt, bevor die Brute Force startet.

## Die Status-Codes, die du siehst

Die volle Liste ist groß; diese treiben die Triage:

| Status | Bedeutung | Was es draußen meist heißt |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Erfolg. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Benutzername existiert nicht. Bursts = Enumeration. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Konto gesperrt / deaktiviert / abgelaufen. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Passwort abgelaufen. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Falsches Passwort. Bursts = Brute Force oder Spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Wird dem Client *zuerst* bei einem frischen TGT-Request zurückgegeben; ein echter Erfolg folgt. Alarmiere nicht auf diese allein. |
| `0x25` | KRB_AP_ERR_SKEW | Clock-Skew > 5 Min zwischen Client und DC. Oft AS-REP-Roasting-Versuche von einem Host mit absichtlich falscher Uhr. |

## Triage-Workflow — AS-REP-Roasting

1. Filtere 4768 über alle DCs nach `PreAuthType == 0` UND `TicketEncryptionType == 0x17`.
2. Gruppiere nach `IpAddress`. Ein einzelnes Konto von einem bekannten Migrations-Host ist Konfiguration; mehrere Konten von einer Quelle ist der Angriff.
3. Pivotiere jeden `TargetUserName` auf seinen `userAccountControl` — muss `DONT_REQUIRE_PREAUTH` tatsächlich gesetzt sein? Fast sicher nicht.
4. Quell-IP → [4624](/de/blog/understanding-event-id-4624) auf diesem Host, um das Credential zu finden, das sich authentifiziert hat, um den Angriff zu starten.
5. Rotiere das Passwort jedes geknackten Kontos; entferne `DONT_REQUIRE_PREAUTH` von Konten, die es nicht brauchen.

## Triage-Workflow — Kerberos-Brute-Force

1. Filtere 4768 auf `Status == 0x18`.
2. Gruppiere nach `IpAddress` über 15-Minuten-Fenster; zähle distinct `TargetUserName`.
3. >5 Konten von einer Quelle in 15 Minuten ist Spray; >10 Fehler gegen ein Konto im gleichen Fenster ist Brute Force.
4. Quergleiche mit `Status == 0x6` aus derselben Quelle — Enumeration vor Brute Force ist die Lehrbuchreihenfolge.

## Beispiel-Sigma-Regel — AS-REP-Roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## Beispiel-KQL — Kerberos-Password-Spray

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Beispiel-Splunk — AS-REP-Roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## ATT&CK-Mapping

- **T1558.004 — AS-REP Roasting**: die Schlagzeilen-Detection auf `PreAuthType=0 + etype=0x17`.
- **T1110 — Brute Force** und Subtechniken `.001` Password Guessing und `.003` Password Spraying — `Status=0x18`-Muster.
- **T1558.001 — Golden Ticket**: ein gefälschtes TGT umgeht 4768 komplett. Detection hier ist per *Abwesenheit* — ein [4769](/de/blog/event-id-4769-kerberoasting) (TGS-Anfrage) ohne vorausgehendes 4768 aus derselben Quelle/Fenster ist der Verdacht.
- **T1187 — Forced Authentication**: in 4768 nicht direkt sichtbar, aber die resultierenden TGT-Anfragen schon.

## False Positives, die wie Angriffe aussehen

- **Alte Java- / Unix-Kerberos-Stacks** in Legacy-App-Silos defaulten manchmal auf RC4 ohne Pre-Auth. Sie tauchen als stetiger, tagsüber laufender 4768-Traffic von einem stabilen Host auf. Baseline.
- **PKINIT-Migration** während Smartcard-Rollouts: legitime `PreAuthType=15/16/17`-Wechsel sehen anomal aus, wenn du sie vorher nicht gesehen hast. Beobachte das Rollout-Fenster.
- **Kerberos-Library-Bugs**: bestimmte Clients fordern TGTs bei Zeit-Skew aggressiv neu an und erzeugen Rauschen. Quergleiche mit `Status=0x25`.
- **Domain-Trust-Traversal**: Cross-Forest-Authentifizierung erzeugt 4768 auf beiden Seiten. Die `IpAddress` ist ein DC des anderen Forests; markiere ihn.

## Was 4768 dir nicht sagt

Der Datensatz enthält **nicht** das eigentliche AS-REP-Material, das der Angreifer abgegriffen hat (das er offline knackt). Du siehst, dass die Anfrage gestellt wurde; du siehst nicht, welche Daten jenseits der Metadaten zurückgegeben wurden. Du siehst auch nicht die *Client*-Perspektive — welche Anwendung den Request startete, in welchem User-Kontext sie lief usw. Dafür brauchst du das client-seitige [4624](/de/blog/understanding-event-id-4624) (und [4688](/de/blog/event-id-4688-process-creation), wenn `kerbrute.exe` lokal lief).

Beachte auch, dass 4768 nur für die *initiale* TGT-Anfrage und bei Renewals feuert. Sobald ein Client ein gültiges TGT gecached hat, redet er bis zum Renewal nicht mehr mit dem KDC für TGT; die *Service*-Tickets, die er ableitet, erzeugen [4769](/de/blog/event-id-4769-kerberoasting), nicht 4768. Die beiden Datensätze beschreiben verschiedene Stadien desselben Protokolls — und ein Angreifer, der ein langlebiges TGT stiehlt (Golden Ticket), kann beliebige 4769 ausstellen, ohne je ein weiteres 4768 zu produzieren.

## Wo 4768 in eine Timeline passt

Die AS-REP-Roasting-Kette von Anfang bis Ende:

1. [**4624**](/de/blog/understanding-event-id-4624) — initiale niedrig-privilegierte Domänenanmeldung (gephishtes Credential).
2. *(LDAP, manchmal ein 4662, wenn SACL gesetzt ist)* — Angreifer enumeriert `userAccountControl`-Flags für Konten mit `DONT_REQUIRE_PREAUTH`.
3. **4768**-Burst — `PreAuthType=0`, `etype=0x17`, `Status=0x0` für jedes Kandidatenkonto. **Das ist der Detection-Punkt.**
4. *(Offline, unsichtbar)* — Angreifer knackt das gewonnene AS-REP-Material in Hashcat (Mode 18200) und gewinnt das Klartextpasswort.
5. **4768** — neue TGT-Anfrage als kompromittiertes Konto, diesmal normal pre-authed.
6. [**4769**](/de/blog/event-id-4769-kerberoasting) — Service-Tickets für alles, was das kompromittierte Konto erreichen kann.
7. [**4624**](/de/blog/understanding-event-id-4624) LogonType 3 auf dem Zielservice.

Schritt 3 ist der Kanari. Schritt 5 onwards ist die eigentliche Kompromittierung. Das Fenster dazwischen — Minuten bis Tage — ist das einzige Zeitfenster, in dem ein Defender handeln kann, bevor das Credential in freier Wildbahn lebt.

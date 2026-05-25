---
title: "Event-ID 4625 erklärt: Brute Force, Spray und Enumeration erkennen"
description: "4625 ist der Fehlanmeldungs-Datensatz. Richtig gelesen erkennst du Password Sprays, Credential Stuffing und Kerberos-Missbrauch, bevor sie Erfolg haben."
date: "2026-05-17"
---

Event-ID 4625 — „Ein Konto konnte sich nicht anmelden" — feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file), sobald ein Authentifizierungsversuch abgelehnt wird. Es ist der nützlichste einzelne Datensatz, um Credential-Angriffsaktivität aufzuspüren — aber nur, wenn du die richtigen Felder liest.

## Die Felder, die wirklich zählen

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

Die Kombination aus `Status` und `SubStatus` sagt dir, *warum* die Anmeldung scheiterte:

- `0xc0000064` — Konto existiert nicht (Benutzername-Enumeration).
- `0xc000006a` — falsches Passwort (der Klassiker).
- `0xc0000234` — Konto gesperrt.
- `0xc0000072` — Konto deaktiviert.
- `0xc0000071` — Passwort abgelaufen.
- `0xc0000133` — Clock-Skew bei einem Kerberos-Ticket (häufig bei AS-REP-Roasting).
- `0xc000018b` — falscher SID — die Workstation ist nicht in der Domäne, die sie zu sein glaubt.

Ein Burst von `0xc0000064` gegen gültige und ungültige Benutzernamen ist Reconnaissance. Ein Burst von `0xc000006a` gegen ein Konto ist Brute Force. Ein Burst von `0xc000006a` gegen viele Konten mit *demselben Passwort* ist ein Password Spray.

## Die Muster

Die einfachsten Triage-Queries:

1. **Spray-Erkennung**: 4625-Datensätze nach `IpAddress` gruppieren (oder `WorkstationName`, falls die IP nicht aufgezeichnet ist), distinct `TargetUserName` über 10 Minuten zählen. >5 Konten pro Quelle in diesem Fenster ist fast überall verdächtig.
2. **Brute Force**: nach `TargetUserName` gruppieren, Fehlversuche pro Minute zählen. >10 pro Minute gegen ein Konto ist meist ein Bot.
3. **Lockout-Root-Cause**: 4740 (Konto gesperrt) mit den vorangehenden 4625s paaren — das `WorkstationName`-Feld zeigt, welches Gerät das Lockout ausgelöst hat. Das ist kritisch, weil es oft ein domänen-eingebundener Server mit veraltetem gespeichertem Credential ist, nicht ein Angreifer.

## Das „Danach" zählt genauso viel wie das „Davor"

Ein 4625-Burst gefolgt von einem [4624](/de/blog/understanding-event-id-4624) von derselben `IpAddress` ist der handlungsrelevante Fall — der Angreifer hat ein funktionierendes Credential gefunden. Der Parser auf dieser Seite lässt dich die Tabelle nach einer Quell-IP filtern und die Level- und Event-ID-Übergänge in der Zeitleiste über die Zeit beobachten. Das Burst-dann-Spike-Muster ist unverkennbar.

## Beispiel-Sigma-Regel — Password Spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## Beispiel-KQL — Brute Force gegen ein Konto

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Beispiel-Splunk — Enumeration vor Brute Force

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Das Signal ist die *Progression* — Enumeration, um gültige Benutzernamen zu finden, dann Brute Force gegen diese.

## ATT&CK-Mapping

- **T1110.001 — Brute Force: Password Guessing**: ein Konto, viele `0xC000006A`-Fehler.
- **T1110.003 — Brute Force: Password Spraying**: viele Konten, wenige Fehler pro Konto, eine Quelle.
- **T1110.004 — Brute Force: Credential Stuffing**: viele Konten, eine Quelle, oft `0xC0000064` (Konto existiert nicht) für Treffer auf geleakte Listen, durchsetzt mit `0xC000006A`-Treffern.
- **T1078 — Valid Accounts**: 4625 gefolgt von einem [4624](/de/blog/understanding-event-id-4624)-Erfolg aus derselben Quelle = Kompromittierung.
- **T1556 — Modify Authentication Process**: anomaler `LogonProcessName` (alles außer `User32`, `NtLmSsp`, `Kerberos`, `Advapi` oder `Schannel`) deutet auf Authentifizierungs-Manipulation hin.

## False Positives, die wie Angriffe aussehen

- **Veraltete gespeicherte Credentials** nach einem Passwortwechsel. Die gemappten Laufwerke, geplanten Aufgaben oder Dienstkonto-Konfigurationen des Benutzers versuchen weiterhin das alte Passwort. Muster: ein `TargetUserName`, eine `IpAddress` (manchmal ein `WorkstationName`), stetige `0xC000006A`-Kadenz. Jage den Host mit dem veralteten Credential und korrigiere ihn.
- **Fehlkonfigurierte Automation**: ein Skript mit falschem Passwort, das in einer Schleife retried. Gleiches Profil wie Brute Force; sprich mit dem Owner, bevor du alarmierst.
- **Vulnerability Scanner** während authentifizierter Scans produzieren dichten 4625-Traffic. Markiere Scanner-IPs.
- **Lockout-Policy-Fehlkonfiguration**: Helpdesk-Prozesse, die zu aggressiv entsperren, können wiederholende 4625 → 4740 → 4624-Zyklen erzeugen.

## Was du in 4625 nicht siehst

NTLMv2- und Kerberos-Fehler von einem Domain Controller tragen nicht immer eine nutzbare `IpAddress` — das Feld kann leer oder `-` sein. Dafür brauchst du die passenden DC-Events ([4768](/de/blog/event-id-4768-kerberos-tgt)/4771 für Kerberos-Pre-Auth-Fehler) oder Daten auf Netzwerk-Ebene. Schließe nicht „keine Quell-IP, keine Untersuchung" — pivotiere auf den DC-Kanal.

Die Felder `LogonProcessName` und `AuthenticationPackageName` sagen dir, welcher Auth-Stack den Versuch bearbeitet hat. Am nützlichsten: `NtLmSsp` (NTLM), `Kerberos` und `Negotiate` (das eines von beiden wählt). `User32` ist lokale Konsole; `Schannel` ist TLS-basiert.

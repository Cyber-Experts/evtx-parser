---
title: "Event ID 4625 erklärt: Brute Force, Sprays und Enumeration erkennen"
description: "4625 ist der Datensatz für fehlgeschlagene Anmeldungen. Lies ihn richtig und du erkennst Password Sprays, Credential Stuffing und Kerberos-Missbrauch, bevor sie zum Erfolg werden."
date: "2026-05-17"
---

Event ID 4625, „Ein Konto konnte sich nicht anmelden", feuert auf dem [`Security`-Kanal](/de/blog/what-is-an-evtx-file) jedes Mal, wenn ein Authentifizierungsversuch abgelehnt wird. Es ist der einzelne nützlichste Datensatz, um Credential-Angriffe im Flug zu erwischen. Es ist auch der Datensatz, den Analysten am häufigsten falsch lesen, weil die Headline-Nachricht generisch ist und die Antwort zwei Felder tiefer liegt.

## Die Felder, die die Entscheidung bestimmen

Ein typischer Datensatz:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` und `SubStatus` zusammen sagen dir, warum die Anmeldung fehlschlug. Das Paar, um das es wirklich geht, ist `SubStatus`. Die Codes, die es sich zu merken lohnt:

- `0xC0000064`: Konto existiert nicht. Username-Enumeration.
- `0xC000006A`: falsches Passwort. Der Klassiker.
- `0xC0000234`: Konto gesperrt.
- `0xC0000072`: Konto deaktiviert.
- `0xC0000071`: Passwort abgelaufen.
- `0xC0000133`: Clock-Skew bei Kerberos. Häufig bei AS-REP-Roasting-Versuchen, bei denen der Angreifer eine Zeit gefälscht hat.
- `0xC000018B`: falsche SID, die Workstation denkt, sie sei in einer Domäne, in der sie nicht ist. Selten und interessant.

Ein Burst von `0xC0000064` über gemischte gültige und ungültige Benutzernamen ist Reconnaissance. Ein Burst von `0xC000006A` gegen ein Konto ist Brute Force. Ein Burst von `0xC000006A` gegen viele Konten mit *demselben* Passwort ist ein Spray. Dieselbe Event ID, drei verschiedene Vorfälle.

## Die Triage-Abfragen, die sich lohnen

1. Spray-Erkennung. Gruppiere 4625 nach `IpAddress` (oder `WorkstationName`, wenn das IP-Feld leer ist), zähle distinct `TargetUserName` über 10 Minuten. Mehr als fünf Konten pro Quelle in diesem Fenster ist fast überall verdächtig.
2. Brute Force. Gruppiere nach `TargetUserName`, zähle Fehlschläge pro Minute. Mehr als zehn pro Minute gegen ein Konto sind fast immer automatisiert.
3. Lockout-Ursachenanalyse. Paare 4740 (Konto gesperrt) mit den vorausgehenden 4625. Das `WorkstationName`-Feld sagt dir, welches Gerät die Sperrung ausgelöst hat. Meistens ist es ein in der Domäne befindlicher Server mit einer veralteten gecachten Credential, kein Angreifer. Die Triage zählt, weil der Helpdesk beide gleich behandelt und das SOC entscheiden muss, welches zu eskalieren ist.

## Das „danach" entscheidet die Reaktion

Ein 4625-Burst gefolgt von einem [4624](/de/blog/understanding-event-id-4624) von derselben `IpAddress` ist der handlungsbedürftige Fall. Der Angreifer hat ein funktionierendes Credential gefunden. Die Progression in der Timeline ist unverkennbar: dichte Fehler, plötzliches Schweigen, einzelner Erfolg.

## Sigma: Password Spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
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

## KQL: Brute Force gegen ein Konto

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: Enumeration, die in Brute Force übergeht

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Das Signal ist die *Progression*: zuerst Enumeration, um gültige Benutzernamen zu finden, dann gezielte Passwortversuche. Ein echter Operator mit einer frischen Userliste produziert beide Formen innerhalb von Minuten.

## ATT&CK-Mapping

- T1110.001 Brute Force: Password Guessing. Ein einzelnes Konto, viele `0xC000006A`-Fehler.
- T1110.003 Brute Force: Password Spraying. Viele Konten, eine Quelle, wenige Fehler je.
- T1110.004 Credential Stuffing. Viele Konten, eine Quelle, gemischte `0xC0000064` (Konto existiert nicht, Leaked-List-Miss) und `0xC000006A` (Treffer).
- T1078 Valid Accounts. 4625-Burst gefolgt von [4624](/de/blog/understanding-event-id-4624)-Erfolg von derselben Quelle. Kompromittierung.
- T1556 Modify Authentication Process. Anomaler `LogonProcessName` (alles außer `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) deutet auf Manipulation.

## False Positives, die das Kostüm tragen

- Gespeicherte Credentials, die nach einem Passwortwechsel veralten. Die gemappten Laufwerke, geplanten Aufgaben oder Dienstkonfigurationen des Benutzers versuchen das alte Passwort erneut. Die Form ist ein `TargetUserName`, eine `IpAddress`, stetige `0xC000006A`-Kadenz. Finde den Host mit dem veralteten Credential und repariere es vor dem Alarm.
- Falsch konfigurierte Automatisierung. Ein Skript mit dem falschen Passwort in einer Schleife. Dieselbe Form wie Brute Force. Sprich zuerst mit dem Owner.
- Vulnerability Scanner produzieren während authentifizierter Scans dichten 4625-Verkehr. Markiere Scanner-IPs.
- Lockout-Policy-Churn. Helpdesk-Prozeduren, die aggressiv entsperren, erzeugen sich wiederholende 4625-zu-4740-zu-4624-Zyklen. Nervig. Nicht bösartig.

## Was 4625 verbirgt

Kerberos- und NTLMv2-Fehler, die durch einen DC kommen, tragen nicht immer eine nützliche `IpAddress`. Das Feld kann leer oder `-` sein. Dafür pivotierst du auf die Datensätze des DC: [4768](/de/blog/event-id-4768-kerberos-tgt) und 4771 für Kerberos-Pre-Auth-Fehler. „Keine Quell-IP, keine Untersuchung" ist der falsche Instinkt. Schau stattdessen ins DC-Log.

Die Felder `LogonProcessName` und `AuthenticationPackageName` sagen dir, welcher Auth-Stack den Versuch behandelt hat. Nützliche Werte: `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (wählt einen der zwei), `User32` (lokale Konsole), `Schannel` (TLS-gestützt). Alles andere, schau genauer hin.

## Weiterführende Lektüre

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

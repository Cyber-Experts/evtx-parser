---
title: "Event ID 4624 erklärt: erfolgreicher Windows-Logon und LogonType-Referenz"
description: "Was ein 4624-Record tatsächlich enthält, warum das LogonType-Feld wichtiger ist als das Event selbst, und wie man sie im Maßstab liest."
date: "2026-05-17"
---

Event-ID 4624, "Ein Konto wurde erfolgreich angemeldet", landet auf dem [`Security`-Channel](/en/blog/what-is-an-evtx-file) jedes Mal, wenn Windows eine Identität authentifiziert. Es ist der einzelne Record mit dem höchsten Traffic auf den meisten Workstations und das Rückgrat fast jeder IR-Untersuchung. Zu wissen, wie man einen liest, ist nicht optional.

## Was in einem 4624-Record steht

Die interessanten Teile leben in `<EventData>`:

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

Die `Subject*`-Felder sind der Sicherheitskontext, der den Logon *angefordert* hat (oft `S-1-5-18` für SYSTEM während Service-Starts). Die `Target*`-Felder sind die Identität, die letztlich authentifiziert wurde. Die beiden zu verwechseln kostet Analysten Stunden. Ich habe einen Senior-Analysten gesehen, der wegen eines `Subject` eskalierte, das sich als SYSTEM herausstellte, das einen internen Service ausführte. Lesen Sie beide, zweimal, bevor Sie die Entscheidung treffen.

## LogonType ist das Feld, das entscheidet

Windows liefert zehn Logon-Typen. In der Praxis treiben nur eine Handvoll die Triage:

- **2 Interaktiv**. Physischer oder Konsolen-Logon.
- **3 Netzwerk**. SMB, RPC, WinRM, alles über die Leitung. Der überwiegende Teil des normalen Traffics.
- **4 Batch**. Geplante Aufgaben, die als Benutzer laufen.
- **5 Service**. Ein Service, der unter einem spezifischen Konto gestartet wurde.
- **7 Unlock**. Workstation nach Bildschirmsperre entsperrt.
- **8 NetworkCleartext**. Selten und verdächtig. Credentials im Klartext gesendet (Basic auth auf IIS, alte Drucker, fehlkonfiguriertes LDAP simple bind).
- **9 NewCredentials**. `runas /netonly`. Oft von Angreifern verwendet, die Domain-Creds auf einen Rechner tragen, auf dem sie nur lokale Rechte haben.
- **10 RemoteInteractive**. RDP. Paart sich mit `IpAddress` für Source-Attribution.
- **11 CachedInteractive**. Domain-Konto, das mit gecachten Credentials angemeldet ist. Kein DC erreichbar.

Ein 4624 mit LogonType **10** von einer externen IP um 03:00 an einem Sonntag erzählt eine sehr andere Geschichte als 50 LogonType-**3**-Records von einem Backup-Server um 02:00.

## Womit es zu verketten ist

Ein erfolgreiches 4624 allein ist selten ein Befund. Es wird einer, wenn es gepaart wird mit:

- [4625](/en/blog/detecting-4625-brute-force), das ihm von derselben Quelle vorausgeht. Ein Erfolg nach einem Burst von Fehlschlägen ist die Lehrbuch-Brute-Force-dann-Erfolg-Signatur.
- [4672](/en/blog/event-id-4672-special-privileges). Markiert Logons, die Privilegien wie `SeDebugPrivilege` gewährt haben.
- 4648 (Logon mit expliziten Credentials). Erfasst `runas` und andere Credential-Passing-Muster. Die meisten Verteidiger nutzen das zu wenig.
- [7045](/en/blog/service-creation-event-id-7045), das ihm mit LogonType 3 folgt. Service-Installation nach einem Netzwerk-Logon ist die PsExec-Signatur.

## Die fünf Muster

Diejenigen, die tatsächlich Alarme in einem echten SOC auslösen, in grober Reihenfolge, wie oft sie ihren Wert verdienen:

1. **Brute-Force-dann-Erfolg.** Ein Burst von [4625](/en/blog/detecting-4625-brute-force) von einer Quell-IP gefolgt innerhalb von Minuten von einem 4624 von derselben IP für denselben `TargetUserName`. Angreifer fand ein funktionierendes Credential. Billigster Fang im Audit-Katalog.
2. **Off-Hours-RDP.** 4624 mit `LogonType=10` von einer externen IP außerhalb der Geschäftszeiten. Taggen Sie bekannte Admin-VPN-Egress-IPs. Alles andere ist ein echter Hinweis.
3. **`runas /netonly`.** 4624 mit `LogonType=9`. Legitime Nutzung ist selten (Admin-Tools, die Foreign-Domain-Credentials verwenden). Angreifer-Nutzung ist ein Credential-Pivot-Muster nach dem Erfassen von Creds von einem Host, auf dem sie nicht in Erscheinung treten wollen.
4. **NetworkCleartext (LogonType=8).** Klartext-Credentials über die Leitung. Echte Ursachen sind alte Basic-Auth-IIS-Apps, alte Drucker oder fehlkonfigurierte LDAP-Simple-Binds. Jede ist eine Credential-Leak-Haftung.
5. **LogonType-Drift bei Service-Konten.** Ein Service-Konto, das historisch nur LogonType 3 feuert und plötzlich LogonType 10 oder LogonType 2 produziert. Bedeutet fast immer, dass jemand das Service-Konto interaktiv verwendet. Starkes Stolen-Creds-Signal.

## Sigma: erfolgreicher Logon nach Failure-Burst

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source. Brute-force-then-success.
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: windows
  service: security
detection:
  fail_burst:
    EventID: 4625
  success:
    EventID: 4624
    LogonType:
      - 3
      - 10
  timeframe: 10m
  condition: ( fail_burst | count() by IpAddress,TargetUserName > 10 ) and success
falsepositives:
  - Users repeatedly typing passwords after a recent password change
  - SSO endpoints with retry behavior on first auth
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## KQL: Off-Hours-RDP von externen IPs

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and not (IpAddress startswith "172." and toint(split(IpAddress, ".")[1]) between (16 .. 31))
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 7 or Hour > 20
| project TimeGenerated, Account, IpAddress, WorkstationName, Computer
| order by TimeGenerated desc
```

## Splunk: LogonType-Drift bei einem Service-Konto

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

Service-Konten sollten einen einzelnen, stabilen `LogonType` produzieren (üblicherweise 3 oder 5). Mehrere Typen unter demselben Konto sind der Alarm.

## ATT&CK-Zuordnung

- T1078 Valid Accounts (und Unter-Techniken `.001` Default, `.002` Domain, `.003` Local). Jeder erfolgreiche Logon mit einem kompromittierten Credential wird hier abgebildet. 4624 ist der *Beweis* der Technik.
- T1110 Brute Force. Kombiniert mit [4625](/en/blog/detecting-4625-brute-force)-Bursts.
- T1021 Remote Services (`.001` RDP, `.002` SMB, `.006` WinRM). Der Großteil des netzwerkseitigen 4624 LogonType=3/10 Traffics.
- T1550 Use Alternate Authentication Material. `.002` Pass the Hash (NTLM-Paket 4624 von unerwarteter Quelle), `.003` Pass the Ticket (Kerberos-Paket 4624 ohne passendes [4769](/en/blog/event-id-4769-kerberoasting) auf irgendeinem DC).

## Falschpositive, die genau wie Angriffe aussehen

- Schwachstellen-Scanner (Tenable, Qualys, Rapid7) generieren dichten 4624 LogonType=3 Traffic von einem stabilen Set von Scanner-IPs. Taggen und ausschließen.
- SCCM- und Intune-Client-Check-Ins produzieren wiederkehrenden 4624-Traffic zu Management-Endpoints.
- Backup-Agenten authentifizieren sich nach Zeitplan auf vielen Hosts. Sieht aus wie Ausbreitung. Ist es nicht.
- Citrix- und RDS-Multi-Session-Boxen sehen legitim LogonType=10 von vielen internen IPs. Filtern Sie nach Quellbereich.
- Passwortänderungs-UX. Benutzer, die gerade ein Passwort geändert und das alte zweimal eingetippt haben, produzieren 4625 / 4625 / 4624. Das ist nicht Brute Force, das ist Muskelgedächtnis.

Das Signal ist *unerwartete* Wiederholung oder *neue* Kombinationen, nicht rohes Volumen.

## Was 4624 Ihnen nicht sagt

- Keine Prozessinformation. Sie sehen den Logon, nicht was in der resultierenden Session lief. Pivotieren Sie `LogonId` zu [4688](/en/blog/event-id-4688-process-creation) oder [Sysmon 1](/en/blog/sysmon-event-id-1-process-create), um Prozessaktivität zu sehen.
- Kein Source-Prozess für den Logon selbst. Sie wissen, dass NTLM oder Kerberos verwendet wurde, aber nicht, welche Client-App ihn initiiert hat.
- `IpAddress` kann leer oder `-` für NTLM-Logons von einem DC sein. Das Feld ist nicht in jedem Record zuverlässig.
- Cached Interactive Logons (Type 11) passieren, wenn der DC nicht erreichbar ist. Sie bestätigen, dass ein Credential lokal funktioniert hat, nicht, dass das Live-Konto am DC aktiviert ist.

## Im Maßstab lesen

Der Browser-Parser auf dieser Seite extrahiert diese Felder direkt aus dem XML des Records und exponiert sie in der Tabelle. Filtern Sie nach `LogonType` über die Timeline-Buckets und den Text-Filter, ziehen Sie das gefilterte Set als CSV, dann pivotieren Sie auf `SubjectUserSid` und `IpAddress` in Ihrem Tool der Wahl. Das volle XML für jeden Record ist einen Klick entfernt. Paaren Sie es mit [RDP-Cache-Artefakten](https://www.jumplistparser.com), [Recent-File](https://www.recentfilecacheparser.com)-Tracking und [Browser-History](https://www.browserforensics.app), wenn das fragliche Benutzerkonto ein echter Benutzer ist, kein Service.

## Weiterführende Literatur

- [Microsoft-Dokumentation für 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)

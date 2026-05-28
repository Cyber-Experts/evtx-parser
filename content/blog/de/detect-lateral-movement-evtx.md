---
title: "Lateral Movement in Security.evtx erkennen"
description: "Wie echte Angreifer-Tools sich in Windows-Umgebungen von Host zu Host bewegen, und die genauen Event-ID-Kombinationen in Security.evtx, die PsExec, Impacket und WMIExec fangen."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

Lateral Movement ist die Phase, in der die meisten Eindringversuche vom „sie haben einen Fußabdruck" zum „sie besitzen die Domäne" werden. Es ist auch die Phase, in der Windows-Logging am nützlichsten und am irreführendsten ist. Die Ereignisse, die du brauchst, sind alle in `Security.evtx` und `System.evtx`. Sie isoliert zu lesen bringt dich nirgendwohin. Sie in den richtigen Paaren zu lesen, mit der richtigen Cross-Host-Korrelation, ist das, was eine nützliche Timeline von einer Wand aus `4624`s trennt.

Das ist der Teil einer Untersuchung, in dem ich aufhöre zu scrollen und anfange, nach `LogonId` zu greppen.

## Das Gerüst: was passiert, wenn ein Angreifer sich bewegt

Es gibt kein universelles Lateral-Movement-Muster, aber es gibt eine universelle *Form*:

1. Der Angreifer authentifiziert sich von Host A auf Host B, entweder mit dem Token des aktuellen Benutzers (Pass-the-Hash, Pass-the-Ticket oder ein gestohlenes Kerberos-TGT/TGS) oder mit expliziten Credentials für ein anderes Konto.
2. Etwas auf Host B führt ihre Payload aus: ein Dienst, eine geplante Aufgabe, ein WMI Process Create, eine Remote-PowerShell-Sitzung oder eine DCOM-Invocation.
3. Sie greifen zurück für Tooling, Geheimnisse oder den nächsten Hop.

Jeder Schritt hinterlässt Ereignisse. Die Frage ist, ob du die richtigen anschaust, und ob das Tooling überhaupt instrumentiert wurde.

## 4624 LogonType 3 ist die Eingangstür

Eine erfolgreiche Netzwerk-Anmeldung, `EventID=4624` mit `LogonType=3`, ist das mit Abstand häufigste Lateral-Movement-Primitiv im Log. Es ist auch das lauteste Ereignis, das Windows erzeugt. Ein Fileserver in einem Büro mit 500 Plätzen produziert davon Zehntausende pro Tag, alle legitim. Nur nach `LogonType=3` zu filtern bringt dich nirgendwohin.

Was dich weiterbringt:

- `IpAddress` und `WorkstationName` in den Event-Daten. Hier clustern Anomalien. Eine Workstation, die sich um 02:14 UTC von einem anderen Subnetz an einem Server anmeldet, ist nicht nichts.
- `AuthenticationPackageName` und `LogonProcessName`. NTLM-Anmeldungen (`NTLM` / `NtLmSsp`) zwischen Hosts in einer Kerberos-Umgebung sind standardmäßig verdächtig. Eine saubere Kerberos-Umgebung sollte für Intra-Domain-Auth Kerberos-only sein, mit NTLM-Fallback nur für Nicht-DNS-Namen-Zugriffe und Legacy.
- `TargetUserName`-Muster. Dienstkonten, die sich interaktiv anmelden, sind rote Fahnen. Domain-Admin-Konten, die sich an Workstations anmelden, sind rote Fahnen.

Der Pivot, den du willst: jede interessante `4624 Type 3` mit der passenden `4672` (Special Privileges) auf derselben `TargetLogonId` paaren. Wenn die Anmeldung Admin-Rechte bekommen hat, hast du einen Kandidaten für Credential-Missbrauch. Wenn nicht, operiert der Angreifer mit einem niedriger privilegierten Token und du hast Zeit.

## 4648 ist das Ereignis, das die meisten Verteidiger zu wenig nutzen

`4648`, „Eine Anmeldung wurde mit expliziten Anmeldeinformationen versucht", wird erzeugt, wenn ein Prozess, der als Konto A läuft, Credentials für Konto B aufruft, um etwas zu tun. Das ist das Ereignis, das du für Attribution willst. Wenn `mimikatz` oder `Rubeus` ein Ticket injiziert und der Operator `net use \\TARGET /user:CORP\admin <pass>` ausführt, bekommst du ein `4648` auf dem ursprünglichen Host, das beide Konten und das Ziel zeigt.

Die Felder, die zählen:

- `SubjectUserName` / `SubjectLogonId`: wer initiiert hat.
- `TargetUserName` / `TargetServerName`: wessen Credentials, gegen was.
- `ProcessName`: welches Binary den Aufruf gemacht hat. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (für WMI-basierte Ausführung) und zunehmend `pwsh.exe` sind die üblichen Verdächtigen.

`4648` ist das Bindeglied zwischen einem kompromittierten Host und dem nächsten Hop. Wenn du einen verdächtigen Host hast, dumpe `4648` aus seinem Security-Log zuerst. Es wird dir sagen, welche Credentials der Angreifer hat und wo er sie zu nutzen versuchte, in Zeitreihenfolge, an einem Ort.

## 4672 und die Privilegien-Geschichte

`4672` wird sofort nach `4624` für jede Anmeldung abgelegt, die mit mindestens einem sensiblen Privileg endet (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege` usw.). Es wird für jede Anmeldung eines Mitglieds von `Administrators`, `Domain Admins` oder eines Kontos mit token-erhöhenden Privilegien erzeugt.

Behandle es als Tag, nicht als Befund. Die nützliche Abfrage ist „zeige mir jede `4672`, gefolgt innerhalb von 60 Sekunden von einer `4624 Type 3` von einer Nicht-DC-Quell-IP", was Admin-Token-Nutzung von Workstations zutage fördert, die keine ausstellen sollten. Die nicht-nützliche Abfrage ist „zeige mir jede `4672`", die jeden Dienststart auf jedem Server zurückgibt.

## 4697 und 7045: Dienste als Remote Execution

PsExec, Impackets `psexec.py` und `smbexec.py` arbeiten, indem sie eine Dienst-Binary auf den `ADMIN$`-Share des Ziels schreiben, sie über den Service Control Manager registrieren, starten und abbauen. Das hinterlässt:

- `5145` auf dem Ziel, das den Zugriff auf `\\target\ADMIN$` mit dem geschriebenen Dateinamen zeigt (wenn Object Access Auditing an ist).
- `7045` in `System.evtx`, das die Dienstinstallation zeigt. Der Pfad der Dienst-Binary und der Dienstname stehen in den Event-Daten. PsExec verwendet standardmäßig `PSEXESVC` in `%SystemRoot%`; Impacket randomisiert beide, mit Mustern, die je nach Version variieren und gut dokumentiert sind.
- `4697` in `Security.evtx` für dieselbe Dienstinstallation, wenn du die System-Audit-Policy gesetzt hast.
- `4624 Type 3` von der Quell-Workstation des Operators.

Die Signatur ist die *Kombination*: `4624 Type 3` von einer ungewöhnlichen Quelle, unmittelbar gefolgt von `5145` auf `ADMIN$`, unmittelbar gefolgt von `7045` für einen Dienst, dessen Binary irgendwo liegt, wo sie nicht hingehört. Jedes Ereignis allein ist plausibel. Die Kombination, innerhalb von Sekunden, mit derselben verknüpfenden `LogonId`, ist es nicht.

Dienstnamen, auf die man in `7045` achten sollte: zufällige 8-Zeichen-Kleinbuchstaben-Strings (Impacket-Default), `PSEXESVC` (PsExec-Default), `WinExec` oder seine Varianten, alles mit einem Binary-Pfad unter `C:\Windows\`, das nicht signiert und nicht im normalen Dienste-Set des Systems ist.

## 5140 und 5145: SMB-Share-Zugriff im Detail

`5140` protokolliert, dass ein Share zugegriffen wurde; `5145` protokolliert den im Share zugegriffenen Dateinamen, *wenn* Object Access Auditing für den Share aktiviert ist. Die meisten Umgebungen aktivieren `5145` wegen des Lärms nicht. Die meisten Umgebungen wünschen sich auch, sie hätten es während eines Vorfalls.

Für Lateral Movement sind die `5145`-Ereignisse, die zählen, Zugriffe auf `ADMIN$`, `C$`, `IPC$` und alle `SYSVOL`/`NETLOGON`-Pfade von ungewöhnlichen Quellen. `psexec.py` schreibt seine Dienst-Binary, indem es nach `\\target\ADMIN$\<random>.exe` schreibt. `secretsdump.py` liest `\\target\C$\Windows\System32\config\SAM` (und SYSTEM und SECURITY). Jeder davon ist ein `5145` mit einem `RelativeTargetName`, das auffallen sollte.

Paare `5145` mit dem [USN-Journal](https://www.usnparser.com) auf dem Ziel. Das Journal hat ein `FILE_CREATE` für dieselbe Datei mit demselben Zeitstempel, was dir eine Zweitquellen-Bestätigung gibt, dass die Datei tatsächlich gelandet ist, und einen [MFT](https://www.mftparser.com)-Datensatzverweis zum Verfolgen.

## WMI als Lateral-Movement-Vektor

WMI-basierte Remote Execution (`wmic /node:... process call create`, Impackets `wmiexec.py`, PowerShell `Invoke-WmiMethod`) ist in Security.evtx allein schwerer zu erkennen, weil sie keinen Dienst installiert. Du bekommst:

- `4624 Type 3` auf dem Ziel.
- Einen Process Create auf dem Ziel mit `WmiPrvSE.exe` als Parent. Das ist in Sysmon `EventID=1`, wenn Sysmon an ist. In `4688` ist es dasselbe Bild, wenn Command-Line-Auditing an ist.
- WMI-Ereignisse in `Microsoft-Windows-WMI-Activity%4Operational.evtx`, die den Consumer zeigen.

Wenn Sysmon nicht an ist, ist WMI-basiertes Lateral Movement in den Default-Config-Event-Logs meist unsichtbar. Das ist einer der Gründe, warum jede Konfig-Baseline Sysmon hart pusht.

## Cross-Host-Korrelation

Lateral Movement ist ein Graphproblem. Ein `4648` auf Host A, das Host B und Konto `corp\admin` nennt, ist eine Kante. Das passende `4624 Type 3` auf Host B von Host As IP, mit `TargetUserName=admin`, ist das andere Ende derselben Kante. Das `4769` (Kerberos Service Ticket) auf dem DC, das die Ticketanforderung für `cifs/hostB` von `admin@CORP` zeigt, ist der dritte Zeuge.

In der Praxis willst du alles von:

- Anmeldungs-Ereignissen aus der `Security.evtx` des Quell-Hosts.
- Anmeldungs-Ereignissen aus der `Security.evtx` des Ziel-Hosts.
- TGT-Ereignissen (`4768`) und TGS-Ereignissen (`4769`) aus der `Security.evtx` des Domain Controllers.
- Weitergeleiteten Ereignissen von jedem WEC-Collector, die manchmal die einzige intakte Kopie sind, wenn das lokale Log eines Hosts geleert wurde.

Verknüpfe sie per `LogonId` innerhalb eines Hosts und per Zeitstempel + Konto + IP über Hosts hinweg. Das klassische JPCERT/CC-Paper legt das im Detail dar und ist das einzige beste kostenlose Dokument zu dem Thema.

Für die hostseitigen Artefakte, die das Log-Löschen überleben, stütze dich auf [Prefetch](https://www.prefetchparser.com) für den Nachweis der Ausführung von Angreifer-Tooling, den `Services`-Schlüssel der [Registry](https://www.registryparser.com) für die Spur einer installierten und entfernten Dienst-Binary und [LNK-Dateien](https://www.lnkparser.com) sowie [Jump Lists](https://www.jumplistparser.com) für den Nachweis von Dateien, die ein Operator in einer Hands-on-Sitzung geöffnet hat.

## Weiterführende Lektüre

- JPCERT/CCs ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/). Die Referenz. Lies sie zweimal.
- Die MITRE ATT&CK [Lateral-Movement-Matrix](https://attack.mitre.org/tactics/TA0008/) und die Per-Technique-Datenquellen-Mappings.
- Das Impacket [examples-Verzeichnis](https://github.com/fortra/impacket/tree/master/examples). Wenn du nicht gelesen hast, was `psexec.py`, `wmiexec.py` und `smbexec.py` tatsächlich auf der Leitung tun, sind deine Detektionen Vermutungen.

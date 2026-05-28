---
title: "Sysmon-Konfiguration, die echte Angreifer fängt"
description: "Eine meinungsstarke Sichtweise auf Sysmon: welche Event-IDs in IR tatsächlich wichtig sind, warum olafhartong/sysmon-modular die richtige Baseline ist, und die Konfigurationsfehler, die Sie für echte Angriffe blind machen."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon ist die einzige Sache mit dem höchsten Hebel, die Sie auf einem Windows-Endpoint einsetzen können. Es ist kostenlos, von Microsoft signiert, und ein gut konfiguriertes Sysmon verwandelt Windows von einer Blackbox in etwas, das Sie tatsächlich untersuchen können. Ein schlecht konfiguriertes Sysmon ist andererseits derselbe Festplattenplatz-Kostenaufwand, wobei der Großteil der Sichtbarkeit durch übermäßig aggressive Filter ausgeschlossen ist. Ich bin in mehr Umgebungen mit dem zweiten als dem ersten gelaufen.

Das ist die Konfigurationshaltung, für die ich in jedem Engagement plädiere, das Endpoint-Sichtbarkeit berührt.

## Die EIDs, die ihren Festplattenplatz verdienen

Sysmon definiert ab Version 15 29 Event-IDs. Sie brauchen nicht alle. Diejenigen, die den Speicher zurückzahlen, den sie kosten, in der Reihenfolge der Rendite pro Byte:

- **EID 1 Process create**. Das einzige nützlichste Event in DFIR. Elternprozess, Kindprozess, Befehlszeile, Integritätsstufe, Benutzer, beide Prozess-Hashes und die Prozess-GUID. Wenn Sie sonst nichts von Sysmon loggen, loggen Sie das.
- **EID 3 Network connection**. Jede ausgehende TCP/UDP-Verbindung mit Quellprozess, Ziel-IP, Port und Prozess-Image. Das C2-Detection-Event. Filter ist hier essentiell (eine Standardinstallation loggt jeden Browser-Request und Ihre Retention brennt in einer Woche), aber der Wert pro Event ist extrem. Fangen Sie Ausgehendes zu ungewöhnlichen Zielen von ungewöhnlichen Prozessen (`rundll32.exe` zu einer Wohn-IP, `mshta.exe` zu allem).
- **EID 7 Image loaded**. DLL- und Treiber-Loads mit dem geladenen Image-Hash und Signing-Status. So fangen Sie DLL Search-Order-Hijacking, Sideloading und unsignierte Treiber. Teuer, alles zu loggen; günstig und ertragreich, unsignierte Module und Module aus nicht-standardmäßigen Orten zu loggen.
- **EID 10 Process accessed**. Cross-Process-Memory-Access-Events mit dem Quellprozess, Zielprozess, gewährter Access-Mask und dem Call-Trace. Das ist das Credential-Dumping-Event. `mimikatz` öffnet `lsass.exe` mit `PROCESS_VM_READ` (`0x10`) und `PROCESS_QUERY_INFORMATION` (`0x400`). Jeder moderne Dumper tut das. Die Detection schreibt sich selbst.
- **EID 11 File created**. Neue Datei-Erstellungen mit dem schreibenden Prozess. Fängt Dropper-Aktivität, die nicht zur Ausführung kam, Ransomware-Staging und die meisten LOLBin-vermittelten Payload-Schreibvorgänge.

Diese fünf sind das Fundament. Wenn Sie nur diese haben, gut konfiguriert, haben Sie das meiste gefangen, was Sie ein echtes Eindringen nennen würden, bevor es eines wurde.

Die nächste Stufe, die es wert ist eingeschaltet zu werden:

- **EID 8 CreateRemoteThread**. Thread-Injection über Prozessgrenzen hinweg. Das klassische Process-Injection-Event.
- **EID 13 Registry value set**. Persistenz via Registry. Tunen Sie auf die Run-Keys, Services, Image File Execution Options und die COM-Hijack-Pfade.
- **EID 17/18 Named pipe created/connected**. Cobalt-Strike-Beacons und viele Post-Exploitation-Frameworks verwenden Named Pipes für SMB und Inter-Prozess-Comms. Die Pipe-Namen sind oft Defaults, die Engagement zu Engagement überleben.
- **EID 22 DNS query**. Ausgehende DNS mit dem anfragenden Prozess. Fängt DNS-basiertes C2 (DGA, DNS-Tunnel), wenn EID 3 die Verbindung verpasst hat, weil sie nie einen TCP/UDP-Socket geöffnet hat.
- **EID 25 Process tampering**. Image-Manipulationsevents (Process Hollowing, Doppelganging). Sysmon 13+.

EID 12 (Registry key/value create), 14 (Registry key/value renamed), 15 (file stream created mit FileCreateStreamHash) und 23 (file delete mit Archive) sind in spezifischen Untersuchungen nützlich, produzieren aber zu viel Volumen, um überall standardmäßig geloggt zu werden. Schalten Sie sie für einen Host ein, den Sie genau beobachten, oder für spezifische Pfade.

EID 2 (process changed file creation time) ist ein Nischen-Anti-Timestomp-Event. Wert auf Dateiservern. Optional anderswo.

EID 4, 5, 6 (Sysmon-State-Events) sind operativ, nicht Detection. Loggen Sie sie, damit Sie sagen können, wann Sysmon manipuliert wurde.

## Warum `olafhartong/sysmon-modular` der richtige Ausgangspunkt ist

Es gibt ein halbes Dutzend öffentlicher Sysmon-Configs unterschiedlicher Qualität. Die zwei meistzitierten sind SwiftOnSecuritys `sysmon-config` und Olaf Hartongs `sysmon-modular`. Beide sind gut. `sysmon-modular` ist das, was ich wegen seiner Struktur empfehle.

Das modulare Layout teilt Filter nach EID und Technik in einzelne XML-Dateien auf, die beim Deployment verkettet werden. Die Vorteile, die das bietet:

- **Diffierbarkeit**. Änderungen am Filter einer einzelnen Technik erscheinen als Single-File-Diff in Git. Vergleichen Sie das mit einem 4000-Zeilen monolithischen XML, wo eine kleine Änderung im Rauschen verschwindet.
- **Pro-Umgebung-Overlays**. Sie committen den Upstream-Tree und layern Ihre umgebungsspezifischen Ausschlüsse in Ihren eigenen Dateien darauf. Wenn Upstream einen Filter aktualisiert, machen Sie `git merge` und Ihre Overlays überleben.
- **Coverage-getriebene Autorenschaft**. Filter sind nach MITRE ATT&CK Technik organisiert. Sie können auf einen Blick sehen, für welche Techniken Sie Abdeckung haben und für welche nicht. Die Gap-Analyse ist der File-Tree.
- **Aktive Wartung**. Hartong aktualisiert das Repo gegen neue Techniken und neue Sysmon-Versionen. Die SwiftOnSecurity-Config hat lange Stagnationsphasen zwischen Updates.

Beginnen Sie mit `sysmon-modular`. Committen Sie es in Ihren Konfigurationsverwaltungs-Tree. Layern Sie Ihre Ausschlüsse. Schreiben Sie Ihre eigene nicht von Grund auf; Sie werden Dinge übersehen.

## Die Konfigurationsfehler, die Sie blind machen

Die Muster, die ich in echten Engagements sehe, die am meisten Sichtbarkeit kosten:

**Zu aggressives Ausschließen bei EID 1**. Der Instinkt ist, jeden geschwätzigen legitimen Prozess auszuschließen, um das Volumen verwaltbar zu halten. Der Fehler ist, nach Elternpfad oder Image auszuschließen, ohne darüber nachzudenken, was ein Angreifer von diesem Elternprozess spawnen kann. Wenn Sie jedes Kind von `services.exe` ausschließen, haben Sie genau den Ort ausgeschlossen, wo PsExec-installierte Service-Binärdateien laufen. Schließen Sie nach `User` (System-Konten, die bekanntermaßen gute Binärdateien ausführen), nach `IntegrityLevel` und nach präziser `CommandLine`-Übereinstimmung aus, nicht allein nach Eltern.

**EID 3 nach Image-Namen ausschließen**. "Alle Netzwerkverbindungen von `chrome.exe` ausschließen" ist die kanonische schlechte Regel. Das Erste, was ein Angreifer tut, wenn er EID-3-Logging umgehen muss, ist einen Browser-Prozess zu hijacken. Schließen Sie nach Ziel-IP-Range aus (RFC1918 zu RFC1918, Ihre eigene Infrastruktur), nach Port (das IPC-Port-Set, das Sie validiert haben), oder nach Prozess+Ziel-Tupel. Niemals nach Image allein.

**EID 7 überhaupt nicht loggen**. Image-Load-Logging ist die schwerste Sysmon-EID nach Volumen. Die Versuchung, es zu deaktivieren, ist stark. Die Kosten des Deaktivierens sind, dass DLL-Sideloading, die einzige häufigste Technik in modernen Eindringungen, für Sie unsichtbar ist. Der mittlere Weg: filtern Sie `Image load` auf unsignierte Module, Module geladen aus `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%` und `%PROGRAMDATA%`, und Module mit Namen, die bekannten Missbrauchslisten entsprechen. Das senkt das Volumen um eine Größenordnung und behält das Signal.

**EID 11 auf benutzerbeschreibbaren Pfaden völlig fehlen**. EID 11 geloggt für `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%` und `%PUBLIC%` fängt fast jeden Dropper. Einige Configs schließen diese wegen Volumen aus. Das Volumen ist der Punkt: das ist, wo die wichtigen Schreibvorgänge passieren.

**Den gewünschten Hash-Algorithmus nicht einbeziehen**. Das `<HashAlgorithms>`-Element steuert, welche Hashes Sysmon berechnet. Standard ist nur SHA1. `IMPHASH` ist der Import-Hash, stark bei Malware-Tracking verwendet; `SHA256` ist, was die meisten Threat-Intel-Plattformen als Schlüssel verwenden. Setzen Sie `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>`, damit die Events mit dem übereinstimmen, was Ihre Intel-Daten verwenden.

**Befehlszeilen am Eltern nicht loggen**. Sysmon EID 1 loggt sowohl `CommandLine` (Kind) als auch `ParentCommandLine` (Eltern). Einige Configs deaktivieren `ParentCommandLine`. Das tötet den nützlichsten Pivot bei Prozess-Tree-Untersuchungen; ohne das haben Sie einen Eltern-Image-Namen, aber keine Ahnung, welche Argumente diesen Eltern gestartet haben.

**EID 22 (DNS) überhaupt nicht aktivieren**. DNS-Logging ist neu (Sysmon 10+) und viele Configs sind älter. Schalten Sie es ein. Filtern Sie geschwätzige Hosts (`*.windowsupdate.com`, Ihr internes AD), loggen Sie alles andere.

## Der Festplattenplatz-Trade-Off

Ein gut konfiguriertes Sysmon auf einer typischen Workstation produziert 100-500 MB EVTX pro Tag. Auf einem beschäftigten Server, 1-5 GB. Die Standard-Channel-Größe ist 64 MB, was bedeutet, dass die `Microsoft-Windows-Sysmon%4Operational.evtx`-Datei in Stunden rolliert und Ihre nutzbare Retention kurz ist.

Die Korrektur ist zweistufig. Erstens, erhöhen Sie die Channel-Größe. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` setzt sie auf 4 GB, was Ihnen auf den meisten Hosts Tage bis Wochen gibt. Zweitens, leiten Sie an einen zentralen Collector mit längerer Retention weiter. WEC funktioniert; SIEM-Agenten funktionieren; das [Sysmon-modular WEC-Subscription](https://github.com/olafhartong/sysmon-modular) Repo hat das XML für die Channel-Subscription.

Zentralisierte Retention ist wichtiger als lokale Retention, weil die lokale Datei das ist, was der Angreifer clearen kann. Eine weitergeleitete Kopie an einem Collector, den er nicht erreichen kann, ist der dauerhafte Datensatz. Konfigurieren Sie beides.

## Wie gutes Sysmon in einer Untersuchung aussieht

Ein Host mit deployedem `sysmon-modular`, allen fünf Core-EIDs loggend, EID 7 auf interessante Module gefiltert und an einen Collector weiterleitend, gibt Ihnen:

- Einen Prozess-Tree für jede Ausführung auf dem Host, mit Befehlszeilen, Hashes und dem Benutzerkontext.
- Jede ausgehende Netzwerkverbindung mit dem ursprünglichen Prozess.
- Jeden DLL-Load aus einem benutzerbeschreibbaren Verzeichnis.
- Jeden Memory-Access gegen `lsass.exe`.
- Jede Datei-Erstellung in `%TEMP%` und `%APPDATA%`.
- Jede DNS-Abfrage mit dem anfragenden Prozess.

Die Eindringungs-Story liest sich selbst aus diesen Daten. Sie müssen nicht raten. Sie müssen nicht carven. Sie lesen sie von oben nach unten, und die Lücken in der Story sind die Fragen, die zu jagen sind. Cross-referenzieren Sie mit [AmCache](https://www.amcacheparser.com) und [Prefetch](https://www.prefetchparser.com) für Binär-Ausführungsbeweise, der [Registry](https://www.registryparser.com) für Persistenz und dem [USN-Journal](https://www.usnparser.com) für die Dateisystem-Mutationen, die Sysmons EID 11 verpasst haben könnte, wenn sein Filter aus war. Der Parser auf dieser Seite liest Sysmon-Channels mit derselben Treue wie Security.evtx.

Ohne Sysmon haben Sie `Security.evtx` und eine Wunschliste.

## Weiterführende Literatur

- Olaf Hartongs [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Das Repo. Lesen Sie die README, dann drei oder vier der technik-spezifischen XML-Dateien, um ein Gefühl für den Filter-Style zu bekommen.
- Microsofts [Sysmon-Dokumentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). Die offizielle Referenz; dünn, aber genau.
- Roberto Rodriguez's [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook). Sysmon-getriebene Jagden mit ausformulierten Queries.
- Der [TrustedSec sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide). Das Referenzdokument für Filter-Semantik.

---
title: "Ereignisprotokoll-Löschung und die Lücken, die überleben"
description: "Wie Angreifer Windows-Ereignisprotokolle leeren, welche Beweise auf der Festplatte und in weitergeleiteten Kanälen verbleiben, und der Unterschied zwischen wevtutil cl und Thread-Suspendierungs-Tools wie Invoke-Phant0m."
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

Das Leeren von Ereignisprotokollen ist die anti-forensische Technik, die jeder Operator zuerst lernt, und die, die die nützlichste Spur hinterlässt. Der zweite Teil ist kontraintuitiv. Der ganze Sinn des Log-Leerens ist, Beweise zu entfernen, und ein Angreifer, der es schafft, `Security.evtx` zu leeren, hat tausende Ereignisse entfernt, die du lesen wolltest. Aber der Akt des Leerens selbst ist laut, die Techniken, die leiser zu sein versuchen, hinterlassen eine andere und gleich diagnostische Signatur, und die Kanäle, die die meisten Operatoren vergessen, bewahren genug, um zu rekonstruieren, was gelöscht wurde.

Zu wissen, was überlebt, zählt, weil es die Frage ändert, die du dem Host stellst. „Was ist im Security-Log" wird zu „was fehlt im Security-Log, und wohin sind diese Ereignisse sonst gegangen".

## 1102, 104, 1100: der laute Weg

Der Standardreflex eines Operators, der das Security-Log weg haben will, ist `wevtutil cl Security`. Das produziert:

- Ein einzelnes `EventID=1102` in `Security.evtx`, das unmittelbar nach dem Clear erzeugt wird und das Konto, das das Löschen durchführte, und die Zeit aufzeichnet. Dieses Ereignis überlebt im geleerten Log, weil es das erste Ereignis ist, das in die frisch geleerte Datei geschrieben wird. Behandle es als rauchende Waffe. Der Kontoname, die Quell-Workstation und die Löschzeit sind alle in den Event-Daten.
- Ein passendes `EventID=104` in `System.evtx` vom `Microsoft-Windows-Eventlog`-Provider, mit dem Namen des geleerten Kanals. Das ist der System-Log-Spiegel von `1102`. Manchmal überlebt nur eines der beiden, weil der Operator mehrere Kanäle geleert hat und die Reihenfolge zählt.
- Ein `1100` vom Event-Log-Dienst, das das Herunterfahren des Dienstes anzeigt, wenn der Operator den Dienst vor dem Leeren gestoppt hat. Die Kombination aus `1100`, gefolgt von einer unerklärten Lücke, gefolgt von `1102`, ist das klassische „Shutdown, Manipulation, Neustart"-Muster.

Diese drei Ereignisse sind die laute Signatur. Ein Angreifer, der weiß, was er tut, wird sie nicht erzeugen, oder er wird sie erzeugen und dann *erneut* löschen, um sie zu entfernen, was ein zweites `1102` und ein noch kleineres überlebendes Log produziert. Jeder Lösch-Durchgang hinterlässt ein `1102`. Die Tatsache, dass ein Host mehrere `1102`s in seiner Historie hat, ist an sich anomal.

Die Ereignisse, die geleert werden, sind nicht die einzigen Opfer. Das Leeren eines Kanals setzt die zugrundeliegende EVTX-Datei zurück, was bedeutet, dass die Datei auf der Festplatte neu geschrieben wird. Die Chunks der alten Datei sind nicht zugewiesen. Sie sind von der Festplatte wiederherstellbar, wenn du den Host innerhalb eines vernünftigen Fensters imagest, was der andere Zweig dieser Geschichte ist (im Carving-Post behandelt).

## `wevtutil cl` versus Thread-Suspendierung

Ein raffinierterer Operator leert die Logs überhaupt nicht. Er suspendiert die Threads des Windows-Event-Log-Dienstes (`eventlog`), tut das laute Ding, das er tun will, und nimmt die Threads wieder auf. Während die Threads suspendiert sind, werden Ereignisse, die vom OS und Anwendungen erzeugt werden, in der ETW-Infrastruktur eingereiht, aber nicht in die EVTX-Datei geschrieben. Wenn die Threads wieder aufnehmen, wird die Queue meist geleert, aber Ereignisse, die den Puffer während des Suspendierungs-Fensters überlaufen, sind für immer verloren.

Das ist, was `Invoke-Phant0m` tut (PowerShell, von Halil Dalabasmaz). Das Mimikatz-Modul `event::drop` tut etwas Ähnliches, arbeitet aber, indem es den ETW-Callback innerhalb des Dienstprozesses hookt. Beide hinterlassen:

- Kein `1102`. Nichts wurde geleert.
- Kein `104`. Gleicher Grund.
- Eine Lücke. Ereignisse von vor und nach dem Suspendierungs-Fenster sind vorhanden; Ereignisse von innerhalb fehlen. Das ist die Detektion.

Die Lücke ist auf zwei Wegen erkennbar. Der erste ist eine Sanity-Prüfung der zusammenhängenden RecordIDs: der EVTX-Chunk-Header zeichnet `FirstEventRecordIdentifier` und `LastEventRecordIdentifier` auf, und du kannst verifizieren, dass die Record-IDs über Chunks hinweg monoton sind. Suspendierung bricht den RecordID-Zähler nicht (der Dienst ist suspendiert, nicht der Kernel-ETW-Provider), aber die Zeitstempel im Chunk zeigen ein Fenster ohne Ereignisse von beschäftigten Providern, was auf einem Domain Controller offensichtlich auffällt.

Der zweite ist die Korrelation gegen Kanäle, die du nicht suspendieren kannst, ohne erneut zu eskalieren. Der Kanal `Microsoft-Windows-EventLog%4Operational.evtx` protokolliert den Lebenszyklus des Event-Log-Dienstes selbst. Thread-Suspendierung erzeugt hier keine expliziten „Thread suspendiert"-Ereignisse, aber der interne Heartbeat des Dienstes (Ereignisse `105`, `106` und providerspezifische Debug-Ereignisse, wenn der Operational-Kanal höhere Verbosity hat) zeichnet die Inkonsistenz manchmal auf.

Der dritte, schwierigere, ist die [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config)-Spur. Sysmon schreibt in seinen eigenen Kanal über seinen eigenen Treiber und ist von einer Suspendierung des Event-Log-Dienstes nicht betroffen. Ein Host mit Sysmon hat eine kontinuierliche Aufzeichnung von Prozesserstellungen und Image-Loads über das Suspendierungs-Fenster hinweg. Querverweise auf die Zeit der vermuteten Lücke in `Security.evtx` gegen Sysmons `Operational`-Kanal; wenn Sysmon einen `powershell.exe`-Prozess mit Command-Line-Inhalt zeigt, der zum Phant0m-Quellcode (oder zu einer der Dutzenden öffentlichen Varianten) zu Beginn der Lücke passt, hast du deine Antwort.

## Der Forwarded-Events-Kanal

Windows Event Collector (WEC) ist der Standardmechanismus zur Weiterleitung von Ereignissen an einen zentralen Collector. Weitergeleitete Ereignisse kommen beim Collector in `Microsoft-Windows-EventLog%4ForwardedEvents` (auf Windows-Event-Collector-Abonnenten) an und behalten das `Computer`-Feld des Ursprungshosts, die ursprüngliche `RecordID` und die ursprünglichen Zeitstempel.

Wenn deine Umgebung WEC hat und der Collector selbst nicht kompromittiert wurde, ist der Forwarded-Events-Kanal manchmal der einzige intakte Datensatz dessen, was auf einem Host passiert ist, dessen lokales Log geleert wurde. Die Ereignisse sind byte-identisch mit dem, was auf dem Ursprungshost erzeugt wurde (modulo collector-hinzugefügter Metadaten), und die `RecordID` des Ursprungshosts erlaubt dir, die weitergeleitete Kopie zurück in die RecordID-Timeline des lokalen Logs zu nähen.

Der Haken: WEC-Subscriptions sind standardmäßig pull-basiert, mit einem 15-Minuten-Heartbeat. Ein schnell agierender Angreifer kann das lokale Log zwischen Forwarding-Heartbeats leeren, und der Collector hat nur die Ereignisse von vor dem letzten erfolgreichen Pull. Konfiguriere Subscriptions im `MinLatency`-Modus (Push mit 30-Sekunden-Batch-Latenz) für die Kanäle, die dich interessieren. Das kostet Netzwerk- und Collector-Durchsatz; es zahlt sich beim ersten Mal aus, wenn du es brauchst.

Der andere Haken: WEC leitet standardmäßig nicht weiter. Wenn niemand die Subscription konfiguriert hat, ist der Collector-Kanal leer. Prüfe den Subscription-Zustand auf Kandidaten-Collectoren, bevor du eine Untersuchung auf diesen Beweis-Pfad setzt.

## Selektive Löschung und die EVTX-Level-Frage

Selektive Datensatzlöschung (spezifische Ereignisse aus einer Live-EVTX-Datei entfernen, während der Rest belassen wird) ist theoretisch möglich, indem man die Datei mit Kenntnis des Formats editiert und die Chunk-CRCs neu berechnet. In der Praxis macht das niemand in Live-Operationen, weil der Event-Log-Dienst die Datei geöffnet und gesperrt hat; du kannst sie aus dem Userland nicht editieren, ohne den Dienst herunterzufahren, und das Herunterfahren des Dienstes erzeugt `1100`/`105`-Ereignisse.

Was in freier Wildbahn passiert, ist Offline-Manipulation nachträglich. Ein Operator, der die EVTX-Datei exfiltriert, sie auf seinem eigenen Rechner editiert und sie wieder hochlädt, um die Live-Datei zu ersetzen (nach Stoppen des Dienstes), hinterlässt:

- Inkonsistente CRCs auf den editierten Chunks, es sei denn, er hat sowohl die Chunk-Header-CRC als auch die Records-Region-CRC korrekt neu berechnet.
- Inkonsistente `LastEventRecordNumber` in Chunk-Headern, wenn er diese nicht auch aktualisiert hat.
- Diskontinuitäten in RecordIDs über Chunk-Grenzen hinweg.

Jeder anständige Parser markiert diese. `evtx_dump` warnt bei CRC-Mismatch standardmäßig. `EvtxECmd` loggt die Diskrepanz in seiner Ausgabe. Behandle jede CRC-Warnung während des Parsens einer EVTX-Datei von einem mutmaßlich kompromittierten Host als potenziellen Manipulationsindikator und image die zugrundeliegende Festplatte, bevor du etwas anderes tust.

## Was nur in `Microsoft-Windows-EventLog%4Operational.evtx` auftaucht

Dieser Kanal ist getrennt von `Security.evtx` und die meisten Angreifer ignorieren ihn. Er zeichnet auf:

- Event-Log-Dienst-Start und -Stop (`105`, `106`).
- Kanal-Zustandsänderungen (Subscription gestartet, Kanal aktiviert/deaktiviert).
- Manifest-Registrierungs-Ereignisse.

Wenn der Event-Log-Dienst neu gestartet wird (weil der Operator `Stop-Service eventlog` benutzt hat oder weil sie etwas gepatcht und neu gestartet haben), bekommst du hier Ereignisse, die zur `1100`/`105`/`106`-Familie passen. Wenn `Security.evtx` zur Zeit T `1100` zeigt und `EventLog%4Operational.evtx` zur selben Zeit T eine entsprechende Dienstzustandsänderung zeigt, war das Herunterfahren geordnet. Wenn `Security.evtx` eine Lücke ohne `1100` zeigt, aber `EventLog%4Operational.evtx` zeigt, dass der Dienst neu gestartet wurde, ist der Dienst abgestürzt oder wurde ohne ordentlichen Shutdown getötet, was an sich verdächtig ist.

Dieser Kanal ist klein und liest schnell. Füge ihn deiner Standard-Triage-Checkliste hinzu.

## Querverifikation gegen Host-Artefakte

Wenn das Security-Log weg oder manipuliert ist, sind die überlebenden Artefakte die üblichen Verdächtigen:

- Die [Master File Table](https://www.mftparser.com) für die EVTX-Datei selbst. `$STANDARD_INFORMATION`- und `$FILE_NAME`-Zeitstempel zeigen, wann die Datei durch Löschen neu geschrieben wurde.
- Das [USN-Journal](https://www.usnparser.com) für `DATA_OVERWRITE`- und `DATA_TRUNCATION`-Ereignisse auf `Security.evtx`. Diese zeigen das Löschen in Journal-Begriffen mit hochauflösenden Zeitstempeln.
- [Prefetch](https://www.prefetchparser.com) für `wevtutil.exe`-Ausführung oder für `powershell.exe`-Läufe, die mit dem vermuteten Löschen übereinstimmen.
- [Shimcache](https://www.shimcacheparser.com) und [AmCache](https://www.amcacheparser.com) für Tooling, das der Operator mitgebracht hat, um das Löschen durchzuführen, besonders wenn sie ein Nicht-Standard-Binary benutzt haben.
- [RAM-Dump](https://www.ramparser.com)-Artefakte, wenn du einen erfasst hast. Der In-Memory-Cache des Event-Log-Dienstes wird Datensätze haben, die nie auf die Festplatte geflusht wurden.

Das Security-Log ist eine Quelle. Behandle es als eine Quelle. Die Untersuchung, die allein darauf angewiesen ist, ist eine manipulierte Datei davon entfernt, nutzlos zu sein. Der [Parser auf dieser Seite](https://www.evtxparser.com) markiert Chunk-CRC-Mismatches und RecordID-Lücken in seiner Ausgabe, was die billige Erst-Prüfung dafür ist, ob du ein manipuliertes Log anschaust, bevor du eine Stunde investiert hast, es zu lesen.

## Weiterführende Lektüre

- Halil Dalabasmaz' [Invoke-Phant0m-Quelltext](https://github.com/hlldz/Invoke-Phant0m). Lies, was er tut. Die Detektion folgt direkt.
- Roberto Rodriguez' [ThreatHunter-Playbook-Eintrag zu 1102](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html) und das umliegende Clearing-Detection-Material.
- Microsofts Dokumentation zu [Windows-Event-Collector-Subscriptions](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) für die WEC-Konfiguration, die dir das Forwarded-Events-Sicherheitsnetz gibt.

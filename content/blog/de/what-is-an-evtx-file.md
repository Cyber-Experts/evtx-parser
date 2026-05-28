---
title: "Was ist eine .evtx-Datei? Das Windows-Ereignisprotokollformat erklärt"
description: "Eine .evtx-Datei ist ein binäres Windows-Ereignisprotokoll. Wo sie liegen, was drinsteckt, wie sie sich von .evt unterscheiden und wie man sie öffnet. Keine Installation nötig."
date: "2026-05-24"
faq:
  - question: "Was ist eine .evtx-Datei?"
    answer: "Eine .evtx-Datei ist das binäre Windows-Ereignisprotokollformat, das mit Windows Vista eingeführt wurde. Sie speichert System-, Sicherheits- und Anwendungsereignisse, die vom EventLog-Dienst geschrieben werden. Jeder Windows-Rechner hat Dutzende .evtx-Dateien unter C:\\Windows\\System32\\winevt\\Logs\\, eine pro Kanal."
  - question: "Wo werden .evtx-Dateien unter Windows gespeichert?"
    answer: "Der Standardspeicherort ist C:\\Windows\\System32\\winevt\\Logs\\. Die drei stark frequentierten Dateien sind Security.evtx, System.evtx und Application.evtx. Anwendungsspezifische Kanäle liegen im selben Ordner unter Namen wie Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "Was ist der Unterschied zwischen .evtx und .evt?"
    answer: ".evt ist das ältere Binärformat, das Windows bis XP und Server 2003 verwendet hat. .evtx hat es 2007 mit Windows Vista abgelöst und bringt ein in Chunks aufgeteiltes, BinXML-basiertes Layout mit, das reichhaltigere Ereignis-Metadaten, größere Logs und strukturierte Abfragen über wevtutil und Get-WinEvent unterstützt. Die beiden Formate sind nicht austauschbar."
  - question: "Wie öffne ich eine .evtx-Datei?"
    answer: "Windows-Bordmittel: Ereignisanzeige (eventvwr.msc), wevtutil von der Kommandozeile oder Get-WinEvent aus PowerShell. Plattformübergreifend: im browserbasierten Parser auf dieser Seite öffnen (keine Installation, kein Upload) oder evtxecmd auf der Kommandozeile verwenden. Alle Optionen findest du im Beitrag how-to-open-an-evtx-file."
  - question: "Kann ich eine .evtx-Datei unter macOS oder Linux öffnen?"
    answer: "Ja. Die nativen Windows-Werkzeuge funktionieren nicht, aber mehrere plattformübergreifende Parser schon: der browserbasierte Parser auf dieser Seite (jedes Betriebssystem mit modernem Browser), python-evtx, das Rust-Crate evtx und evtxecmd über .NET. Keiner davon braucht einen Windows-Host."
---

Eine `.evtx`-Datei ist das binäre Windows-Ereignisprotokollformat, das Microsoft 2007 mit Vista ausgeliefert hat, um das ältere `.evt` abzulösen. Jedes Ereignis, das das Betriebssystem, ein Treiber, ein Dienst oder eine Anwendung in das Windows-Ereignisprotokoll schreibt, landet in einer `.evtx`-Datei auf der Festplatte. Sie sind das Rückgrat jeder Windows-Untersuchung. Wer DFIR unter Windows macht, verbringt mehr Zeit in diesen Dateien als in jeder anderen Artefaktklasse.

## Kurzantwort

`.evtx`-Dateien werden vom Windows-EventLog-Dienst nach `C:\Windows\System32\winevt\Logs\` geschrieben. Eine Datei pro **Kanal** (`Security.evtx`, `System.evtx`, `Application.evtx` plus anwendungsspezifische Kanäle). Intern ist jede Datei ein chunkbasierter Binärcontainer mit `BinXML`-kodierten Datensätzen. Kein Klartext. Lesen lassen sie sich mit der Ereignisanzeige, `wevtutil`, `Get-WinEvent` oder einem Drittanbieter-Parser.

## Wo .evtx-Dateien liegen

Standardspeicherort auf jeder unterstützten Windows-Version (Vista bis Windows 11 und Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Jede `.evtx`-Datei entspricht einem Ereigniskanal. Die Standardkanäle:

- `Security.evtx`. Anmeldungen, Privilegiennutzung, Änderungen an der Audit-Richtlinie. In den meisten Fällen der höchste forensische Wert.
- `System.evtx`. Treiber, Dienste, Fehler auf Kernel-Ebene.
- `Application.evtx`. Fehler und Informationsereignisse auf Anwendungsebene.
- `Setup.evtx`. Installationsdatensätze.
- `ForwardedEvents.evtx`. Ereignisse, die per Windows Event Forwarding (WEF) von anderen Hosts eingesammelt werden.

Anwendungsspezifische Kanäle liegen im selben Ordner, wobei `%4` den Pfadtrenner ersetzt:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Sysmon-Prozess-, Netzwerk- und Dateiereignisse (sofern installiert).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. PowerShell-Scriptblock- und Modul-Logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Erstellung und Ausführung geplanter Aufgaben.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Lebenszyklus von RDP-Sitzungen.

Rotierte Kanäle erzeugen im selben Ordner archivierte Dateien mit Zeitstempel (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). Die aktive Datei wird vom EventLog-Dienst offen gehalten, solange Windows läuft, was der ganze Grund ist, warum es [einen Sammlungsbeitrag dazu gibt, wie man diese Dateien von einem Live-Host bekommt](/de/blog/collecting-evtx-from-live-system).

## Was in einer .evtx-Datei steckt

Die Datei ist ein Binärcontainer, kein Klartext. Auf einen 4-KB-Header (Magic `ElfFile\0`) folgt eine Abfolge von 64-KB-**Chunks**. Jeder Chunk hat seinen eigenen Header (`ElfChnk`), eine Tabelle der darin enthaltenen XML-**Templates** und einen Strom von Datensätzen, die diese Templates per ID referenzieren. Ein Parser rekonstruiert jedes Ereignis, indem er datensatzspezifische Werte in die Platzhalter des Templates einsetzt. Genau das macht `.evtx` auf der Festplatte kompakter als wörtliches XML.

Einmal dekodiert, ist jeder Datensatz ein XML-Dokument mit zwei Hälften:

- `<System>`. Provider-Name, Kanal, Event ID, Stufe (1 Critical bis 5 Verbose), Computername, Sicherheitskontext und UTC-Schreibzeitstempel.
- `<EventData>`. Providerspezifische Parameter: das Zielkonto bei einer Anmeldung, der Image-Pfad bei einem Process Create, der Registry-Schlüssel bei einem überwachten Schreibvorgang und so weiter.

Die Event ID allein reicht für die Triage selten aus. Das forensische Signal steckt in `<EventData>`. Für die tiefen Format-Mechaniken (Chunks, BinXML, Templates, Recovery aus dirty Chunks) siehe [die Chunk-Tiefenanalyse](/de/blog/evtx-file-format-chunks).

## .evtx vs. .evt: warum das Format gewechselt wurde

Das alte `.evt`-Format, das Windows bis XP und Server 2003 verwendet hat, hatte drei harte Limits, die das neue Format gezielt aufheben sollte:

- **Strings fester Größe.** `.evt`-Datensätze trugen Verweise auf Message-Tabellen statt der vollständigen Nachricht. Die Auflösung zur Laufzeit brach, sobald Quell-DLLs fehlten oder aktualisiert wurden.
- **Keine strukturierten Abfragen.** Zum Filtern musste jeder Datensatz linear gelesen und geparst werden.
- **Ein Kanal pro Datei.** Eigene Anwendungs-Logs brauchten ihre eigenen, nicht standardisierten Formate.

`.evtx` (Vista, 2007) brachte BinXML-Datensätze, kanalweise Dateien mit beliebiger Schachtelung, XPath-artiges Filtern über `wevtutil qe` und `Get-WinEvent -FilterHashtable` sowie ein Chunk-Layout, das partielle Schreibvorgänge übersteht. Der Preis war ein vollständiger Bruch der Kompatibilität. `.evt` und `.evtx` sind nicht austauschbar, und das einzige Bordmittel, das `.evt` auf modernem Windows noch liest, ist `wevtutil` mit dem Legacy-Flag (und auch nur für den Export nach `.evtx`).

## Wie man eine .evtx-Datei öffnet

Fünf gängige Wege, grob nach Aufwand sortiert:

1. **Im Browser, ohne Installation.** Die Datei auf den Parser auf der Startseite dieser Seite ziehen. Er führt das Rust-Crate [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) als WebAssembly in einem Web Worker aus. Nichts verlässt deinen Rechner. Passt für Ad-hoc-Triage, wenn du keine forensische VM hochfahren willst.
2. **Ereignisanzeige (`eventvwr.msc`).** Die mitgelieferte Windows-GUI. Aktion / Gespeicherte Protokolldatei öffnen / die `.evtx` auswählen. Gut zum Stöbern, schwach beim Filtern in großem Stil.
3. **`wevtutil` / `Get-WinEvent`.** Kommandozeile und PowerShell, beide gehören zum Lieferumfang von Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` gibt jeden Datensatz aus. `Get-WinEvent -Path` liefert Objekte, die du per Pipe an `Where-Object` weitergeben kannst.
4. **EvtxECmd.** Der Parser von Eric Zimmerman. Plattformübergreifend über .NET, schnell, erzeugt CSV mit einer Zeile pro Datensatz und vollständig ausgeflachtem `<EventData>`.
5. **`python-evtx`.** Reines Python, leicht zu skripten. Langsamer als das Rust-Crate, aber nützlich, wenn du ohnehin schon einen Python-Toolstack hast.

Eine ausführliche Erklärung jeder Methode mit den Befehlen, die du tatsächlich tippen würdest, findest du in [Wie man eine .evtx-Datei öffnet](/de/blog/how-to-open-an-evtx-file).

## Wann dir .evtx in der Praxis begegnet

- **Incident Response.** Im Rahmen der Triage von einem kompromittierten Host gezogen. Welche Kanäle relevant sind, hängt vom Ansatzpunkt ab: `Security` für Anmeldungen und Rechtemissbrauch, `Sysmon` für Prozessbäume, `PowerShell` für Scriptblock-Inhalte. Kombiniere mit [Registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN-Journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com) und [Prefetch](https://www.prefetchparser.com) zur Ausführungs-Korroboration.
- **Compliance-Audits.** Auditoren fordern `Security.evtx` über einen definierten Zeitraum an, um Anmelde- und Richtlinienänderungs-Historie zu prüfen.
- **Anwendungs-Debugging.** `Application.evtx` plus herstellerspezifische Kanäle enthalten oft Crash- und Fehler-Kontext, den die eigenen Logs der Anwendung nicht haben.
- **Threat Hunting.** Langfristige Regeln gegen archivierte `.evtx` (oder ein SIEM, das den Live-Kanal weiterleitet) finden langsam brennende Muster wie RDP außerhalb der Arbeitszeit oder Drift im `LogonType` von Dienstkonten.

Der mit Abstand nützlichste Pivot ist die Event ID. Für die Kurzliste, die sich in einem echten SOC bewährt ([4624](/de/blog/understanding-event-id-4624), [4625](/de/blog/detecting-4625-brute-force), [1102](/de/blog/event-id-1102-cleared-log), [4104](/de/blog/powershell-4104-scriptblock), [7045](/de/blog/service-creation-event-id-7045), [Sysmon 1](/de/blog/sysmon-event-id-1-process-create)), siehe [die Einstiegsorientierung](/de/blog/welcome).

## Weiterführende Lektüre

- [Microsoft-Dokumentation: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [libevtx EVTX-Formatspezifikation](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (Rust-Parser)](https://github.com/omerbenamram/evtx)

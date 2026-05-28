---
title: "Das EVTX-Dateiformat, entschlüsselt"
description: "Eine praktische Tour durch das binäre EVTX-Format: Datei-Header, ELFCHNK-Chunks, BinXML-Templates, Substitutionsarrays und warum das Parsen schwerer ist, als es aussieht."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

Das alte EVT-Format war mit Geduld und einem Hex-Editor fast lesbar. EVTX ist es nicht. Microsoft ersetzte es in Vista durch etwas, das für Write-Throughput und maschinelle Konsumierung entworfen wurde, und die Nebenwirkung ist, dass jeder, der eine EVTX-Datei lesen möchte, die gleichen paar hundert Seiten von Andreas Schusters Reverse-Engineering-Notizen neu implementiert. Das Format ist in `[MS-EVEN6]` nur auf der Protokollebene dokumentiert. Die On-Disk-Struktur müssen Sie selbst herausfinden oder von `libevtx` borgen.

Dieser Beitrag ist die Version davon, die ich gerne gehabt hätte, als ich anfing.

## Der Datei-Header, kurz

Jede EVTX-Datei beginnt mit einem 4096-Byte-Datei-Header. Die Magic ist `ElfFile\0` bei Offset 0. Danach die Felder, die Sie während der Triage tatsächlich interessieren:

- `FirstChunkNumber` und `LastChunkNumber` Chunk-Indizes, keine Byte-Offsets.
- `NextRecordIdentifier` die nächste RecordID, die geschrieben würde. Nützlich, um Truncation zu erkennen.
- `HeaderSize` fast immer 128, mit dem Rest der 4096 Bytes nullgepolstert.
- `MinorVersion` / `MajorVersion` `3.1` ist die Version, die jedes moderne Windows schreibt.
- `FileFlags` Bit 0 gesetzt bedeutet, die Datei ist dirty (nicht sauber geschlossen), Bit 1 bedeutet, sie war "voll" und rolliert. Beide sind wichtig für die forensische Interpretation.
- Ein CRC32 über die ersten 120 Bytes des Headers. Tools, die den CRC ignorieren, parsen fröhlich korrupte Header; Tools, die ihn erzwingen, lehnen Dateien ab, aus denen Sie noch Records wiederherstellen können. Wissen Sie, welches Ihres tut.

Nach dem Header bekommen Sie eine Sequenz von 65.536-Byte-Chunks. Immer 64 KB, immer ausgerichtet. Das ist die Einheit, die Windows atomar schreibt, und die Einheit, die Sie carven.

## ELFCHNK: der Chunk-Header

Jeder Chunk beginnt mit `ElfChnk\0` an der Chunk-Grenze. Der Header ist 512 Bytes und trägt die Felder, die das Parsen ermöglichen:

- `FirstEventRecordNumber` und `LastEventRecordNumber` der von diesem Chunk abgedeckte RecordID-Bereich.
- `FirstEventRecordIdentifier` und `LastEventRecordIdentifier` dasselbe, aus Legacy-Gründen erhalten.
- `FirstEventRecordOffset` wo die Bytes des ersten Records innerhalb dieses Chunks beginnen.
- `LastEventRecordOffset` wo der letzte Record beginnt. Wenn das hinter dem Ende des befüllten Chunks liegt, wurde der Chunk teilweise geschrieben; der Writer ist abgestürzt.
- Eine `StringTable` und eine `TemplateTable`, beide Hash-Tabellen mit FNV-Style-Hashes als Schlüssel, die in den BinXML-Payload des Chunks zeigen.
- Zwei CRCs: einer über den Header, einer über den Records-Bereich.

Die String- und Template-Tabellen sind der Teil, der die Leute aus der Bahn wirft. Templates und Strings werden *einmal pro Chunk* gespeichert und über Offsets innerhalb des Chunks referenziert. Das bedeutet, Sie können einen Record nicht sinnvoll isoliert parsen. Sie brauchen seinen umschließenden Chunk mit aufgelösten Tabellen, um das XML des Records zu rendern. Carven Sie einen Record ohne seinen Chunk und Sie bekommen ein Substitutionsarray ohne Template zum Einsetzen.

`NumLogRecords` lebt implizit als `LastEventRecordNumber - FirstEventRecordNumber + 1`. Einige frühe Dokumentationen nannten dieses Feld beim Namen; moderne Parser berechnen es.

## EventRecord-Codierung

Hinter dem Chunk-Header bekommen Sie Records, Rücken an Rücken, bis der Chunk voll ist oder der Rest genullt ist. Jeder Record beginnt mit der Magic `2a 2a 00 00` (was Signature-Carving aus rohem Disk machbar macht, mehr dazu in einem separaten Beitrag) gefolgt von:

- `Size` totale Record-Länge einschließlich der nachfolgenden Größenwiederholung.
- `EventRecordIdentifier` die monoton steigende RecordID.
- `WriteTime` ein Windows FILETIME, 100-ns Ticks seit 1601-01-01 UTC.
- Der BinXML-Payload.
- `Size` erneut, am Ende wiederholt, damit ein Reader Records rückwärts laufen kann.

Der BinXML-Payload ist, wo die eigentliche Arbeit beginnt.

## BinXML und das Template/Substitutionsmodell

BinXML ist ein Token-Stream, der XML als binäre Opcodes codiert. Die wichtigen Opcodes:

- `0x00` end-of-stream.
- `0x01` open start tag (mit Attributen).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, gefolgt von einem `ValueType` und den Wert-Bytes.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` normal substitution.
- `0x0e` conditional substitution.
- `0x0f` start of stream (mit einer 3-Byte-Präambel).

Der Windows Event Log Writer emittiert für ein Event fast nie rohes XML. Er emittiert eine *Template-Instanz* (`0x0c`), die eine Template-Definition (einmal pro Chunk nach ID gespeichert) referenziert und ein *Substitutionsarray* mit den Variablenwerten für dieses Template bereitstellt. Um einen einzelnen menschenlesbaren XML-Record zu rendern, müssen Sie:

1. Das Template in der Template-Tabelle des Chunks nach Template-ID und Offset lokalisieren.
2. Das BinXML des Templates durchlaufen und es als Skelett mit nummerierten Substitutionsplatzhaltern behandeln.
3. Für jeden Platzhalter den entsprechenden Eintrag im Substitutionsarray nachschlagen, ihn gegen den deklarierten Typ des Platzhalters typprüfen und ihn inlinen.

Das Substitutionsarray hat typisierte Einträge: UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, plus Strings entweder in UTF-16LE inline oder per Offset-Referenz, plus Arrays von allen oben genannten. Typ 0x21 ist "BinXML", was bedeutet, dass die Substitution selbst ein verschachtelter BinXML-Stream ist, was bedeutet, dass Parser rekursieren müssen. Hier scheitern naive Implementierungen.

Zwei Fallstricke, die erwähnenswert sind:

- Templates können von *anderen* Records im selben Chunk per Offset referenziert werden. Wenn Sie einen Parser bauen, der Templates nur dann auflöst, wenn er ihre Deklaration inline sieht, werden Sie Records verpassen, die ein früheres Template nur per ID referenzieren.
- Der "conditional substitution"-Typ (`0x0e`) bedeutet: einsetzen, wenn der Wert nicht null ist, sonst das übergeordnete Element weglassen. Diese Unterscheidung zu überspringen, produziert XML, das gut aussieht, aber leere Elemente hat, wo das echte Log nichts hätte.

## Warum das schwieriger ist als EVT zu parsen

EVT war eine flache Datei mit Records fester Form. Strings wurden inline gespeichert. Sie konnten an einem Nachmittag einen Parser schreiben.

EVTX ist ein paginiertes, write-optimiertes, selbst-deduplizierendes Format. Derselbe String ("Microsoft-Windows-Security-Auditing") wird einmal pro Chunk gespeichert und von jedem Record referenziert, der ihn verwendet. Dasselbe XML-Skelett ("ein 4624-Event") wird einmal pro Chunk als Template gespeichert, und jeder 4624-Record in diesem Chunk ist ein Substitutionsarray dagegen. Cross-Record-State ist wichtig. Cross-Chunk-State ist es nicht, was die rettende Gnade ist: Verlieren Sie einen Chunk und Sie verlieren seine Records, aber der Rest der Datei ist wiederherstellbar.

Diese Deduplizierung ist es, was EVTX klein genug macht, um auf beschäftigten Hosts zu bleiben, und was naive Parser falsch macht. Wenn Sie jemals ein "geparstes" EVTX gesehen haben, bei dem das `Provider`-Feld jedes Records "Unknown" sagt, haben Sie einen Parser gesehen, der die String-Tabelle nicht aufgelöst hat.

## Die Tools, die tatsächlich funktionieren

- `python-evtx` (Willi Ballenthin) langsam, pure Python, aber die sauberste Referenzimplementierung. Lesen Sie ihren Quellcode, bevor Sie Ihren eigenen schreiben.
- `evtx_dump` aus Omer Ben-Amrams `evtx` Rust-Crate schnell, robust, der Default für Kommandozeilen-Dumping. JSONL-Ausgabe, die in alles pipet.
- `libevtx` und `evtxtools` (Joachim Metz) C-Bibliothek, die kanonische Referenz für das Format. Die Python-Bindings (`pyevtx`) sind in einigen Workloads langsamer als `python-evtx`, behandeln Edge-Cases aber besser.
- Eric Zimmermans `EvtxECmd` .NET, hands-down das Beste für IR-Feldarbeit wegen seines Map-Systems. Maps sind YAML-Dateien, die die EventData-Substitutionen in benannte Spalten abflachen, was Sie für Grep- und Timeline-Arbeit wollen. Paaren Sie es mit `Timeline Explorer`.
- Der Parser auf dieser Seite browser-basiert, nützlich, wenn Sie regulierte Daten nicht zu einem Hersteller hochladen wollen und Ihre Ausrüstung nicht auf der Box haben, an der Sie arbeiten.

Wenn Sie einen Parser von Grund auf schreiben (tun Sie das nicht, aber wenn Sie müssen), ist der Test-Corpus zur Validierung die öffentlichen EVTX-Samples aus dem [SANS DFIR Poster](https://github.com/forensicmatt/EVTX-ETW-Resources) Repo und die Yamato Security `hayabusa` Sample Logs. Sie decken die Fälle von fehlerhaftem Chunk und Teil-Record ab, bei denen Ihr Code beim ersten Durchgang falsch liegen wird.

Eine andere Sache, die erwähnenswert ist: Das Format wird mit anderen Windows-Artefakten geteilt. Die gleiche FILETIME-Codierung erscheint in der [Registry](https://www.registryparser.com), in [MFT](https://www.mftparser.com) `$STANDARD_INFORMATION`-Zeitstempeln, in [Prefetch](https://www.prefetchparser.com)-Headern. Werden Sie gut darin, FILETIME im Kopf zu lesen, und viel von Windows-Forensik wird ruhiger.

## Weiterführende Literatur

- Andreas Schusters Original ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007). Das Reverse-Engineering-Papier, das alles seither zitiert.
- Joachim Metz' [libevtx Formatspezifikation](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc). Das Nächste zu einer vollständigen Referenz.
- Willi Ballenthins [python-evtx Quellcode](https://github.com/williballenthin/python-evtx). Lesen Sie `Evtx/Nodes.py` für die BinXML-Knoten-Hierarchie.
- Omer Ben-Amrams [evtx Rust-Crate](https://github.com/omerbenamram/evtx). Der schnelle Pfad, auf dem die meisten modernen Tools sitzen.

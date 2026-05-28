---
title: "EVTX-Dateiformat erklärt: Chunks, Templates und BinXML-Interna"
description: "Wie eine .evtx-Datei auf Byte-Ebene aufgebaut ist: Datei-Header, 64-KB-Chunks, die Template-Tabelle und der BinXML-Datensatzstrom, der darauf verweist."
date: "2026-05-17"
---

Das [Windows-Ereignisprotokollformat `.evtx`](/de/blog/what-is-an-evtx-file) wurde mit Vista ausgeliefert, um das zeilenorientierte `.evt` abzulösen. Es ist ein binärer, nur-anhängender, in Chunks unterteilter Container, der von einem einzigen Prozess (dem EventLog-Dienst) geschrieben wird und rotiert, wenn er voll ist. Die meisten Analysten müssen nie wissen, wie er auf Byte-Ebene aufgebaut ist. Diejenigen, die Datensätze aus nicht zugewiesenem Speicher carven, beschädigte Chunks per Hand parsen oder mit einem Parser streiten, der eine abgeschnittene Datei nicht lesen will, sehr wohl.

Dieser Beitrag ist die praktische Version. Genug Interna, um einen kaputten Parse zu debuggen, nicht so viel, dass du am Ende deinen eigenen Parser von Grund auf schreibst.

## Datei-Header

Jede `.evtx` beginnt mit einem 4-KB-Header. Das Magic ist `ElfFile\0\0`. Die für einen Ermittler relevanten Felder sind Version, Chunk-Anzahl, älteste und aktuelle Chunk-Indizes und ein CRC32 über den Header selbst. Der Header wird jedes Mal an Ort und Stelle neu geschrieben, wenn die Datei rotiert oder ein Chunk versiegelt wird, also sind seine `Dirty`- und `Full`-Flags nützliche Hinweise. Eine Datei mit gesetztem `Dirty` war offen, als der Host abstürzte oder das Disk-Image live erfasst wurde.

Nach dem Header folgt eine Sequenz von Chunks fester Größe.

## Chunks: jeweils 64 KB

Jeder Chunk ist genau 65.536 Bytes groß und hat seinen eigenen 512-Byte-Header. Das Chunk-Magic ist `ElfChnk\0`. Der Header trägt die Log-RecordIDs des ersten und letzten Datensatzes im Chunk, die Datei-Offsets und zwei CRC32: einer über den Header, einer über die Datensatzdaten.

Chunks sind unabhängig. Du kannst einen Chunk aus nicht zugewiesenem Speicher carven und ihn ohne den Rest der Datei parsen. Das ist, was EVTX [aus Festplattenfragmenten wiederherstellbar](/de/blog/carve-deleted-evtx-records) macht, und es ist auch das, was das Format forensik-freundlicher macht als etwas, das über die ganze Datei komprimiert wäre.

Innerhalb eines Chunks:

- **String-Tabelle.** Innerhalb dieses Chunks internierte Strings, per Offset referenziert.
- **Template-Tabelle.** Von Datensätzen in diesem Chunk verwendete XML-Templates, ebenfalls per Offset indiziert.
- **Datensätze.** Ein Strom von BinXML-Datensätzen, jeder referenziert ein Template plus pro-Datensatz-Substitutionswerte.

## BinXML und Templates

EVTX-Datensätze werden nicht als XML-Text gespeichert. Sie werden als **BinXML** gespeichert, einer tokenisierten Binärdarstellung eines XML-Dokuments. Um Platz zu sparen, wird das strukturelle Skelett (Elementnamen, Attributnamen, Baumform) in ein **Template** ausgelagert, das einmal in der Template-Tabelle des Chunks gespeichert wird. Jeder Datensatz sagt dann „verwende Template ID 5, mit Werten [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Um das XML für einen Datensatz zu rekonstruieren, macht ein Parser:

1. Liest den Token-Stream des Datensatzes.
2. Schlägt das Template per ID in der Template-Tabelle des Chunks nach.
3. Setzt die Pro-Datensatz-Werte in die Platzhalter-Positionen des Templates ein.
4. Gibt das resultierende XML aus.

Das ist, warum Parser (der [Browser-Parser auf dieser Seite](/de/blog/how-to-open-an-evtx-file), das [Rust-`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)-Crate, das er umschließt, und python-evtx teilen sich diese Anforderung) Chunk-lokalen Kontext verfolgen müssen. Template-IDs sind dateiübergreifend nicht global. Zwei Chunks können vollkommen unterschiedliche Template-Tabellen haben; dieselbe Template-ID-Nummer bedeutet in jedem etwas anderes.

Das ist auch der mit Abstand häufigste Grund, warum Analysten „Müll-XML" sehen, wenn sie versuchen, einen Datensatz, den sie mit `xxd` herausgezogen haben, von Hand zu dekodieren. Ohne die Template-Tabelle sind die Substitutionswerte nur ein Beutel typisierter Werte ohne Schema.

## Versiegelte versus dirty Chunks

Wenn der EventLog-Dienst das Schreiben eines Chunks beendet und zum nächsten übergeht, berechnet und schreibt er die CRC32 des Chunks und markiert den Header des Chunks als `Full`. Eine saubere Datei hat jeden Chunk in diesem Zustand außer dem letzten.

Ein `Dirty`-Chunk (Last-Modified-Zeit nach der letzten Aktualisierung des Datei-Headers) ist das Live-Tail. Er ist oft parsbar, aber Tools weigern sich manchmal, ihn zu lesen, weil der Datensatzstrom mitten in einem Token enden kann. Für die Forensik zählt das: ein von einem Live-Host [gesammeltes Bundle](/de/blog/collecting-evtx-from-live-system) wird einen dirty trailing Chunk auf dem aktiven Kanal haben, und das Verhalten deines Parsers auf diesem Chunk muss bekannt sein. Überspringt er den Chunk, errort er auf der Datei oder rettet er, was er kann?

EvtxECmd, hayabusa und python-evtx erholen sich alle mit unterschiedlicher Toleranz von dirty Chunks. Der native Event Viewer ist der strikteste und wird die Datei häufiger gänzlich verweigern als die anderen.

## Praktische Implikationen

- Eine abgeschnittene `.evtx`, häufig, wenn du [von einem Live-Host sammelst](/de/blog/collecting-evtx-from-live-system), ist meist größtenteils wiederherstellbar. Jeder vollständige Chunk ist unabhängig.
- Aus nicht zugewiesenem Speicher gecarvte Chunks können mit einem synthetischen Datei-Header umhüllt und geparst werden. So erholen sich libevtx und python-evtx aus `pagefile.sys` (siehe [Pagefile-Parser](https://www.pagefilesysparser.com)) und [RAM-Dump](https://www.ramparser.com)-Carving-Durchgängen.
- Ein fehlgeschlagener Parse eines Chunks bedeutet kein Versagen der Datei. Robuste Parser gehen zum nächsten Chunk weiter und melden den schlechten separat.
- Die Chunk-CRC32 ist das, was Manipulation markiert. Ein modifizierter Datensatz, der die CRC nicht neu berechnet, ist erkennbar. Die meisten Angreifer machen sich nicht die Mühe, weil das Leeren des Logs (Feuern von [1102](/de/blog/event-id-1102-cleared-log)) der leichtere Weg ist. Die vorsichtigen nutzen Phant0m, das die Datei ganz in Ruhe lässt.

## Weiterführende Lektüre

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (ursprüngliche Reverse-Engineering-Arbeit)
- [libevtx-Dokumentation](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (die gründlichste Formatspezifikation, die es gibt)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (Rust-Parser, der WASM-Build betreibt den Browser-Parser auf dieser Seite)

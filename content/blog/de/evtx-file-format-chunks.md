---
title: "EVTX-Dateiformat erklärt: Chunks, Templates und BinXML-Interna"
description: "Wie eine .evtx-Datei auf Byte-Ebene aufgebaut ist — File-Header, 64-KB-Chunks, die Template-Tabelle und der BinXML-Datensatzstream, der darauf verweist."
date: "2026-05-17"
---

Das [Windows-Event-Log-Format — `.evtx`](/de/blog/what-is-an-evtx-file) — wurde mit Windows Vista eingeführt, um das zeilenorientierte `.evt` abzulösen. Es ist ein binärer, append-only, gechunkter Container, gedacht zum Beschreiben durch einen einzelnen Prozess (den EventLog-Dienst) und zur Rotation oder Versiegelung, wenn voll. Zu verstehen, wie er aufgebaut ist, macht die forensischen Recovery-Fälle — partielle Dateien, Dirty Chunks, Carving — deutlich einfacher.

## File-Header

Jede `.evtx` beginnt mit einem 4-KB-Header (`ElfFile\0\0`-Magic, Version, Chunk-Anzahl, Indizes des ältesten/aktuellen Chunks und ein CRC32). Der Header wird bei jeder Rotation oder Versiegelung eines Chunks in-place neu geschrieben, was seine `Dirty`- und `Full`-Flags zu nützlichen Indizien macht: eine Datei mit gesetztem `Dirty` war offen, als der Host abstürzte oder das Disk-Image live akquiriert wurde.

Nach dem Header folgt eine Sequenz von fix-großen Chunks.

## Chunks (64 KB)

Jeder Chunk ist exakt 64 KB groß und hat seinen eigenen 512-Byte-Header (`ElfChnk\0`-Magic, Log-Record-IDs des ersten und letzten Datensatzes im Chunk, File-Offsets, zwei CRC32 — einer für den Header, einer für die Datensatzdaten). Chunks sind unabhängig: du kannst einen Chunk aus unallokiertem Bereich carven und ohne den Rest der Datei parsen. Das ist es, was EVTX aus Disk-Fragmenten wiederherstellbar macht.

Innerhalb eines Chunks:

- **String-Tabelle** — innerhalb dieses Chunks internierte Strings, per Offset referenziert.
- **Template-Tabelle** — von Datensätzen in diesem Chunk verwendete XML-Templates, ebenfalls Offset-indiziert.
- **Datensätze** — ein Strom von BinXML-Datensätzen, jeder verweist auf ein Template plus per-Record-Substitutionswerte.

## BinXML und Templates

EVTX-Datensätze werden nicht als XML-Text gespeichert. Sie liegen als **BinXML** vor, einer tokenisierten Binärrepräsentation eines XML-Dokuments. Um Platz zu sparen, wird das strukturelle Skelett (Element-Namen, Attributnamen, Baumform) in ein **Template** ausgelagert, das einmal in der Template-Tabelle des Chunks gespeichert ist. Jeder Datensatz sagt dann „nutze Template-ID 5 mit den Werten [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Um das XML für einen Datensatz zu rekonstruieren, geht ein Parser so vor:

1. Liest den Token-Stream des Datensatzes.
2. Schlägt das Template per ID in der Template-Tabelle des Chunks nach.
3. Setzt die per-Record-Werte in die Platzhalter-Positionen des Templates ein.
4. Emittiert das resultierende XML.

Deshalb müssen [Parser](/de/blog/how-to-open-an-evtx-file) (auch der, der diese Seite antreibt, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) chunk-lokalen Kontext mitführen — Template-IDs sind nicht global über die Datei hinweg.

## Sealed vs Dirty Chunks

Wenn der EventLog-Dienst das Schreiben eines Chunks beendet und zum nächsten wechselt, berechnet und schreibt er den CRC32 des Chunks und markiert den Chunk-Header als `Full`. Eine saubere Datei hat alle Chunks außer dem letzten in diesem Zustand.

Ein `Dirty`-Chunk — Last-Modified-Zeit nach der letzten Aktualisierung des File-Headers — ist das Live-Tail. Er ist oft parsebar, aber Tools weigern sich manchmal, ihn zu lesen, weil der Datensatzstrom mitten in einem Token enden kann. Für Forensik zählt das: ein Angreifer, der einen Host mitten im Schreibvorgang akquiriert hat, sieht einen Dirty-Trailing-Chunk, und das Verhalten deines Parsers auf diesem Chunk muss bekannt sein (überspringt er, errored er, oder rettet er, was er kann?).

## Praktische Implikationen fürs Parsen

- Eine abgeschnittene `.evtx` — häufig, wenn du [von einem laufenden Host sammelst](/de/blog/collecting-evtx-from-live-system) — ist oft trotzdem zum großen Teil wiederherstellbar, weil jeder vollständige Chunk unabhängig ist.
- Aus dem Unallokierten gecarvete Chunks können mit einem synthetischen File-Header umhüllt und geparst werden.
- Ein gescheiterter Parse eines Chunks bedeutet nicht das Scheitern der Datei — robuste Parser gehen zum nächsten Chunk weiter.
- Der CRC32 des Chunks ist das, was Tampering flaggt: ein veränderter Datensatz, der den CRC nicht neu berechnet, ist detektierbar.

---
title: "Gelöschte EVTX-Datensätze carven und überrollte Logs wiederherstellen"
description: "Signatur-basiertes Carving von EVTX-Datensätzen aus nicht zugewiesenem Speicher, Pagefile und RAM, plus die Tools, die mit kaputten Chunks gut umgehen, wenn das Live-Log fehlt, was du brauchst."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

Das Security-Log eines belasteten Domain Controllers rollt in Stunden, nicht in Tagen. Die Standard-Kanalgröße ist 20 MB, was auf einem lauten Host ein paar tausend Datensätze sind. Wenn du [die Festplatte](https://www.diskimageparser.com) als Reaktion auf einen Vorfall sicherst, der vor drei Wochen begann, sind die Ereignisse, die du eigentlich wolltest, längst aus der Live-Datei gerollt und liegen in nicht zugewiesenem Speicher, im Pagefile und möglicherweise im Hibernation-File. Sie zurückzucarven gehört zur Routine jeder EVTX-getriebenen Untersuchung, und die meisten Verteidiger lassen es weg, weil sie die Live-Datei als Quelle der Wahrheit behandeln.

Das ist sie nicht. Die Live-Datei sind die letzten 20 MB. Die Festplatte hat den Rest.

## Die Signatur: `2a 2a 00 00`

Jeder EVTX-Datensatz beginnt mit dem 4-Byte-Magic `2a 2a 00 00`. Das ist `**` gefolgt von zwei Null-Bytes. Diese Signatur ist eindeutig genug, dass das Scannen eines rohen Disk-Images mit `bulk_extractor`, `scalpel` oder sogar einem eigenen 4-Byte-grep eine nutzbare Kandidatenmenge zurückgibt. Die Signatur-Dichte auf einem Windows-Volume ist niedrig; die meisten Treffer sind echte Datensätze.

Die Struktur, die dem Magic folgt, ist gut genug definiert, dass du Treffer billig validieren kannst:

- Bytes 4-7: `Size` (uint32). Sollte plausibel sein (mindestens 32 Bytes, typisch unter 4 KB).
- Bytes 8-15: `EventRecordIdentifier` (uint64). Sollte eine sinnvolle RecordID für das Zeitfenster sein.
- Bytes 16-23: `WriteTime` als FILETIME. Sollte zwischen Vista (erste Version mit EVTX) und jetzt liegen.
- Bytes `Size-4` bis `Size`: derselbe `Size`-Wert, als Tail-Marker wiederholt.

Ein Kandidat, bei dem die Kopf-`Size` der Schwanz-`Size` entspricht, die FILETIME zu einem plausiblen Datum parst und die RecordID im Bereich liegt, ist mit überwältigender Wahrscheinlichkeit ein echter Datensatz. False Positives gehen mit diesen vier Prüfungen gegen null.

Die Herausforderung ist, was mit den Bytes zwischen Kopf und Schwanz zu tun ist.

## Das Chunk-Problem

EVTX-Datensätze referenzieren Templates und Strings, die einmal pro Chunk gespeichert sind. Ein isoliert gecarvter Datensatz hat Substitutions-Arrays ohne Template, auf das man sie anwenden könnte. Du kannst die typisierten Werte direkt aus dem Substitutions-Array lesen, was reicht, um Felddaten zu rekonstruieren ("Benutzer X hat sich zur Zeit T von IP Y angemeldet"), aber das gerenderte XML, das du von einem Live-Parser bekommst, ist ohne den Chunk nicht rekonstruierbar.

Das ist der Unterschied zwischen zwei Carving-Ergebnissen:

- **Reines Datensatz-Carving**: du holst RecordID, Zeitstempel, EventID und die Substitutionswerte zurück. Du kannst eine Feld-für-Feld-Ansicht des Ereignisses bauen, aber nicht das menschenlesbar gerenderte XML.
- **Chunk-Carving**: du findest einen Chunk (`ElfChnk\0`-Magic, 64-KB-Ausrichtung) und holst seine Template-Tabelle samt der Datensätze zurück. Jetzt hast du alles.

`ElfChnk\0` ist ebenfalls signatur-carvbar. Die 64-KB-Ausrichtung hilft, weil Chunks auf Sektorgrenzen auf der Festplatte landen; ein offset-ausgerichteter Signatur-Scan ist schnell. Die meisten Carving-Tools unterstützen beide Modi, und du solltest beide laufen lassen. Chunks geben dir lesbare Ereignisse; verwaiste Datensätze geben dir den Rest, wenn kein umschließender Chunk überlebt hat.

## Wo die Bytes liegen

Die Stellen, die einen Scan lohnen, nach Ertrag sortiert:

- **Nicht zugewiesene Cluster auf dem Volume, das `%SystemRoot%\System32\winevt\Logs\` hostet**. Wenn eine EVTX-Datei rollt oder geleert wird, ist der alte Inhalt nicht zugewiesen. NTFS nullt nicht zugewiesene Cluster nicht, also sind die Bytes wiederherstellbar, bis sie wiederverwendet werden. Auf einem Server mit geringer Schreib-Churn kann das Wochen sein.
- **Slack-Space in der Live-EVTX-Datei**. EVTX-Dateien werden in 64-KB-Chunks geschrieben. Der letzte Chunk der Datei ist oft teilweise gefüllt, und der Slack enthält die vorherige Generation von Daten, die in diese Bytes geschrieben wurden, bevor der aktuelle Chunk verkleinert wurde. Einen Scan wert.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. Der Event-Log-Dienst cacht aktuelle Datensätze und Templates im Speicher. Seiten, die diese Strukturen halten, werden bei Speicherdruck ausgelagert. Das Pagefile ist eine Goldmine für Datensätze, die nie auf Disk geflusht wurden, weil der Host abgestürzt oder beendet wurde, bevor sie es geschafft haben.
- **`hiberfil.sys`**. Komprimierter Snapshot des physischen Speichers zum Hibernation-Zeitpunkt. Mit `Volatility 3` oder Hibr2Bin dekomprimieren und den resultierenden Roh-RAM nach den Datensatz-Signaturen durchsuchen.
- **[RAM-Dump](https://www.ramparser.com)**, der während der Live Response erfasst wurde. Das Working Set des Event-Log-Dienstes enthält aktuelle Datensätze und die Templates, die zum Rendern nötig sind.
- **Shadow Copies (VSS)**. Alte Snapshots des Volumes enthalten alte Versionen der Live-EVTX-Dateien. `vshadow` oder `vssadmin list shadows` gefolgt von `mklink /d` zum Mounten des Shadows gibt dir eine Vorgenerationskopie der Datei mit den Datensätzen, die zum Shadow-Zeitpunkt live waren.

VSS ist die hebelstärkste Quelle auf Hosts, die es aktiviert haben und auf VSS-Ebene nicht manipuliert wurden. Ein moderner Windows-Server hat typischerweise 7-30 Tage an Shadow Copies. Wenn der Vorfall vor drei Wochen war, hat der Shadow vom Vorfallszeitpunkt möglicherweise das Live-Log so, wie es damals existierte, unangetastet.

## Tools, die mit fehlerhaften Eingaben umgehen

Eine saubere EVTX-Datei ist in Carving-Szenarien selten. Du bekommst Teil-Chunks, Datensätze mit fehlendem Schwanz, Templates, die Offsets außerhalb des Chunks referenzieren, und CRC-Fehler überall. Die Parser, die damit umgehen, sind nicht dieselben wie die für saubere Dateien.

- **`EvtxECmd`** (Eric Zimmerman). Best in Class für IR-Feldarbeit. Übergib `--inc`, um Datensätze einzubeziehen, die beim normalen Parsen fehlschlugen, und es gibt aus, was es von Teildatensätzen lesen konnte. Die CSV-Ausgabe ist das, was du für Timeline-Arbeit willst.
- **`hayabusa`** (Yamato Security). Gebaut fürs Hunten über große EVTX-Korpora, mit sigma-artigen Regeln. Es geht vernünftig mit Teil-Chunks um und ist schnell. Der `--exclude-status`-Filter erlaubt dir, Rauschen aus korrupten Datensätzen zu reduzieren.
- **`evtx_dump`** (das Rust-Crate von Omer Ben-Amram). Robust gegen fehlerhafte Strukturen, JSONL-Ausgabe. Gut zum Pipelinen in `jq` oder ein SIEM.
- **`evtxtools`** (Joachim Metz, Teil von libevtx). Die format-kanonische Referenzimplementierung. Langsamer als die anderen, aber sie sagt dir genau, welches Feld welche Validierung gerissen hat, wenn ein Datensatz teilweise wiederhergestellt ist, was du beim Debuggen von Carving-Ausgaben willst.
- **`bulk_extractor`** mit dem EVTX-Scanner. Der Carving-Schritt selbst. Gibt Kandidaten-Datensätze mit ihren Offsets im Quell-Image zur späteren Validierung aus.

Eine praktische Pipeline:

1. `bulk_extractor -E evtx -o out/ image.dd`, um Kandidaten-Datensätze und Chunks aus dem Disk-Image zu carven.
2. Die Chunks zu synthetischen EVTX-Dateien zusammenbauen, indem du die gecarvten Chunks mit einem gefälschten Datei-Header konkateniert. Die `libevtx`-Beispiele enthalten einen `evtxexport`-kompatiblen Chunk-Reassembler.
3. `EvtxECmd` mit `--inc` über die wiederzusammengebaute Datei laufen lassen, um alles Lesbare in CSV zu dumpen.
4. Die gecarvten RecordIDs gegen die RecordIDs der Live-Datei diffen, um die Datensätze zu finden, die nicht im Live-Log waren.

Die Ausgabe von Schritt 4 ist das, was dir Carving gibt: die Ereignisse, die der Angreifer oder die Zeit aus der Live-Datei entfernt hat.

## Wenn das Live-Log nichts zeigt, weil es gerollt ist

Der häufige Fall fürs Carving ist nicht anti-forensisches Löschen; es ist Rollover. Ein Vorfall von vor 30 Tagen auf einem Host mit 20-MB-Security-Log und 50 Ereignissen pro Sekunde hat die gesamte Datei Dutzende Male gerollt. Das Live-Log zeigt die letzten paar Stunden. Alles dazwischen liegt im Nicht-Zugewiesenen.

Der Carve ist hier unkompliziert, weil es keine Manipulation gab. Du scannst Nicht-Zugewiesenes, findest Chunks, baust zusammen. Der Ertrag hängt davon ab, wie viel Schreib-Churn das Volume seit dem Rollover hatte. Ein Server-Volume mit überwiegend statischen Systemdateien und dem EVTX-Verzeichnis als dominanter Schreibquelle hält alte Chunks lange intakt. Ein Volume mit starken Anwendungs-Schreibvorgängen überschreibt die nicht zugewiesenen Bereiche schneller.

Ein Trick, der hilft: das EVTX-Verzeichnis liegt unter `%SystemRoot%\System32\winevt\Logs\`, was einer der kältesten Punkte auf dem Volume in Bezug auf konkurrierende Schreibvorgänge ist. Cluster-Runs, die beim Rollover der EVTX-Datei freigegeben wurden, bleiben oft wochenlang nicht zugewiesen. Dasselbe gilt nicht für Volumes mit Anwendungsdaten.

## Was mit dem zu tun ist, was du wiederherstellst

Gecarvte Datensätze gehen in dieselbe Timeline wie Live-Datensätze. Die RecordID und WriteTime überleben das Carving und sind die Join-Keys. Ein gecarvtes `4624 Type 3` zum Zeitpunkt des vermuteten Initial Access ist genauso nützlich wie ein Live-Datensatz, mit dem Vorbehalt, dass du sein volles XML nicht unbedingt rendern kannst.

Querverweise mit:

- Den [Master File Table](https://www.mftparser.com)-Einträgen für `Security.evtx`, um zu sehen, wann die Datei durch Löschen oder Rollover neu geschrieben wurde.
- Dem [USN-Journal](https://www.usnparser.com) für `DATA_OVERWRITE`-Ereignisse auf der EVTX-Datei, was hochauflösende Zeitstempel für jeden Rollover liefert.
- [Prefetch](https://www.prefetchparser.com) für die Binaries, die während der Lücke liefen, da `Prefetch` unabhängig von `Security.evtx` ist und das Log-Löschen überlebt.
- [AmCache](https://www.amcacheparser.com) und [Shimcache](https://www.shimcacheparser.com) für Erst-Ausführungs-Beweise.
- Den [Registry](https://www.registryparser.com)-Hives in Shadow Copies für den Zustand zum Vorfallszeitpunkt.

Ein gecarvter Datensatz, der mit einem Prefetch-Eintrag und einem MFT-Zeitstempel auf einer verdächtigen Binary übereinstimmt, ist ein Befund. Ein einsam stehender gecarvter Datensatz ist ein Hinweis, dem man nachgehen sollte.

## Weiterführende Lektüre

- Andreas Schusters ursprüngliche Carving-Arbeit im [DFRWS-2007-Paper](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). Die Carving-Heuristiken in jedem modernen Tool gehen hierauf zurück.
- Eric Zimmermans [EvtxECmd](https://github.com/EricZimmerman/evtx)-Dokumentation und das `--inc`-Flag für die Behandlung von Teildatensätzen.
- Yamato Securitys [hayabusa](https://github.com/Yamato-Security/hayabusa) und sein mitgeliefertes Beispielkorpus, nützlich zum Testen von Carving-Pipelines.
- Simson Garfinkels [bulk_extractor](https://github.com/simsong/bulk_extractor) und sein EVTX-Scanner-Modul.

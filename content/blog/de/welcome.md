---
title: "Das binäre Windows-Ereignisprotokollformat lesen"
description: "Eine kurze Einführung in den Aufbau von .evtx-Dateien, den Inhalt jedes Ereignisses und warum das Binärformat für die Forensik wichtig ist."
date: "2026-05-16"
---

Das Windows-Ereignisprotokoll — `.evtx` — ist das binäre Format, das Microsoft mit Windows Vista eingeführt hat, um das ältere `.evt` abzulösen. Es ist das Rückgrat fast jeder Windows-Incident-Response: Anmeldungen, Dienststarts, PowerShell-Befehlszeilen, Sysmon-Prozesserstellungen und eine lange Liste anbieterspezifischer Kanäle werden darin serialisiert.

## Wie eine Datei aufgebaut ist

Jede `.evtx`-Datei beginnt mit einem 4 KB großen Header (Magic `ElfFile\0`, Prüfsumme, Block-Anzahl), gefolgt von einer Folge von 64 KB-Blöcken. Jeder Block hat seinen eigenen Header (`ElfChnk`), eine Tabelle der im Block vorkommenden XML-Vorlagen und einen Strom binärer Datensätze, die diese Vorlagen per ID referenzieren. Der Parser rekonstruiert jedes Ereignis, indem er die Vorlagen-Platzhalter mit den Werten aus dem jeweiligen Datensatz verknüpft.

## Wie ein Datensatz aussieht

Einmal dekodiert ist jeder Datensatz ein XML-Dokument mit zwei Hauptteilen:

- `<System>` — Anbietername, Kanal, Event ID, Stufe (1 Kritisch → 5 Ausführlich), Computername, Sicherheitskontext und UTC-Zeitstempel des Schreibens.
- `<EventData>` — anbieterspezifische Parameter: Zielkonto bei einer Anmeldung, Image-Pfad bei einer Prozesserstellung usw.

Die Event ID allein reicht selten für die Triage; das forensische Signal liegt in der `<EventData>`-Nutzlast.

## Wie dieses Tool sie liest

Der Parser ist das Rust-Crate [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx), kompiliert zu WebAssembly und in einen Web Worker geladen. Sobald du eine Datei ablegst, lädt der Worker sie in den Speicher, läuft jeden Block durch und stellt das XML jedes Datensatzes wieder her. Nichts geht über das Netzwerk — trenne dein WLAN, um es zu prüfen.

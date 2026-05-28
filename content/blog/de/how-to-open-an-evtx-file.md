---
title: "Eine .evtx-Datei öffnen (5 Methoden, keine Installation erforderlich)"
description: "Fünf Wege, eine Windows .evtx-Datei zu öffnen: im Browser, im Event Viewer, mit wevtutil, mit EvtxECmd oder mit python-evtx. Wählen Sie nach Host-OS und wie viel Reibung Sie aushalten."
date: "2026-05-24"
howto:
  name: "Eine .evtx-Datei öffnen"
  steps:
    - name: "Öffnen Sie sie in Ihrem Browser (keine Installation)"
      text: "Gehen Sie zur Startseite des EVTX-Parsers und legen Sie Ihre .evtx-Datei auf die Upload-Zone. Die Datei wird lokal in einem Web Worker mit einem Rust EVTX-Parser geparst, der zu WebAssembly kompiliert wurde. Nichts wird hochgeladen. Funktioniert auf Windows, macOS und Linux."
    - name: "Öffnen Sie sie im Event Viewer (nur Windows)"
      text: "Starten Sie eventvwr.msc, wählen Sie Aktion, dann Gespeichertes Protokoll öffnen, navigieren Sie zur .evtx-Datei, benennen Sie die Ansicht und klicken Sie auf OK. Gut zum Durchsuchen eines Channels; schwach zum Filtern über Tausende von Records."
    - name: "Dumpen Sie sie mit wevtutil oder Get-WinEvent (Windows-Kommandozeile)"
      text: "Führen Sie wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt aus, um jeden Record als Text zu exportieren. Aus PowerShell gibt Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 geparste Objekte zurück, die Sie weiter pipen können."
    - name: "Parsen Sie sie mit EvtxECmd (plattformübergreifendes CLI)"
      text: "Laden Sie EvtxECmd von Eric Zimmermans Tools herunter, dann führen Sie EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv aus, um jeden Record (einschließlich aller EventData-Felder) in eine CSV-Zeile pro Event abzuflachen."
    - name: "Skripten Sie sie mit python-evtx (plattformübergreifendes Python)"
      text: "pip install python-evtx, dann python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml ausführen, um jeden Record als XML auf stdout zu erhalten. Langsamer als der Rust-Parser, aber leicht in Pipelines und Jupyter-Notebooks einzubetten."
---

Eine `.evtx`-Datei ist das binäre Windows Event Log-Format ([was darin steckt](/en/blog/what-is-an-evtx-file)). Sie können sie nicht mit einem Texteditor lesen. Es ist BinXML in gechunkten binären Containern. Es gibt fünf Methoden, die jeden realistischen Fall abdecken, in grober Reihenfolge von "Datei ablegen und fertig" bis "in eine Python-Pipeline einbauen".

## Methode 1: im Browser öffnen, keine Installation

Der schnellste Weg auf jedem Betriebssystem. Legen Sie die `.evtx` auf den Parser auf der [Startseite dieser Seite](/en) ab. Die Datei wird in den Speicher Ihres Browsers gelesen und lokal von einem Web Worker geparst, der die [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx)-Crate ausführt, die zu WebAssembly kompiliert wurde. Nichts verlässt Ihre Maschine. Bestätigen Sie das, indem Sie die Netzwerkverbindung trennen, bevor Sie die Datei ablegen.

Sie erhalten dieselbe Record-Level-Ansicht, die ein Desktop-Tool produziert: filterbare Timeline, vollständige `<EventData>` in die Tabelle abgeflacht, vollständiges XML mit einem Klick, CSV/JSON-Export des gefilterten Sets. Richtig für Ad-hoc-Triage, wenn Sie nichts installieren, nichts hochladen wollen oder auf einer Maschine sind, die nicht Ihre ist.

Einschränkung. Browser-Speicher-Caps bedeuten, dass Dateien größer als etwa 500 MB langsam werden. Für mehrere Gigabyte große archivierte Logs steigen Sie auf ein natives Tool um.

## Methode 2: Event Viewer, nur Windows, eingebaut

Jede Windows-Installation liefert den Event Viewer. Starten Sie `eventvwr.msc`, dann **Aktion / Gespeichertes Protokoll öffnen** und wählen Sie die `.evtx`. Der Event Viewer bietet an, die Datei in Ihre aktuelle Ansicht zu importieren. Akzeptieren und Sie können sie wie jeden Live-Channel durchsuchen.

```text
Aktion -> Gespeichertes Protokoll öffnen -> Durchsuchen -> .evtx auswählen -> OK
```

Gut zum Durchsuchen einer einzelnen Datei, zum Anschauen einer benutzerfreundlich formatierten Nachricht eines Records, zum Kopieren einer XML-Ansicht. Schwach zum Filtern Tausender Records (die UI wird langsam), für Bulk-Export oder zum Ausführen von Abfragen, die Sie skripten wollen. Auch am striktesten bei dirty trailing chunks: er lehnt Dateien ab, die andere Tools akzeptieren.

## Methode 3: wevtutil und Get-WinEvent, Windows-Kommandozeile

`wevtutil` ist das Windows-eingebaute für die Log-Verwaltung. `Get-WinEvent` ist sein PowerShell-Gegenstück. Beide funktionieren auf gespeicherten `.evtx`-Dateien, nicht nur auf Live-Channels.

Jeden Record aus einer gespeicherten `.evtx` als Text dumpen:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Mit XPath filtern. Jedes 4624 in den letzten 24 Stunden:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell mit demselben Zweck, aber typisierte Objekte zurückgebend:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Gut für skriptbasierte Extraktion, geplante Jobs, chirurgisches Filtern. Der Trade-off ist Wortreichtum. XPath gegen XML ist präzise, aber nicht freundlich.

## Methode 4: EvtxECmd, der DFIR-Standard

[Eric Zimmermans `EvtxECmd`](https://ericzimmerman.github.io/) ist der Parser, auf den die meisten IR-Praktiker standardmäßig zurückgreifen. Er läuft nativ auf Windows und auf macOS / Linux unter .NET. Er parst schneller als `wevtutil` und flacht jedes `<EventData>`-Feld in eine CSV-Spalte ab. Eine Zeile pro Record.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Für einen ganzen `winevt\Logs\`-Ordner in einem Durchgang, mit Maps, die wohlbekannte Event-Felder in benutzerfreundliche Spalten dekodieren:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Richtig für Bulk-Parsing von Mehrdatei-Sammlungen, Importieren in ein SIEM oder Notebook, plattformübergreifenden Analyst-Workflow. EvtxECmd ist die richtige Antwort für fast jede "parse das offline"-Aufgabe. Paaren Sie es mit KAPEs `EventLogs`-Target und Sie haben eine Ein-Befehls-Engagement.

## Methode 5: python-evtx, skripten Sie es in eine Pipeline

Wenn die Datei eine Python-Pipeline füttern muss, ist [`python-evtx`](https://github.com/williballenthin/python-evtx) der reine Python-Parser.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

In einem Notebook oder Skript:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Langsamer als der Rust-Crate (interpretiertes Python auf binären Chunks), aber der richtige Aufruf, wenn Sie bereits in einer Python-Toolchain sind: Jupyter Forensic Notebooks, Threat-Hunting-Jobs, benutzerdefinierte Anreicherung, Verbindung von EVTX-Daten mit [Registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com) oder [Prefetch](https://www.prefetchparser.com)-Artefakten aus demselben Fall.

## Welche Methode wann verwenden

- Sie wollen nur die Datei ansehen: legen Sie sie auf den [Startseiten-Parser](/en) ab. Am schnellsten, keine Installation.
- Windows-Endpoint mit Admin und die Datei ist klein: Event Viewer.
- Skript-basierte einmalige Extraktion: `wevtutil` oder `Get-WinEvent`.
- Echte DFIR auf Multi-Channel-Sammlungen: EvtxECmd.
- Eine Pipeline in Python bauen: `python-evtx`.

## Häufige Fehler und wie man sie liest

- "Die Datei scheint nicht gültig zu sein" im Event Viewer bedeutet fast immer, dass der trailing chunk dirty ist (die Datei wurde kopiert, während der EventLog-Service noch schrieb). Die meisten Parser kommen damit zurecht. Versuchen Sie [den Browser-Parser](/en) oder `EvtxECmd`, die beide dirty chunks als Warnung melden und fortfahren.
- "Zugriff verweigert" von `wevtutil` gegen eine Datei in `winevt\Logs\` ist der EventLog-Service, der eine exklusive Sperre hält. Siehe [.evtx von einem Live-System sammeln](/en/blog/collecting-evtx-from-live-system) für die vier Standardwege drumherum.
- Leere Ausgabe von `Get-WinEvent` auf einem gespeicherten Log. Übergeben Sie die Datei mit `-Path`, nicht `-LogName`. `-LogName` liest nur Live-Channels.
- PowerShell `Get-WinEvent` sagt "Es wurden keine Ereignisse gefunden, die den angegebenen Auswahlkriterien entsprechen". Ihre `-FilterHashtable`-Schlüssel sind bei einigen Properties case-sensitive. Versuchen Sie es zuerst ohne Filter, um zu bestätigen, dass die Datei parst.

Für Hintergrund dazu, was tatsächlich in einer `.evtx` ist und warum das Format so aussieht, wie es aussieht, siehe [den Chunk-Level Deep Dive](/en/blog/evtx-file-format-chunks).

## Weiterführende Literatur

- [Eric Zimmermans Tools](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)

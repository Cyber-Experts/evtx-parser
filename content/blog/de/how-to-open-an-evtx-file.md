---
title: "EVTX-Datei öffnen: 5 Methoden (ohne Installation möglich)"
description: "Fünf Wege, eine Windows-EVTX-Datei zu öffnen — im Browser, in der Ereignisanzeige, mit wevtutil, mit EvtxECmd oder mit python-evtx. Wähle nach Host-OS und gewünschter Reibung."
date: "2026-05-24"
howto:
  name: "EVTX-Datei öffnen"
  steps:
    - name: "Im Browser öffnen (ohne Installation)"
      text: "Rufe die Startseite des EVTX-Parsers auf und ziehe deine .evtx-Datei in die Upload-Zone. Die Datei wird lokal in einem Web Worker geparst, der einen Rust-EVTX-Parser als WebAssembly ausführt. Nichts wird hochgeladen — trenne dein Netzwerk, wenn du es verifizieren willst. Läuft unter Windows, macOS und Linux."
    - name: "In der Ereignisanzeige öffnen (nur Windows)"
      text: "Starte eventvwr.msc, wähle Aktion → Gespeicherte Protokolldatei öffnen…, suche die .evtx-Datei, benenne die Ansicht und klicke auf OK. Gut zum Stöbern in einem Kanal; schwach beim Filtern über Tausende Datensätze."
    - name: "Mit wevtutil oder Get-WinEvent ausgeben (Windows-Kommandozeile)"
      text: "Führe wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt aus, um jeden Datensatz als Text zu exportieren. In PowerShell liefert Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 geparste Objekte, die du weiter pipen kannst."
    - name: "Mit EvtxECmd parsen (plattformübergreifende CLI)"
      text: "Lade EvtxECmd aus den Eric-Zimmerman-Tools und führe EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv aus, um jeden Datensatz (inklusive aller EventData-Felder) in eine CSV-Zeile pro Ereignis zu flachen. Läuft nativ unter Windows und über .NET auch unter macOS/Linux."
    - name: "Mit python-evtx skripten (plattformübergreifendes Python)"
      text: "pip install python-evtx, dann python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml ausführen, um jeden Datensatz als XML auf stdout zu erhalten. Langsamer als der Rust-Parser, aber leicht in Pipelines und Jupyter-Notebooks einzubetten."
---

Eine `.evtx`-Datei ist das binäre Windows-Event-Log-Format ([was drinsteckt →](/de/blog/what-is-an-evtx-file)). Mit einem Texteditor kannst du sie nicht lesen — es ist BinXML in binären Chunk-Containern. Unten stehen die fünf Methoden, die jeden realistischen Fall abdecken, sortiert von „Datei reinziehen, fertig" bis „in eine Python-Pipeline einbauen".

## Methode 1 — im Browser öffnen (ohne Installation)

Der schnellste Weg unter jedem Betriebssystem: die `.evtx` auf den Parser auf der [Startseite dieser Seite](/de) ziehen. Die Datei wird in den Speicher deines Browsers geladen und lokal von einem Web Worker geparst, der das Rust-Crate [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) als WebAssembly ausführt. Nichts verlässt deinen Rechner — du kannst das überprüfen, indem du dich vor dem Drop vom Netzwerk trennst.

Du bekommst dieselbe datensatzgenaue Ansicht wie bei einem Desktop-Tool: eine filterbare Zeitleiste, das vollständig in die Tabelle geflachte `<EventData>`, das komplette XML einen Klick entfernt und CSV-/JSON-Export der gefilterten Auswahl. Am besten geeignet für Ad-hoc-Triage, wenn du nichts installieren willst, nichts hochladen willst oder an einem fremden Rechner sitzt.

**Einschränkungen.** Browser-Speicherlimits machen Dateien jenseits von ~500 MB zäh. Bei archivierten Logs im Multi-Gigabyte-Bereich solltest du auf ein natives Werkzeug ausweichen.

## Methode 2 — Ereignisanzeige (nur Windows, Bordmittel)

Jede Windows-Installation bringt die Ereignisanzeige mit. Starte sie mit `eventvwr.msc`, dann **Aktion → Gespeicherte Protokolldatei öffnen…** und wähle die `.evtx` aus. Die Ereignisanzeige bietet an, die Datei in die aktuelle Ansicht zu importieren; akzeptiere das, und du kannst sie wie jeden Live-Kanal durchsuchen.

```text
Aktion → Gespeicherte Protokolldatei öffnen… → Durchsuchen → .evtx auswählen → OK
```

Gut für: das Durchsehen einer einzelnen Datei, den Blick auf die formatierte Meldung eines Datensatzes, das Kopieren einer XML-Ansicht. Schwach bei: Filtern über Tausende Datensätze (die UI wird langsam), Massenexport oder Abfragen, die du skripten willst.

## Methode 3 — wevtutil / Get-WinEvent (Windows-Kommandozeile)

`wevtutil` ist das Windows-Bordmittel für die Protokollverwaltung; `Get-WinEvent` ist das PowerShell-Pendant. Beide arbeiten auf gespeicherten `.evtx`-Dateien, nicht nur auf Live-Kanälen.

Jeden Datensatz aus einer gespeicherten `.evtx` als Text ausgeben:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Mit XPath filtern (hier jedes 4624 in den letzten 24 Stunden):

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell mit derselben Absicht, aber als typisierte Objekte:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Gut für: skriptbare Extraktion, geplante Jobs, chirurgisches Filtern. Der Preis ist Geschwätzigkeit — XPath gegen XML ist präzise, aber nicht freundlich.

## Methode 4 — EvtxECmd (plattformübergreifende CLI, DFIR-Standard)

[Eric Zimmermans `EvtxECmd`](https://ericzimmerman.github.io/) ist der Parser, zu dem die meisten IR-Praktiker greifen. Er läuft nativ unter Windows und unter macOS / Linux über .NET, parst schneller als `wevtutil` und flacht jedes `<EventData>`-Feld in eine CSV-Spalte ab. Eine Zeile pro Datensatz.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Einen ganzen `winevt\Logs\`-Ordner in einem Durchgang, mit Maps, die bekannte Ereignisfelder in lesbare Spalten dekodieren:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Gut für: Bulk-Parsing von Multi-File-Sammlungen, Import in SIEM oder Notebook, plattformübergreifenden Analysten-Workflow. EvtxECmd ist die richtige Antwort für so gut wie jede „parse das offline"-Aufgabe.

## Methode 5 — python-evtx (in eine Pipeline einbinden)

Wenn die Datei in eine Python-Pipeline fließen muss, ist [`python-evtx`](https://github.com/williballenthin/python-evtx) der reine Python-Parser.

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

Langsamer als das Rust-Crate (interpretiertes Python auf binären Chunks), aber die richtige Wahl, wenn du ohnehin schon in einem Python-Toolstack arbeitest — forensische Jupyter-Notebooks, Threat-Hunting-Jobs, eigene Anreicherungen.

## Welche Methode wann

- **Du willst die Datei nur anschauen**: Drop sie auf den [Parser auf der Startseite](/de). Schnellster Weg, keine Installation.
- **Du sitzt an einem Windows-Endpunkt mit Adminrechten und die Datei ist klein**: Ereignisanzeige.
- **Du brauchst eine einmalige Extraktion per Skript**: `wevtutil` oder `Get-WinEvent`.
- **Du machst echtes DFIR an Multi-Channel-Sammlungen**: EvtxECmd.
- **Du baust eine Pipeline in Python**: `python-evtx`.

## Häufige Fehler und wie man sie liest

- **„Die Datei scheint nicht gültig zu sein"** in der Ereignisanzeige bedeutet meist, dass der letzte Chunk „dirty" ist (die Datei wurde kopiert, während der EventLog-Dienst noch geschrieben hat). Die meisten Parser kommen damit klar — probier es mit [dem Browser-Parser](/de) oder `EvtxECmd`, beide melden Dirty Chunks als Warnung und machen weiter.
- **„Zugriff verweigert"** von `wevtutil` gegen eine Datei in `winevt\Logs\` ist der EventLog-Dienst, der eine exklusive Sperre hält. Siehe [.evtx von einem laufenden System einsammeln](/de/blog/collecting-evtx-from-live-system) für die vier üblichen Wege drumherum.
- **Leere Ausgabe von `Get-WinEvent`** auf einer gespeicherten Datei: Übergib die Datei mit `-Path`, nicht mit `-LogName`. `-LogName` liest nur Live-Kanäle.
- **PowerShell-`Get-WinEvent` meldet „Es wurden keine Ereignisse gefunden, die mit den angegebenen Auswahlkriterien übereinstimmen"** — die Schlüssel deiner `-FilterHashtable` unterscheiden bei manchen Eigenschaften Groß- und Kleinschreibung. Probiere es zunächst ohne Filter, um sicherzugehen, dass die Datei überhaupt parst.

Hintergründe dazu, was tatsächlich in einer `.evtx` steckt und warum das Format so aussieht, wie es aussieht, findest du in [Was ist eine EVTX-Datei?](/de/blog/what-is-an-evtx-file).

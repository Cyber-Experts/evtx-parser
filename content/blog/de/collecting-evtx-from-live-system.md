---
title: "Wie man .evtx-Logs von einem laufenden Windows-System sammelt (4 Methoden)"
description: "Vier Wege, .evtx von einem Live-Windows-Host zu ziehen: wevtutil, FTK Imager, KAPE, Roh-NTFS. Mit den Beweisketten-Kompromissen für jede und den Befehlen, die du tatsächlich tippst."
date: "2026-05-17"
howto:
  name: "Wie man .evtx-Logs von einem laufenden Windows-System sammelt"
  steps:
    - name: "Mit wevtutil exportieren"
      text: "Führe als Administrator wevtutil epl Security C:\\triage\\Security.evtx aus, um eine portable Kopie des aktiven Security-Kanals zu versiegeln, ohne die Live-Datei zu nehmen."
    - name: "Mit FTK Imager erfassen"
      text: "Öffne FTK Imager, Add Evidence Item, navigiere zu \\Windows\\System32\\winevt\\Logs\\, wähle die Kanaldateien (einschließlich archivierter *.evtx) und Export Files. FTK liest NTFS direkt und umgeht die Datei-Locks des EventLog-Diensts."
    - name: "Bulk-Sammlung mit KAPE"
      text: "Führe kape.exe --tsource C: --target EventLogs --tdest C:\\triage aus, um in einem Durchgang jede .evtx unter winevt\\Logs\\ zu ziehen, mit Beweisketten-Metadaten. Kombiniere mit dem WindowsEventLogs-Modul, um beim Sammeln zu parsen."
    - name: "Roh-NTFS-Lesen"
      text: "Wenn Manipulation vermutet wird, verwende RawCopy oder tsk_recover, um das Volume unter der Dateisystem-Schicht zu öffnen (\\\\.\\PhysicalDriveN oder \\\\.\\C:) und jede .evtx Byte für Byte aus der MFT zu lesen. Der EventLog-Dienst kann diesen Pfad nicht blockieren."
---

Das erste schwere Problem in einem Event-Log-Job ist nicht das Parsen. Es ist, die Dateien vom Host zu bekommen, ohne dass der EventLog-Dienst dir auf die Finger haut. Auf einer laufenden Windows-Kiste hält der Dienst offene Handles zu den aktiven [`.evtx`-Dateien](/de/blog/what-is-an-evtx-file) in `C:\Windows\System32\winevt\Logs\`, also gibt ein naives `copy` Sharing-Violation-Fehler zurück. Vier Methoden decken fast jeden Fall ab, den ich erlebt habe.

## wevtutil und Get-WinEvent: integriert, am schnellsten

Der billigste Weg nutzt die von Microsoft dokumentierte API:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Das erzeugt eine versiegelte `.evtx` mit jedem Datensatz, der aktuell im Kanal ist. Kein Drittanbieter-Tooling, Admin-Shell erforderlich. Der Haken, den man laut aussprechen sollte: `epl` erfasst nur das aktive Log. Rotierte `Archive-Security-*.evtx`-Dateien im selben Verzeichnis werden zurückgelassen. Wenn die Rotation kürzlich passiert ist und die Datensätze, die du willst, in einem Archiv liegen, verfehlt diese Methode sie.

PowerShell macht stattdessen geparste Datensätze:

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

Das gibt dir eine CSV, kein `.evtx`. Bequem für Ad-hoc-Triage auf der Kiste. Nutzlos für [Chunk-Level-Recovery, Dirty-Chunk-Inspektion oder Carving aus nicht zugewiesenem Speicher](/de/blog/evtx-file-format-chunks), weil du die binäre Treue weggeworfen hast.

## FTK Imager: NTFS-Level-Akquise

Wenn du die Datei willst, nicht die Datensätze, ist FTK Imager das Arbeitspferd. Füge das Live-Laufwerk als Beweis hinzu (Physical Drive oder Logical Drive), navigiere zu `\Windows\System32\winevt\Logs\`, Rechtsklick auf die Kanaldateien und Export Files. FTK liest die zugrunde liegenden NTFS-Strukturen direkt, was das Dateisystem-Lock umgeht, das der EventLog-Dienst hält. Es erfasst auch die archivierten `Archive-*.evtx`-Dateien, die `wevtutil epl` überspringt.

Kompromiss: FTK liest Dateien, die mitten im Schreiben sein können. Der nachfolgende Chunk auf dem aktiven Kanal kann dirty sein. Die meisten Parser gehen damit elegant um (einschließlich des [Browser-Parsers auf dieser Seite](/de/blog/how-to-open-an-evtx-file)), aber verifiziere es auf der Werkbank, bevor du es in einen Bericht schreibst. Die entsprechenden [USN-Journal](https://www.usnparser.com)-Einträge sind nützliche Bestätigung, wenn du vermutest, dass der EventLog-Dienst während der Akquise etwas Außergewöhnliches getan hat.

## KAPE: Bulk-Sammlung bei IR-Geschwindigkeit

Wenn der Auftrag mehr als einen Host hat, zahlt sich der Kroll Artifact Parser and Extractor binnen einer Stunde aus.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Das `EventLogs`-Target fegt jede `.evtx` unter `winevt\Logs\` plus die zugehörigen ETW-Dateien. Kombiniere es mit dem `!EZParser`- oder `WindowsEventLogs`-Modul, und KAPE wird beim Hinausgehen auch EvtxECmd gegen die Sammlung laufen lassen, was dir geparste CSVs neben den Rohbeweisen liefert. Während du dabei bist, holen die `RegistryHives`- und `FileSystem`-Targets die [Registry](https://www.registryparser.com)-, [MFT](https://www.mftparser.com)-, [USN-Journal](https://www.usnparser.com)- und [Prefetch](https://www.prefetchparser.com)-Daten ab, die du sowieso willst.

KAPEs Ausgabe wird mit Copy-Log-Metadaten ausgeliefert. Das zählt für die Beweiskette mehr, als die Leute ihm zugutehalten.

## Roh-NTFS-Lesen: wenn du Manipulation vermutest

Für maximale Treue fall unter die Dateisystem-Schicht. The Sleuth Kits `tsk_recover` und `icat` oder Eric Zimmermans `RawCopy.exe` öffnen das Volume über `\\.\PhysicalDriveN` oder `\\.\C:`, gehen durch die MFT und geben den Dateiinhalt Byte für Byte aus. Der EventLog-Dienst kann das nicht blockieren, weil das Lesen nicht durch die Win32-Datei-API geht.

Nutze das, wenn ein Rootkit im Spiel ist, wenn du Grund hast zu denken, dass ein Kernel-Filtertreiber `\winevt\Logs\`-Lesevorgänge abfängt, oder wenn du dem laufenden OS einfach nicht traust. Kombiniere das Ergebnis mit einem zur selben Zeit genommenen [RAM-Dump](https://www.ramparser.com). Der Event-Log-Dienst cacht aktuelle Datensätze im Speicher, und ein Snapshot, der Minuten vor der Manipulation genommen wurde, enthält manchmal Datensätze, die es nie auf die Festplatte geschafft haben.

## Welche wann

- Ein Host, du hast Admin-Rechte, du hast eine Stunde: `wevtutil epl` für jeden Kanal, der zählt, Verzeichnis zippen, fertig.
- Disk-Image schon in der Hand: FTK Imager oder `tsk_recover` gegen das Image. Schneller als der Live-Host, und du musst dich nicht mit dem SOC koordinieren.
- Mehrere Hosts, echter IR-Auftrag: KAPE. Bei Durchsatz kommt nichts anderes nahe heran.
- Vermutete Live-Manipulation oder Rootkit: RawCopy oder TSK gegen das Volume, mit isoliertem Host-Netzwerk.

Welche du auch wählst, dokumentiere es. Geparste CSVs sagen nichts über Herkunft. Eine Zeile in den Fallnotizen, die `KAPE 1.3.0.2 EventLogs target, hash file attached` lautet, ist der Unterschied zwischen einem Beweisstück und einer Meinung.

## Weiterführende Lektüre

- [KAPE-Dokumentation](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)

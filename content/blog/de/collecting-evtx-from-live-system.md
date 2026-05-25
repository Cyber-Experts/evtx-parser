---
title: ".evtx-Logs vom laufenden Windows-System holen (4 Methoden)"
description: "Vier Wege, .evtx von einem laufenden Windows-Host zu ziehen — wevtutil, FTK Imager, KAPE, rohes NTFS — mit den jeweiligen Chain-of-Custody-Trade-offs und den Befehlen, die du wirklich brauchst."
date: "2026-05-17"
howto:
  name: ".evtx-Logs von einem laufenden Windows-System sammeln"
  steps:
    - name: "Export mit wevtutil"
      text: "Führe wevtutil epl Security C:\\triage\\Security.evtx als Administrator aus, um eine portable Kopie des aktiven Security-Kanals zu sichern, ohne die Live-Datei anzufassen."
    - name: "Acquisition mit FTK Imager"
      text: "FTK Imager öffnen, Add Evidence Item → Physical or Logical Drive, zu \\Windows\\System32\\winevt\\Logs\\ navigieren, die Kanaldateien (inklusive archivierter *.evtx) auswählen und Export Files. FTK liest NTFS direkt und umgeht die Datei-Sperren des EventLog-Dienstes."
    - name: "Massenerfassung mit KAPE"
      text: "Führe kape.exe --tsource C: --target EventLogs --tdest C:\\triage aus, um alle .evtx unter winevt\\Logs\\ in einem Durchgang mit Chain-of-Custody-Metadaten zu ziehen. Kombiniere es mit dem WindowsEventLogs-Modul, um direkt bei der Erfassung zu parsen."
    - name: "Rohes NTFS-Lesen"
      text: "Wenn Manipulation vermutet wird, öffne mit RawCopy oder tsk_recover den Datenträger unterhalb der Dateisystem-Ebene (\\\\.\\PhysicalDriveN oder \\\\.\\C:) und lies jede .evtx-Datei Byte für Byte aus der MFT. Der EventLog-Dienst kann diesen Pfad nicht blockieren."
---

Das erste schwierige Problem in einer Event-Log-Untersuchung ist nicht das Parsen, sondern *die Dateien zu bekommen*. Auf einem laufenden Windows-Host hält der EventLog-Dienst offene Handles auf die aktiven [`.evtx`-Dateien](/de/blog/what-is-an-evtx-file) in `C:\Windows\System32\winevt\Logs\`, was bedeutet, dass ein naives `copy` scheitert. Vier Ansätze decken nahezu jeden Fall ab.

## Bordmittel: wevtutil / Get-WinEvent

Die einfachste Methode exportiert Datensätze (nicht die Datei) über die dokumentierte API:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Das erzeugt eine versiegelte `.evtx`, die jeden Datensatz enthält, der aktuell im Log steht. Schnell, ohne Drittanbieter-Tools, läuft als Administrator. Nachteil: archivierte (rotierte) `.evtx`-Dateien werden nicht erfasst, nur die aktive.

PowerShell-Äquivalent:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` liefert geparste Datensätze, nicht die Datei. Nützlich für eine schnelle Triage-CSV, verliert aber die binäre Treue, die für tiefere Forensik nötig ist — [Chunk-Level-Recovery, Inspektion von Dirty Chunks, Carving](/de/blog/evtx-file-format-chunks).

## FTK Imager

Für die Akquise auf Volldatenträger- oder Dateisystem-Ebene ist FTK Imager der Standard. Füge das Live-Laufwerk als Beweisstück hinzu (Physical Drive oder Logical Drive), navigiere zu `\Windows\System32\winevt\Logs\`, Rechtsklick auf die Kanal-Dateien, Export Files. FTK liest die zugrundeliegenden NTFS-Strukturen direkt und umgeht damit die Dateisystem-Sperre, die der EventLog-Dienst hält. Er exportiert auch archivierte `*.evtx`-Dateien (die mit Zeitstempeln im Namen), die `wevtutil` nicht anrührt.

Der Trade-off: FTK liest Dateien, die mitten im Schreibvorgang sein können — die resultierende `.evtx` kann einen Dirty-Trailing-Chunk haben. Die meisten Parser ([auch dieser](/de/blog/how-to-open-an-evtx-file)) gehen damit sauber um, aber es lohnt sich zu verifizieren.

## KAPE

Für Incident Response im großen Maßstab automatisiert der Kroll Artifact Parser and Extractor (KAPE) die Sammlung jeder forensisch relevanten Datei in einem Durchgang:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

Das `EventLogs`-Target zieht jede `.evtx` unter `winevt\Logs\` plus die zugehörigen Event-Tracing-Dateien. Kombiniert mit dem `WindowsEventLogs`-Modul läuft auch ein sofortiger Parser und produziert eine CSV neben den Rohdateien. Empfehlung für jede IR-Aufgabe, die mehr als einen Host betrifft.

## Roh-NTFS-Read

Für maximale Treue — nützlich, wenn du vermutest, dass die Live-Dateisystem-APIs abgefangen werden, oder wenn du eine Bit-für-Bit-Akquise willst — liest du das Volume unterhalb der Dateisystem-Ebene. Tools wie [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) oder Eric Zimmermans `RawCopy.exe` öffnen das Volume über `\\.\PhysicalDriveN` oder `\\.\C:`, laufen über die MFT und geben den Dateiinhalt Byte für Byte aus. Der EventLog-Dienst kann das nicht blockieren, weil der Read die Dateisystem-Ebene komplett umgeht.

## Wann was

- **Schnelle Triage auf einem Host, du hast Admin**: `wevtutil`.
- **Volle forensische Akquise, du hast bereits ein Disk-Image**: FTK Imager oder `tsk_recover` gegen das Image.
- **IR-Einsatz, mehrere Hosts**: KAPE.
- **Verdacht auf Rootkit oder Live-Tampering**: rohes NTFS via RawCopy oder TSK auf dem Live-Volume, mit netzwerk-isoliertem Host.

Was immer du wählst, dokumentiere es. Die Provenienzkette zählt in Incident Reports — eine geparste CSV sagt nichts darüber, ob sie von einem Live-Host mit laufendem EventLog-Dienst oder von einem versiegelten Image stammt.

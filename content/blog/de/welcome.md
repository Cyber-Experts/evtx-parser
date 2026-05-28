---
title: "Hier starten: Leitfaden eines DFIR-Analysten zu .evtx"
description: "Was .evtx ist, welche Kanäle wichtig sind, die Event IDs, die man kennen muss, und wo jede davon auf der Festplatte zu finden ist. Ein Orientierungspunkt für alles Weitere in diesem Blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` ist das binäre Windows-Ereignisprotokollformat, das Microsoft mit Vista zum Ersatz des älteren `.evt` ausgeliefert hat. Es ist das Rückgrat jeder Windows-Incident-Response: Anmeldungen, Dienstinstallationen, geplante Aufgaben, PowerShell-Befehlszeilen, Sysmon-Prozessbäume. All das wird in dieses Format serialisiert. Dieser Beitrag ist der Index. Eine Orientierung auf einer Bildschirmseite, dann Links zu den tieferen Beiträgen über die Kanäle und Event IDs, die in einem Fall wirklich zählen.

Neu bei `.evtx`? Beginne mit [was eine .evtx-Datei ist](/de/blog/what-is-an-evtx-file) und [wie man eine öffnet](/de/blog/how-to-open-an-evtx-file). Der Rest dieses Beitrags setzt voraus, dass du mit dem Format bereits vertraut bist und wissen willst, was zuerst zu lesen ist, wenn ein Host brennt.

## Wo die Dateien liegen

Live-Protokolle liegen unter `C:\Windows\System32\winevt\Logs\`. Ein Kanal, eine `.evtx`-Datei. Die Standardwerte, die du immer hast:

- `Security.evtx`. Anmeldungen, Privilegiennutzung, Änderungen der Audit-Richtlinie. In den meisten Fällen der höchste forensische Wert.
- `System.evtx`. Treiber, Dienste, Fehler auf OS-Ebene.
- `Application.evtx`. Fehler auf Anwendungsebene.
- `Setup.evtx` und `ForwardedEvents.evtx`. Installationseinträge und weitergeleiteter WEF-Verkehr.

Dazu anwendungsspezifische Kanäle unter `Microsoft-Windows-*`. Die, die sich in einem Fall lohnen:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Nur vorhanden, wenn Sysmon installiert ist. Goldwert, wenn doch.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Scriptblock- und Modul-Logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Erstellung und Ausführung geplanter Aufgaben.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. RDP-Sitzungs-Lebenszyklus.

Für tiefe Details zum Aufbau einer Datei (die 64-KB-Blöcke, die XML-Vorlagentabellen, BinXML) siehe [die Block-Tiefenanalyse](/de/blog/evtx-file-format-chunks).

## Die Event IDs, die man kennen muss

Die Kurzliste, die das meiste abdeckt, worauf ein Analyst pivotiert:

- [**4624** erfolgreiche Anmeldung](/de/blog/understanding-event-id-4624). Lies sie über `LogonType`. Das Feld entscheidet, ob du eine Konsole (2), Netzwerk (3), RDP (10) oder `runas /netonly` (9) siehst.
- [**4625** fehlgeschlagene Anmeldung](/de/blog/detecting-4625-brute-force). Bursts sind Erkundung, Brute Force oder Password Spray, je nachdem, welche Felder sich häufen.
- [**1102** Sicherheitsprotokoll geleert](/de/blog/event-id-1102-cleared-log). Wenn du das siehst, hat das Protokoll, das du in der Hand hältst, eine bekannte Lücke. Notiere es deutlich.
- [**4104** PowerShell-Scriptblock](/de/blog/powershell-4104-scriptblock). Der Skripttext *nach* Dekodierung und Reflexion. Die mit Abstand nützlichste kostenlose defensive Kontrolle der Plattform.
- [**7045** Dienst installiert](/de/blog/service-creation-event-id-7045). Eine der meistzitierten Persistenztechniken in MITRE ATT&CK (T1543.003). Auch die PsExec-Signatur.
- [**Sysmon 1** Prozesserstellung](/de/blog/sysmon-event-id-1-process-create). Der reichhaltigste Prozesserstellungsdatensatz, den Windows liefern kann, wenn Sysmon vorhanden ist.

Für den Workflow, der sie zusammenführt, lies [EVTX-Triage, wenn du eine Stunde und einen Host hast](/de/blog/evtx-triage-incident-response).

## Wie diese Seite zusammenpasst

Der Parser auf der Startseite ist das Rust-Crate [omerbenamram/evtx](https://github.com/omerbenamram/evtx), kompiliert zu WebAssembly und ausgeführt in einem Web Worker. Du legst eine `.evtx` ab, der Worker geht die Blöcke durch, und du erhältst eine filterbare Ereignis-Timeline plus XML pro Datensatz. Alles im Browser, nichts wird hochgeladen. Nutze es für Ad-hoc-Triage, wenn du keine EDR hochfahren oder eine Datei nicht von einem System nehmen willst, das dir nicht gehört.

Wenn du [`.evtx` von einem Live-Host sammelst](/de/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), deckt dieser Beitrag die vier Standardmethoden mit ihren jeweiligen Beweiskettenkompromissen ab.

EVTX ist selten das einzige Artefakt, das du brauchst. Kombiniere es mit Parsern für [Registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN-Journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [Prefetch](https://www.prefetchparser.com) und [LNK](https://www.lnkparser.com). Wenn du tiefer graben musst, holen [Pagefile](https://www.pagefilesysparser.com) und [RAM-Dump](https://www.ramparser.com) das zurück, was plattenresidente Logs verloren haben. Für Zeitleisten zur Benutzeraktivität füllen [SRUM](https://www.srumparser.com), [Jump Lists](https://www.jumplistparser.com), [Papierkorb](https://www.recyclebinparser.com), [Recent File Cache](https://www.recentfilecacheparser.com) und [Browserverlauf](https://www.browserforensics.app) die Lücken, die EVTX nicht schließen kann.

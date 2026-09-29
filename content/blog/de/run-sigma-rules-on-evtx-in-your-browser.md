---
title: "Sigma-Regeln auf EVTX im Browser ausführen"
description: "2.395 SigmaHQ-Regeln auf Windows-.evtx-Logs, ohne Hayabusa oder Chainsaw zu installieren: Sigma-Erkennung im Browser, ATT&CK-Kontext, Pivots und eigene YAML-Regeln."
date: "2026-09-29"
tags:
  - evtx
  - dfir
  - threat-hunting
  - sigma
  - sysmon
author: "Florian Amette"
---

Sigma ist das, was dem Detection Engineering am ehesten als gemeinsame Sprache dient. Eine Regel beschreibt, *wie* Verdächtiges aussieht — ein Prozess, ein Registry-Schreibzugriff, eine Anmeldung mit dem falschen Typ — und ein Backend übersetzt sie in die Sprache Ihres SIEM. Für Ereignisprotokolle auf dem Laptop eines Analysten ist die übliche Antwort ein Kommandozeilenwerkzeug wie Hayabusa oder Chainsaw: Binary herunterladen, auf einen Ordner mit `.evtx`-Dateien richten, CSV lesen.

Das funktioniert, setzt aber voraus, dass Sie auf dem Rechner mit den Beweismitteln ein unsigniertes Binary ausführen dürfen und die Zeit für die Einrichtung haben. Dieser Viewer führt den SigmaHQ-Regelsatz jetzt direkt im Browser-Tab aus, neben den Ereignissen. Nichts wird installiert, nichts wird hochgeladen.

## Was Sie beim Ablegen eines Logs bekommen

Öffnen Sie wie gewohnt eine oder mehrere `.evtx`-Dateien. Sobald das Parsen fertig ist, führt der Web Worker des Parsers jede mitgelieferte Regel über jeden Datensatz aus, und der Tab **Sigma** zeigt ein Badge mit der Zahl der Regeln, die getroffen haben.

Im Tab:

- Getroffene Regeln sind nach Stufe gruppiert — kritisch, hoch, mittel, niedrig, informativ — mit der Zahl der Ereignisse pro Regel.
- Die Auswahl einer Regel zeigt Beschreibung, MITRE-ATT&CK-Taktiken und -Techniken (verlinkt auf attack.mitre.org), die vom Autor dokumentierten False Positives, Referenzen, Protokollquelle und Regel-ID.
- Die getroffenen Ereignisse werden mit den Feldern aufgelistet, die die Regel tatsächlich geprüft hat. Ein Klick auf einen Zeitstempel öffnet das Ereignis in der Haupttabelle; **Rund um dieses Ereignis** setzt den Zeitraum auf ein Fenster um das Ereignis, damit Sie sehen, was kurz davor und danach geschah.
- **In der Ereignistabelle zeigen** beschränkt die Tabelle auf die Treffer der Regel, sodass Suche, Feldleiste und Exporte darauf arbeiten.
- Der vorhandene Zeitraum gilt: Grenzen Sie ihn auf das Vorfallsfenster ein, und die Zähler folgen.
- **Treffer exportieren** schreibt CSV oder JSON mit Regel-ID, Titel, Stufe, Record-ID, Zeit, Computer, Kanal und den Werten der Schlüsselfelder.

Wenn Ihnen die beteiligten Event-IDs neu sind: [Sysmon Event ID 1](/de/blog/sysmon-event-id-1-process-create) und [Security 4688](/de/blog/event-id-4688-process-creation) sind die beiden Datensätze, auf die die meisten Regeln am Ende schauen.

## Welche Regeln, und wie sie auf EVTX abgebildet werden

Der Regelsatz ist `rules/windows/**` aus einem festgelegten SigmaHQ-Release (zum Zeitpunkt des Schreibens r2026-07-01). Er wird beim Build geholt und als JSON-Datei mit der Website ausgeliefert, der Browser kontaktiert GitHub also nie — die Content Security Policy der Website würde es ohnehin nicht zulassen. Von 2.403 Windows-Regeln laufen 2.395. Die 8 ausgelassenen nutzen die Kategorien `file_access` und `file_rename`, die aus ETW-Providern stammen, die nie in eine `.evtx`-Datei schreiben. Veraltete Regeln werden nicht importiert.

Sigma-Regeln nennen eine Protokollquelle, keine Datei. Die Zuordnung ist dieselbe, die Hayabusa, Chainsaw und pySigma verwenden:

- `category: process_creation` läuft auf Sysmon Event ID 1 **und** auf Security 4688. Für 4688 werden Felder übersetzt: `Image` liest `NewProcessName`, `ParentImage` liest `ParentProcessName`, `IntegrityLevel` wird aus `MandatoryLabel` abgeleitet, und die hexadezimalen Prozess-IDs werden umgerechnet.
- Andere Sysmon-Kategorien entsprechen ihren Event-IDs: Netzwerkverbindungen 3, Image-Loads 7, Prozesszugriff 10, Dateierstellung 11, Registry 12–14, DNS 22.
- `ps_script` und `ps_module` lesen PowerShell Operational 4104 und 4103; die klassischen `ps_classic_start`-Regeln lesen Windows PowerShell 400, wo `HostApplication=` und Verwandte aus dem `Data`-Block gezogen werden.
- `service: security`, `system`, `windefend`, `taskscheduler`, `bits-client` und rund vierzig weitere entsprechen ihrem Kanal.

Ein 4688 hat weder `OriginalFileName` noch `Hashes` noch `CurrentDirectory`, Regeln, die nur auf diesen Feldern beruhen, können darauf also nicht auslösen. Das liegt am Protokoll, nicht an der Engine: Wenn diese Regeln greifen sollen, sammeln Sie Sysmon.

## Eigene Regeln mitbringen

Die Schaltfläche **Eigene Regeln** nimmt YAML aus einem Textfeld oder abgelegte `.yml`-Dateien an (mehrere Regeln, getrennt durch `---`, sind kein Problem). Jede Regel wird im Worker geparst und kompiliert; Fehler werden pro Regel gemeldet, gültige Regeln laufen beim nächsten Durchgang mit:

```yaml
title: Dienst aus einem Benutzerprofil installiert
id: 3b0f0b6e-6b1d-4e36-9a44-6d2f7d8f7a11
author: Ihr Name
level: high
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains: '\Users\'
  condition: selection
```

Ihre Regeln bleiben im lokalen Speicher dieses Browsers, damit sie ein Neuladen überstehen. Sie werden nirgendwohin gesendet.

## Was die Engine unterstützt

Die Engine implementiert den Detection-Teil der Sigma-Spezifikation: Selektionen als Maps und Listen, Keyword-Suchen, Wildcards mit Sigmas Escape-Regeln sowie die Modifier `contains`, `startswith`, `endswith`, `all`, `exists`, `re` (mit `i`, `m`, `s`), `cased`, `base64`, `base64offset`, `utf16le`, `utf16be`, `wide`, `windash`, `cidr`, `gt`, `gte`, `lt`, `lte` und `fieldref`. Bedingungen unterstützen `and`, `or`, `not`, Klammern, `1 of`, `all of` und `them`.

Zwei Dinge werden bewusst nicht unterstützt, und das Werkzeug sagt das, statt sie stillschweigend zu überspringen: Aggregationsbedingungen (`| count() by …`) und Sigma-Korrelationsregeln. Keine der mitgelieferten Windows-Regeln nutzt sie; fügen Sie eine ein, wird sie mit Begründung als nicht geladen aufgeführt.

## Ist das schnell genug?

2.400 Regeln naiv auf jedes Ereignis anzuwenden wäre langsam: Ein einziger Sysmon-Prozesserstellungs-Datensatz ist Kandidat für rund 1.200 Regeln. Die Engine sortiert Regeln nach Kanal und Event-ID und gibt jeder Regel einen literalen Vorfilter — etwa: `Image` muss auf `\certutil.exe` enden, oder `CommandLine` muss `urlcache` enthalten. Diese Literale werden pro Feld indiziert, Teilstrings in einem Aho-Corasick-Automaten, sodass jeder Datensatz nur die Handvoll Regeln ausführt, deren Vorfilter angeschlagen hat. In der Testsuite brauchen 200.000 synthetische Ereignisse gegen den vollen Satz etwa fünf Sekunden, und der Worker meldet den Fortschritt und bleibt währenddessen ansprechbar.

Für eine sehr große Sammlung — die Logs einer ganzen Domäne — bleibt ein natives Werkzeug auf einer Workstation schneller. Für den Host vor Ihnen ist es meist fertig, bevor Sie das Findings-Panel zu Ende gelesen haben. Einen Einstieg für diese erste Stunde bietet [was man beim EVTX-Triage zuerst liest](/de/blog/evtx-triage-incident-response).

## Ehre, wem Ehre gebührt

Die Regeln sind die Arbeit der SigmaHQ-Community und stehen unter der Detection Rule License 1.1. Jeder Treffer zeigt „Regel von *Autor* · SigmaHQ · DRL 1.1“ mit einem Link zur Originalregel, und jede exportierte Zeile trägt dieselbe Attribution. Wenn eine Regel Ihnen hilft, einen Fall abzuschließen, verweist ihr Referenzteil meist auf die Forschung dahinter — die Lektüre lohnt sich.

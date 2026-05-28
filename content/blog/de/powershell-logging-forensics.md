---
title: "PowerShell-Logging: was Sie mit Modul- und Scriptblock-Logging an bekommen"
description: "Der praktische Unterschied zwischen PowerShell Module Logging, Script Block Logging, Transcripts und AMSI-Buffern, und die GPO-Einstellungen, die die nützlichen tatsächlich einschalten."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Jedes Adversary-Toolkit, das es wert ist, sich darüber Gedanken zu machen, führt irgendwann PowerShell aus. Cobalt-Strike-Beacons starten es. Empire und Covenant sind darauf aufgebaut. Living-off-the-Land-Guides beginnen damit. Die gute Nachricht ist, dass Microsoft seit PowerShell 5.0 Logging ausliefert, das, wenn richtig konfiguriert, den wörtlichen Text von allem erfasst, was PowerShell ausführt, einschließlich obfuskierter Payloads nach der Deobfuskation. Die schlechte Nachricht ist, dass "wenn richtig konfiguriert" in diesem Satz viel Arbeit leistet. Die meisten Umgebungen, in die ich gehe, haben eines der vier relevanten Logs an, nicht alle vier, und nicht das nützlichste.

Dieser Beitrag ist, was Sie tatsächlich bekommen, was es wert ist einzuschalten, und wo die Lücken sind.

## Die vier Logs, in Reihenfolge der Nützlichkeit

PowerShell schreibt in `Microsoft-Windows-PowerShell%4Operational.evtx`. Die Event-IDs, die wichtig sind:

- `4104` Script Block Logging. Der wörtliche Text jedes Script-Blocks, den PowerShell kompiliert und ausführt. Wenn ein Block von den eingebauten Heuristiken als verdächtig markiert wird, wird er mit Warning-Severity geloggt; sonst mit Verbose, was standardmäßig aus ist. Das ist das Event, das Sie wollen.
- `4103` Module Logging. Zeichnet Pipeline-Ausführung pro Modul auf, mit Parameter-Binding. Weniger Prosa als `4104`, strukturierter. Nützlich für "welche Cmdlets liefen" ohne den Skript-Body.
- `4105` und `4106` Pipeline gestartet und Pipeline gestoppt. Nützlich für Bracketing, nicht für Inhalt.
- `400` / `403` (Legacy, PowerShell 2.0 Ära) Engine-State-Änderungen. Die forensisch-historischen Events. Sie werden diese immer noch auf Hosts sehen, wo jemand einen PS 2.0 Downgrade-Angriff erzwungen hat.

Wenn Sie genau eine Sache einschalten können, schalten Sie `4104` auf Verbose. Alles andere ist ergänzend.

## Was `4104` tatsächlich erfasst

Ein `4104`-Event enthält den vollständigen Text eines Script-Blocks, wie PowerShell ihn kompiliert hat. Zwei Dinge folgen aus "wie PowerShell ihn kompiliert hat":

- Der Text im Event ist in den meisten Fällen die *Post-Deobfuskations*-Repräsentation. Wenn ein Operator `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))` ausführt, bekommen Sie sowohl den äußeren `iex`-Aufruf (der selbst ein `4104` ist) als auch einen *zweiten* `4104` für den inneren dekodierten Script-Block, weil PowerShell diesen Block kompilieren musste, um ihn auszuführen. Das ist die einzige wertvollste Eigenschaft des `4104`-Loggings.
- Große Skripte werden über mehrere Events mit `MessageNumber` und `MessageTotal` in den Event-Daten geteilt. Ein 50 KB Skript wird zu einer Kette von Events, die Sie vor der Analyse wieder zusammensetzen müssen. Die meisten Tools tun das; einige nicht. Wenn Ihr Parser Ihnen Fragmente zeigt, prüfen Sie, ob er die Kette handhabt.

Das `Path`-Feld zeigt die Quelldatei, falls es eine gab. Leeres `Path` plus ein vollständig inlined Skript-Body bedeutet "das kam über den Draht oder aus dem Speicher" und ist die einzige beste Heuristik, um interaktive Operator-Aktivität gegenüber geplanten Skripten zu finden.

Die `ScriptBlockId` ist eine GUID. Re-Runs desselben Blocks auf demselben Host verwenden typischerweise dieselbe GUID (wegen des Caches), was praktisch ist, um "jeden Host, auf dem dieser Code lief" zu finden, wenn Sie ein SIEM mit Cross-Host-Suche haben.

## Module Logging: was `4103` hinzufügt

Module Logging ist älter und lauter als Script Block Logging. Es hakt sich in die Pipeline-Ausführungs-Layer ein, sodass Sie für jeden Cmdlet-Aufruf in einem geloggten Modul ein `4103` mit dem Cmdlet-Namen, den gebundenen Parametern und einem Payload-String bekommen.

In modernem IR ist `4103` in drei Fällen am nützlichsten:

- Der Angreifer hat Cmdlets verwendet, die interessante Parameter binden (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` zeigt die Quelle; `4103` zeigt die aufgelösten Parameterwerte nach Variablen-Expansion.
- Der Angreifer hat codierte Befehle verwendet. `powershell -enc <base64>` produziert ein `4103` mit dem dekodierten Text im Payload, bevor das entsprechende `4104` emittiert wird.
- Der Angreifer hat `4104` deaktiviert (durch Registry-Edit erreichbar, wenn er lokale Admin-Rechte hat). `4103` lebt unter einem separaten Logging-Pfad und wird manchmal angelassen, wenn `4104` zum Schweigen gebracht wird.

Der Haken: Module Logging loggt nur Module, die explizit aktiviert sind. Die GPO-Einstellung will entweder `*` (alles loggen) oder eine Liste von Modulnamen. `*` ist die Antwort in jeder Umgebung, die Logging ernst nimmt. Der "Performance-Impact"-Einwand, den Sie hören werden, ist für sehr schwere PowerShell-Workloads real und für normale Fleet-Desktops falsch.

## Transcripts sind keine Script-Block-Logs

Es gibt eine separate Einstellung namens "Turn on PowerShell Transcription", die Input und Output jeder Session in eine Textdatei unter einem konfigurierten Verzeichnis schreibt. Das ist nicht dasselbe wie `4104` und Leute verwechseln sie ständig.

Die wichtigen Unterschiede:

- Transcripts enthalten Cmdlet-*Output*. `4104` nicht. Wenn Sie wissen wollen, was `Get-ADUser` tatsächlich zurückgegeben hat, sind Transcripts das.
- Transcripts sind Textdateien. Sie sind trivial löschbar und trivial modifizierbar auf einem kompromittierten Host. `4104`-Events gehen auf einen EVTX-Channel, der Log-Clearing oder Schlimmeres erfordert, um gestört zu werden.
- Transcripts gehen standardmäßig in den Documents-Ordner des Benutzers, es sei denn `OutputDirectory` ist gesetzt. Wenn Sie `OutputDirectory` nicht auf eine Write-Only-Netzwerkfreigabe setzen, sind Transcripts kein Beweis; sie sind eine Höflichkeit.

Schalten Sie Transcripts mit `OutputDirectory` auf einen UNC-Pfad, wo der schreibende Benutzer Write-Only-NTFS-Berechtigungen hat (kein Lesen, kein Löschen). Das gibt Ihnen den Cmdlet-Output-Trail, den `4104` nicht hat, ohne dem Angreifer die Option zu geben, seine eigene Historie zu ändern oder zu entfernen.

## AMSI und der Buffer-Aspekt

AMSI (das Antimalware Scan Interface) ist der Runtime-Hook, der Defender und anderen AV-Produkten erlaubt, PowerShell-Skript-Inhalt vor der Ausführung zu inspizieren. Zwei Konsequenzen für Forensik:

- Selbst wenn der Angreifer PowerShell-Logging deaktiviert, sieht AMSI den Skript-Inhalt immer noch direkt vor der Ausführung, und Defender wird ein `1116` oder `1117` in `Microsoft-Windows-Windows Defender%4Operational.evtx` loggen, wenn der Inhalt einer Signatur entspricht. Das Defender-Event enthält den Skript-Text, teilweise, im Threat-Detection-Record. Auf Hosts, wo Script Block Logging aus war, ist das manchmal der einzige Ort, wo der bösartige Code lebt.
- Die "AMSI-Bypass"-Techniken, die Angreifer verwenden (Patchen von `amsi.dll!AmsiScanBuffer` im Speicher, Bereitstellen eines gefälschten `AmsiContext`, COM-Hijack des AMSI-Providers), werden selbst typischerweise `4104`-Events für den Bypass-Code generieren, *bevor* der Bypass in Kraft tritt. Der Bypass kann Logging nicht rückwirkend ausschalten. Also selbst auf Hosts, wo der Operator AMSI erfolgreich neutralisiert hat, ist der Moment, in dem er es getan hat, aufgezeichnet.

Das Muster, nach dem in `4104` zu suchen ist: kleine Script-Blöcke, die die Strings `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect` oder `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')` enthalten. Das sind die Signaturen jedes gängigen Bypasses.

## Das Logging einschalten

Die GPO-Einstellungen leben unter `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. Die drei, die Sie aktiviert wollen:

- "Turn on PowerShell Script Block Logging" aktiviert. Häkchen bei "Log script block invocation start / stop events" setzen, wenn Sie die Bracketing-`4105`/`4106`-Events wollen; standardmäßig aus und normalerweise das Volumen nicht wert.
- "Turn on Module Logging" aktiviert. Modulnamen: `*`.
- "Turn on PowerShell Transcription" aktiviert. `OutputDirectory`: ein UNC-Pfad. `Include invocation headers`: angekreuzt.

Die entsprechenden Registry-Pfade, wenn Sie sie außerhalb von GPO setzen:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

Wenden Sie auf die OUs an, die Maschinen enthalten, die Sie untersuchen müssten. Das sind "alle davon" in jeder ernsthaften Organisation.

## Wie das während einer Untersuchung aussieht

Eine Kompromittierung, bei der Script Block Logging an war, sagt Ihnen in der Reihenfolge:

1. Das erste `4104` mit einem nicht-trivialen Script-Block von einem Nicht-Standard-Elternprozess. Zeit der ersten Ausführung.
2. Die Kette von `4104`s, während der Loader sich selbst auspackt. Jede Obfuskationsschicht abgeschält und geloggt.
3. Die Runtime-Cmdlets des C2-Frameworks (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, jeder gängige offensive Cmdlet-Name und seine umbenannten Varianten).
4. Die Hands-on-Keyboard-Befehle des interaktiven Operators. Diese lesen sich wie eine aufgezeichnete Shell-Session, weil sie das sind.

Cross-referenzieren Sie gegen [Prefetch](https://www.prefetchparser.com), um zu finden, wann `powershell.exe` lief, [LNK-Dateien](https://www.lnkparser.com) für Dateien, die der Operator geöffnet hat, [AmCache](https://www.amcacheparser.com) für den Hash der PowerShell-Binärdatei selbst (sie wird manchmal umbenannt), und die [Registry](https://www.registryparser.com) für den GPO-Zustand, um zu bestätigen, dass Logging zur Zeit der Events, die Sie lesen, wirklich an war.

Eine Kompromittierung, bei der Script Block Logging aus war, sagt Ihnen fast nichts über PowerShell und viel über Ihre Detection-Haltung. Beheben Sie das zuerst.

## Weiterführende Literatur

- Microsofts [PowerShell-Logging-Dokumentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows). Die offizielle Referenz.
- FireEye / Mandiants [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility) Beitrag. Alt, aber immer noch die sauberste Feld-Perspektive.
- Daniel Bohannons [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) Projekt. Das Deobfuskations-Toolkit, das `4104`-Analyse ergänzt.

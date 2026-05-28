---
title: "EVTX-Triage: was Sie zuerst lesen, wenn Sie eine Stunde und einen Host haben"
description: "Eine Reihenfolge der Operationen eines Praktikers für die Triage von Windows Event Logs während eines Incident Response: welche Channels wichtig sind, welche Event-IDs Sie anlügen und wo Sysmon die Schwerstarbeit leistet."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

Wenn Ihnen jemand ein EVTX-Bundle von einem Host übergibt, von dem er denkt, dass er kompromittiert ist, und Ihnen eine Stunde gibt, haben Sie keine Zeit für Eleganz. Sie haben Zeit für eine Reihenfolge der Operationen, die oft genug funktioniert hat, dass Sie ihr vertrauen, bevor Sie einen einzigen Record gelesen haben.

Das ist meine. Es ist nicht die vollständige Referenz und es ist nicht das Richtige für jeden Fall, langsam brennende Insider-Untersuchungen brauchen eine völlig andere Haltung, aber für die Standardfrage "ist das Ding kompromittiert und wie", ist das, was ich laufen lasse.

## Welche Channels die Zeit tatsächlich zurückzahlen

Eine Standard-Windows-Installation liefert irgendwo nördlich von dreihundert EVTX-Channels. Sie werden vielleicht sieben davon ansehen. Diejenigen, die konsistent wichtig sind:

- `Security.evtx` Anmeldungen, Privilegienverwendung, Kontoänderungen. Der erste Stopp für jeden interaktiven Vorfall.
- `Microsoft-Windows-Sysmon%4Operational.evtx` wenn Sysmon eingesetzt ist (und Sie sollten betteln, flehen, drohen, bis es so ist), hier lebt das echte Signal. Prozesserstellungen mit Befehlszeilen, Dateierstellungen, Netzwerkverbindungen, DNS, Image-Loads. Alles, worauf `Security.evtx` hindeutet, ohne es zu sagen.
- `System.evtx` Service-Installationen, geladene Treiber, Boot-Events, Zeitänderungen. Oft der einzige Ort, wo Lateral Movement eine Service-Installation hinterlässt.
- `Application.evtx` üblicherweise Rauschen, aber Office-Makrofehler, .NET-Exceptions und einige EDR-Seitenkanäle tauchen hier auf.
- `Microsoft-Windows-PowerShell%4Operational.evtx` Modul-Logging und Pipeline-Events, falls aktiviert. Das `4104` Script-Block-Log ist, wo Sie jede Zeile bösartigen PowerShells finden, vorausgesetzt das Logging war an. Es ist der zweitwichtigste Channel nach Sysmon, wenn beide aktiv sind.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` Erstellung, Löschung und Ausführung geplanter Aufgaben. Liest sich kurz, zahlt sich schnell aus.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` WMI-Subscriptions und Consumer-Registrierungen. Billig zu lesen; fängt ein spezifisches Persistenzmuster.

Wenn der Host Defender hat, schnappen Sie sich auch `Microsoft-Windows-Windows Defender%4Operational.evtx`. Die `1116` / `1117` Familie ist manchmal die einzige zeitgenössische Erwähnung der Datei, die wichtig war.

Alles andere können Sie für den zweiten Durchgang lassen.

## Das Erste, was ich öffne, ist nicht das Security Log

Der Default-Reflex ist, `Security.evtx` nach `4624` zu greppen. Ich habe damit beim ersten Durchgang aufgehört und Sie sollten das wahrscheinlich auch. Das Security Log auf einem beschäftigten Server loggt Tausende legitimer Logons pro Stunde. Sie ertrinken im Rauschen, bevor Sie die Frage formuliert haben.

Was ich zuerst öffne, wenn es existiert, ist `Sysmon%4Operational.evtx`, gefiltert auf `EventID=1` (Prozesserstellung) innerhalb des verdächtigten Fensters. Sysmon gibt Ihnen den Elternprozess, die Befehlszeile wie tatsächlich aufgerufen, den Benutzer, die Integritätsstufe und die Hashes von Eltern und Kind. Das reicht, um eine Geschichte vom Bildschirm zu lesen.

Wenn Sysmon nicht vorhanden ist (und auf einer deprimierenden Anzahl von Unternehmens-Windows-Beständen ist es das immer noch nicht), ist mein nächster Schritt `Security.evtx` gefiltert auf `4688` *mit aktiviertem Command-Line-Audit*. Wenn Befehlszeilen nicht auditiert werden, bekommen Sie nur den nackten Programmnamen, was kaum nützlich ist, an diesem Punkt springe ich zu AmCache, Prefetch und dem [USN-Journal](https://www.usnparser.com), um zu rekonstruieren, was gelaufen ist.

Das Korollar, das laut gesagt werden muss: Eine EVTX-Untersuchung ohne Sysmon und ohne `4688`-Befehlszeilen ist hauptsächlich ein Ratespiel. Wenn Sie das im Vorfeld eines Vorfalls lesen, beheben Sie das zuerst.

## Die Event-IDs, die Sie nicht mehr nachschlagen müssen

Diese lernen Sie irgendwann auswendig. Die Kurzversion, mit der Art, wie ich jede in IR denke:

- `4624` erfolgreicher Logon. Lesen Sie `LogonType` zuerst: `3` ist Netzwerk (File Share, Remote Tool), `10` ist RDP / Terminal Services, `2` ist interaktiv, `9` ist `runas` mit expliziten Credentials. `5` ist Service. Der `LogonType` trägt mehr Bedeutung als das Event selbst.
- `4625` fehlgeschlagener Logon. Bursts sind Spray-Angriffe; isolierte über viele Konten sind Credential Stuffing.
- `4634` / `4647` Logoff und benutzerinitiierter Logoff. Nützlich, um die Klammer um eine Sitzung zu schließen.
- `4648` Logon mit expliziten Credentials. Das, was Sie tatsächlich für Lateral-Movement-Attribution wollen: Wenn Konto A Konto Bs Creds verwendet, um einen Prozess zu starten oder sich irgendwo zu verbinden, ist das der Record. Die meisten Verteidiger nutzen es zu wenig.
- `4672` spezielle Privilegien beim Logon zugewiesen. Die "dieses Konto ist gerade Admin geworden"-Zeile. Paaren Sie mit dem `4624`, das es folgt.
- `4688` Prozesserstellung. Nur nützlich, wenn Command-Line-Auditing aktiviert ist (Group Policy: *Audit Process Creation* und *Include command line in process creation events*). Ohne das bekommen Sie Programmnamen.
- `4697` Service installiert. Lateral Movement via PsExec, Impacket-`smbexec` und ähnliches Tooling lebt hier.
- `4720` / `4732` / `4738` Konto erstellt, Gruppenmitgliedschaftsänderung, Konto geändert. Persistenz liebt diese.
- `1102` Security Log wurde gelöscht. Wenn Sie das sehen, ist der Rest des Security Logs bis zu diesem Punkt verdächtig oder fehlt. Die Tatsache, dass das Event überhaupt existiert, ist die rauchende Waffe.
- `5140` / `5145` Netzwerkfreigabe zugegriffen. Letzteres loggt den Dateinamen; wenn es an ist, ist Lateral Movement via SMB im Detail auditierbar.
- `7045` Service installiert (System Log). Spiegelt `4697`, aber vom System-Channel.
- `Sysmon 1` Prozesserstellung mit vollem Kontext. Die einzige nützlichste Event-ID in DFIR, wenn Sysmon an ist.
- `Sysmon 3` Netzwerkverbindung. Fängt ausgehendes C2, selbst wenn Defender es nicht tat.
- `Sysmon 10` Prozesszugriff. Das, was Credential Dumping von `lsass.exe` fängt.
- `Sysmon 11` Dateierstellung. Fängt Dropper-Aktivität, die keine Chance zur Ausführung hatte.
- `PowerShell 4104` Script-Block-Logging. Zeichnet den vollen Text jedes PowerShell-Befehls auf, einschließlich obfuskierter (in vielen Fällen deobfuskiert nach dem Decode).

Ich halte einen gedruckten Spickzettel neben meinem Schreibtisch und Sie sollten das auch. Es ist nicht glamourös und spart echte Minuten.

## Die Events, die Sie anlügen oder leicht falsch lesbar sind

`4624 Type 3` von `\\NT AUTHORITY\ANONYMOUS LOGON` ist nicht "der Angreifer ist drin". Es ist üblicherweise eine fehlkonfigurierte Share-Enumeration, ein Schwachstellen-Scanner oder einer von einem halben Dutzend interner Windows-Mechanismen. Validieren Sie vor der Eskalation.

`4625` gegen ein einzelnes Service-Konto mit der Rate von einem pro Minute ist fast immer eine stale Credential, die irgendwo gecached ist. Schauen Sie auf das Source-Workstation-Feld, bevor Sie es Brute Force nennen.

Zeitstempel in Security.evtx sind in einigen Tools standardmäßig in lokaler Zeit auf dem Host, der sie generiert hat, in anderen UTC. Wenn Sie ein Bundle in einem neuen Tool laden, sanity-checken Sie, indem Sie einen Logon finden, den Sie mit einem bekannten externen Event korrelieren können (ein Ticket-Update, eine VPN-Session) und Offsets bestätigen. Ich habe ganze Berichte um 4 Stunden verschoben gesehen, weil jemand vergessen hat zu prüfen.

Event-Log-Clearing (`1102`) ist üblicherweise laut, aber selektives Record-Löschen ist eine andere Bestie. `wevtutil cl` clearet den ganzen Channel, was detektierbar ist. Tools wie `phant0m` und `Invoke-Phant0m` suspendieren stattdessen die Event-Service-Threads, was kein Clearing-Event hinterlässt, aber eine sichtbare Lücke erzeugt. Suchen Sie nach der Lücke, nicht nur nach dem `1102`.

Forwarded Events (`Microsoft-Windows-EventLog%4ForwardedEvents`) bewahren die RecordID und die ursprünglichen Zeitstempel des Ursprungs-Hosts. Wenn Sie einen WEC-Subscriber haben, der den Vorfall überlebt hat, sind diese Kopien manchmal der einzige intakte Record, der übrig ist.

Wenn das Security Log `1100` (Event Service Shutdown) gefolgt von einer unerklärten Lücke zeigt, schauen Sie auf einen der saubereren Versuche, Beweise zu löschen. Cross-validieren Sie gegen [Registry-Hives](https://www.registryparser.com), die [Master File Table](https://www.mftparser.com) und Prefetch.

## Carving und Wiederherstellung, wenn Records fehlen

EVTX-Records können aus unallociertem Disk-Speicher und aus [pagefile.sys](https://www.pagefilesysparser.com) gecarvt werden, wenn die Live-Datei gelöscht oder rolliert wurde. Der Record-Header (`2a 2a 00 00` Magic) ist charakteristisch genug, dass Signature-Carving angemessen gut funktioniert. Yamato Securitys `hayabusa` und `evtx_dump` handhaben beide fehlerhafte Dateien mit ausgebesserten Record-Streams.

Wenn Sie es mit einem Host zu tun haben, bei dem Sie vermuten, dass das Log manipuliert wurde, versuchen Sie auch, EVTX-Records aus einem [RAM-Dump](https://www.ramparser.com) wiederherzustellen. Der Event Log Service cached jüngste Records im Speicher; ein Snapshot, der nahe am Vorfall genommen wurde, enthält manchmal Records, die es nie auf die Disk geschafft haben.

## Wohin von einem Treffer

Ein einzelnes Event schließt selten einen Fall ab. Die Pivot-Punkte, nach denen ich greife, in Reihenfolge:

- Ein verdächtiges `4624` schauen Sie nach dem passenden `4672`, den vorhergehenden `4625`-Fehlern und welcher Prozess danach mit diesem Token erstellt wurde (Sysmon 1 mit passender `LogonId`).
- Ein `7045` oder `4697` Service-Install prüfen Sie `Microsoft-Windows-TaskScheduler%4Operational.evtx` auf Folge-Aufgaben und die [Registry](https://www.registryparser.com) `HKLM\SYSTEM\CurrentControlSet\Services\` auf den Binärpfad.
- Ein Sysmon 10 gegen `lsass.exe` Prozessbaum des anfragenden Prozesses, Datei-Drops im Arbeitsverzeichnis, Netzwerkverbindungen zu Nicht-Unternehmensdestinationen.
- Ein PowerShell 4104 mit obfuskiertem Inhalt in einer Sandbox dekodieren, dann nach demselben Payload suchen, der auf anderen Hosts landet (die meisten Enterprise-Akteure wiederverwenden).

## EVTX im Browser lesen

Der Parser auf dieser Seite liest EVTX vollständig clientseitig: Datei reinwerfen und Sie bekommen eine sortierbare, filterbare Tabelle mit Channel, RecordID, EventID, Zeit, Computer und dem gerenderten XML. Kein Upload, was wichtig ist, weil EVTX aus regulierten Umgebungen fast immer PII enthält, die Sie nicht über eine Anbietergrenze schicken wollen.

## Weiterführende Literatur

- [JPCERT/CCs "Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) das nützlichste einzelne Dokument zur Lateral-Movement-Event-Korrelation. Eine langsame Lektüre wert.
- Eric Zimmermans [EvtxECmd](https://github.com/EricZimmerman/evtx) Offline-Parser mit den kanonischen Feld-Mapping-Outputs.
- Die Sysmon-Konfiguration, die Microsoft Threat Intelligence (ehemals SwiftOnSecurity) als Baseline pflegt: [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Starten Sie von dort, schreiben Sie nicht Ihre eigene von Grund auf.

Die zynische Version all dessen: Mit Sysmon und Command-Line-Auditing gibt EVTX Ihnen 80% von dem, was Sie brauchen, um ein Eindringen zu rekonstruieren. Ohne sie machen Sie Forensik auf der Silhouette des Events statt auf dem Event selbst.

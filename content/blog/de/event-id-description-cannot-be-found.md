---
title: "„Beschreibung der Ereignis-ID nicht gefunden“: so geht's"
description: "Warum die Ereignisanzeige die Beschreibung einer Event ID nicht findet, was Codes wie %%1833 bedeuten und wie Sie das Event trotzdem offline lesen."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "Was bedeutet „The description for Event ID X from source Y cannot be found“?"
    answer: "Der Record selbst ist in Ordnung. Ein .evtx-Record speichert nur die Event ID, den Provider-Namen und die Insertion Strings (EventData / UserData). Der Satz, den Sie normalerweise in der Ereignisanzeige lesen, ist eine Vorlage in der Message-DLL des Providers auf dem Rechner, der das Log anzeigt. Ist dieser Provider dort nicht registriert, kann die Ereignisanzeige den Satz nicht bauen und zeigt diesen Fehler plus die rohen Insertion Strings."
  - question: "Sind die Event-Daten verloren oder beschädigt?"
    answer: "Nein. Jedes Feld steht weiterhin im Record. Öffnen Sie in der Ereignisanzeige den Reiter Details (XML-Ansicht) oder lesen Sie die EventData-Felder mit Get-WinEvent, wevtutil oder einem Parser. Nur der lesbare Rahmentext fehlt."
  - question: "Was bedeutet %%1833 in einem Event?"
    answer: "%%1833 ist ein Verweis auf eine Parameter-Message, aufgelöst aus msobjs.dll, der Parameter-Message-Datei des Security-Auditing-Providers. %%1833 bedeutet Impersonation (Feld ImpersonationLevel in 4624). Weitere häufige Codes: %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 Token-Elevation-Typ 1/2/3."
  - question: "Wie exportiere ich eine .evtx so, dass sie auf einem anderen Rechner mit Beschreibungen geöffnet wird?"
    answer: "Auf dem Quellsystem in der Ereignisanzeige Alle Ereignisse speichern unter wählen, .evtx auswählen und die Option zum Anzeigen der Informationen für die gewünschten Sprachen aktivieren. Die Ereignisanzeige schreibt einen Ordner LocaleMetaData mit .MTA-Dateien neben die .evtx. Beides zusammen kopieren. wevtutil archive-log (wevtutil al) macht dasselbe auf der Kommandozeile."
  - question: "Kann ich das Event lesen, ohne den Provider zu installieren?"
    answer: "Ja. Im DFIR brauchen Sie die gerenderte Meldung selten: Die EventData-Felder enthalten jeden Wert, den die Meldung anzeigen würde. Der Browser-Parser auf evtxparser.com zeigt zusätzlich eine einzeilige Beschreibung für gängige DFIR-Events und dekodiert %%-Codes, NTSTATUS-Codes und Kerberos-Verschlüsselungstypen offline, ohne die Datei hochzuladen."
---

Sie kopieren eine `Security.evtx` von einem verdächtigen Host, öffnen sie auf Ihrer Analyse-Workstation, und jeder Record zeigt:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

Auf einem deutschen Windows beginnt dieselbe Meldung mit „Die Beschreibung der Ereignis-ID 4625 aus der Quelle Microsoft-Windows-Security-Auditing wurde nicht gefunden.“ Danach folgt ein Block roher Werte: `%%2313`, `0xC000006A`, `0x17`. Nichts ist kaputt, nichts ist verloren. Es ist ein *Rendering*-Fehler, kein Datenfehler. Dieser Artikel erklärt, wo der Beschreibungstext tatsächlich liegt, warum er fehlt, wie Sie das beheben, wenn Sie ihn brauchen, und warum Sie ihn für die Triage meistens nicht brauchen. (Wenn Sie die Events einfach sofort lesbar haben wollen: [der Browser-Parser](/de) rendert Beschreibungen und dekodiert diese Codes offline.)

## Was der Fehler tatsächlich bedeutet

Ein `.evtx`-Record speichert nicht den Satz, den Sie in der Ereignisanzeige lesen. Er speichert den `<System>`-Block (Provider, Event ID, Zeit, Computer) und die **Insertion Strings** in `<EventData>` oder `<UserData>` ([was in einem Record steckt](/de/blog/what-is-an-evtx-file)). Der Satz, „Fehler beim Anmelden eines Kontos. Antragsteller: … Fehlerursache: …“, ist eine Vorlage mit Platzhaltern `%1`, `%2`, gespeichert in einer **Message-Table-Ressource** in einer DLL oder EXE des Event-Providers.

Wo Windows diese Datei sucht, hängt vom Provider-Typ ab:

- **Klassische (Legacy-)Event-Quellen** registrieren sich unter `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, mit dem Pfad im Wert `EventMessageFile` (plus optional `ParameterMessageFile` und `CategoryMessageFile`).
- **Manifest-basierte Provider** (ab Vista, die `Microsoft-Windows-*`-Familie) registrieren sich unter `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. Die Werte `MessageFileName`, `ResourceFileName` und `ParameterFileName` zeigen auf die Binaries, die das kompilierte Manifest (Ressource `WEVT_TEMPLATE`) und die Message Table enthalten.

Der entscheidende Punkt: **Die Ereignisanzeige rendert die Meldung auf dem Rechner, auf dem Sie das Log ansehen**, mit dessen Registry und DLLs. Der Rechner, der das Event geschrieben hat, spielt bei der Anzeige keine Rolle. Ist der Provider lokal nicht registriert, gibt es keine Vorlage, und Sie bekommen den Fehler plus die rohen Insertion Strings.

## Häufige Ursachen

- **Das Log stammt von einem anderen Host.** Der klassische DFIR-Fall. Ein Drittanbieter-Agent, ein EDR, eine SQL-Server-Instanz oder eine Fachanwendung auf dem Quellhost hat auf Ihrer Analyse-Workstation keinen Provider. Das Öffnen unter macOS, Linux oder in einer frischen VM hat denselben Effekt: überhaupt kein Windows-Provider.
- **Software wurde deinstalliert.** Der Deinstaller hat die DLL entfernt, alte Events verweisen aber weiterhin auf die Quelle.
- **Fehlende, beschädigte oder verschobene DLL.** Die Registry zeigt auf einen Pfad, der nicht mehr existiert, oder `EventMessageFile` ist als `REG_SZ` statt `REG_EXPAND_SZ` gespeichert, sodass `%SystemRoot%` nie expandiert wird.
- **32/64-Bit-Konflikt.** Ein 32-Bit-Installer hat seine DLL in das vermeintliche `System32` geschrieben (dank Dateisystem-Umleitung tatsächlich `SysWOW64`), während der registrierte Pfad vom 64-Bit-Event-Log-Stack als das echte `System32` gelesen wird.
- **Sprache.** Die Message Table des Providers existiert, aber nicht in der Anzeigesprache, oder Sie haben einen Export „mit Anzeigeinformationen“ für eine andere Sprache geöffnet als die Ihres Viewers.

## Die %%-Codes: Parameter-Messages

Selbst wenn die Hauptbeschreibung gerendert wird, zeigen manche Felder `%%1833` oder `%%2313` statt Wörtern. Das sind Verweise auf **Parameter-Messages**: Der Wert ist eine ID in einer zweiten Message Table, der `ParameterMessageFile` / `ParameterFileName` des Providers. Beim Security-Auditing-Provider ist diese Datei `msobjs.dll`. Offline bleiben diese Verweise unaufgelöst. Die gängigen, die man auswendig kennen sollte (Bezeichnungen wie auf einem englischen Windows):

| Code | Bedeutung | Wo er auftaucht |
|------|-----------|-----------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Typ 1, volles Token (UAC aus oder eingebauter Admin) | 4688 `TokenElevationType` |
| `%%1937` | Typ 2, erhöhtes Token | 4688 `TokenElevationType` |
| `%%1938` | Typ 3, eingeschränktes Token | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (Konto gesperrt) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (Konto deaktiviert) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

Das Triplet `%%2080 %%2082 %%2084` ist die normale Signatur eines frisch angelegten Kontos in [4720](/de/blog/event-id-4720-account-created). `%%1937` in einem [4688](/de/blog/event-id-4688-process-creation) ist ein Prozess, der nach einem UAC-Prompt mit vollem Admin-Token gestartet wurde.

Hex-Werte sind keine `%%`-Codes. Die Felder `Status` / `SubStatus` von [4625](/de/blog/detecting-4625-brute-force) sind NTSTATUS-Codes: `0xC000006A` ist ein falsches Passwort für ein gültiges Konto, `0xC0000064` ein Benutzername, der nicht existiert, `0xC0000234` ein gesperrtes Konto. `TicketEncryptionType` in [4769](/de/blog/event-id-4769-kerberoasting) ist ein Kerberos-Etype: `0x17` ist RC4-HMAC, `0x12` AES256. Beide erscheinen als rohes Hex, auch wenn der Provider vorhanden ist.

## Lösung 1: mit Anzeigeinformationen exportieren

Wenn Sie noch Zugriff auf den Quellhost haben, exportieren Sie das Log so, dass es seine Meldungen mitnimmt. In der Ereignisanzeige: Rechtsklick auf das Log, **Alle Ereignisse speichern unter…**, `.evtx` wählen und im folgenden Dialog die Anzeigeinformationen für die gewünschten Sprachen aktivieren (auf einem englischen Windows **Display information for these languages**). Die Ereignisanzeige schreibt neben die Datei einen Ordner `LocaleMetaData` mit einer `.MTA`-Datei pro Sprache. Lassen Sie den Ordner beim Kopieren neben der `.evtx`; die Ereignisanzeige auf dem Analyserechner nutzt ihn.

Auf der Kommandozeile:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) ergänzt eine exportierte Datei um die Sprach-Metadaten. Für die Sammlung im großen Stil siehe [EVTX von einem laufenden System sichern](/de/blog/collecting-evtx-from-live-system).

## Lösung 2: Provider installieren oder reparieren

Auf einem Rechner, den Sie selbst administrieren und auf dem Events Ihrer eigenen Software nicht gerendert werden:

- Die Anwendung, der die Quelle gehört, neu installieren oder reparieren.
- `EventMessageFile` unter `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>` prüfen: Der Pfad muss existieren, und der Werttyp sollte `REG_EXPAND_SZ` sein, wenn er `%SystemRoot%` enthält.
- Bei Manifest-Providern `Get-WinEvent -ListProvider <Name>` prüfen; schlägt es fehl oder listet es keine Messages, ist die Manifest-Registrierung kaputt (`wevtutil im <manifest>.man` registriert sie neu, bei vorhandenen Binaries).

## Lösung 3: auf dem Quellhost rendern

`Get-WinEvent` füllt die Eigenschaft `Message` nur, wenn der Provider lokal vorhanden ist. Auf dem Quellhost (oder einem Rechner mit derselben installierten Software) funktioniert:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Auf Ihrer Workstation liefert derselbe Befehl ein leeres `Message`, aber `.Properties` und `.ToXml()` legen weiterhin jeden Wert offen. Mehr Filter-Rezepte in [EVTX mit Get-WinEvent abfragen](/en/blog/query-evtx-powershell-get-winevent) (englisch).

## Lösung 4: Sie brauchen die Meldung meistens nicht

Im DFIR ist der gerenderte Satz Komfort. Jeder Wert, den er anzeigen würde, steht in `<EventData>`: `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. Der Reiter **Details** (XML-Ansicht) der Ereignisanzeige zeigt sie, auch wenn der Reiter Allgemein den Fehler zeigt. Wer im großen Maßstab analysiert, liest die Felder ohnehin direkt, und genau so sollten Sie [4624](/de/blog/understanding-event-id-4624) und den Rest der [Logon-Event-Familie](/en/blog/windows-logon-events-explained) angehen: Die Feldnamen sind über Windows-Versionen und Sprachen hinweg stabil, der gerenderte Text nicht.

## Events offline im Browser lesen

Der [EVTX-Parser](/de) zeigt jetzt eine lesbare einzeilige Beschreibung für rund 60 gängige DFIR-Events: Logons und 4625-Fehlschläge, Konto- und Gruppenänderungen, Kerberos 4768/4769/4771, NTLM 4776, Dienste 7045/4697, geplante Tasks, Sysmon, PowerShell 4104 und RDP. Zusätzlich dekodiert er `%%`-Codes, NTSTATUS-Codes (`0xC000006A` falsches Passwort, `0xC0000064` unbekannter Benutzer) und Kerberos-Ticket-Verschlüsselungstypen (`0x17` RC4) direkt in der Ansicht. Er braucht weder Provider-DLLs noch Windows; die Datei wird in Ihrem Browser geparst und nie hochgeladen. Weitere Wege, die Datei zu öffnen, finden Sie unter [eine EVTX-Datei öffnen](/de/blog/how-to-open-an-evtx-file).

## Checkliste

- Der Fehler bedeutet, dass **dem anzeigenden Rechner** der Provider fehlt, nicht dass der Record beschädigt ist.
- `<EventData>` im Reiter Details, über `.Properties` von `Get-WinEvent` oder mit einem Parser lesen.
- `%%`-Verweise mit der Tabelle oben dekodieren; `Status` / `SubStatus` als NTSTATUS dekodieren.
- Gerenderten Text für einen Bericht nötig? Auf dem Quellhost mit Anzeigeinformationen (`LocaleMetaData`) oder `wevtutil al` neu exportieren.
- Bei eigener Software `EventMessageFile` korrigieren oder das Manifest neu registrieren.

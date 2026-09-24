---
title: "Descrizione per l'ID evento non trovata: come risolvere"
description: "Perché il Visualizzatore eventi non trova la descrizione di un Event ID, cosa significano codici come %%1833 e come leggere comunque l'evento, offline."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "Cosa significa «The description for Event ID X from source Y cannot be found»?"
    answer: "Il record in sé è integro. Un record .evtx memorizza solo l'Event ID, il nome del provider e le stringhe di inserimento (EventData / UserData). La frase che leggi di solito nel Visualizzatore eventi è un modello memorizzato nella DLL dei messaggi del provider, sulla macchina che visualizza il log. Se quel provider non è registrato sulla tua macchina, il Visualizzatore non può costruire la frase e mostra questo errore seguito dalle stringhe di inserimento grezze."
  - question: "I dati dell'evento sono persi o corrotti?"
    answer: "No. Tutti i campi sono ancora nel record. Apri la scheda Dettagli (Visualizzazione XML) del Visualizzatore eventi, oppure leggi i campi EventData con Get-WinEvent, wevtutil o un parser. Manca solo il testo leggibile che li avvolge."
  - question: "Cosa significa %%1833 in un evento?"
    answer: "%%1833 è un riferimento a un messaggio di parametro risolto da msobjs.dll, il file dei messaggi di parametro del provider di controllo di sicurezza. %%1833 significa Impersonation (campo ImpersonationLevel del 4624). Altri codici frequenti: %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 tipo di elevazione del token 1/2/3."
  - question: "Come esporto un .evtx perché si apra con le descrizioni su un altro computer?"
    answer: "Sulla macchina di origine, nel Visualizzatore eventi, usa Salva tutti gli eventi con nome, scegli .evtx e seleziona l'opzione per visualizzare le informazioni nelle lingue desiderate. Il Visualizzatore scrive una cartella LocaleMetaData con file .MTA accanto al .evtx. Copia entrambi insieme. wevtutil archive-log (wevtutil al) fa lo stesso da riga di comando."
  - question: "Posso leggere l'evento senza installare il provider?"
    answer: "Sì. In DFIR il messaggio renderizzato serve raramente: i campi EventData contengono ogni valore che il messaggio mostrerebbe. Il parser nel browser di evtxparser.com mostra inoltre una descrizione di una riga per gli eventi DFIR più comuni e decodifica offline i codici %%, i codici NTSTATUS e i tipi di cifratura Kerberos, senza caricare il file."
---

Copi un `Security.evtx` da un host sospetto, lo apri sulla tua workstation di analisi e ogni record mostra:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

Su un Windows in italiano lo stesso messaggio inizia con «Impossibile trovare la descrizione per l'ID evento 4625 dall'origine Microsoft-Windows-Security-Auditing.» Segue un blocco di valori grezzi: `%%2313`, `0xC000006A`, `0x17`. Non c'è niente di rotto e niente di perso. È un errore di *rendering*, non di dati. Questo articolo spiega dove vive davvero il testo della descrizione, perché sparisce, come ripristinarlo quando serve e perché, per il triage, di solito non serve. (Se vuoi solo eventi leggibili subito: [il parser nel browser](/it) renderizza le descrizioni e decodifica questi codici offline.)

## Cosa significa davvero l'errore

Un record `.evtx` non memorizza la frase che leggi nel Visualizzatore eventi. Memorizza il blocco `<System>` (provider, Event ID, ora, computer) e le **stringhe di inserimento** in `<EventData>` o `<UserData>` ([cosa c'è dentro un record](/it/blog/what-is-an-evtx-file)). La frase («An account failed to log on. Subject: … Failure Reason: …» su un Windows in inglese) è un modello con segnaposto `%1`, `%2` memorizzato in una **risorsa message table** all'interno di una DLL o di un EXE del provider dell'evento.

Dove Windows cerca quel file dipende dal tipo di provider:

- **Le sorgenti di eventi classiche (legacy)** si registrano sotto `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, con il percorso nel valore `EventMessageFile` (più, opzionalmente, `ParameterMessageFile` e `CategoryMessageFile`).
- **I provider basati su manifest** (da Vista in poi, la famiglia `Microsoft-Windows-*`) si registrano sotto `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. I valori `MessageFileName`, `ResourceFileName` e `ParameterFileName` puntano ai binari che contengono il manifest compilato (risorsa `WEVT_TEMPLATE`) e la message table.

Il punto chiave: **il Visualizzatore eventi renderizza il messaggio sulla macchina su cui guardi il log**, usando il registro e le DLL di quella macchina. La macchina che ha scritto l'evento non conta al momento della visualizzazione. Se il provider non è registrato localmente, non c'è modello e ottieni l'errore seguito dalle stringhe di inserimento grezze.

## Cause comuni

- **Il log arriva da un altro host.** Il caso DFIR classico. Un agent di terze parti, un EDR, un'istanza SQL Server o un'applicazione gestionale presenti sull'host di origine non hanno alcun provider sulla tua workstation di analisi. Aprire il file su macOS, Linux o una VM pulita ha lo stesso effetto: nessun provider Windows.
- **Il software è stato disinstallato.** Il programma di disinstallazione ha rimosso la DLL, ma i vecchi eventi fanno ancora riferimento alla sorgente.
- **DLL mancante, danneggiata o spostata.** Il registro punta a un percorso che non esiste più, oppure `EventMessageFile` è salvato come `REG_SZ` invece di `REG_EXPAND_SZ`, quindi `%SystemRoot%` non viene mai espanso.
- **Disallineamento 32/64 bit.** Un installer a 32 bit ha scritto la sua DLL in quello che credeva fosse `System32` (in realtà `SysWOW64`, per via del reindirizzamento del file system), mentre lo stack Event Log a 64 bit legge il percorso registrato come il vero `System32`.
- **Lingua.** La message table del provider esiste ma non nella lingua di visualizzazione, oppure hai aperto un'esportazione salvata «con le informazioni di visualizzazione» per una lingua diversa da quella del tuo visualizzatore.

## I codici %%: messaggi di parametro

Anche quando la descrizione principale viene renderizzata, alcuni campi mostrano `%%1833` o `%%2313` invece di parole. Sono riferimenti a **messaggi di parametro**: il valore è un ID in una seconda message table, il `ParameterMessageFile` / `ParameterFileName` del provider. Per il provider di controllo di sicurezza quel file è `msobjs.dll`. Offline, questi riferimenti restano irrisolti. Quelli da conoscere a memoria (etichette come le mostra un Windows in inglese):

| Codice | Significato | Dove compare |
|--------|-------------|--------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Tipo 1, token completo (UAC disattivato o admin integrato) | 4688 `TokenElevationType` |
| `%%1937` | Tipo 2, token elevato | 4688 `TokenElevationType` |
| `%%1938` | Tipo 3, token limitato | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (account bloccato) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (account disabilitato) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

La tripletta `%%2080 %%2082 %%2084` è la firma normale di un account appena creato in un [4720](/it/blog/event-id-4720-account-created). Un `%%1937` su un [4688](/it/blog/event-id-4688-process-creation) è un processo avviato con un token amministrativo completo dopo un prompt UAC.

I valori esadecimali non sono codici `%%`. I campi `Status` / `SubStatus` del [4625](/it/blog/detecting-4625-brute-force) sono codici NTSTATUS: `0xC000006A` è una password errata per un account valido, `0xC0000064` un nome utente inesistente, `0xC0000234` un account bloccato. `TicketEncryptionType` sul [4769](/it/blog/event-id-4769-kerberoasting) è un etype Kerberos: `0x17` è RC4-HMAC, `0x12` AES256. Entrambi appaiono come esadecimale grezzo anche quando il provider è presente.

## Soluzione 1: esportare con le informazioni di visualizzazione

Se hai ancora accesso all'host di origine, esporta il log in modo che viaggi con i suoi messaggi. Nel Visualizzatore eventi: clic destro sul log, **Salva tutti gli eventi con nome…**, scegli `.evtx` e nella finestra successiva seleziona la visualizzazione delle informazioni per le lingue desiderate (**Display information for these languages** su un Windows in inglese). Il Visualizzatore scrive una cartella `LocaleMetaData` accanto al file, con un `.MTA` per lingua. Tieni la cartella accanto al `.evtx` quando lo copi; il Visualizzatore sulla macchina di analisi la utilizza.

Da riga di comando:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) aggiunge i metadati di lingua a un file esportato. Per la raccolta su larga scala, vedi [raccogliere EVTX da un sistema attivo](/it/blog/collecting-evtx-from-live-system).

## Soluzione 2: installare o riparare il provider

Su una macchina che amministri, quando gli eventi del tuo software non vengono renderizzati:

- Reinstalla o ripara l'applicazione proprietaria della sorgente.
- Controlla `EventMessageFile` sotto `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`: il percorso deve esistere e il tipo di valore dovrebbe essere `REG_EXPAND_SZ` se contiene `%SystemRoot%`.
- Per i provider con manifest, verifica `Get-WinEvent -ListProvider <Name>`; se fallisce o non elenca messaggi, la registrazione del manifest è rotta (`wevtutil im <manifest>.man` la registra di nuovo, con i binari al loro posto).

## Soluzione 3: renderizzare sull'host di origine

`Get-WinEvent` popola la proprietà `Message` solo se il provider è presente localmente. Sull'host di origine (o su una macchina con lo stesso software installato) funziona:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

Sulla tua workstation lo stesso comando restituisce un `Message` vuoto, ma `.Properties` e `.ToXml()` espongono comunque ogni valore. Altre ricette di filtro in [interrogare EVTX con Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent) (in inglese).

## Soluzione 4: di solito il messaggio non serve

In DFIR la frase renderizzata è una comodità. Ogni valore che mostrerebbe è in `<EventData>`: `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. La scheda **Dettagli** (Visualizzazione XML) del Visualizzatore li mostra anche quando la scheda Generale mostra l'errore. Chi analizza su larga scala legge comunque i campi direttamente, ed è così che conviene affrontare il [4624](/it/blog/understanding-event-id-4624) e il resto della [famiglia degli eventi di logon](/en/blog/windows-logon-events-explained): i nomi dei campi sono stabili tra versioni e lingue di Windows, il testo renderizzato no.

## Leggere gli eventi offline nel browser

Il [parser EVTX](/it) ora mostra una descrizione leggibile di una riga per circa 60 eventi DFIR comuni: logon e fallimenti 4625, modifiche ad account e gruppi, Kerberos 4768/4769/4771, NTLM 4776, servizi 7045/4697, attività pianificate, Sysmon, PowerShell 4104 e RDP. Decodifica inoltre in linea i codici `%%`, i codici NTSTATUS (`0xC000006A` password errata, `0xC0000064` utente sconosciuto) e i tipi di cifratura dei ticket Kerberos (`0x17` RC4). Non servono DLL dei provider né Windows; il file viene analizzato nel browser e mai caricato. Per gli altri modi di aprire il file, vedi [come aprire un file EVTX](/it/blog/how-to-open-an-evtx-file).

## Checklist

- L'errore significa che **la macchina che visualizza** non ha il provider, non che il record sia danneggiato.
- Leggi `<EventData>` nella scheda Dettagli, tramite `.Properties` di `Get-WinEvent` o con un parser.
- Decodifica i riferimenti `%%` con la tabella qui sopra; decodifica `Status` / `SubStatus` come NTSTATUS.
- Ti serve il testo renderizzato per un report? Riesporta sull'host di origine con le informazioni di visualizzazione (`LocaleMetaData`) o con `wevtutil al`.
- Per il tuo software, correggi `EventMessageFile` o registra di nuovo il manifest.

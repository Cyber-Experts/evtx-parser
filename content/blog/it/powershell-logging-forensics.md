---
title: "Logging di PowerShell: cosa ottenete con module logging e script block logging attivi"
description: "La differenza pratica tra PowerShell module logging, script block logging, trascrizioni e buffer AMSI, e le impostazioni GPO che attivano davvero quelle utili."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Ogni toolkit di adversary degno di preoccupazione esegue PowerShell a un certo punto. I beacon di Cobalt Strike lo lanciano. Empire e Covenant sono costruiti su di esso. Le guide living-off-the-land iniziano con esso. La buona notizia è che da PowerShell 5.0, Microsoft ha rilasciato un logging che, se configurato correttamente, cattura il testo letterale di tutto ciò che PowerShell esegue, inclusi payload offuscati dopo la deoffuscazione. La cattiva notizia è che "se configurato correttamente" sta facendo molto lavoro in quella frase. La maggior parte degli ambienti in cui entro ha uno dei quattro log rilevanti attivo, non tutti e quattro, e non il più utile.

Questo post è cosa ottenete davvero, cosa vale la pena accendere, e dove sono le lacune.

## I quattro log, in ordine di utilità

PowerShell scrive a `Microsoft-Windows-PowerShell%4Operational.evtx`. Gli event ID che contano:

- `4104` script block logging. Il testo letterale di ogni script block che PowerShell compila ed esegue. Se un block è flaggato come sospetto dalle euristiche integrate, viene loggato a severità Warning; altrimenti a Verbose, che è spento di default. Questo è l'evento che volete.
- `4103` module logging. Registra l'esecuzione di pipeline per modulo, con binding di parametri. Meno prosa di `4104`, più strutturato. Utile per "quali cmdlet sono girati" senza il corpo dello script.
- `4105` e `4106` pipeline avviata e pipeline fermata. Utili per il bracketing, non per il contenuto.
- `400` / `403` (legacy, era PowerShell 2.0) cambi di stato del motore. Gli eventi forense-storici. Li vedrete ancora su host dove qualcuno ha forzato un attacco di downgrade PS 2.0.

Se potete attivare esattamente una cosa, attivate `4104` a Verbose. Tutto il resto è supplementare.

## Cosa cattura davvero `4104`

Un evento `4104` contiene il testo completo di uno script block come PowerShell l'ha compilato. Due cose seguono da "come PowerShell l'ha compilato":

- Il testo nell'evento è la rappresentazione *post-deoffuscazione* nella maggior parte dei casi. Se un operatore esegue `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`, ottenete sia la chiamata esterna `iex` (che è essa stessa un `4104`) sia un *secondo* `4104` per lo script block decodato interno, perché PowerShell ha dovuto compilare quel block per eseguirlo. Questa è la singola proprietà più preziosa del logging `4104`.
- Gli script grandi sono divisi su più eventi usando `MessageNumber` e `MessageTotal` nei dati dell'evento. Uno script da 50 KB diventa una catena di eventi che dovete riassemblare prima dell'analisi. La maggior parte dei tool fa questo; alcuni no. Se il vostro parser vi mostra frammenti, controllate se gestisce la catena.

Il campo `Path` mostra il file sorgente se ce n'era uno. `Path` vuoto più un corpo script totalmente inline equivale a "questo è arrivato via filo o dalla memoria" ed è la singola migliore euristica per trovare attività operatore interattiva versus script schedulati.

Lo `ScriptBlockId` è un GUID. Re-esecuzioni dello stesso block sullo stesso host tipicamente riutilizzano il GUID (per la cache), che è conveniente per trovare "ogni host su cui questo codice è girato" se avete un SIEM con ricerca cross-host.

## Module logging: cosa aggiunge `4103`

Module logging è più vecchio e più rumoroso di script block logging. Si aggancia al layer di esecuzione pipeline, quindi per ogni invocazione di cmdlet in un modulo loggato ottenete un `4103` con il nome del cmdlet, i parametri bound e una stringa di payload.

Nell'IR moderno, `4103` è più utile in tre casi:

- L'attaccante ha usato cmdlet che bindano parametri interessanti (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` mostra la sorgente; `4103` mostra i valori dei parametri risolti dopo l'espansione di variabili.
- L'attaccante ha usato comandi encodati. `powershell -enc <base64>` produce un `4103` con il testo decodato nel payload prima che il `4104` corrispondente venga emesso.
- L'attaccante ha disabilitato `4104` (ottenibile per modifica di registry se hanno admin locale). `4103` vive sotto un path di logging separato e a volte è lasciato attivo quando `4104` è silenziato.

L'inghippo: module logging logga solo i moduli esplicitamente abilitati. L'impostazione GPO vuole o `*` (logga tutto) o una lista di nomi di moduli. `*` è la risposta in qualsiasi ambiente che prende il logging seriamente. L'obiezione del "performance impact" che sentirete è reale per workload PowerShell molto pesanti ed è sbagliata per desktop di flotta ordinari.

## Le trascrizioni non sono script block log

C'è un'impostazione separata chiamata "Turn on PowerShell Transcription" che scrive l'input e l'output di ogni sessione in un file di testo sotto una directory configurata. Questa non è la stessa cosa di `4104` e le persone le confondono continuamente.

Le differenze che contano:

- Le trascrizioni includono l'*output* dei cmdlet. `4104` no. Se volete sapere cosa `Get-ADUser` ha restituito davvero, le trascrizioni sono quello.
- Le trascrizioni sono file di testo. Sono trivialmente cancellabili e trivialmente modificabili su un host compromesso. Gli eventi `4104` vanno a un canale EVTX che richiede log clearing o peggio per essere disturbato.
- Le trascrizioni vanno di default nella cartella documenti dell'utente a meno che `OutputDirectory` non sia impostato. Se non impostate `OutputDirectory` a una share di rete write-only, le trascrizioni non sono evidenza; sono una cortesia.

Accendete le trascrizioni con `OutputDirectory` puntato a un path UNC dove l'utente che scrive ha permessi NTFS write-only (no read, no delete). Questo vi dà il trail di output cmdlet che `4104` non dà, senza dare all'attaccante l'opzione di alterare o rimuovere la propria cronologia.

## AMSI e l'angolo del buffer

AMSI (l'Antimalware Scan Interface) è l'hook runtime che permette a Defender e altri prodotti AV di ispezionare il contenuto degli script PowerShell prima dell'esecuzione. Due conseguenze per la forensics:

- Anche se l'attaccante disabilita il logging di PowerShell, AMSI vede ancora il contenuto dello script proprio prima dell'esecuzione, e Defender loggerà un `1116` o `1117` in `Microsoft-Windows-Windows Defender%4Operational.evtx` se il contenuto matcha una signature. L'evento Defender include il testo dello script, parzialmente, nel record di rilevamento minaccia. Su host dove script block logging era spento, questo è a volte l'unico posto dove vive il codice malevolo.
- Le tecniche di "AMSI bypass" che gli attaccanti usano (patchare `amsi.dll!AmsiScanBuffer` in memoria, fornire un `AmsiContext` falsificato, COM hijack del provider AMSI) generano esse stesse tipicamente eventi `4104` per il codice di bypass, *prima* che il bypass entri in effetto. Il bypass non può spegnere il logging retroattivamente. Quindi anche su host dove l'operatore ha neutralizzato AMSI con successo, il momento in cui l'hanno fatto è registrato.

Il pattern da cercare in `4104`: piccoli script block contenenti le stringhe `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect`, o `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`. Queste sono le signature di ogni bypass comune.

## Accendere il logging

Le impostazioni GPO vivono sotto `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. Le tre che volete abilitate:

- "Turn on PowerShell Script Block Logging" abilitata. Spuntate "Log script block invocation start / stop events" se volete gli eventi di bracketing `4105`/`4106`; spento di default e di solito non vale il volume.
- "Turn on Module Logging" abilitata. Nomi di moduli: `*`.
- "Turn on PowerShell Transcription" abilitata. `OutputDirectory`: un path UNC. `Include invocation headers`: spuntato.

I path di registry corrispondenti se li impostate fuori GPO:

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

Applicate alle OU che contengono macchine che dovreste investigare. Quello è "tutte" in qualsiasi organizzazione seria.

## Come appare questo durante un'indagine

Una compromissione dove script block logging era acceso vi dice, in ordine:

1. Il primo `4104` con uno script block non triviale da un padre non-standard. Ora di prima esecuzione.
2. La catena di `4104` mentre il loader si spacchetta. Ogni strato di offuscamento sbucciato e loggato.
3. Le cmdlet runtime del framework C2 (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, ogni nome di cmdlet offensivo comune e le sue varianti rinominate).
4. I comandi hands-on-keyboard dell'operatore interattivo. Si leggono come una sessione shell registrata, perché è quello che sono.

Cross-referenziate contro [Prefetch](https://www.prefetchparser.com) per trovare quando `powershell.exe` è girato, [file LNK](https://www.lnkparser.com) per i file che l'operatore ha aperto, [AmCache](https://www.amcacheparser.com) per l'hash del binario PowerShell stesso (viene rinominato a volte), e il [registry](https://www.registryparser.com) per lo stato GPO per confermare che il logging era davvero acceso al momento degli eventi che state leggendo.

Una compromissione dove script block logging era spento vi dice quasi niente su PowerShell, e molto sulla vostra postura di rilevamento. Sistemate quello prima.

## Per approfondire

- [Documentazione PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) di Microsoft. Il riferimento ufficiale.
- Il post di FireEye / Mandiant [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility). Vecchio ma ancora il writeup più pulito da prospettiva di campo.
- Il progetto [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) di Daniel Bohannon. Il toolkit di deoffuscazione che complementa l'analisi `4104`.

---
title: "Configurazione Sysmon che cattura adversary veri"
description: "Una visione opinata su Sysmon: quali event ID contano davvero in IR, perché olafhartong/sysmon-modular è la baseline giusta, e gli errori di configurazione che vi accecano agli attacchi veri."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon è la singola cosa con maggiore leva che potete deployare su un endpoint Windows. È gratuito, firmato da Microsoft, e un Sysmon ben configurato trasforma Windows da scatola nera in qualcosa che potete davvero investigare. Un Sysmon mal configurato, dall'altro lato, è lo stesso costo di spazio disco con la maggior parte della visibilità esclusa da filtri troppo aggressivi. Sono entrato in più ambienti col secondo che col primo.

Questa è la postura di configurazione per cui argomento in ogni engagement che tocca visibilità endpoint.

## Gli EID che si guadagnano il loro spazio disco

Sysmon definisce 29 event ID dalla versione 15. Non vi servono tutti. Quelli che ripagano lo storage che costano, in ordine di ritorno per byte:

- **EID 1 Process create**. Il singolo evento più utile in DFIR. Processo padre, processo figlio, command line, integrity level, utente, entrambi gli hash di processo, e il process GUID. Se non loggate nient'altro di Sysmon, loggate questo.
- **EID 3 Network connection**. Ogni connessione TCP/UDP in uscita con processo sorgente, IP destinazione, porta, e l'immagine del processo. L'evento di detection C2. Il filtro è essenziale qui (un'installazione di default logga ogni richiesta browser e la vostra retention brucia in una settimana) ma il valore per evento è estremo. Catturate uscite verso destinazioni inusuali da processi inusuali (`rundll32.exe` verso un IP residenziale, `mshta.exe` verso qualsiasi cosa).
- **EID 7 Image loaded**. Caricamenti di DLL e driver con l'hash dell'immagine caricata e lo stato di firma. È così che catturate DLL search-order hijacking, sideloading, e driver non firmati. Costoso loggare tutto; economico e ad alto rendimento loggare moduli non firmati e moduli caricati da location non-standard.
- **EID 10 Process accessed**. Eventi di accesso a memoria cross-process con il processo sorgente, processo target, maschera di accesso concessa, e il call trace. Questo è l'evento di credential dumping. `mimikatz` apre `lsass.exe` con `PROCESS_VM_READ` (`0x10`) e `PROCESS_QUERY_INFORMATION` (`0x400`). Ogni dumper moderno lo fa. La detection si scrive da sola.
- **EID 11 File created**. Nuove creazioni di file con il processo che scrive. Cattura attività di dropper che non è riuscita a eseguire, staging di ransomware, e la maggior parte delle scritture di payload mediate da LOLBin.

Questi cinque sono la fondazione. Se avete solo questi, configurati bene, avete catturato la maggior parte di ciò che chiamereste un'intrusione vera prima che lo diventi.

Il livello successivo che vale la pena accendere:

- **EID 8 CreateRemoteThread**. Iniezione di thread attraverso confini di processo. L'evento classico di process injection.
- **EID 13 Registry value set**. Persistenza via registry. Sintonizzate alle run key, servizi, image file execution options, e i path di COM hijack.
- **EID 17/18 Named pipe created/connected**. I beacon Cobalt Strike e molti framework di post-exploitation usano named pipe per SMB e comunicazioni inter-processo. I nomi delle pipe sono spesso default che sopravvivono da engagement a engagement.
- **EID 22 DNS query**. DNS in uscita con il processo richiedente. Cattura C2 basato su DNS (DGA, DNS tunnel) quando EID 3 ha mancato la connessione perché non ha mai aperto un socket TCP/UDP.
- **EID 25 Process tampering**. Eventi di manipolazione immagine (process hollowing, doppelganging). Sysmon 13+.

EID 12 (registry key/value create), 14 (registry key/value renamed), 15 (file stream created con FileCreateStreamHash) e 23 (file delete con archive) sono utili in indagini specifiche ma producono troppo volume per loggarli ovunque di default. Accendeteli per un host che state osservando da vicino o per path specifici.

EID 2 (process changed file creation time) è un evento anti-timestomp di nicchia. Vale la pena sui file server. Opzionale altrove.

EID 4, 5, 6 (eventi di stato Sysmon) sono operativi, non detection. Loggateli così potete sapere quando Sysmon è stato manomesso.

## Perché `olafhartong/sysmon-modular` è il punto di partenza giusto

Ci sono mezza dozzina di config Sysmon pubblici di qualità variabile. I due più citati sono `sysmon-config` di SwiftOnSecurity e `sysmon-modular` di Olaf Hartong. Entrambi sono buoni. `sysmon-modular` è quello verso cui spingo per via della sua struttura.

Il layout modulare divide i filtri per EID e per tecnica in file XML individuali che sono concatenati al deploy. I benefici che vi dà:

- **Diffabilità**. I cambi al filtro di una singola tecnica appaiono come diff a file singolo in git. Confrontate con un XML monolitico da 4000 righe dove un piccolo cambio scompare nel rumore.
- **Overlay per ambiente**. Commitate l'albero upstream e fate layer con le vostre esclusioni specifiche d'ambiente sopra nei vostri file. Quando upstream aggiorna un filtro, fate `git merge` e i vostri overlay sopravvivono.
- **Authoring guidato dalla copertura**. I filtri sono organizzati per tecnica MITRE ATT&CK. Potete vedere a colpo d'occhio quali tecniche coprite e quali no. L'analisi del gap è l'albero dei file.
- **Manutenzione attiva**. Hartong aggiorna il repo contro nuove tecniche e nuove versioni di Sysmon. Il config SwiftOnSecurity ha lunghi tratti di stagnazione tra gli aggiornamenti.

Partite da `sysmon-modular`. Commitatelo nel vostro albero di gestione config. Fate layer delle vostre esclusioni. Non scrivete il vostro da zero; vi perderete cose.

## Gli errori di configurazione che vi accecano

I pattern che vedo in engagement reali che costano più visibilità:

**Escludere troppo aggressivamente in EID 1**. L'istinto è escludere ogni processo legittimo chiacchierone per mantenere il volume gestibile. L'errore è escludere per path padre o image senza pensare a cosa un attaccante può spawnare da quel padre. Se escludete ogni figlio di `services.exe`, avete escluso il posto esatto dove girano i binari di servizio installati da PsExec. Escludete per `User` (account di sistema che eseguono binari conosciuti come buoni), per `IntegrityLevel`, e per corrispondenza precisa di `CommandLine`, non solo per padre.

**Escludere EID 3 per nome di image**. "Escludere tutte le connessioni di rete da `chrome.exe`" è la regola canonica cattiva. La prima cosa che un attaccante fa quando deve evadere il logging di EID 3 è hijackare un processo browser. Escludete per range di IP destinazione (RFC1918 a RFC1918, la vostra infrastruttura), per porta (il set di porte IPC che avete validato), o per tupla processo+destinazione. Mai solo per image.

**Non loggare EID 7 affatto**. Il logging Image load è il più pesante EID Sysmon per volume. La tentazione di disabilitarlo è forte. Il costo di disabilitarlo è che il DLL sideloading, la tecnica più comune nelle intrusioni moderne, è invisibile per voi. La via di mezzo: filtrare `Image load` a moduli non firmati, moduli caricati da `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%`, e `%PROGRAMDATA%`, e moduli con nomi che corrispondono a liste di abuso note. Questo riduce il volume di un ordine di grandezza e mantiene il segnale.

**Mancare EID 11 interamente su path scrivibili dall'utente**. EID 11 loggato per `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%`, e `%PUBLIC%` cattura quasi ogni dropper. Alcuni config escludono questi per via del volume. Il volume è il punto: è lì che avvengono le scritture che contano.

**Non includere l'algoritmo di hash che volete**. L'elemento `<HashAlgorithms>` controlla quali hash Sysmon calcola. Il default è SHA1 solo. `IMPHASH` è l'import-hash, usato pesantemente nel tracking malware; `SHA256` è ciò su cui la maggior parte delle piattaforme threat intel si basa. Impostate `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` così che gli eventi si allineino con quello che usano i vostri dati intel.

**Non loggare command line sul padre**. Sysmon EID 1 logga sia `CommandLine` (figlio) sia `ParentCommandLine` (padre). Alcuni config disabilitano `ParentCommandLine`. Questo uccide il pivot più utile nell'investigazione di albero di processo; senza, avete un nome di image padre ma nessuna idea di quali argomenti hanno avviato quel padre.

**Non abilitare EID 22 (DNS) affatto**. Il logging DNS è recente (Sysmon 10+) e molti config sono precedenti. Accendetelo. Filtrate host chiacchieroni (`*.windowsupdate.com`, il vostro AD interno), loggate tutto il resto.

## Il tradeoff dello spazio disco

Un Sysmon ben configurato su una workstation tipica produce 100-500 MB di EVTX al giorno. Su un server occupato, 1-5 GB. La dimensione canale di default è 64 MB, il che significa che il file `Microsoft-Windows-Sysmon%4Operational.evtx` ruota in ore e la vostra retention usabile è breve.

La correzione è in due step. Primo, alzate la dimensione del canale. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` la imposta a 4 GB, che vi dà giorni a settimane sulla maggior parte degli host. Secondo, forwardate a un collector centrale con retention più lunga. WEC funziona; agenti SIEM funzionano; il repo [Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) ha l'XML per la sottoscrizione del canale.

La retention centralizzata conta più della retention locale perché il file locale è ciò che l'attaccante può clearare. Una copia forwardata su un collector che non possono raggiungere è il record durevole. Configurate entrambi.

## Come appare un buon Sysmon in un'indagine

Un host con `sysmon-modular` deployato, tutti e cinque gli EID core che loggano, EID 7 filtrato a moduli interessanti, e forwardato a un collector, vi dà:

- Un albero di processi per ogni esecuzione sull'host, con command line, hash, e contesto utente.
- Ogni connessione di rete in uscita con il processo originante.
- Ogni caricamento DLL da una directory scrivibile dall'utente.
- Ogni accesso memoria contro `lsass.exe`.
- Ogni creazione di file in `%TEMP%` e `%APPDATA%`.
- Ogni query DNS con il processo richiedente.

La storia dell'intrusione si legge da sola da questi dati. Non dovete indovinare. Non dovete fare carving. La leggete, dall'alto al basso, e i gap nella storia sono le domande da inseguire. Cross-referenziate con [AmCache](https://www.amcacheparser.com) e [Prefetch](https://www.prefetchparser.com) per evidenza di esecuzione binari, il [registry](https://www.registryparser.com) per persistenza, e l'[USN journal](https://www.usnparser.com) per le mutazioni di file system che l'EID 11 di Sysmon può aver mancato se il filtro era spento. Il parser su questo sito legge canali Sysmon con la stessa fedeltà di Security.evtx.

Senza Sysmon, avete `Security.evtx` e una wishlist.

## Per approfondire

- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) di Olaf Hartong. Il repo. Leggete la README, poi leggete tre o quattro dei file XML specifici per tecnica per cogliere lo stile dei filtri.
- [Documentazione Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) di Microsoft. Il riferimento ufficiale; magro ma accurato.
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) di Roberto Rodriguez. Cacce guidate da Sysmon con le query scritte.
- Il [sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide) di TrustedSec. Il doc di riferimento per la semantica dei filtri.

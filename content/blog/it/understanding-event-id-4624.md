---
title: "Event ID Windows 4624: decodificare ogni accesso riuscito"
description: "Cosa contiene davvero un record 4624, perché il campo LogonType conta più dell'evento stesso, e come leggerli su larga scala."
date: "2026-05-17"
---

L'Event ID 4624 — «Account connesso correttamente» — viene registrato sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che Windows autentica un'identità. È il record più voluminoso sulla maggior parte delle postazioni e la spina dorsale di quasi ogni indagine IR. Saperlo leggere non è opzionale.

## Cosa contiene un record 4624

Le parti interessanti vivono in `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

I campi `Subject*` sono il contesto di sicurezza che ha *richiesto* l'accesso (spesso `S-1-5-18` per SYSTEM all'avvio di un servizio). I campi `Target*` sono l'identità effettivamente autenticata. Confonderli costa ore agli analisti.

## LogonType è il campo che conta

Windows definisce dieci tipi di logon; nella pratica solo alcuni guidano il triage:

- **2 — Interactive**: accesso fisico o da console.
- **3 — Network**: SMB, RPC, WinRM, qualsiasi cosa via rete. La grande maggioranza del traffico normale.
- **4 — Batch**: attività pianificate sotto un account utente.
- **5 — Service**: servizio avviato con un account specifico.
- **7 — Unlock**: workstation sbloccata dopo lo screen lock.
- **8 — NetworkCleartext**: raro, sospetto — credenziali in chiaro (Basic auth su IIS, vecchie stampanti).
- **9 — NewCredentials**: `runas /netonly`, usato spesso dagli attaccanti per portare credenziali di dominio su una macchina dove hanno solo diritti locali.
- **10 — RemoteInteractive**: RDP. Si abbina a `IpAddress` per l'attribuzione della sorgente.
- **11 — CachedInteractive**: account di dominio con credenziali in cache (nessun DC raggiungibile).

Un 4624 con LogonType **10** da un IP esterno alle 03:00 di domenica racconta una storia diversa da 50 LogonType **3** da un server di backup alle 02:00.

## A cosa concatenarlo

Un 4624 da solo è raramente un finding. Lo diventa quando abbinato a:

- **4625** che lo precede dalla stessa sorgente — un successo dopo una raffica di fallimenti è la firma manuale per brute-force-poi-successo.
- **4672** (privilegi speciali assegnati) — segnala le sessioni che hanno concesso privilegi come `SeDebugPrivilege`, utile per scoprire l'uso di account privilegiati.
- **4648** (accesso con credenziali esplicite) — cattura `runas` e altri pattern di passaggio credenziali.

## Leggerli su larga scala

Il parser su questa pagina estrae questi campi direttamente dall'XML del record e li espone in tabella. Filtra per `LogonType` via i bucket della timeline e il filtro testo (`4624` nella ricerca), esporta l'insieme filtrato come CSV e pivota su `SubjectUserSid` + `IpAddress` nello strumento che preferisci. L'XML completo di ogni record è a un clic.

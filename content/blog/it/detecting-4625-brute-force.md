---
title: "Event ID 4625 spiegato: rilevare brute force, spray ed enumerazione"
description: "4625 è il record di logon fallito. Leggilo bene e individui password spray, credential stuffing e abuso di Kerberos prima che si trasformino in un successo."
date: "2026-05-17"
---

L'Event ID 4625, „Un account non è riuscito ad accedere", scatta sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un tentativo di autenticazione viene rifiutato. È il singolo record più utile per cogliere attacchi alle credenziali in volo. È anche il record che gli analisti leggono male più spesso, perché il messaggio di testa è generico e la risposta vive due campi più in basso.

## I campi che decidono la chiamata

Un record tipico:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` e `SubStatus` insieme ti dicono perché il logon è fallito. La coppia che ti interessa davvero è `SubStatus`. I codici che vale la pena memorizzare:

- `0xC0000064`: l'account non esiste. Enumerazione di username.
- `0xC000006A`: password sbagliata. Il classico.
- `0xC0000234`: account bloccato.
- `0xC0000072`: account disabilitato.
- `0xC0000071`: password scaduta.
- `0xC0000133`: clock skew su Kerberos. Comune nei tentativi di AS-REP roasting dove l'attaccante ha falsificato un orario.
- `0xC000018B`: SID sbagliato, la workstation pensa di essere in un dominio in cui non è. Raro e interessante.

Una raffica di `0xC0000064` su un mix di username validi e non validi è ricognizione. Una raffica di `0xC000006A` contro un account è brute force. Una raffica di `0xC000006A` contro molti account usando la *stessa* password è uno spray. Stesso Event ID, tre incidenti diversi.

## Le query di triage che si guadagnano lo stipendio

1. Rilevamento spray. Raggruppa 4625 per `IpAddress` (o `WorkstationName` se il campo IP è vuoto), conta `TargetUserName` distinti su 10 minuti. Più di cinque account per sorgente in quella finestra è sospetto quasi ovunque.
2. Brute force. Raggruppa per `TargetUserName`, conta fallimenti al minuto. Più di dieci al minuto contro un account è quasi sempre automatizzato.
3. Causa radice del lockout. Abbina 4740 (account bloccato) con i 4625 precedenti. Il campo `WorkstationName` ti dirà quale dispositivo ha innescato il blocco. La maggior parte delle volte è un server in dominio con una credenziale in cache obsoleta, non un attaccante. Il triage conta perché l'helpdesk tratta entrambi allo stesso modo e il SOC deve scegliere quale escalare.

## Il „dopo" decide la risposta

Una raffica di 4625 seguita da un [4624](/it/blog/understanding-event-id-4624) dallo stesso `IpAddress` è il caso azionabile. L'attaccante ha trovato una credenziale funzionante. La progressione nella timeline è inconfondibile: fallimenti densi, silenzio improvviso, singolo successo.

## Sigma: password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL: brute force contro un account

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: enumerazione che sfocia in brute force

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Il segnale è la *progressione*: enumerazione prima per trovare username validi, poi tentativi mirati di password. Un operatore reale con una lista utenti fresca produrrà entrambe le forme in minuti.

## Mapping ATT&CK

- T1110.001 Brute Force: Password Guessing. Un singolo account, molti fallimenti `0xC000006A`.
- T1110.003 Brute Force: Password Spraying. Molti account, una sorgente, pochi fallimenti ciascuno.
- T1110.004 Credential Stuffing. Molti account, una sorgente, mix di `0xC0000064` (account inesistente, miss della lista leaked) e `0xC000006A` (hit).
- T1078 Valid Accounts. Raffica 4625 seguita da successo [4624](/it/blog/understanding-event-id-4624) dalla stessa sorgente. Compromissione.
- T1556 Modify Authentication Process. `LogonProcessName` anomalo (qualcosa diverso da `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) suggerisce manomissione.

## Falsi positivi che indossano il costume

- Credenziali salvate che invecchiano dopo un cambio password. Le unità mappate dell'utente, le attività pianificate o le config di servizio riprovano la vecchia password. La forma è un `TargetUserName`, un `IpAddress`, cadenza costante di `0xC000006A`. Trova l'host con la credenziale obsoleta e aggiustalo prima di allertare.
- Automazione mal configurata. Uno script con la password sbagliata che ritenta in loop. Stessa forma di una brute force. Parla prima con l'owner.
- Gli scanner di vulnerabilità durante scan autenticati producono traffico 4625 denso. Tagga gli IP dello scanner.
- Churn della policy di lockout. Procedure helpdesk che sbloccano in modo aggressivo creano cicli ripetuti 4625 a 4740 a 4624. Fastidioso. Non malevolo.

## Cosa nasconde 4625

I fallimenti Kerberos e NTLMv2 che passano per un DC non sempre portano un `IpAddress` utile. Il campo può essere vuoto o `-`. Per quelli, pivoti sui record del DC: [4768](/it/blog/event-id-4768-kerberos-tgt) e 4771 per i fallimenti di pre-auth Kerberos. „Niente IP sorgente, niente indagine" è l'istinto sbagliato. Guarda invece il log del DC.

I campi `LogonProcessName` e `AuthenticationPackageName` ti dicono quale stack di auth ha gestito il tentativo. Valori utili: `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (sceglie uno dei due), `User32` (console locale), `Schannel` (sostenuto da TLS). Qualsiasi altra cosa, guarda più attentamente.

## Per approfondire

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

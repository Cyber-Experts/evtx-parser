---
title: "Event ID 4625 spiegato: rilevare brute force, password spray ed enumerazione"
description: "Il 4625 è il record dei logon falliti. Leggerlo bene significa individuare password spray, credential stuffing e abusi Kerberos prima che vadano a segno."
date: "2026-05-17"
---

L'Event ID 4625 — «An account failed to log on» — si attiva sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un tentativo di autenticazione viene rifiutato. È il singolo record più utile per intercettare l'attività di credential attack, ma solo se leggi i campi giusti.

## I campi che contano davvero

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

La combinazione di `Status` e `SubStatus` ti dice *perché* il logon è fallito:

- `0xc0000064` — l'account non esiste (enumerazione username).
- `0xc000006a` — password sbagliata (il classico).
- `0xc0000234` — account bloccato.
- `0xc0000072` — account disabilitato.
- `0xc0000071` — password scaduta.
- `0xc0000133` — clock skew su un ticket Kerberos (comune durante AS-REP roasting).
- `0xc000018b` — SID errato — la workstation non è nel dominio che pensa.

Una raffica di `0xc0000064` contro username validi e invalidi è ricognizione. Una raffica di `0xc000006a` contro un singolo account è brute force. Una raffica di `0xc000006a` contro molti account con la *stessa password* è un password spray.

## I pattern

Le query di triage più semplici:

1. **Rilevamento spray**: raggruppa i record 4625 per `IpAddress` (o `WorkstationName` se l'IP non è registrato), conta i `TargetUserName` distinti in 10 minuti. >5 account per sorgente in quella finestra è sospetto quasi ovunque.
2. **Brute force**: raggruppa per `TargetUserName`, conta i fallimenti al minuto. >10 al minuto contro un singolo account è di solito un bot.
3. **Causa di un lockout**: abbina il 4740 (account bloccato) ai 4625 che lo precedono — il campo `WorkstationName` mostrerà quale device ha innescato il lockout, cosa critica perché spesso è un server domain-joined con una credenziale stantia memorizzata, non un attaccante.

## Il «dopo» conta quanto il «prima»

Una raffica di 4625 seguita da un [4624](/it/blog/understanding-event-id-4624) dallo stesso `IpAddress` è il caso azionabile — l'attaccante ha trovato una credenziale funzionante. Il parser su questa pagina ti consente di filtrare la tabella per IP sorgente e osservare le transizioni di livello e Event ID nel tempo nella timeline. Il pattern «raffica-poi-picco» è inconfondibile.

## Esempio di regola Sigma — password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
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

## Esempio KQL — brute force contro un singolo account

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Esempio Splunk — enumerazione prima del brute

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

Il segnale è la *progressione* — enumerazione per trovare username validi, poi brute force contro quelli.

## Mappatura ATT&CK

- **T1110.001 — Brute Force: Password Guessing**: singolo account, molti fallimenti `0xC000006A`.
- **T1110.003 — Brute Force: Password Spraying**: molti account, pochi fallimenti per account, una sola sorgente.
- **T1110.004 — Brute Force: Credential Stuffing**: molti account, una sorgente, spesso `0xC0000064` (account inesistente) per i miss della leaked list intervallati a hit `0xC000006A`.
- **T1078 — Valid Accounts**: 4625 seguito da successo [4624](/it/blog/understanding-event-id-4624) dalla stessa sorgente = compromissione.
- **T1556 — Modify Authentication Process**: `LogonProcessName` anomalo (qualsiasi cosa diversa da `User32`, `NtLmSsp`, `Kerberos`, `Advapi` o `Schannel`) suggerisce tampering dell'autenticazione.

## Falsi positivi che sembrano attacchi

- **Credenziali memorizzate diventate stantie** dopo un cambio password. I mapped drive dell'utente, le scheduled task o le configurazioni di service account continuano a riprovare la vecchia password. Il pattern: un solo `TargetUserName`, un solo `IpAddress` (a volte un solo `WorkstationName`), cadenza costante di `0xC000006A`. Caccia l'host con la credenziale stantia e correggilo.
- **Automation mal configurata**: uno script con password sbagliata che ritenta in loop. Stessa forma del brute force; parla con il proprietario prima di lanciare un alert.
- **Vulnerability scanner** durante scansioni autenticate producono traffico 4625 denso. Tagga gli IP degli scanner.
- **Lockout policy mal configurata**: procedure di helpdesk che sbloccano troppo aggressivamente possono produrre cicli ricorrenti 4625 → 4740 → 4624.

## Cosa non vedi nel 4625

I fallimenti NTLMv2 e Kerberos provenienti da un domain controller non sempre portano un `IpAddress` utile — il campo può essere vuoto o `-`. Per quelli ti servono gli eventi DC corrispondenti ([4768](/it/blog/event-id-4768-kerberos-tgt)/4771 per i fallimenti di pre-auth Kerberos) o dati a livello di rete. Non concludere «niente IP sorgente, niente indagine» — pivota sul canale del DC.

I campi `LogonProcessName` e `AuthenticationPackageName` ti dicono quale stack di autenticazione ha gestito il tentativo. I più utili sono `NtLmSsp` (NTLM), `Kerberos` e `Negotiate` (che ne sceglie uno dei due). `User32` è console locale; `Schannel` è basato su TLS.

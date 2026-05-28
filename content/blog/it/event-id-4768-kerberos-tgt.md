---
title: "Event ID 4768 spiegato: richieste TGT Kerberos e AS-REP roasting"
description: "4768 è il record del DC di ogni TGT emesso. Leggilo attraverso il codice di risultato e il flag pre-auth e individui AS-REP roasting, brute force e abuso di unconstrained delegation."
date: "2026-05-24"
---

L'Event ID **4768**, „È stato richiesto un ticket di autenticazione Kerberos (TGT)", scatta su un Domain Controller ogni volta che qualcuno chiede un Ticket Granting Ticket. Ogni logon di dominio inizia con uno di questi. Abbinalo a [4769](/it/blog/event-id-4769-kerberoasting) (service ticket) e vedi l'intero ciclo di vita Kerberos di ogni account nel forest.

Su un DC, 4768 è il record a più alto volume nel [canale Security](/it/blog/what-is-an-evtx-file) dopo 4624. La maggior parte è rumore. Le fette ad alto segnale vivono in due campi specifici, e uno di essi è l'impronta di AS-REP roasting.

## Dove scatta

Come [4769](/it/blog/event-id-4769-kerberoasting), 4768 atterra solo sul **Domain Controller** emittente. Il client non lo vede. Il servizio target non lo vede. Per rilevare qualsiasi cosa da 4768, ti serve la raccolta di Security da ogni DC. Stile KAPE per ingaggi una tantum, WEF per regime continuo.

## Cosa contiene il record

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

I campi che contano:

- `TargetUserName`. L'account che richiede un TGT. Sempre un account utente o computer. `ServiceName` è sempre `krbtgt`.
- `Status`. Codice di risultato Kerberos. `0x0` è successo. I fallimenti sono ciò che rende utile 4768: `0x6` utente sconosciuto, `0x12` client bloccato, `0x17` password scaduta, `0x18` password sbagliata.
- `TicketEncryptionType`. Stessa codifica del 4769: `0x12` e `0x11` AES (moderno), **`0x17` RC4** (legacy, anche l'impronta di AS-REP roasting).
- `PreAuthType`. `2` è la pre-auth standard con encrypted-timestamp. `0` significa **nessuna pre-auth è stata usata** (il prerequisito di AS-REP roasting). `15`, `16`, `17` sono valori di pre-auth basata su certificato PKINIT.
- `IpAddress`. Host richiedente. Abbina al [4624](/it/blog/understanding-event-id-4624) lato client per il contesto completo.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Popolati per PKINIT (logon con smart-card o certificato). Vuoti per logon basati su password.

## I due pattern di attacco che 4768 rivela

### AS-REP roasting (T1558.004)

L'uso da titolone. Alcuni account hanno `DONT_REQUIRE_PREAUTH` impostato in `userAccountControl` (bit UAC 22 = `0x400000`). Per quegli account, il DC risponde a una richiesta TGT **senza** richiedere la pre-auth encrypted-timestamp. L'AS-REP che restituisce contiene materiale che un attaccante può crackare offline per recuperare l'hash della password dell'account.

L'impronta 4768 di un AS-REP roast in corso:

- `PreAuthType = 0` (nessuna pre-auth).
- `TicketEncryptionType = 0x17` (RC4, ciò di cui lo strumento di cracking ha bisogno).
- `Status = 0x0` (il DC ha emesso felicemente l'AS-REP).
- Spesso a cluster. Un attaccante elabora a lotti dozzine di account per testare quali hanno la pre-auth disabilitata.

Account reali con `DONT_REQUIRE_PREAUTH` esistono quasi esclusivamente per compatibilità legacy: client Kerberos Unix molto vecchi, alcune appliance antichissime. Sono pochi di numero e prevedibili in posizione. Un 4768 con `PreAuthType=0` per un account che non ha nulla a che fare con Kerberos senza pre-auth è il segnale.

### Brute force di password o spray

La pre-auth Kerberos fallita produce 4768 con `Status=0x18` („password sbagliata"). A differenza di [4625](/it/blog/detecting-4625-brute-force) (che cattura i fallimenti NTLM), 4768 è dove atterrano gli attacchi di password basati su Kerberos. I toolkit moderni (Rubeus, kerbrute) parlano Kerberos direttamente perché il DC fallisce silenziosamente su tentativi NTLM più veloce di quanto risponda a quelli Kerberos, e molti SOC guardano solo 4625.

L'impronta brute-force di 4768:

- Molti record `Status=0x18` per lo stesso `TargetUserName` dallo stesso IP sorgente in una finestra breve. Brute force.
- Molti record `Status=0x18` su molti valori di `TargetUserName` da un IP sorgente, ciascuno colpito una o due volte. Password spray.
- Una raffica di `Status=0x6` („utente sconosciuto") che precede `Status=0x18` dalla stessa sorgente. Enumerazione utenti confermata prima che inizi la brute.

## Codici di stato che guidano il triage

| Status | Significato | Lettura del campo |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Successo. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Username inesistente. Raffiche = enumerazione. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Account bloccato, disabilitato o scaduto. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Password scaduta. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Password sbagliata. Raffiche = brute force o spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Restituito prima al client su una nuova richiesta TGT. Il vero successo segue. Non allertare solo su questi. |
| `0x25` | KRB_AP_ERR_SKEW | Clock skew > 5 min. Spesso tentativi di AS-REP roasting da un host con clock deliberatamente sbagliato. |

## Workflow di triage: AS-REP roasting

1. Filtra 4768 su tutti i DC per `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Raggruppa per `IpAddress`. Singolo account da un host di migrazione noto è configurazione. Più account da una sorgente è l'attacco.
3. Pivota ogni `TargetUserName` al suo `userAccountControl`. `DONT_REQUIRE_PREAUTH` deve davvero essere impostato? Quasi certamente no.
4. IP sorgente al [4624](/it/blog/understanding-event-id-4624) su quell'host per trovare la credenziale che si è autenticata per lanciare l'attacco.
5. Ruota la password di ogni account crackato. Rimuovi `DONT_REQUIRE_PREAUTH` dagli account che non ne hanno bisogno.

## Workflow di triage: brute force Kerberos

1. Filtra 4768 per `Status == 0x18`.
2. Raggruppa per `IpAddress` su finestre di 15 minuti. Conta i `TargetUserName` distinti.
3. Più di 5 account da una sorgente in 15 minuti è spray. Più di 10 fallimenti contro un account nella stessa finestra è brute force.
4. Incrocia contro `Status == 0x6` dalla stessa sorgente. Enumerazione prima della brute è l'ordine da manuale.

## Sigma: AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: password spray Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapping ATT&CK

- T1558.004 AS-REP Roasting. Detection da titolone su `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force e sotto-tecniche `.001` Password Guessing e `.003` Password Spraying. Pattern `Status=0x18`.
- T1558.001 Golden Ticket. Un TGT forgiato bypassa interamente 4768. La detection qui è per *assenza*: un [4769](/it/blog/event-id-4769-kerberoasting) senza un 4768 precedente dalla stessa sorgente e finestra è il sospetto.
- T1187 Forced Authentication. Non visibile direttamente in 4768 ma le richieste TGT risultanti lo saranno.

## Falsi positivi che sembrano attacchi

- Vecchi stack Java o Unix Kerberos in silos di app legacy a volte fanno default su RC4 senza pre-auth. Si presentano come traffico 4768 costante diurno da un host stabile. Baseline.
- Migrazione PKINIT durante rollout di smart card. Cambi `PreAuthType=15/16/17` legittimi sembrano anomali se non li hai mai visti prima. Sorveglia la finestra di rollout.
- Bug delle librerie Kerberos. Certi client richiedono TGT aggressivamente in caso di clock skew, generando rumore. Incrocia con `Status=0x25`.
- Attraversamento di trust di dominio. L'autenticazione cross-forest produce 4768 da entrambi i lati. L'`IpAddress` è un DC dell'altro forest. Taggalo.

## Cosa 4768 non ti dice

Il record non include il materiale AS-REP effettivo che l'attaccante ha catturato (che è quello che cracka offline). Vedi che la richiesta è stata emessa. Non vedi quali dati sono stati restituiti oltre ai metadati. Non vedi nemmeno la prospettiva client: quale applicazione ha lanciato la richiesta, in quale contesto utente girava. Per quello ti serve il [4624](/it/blog/understanding-event-id-4624) lato client e [4688](/it/blog/event-id-4688-process-creation) se `kerbrute.exe` o Rubeus è girato localmente.

Nota anche che 4768 scatta solo per la richiesta TGT iniziale e per i rinnovi. Una volta che un client ha un TGT valido in cache, non parla più al KDC per TGT fino al rinnovo. I service ticket che ne derivano generano [4769](/it/blog/event-id-4769-kerberoasting), non 4768. Un attaccante che ruba un TGT a lunga vita (golden ticket) può emettere 4769 arbitrari senza mai produrre un altro 4768.

## Dove si inserisce 4768 in una timeline

AS-REP roasting dall'inizio alla fine:

1. [4624](/it/blog/understanding-event-id-4624). Logon iniziale di dominio a basso privilegio (credenziale phishata).
2. *(LDAP, a volte un 4662 se la SACL è impostata)*. L'attaccante enumera `userAccountControl` per account con `DONT_REQUIRE_PREAUTH`.
3. Raffica **4768**. `PreAuthType=0`, `etype=0x17`, `Status=0x0` per ogni account candidato. Il punto di detection.
4. *(Offline, invisibile)*. L'attaccante cracka il materiale AS-REP recuperato in Hashcat (modalità 18200).
5. **4768**. Nuova richiesta TGT come account compromesso, questa volta pre-autenticato normalmente.
6. [4769](/it/blog/event-id-4769-kerberoasting). Service ticket per tutto ciò che l'account compromesso può raggiungere.
7. [4624](/it/blog/understanding-event-id-4624) LogonType 3 sul servizio target.

Il passo 3 è il canarino. Il passo 5 in avanti è la compromissione reale. La finestra tra i due, minuti o giorni, è l'unica finestra in cui un difensore può agire prima che la credenziale sia viva in libertà.

## Per approfondire

- [Documentazione Microsoft per 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)

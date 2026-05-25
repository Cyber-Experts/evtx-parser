---
title: "Event ID 4768 spiegato: richieste TGT Kerberos e AS-REP roasting"
description: "Il 4768 è il record del DC di ogni TGT emesso. Leggilo attraverso il codice di risultato e il flag di pre-auth e individui AS-REP roasting, brute force e abusi di unconstrained delegation."
date: "2026-05-24"
---

L'Event ID **4768** — «A Kerberos authentication ticket (TGT) was requested» — si attiva su un Domain Controller ogni volta che qualcuno richiede un Ticket Granting Ticket. Ogni logon di dominio inizia con uno di questi. Abbinalo a [4769](/it/blog/event-id-4769-kerberoasting) (service ticket) e vedi l'intero ciclo di vita Kerberos di ogni account nel forest.

Su un DC, il 4768 è il record a più alto volume nel [canale Security](/it/blog/what-is-an-evtx-file) dopo il 4624. La maggior parte è rumore; le fette ad alto segnale vivono in due campi specifici — e uno di loro è il fingerprint dell'AS-REP roasting.

## Dove si attiva

Come per il [4769](/it/blog/event-id-4769-kerberoasting), il 4768 atterra solo sul **Domain Controller** emittente. Il client non lo vede; il servizio target non lo vede. Per rilevare qualcosa dal 4768 serve la collection di Security da ogni DC — stile KAPE per engagement one-off, WEF per regime steady-state.

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

- **`TargetUserName`** — l'account che richiede un TGT. Sempre un account utente o computer; `ServiceName` è sempre `krbtgt`.
- **`Status`** — codice di risultato Kerberos. `0x0` è successo. Sono i fallimenti a rendere il 4768 utile: `0x6` = utente sconosciuto, `0x12` = client locked out, `0x17` = password scaduta, `0x18` = bad password.
- **`TicketEncryptionType`** — stessa codifica del 4769: `0x12`/`0x11` AES (moderno), **`0x17` RC4** (legacy, anche il fingerprint di AS-REP roasting).
- **`PreAuthType`** — `2` è la pre-auth standard a encrypted-timestamp; `0` significa **nessuna pre-auth usata** (la precondizione per AS-REP roasting); `15`/`16`/`17` sono valori di pre-auth basata su certificato PKINIT.
- **`IpAddress`** — host richiedente. Abbina al [4624](/it/blog/understanding-event-id-4624) lato client per il contesto completo.
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — popolati per PKINIT (logon smart-card / certificato). Vuoti per logon password-based.

## I due pattern di attacco che il 4768 rivela

### 1. AS-REP roasting (T1558.004)

L'uso principe. Alcuni account hanno il flag `DONT_REQUIRE_PREAUTH` impostato in `userAccountControl` (bit UAC 22 = `0x400000`). Per quegli account, il DC risponde a una richiesta TGT **senza** richiedere la pre-auth a encrypted-timestamp — il che significa che l'AS-REP restituito contiene materiale che un attaccante può crackare offline per recuperare l'hash password dell'account.

Il fingerprint 4768 di un AS-REP roast in corso:

- `PreAuthType` è `0` (no pre-auth).
- `TicketEncryptionType` è `0x17` (RC4 — quello che il tool di cracking richiede).
- `Status` è `0x0` (il DC ha emesso volentieri l'AS-REP).
- Spesso a cluster: un attaccante batcha decine di account per testare quali abbiano la pre-auth disabilitata.

Account reali con `DONT_REQUIRE_PREAUTH` esistono quasi esclusivamente per compatibilità legacy (client Kerberos Unix molto vecchi, alcune appliance antiche). Sono pochi e prevedibili in posizione. Un 4768 con `PreAuthType=0` per un account che *non ha motivo* di usare Kerberos senza pre-auth è il segnale.

### 2. Brute force / spray basato su password

La pre-auth Kerberos fallita produce un 4768 con `Status=0x18` («password sbagliata»). A differenza del [4625](/it/blog/detecting-4625-brute-force) (che cattura fallimenti NTLM), il 4768 è dove atterrano gli attacchi password Kerberos. I toolkit moderni (Rubeus, kerbrute) parlano Kerberos direttamente perché il DC fallisce silenziosamente sui tentativi NTLM più velocemente di quanto risponda a quelli Kerberos — e molti SOC guardano solo il 4625.

Il fingerprint brute-force del 4768:

- Molti record `Status=0x18` per lo stesso `TargetUserName` dallo stesso IP sorgente in una finestra ristretta — brute force classico.
- Molti record `Status=0x18` attraverso molti valori `TargetUserName` dallo stesso IP sorgente, ciascun account colpito una o due volte — password spray.
- Una raffica di `Status=0x6` («utente sconosciuto») che precede un `Status=0x18` dalla stessa sorgente — enumerazione utenti confermata prima dell'inizio del brute.

## I codici Status che vedrai

La lista completa è ampia; questi sono quelli che guidano il triage:

| Status | Significato | Cosa significa solitamente in natura |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Successo. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Username non esiste. Raffiche = enumerazione. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Account locked / disabled / expired. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Password scaduta. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Password sbagliata. Raffiche = brute force o spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Restituito al client *per primo* su una nuova richiesta TGT; segue un vero successo. Non lanciare alert su questi da soli. |
| `0x25` | KRB_AP_ERR_SKEW | Skew di clock > 5 min tra client e DC. Spesso tentativi di AS-REP roasting da un host con un orologio deliberatamente sbagliato. |

## Workflow di triage — AS-REP roasting

1. Filtra i 4768 su tutti i DC per `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Raggruppa per `IpAddress`. Un singolo account da un host di migrazione noto è configurazione; più account da una sorgente è l'attacco.
3. Pivota ogni `TargetUserName` al suo `userAccountControl` — `DONT_REQUIRE_PREAUTH` deve davvero essere impostato? Quasi certamente no.
4. IP sorgente → [4624](/it/blog/understanding-event-id-4624) su quell'host per trovare la credenziale che si è autenticata per lanciare l'attacco.
5. Ruota la password di ogni account crackato; rimuovi `DONT_REQUIRE_PREAUTH` dagli account che non ne hanno bisogno.

## Workflow di triage — brute force Kerberos

1. Filtra i 4768 per `Status == 0x18`.
2. Raggruppa per `IpAddress` su finestre di 15 minuti; conta `TargetUserName` distinti.
3. >5 account da una sorgente in 15 minuti è spray; >10 fallimenti contro un account nella stessa finestra è brute force.
4. Cross-check contro `Status == 0x6` dalla stessa sorgente — enumerazione prima del brute è l'ordering da manuale.

## Esempio di regola Sigma — AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## Esempio KQL — password spray Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Esempio Splunk — AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mappatura ATT&CK

- **T1558.004 — AS-REP Roasting**: la detection di punta su `PreAuthType=0 + etype=0x17`.
- **T1110 — Brute Force** e sub-techniques `.001` Password Guessing e `.003` Password Spraying — pattern `Status=0x18`.
- **T1558.001 — Golden Ticket**: un TGT forgiato bypassa il 4768 interamente. Qui la detection è per *assenza* — un [4769](/it/blog/event-id-4769-kerberoasting) (TGS request) senza un 4768 precedente dalla stessa sorgente/finestra è il sospetto.
- **T1187 — Forced Authentication**: non direttamente visibile nel 4768 ma le richieste TGT risultanti lo saranno.

## Falsi positivi che sembrano attacchi

- **Vecchi stack Kerberos Java / Unix** in silos di app legacy a volte fanno default a RC4 senza pre-auth. Si presentano come traffico 4768 stabile, diurno, da un host stabile. Baseline.
- **Migrazione PKINIT** durante rollout di smart-card: i legittimi flip `PreAuthType=15/16/17` sembrano anomali se non li hai mai visti prima. Sorveglia la finestra di rollout.
- **Bug di librerie Kerberos**: certi client ri-richiedono TGT aggressivamente con skew temporale, generando rumore. Cross-check con `Status=0x25`.
- **Traversal di trust di dominio**: l'autenticazione cross-forest produce 4768 su entrambi i lati. L'`IpAddress` sarà un DC dell'altro forest; taggalo.

## Cosa il 4768 non ti dice

Il record **non** include il materiale AS-REP effettivo che l'attaccante ha catturato (che è ciò che crackano offline). Vedi che la richiesta è stata emessa; non vedi quali dati sono stati restituiti oltre ai metadati. Non vedi nemmeno la prospettiva *client* — quale applicazione ha lanciato la richiesta, in quale contesto utente girava, ecc. Per quello ti serve il [4624](/it/blog/understanding-event-id-4624) lato client (e il [4688](/it/blog/event-id-4688-process-creation) se `kerbrute.exe` è girato localmente).

Nota anche che il 4768 si attiva solo per la richiesta TGT *iniziale* e sui rinnovi. Una volta che un client ha un TGT valido in cache, non parla di nuovo col KDC per TGT fino al rinnovo; i ticket di *servizio* che ne deriva generano [4769](/it/blog/event-id-4769-kerberoasting), non 4768. I due record descrivono stadi differenti dello stesso protocollo — e un attaccante che ruba un TGT a lunga durata (golden ticket) può emettere 4769 arbitrari senza mai produrre un altro 4768.

## Dove il 4768 si colloca in una timeline

La catena AS-REP roasting da inizio a fine:

1. [**4624**](/it/blog/understanding-event-id-4624) — logon di dominio iniziale low-privilege (credenziale phishata).
2. *(LDAP, talvolta un 4662 se la SACL è impostata)* — l'attaccante enumera i flag `userAccountControl` per account con `DONT_REQUIRE_PREAUTH`.
3. **4768** burst — `PreAuthType=0`, `etype=0x17`, `Status=0x0` per ogni account candidato. **Questo è il punto di detection.**
4. *(Offline, invisibile)* — l'attaccante cracca il materiale AS-REP recuperato in Hashcat (mode 18200) e recupera la password in chiaro.
5. **4768** — nuova richiesta TGT come account compromesso, stavolta normalmente pre-authata.
6. [**4769**](/it/blog/event-id-4769-kerberoasting) — service ticket per tutto ciò che l'account compromesso può raggiungere.
7. [**4624**](/it/blog/understanding-event-id-4624) LogonType 3 sul servizio target.

Il passo 3 è il canarino. Dal passo 5 in poi è la compromissione vera. La finestra tra di loro — da minuti a giorni — è l'unica finestra in cui un difensore può agire prima che la credenziale sia viva in natura.

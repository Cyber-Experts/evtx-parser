---
title: "Event ID 4769 spiegato: service ticket Kerberos e kerberoasting"
description: "4769 è il record del DC di ogni richiesta di service ticket. Leggilo attraverso il tipo di cifratura e individui il kerberoasting. Leggilo con 4768 e individui il pass-the-ticket."
date: "2026-05-24"
---

L'Event ID **4769**, „È stato richiesto un service ticket Kerberos", scatta su ogni Domain Controller ogni volta che un account richiede un ticket TGS (Ticket Granting Service) per un servizio. Ogni connessione SMB, ogni login SQL, ogni hit SSO web ne produce uno sul DC che ha gestito la richiesta. È il record a più alto volume nel [canale Security](/it/blog/what-is-an-evtx-file) su un DC carico, e l'unico posto dove il kerberoasting si presenta in modo affidabile prima che le credenziali vengano crackate offline.

Se strumenti solo tre record di Security dai tuoi DC, questo è uno di essi.

## Dove vive

`4769` viene scritto sul canale Security del **Domain Controller emittente** soltanto. Non il client, non il servizio target. Per vedere tutti i record 4769 di un dominio, devi raccogliere da ogni DC. Il target `EventLogs` di KAPE su un DC, o l'inoltro di Security via WEF a un collector, funzionano entrambi. WEF è quello che usano gli shop maturi.

## Cosa contiene il record

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

I campi che guidano il triage:

- `TargetUserName`. Il richiedente (l'account utente, in formato `user@DOMAIN`).
- `ServiceName`. Lo SPN richiesto. Un account utente qui (anziché `host/...` o una service class) è sospetto.
- `TicketEncryptionType`. Il campo che decide se questo record conta. I domini moderni girano con `0x12` (AES-256-CTS-HMAC-SHA1-96) o `0x11` (AES-128). **`0x17` è RC4-HMAC**: legacy, debole e l'*unico* tipo di cifratura che Mimikatz e la modalità `kerberoast` di Rubeus richiedono. Un 4769 per un ticket di service account con `0x17` è un'impronta da manuale di kerberoasting.
- `Status`. `0x0` è successo. Tutto il resto è negato (codici documentati in `[MS-KILE]`).
- `IpAddress`. Host richiedente. Abbina al [4624](/it/blog/understanding-event-id-4624) su quell'host per vedere il logon che ha prodotto la sessione.

## TicketEncryptionType: il campo che decide

| Valore | Algoritmo | Stato |
|---|---|---|
| 0x01 | DES-CBC-CRC | Disabilitato per default da Win7 |
| 0x03 | DES-CBC-MD5 | Disabilitato per default da Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (default per la maggior parte degli account) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Richiesto per il kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 grade export, raro al limite |

Se il dominio è stato baselined e `msDS-SupportedEncryptionTypes` impostato ad AES-only sui service account, `0x17` non dovrebbe apparire per quegli account affatto. Gli attaccanti richiedono `0x17` esplicitamente perché crackare service ticket cifrati in RC4 è computazionalmente economico. AES no. Lo strumento di cracking *deve* richiedere 0x17.

Questo è il singolo campo a più alto segnale del record.

## Il pattern del kerberoasting

Il kerberoasting (T1558.003) funziona così:

1. L'attaccante si autentica con un qualsiasi utente di dominio (non servono privilegi admin).
2. L'attaccante enumera gli SPN registrati su account utente (non account computer), tipicamente tramite LDAP `(servicePrincipalName=*)` filtrato sugli oggetti user.
3. L'attaccante richiede un TGS per ogni SPN con `etype=23` (RC4) tramite il protocollo Kerberos standard. Il 4769 che stai cercando.
4. Il DC emette felicemente il ticket, cifrato con l'hash NTLM del service account.
5. L'attaccante tira il blob cifrato e lo cracka offline in Hashcat (`-m 13100`).

L'impronta 4769:

- `ServiceName` è `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` o qualsiasi SPN che punta a un account utente (non `host/...` o `cifs/...`, che sono account computer).
- `TicketEncryptionType` è `0x17`.
- Una raffica in una finestra breve, dalla stessa sorgente, per molti SPN.

Un pattern correlato, **AS-REP roasting** (T1558.004), usa invece [4768](/it/blog/event-id-4768-kerberos-tgt), mirando ad account con `DONT_REQUIRE_PREAUTH`. Record diverso, stessa famiglia.

## Pass-the-ticket, golden, silver

4769 rivela anche la forgia di ticket, ma il segnale è più sottile.

- Un 4769 *senza* un 4768 precedente per la stessa `LogonGuid` dallo stesso host in una finestra ragionevole: sospetto di golden ticket. L'attaccante ha presentato un TGT forgiato ed è andato dritto alle richieste TGS.
- Un 4769 *e* l'autenticazione di servizio risultante sul target *senza* un 4769 visibile su nessun DC: sospetto di silver ticket. L'attaccante ha forgiato il TGS stesso. Al DC non è stato mai chiesto.
- Mismatch di `LogonGuid` tra il 4624 sul target e il 4769 che presumibilmente avrebbe emesso il ticket: ticket forgiato.

Questi sono pattern di detection per assenza. Richiedono copertura log completa su tutti i DC e servizi target. Lacune nella copertura WEF producono falsi positivi identici. Caratterizza la tua raccolta prima di allertare.

## Workflow di triage

1. Filtra tutti i 4769 sul corpus DC per `TicketEncryptionType == 0x17`.
2. Raggruppa per `IpAddress` e `TargetUserName` su finestre di 30 minuti. Conta `ServiceName` distinti per sorgente.
3. Più di 3 SPN distinti richiesti come 0x17 da una sorgente entro 30 minuti è kerberoasting quasi ovunque.
4. Pivota l'IP sorgente al suo [4624](/it/blog/understanding-event-id-4624) per trovare la credenziale che ha iniziato l'attacco.
5. Pivota gli SPN richiesti agli account di servizio proprietari. Ruota quelle password. Resetta gli hash crackati in ore, non in giorni.

## Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

`filter_machine` esclude gli SPN di account computer (che finiscono sempre in `$`). Il kerberoasting mira solo a SPN di account utente.

## KQL e Splunk

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapping ATT&CK

- T1558.003 Kerberoasting. Il titolo.
- T1558.001 Golden Ticket. 4769 senza 4768 dalla stessa `LogonGuid`.
- T1558.002 Silver Ticket. 4769 assente per una service auth osservata sul target.
- T1078 Valid Accounts. 4769 da un IP inatteso per un service account noto.
- T1550.003 Pass the Ticket. 4769 seguito da [4624](/it/blog/understanding-event-id-4624) LogonType 3 con `LogonProcessName: Kerberos`.

## Falsi positivi che vedrai

- Le applicazioni legacy (alcuni vecchi connettori di SQL Server, certe app Java/JBoss) richiedono RC4 esplicitamente. `0x17` costante diurno da un piccolo set di host stabili. Baseline ed escludi.
- I domini pre-AES durante una transizione di hardening Kerberos emettono `0x17` ampiamente finché `msDS-SupportedEncryptionTypes` non è impostato su ogni account. Fastidioso. Non malevolo.
- Gli scanner di vulnerabilità (Tenable, Qualys, script di enumerazione BloodHound) replicano il traffico di kerberoasting. Tagga gli host scanner.
- Gli strumenti di migrazione account durante spostamenti cross-forest possono richiedere combinazioni inusuali.

Il segnale è il pattern in *raffica*, non il singolo record. `0x17` costante da un host è configurazione. `0x17` a raffica verso molti SPN da un host in pochi minuti è l'attacco.

## Cosa 4769 non ti dice

Il record non include il ticket cifrato stesso. Il cracking avviene su quello che l'attaccante ha esfiltrato, non sul cavo dal DC. Non puoi, dal solo 4769, distinguere „ticket emesso e mai usato" da „ticket crackato, credenziali riutilizzate". Per la seconda metà della catena ti serve il [4624](/it/blog/understanding-event-id-4624) risultante sul servizio target (LogonType 3, AuthenticationPackage Kerberos), e idealmente [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) che mostri cosa è girato dopo che la credenziale è stata riutilizzata. Tratta 4769 come il canarino, non come l'allarme.

## Dove si inserisce 4769 in una timeline

Catena classica di kerberoasting post-exploitation:

1. [4624](/it/blog/understanding-event-id-4624) su una workstation. Accesso iniziale tramite credenziali utente phishate.
2. **4769** ×N da quella workstation a un DC, tutti `etype=0x17`, tutti che mirano a service account con SPN-utente entro 5 minuti. Kerberoasting.
3. *(Offline, invisibile)*. L'attaccante cracka l'hash del service account più debole in Hashcat.
4. [4768](/it/blog/event-id-4768-kerberos-tgt). Richiesta TGT come service account compromesso, da un host diverso.
5. 4624 LogonType 3 su un server ad alto valore, AuthenticationPackage Kerberos.
6. [7045](/it/blog/service-creation-event-id-7045). Servizio installato per la persistenza sotto l'account compromesso.

La raffica 4769 al passo 2 è il tuo punto di detection più precoce ed economico. Ore o giorni prima che l'attaccante torni come service account.

## Per approfondire

- [Documentazione Microsoft per 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)

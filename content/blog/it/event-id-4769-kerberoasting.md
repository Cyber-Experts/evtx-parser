---
title: "Event ID 4769 spiegato: service ticket Kerberos e kerberoasting"
description: "Il 4769 è il record del DC di ogni richiesta di service ticket. Leggilo attraverso il tipo di encryption e individui il kerberoasting; leggilo insieme al 4768 e individui il pass-the-ticket."
date: "2026-05-24"
---

L'Event ID **4769** — «A Kerberos service ticket was requested» — si attiva su ogni Domain Controller ogni volta che qualunque account richiede un ticket TGS (Ticket Granting Service) per un servizio. Ogni connessione SMB, ogni login SQL, ogni hit di SSO web ne produce uno su qualsiasi DC abbia gestito la richiesta. È il record a più alto volume nel [canale Security](/it/blog/what-is-an-evtx-file) su un DC occupato — e l'unico posto dove il kerberoasting si manifesta in modo affidabile prima che le credenziali vengano crackate offline.

Se devi strumentare solo tre record Security dai tuoi domain controller, questo è uno di loro.

## Dove vive

Il `4769` viene scritto sul canale `Security` del **Domain Controller emittente** — non sul client e non sul servizio target. Per vedere tutti i record 4769 di un dominio devi collezionare da ogni DC. Il target `EventLogs` di KAPE su un DC, o il forwarding di `Security` via WEF a un collector, entrambi funzionano; la via WEF è quella che usa la maggior parte dei negozi maturi.

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

- **`TargetUserName`** — il *richiedente* (l'account utente, in forma `user@DOMAIN`).
- **`ServiceName`** — l'SPN richiesto. Un account utente qui (invece di `host/...` o di una service class) è sospetto.
- **`TicketEncryptionType`** — il valore che decide se questo record conta. I domini moderni usano `0x12` (AES-256-CTS-HMAC-SHA1-96) o `0x11` (AES-128). **`0x17` è RC4-HMAC** — legacy, debole, e l'*unico* tipo di encryption che la modalità `kerberoast` di Mimikatz/Rubeus richiede. Un 4769 per un ticket di service account con `0x17` è un fingerprint da manuale di kerberoasting.
- **`Status`** — `0x0` è successo; qualsiasi altra cosa significa denied (codici di status documentati in `[MS-KILE]`).
- **`IpAddress`** — l'host richiedente. Abbina al [4624](/it/blog/understanding-event-id-4624) su quell'host per vedere il logon che ha prodotto la sessione.

## TicketEncryptionType — il campo che conta

La tabella completa, abbreviata:

| Valore | Algoritmo | Stato |
|---|---|---|
| 0x01 | DES-CBC-CRC | Disabilitato per default da Win7 |
| 0x03 | DES-CBC-MD5 | Disabilitato per default da Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (default per la maggior parte degli account) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Richiesto per kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 export-grade, estremamente raro |

Se il dominio è stato baselinato e `msDS-SupportedEncryptionTypes` è impostato a solo AES sui service account, `0x17` non dovrebbe apparire affatto per quegli account. Gli attaccanti richiedono `0x17` esplicitamente perché crackare service ticket cifrati RC4 è computazionalmente economico; AES no. Il tool di cracking ha bisogno dell'hash RC4, quindi la richiesta *deve* essere 0x17.

Questo è il singolo campo a segnale più alto sul record.

## Il pattern di kerberoasting

Il kerberoasting (MITRE T1558.003) funziona così:

1. L'attaccante si autentica con un qualunque account utente di dominio (non servono diritti admin).
2. L'attaccante enumera gli SPN registrati su account utente (non account computer), tipicamente via LDAP `(servicePrincipalName=*)` filtrato a oggetti utente.
3. L'attaccante richiede un TGS per ogni SPN con `etype=23` (RC4) tramite il protocollo Kerberos standard. **Questo è il 4769 che stai cercando.**
4. Il DC emette volentieri il ticket, cifrato con l'hash NTLM del *service account*.
5. L'attaccante estrae il blob cifrato dalla memoria (o dal cavo) e lo cracca offline con Hashcat (`-m 13100`).

Il fingerprint 4769:

- `ServiceName` è `MSSQLSvc/...`, `HTTP/...`, `LDAP/...`, o qualsiasi SPN che punti a un account *utente* (non `host/...` o `cifs/...` che sono account computer).
- `TicketEncryptionType` è `0x17`.
- Una raffica di queste richieste in una finestra ristretta, dalla stessa sorgente, per molti SPN, è la prova schiacciante.

Un secondo pattern correlato — **AS-REP roasting** (T1558.004) — usa il [4768](/it/blog/event-id-4768-kerberos-tgt) invece (la richiesta TGT), targettando account con `DONT_REQUIRE_PREAUTH` impostato. Record diverso, stessa famiglia di attacchi.

## Pass-the-ticket / golden / silver ticket

Il 4769 rivela anche la forgery di ticket, ma il segnale è più sottile.

- Un 4769 *senza* un 4768 precedente (richiesta TGT) per lo stesso `LogonGuid` dallo stesso host in una finestra ragionevole — sospetto di **golden ticket**. L'attaccante ha presentato un TGT forgiato ed è andato dritto alle richieste TGS senza mai chiedere un vero TGT.
- Un 4769 *e* l'autenticazione di servizio risultante sul target *senza* un 4769 visibile su qualunque DC — sospetto di **silver ticket**. L'attaccante ha forgiato il TGS stesso; al DC non è mai stato chiesto.
- Mismatch del `LogonGuid` tra il 4624 sul servizio target e il 4769 che presumibilmente emette il ticket — ticket forgiato.

Questi sono pattern di detection-by-absence, il che significa che richiedono una copertura di log completa su tutti i DC e i servizi target. I gap nella copertura WEF producono falsi positivi identici; caratterizza la tua collection prima di lanciare alert.

## Workflow di triage

1. Filtra tutti i 4769 nel corpus dei DC per `TicketEncryptionType == 0x17`.
2. Raggruppa per `IpAddress` e per `TargetUserName` su finestre di 30 minuti. Conta gli `ServiceName` distinti per sorgente.
3. >3 SPN distinti richiesti come 0x17 da una sorgente in 30 minuti è kerberoasting quasi ovunque.
4. Pivota l'IP sorgente al suo [4624](/it/blog/understanding-event-id-4624) sull'host originante — trova la credenziale che ha iniziato l'attacco.
5. Pivota gli SPN richiesti ai service account che li possiedono. Ruota quelle password. Resetta gli hash crackati in ore, non giorni.

## Esempio di regola Sigma

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

La clausola `filter_machine` esclude gli SPN di account computer (che finiscono sempre con `$`); il kerberoasting target solo SPN di account utente.

## Esempio KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`):

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

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mappatura ATT&CK

Il corpus 4769 copre:

- **T1558.003 — Kerberoasting**: il caso d'uso di punta.
- **T1558.001 — Golden Ticket**: 4769 senza 4768 dallo stesso `LogonGuid`.
- **T1558.002 — Silver Ticket**: 4769 assente per un service-auth osservato sul target.
- **T1078 — Valid Accounts**: 4769 da un IP inatteso per un service account noto.
- **T1550.003 — Pass the Ticket**: 4769 seguito da [4624](/it/blog/understanding-event-id-4624) LogonType 3 con `LogonProcessName: Kerberos`.

## Falsi positivi che vedrai

- **Applicazioni legacy** (alcuni vecchi connettori SQL Server, alcune app Java/JBoss) richiedono esplicitamente RC4. Si presentano come traffico 0x17 stabile, diurno, da un piccolo set di host stabili. Baseline ed escludi.
- **Domini pre-AES** durante una transizione di hardening Kerberos emetteranno 0x17 ampiamente finché `msDS-SupportedEncryptionTypes` non sia impostato su ogni account. Fastidioso; non malizioso.
- **Vulnerability scanner** (Tenable, Qualys, script di enumerazione BloodHound) replicano il traffico di kerberoasting. Tagga gli host degli scanner.
- **Tool di migrazione account** durante move cross-forest possono richiedere combinazioni di ticket inusuali.

Il segnale è il pattern di *raffica*, non il record individuale. Un 0x17 stabile da un host è configurazione; un 0x17 in raffica verso molti SPN da un host in pochi minuti è l'attacco.

## Cosa il 4769 non ti dice

Il record non include il ticket cifrato stesso — il cracking avviene su qualsiasi cosa l'attaccante abbia exfiltrato, non sul cavo dal DC. Dal solo 4769 non puoi distinguere «ticket emesso e mai usato» da «ticket crackato, credenziali riutilizzate». Per la seconda metà della catena ti serve il [4624](/it/blog/understanding-event-id-4624) risultante sul servizio target (LogonType 3, AuthenticationPackage Kerberos), e idealmente il [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) che mostri cosa è girato dopo il riutilizzo della credenziale. Tratta il 4769 come canarino, non come allarme.

## Dove il 4769 si colloca in una timeline

Catena classica di kerberoasting post-exploitation:

1. [**4624**](/it/blog/understanding-event-id-4624) su una workstation — accesso iniziale via credenziali utente phishate.
2. **4769** ×N da quell'IP workstation a un DC, tutti `etype=0x17`, tutti targettanti service account user-SPN in 5 minuti — kerberoasting.
3. *(Offline, invisibile)* — l'attaccante cracka l'hash del service account più debole in Hashcat.
4. **4768** — richiesta TGT come service account compromesso, da un host diverso.
5. **4624** LogonType 3 su un server ad alto valore, AuthenticationPackage Kerberos, usando il service account.
6. [**7045**](/it/blog/service-creation-event-id-7045) — servizio installato per persistenza sotto l'account compromesso.

La raffica di 4769 al passo 2 è il tuo punto di detection più precoce ed economico — ore o giorni prima che l'attaccante torni come service account.

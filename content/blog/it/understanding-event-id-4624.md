---
title: "Event ID 4624 spiegato: logon Windows riuscito e riferimento LogonType"
description: "Cosa contiene davvero un record 4624, perché il campo LogonType conta più dell'evento stesso, e come leggerli su scala."
date: "2026-05-17"
---

L'event ID 4624, "Un account ha effettuato l'accesso correttamente", atterra sul [canale `Security`](/en/blog/what-is-an-evtx-file) ogni volta che Windows autentica un'identità. È il singolo record con più alto traffico sulla maggior parte delle workstation e la spina dorsale di quasi ogni indagine IR. Sapere come leggerne uno non è opzionale.

## Cosa c'è dentro un record 4624

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

I campi `Subject*` sono il contesto di sicurezza che *ha richiesto* il logon (spesso `S-1-5-18` per SYSTEM durante start di servizio). I campi `Target*` sono l'identità che è finita autenticata. Confondere i due costa ore agli analisti. Ho visto un analista senior escalare su un `Subject` che si è rivelato essere SYSTEM che eseguiva un servizio interno. Leggete entrambi, due volte, prima di fare la chiamata.

## LogonType è il campo che decide

Windows porta dieci tipi di logon. In pratica solo una manciata guidano il triage:

- **2 Interattivo**. Logon fisico o di console.
- **3 Rete**. SMB, RPC, WinRM, qualsiasi cosa attraverso il filo. La vasta maggioranza del traffico normale.
- **4 Batch**. Task pianificati che girano come utente.
- **5 Servizio**. Un servizio avviato sotto un account specifico.
- **7 Unlock**. Workstation sbloccata dopo blocco schermo.
- **8 NetworkCleartext**. Raro e sospetto. Credenziali inviate in chiaro (Basic auth su IIS, stampanti antiche, simple bind LDAP mal configurato).
- **9 NewCredentials**. `runas /netonly`. Spesso usato da attaccanti che portano credenziali di dominio su una macchina su cui hanno solo diritti locali.
- **10 RemoteInteractive**. RDP. Si abbina a `IpAddress` per attribuzione di sorgente.
- **11 CachedInteractive**. Account di dominio loggato con credenziali in cache. Nessun DC raggiungibile.

Un 4624 con LogonType **10** da un IP esterno alle 03:00 di domenica racconta una storia molto diversa da 50 record LogonType **3** da un server backup alle 02:00.

## Con cosa concatenarlo

Un 4624 riuscito da solo è raramente un finding. Diventa uno quando abbinato con:

- [4625](/en/blog/detecting-4625-brute-force) che lo precede dalla stessa sorgente. Un successo dopo una raffica di fallimenti è la firma da manuale brute-force-poi-successo.
- [4672](/en/blog/event-id-4672-special-privileges). Segnala logon che hanno concesso privilegi come `SeDebugPrivilege`.
- 4648 (logon con credenziali esplicite). Cattura `runas` e altri pattern di passaggio credenziali. La maggior parte dei difensori lo sottoutilizza.
- [7045](/en/blog/service-creation-event-id-7045) che lo segue con LogonType 3. Installazione di servizio dopo un logon di rete è la firma di PsExec.

## I cinque pattern

Quelli che effettivamente scattano allarmi in un vero SOC, in ordine approssimativo di quanto spesso guadagnano il loro valore:

1. **Brute-force-poi-successo.** Una raffica di [4625](/en/blog/detecting-4625-brute-force) da un IP sorgente seguita entro minuti da un 4624 dallo stesso IP per lo stesso `TargetUserName`. L'attaccante ha trovato una credenziale funzionante. La cattura più economica nel catalogo di audit.
2. **RDP fuori orario.** 4624 con `LogonType=10` da IP esterno fuori orario di ufficio. Taggate IP di egress VPN admin noti. Tutto il resto è una vera pista.
3. **`runas /netonly`.** 4624 con `LogonType=9`. L'uso legittimo è raro (tool admin che usano credenziali di dominio estraneo). L'uso attaccante è un pattern di pivot credenziali dopo aver catturato credenziali da un host su cui non vogliono apparire.
4. **NetworkCleartext (LogonType=8).** Credenziali in chiaro sul filo. Cause reali sono vecchie app IIS Basic-auth, stampanti antiche, o simple bind LDAP mal configurato. Ciascuna è una responsabilità di leak di credenziali.
5. **Drift di LogonType su service account.** Un service account che storicamente scatta solo LogonType 3 che improvvisamente produce LogonType 10 o LogonType 2. Significa quasi sempre che qualcuno sta usando il service account interattivamente. Segnale forte di credenziali rubate.

## Sigma: logon riuscito dopo raffica di fallimenti

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source. Brute-force-then-success.
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: windows
  service: security
detection:
  fail_burst:
    EventID: 4625
  success:
    EventID: 4624
    LogonType:
      - 3
      - 10
  timeframe: 10m
  condition: ( fail_burst | count() by IpAddress,TargetUserName > 10 ) and success
falsepositives:
  - Users repeatedly typing passwords after a recent password change
  - SSO endpoints with retry behavior on first auth
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## KQL: RDP fuori orario da IP esterni

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and not (IpAddress startswith "172." and toint(split(IpAddress, ".")[1]) between (16 .. 31))
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 7 or Hour > 20
| project TimeGenerated, Account, IpAddress, WorkstationName, Computer
| order by TimeGenerated desc
```

## Splunk: drift di LogonType su un service account

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

I service account dovrebbero produrre un singolo `LogonType` stabile (di solito 3 o 5). Più tipi sotto lo stesso account è l'allarme.

## Mapping ATT&CK

- T1078 Valid Accounts (e sotto-tecniche `.001` Default, `.002` Domain, `.003` Local). Ogni logon riuscito da una credenziale compromessa si mappa qui. 4624 è la *prova* della tecnica.
- T1110 Brute Force. Combinato con raffiche [4625](/en/blog/detecting-4625-brute-force).
- T1021 Remote Services (`.001` RDP, `.002` SMB, `.006` WinRM). La maggior parte del traffico 4624 LogonType=3/10 lato-rete.
- T1550 Use Alternate Authentication Material. `.002` Pass the Hash (4624 NTLM-package da sorgente inattesa), `.003` Pass the Ticket (4624 Kerberos-package senza [4769](/en/blog/event-id-4769-kerberoasting) corrispondente su nessun DC).

## Falsi positivi che sembrano esattamente attacchi

- I vulnerability scanner (Tenable, Qualys, Rapid7) generano traffico denso 4624 LogonType=3 da un set stabile di IP scanner. Taggate ed escludete.
- I check-in dei client SCCM e Intune producono traffico 4624 ricorrente verso endpoint di management.
- Gli agenti di backup si autenticano su molti host secondo schedule. Sembra propagazione. Non lo è.
- Le box Citrix e RDS multi-sessione vedono legittimamente LogonType=10 da molti IP interni. Filtrate per range sorgente.
- UX di cambio password. Gli utenti che hanno appena cambiato una password e hanno ribattuto la vecchia due volte producono 4625 / 4625 / 4624. Quello non è brute force, è memoria muscolare.

Il segnale è ricorrenza *inattesa* o combinazioni *nuove*, non volume grezzo.

## Cosa 4624 non vi dice

- Nessuna informazione di processo. Vedete il logon, non cosa è girato nella sessione risultante. Pivotate `LogonId` su [4688](/en/blog/event-id-4688-process-creation) o [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) per vedere attività di processo.
- Nessun processo sorgente per il logon stesso. Sapete che NTLM o Kerberos è stato usato, ma non quale app client l'ha iniziato.
- `IpAddress` può essere vuoto o `-` per logon NTLM da un DC. Il campo non è affidabile su ogni record.
- I logon interattivi cached (Type 11) avvengono quando il DC è irraggiungibile. Confermano che una credenziale ha funzionato localmente, non che l'account vivo sia abilitato sul DC.

## Leggere su scala

Il [parser browser su questo sito](/en/blog/how-to-open-an-evtx-file) estrae questi campi direttamente dall'XML del record e li espone nella tabella. Filtrate per `LogonType` tramite i bucket di timeline e il filtro testo, tirate il set filtrato come CSV, poi pivotate su `SubjectUserSid` e `IpAddress` nel vostro tool di scelta. L'XML completo di ogni record è a un click di distanza. Abbinatelo agli [artefatti cache RDP](https://www.jumplistparser.com), al tracking [recent file](https://www.recentfilecacheparser.com), e all'[history del browser](https://www.browserforensics.app) quando l'account utente in questione è un utente reale, non un servizio.

## Per approfondire

- [Documentazione Microsoft per 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)

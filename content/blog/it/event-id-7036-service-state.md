---
title: "Event ID 7036 spiegato: cambi di stato dei servizi per il triage DFIR"
description: "7036 scatta ogni volta che un servizio parte o si ferma. Abbinato a 7045 conferma se la persistenza è davvero girata. Da solo rivela abuso di servizi, evasione difensiva e anomalie di boot."
date: "2026-05-24"
---

L'Event ID **7036**, „Il servizio {service} è passato nello stato {state}", scatta sul [canale `System`](/it/blog/what-is-an-evtx-file) ogni volta che il Service Control Manager vede una transizione di servizio. Ogni avvio, arresto, pausa e ripresa ne produce uno. Da solo è ad alto volume e facile da liquidare. Abbinato a [7045](/it/blog/service-creation-event-id-7045) è la differenza tra „è stato installato un backdoor" e „è stato installato un backdoor ed è girato".

Per l'incident response, questo è il record „è stato eseguito?" più economico che l'OS ti dia.

## Dove vive

Canale `System` sull'host dove il servizio è girato. Nessun coinvolgimento del DC, nessuna preoccupazione di inoltro per canale. È proprio lì in `System.evtx`. Provider: `Service Control Manager`.

## Cosa contiene il record

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

È tutto. Due parametri e un tag binario. Molto più piccolo della maggior parte dei record Security, ed è per questo che gli analisti lo saltano.

- `param1`. Il *nome visualizzato* del servizio (non il nome breve). `Background Intelligent Transfer Service` qui è il nome lato utente di `BITS`. Per pivotare alla definizione del servizio di solito ti serve il nome breve. L'SCM lo stampa in `Binary` come blob UTF-16 (`42 00 49 00 54 00 53 00` decodifica a `BITS`).
- `param2`. Il nuovo stato: `running`, `stopped`, `paused`, `resumed` o intermedi pendenti (`start pending`, `stop pending`). `running` e `stopped` sono ciò su cui la maggior parte delle regole si basa.

Non c'è `AccountName`, né `ImagePath`, né `ProcessId`. 7036 ti dice *cosa* ha cambiato stato, non *chi* l'ha innescato. Per il perché, abbina ad altri record.

## 7036, 7045, 7035, 7034: qual è quale

Quattro eventi relativi ai servizi del canale System vengono confusi di continuo:

| Evento | Quando | Cosa ti dà |
|---|---|---|
| **7045** | Servizio installato | Nome visualizzato, nome breve, `ImagePath`, `AccountName`, `StartType`. Il punto di persistenza. |
| **7036** | Avvio/arresto servizio | Solo nome visualizzato. Il punto di esecuzione. |
| **7035** | Service control inviato | Chi ha iniziato start/stop (SID), quale controllo è stato inviato. Raramente attivo di default. |
| **7034** | Servizio crashato inaspettatamente | Servizio terminato senza stop pulito. |

Il pattern conta: un 7045 seguito secondi dopo da un 7036 `running` per lo stesso nome visualizzato è la sequenza da manuale di „installato e girato". Un 7045 *senza* un 7036 corrispondente significa che il servizio è stato registrato ma mai eseguito: o l'attaccante ha ripulito, o l'installer ha abortito, o l'avvio è stato differito.

## I pattern di triage

### Verifica di persistenza: abbinare a 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Tre record, un evento di esecuzione laterale PsExec. La coppia 7036 ti dice che il servizio è davvero girato (non solo installato). Per un backdoor *persistente* il secondo 7036 (stopped) può mancare o apparire ore dopo quando l'host riavvia.

Un 7045 senza un 7036 `running` entro pochi minuti è una sua propria anomalia. Indaga perché l'installazione non ha scattato. Cause comuni: staged per il prossimo reboot, impostato su avvio manuale e l'attaccante non l'aveva ancora innescato, avvio fallito (cerca errori 7034 / 7000).

### Evasione difensiva: fermare i servizi di sicurezza

Il pattern più abusato. Un attaccante ferma `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` o il servizio di un prodotto EDR. Ciascuno genera un 7036 `stopped` per il nome visualizzato corrispondente. Se si tenta manomissione di audit policy o Defender, questo è uno dei record che sopravvive.

Nomi da allertare (nomi visualizzati; variano per versione di Defender o EDR):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Qualsiasi cosa che combaci con `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` per uno di questi, specialmente fuori da una finestra di manutenzione pianificata, dovrebbe essere un allert duro. Molti attaccanti usano `sc stop`, `net stop`, `Stop-Service` o `taskkill /im`. Tutti e quattro producono un 7036.

### Typosquatting del nome del servizio

7036 scatta per il nome visualizzato anche quando il servizio sottostante è malevolo. Sorveglia nomi visualizzati che sembrano legittimi ma non combaciano con nessun servizio Microsoft installato: `Windows Update Service` (il vero nome è `Windows Update`), `Windows Defender Service` (il vero nome è `Windows Defender Antivirus Service`), `Microsoft Telemetry` (nessun servizio del genere). Baseline i nomi visualizzati da un host noto buono e fai diff.

### Anomalie di boot

Dopo un reboot l'SCM tira su i servizi ad avvio automatico in un ordine grossomodo stabile. Un nuovo servizio ad avvio automatico che appare nella sequenza 7036 di boot, specialmente uno non presente nel boot precedente, è un nuovo punto di persistenza. Incrocia col 7045 corrispondente sullo o prima dello shutdown precedente.

## Sigma: servizio di sicurezza fermato

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL: sequenza 7045 a 7036

Il pivot da titolone. Installazione di persistenza seguita da esecuzione entro 5 minuti sullo stesso host:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

`DisplayName` di 7036 non sarà sempre letteralmente uguale a `ServiceName` di 7045 (uno è display, l'altro è short). Matcha euristicamente o pre-calcola una mappa per il piccolo set di servizi che contano.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapping ATT&CK

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` per servizi di sicurezza.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` abbinato a 7045 per lo stesso servizio.
- T1569.002 System Services: Service Execution. 7036 `running` per un `ImagePath` che punta a un binario non standard, spesso parte di movimento laterale (PsExec, esecuzione remota basata su SCM, Impacket `psexec.py`).
- T1489 Service Stop. Mirato alla disponibilità (ransomware che ferma SQL Server prima di cifrare database).

## Falsi positivi che sembrano esattamente attacchi

- Windows Update riavvia una dozzina di servizi in una sequenza prevedibile. Ricorrente e rapida.
- Gli aggiornamenti delle firme di Defender a volte riavviano `WinDefend` stesso. Uno `stopped` rapidamente seguito da `running` da `MsSecFlt.exe` è il pattern normale. Quello malevolo è *no* `running` dopo lo `stopped`.
- Gli upgrade dell'EDR fermano e riavviano il servizio EDR. Tagga le finestre di upgrade del vendor.
- Sleep e ibernazione del sistema generano lotti di `stopped` allo sleep e `running` al risveglio. Non allertare su questi isolatamente.
- I carichi container e Hyper-V su e giù i servizi continuamente.

## Cosa 7036 non ti dice

- Niente `AccountName`. Tira fuori quello dal 7045 corrispondente o dal database SCM.
- Niente PID. Non puoi mappare un 7036 direttamente a un record [4688](/it/blog/event-id-4688-process-creation) o [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) senza correlare per `ImagePath` e timestamp. La cache di [prefetch](https://www.prefetchparser.com) è la conferma secondaria quando 4688 era spento.
- Nessun iniziatore. Non vedi chi ha chiamato Stop-Service. Per quello ti serve 7035 (spesso disabilitato di default), [4688](/it/blog/event-id-4688-process-creation) per il `net stop` / `sc stop` / `taskkill` chiamante, o [4104](/it/blog/powershell-4104-scriptblock) per `Stop-Service`.
- Mapping del nome breve del servizio. Il nome visualizzato è in `param1`. Il nome breve è nel blob binario e va decodificato. La maggior parte dei parser lo fa automaticamente. Se interroghi `EventData` grezzo devi gestirlo tu.

## Dove si inserisce 7036 in una timeline

Esecuzione laterale più evasione difensiva:

1. [4624](/it/blog/understanding-event-id-4624). LogonType 3 da un host controllato dall'attaccante, AuthenticationPackage Kerberos.
2. [4688](/it/blog/event-id-4688-process-creation). `services.exe` che genera un figlio per operazioni SCM (o il `psexesvc.exe` di PsExec).
3. [7045](/it/blog/service-creation-event-id-7045). Servizio installato, `ImagePath` fuori dai path di installazione standard.
4. **7036 `running`**. L'installazione è davvero scattata. Conferma di esecuzione.
5. **7036 `stopped`** per `WinDefend` o EDR. Evasione difensiva prima che il payload giri.
6. [4688](/it/blog/event-id-4688-process-creation). Processo payload sotto l'account del servizio.
7. **7036 `stopped`** per il servizio installer. Pulizia.

7036 appare nei passi 4, 5 e 7. Tre stadi diversi della stessa intrusione. Da solo è difficile da usare. In contesto lega il record di persistenza (7045) all'esecuzione effettiva e alle azioni di evasione difensiva circostanti.

## Per approfondire

- [Documentazione Microsoft: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

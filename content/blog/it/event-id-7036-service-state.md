---
title: "Event ID 7036 spiegato: cambi di stato dei servizi per il triage DFIR"
description: "Il 7036 si attiva ogni volta che un servizio parte o si ferma. Abbinato al 7045 conferma se la persistenza ha davvero girato — e da solo rivela abusi di servizio, defense evasion e anomalie di boot."
date: "2026-05-24"
---

L'Event ID **7036** — «The {service} service entered the {state} state» — si attiva sul [canale `System`](/it/blog/what-is-an-evtx-file) ogni volta che il Service Control Manager (SCM) vede una transizione di servizio. Ogni start, stop, pause e resume di servizio ne produce uno. Da solo è ad alto volume e facile da liquidare; abbinato al [7045](/it/blog/service-creation-event-id-7045) (servizio installato) fa la differenza tra *una backdoor è stata installata* e *una backdoor è stata installata ed è girata*.

Per la risposta agli incidenti, questo è il record «ha eseguito?» più economico che il SO ti dà.

## Dove vive

Sempre il **canale `System`** sull'host dove il servizio è girato. Nessun coinvolgimento del DC, nessun forwarding per canale di cui preoccuparsi — è lì in `System.evtx`. Il provider è `Service Control Manager`.

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

Tutto qui. Due parametri e un tag binario — molto più piccolo della maggior parte dei record Security, ed è per questo che gli analisti lo saltano.

- **`param1`** — il *display name* del servizio (non il nome breve). `Background Intelligent Transfer Service` qui è il nome user-facing di `BITS`. Per pivotare alla definizione del servizio spesso ti servirà il nome breve; l'SCM lo stampa anche in `Binary` come blob UTF-16 encoded (`42 00 49 00 54 00 53 00` qui decodifica a `BITS`).
- **`param2`** — il nuovo stato: `running`, `stopped`, `paused`, `resumed`, o uno di una manciata di intermedi pending (`start pending`, `stop pending`). Le transizioni `running` e `stopped` sono quelle su cui la maggior parte delle regole fa leva.

Non c'è `AccountName`, non c'è `ImagePath`, non c'è `ProcessId` — il 7036 ti dice *cosa* ha cambiato stato, non *chi* ha innescato il cambio. Per ottenere il perché, abbina ad altri record (vedi sotto).

## 7036 vs 7045 vs 7035 vs 7034

Quattro eventi del canale System legati ai servizi vengono confusi di continuo:

| Evento | Quando | Cosa ti dà |
|---|---|---|
| **7045** | Servizio installato | Display name, nome breve, `ImagePath`, `AccountName`, `StartType`. Il punto di persistenza. |
| **7036** | Start/stop del servizio | Solo display name. Il punto di esecuzione. |
| **7035** | Service control inviato | Chi ha iniziato lo start/stop (SID), quale control è stato inviato. Raramente attivo per default; di valore quando lo è. |
| **7034** | Servizio crashato inaspettatamente | Servizio che è terminato senza uno stop pulito. Azione di recovery. |

Il pattern conta: **un 7045 seguito secondi dopo da un 7036 `running` per lo stesso display name è la sequenza da manuale «installato e girato».** Un 7045 *senza* un 7036 corrispondente significa che il servizio è stato registrato ma mai eseguito — o l'attaccante ha fatto cleanup, o l'installer è abortito, o lo start è stato differito.

## I pattern di triage

### 1. Verifica della persistenza — abbina con il 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Tre record, un evento di lateral execution PsExec. La coppia 7036 ti dice che il servizio ha davvero girato (non solo che è stato installato). Per una backdoor *persistente*, il secondo 7036 (stopped) può mancare o apparire ore/giorni dopo al reboot dell'host.

Un 7045 senza 7036 `running` entro pochi minuti è una sua propria anomalia — investiga perché l'install non si è attivato. Cause comuni: l'installer è in staging per il reboot successivo, il servizio era impostato a manual start e l'attaccante non l'aveva ancora innescato, o lo start è fallito (cerca errori 7034 / 7000).

### 2. Segnale di defense-evasion — fermare i servizi di sicurezza

Il pattern più abusato: un attaccante ferma `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc`, o il servizio di un prodotto EDR. Ognuno genera un 7036 `stopped` per il display name corrispondente. Se viene tentato un tampering di audit-policy / Defender, questo è uno dei record che sopravvive.

I nomi su cui lanciare alert (display name; variano per versione di Defender / EDR):

- `Windows Defender Antivirus Service` → servizio `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- Qualsiasi cosa che matchi `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` per uno di questi — specialmente fuori da una finestra di manutenzione pianificata — dovrebbe essere un alert hard. Molti attaccanti usano `sc stop`, `net stop`, `Stop-Service` o `taskkill /im` — tutti e quattro producono un 7036.

### 3. Typosquatting del nome del servizio

Il 7036 si attiva per il display name anche quando il servizio sottostante è malizioso. Sorveglia i display name che sembrano legittimi ma non corrispondono effettivamente a nessun servizio Microsoft installato: `Windows Update Service` (il vero nome è `Windows Update`), `Windows Defender Service` (il vero nome è `Windows Defender Antivirus Service`), `Microsoft Telemetry` (non esiste). Fai una baseline dei display name da un host known-good e diff.

### 4. Anomalie di boot

Dopo un reboot l'SCM porta su i servizi auto-start in un ordine grosso modo stabile. Un nuovo servizio auto-start che appare nella sequenza 7036 di boot — specialmente uno che non c'era nel boot precedente — è un nuovo punto di persistenza. Cross-reference con il 7045 corrispondente al o prima dello shutdown precedente.

## Esempio di regola Sigma — servizio di sicurezza fermato

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

## Esempio KQL — sequenza 7045 → 7036

Il pivot di punta. Install di persistenza seguito da esecuzione entro 5 minuti sullo stesso host:

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

Il `DisplayName` dal 7036 non sarà sempre letteralmente uguale a `ServiceName` dal 7045 (uno è display, l'altro è breve) — matcha in modo euristico o precalcola una mappa per il piccolo set di servizi che contano.

## Esempio Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mappatura ATT&CK

- **T1562.001 — Impair Defenses: Disable or Modify Tools**: 7036 `stopped` per servizi di sicurezza.
- **T1543.003 — Create or Modify System Process: Windows Service**: 7036 `running` abbinato al 7045 per lo stesso servizio.
- **T1569.002 — System Services: Service Execution**: 7036 `running` per un `ImagePath` che punta a un binario non standard, spesso come parte di lateral movement (PsExec, esecuzione remota SCM-based).
- **T1489 — Service Stop**: mirato alla disponibilità — fermare servizi per abilitare altre azioni (ransomware che ferma SQL Server prima di cifrare i database).

## Falsi positivi che sembrano esattamente attacchi

- **Windows Update di routine** riavvia una dozzina di servizi in una sequenza prevedibile. Il pattern è ricorrente e veloce.
- **Aggiornamenti firma Defender** a volte riavviano `WinDefend` stesso — uno `stopped` rapidamente seguito da `running` da `MsSecFlt.exe` è il pattern normale. Quello malizioso è *nessun* `running` dopo lo `stopped`.
- **Upgrade EDR** fermano e riavviano il servizio EDR. Tagga le finestre di upgrade del vendor.
- **System sleep / hibernate** generano batch di record `stopped` allo sleep e `running` al wake. Combinati con eventi `wake source` sono ovvi; non lanciare alert su questi in isolamento.
- **Workload container / Hyper-V** portano su e giù servizi costantemente.

## Cosa il 7036 non ti dice

- **Nessun `AccountName`**: il record non dice sotto quale contesto di sicurezza gira il servizio. Estrailo dal 7045 corrispondente o dal database SCM.
- **Nessun PID**: non puoi mappare un 7036 direttamente a un record [4688](/it/blog/event-id-4688-process-creation) / [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) senza correlare per `ImagePath` e timestamp.
- **Nessun initiator**: non vedi *chi* ha chiamato Stop-Service. Per quello serve il 7035 (spesso disabilitato per default), il [4688](/it/blog/event-id-4688-process-creation) per il `net stop` / `sc stop` / `taskkill` chiamante, o il [4104](/it/blog/powershell-4104-scriptblock) per `Stop-Service`.
- **Mapping nome breve del servizio**: il display name è in `param1`; il nome breve è nel blob binario e va decodificato. La maggior parte dei parser lo fa automaticamente; se interroghi `EventData` grezzo devi gestirlo.

## Dove il 7036 si colloca in una timeline

La combo lateral-execution + defense-evasion:

1. [**4624**](/it/blog/understanding-event-id-4624) — LogonType 3 da un host controllato dall'attaccante, AuthenticationPackage Kerberos.
2. [**4688**](/it/blog/event-id-4688-process-creation) — `services.exe` che spawna un figlio per operazioni SCM (o il `psexesvc.exe` di PsExec).
3. [**7045**](/it/blog/service-creation-event-id-7045) — servizio installato, `ImagePath` fuori dai path di install standard.
4. **7036** `running` — l'install si è davvero attivato. **Questa è la tua conferma di esecuzione.**
5. **7036** `stopped` per `WinDefend` / EDR — defense evasion prima che il payload giri.
6. [**4688**](/it/blog/event-id-4688-process-creation) — processo payload sotto il service account.
7. **7036** `stopped` per il servizio installer — cleanup.

Il 7036 appare nei passi 4, 5 e 7 — tre stadi diversi della stessa intrusione. Da solo è difficile da usare; in contesto lega il record di persistenza (7045) all'esecuzione effettiva e alle azioni di defense-evasion circostanti.

---
title: "Event ID 7045 spiegato: installazione di servizio come segnale di persistenza"
description: "La creazione di servizi è una delle tecniche di persistenza più rumorose. L'evento 7045 cattura ogni installazione. Leggete questi tre campi e ne prendete la maggior parte."
date: "2026-05-17"
---

L'event ID **7045**, "Un servizio è stato installato nel sistema", scatta sul [canale `System`](/en/blog/what-is-an-evtx-file) ogni volta che il Service Control Manager registra un nuovo servizio. È rumoroso su una build stock (installazioni di driver, Windows update) ma in un ambiente aziendale a regime stazionario diventa abbastanza silenzioso che le anomalie si notano. È anche una delle tecniche di persistenza più citate di MITRE ATT&CK: T1543.003. Vale la pena conoscerla a memoria.

## Cosa c'è nel record

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinque campi. Tre contano per l'IR.

## I tre campi da leggere per primi

**`ImagePath`** è il singolo campo più utile. I servizi legittimi vivono sotto `C:\Windows\System32\`, `C:\Program Files\` o `C:\Program Files (x86)\`. Qualsiasi servizio il cui binario sta in `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\`, o una directory con nome casuale merita uno sguardo più ravvicinato. `ImagePath` può anche essere `cmd.exe /c ...` o `powershell.exe -e ...`. Quelli sono quasi sempre malevoli. I servizi legittimi non escono in shell.

**`AccountName`** di solito è `LocalSystem`. Un servizio installato sotto un utente di dominio, o un account servizio specifico che non corrisponde al pattern dell'organizzazione, è inusuale.

**`StartType`** di `auto start` significa che il servizio gira a ogni boot. `demand start` significa manuale. La persistenza vuole quasi sempre `auto start`. Esecuzione laterale one-shot può usare `demand start` e ripulire dopo. Questo rende il 7045 l'unico artefatto rimasto.

## Il pattern di esecuzione laterale

Quando un attaccante esegue PsExec o qualsiasi tool che usa l'SCM per eseguire remotamente su un altro host, ottenete un 7045 sull'host *target* con un `ImagePath` come `%SystemRoot%\PSEXESVC.exe` (default) o un equivalente rinominato. Il servizio appare, gira, e spesso viene cancellato in secondi. Il 7045 è l'impronta sopravvissuta molto dopo che il servizio stesso è andato.

Un 7045 con `ImagePath` che finisce in `.exe` seguito secondi dopo da un [4624 LogonType **3**](/en/blog/understanding-event-id-4624) da un host sorgente specifico è la firma da manuale di PsExec. Le varianti come Impacket `psexec.py`, `smbexec.py`, `wmiexec.py` producono valori di `ImagePath` leggermente diversi ma lo stesso pattern complessivo. La variante Impacket rinominata di solito è il delatore: un nome di servizio come `wfDsaQbA` (otto lettere casuali) non viene da un sysadmin.

## Cosa 7045 non vi dice

7045 scatta su *installazione*, non su ogni avvio successivo. Per vedere il servizio davvero girare avete bisogno di [7036](/en/blog/event-id-7036-service-state) ("servizio entrato nello stato running"). Per vedere il processo sottostante avete bisogno di [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) o [4688](/en/blog/event-id-4688-process-creation) con il path `Image` corrispondente.

Per servizi installati *prima* che inizi l'audit log (es. durante l'installazione OS), non c'è 7045. Esistono nel [registry](https://www.registryparser.com) sotto `HKLM\SYSTEM\CurrentControlSet\Services\` e devono essere enumerati lì, non dagli event log. L'hive [AmCache](https://www.amcacheparser.com) e la cache [prefetch](https://www.prefetchparser.com) spesso corroborano un'esecuzione che non ha prodotto un 4688.

## Workflow di triage

1. Filtrate il canale System per `EventID:7045`.
2. Ordinate o pivotate per `ImagePath`. Qualsiasi cosa fuori dai path di installazione standard è sospetta.
3. Per ogni sospetto, tirate il 4624 corrispondente per timestamp e host sorgente. Trovate la credenziale che l'ha installato.
4. Tirate Sysmon 1 con `Image` che matcha l'`ImagePath` per vedere esecuzioni reali.
5. Notate se una sequenza [7036](/en/blog/event-id-7036-service-state) / 7034 / 7035 mostra un run one-shot o un servizio persistente.

## Sigma: servizio installato da path non-standard

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory. Common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## KQL: impronta di esecuzione laterale PsExec

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

Un 4624 LogonType-3 entro 30 secondi da un 7045 sullo stesso host è la firma da manuale di PsExec.

## Splunk: installer di servizio anomalo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mapping ATT&CK

- T1543.003 Create or Modify System Process: Windows Service. Servizi long-running avviati sotto binari controllati dall'attaccante.
- T1569.002 System Services: Service Execution. Servizi a breve termine usati puramente come veicolo per esecuzione remota (PsExec, SMBExec, lateral movement basato su SCM).
- T1078 Valid Accounts. Quando il principal che installa è un admin di dominio le cui credenziali sono state rubate.
- T1036.005 Masquerading: Match Legitimate Name or Location. Servizi con nomi di display che imitano veri servizi Microsoft ma binari altrove.

## Falsi positivi che sembrano esattamente attacchi

- Gli installer software (Chocolatey, bootstrapper MSI) installano frequentemente servizi da una directory di staging prima di spostare il binario. Il 7045 scatta dal path di staging anche se l'installazione finale è pulita.
- Gli agenti EDR e AV installano servizi come parte del loro setup. L'`ImagePath` del vendor sarà stabile e firmato. Fate baseline.
- Alcuni Microsoft update installano servizi di servicing temporanei. Brevi, da `LocalSystem`.
- I workload container o Hyper-V a volte registrano servizi transitori per-VM.

Il segnale sono installazioni *one-off* a path scrivibili dall'utente da installer *non-admin o non-standard*. Un servizio installer firmato in `C:\Program Files\` non è l'attacco.

## Per approfondire

- [Documentazione Microsoft per 7045](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7045)
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

---
title: "Event ID 7045 spiegato: installazione di servizio come segnale di persistenza"
description: "La creazione di servizio è una delle tecniche di persistenza più rumorose. L'evento 7045 cattura ogni installazione — leggi questi tre campi e ne intercetterai la maggior parte."
date: "2026-05-17"
---

L'Event ID **7045** — «A service was installed in the system» — si attiva sul [canale `System`](/it/blog/what-is-an-evtx-file) ogni volta che il Service Control Manager registra un nuovo servizio. È rumoroso su una build stock (install di driver, update) ma negli ambienti corporate in steady-state è abbastanza tranquillo da far spiccare le anomalie. È anche una delle tecniche di persistenza più citate di MITRE ATT&CK: T1543.003.

## Cosa contiene il record

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinque campi, tre dei quali contano per l'IR.

## I tre campi da leggere per primi

**`ImagePath`** è il singolo campo più utile. I servizi legittimi vivono sotto `C:\Windows\System32\`, `C:\Program Files\` o `C:\Program Files (x86)\`. Qualsiasi servizio il cui binario stia in `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` o una directory dal nome random merita uno sguardo più attento. `ImagePath` può anche essere una riga `cmd.exe /c …` o `powershell.exe -e …` — quelli sono quasi sempre maliziosi; i servizi legittimi non spawnano shell.

**`AccountName`** è di solito `LocalSystem`. Un servizio installato sotto un utente di dominio o uno specifico service account che non matcha il pattern dell'organizzazione è inusuale.

**`StartType`** di `auto start` significa che il servizio gira a ogni boot. `demand start` significa manuale. La persistenza quasi sempre vuole `auto start`; l'esecuzione laterale one-shot può usare `demand start` e fare cleanup di se stessa — rendendo il 7045 l'unico artefatto rimasto.

## Il pattern di lateral execution

Quando un attaccante esegue `PsExec` o qualsiasi tool che usa l'SCM per remote-execute su un altro host, ottieni un 7045 sull'host *target* con un `ImagePath` come `%SystemRoot%\PSEXESVC.exe` (default) o un equivalente rinominato. Il servizio appare, gira, e spesso viene cancellato in pochi secondi. Il 7045 è il fingerprint sopravvissuto a lungo dopo che il servizio stesso è scomparso.

Un 7045 con `ImagePath` che finisce in `.exe` seguito secondi dopo da un [4624 LogonType **3**](/it/blog/understanding-event-id-4624) da uno specifico host sorgente è la firma da manuale di PsExec. Varianti come SMBExec, WMIExec e `psexec.py` di Impacket producono valori `ImagePath` leggermente diversi ma lo stesso pattern complessivo.

## Cosa il 7045 non ti dice

Il 7045 si attiva sull'*installazione*, non su ogni start successivo. Per vedere il servizio effettivamente in esecuzione serve il 7036 («service entered the running state»). Per vedere il processo sottostante ti serve [Sysmon evento 1](/it/blog/sysmon-event-id-1-process-create) o il [4688](/it/blog/event-id-4688-process-creation) con il path `Image` corrispondente.

Per servizi installati *prima* che inizi il log di audit (es. durante l'install del SO), non c'è 7045 — esistono nel registry sotto `HKLM\SYSTEM\CurrentControlSet\Services\` e vanno enumerati lì, non dai log eventi.

## Workflow di triage

1. Filtra il canale System per `EventID:7045`.
2. Ordina o pivota per `ImagePath` — qualsiasi cosa fuori dai path di install standard è sospetta.
3. Per ogni sospetto, estrai il 4624 corrispondente per timestamp + host sorgente — trova la credenziale che l'ha installato.
4. Estrai il Sysmon evento 1 per `Image` che matcha l'`ImagePath` per vedere le esecuzioni effettive.
5. Nota se una sequenza [**7036**](/it/blog/event-id-7036-service-state) / 7034 / 7035 mostra un run one-shot o un servizio persistente.

## Esempio di regola Sigma — servizio installato da path non standard

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
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

## Esempio KQL — fingerprint di lateral execution PsExec

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

## Esempio Splunk — installer di servizio anomalo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mappatura ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service**: la mappatura di punta. Servizi long-running avviati sotto binari controllati dall'attaccante.
- **T1569.002 — System Services: Service Execution**: servizi a vita breve usati puramente come veicolo per esecuzione remota (PsExec, SMBExec, lateral movement SCM-based).
- **T1078 — Valid Accounts**: quando il principal che installa è un domain admin le cui credenziali sono state rubate.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: servizi con display name che mimano servizi Microsoft reali ma con binari altrove.

## Falsi positivi che sembrano esattamente attacchi

- **Installer software** (Chocolatey, bootstrapper MSI) frequentemente installano servizi da una directory di staging prima di spostare il binario. Il 7045 si attiva dal path di staging anche se l'install finale è pulito.
- **Agenti EDR / AV** installano servizi come parte del loro setup. L'`ImagePath` del vendor sarà stabile e firmato; baseline.
- **Alcuni update Microsoft** installano servizi di servicing temporanei; sono a vita breve e da `LocalSystem`.
- **Workload container / Hyper-V** a volte registrano servizi transitori per-VM.

Il segnale è un'install *one-off* a path scrivibili dall'utente da installer *non-admin o non-standard*. Un servizio installer firmato in `C:\Program Files\` non è l'attacco.

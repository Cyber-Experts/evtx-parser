---
title: "Event ID 4688 spiegato: auditing della creazione di processi Windows per DFIR"
description: "Il 4688 è il process create del SO di base — se il command-line auditing è on. Cosa contiene, come differisce dal Sysmon 1 e i pattern di triage utili."
date: "2026-05-24"
---

L'Event ID **4688** — «A new process has been created» — si attiva sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che viene lanciato un processo. È quanto di più vicino al telemetry che fornisce [Sysmon evento 1](/it/blog/sysmon-event-id-1-process-create) il SO di base possa offrire — e sugli host dove Sysmon non è deployato, è l'unica fonte di `CommandLine` che ottieni. Su un'estate configurata correttamente, ogni process create è uno di questi record. Leggilo bene e puoi rispondere a «cosa è girato» senza mai aprire un EDR.

## Accenderlo (perché il default è semi-cieco)

Di default il 4688 è abilitato ma la `CommandLine` **non** viene catturata. Senza `CommandLine` il record ti dice un path di binario, un PID, un parent PID — e nulla sugli argomenti. Per il triage è quasi inutile: `powershell.exe` va bene; `powershell.exe -enc SQBFAFgA…` no.

La correzione è un'impostazione di Group Policy:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

O l'equivalente di registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Una volta impostato, ogni 4688 porta il campo `CommandLine` completo. Il costo è il volume di log; il beneficio è l'intera superficie d'indagine che vive sotto il nome del binario. Accendilo.

Serve anche l'audit policy sottostante: `auditpol /set /subcategory:"Process Creation" /success:enable`. Molti host hanno la policy attiva ma il command-line off — verifica entrambi.

## Cosa contiene il record

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

Campi che guidano ogni indagine:

- **`CommandLine`** — argv completo (quando la GPO è attiva).
- **`NewProcessName`** — il path del binario. Combinato con `CommandLine` è l'esecuzione completa.
- **`ParentProcessName`** — il processo chiamante. Office → cmd, browser → powershell, services → unsigned.exe sono le catene da manuale.
- **`SubjectUserName` / `SubjectLogonId`** — chi l'ha lanciato, sotto quale sessione. `SubjectLogonId` pivota indietro al [4624](/it/blog/understanding-event-id-4624) che ha creato la sessione e ad altri record nella stessa sessione.
- **`TokenElevationType`** — `%%1936` Default (nessuna elevation), `%%1937` Full (UAC consent concesso), `%%1938` Limited (filtrato). Un `1937` in una sessione non admin è una transizione di privilegio che merita uno sguardo più attento.
- **`MandatoryLabel`** — SID dell'integrity level. `S-1-16-12288` è High (elevated), `8192` è Medium, `16384` System.

## 4688 vs. Sysmon 1

Si sovrappongono; non sono identici.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sì (se GPO attiva) | Sì |
| Image / NewProcessName | Sì | Sì |
| Parent image | Sì (path) | Sì (path + CommandLine) |
| ParentCommandLine | No | Sì |
| ImageHash (SHA/MD5/IMPHASH) | No | Sì |
| ProcessGuid (cross-host stabile) | No (solo PID, riusati) | Sì |
| User SID + name | Sì | Sì |
| Logon ID | Sì | Sì |
| CurrentDirectory | No | Sì |
| Integrity level | Sì | Sì |
| Disponibile senza install | Sì | Richiede Sysmon |

Quando entrambi sono presenti, [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) è il record più ricco — `ParentCommandLine`, hash di immagine, ProcessGuid per catene parent-child stabili. Quando solo il 4688 è presente, costruisci le catene con i PID (che Windows riutilizza), quindi una timeline lunga può contenere match falsi; verifica sempre i link parent-child con i timestamp.

## I pattern di triage

In un corpus di record 4688, questi pattern si guadagnano il pane:

1. **Office → shell**: `ParentProcessName` che termina con `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` o `mshta.exe`, con `NewProcessName` che è `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` o `regsvr32.exe`. Document app che spawnano shell è la classica catena macro / phishing.
2. **PowerShell encoded**: `NewProcessName` che termina con `powershell.exe` e `CommandLine` che matcha `-enc`, `-encodedcommand`, `-e ` (lettera singola), `frombase64string`, `iex ` o `invoke-expression`. Decodifica il payload; cross-check il [record scriptblock 4104](/it/blog/powershell-4104-scriptblock) per la stessa sessione.
3. **LOLBin da path scrivibili dall'utente**: binari Microsoft firmati (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lanciati da `C:\Users\`, `%TEMP%` o `C:\ProgramData\`. L'uso legittimo di questi è raro in quelle posizioni.
4. **Orfani di service host**: `svchost.exe` con `ParentProcessName` ≠ `services.exe` (o `wininit.exe` per i boot molto precoci). Il vero `svchost` è sempre spawnato da `services.exe`; gli impostori spiccano.
5. **Binari rinominati**: `NewProcessName` che termina con qualcosa di neutro (`update.exe`, `svc.exe`, `data.exe`) sotto path non standard. Abbina con il campo `OriginalFileName` di Sysmon 1 quando disponibile — è quello che becca PsExec rinominato, Mimikatz, ecc.

## Esempio di regola Sigma (office → shell)

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## Esempio KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Mappatura ATT&CK

Il grosso della copertura di detection del 4688 ricade sotto **T1059 — Command and Scripting Interpreter** e le sue sub-techniques (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). I pattern LOLBin mappano a **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Le catene Office → shell corrispondono a **T1566.001 — Phishing: Spearphishing Attachment** combinata con T1059. Le detection di binari rinominati ricadono sotto **T1036.003 — Masquerading: Rename System Utilities**.

## Falsi positivi (leggi questo prima di lanciare alert)

- **Agenti di aggiornamento software** spawnano legittimamente shell: Chocolatey, WinGet, wrapper MSI di vendor. Whitelist per `SubjectUserSid` (LocalSystem) più pattern stabili di `ParentProcessName` invece che account utente.
- **Vulnerability scanner e prodotti EDR** generano alberi di processo che sembrano esattamente un attaccante che fa recon: net.exe, whoami.exe, systeminfo.exe. Tagga IP / host degli scanner ed escludi.
- **Box multi-sessione Citrix / RDS** vedono catene legittime di `runas /netonly` per accesso cross-domain. Investiga l'utente, non il pattern.
- **Logon script** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) si attivano a ogni logon e appariranno come catena ricorrente. Identifica e fai baseline prima di lanciare alert.

## Cosa il 4688 non ti dice

Nessun hash file. Nessuna `ParentCommandLine`. Nessun `ImageLoaded` (la DLL injection non è un process create). Nessun comportamento di rete. Per quelli ti servono [Sysmon evento 1](/it/blog/sysmon-event-id-1-process-create) (il 4688 più ricco), Sysmon 7 (image load), Sysmon 3/22 (network/DNS) e, dove presente, i dati comportamentali di un EDR. Il 4688 è il pavimento della visibilità sui processi — il minimo che ogni host Windows dovrebbe avere. Non è un sostituto per un EDR proprio + Sysmon sugli host che contano.

## Dove il 4688 si colloca in una timeline

Per una tipica catena post-exploitation su un host senza Sysmon, la tua timeline reciterà:

1. [**4624**](/it/blog/understanding-event-id-4624) — logon iniziale, LogonType 3 da un IP esterno.
2. **4624** — secondo logon, LogonType 9 (`runas /netonly`) sotto lo stesso `SubjectLogonId` — pivot di credenziali.
3. **4688** — `powershell.exe -enc ...` sotto quella sessione.
4. [**4104**](/it/blog/powershell-4104-scriptblock) — corpo dello script decodificato, che recupera un payload di secondo stadio.
5. **4688** — binario di secondo stadio in esecuzione da `%TEMP%`.
6. [**7045**](/it/blog/service-creation-event-id-7045) — servizio installato per persistenza.

Sei record raccontano l'intera storia. I PID in (3) e (5) si collegano via `ProcessId`/`NewProcessId` del 4688 — ma verifica per timestamp perché Windows ricicla i PID. Con Sysmon presente, la catena `ProcessGuid` sostituisce quel match fragile.

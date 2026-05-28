---
title: "Event ID 4688 spiegato: auditing di creazione processi Windows per il DFIR"
description: "4688 è il record di creazione processi dell'OS base, a patto che l'auditing della command-line sia acceso. Ecco cosa c'è dentro, in cosa differisce da Sysmon 1 e i pattern di triage che si guadagnano lo stipendio."
date: "2026-05-24"
---

L'Event ID **4688**, „È stato creato un nuovo processo", scatta sul [canale `Security`](/it/blog/what-is-an-evtx-file) ogni volta che un processo viene lanciato. È quanto di più vicino l'OS base arriva alla telemetria che [Sysmon event 1](/it/blog/sysmon-event-id-1-process-create) fornisce, e sugli host dove Sysmon non è dispiegato è l'unica fonte di `CommandLine` che hai. Su un parco configurato a dovere, ogni creazione di processo è uno di questi. Leggilo bene e puoi rispondere a „cosa è girato" senza mai aprire un EDR.

## Accenderlo, perché il default è mezzo cieco

Per default, 4688 è abilitato e `CommandLine` **non** viene catturata. Senza le command-line il record ti dice un path di binario, un PID, un parent PID e nulla sugli argomenti. Per il triage è quasi inutile. `powershell.exe` va bene. `powershell.exe -enc SQBFAFgA...` no.

La correzione è un'impostazione di Group Policy:

*Configurazione computer / Modelli amministrativi / Sistema / Controlla la creazione del processo / Includi la riga di comando negli eventi di creazione del processo*

O l'equivalente nel registro: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Una volta impostato, ogni 4688 porta il campo `CommandLine` completo. Il costo è il volume di log. Il beneficio è l'intera superficie di indagine che esiste sotto al nome del binario. Accendilo.

Hai anche bisogno dell'audit policy sottostante accesa: `auditpol /set /subcategory:"Process Creation" /success:enable`. Molti host hanno la policy accesa e la command-line spenta. Verifica entrambe.

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

I campi che guidano ogni indagine:

- `CommandLine`. argv completa (quando la GPO è accesa).
- `NewProcessName`. Il path del binario. Combinato con `CommandLine` questa è l'esecuzione completa.
- `ParentProcessName`. Il processo chiamante. Office a cmd, browser a powershell, services a unsigned.exe sono le catene da manuale.
- `SubjectUserName` e `SubjectLogonId`. Chi l'ha lanciato, sotto quale sessione. `SubjectLogonId` pivota indietro al [4624](/it/blog/understanding-event-id-4624) che ha creato la sessione.
- `TokenElevationType`. `%%1936` Default (nessuna elevation), `%%1937` Full (consenso UAC), `%%1938` Limited (filtrato). Un `1937` in una sessione non-admin è una transizione di privilegio che merita uno sguardo più attento.
- `MandatoryLabel`. SID del livello di integrità. `S-1-16-12288` è High (elevato), `8192` Medium, `16384` System.

## 4688 contro Sysmon 1

Si sovrappongono. Non sono la stessa cosa.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sì (se GPO accesa) | Sì |
| Image / NewProcessName | Sì | Sì |
| Image parent | Sì (path) | Sì (path + CommandLine) |
| ParentCommandLine | No | Sì |
| Hash dell'immagine (SHA/MD5/IMPHASH) | No | Sì |
| ProcessGuid (stabile cross-host) | No (i PID si riusano) | Sì |
| SID utente + nome | Sì | Sì |
| LogonId | Sì | Sì |
| CurrentDirectory | No | Sì |
| Livello di integrità | Sì | Sì |
| Disponibile senza installazione | Sì | Richiede Sysmon |

Quando entrambi sono presenti, [Sysmon 1](/it/blog/sysmon-event-id-1-process-create) è il record più ricco. `ParentCommandLine`, hash dell'immagine, `ProcessGuid` per catene parent-child stabili. Quando solo 4688 è presente, costruisci le catene con i PID, che Windows riusa, quindi una lunga timeline può contenere match falsi. Verifica sempre i link parent-child contro i timestamp. Quando non hai nessuno dei due (no Sysmon, no auditing della command-line), [AmCache](https://www.amcacheparser.com), [prefetch](https://www.prefetchparser.com) e il [journal USN](https://www.usnparser.com) sono la migliore prova di esecuzione successiva.

## I pattern che si guadagnano lo stipendio

1. **Office a shell**. `ParentProcessName` che termina in `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` o `mshta.exe`, con `NewProcessName` che è `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` o `regsvr32.exe`. App per documenti che generano shell è la catena classica macro/phishing.
2. **PowerShell codificato**. `NewProcessName` che termina in `powershell.exe` e `CommandLine` che combacia con `-enc`, `-encodedcommand`, `-e ` (lettera singola), `frombase64string`, `iex ` o `invoke-expression`. Decodifica il payload. Incrocia con il [record 4104 scriptblock](/it/blog/powershell-4104-scriptblock) per la stessa sessione.
3. **LOLBin da path scrivibili dall'utente**. Binari Microsoft firmati (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) che si lanciano da `C:\Users\`, `%TEMP%` o `C:\ProgramData\`. L'uso legittimo in quelle location è raro.
4. **Orfani svchost**. `svchost.exe` con `ParentProcessName` diverso da `services.exe` (o `wininit.exe` per boot molto precoce). Il vero `svchost` è sempre generato da `services.exe`. Gli impostori spiccano.
5. **Binari rinominati**. `NewProcessName` che termina in qualcosa di neutro (`update.exe`, `svc.exe`, `data.exe`) sotto path non standard. Abbina al campo `OriginalFileName` di Sysmon 1 quando disponibile. Quel campo coglie binari PsExec, Mimikatz, Impacket rinominati che bypassano la detection semplice basata sul nome.

## Sigma: Office a shell

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
  - Office add-ins running approved scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## KQL e Splunk

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

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## Mapping ATT&CK

La maggior parte della copertura di 4688 cade sotto T1059 Command and Scripting Interpreter e le sue sotto-tecniche (.001 PowerShell, .003 Windows Command Shell, .005 Visual Basic, .007 JavaScript). I pattern LOLBin mappano a T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32). Le catene Office-a-shell mappano a T1566.001 Phishing: Spearphishing Attachment combinato con T1059. Le detection di binari rinominati mappano a T1036.003 Masquerading: Rename System Utilities.

## Falsi positivi, leggere prima di allertare

- Gli agenti di aggiornamento software generano legittimamente shell: Chocolatey, WinGet, wrapper MSI di vendor. Whitelist per `SubjectUserSid` (LocalSystem) più pattern stabili di `ParentProcessName` invece che per account utente.
- Gli scanner di vulnerabilità e i prodotti EDR generano alberi di processo che sembrano esattamente un attaccante che fa recon: `net.exe`, `whoami.exe`, `systeminfo.exe`. Tagga gli IP e gli host dello scanner.
- Le box Citrix e RDS multi-sessione vedono catene legittime `runas /netonly` per accesso cross-domain. Indaga l'utente, non il pattern.
- Gli script di logon (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) scattano a ogni logon e appaiono come una catena ricorrente. Fai baseline prima di allertare.

## Cosa 4688 non ti dice

Nessun hash di file. Nessun `ParentCommandLine`. Nessun `ImageLoaded` (l'iniezione di DLL non è una creazione di processo). Nessun comportamento di rete. Per quelli ti serve [Sysmon event 1](/it/blog/sysmon-event-id-1-process-create) (il 4688 più ricco), Sysmon 7 (image load), Sysmon 3/22 (rete/DNS) e la telemetria comportamentale di un EDR. 4688 è il pavimento della visibilità sui processi. Il minimo che ogni host Windows dovrebbe avere. Non un sostituto di un EDR adeguato più Sysmon sugli host che contano.

## Dove si inserisce 4688 in una timeline

Per una tipica catena post-exploitation su un host senza Sysmon:

1. [4624](/it/blog/understanding-event-id-4624). Logon iniziale, LogonType 3 da un IP esterno.
2. 4624 di nuovo. LogonType 9 (`runas /netonly`) sotto la stessa `SubjectLogonId`. Pivot di credenziale.
3. **4688**. `powershell.exe -enc ...` sotto quella sessione.
4. [4104](/it/blog/powershell-4104-scriptblock). Corpo dello script decodificato, che recupera un payload di seconda fase.
5. **4688**. Binario di seconda fase che gira da `%TEMP%`.
6. [7045](/it/blog/service-creation-event-id-7045). Servizio installato per la persistenza.

Sei record raccontano tutta la storia. I PID in (3) e (5) si collegano tramite `ProcessId` e `NewProcessId` di 4688, ma verifica per timestamp perché Windows ricicla i PID. Con Sysmon presente, la catena `ProcessGuid` sostituisce quel match fragile.

## Per approfondire

- [Documentazione Microsoft per 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

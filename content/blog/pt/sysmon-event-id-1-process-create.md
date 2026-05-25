---
title: "Sysmon Event ID 1 explicado: criação de processo para triagem DFIR"
description: "O event 1 do Sysmon é o registro mais rico de criação de processo que o Windows consegue produzir. Eis o que ele contém e como triá-lo rápido."
date: "2026-05-17"
---

Sysmon é uma ferramenta gratuita da Microsoft que aumenta o [Windows Event Log](/pt/blog/what-is-an-evtx-file) com telemetria que o SO base não captura em forma utilizável. Seu event ID 1 — `ProcessCreate` — é o registro Sysmon mais citado em playbooks de IR. Se você só extrai um canal Sysmon de um host, este é o canal.

## Onde vive e o que captura

Sysmon escreve no canal `Microsoft-Windows-Sysmon/Operational` (em disco: `Microsoft-Windows-Sysmon%4Operational.evtx`). Um registro ProcessCreate contém:

```xml
<Data Name="UtcTime">2026-05-17 14:02:11.123</Data>
<Data Name="ProcessGuid">{...}</Data>
<Data Name="ProcessId">7842</Data>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="CommandLine">powershell -enc SQBFAFgA...</Data>
<Data Name="CurrentDirectory">C:\Users\alice\</Data>
<Data Name="User">CORP\alice</Data>
<Data Name="LogonId">0x3e7</Data>
<Data Name="Hashes">SHA256=...</Data>
<Data Name="ParentProcessGuid">{...}</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\winword.exe</Data>
<Data Name="ParentCommandLine">"winword.exe" /n /dde</Data>
```

Os campos que dirigem investigações: `CommandLine` (o argv completo, não só o binário), `Image` + `Hashes` (o binário exato que rodou, hash usável em VT/Hybrid Analysis) e o conjunto `Parent*` (o processo chamador — crítico para encontrar cadeias de macro e LOLBin).

## Triagem em três pivots

Quando você tem um arquivo Sysmon de triagem, três queries cobrem a maioria dos casos:

1. **Pais suspeitos**: filtre por `ParentImage` terminando em `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe` ou um browser, com `Image` sendo um shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Um app de documento spawnando um shell é quase sempre malicioso.
2. **PowerShell encodado**: `Image` terminando em `powershell.exe` e `CommandLine` contendo `-enc`, `-encodedcommand` ou `FromBase64String`. Decodifique o payload, veja o que faz — e cruze com o registro [PowerShell 4104 scriptblock](/pt/blog/powershell-4104-scriptblock) no mesmo host para ver o que de fato executou.
3. **LOLBins de locais estranhos**: binários Microsoft assinados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) rodando de `C:\Users\`, `%TEMP%` ou `C:\ProgramData\`.

## Por que a cadeia pai importa

Um único ProcessCreate é um snapshot; a cadeia é a história. `ProcessGuid` e `ParentProcessGuid` são GUIDs que o Sysmon atribui para rastrear linhagem entre exits de processo — são mais confiáveis que PIDs porque PIDs são reutilizados. Reconstrua a árvore (cada `ParentProcessGuid` de registro é o `ProcessGuid` de algum outro registro) e a kill-chain fica óbvia: Outlook → Word → PowerShell → cmd → certutil → mshta.

## Exemplo de regra Sigma — app Office spawnando shell

```yaml
title: Office Application Spawning Shell or Scripting Host (Sysmon)
id: 7a4c1f2b-6e3d-4a5f-9c2a-1b3d4e5f6a7c
status: stable
description: A Microsoft Office or document-rendering process spawned cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
      - '\acrord32.exe'
    Image|endswith:
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
  - Document automation pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
```

## Exemplo de KQL — PowerShell encodado com contexto pai

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` é o equivalente do Defender XDR para o `ParentCommandLine` do Sysmon 1 — que o [4688](/pt/blog/event-id-4688-process-creation) não fornece.

## Exemplo de Splunk — LOLBins de caminhos graváveis por usuário

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## Mapeamento ATT&CK

- **T1059 — Command and Scripting Interpreter** e sub-técnicas `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- **T1566.001 — Phishing: Spearphishing Attachment**: cadeias Office → shell.
- **T1218 — System Binary Proxy Execution** e sub-técnicas `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- **T1036.003 — Masquerading: Rename System Utilities**: `OriginalFileName` ≠ filename de `Image`.
- **T1055 — Process Injection**: `IntegrityLevel` do Sysmon 1 e a cadeia pai ajudam a detectar pais anômalos para processos como `lsass.exe` ou `services.exe`.

## Falsos positivos que parecem ataques

- **Agentes de software-update** rotineiramente spawnam shells sob SYSTEM (Chocolatey, WinGet, MSI de vendor). Marque hosts conhecidos de auto-update.
- **Scanners de vulnerabilidade** imitam árvores de processo ofensivas durante scans autenticados. Marque IPs de scanner.
- **Citrix / RDS** hosts multi-sessão geram tráfego denso de process-create que se sobrepõe a padrões de atacante. Filtre por range de origem.
- **Scans do Defender / EDR** rodam binários Microsoft assinados de caminhos incomuns durante scans on-demand.

## Caveats de cobertura

Sysmon só captura o que sua config diz para capturar. A config padrão não registra nada; as referências canônicas são o `sysmon-config` do SwiftOnSecurity e o `sysmon-modular` do Olaf Hartong. Sem uma config real no lugar, seus registros de event 1 serão esparsos, o campo `CommandLine` pode estar redacted e `Hashes` pode estar ausente. Leia a config Sysmon do host junto com seus logs.

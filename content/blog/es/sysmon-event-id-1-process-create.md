---
title: "Sysmon Event ID 1 explicado: creación de procesos para triage DFIR"
description: "El evento 1 de Sysmon es el registro de creación de procesos más rico que Windows puede producir. Aquí está qué contiene y cómo triagearlo rápido."
date: "2026-05-17"
---

Sysmon es una herramienta gratuita de Microsoft que aumenta el [Windows Event Log](/es/blog/what-is-an-evtx-file) con telemetría que el SO base no captura en forma utilizable. Su Event ID 1 — `ProcessCreate` — es el registro de Sysmon más citado en playbooks de IR. Si alguna vez extraes solo un canal Sysmon de un host, este es el que.

## Dónde vive y qué captura

Sysmon escribe al canal `Microsoft-Windows-Sysmon/Operational` (en disco: `Microsoft-Windows-Sysmon%4Operational.evtx`). Un registro ProcessCreate contiene:

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

Los campos que conducen las investigaciones: `CommandLine` (el argv completo, no solo el binario), `Image` + `Hashes` (el binario exacto que corrió, hash usable en VT/Hybrid Analysis), y el conjunto `Parent*` (el proceso llamante — crítico para encontrar cadenas de macro y LOLBin).

## Triage en tres pivots

Cuando tienes un archivo Sysmon de triage, tres consultas cubren la mayoría de casos:

1. **Padres sospechosos**: filtra por `ParentImage` terminando en `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, o un browser, con `Image` siendo una shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Una app de documentos spawneando una shell es casi siempre malicioso.
2. **PowerShell codificado**: `Image` terminando en `powershell.exe` y `CommandLine` conteniendo `-enc`, `-encodedcommand`, o `FromBase64String`. Decodifica el payload, verifica qué hace — y cruza-verifica el registro [scriptblock 4104 de PowerShell](/es/blog/powershell-4104-scriptblock) en el mismo host para ver qué se ejecutó realmente.
3. **LOLBins desde ubicaciones extrañas**: binarios Microsoft firmados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) corriendo desde `C:\Users\`, `%TEMP%`, o `C:\ProgramData\`.

## Por qué la cadena de padre importa

Un solo ProcessCreate es un snapshot; la cadena es la historia. `ProcessGuid` y `ParentProcessGuid` son GUIDs que Sysmon asigna para rastrear linaje a través de exits de procesos — son más confiables que los PIDs porque los PIDs se reutilizan. Reconstruye el árbol (cada `ParentProcessGuid` del registro es algún `ProcessGuid` de otro registro) y la kill-chain se vuelve obvia: Outlook → Word → PowerShell → cmd → certutil → mshta.

## Regla Sigma de ejemplo — app Office spawneando shell

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

## KQL de ejemplo — PowerShell codificado con contexto de padre

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` es el equivalente en Defender XDR del `ParentCommandLine` de Sysmon 1 — que [4688](/es/blog/event-id-4688-process-creation) no provee.

## Splunk de ejemplo — LOLBins desde rutas escribibles por usuario

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## Mapeo ATT&CK

- **T1059 — Command and Scripting Interpreter** y sub-técnicas `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- **T1566.001 — Phishing: Spearphishing Attachment**: cadenas Office → shell.
- **T1218 — System Binary Proxy Execution** y sub-técnicas `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- **T1036.003 — Masquerading: Rename System Utilities**: `OriginalFileName` ≠ nombre de archivo de `Image`.
- **T1055 — Process Injection**: el `IntegrityLevel` de Sysmon 1 y la cadena de padre ayudan a detectar padres anómalos para procesos como `lsass.exe` o `services.exe`.

## Falsos positivos que parecen ataques

- **Agentes de actualización de software** rutinariamente spawnean shells bajo SYSTEM (Chocolatey, WinGet, MSI de vendor). Etiqueta hosts conocidos de auto-update.
- **Escáneres de vulnerabilidades** imitan árboles de proceso ofensivos durante escaneos autenticados. Etiqueta IPs de escáner.
- **Hosts multi-sesión Citrix / RDS** generan tráfico denso de creación de procesos que se solapa con patrones de atacantes. Filtra por rango de origen.
- **Escaneos de Defender / EDR** corren binarios Microsoft firmados desde rutas inusuales durante escaneos on-demand.

## Advertencias de cobertura

Sysmon solo captura lo que su config le dice. La config por defecto no registra nada; las referencias canónicas son `sysmon-config` de SwiftOnSecurity y `sysmon-modular` de Olaf Hartong. Sin una config real en su sitio, tus registros event 1 serán escasos, el campo `CommandLine` puede estar redactado, y `Hashes` puede faltar. Lee la config Sysmon del host junto a sus logs.

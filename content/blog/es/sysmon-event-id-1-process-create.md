---
title: "Sysmon Event ID 1 explicado: creación de procesos para triaje DFIR"
description: "El evento 1 de Sysmon es el registro de creación de proceso más rico que Windows puede producir. Aquí está lo que contiene y cómo triarlo rápido."
date: "2026-05-17"
---

Sysmon es una herramienta gratuita de Microsoft que aumenta el [Windows Event Log](/en/blog/what-is-an-evtx-file) con telemetría que el SO base no captura en forma usable. Su event ID 1, `ProcessCreate`, es el registro Sysmon más citado en los playbooks IR. Si solo extraes un canal Sysmon de un host, este es el que.

Diré lo que digo en cada writeup de Sysmon: un despliegue sin una config real es principalmente teatro. Lee [sysmon-modular](https://github.com/olafhartong/sysmon-modular) o el `sysmon-config` de SwiftOnSecurity antes de decidir qué contienen realmente tus registros de event 1.

## Dónde vive y qué captura

Sysmon escribe a `Microsoft-Windows-Sysmon/Operational` (en disco: `Microsoft-Windows-Sysmon%4Operational.evtx`). Un registro ProcessCreate contiene:

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

Los campos que conducen investigaciones:

- `CommandLine`. El argv completo, no solo el binario.
- `Image` y `Hashes`. El binario exacto que corrió, hash usable en VirusTotal o Hybrid Analysis.
- El conjunto `Parent*`. El proceso que llama. Crítico para encontrar cadenas de macro y LOLBin. `ParentCommandLine` en particular es lo que [4688](/en/blog/event-id-4688-process-creation) no puede darte.

## Triaje en tres pivotes

Tres consultas cubren la mayoría de los casos:

1. **Padres sospechosos.** Filtra por `ParentImage` terminando en `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe` o un navegador, con `Image` siendo una shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). Una app de documento generando una shell es casi siempre maliciosa.
2. **PowerShell codificado.** `Image` terminando en `powershell.exe` y `CommandLine` conteniendo `-enc`, `-encodedcommand`, o `FromBase64String`. Descodifica el payload, verifica qué hace. Cross-check el [scriptblock PowerShell 4104](/en/blog/powershell-4104-scriptblock) en el mismo host para ver qué se ejecutó realmente.
3. **LOLBins desde ubicaciones extrañas.** Binarios Microsoft firmados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) corriendo desde `C:\Users\`, `%TEMP%`, o `C:\ProgramData\`.

## Por qué importa la cadena padre

Un solo ProcessCreate es una instantánea. La cadena es la historia. `ProcessGuid` y `ParentProcessGuid` son GUIDs que Sysmon asigna para rastrear linaje a través de salidas de proceso. Son más confiables que los PIDs porque los PIDs se reutilizan. Reconstruye el árbol (el `ParentProcessGuid` de cada registro es el `ProcessGuid` de algún otro registro) y la kill chain se vuelve obvia: Outlook a Word a PowerShell a cmd a certutil a mshta. Leer el árbol en orden cronológico es usualmente cómo un writeup se escribe a sí mismo.

## Sigma: app Office generando shell

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

## KQL: PowerShell codificado con contexto padre

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` es el equivalente Defender XDR del `ParentCommandLine` de Sysmon 1, que [4688](/en/blog/event-id-4688-process-creation) no provee.

## Splunk: LOLBins desde rutas escribibles por usuario

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

- T1059 Command and Scripting Interpreter y sub-técnicas `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- T1566.001 Phishing: Spearphishing Attachment. Cadenas Office a shell.
- T1218 System Binary Proxy Execution y sub-técnicas `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- T1036.003 Masquerading: Rename System Utilities. `OriginalFileName` != nombre de archivo de `Image`.
- T1055 Process Injection. El `IntegrityLevel` y cadena padre de Sysmon 1 ayudan a detectar padres anómalos para procesos como `lsass.exe` o `services.exe`.

## Falsos positivos que parecen ataques

- Los agentes de actualización de software rutinariamente generan shells bajo SYSTEM (Chocolatey, WinGet, MSI del vendor). Etiqueta hosts de auto-update conocidos.
- Los escáneres de vulnerabilidad imitan árboles de procesos ofensivos durante escaneos autenticados. Etiqueta IPs de scanner.
- Hosts Citrix y RDS multi-sesión generan tráfico denso de creación de procesos que se solapa con patrones de atacante. Filtra por rango de origen.
- Escaneos de Defender o EDR ejecutan binarios Microsoft firmados desde rutas inusuales durante escaneos on-demand.

## Advertencias de cobertura

Sysmon solo captura lo que su config le dice. La config por defecto loguea casi nada. Las referencias canónicas son el `sysmon-config` de SwiftOnSecurity y `sysmon-modular` de Olaf Hartong. Sin una config real en su lugar, tus registros de event 1 serán escasos, `CommandLine` puede estar redactado por una regla `<CommandLine onmatch="exclude">`, y `Hashes` puede faltar. Lee la config de Sysmon del host junto con sus logs. La discrepancia entre lo que un analista piensa que Sysmon está logueando y lo que realmente loguea me ha costado horas más de una vez.

Cuando Sysmon no está instalado en absoluto, recurre a [4688](/en/blog/event-id-4688-process-creation) con auditoría de línea de comandos, luego [prefetch](https://www.prefetchparser.com), [AmCache](https://www.amcacheparser.com), y el [USN journal](https://www.usnparser.com) para evidencia de ejecución.

## Lecturas adicionales

- [Documentación Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

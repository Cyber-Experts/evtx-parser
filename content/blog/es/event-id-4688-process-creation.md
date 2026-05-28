---
title: "Event ID 4688 explicado: auditoría de creación de procesos en Windows para DFIR"
description: "4688 es el registro de creación de procesos del SO base, siempre que la auditoría de línea de comandos esté activa. Esto es lo que contiene, en qué se diferencia de Sysmon 1 y los patrones de triaje que se ganan su sitio."
date: "2026-05-24"
---

El Event ID **4688**, "Se ha creado un nuevo proceso", se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que se lanza un proceso. Es lo más cerca que el SO base llega a la telemetría que proporciona [Sysmon event 1](/es/blog/sysmon-event-id-1-process-create), y en hosts donde Sysmon no está desplegado es la única fuente de `CommandLine` que tienes. En un parque correctamente configurado, cada creación de proceso es uno de estos. Léelos bien y puedes responder "qué se ejecutó" sin abrir nunca un EDR.

## Encenderlo, porque el default está medio ciego

Por defecto, 4688 está habilitado y `CommandLine` **no** se captura. Sin las líneas de comando el registro te dice una ruta de binario, un PID, un parent PID y nada sobre los argumentos. Para triaje eso es casi inútil. `powershell.exe` está bien. `powershell.exe -enc SQBFAFgA...` no.

La solución es una configuración de Group Policy:

*Configuración del equipo / Plantillas administrativas / Sistema / Auditar la creación de procesos / Incluir línea de comandos en eventos de creación de procesos*

O el equivalente en registro: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Una vez establecido, cada 4688 lleva el campo `CommandLine` completo. El coste es volumen de log. El beneficio es toda la superficie de investigación que existe por debajo del nombre del binario. Actívalo.

También necesitas la política de auditoría subyacente activa: `auditpol /set /subcategory:"Process Creation" /success:enable`. Muchos hosts tienen la política activa y la línea de comandos apagada. Verifica ambos.

## Qué contiene el registro

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

Los campos que mueven toda investigación:

- `CommandLine`. argv completa (cuando la GPO está activa).
- `NewProcessName`. La ruta del binario. Combinado con `CommandLine` esta es la ejecución completa.
- `ParentProcessName`. El proceso llamante. Office a cmd, browser a powershell, services a unsigned.exe son las cadenas de manual.
- `SubjectUserName` y `SubjectLogonId`. Quién lo lanzó, bajo qué sesión. `SubjectLogonId` pivota de vuelta al [4624](/es/blog/understanding-event-id-4624) que creó la sesión.
- `TokenElevationType`. `%%1936` Default (sin elevación), `%%1937` Full (consentimiento UAC), `%%1938` Limited (filtrado). Un `1937` en una sesión no-admin es una transición de privilegio que merece una mirada más cercana.
- `MandatoryLabel`. SID de nivel de integridad. `S-1-16-12288` es High (elevado), `8192` Medium, `16384` System.

## 4688 frente a Sysmon 1

Se solapan. No son lo mismo.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sí (si GPO activa) | Sí |
| Image / NewProcessName | Sí | Sí |
| Parent image | Sí (ruta) | Sí (ruta + CommandLine) |
| ParentCommandLine | No | Sí |
| Image hashes (SHA/MD5/IMPHASH) | No | Sí |
| ProcessGuid (estable cross-host) | No (PIDs se reutilizan) | Sí |
| User SID + nombre | Sí | Sí |
| Logon ID | Sí | Sí |
| CurrentDirectory | No | Sí |
| Nivel de integridad | Sí | Sí |
| Disponible sin instalar | Sí | Requiere Sysmon |

Cuando ambos están presentes, [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) es el registro más rico. `ParentCommandLine`, hashes de imagen, `ProcessGuid` para cadenas parent-child estables. Cuando solo está 4688, construyes cadenas con PIDs, que Windows reutiliza, así que una timeline larga puede contener emparejamientos falsos. Cruza siempre los enlaces parent-child contra timestamps. Cuando no tienes ninguno (sin Sysmon, sin auditoría de línea de comandos), [AmCache](https://www.amcacheparser.com), [prefetch](https://www.prefetchparser.com) y el [diario USN](https://www.usnparser.com) son la siguiente mejor evidencia de ejecución.

## Los patrones que se ganan su sitio

1. **Office a shell**. `ParentProcessName` terminando en `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe` o `mshta.exe`, con `NewProcessName` siendo `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe` o `regsvr32.exe`. Apps de documentos engendrando shells es la cadena clásica macro/phishing.
2. **PowerShell codificado**. `NewProcessName` terminando en `powershell.exe` y `CommandLine` matcheando `-enc`, `-encodedcommand`, `-e ` (letra única), `frombase64string`, `iex ` o `invoke-expression`. Decodifica la payload. Cruza con el [registro 4104 scriptblock](/es/blog/powershell-4104-scriptblock) para la misma sesión.
3. **LOLBins desde rutas escribibles por el usuario**. Binarios Microsoft firmados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lanzándose desde `C:\Users\`, `%TEMP%` o `C:\ProgramData\`. El uso legítimo en esas ubicaciones es raro.
4. **Huérfanos de svchost**. `svchost.exe` con `ParentProcessName` distinto a `services.exe` (o `wininit.exe` para arranque muy temprano). El `svchost` real siempre lo engendra `services.exe`. Los impostores destacan.
5. **Binarios renombrados**. `NewProcessName` terminando en algo neutro (`update.exe`, `svc.exe`, `data.exe`) bajo rutas no estándar. Empareja con el campo `OriginalFileName` de Sysmon 1 cuando esté disponible. Ese campo caza binarios PsExec, Mimikatz, Impacket renombrados que esquivan la detección simple por nombre.

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

## KQL y Splunk

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

## Mapeo ATT&CK

La mayoría de la cobertura de 4688 cae bajo T1059 Command and Scripting Interpreter y sus sub-técnicas (.001 PowerShell, .003 Windows Command Shell, .005 Visual Basic, .007 JavaScript). Los patrones LOLBin mapean a T1218 System Binary Proxy Execution (.005 Mshta, .010 Regsvr32, .011 Rundll32). Las cadenas Office-a-shell mapean a T1566.001 Phishing: Spearphishing Attachment combinado con T1059. Las detecciones de binarios renombrados mapean a T1036.003 Masquerading: Rename System Utilities.

## Falsos positivos, leer antes de alertar

- Los agentes de actualización de software legítimamente engendran shells: Chocolatey, WinGet, wrappers MSI de vendor. Whitelist por `SubjectUserSid` (LocalSystem) más patrones estables de `ParentProcessName` en lugar de cuentas de usuario.
- Los escáneres de vulnerabilidades y productos EDR generan árboles de procesos que parecen exactamente un atacante haciendo recon: `net.exe`, `whoami.exe`, `systeminfo.exe`. Etiqueta IPs y hosts de escáner.
- Las cajas Citrix y RDS multi-sesión ven cadenas legítimas `runas /netonly` para acceso cross-domain. Investiga al usuario, no el patrón.
- Los scripts de logon (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) se disparan en cada logon y aparecen como una cadena recurrente. Baseline antes de alertar.

## Lo que 4688 no te dice

Sin hash de archivo. Sin `ParentCommandLine`. Sin `ImageLoaded` (la inyección de DLL no es una creación de proceso). Sin comportamiento de red. Para eso necesitas [Sysmon event 1](/es/blog/sysmon-event-id-1-process-create) (el 4688 más rico), Sysmon 7 (carga de imágenes), Sysmon 3/22 (red/DNS) y la telemetría conductual de un EDR. 4688 es el suelo de la visibilidad de proceso. El mínimo que todo host Windows debería tener. No un sustituto de un EDR adecuado más Sysmon en hosts que importan.

## Dónde encaja 4688 en una timeline

Para una cadena post-explotación típica en un host sin Sysmon:

1. [4624](/es/blog/understanding-event-id-4624). Logon inicial, LogonType 3 desde una IP externa.
2. 4624 otra vez. LogonType 9 (`runas /netonly`) bajo la misma `SubjectLogonId`. Pivote de credencial.
3. **4688**. `powershell.exe -enc ...` bajo esa sesión.
4. [4104](/es/blog/powershell-4104-scriptblock). Cuerpo de script decodificado, trayendo una payload de segunda etapa.
5. **4688**. Binario de segunda etapa ejecutándose desde `%TEMP%`.
6. [7045](/es/blog/service-creation-event-id-7045). Servicio instalado para persistencia.

Seis registros cuentan toda la historia. Los PIDs en (3) y (5) se conectan vía `ProcessId` y `NewProcessId` del 4688, pero verifica por timestamp porque Windows recicla PIDs. Con Sysmon presente, la cadena `ProcessGuid` reemplaza ese match frágil.

## Lectura adicional

- [Documentación Microsoft para 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [MITRE ATT&CK T1059](https://attack.mitre.org/techniques/T1059/)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

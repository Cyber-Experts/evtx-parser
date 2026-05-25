---
title: "Event ID 4688 explicado: auditoría de creación de procesos en Windows para DFIR"
description: "4688 es el registro de creación de procesos del SO base — con auditoría de línea de comandos activa. Qué contiene, cómo se diferencia de Sysmon 1 y los patrones de triage útiles."
date: "2026-05-24"
---

El Event ID **4688** — «Se creó un nuevo proceso» — se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que se lanza un proceso. Es lo más cerca que el SO base llega a la telemetría que provee [Sysmon event 1](/es/blog/sysmon-event-id-1-process-create) — y en hosts donde Sysmon no está desplegado, es la única fuente de `CommandLine` que obtienes. En un estate bien configurado, cada creación de proceso es uno de estos registros. Léelo bien y puedes contestar «qué se ejecutó» sin abrir nunca un EDR.

## Encenderlo (porque el default está medio-ciego)

Por defecto, 4688 está habilitado pero `CommandLine` **no** se captura. Sin `CommandLine` el registro te dice una ruta de binario, un PID, un PID padre — y nada sobre los argumentos. Para triage eso es casi inútil: `powershell.exe` está bien; `powershell.exe -enc SQBFAFgA…` no.

La solución es un ajuste de Group Policy:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

O el equivalente en el registro: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Una vez configurado, cada 4688 lleva el campo `CommandLine` completo. El costo es volumen de logs; el beneficio es toda la superficie de investigación que existe por debajo del nombre del binario. Actívalo.

También necesitas que la política de auditoría subyacente esté activa: `auditpol /set /subcategory:"Process Creation" /success:enable`. Muchos hosts tienen la política activa pero command-line apagado — verifica ambos.

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

Campos que conducen cada investigación:

- **`CommandLine`** — argv completo (cuando la GPO está activa).
- **`NewProcessName`** — la ruta del binario. Combinado con `CommandLine` es la ejecución completa.
- **`ParentProcessName`** — el proceso llamante. Office → cmd, browser → powershell, services → unsigned.exe son las cadenas de libro de texto.
- **`SubjectUserName` / `SubjectLogonId`** — quién lo lanzó, bajo qué sesión. `SubjectLogonId` pivota de vuelta al [4624](/es/blog/understanding-event-id-4624) que creó la sesión y a otros registros en la misma sesión.
- **`TokenElevationType`** — `%%1936` Default (sin elevación), `%%1937` Full (consentimiento UAC otorgado), `%%1938` Limited (filtrado). Un `1937` en una sesión no-admin es una transición de privilegio que merece una mirada más cercana.
- **`MandatoryLabel`** — SID de nivel de integridad. `S-1-16-12288` es High (elevado), `8192` es Medium, `16384` System.

## 4688 vs. Sysmon 1

Se solapan; no son idénticos.

| Campo | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Sí (si la GPO está activa) | Sí |
| Image / NewProcessName | Sí | Sí |
| Imagen padre | Sí (ruta) | Sí (ruta + CommandLine) |
| ParentCommandLine | No | Sí |
| ImageHash (SHA/MD5/IMPHASH) | No | Sí |
| ProcessGuid (estable entre hosts) | No (solo PIDs, reutilizados) | Sí |
| User SID + nombre | Sí | Sí |
| Logon ID | Sí | Sí |
| CurrentDirectory | No | Sí |
| Nivel de integridad | Sí | Sí |
| Disponible sin instalación | Sí | Requiere Sysmon |

Cuando ambos están presentes, [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) es el registro más rico — `ParentCommandLine`, hashes de imagen, ProcessGuid para cadenas padre-hijo estables. Cuando solo 4688 está presente, construyes cadenas con PIDs (que Windows reutiliza), así que una timeline larga puede incluir falsos matches; siempre cruza-verifica los enlaces padre-hijo contra timestamps.

## Los patrones de triage

En un corpus de registros 4688, estos patrones se ganan su sitio:

1. **Office → shell**: `ParentProcessName` terminando en `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe`, o `mshta.exe`, con `NewProcessName` siendo `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, o `regsvr32.exe`. Apps de documentos spawneando shells es la cadena clásica de macro / phishing.
2. **PowerShell codificado**: `NewProcessName` terminando en `powershell.exe` y `CommandLine` coincidiendo con `-enc`, `-encodedcommand`, `-e ` (una sola letra), `frombase64string`, `iex `, o `invoke-expression`. Decodifica el payload; cruza-verifica el [registro scriptblock 4104](/es/blog/powershell-4104-scriptblock) para la misma sesión.
3. **LOLBins desde rutas escribibles por el usuario**: binarios Microsoft firmados (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) lanzando desde `C:\Users\`, `%TEMP%`, o `C:\ProgramData\`. El uso legítimo de estos es raro en esas ubicaciones.
4. **Huérfanos de service host**: `svchost.exe` con `ParentProcessName` ≠ `services.exe` (o `wininit.exe` para arranque muy temprano). El `svchost` real siempre es spawneado por `services.exe`; los impostores destacan.
5. **Binarios renombrados**: `NewProcessName` terminando en algo neutral (`update.exe`, `svc.exe`, `data.exe`) bajo rutas no estándar. Empareja con el campo `OriginalFileName` de Sysmon 1 cuando esté disponible — ese es el que detecta PsExec, Mimikatz, etc. renombrados.

## Regla Sigma de ejemplo (office → shell)

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

## KQL / Splunk de ejemplo

KQL (Defender XDR / Sentinel vía `SecurityEvent`):

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

## Mapeo ATT&CK

El grueso de la cobertura de detección de 4688 cae bajo **T1059 — Command and Scripting Interpreter** y sus sub-técnicas (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). Los patrones LOLBin mapean a **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Las cadenas Office → shell corresponden a **T1566.001 — Phishing: Spearphishing Attachment** combinado con T1059. Las detecciones de binarios renombrados caen bajo **T1036.003 — Masquerading: Rename System Utilities**.

## Falsos positivos (lee esto antes de alertar)

- **Agentes de actualización de software** legítimamente spawnean shells: Chocolatey, WinGet, wrappers MSI de vendors. Whiteliste por `SubjectUserSid` (LocalSystem) más patrones estables de `ParentProcessName` en lugar de cuentas de usuario.
- **Escáneres de vulnerabilidades y productos EDR** generan árboles de procesos que parecen exactamente un atacante haciendo recon: net.exe, whoami.exe, systeminfo.exe. Etiqueta IPs / hosts de escáner y excluye.
- **Boxes multi-sesión Citrix / RDS** ven cadenas legítimas de `runas /netonly` para acceso cross-domain. Investiga al usuario, no al patrón.
- **Logon scripts** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) se disparan en cada logon y aparecerán como cadena recurrente. Identifica y baseline antes de alertar.

## Lo que 4688 no te dice

Sin hash de archivo. Sin `ParentCommandLine`. Sin `ImageLoaded` (la inyección de DLL no es una creación de proceso). Sin comportamiento de red. Para esos necesitas [Sysmon event 1](/es/blog/sysmon-event-id-1-process-create) (el 4688 más rico), Sysmon 7 (carga de imagen), Sysmon 3/22 (red/DNS), y donde esté presente, los datos comportamentales de un EDR. 4688 es el suelo de visibilidad de procesos — el mínimo que cada host Windows debería tener. No es un sustituto de EDR + Sysmon propios en hosts que importan.

## Dónde encaja 4688 en una timeline

Para una cadena típica de post-explotación en un host sin Sysmon, tu timeline leerá:

1. [**4624**](/es/blog/understanding-event-id-4624) — logon inicial, LogonType 3 desde una IP externa.
2. **4624** — segundo logon, LogonType 9 (`runas /netonly`) bajo el mismo `SubjectLogonId` — pivot de credencial.
3. **4688** — `powershell.exe -enc ...` bajo esa sesión.
4. [**4104**](/es/blog/powershell-4104-scriptblock) — cuerpo del script decodificado, fetcheando un payload de segunda etapa.
5. **4688** — binario de segunda etapa corriendo desde `%TEMP%`.
6. [**7045**](/es/blog/service-creation-event-id-7045) — servicio instalado para persistencia.

Seis registros cuentan toda la historia. Los PIDs en (3) y (5) conectan vía `ProcessId`/`NewProcessId` de 4688 — pero verifica por timestamp porque Windows recicla PIDs. Con Sysmon presente, la cadena `ProcessGuid` reemplaza ese match frágil.

---
title: "Event ID 4663 explicado: auditoría de acceso a archivos y registro con SACLs"
description: "4663 es el registro de auditoría de objetos por acceso. Configura SACLs en los archivos y claves adecuados y obtienes un log de quién tocó qué — útil para ransomware, exfil y robo de credenciales."
date: "2026-05-24"
---

El Event ID **4663** — «Se intentó acceder a un objeto» — se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que un archivo, clave de registro u objeto del kernel auditado es accedido de una forma que coincide con su System Access Control List (SACL). A diferencia de la mayoría de registros Security, 4663 no produce nada por sí solo — tienes que *configurar* la SACL en el objeto que te importa antes de que existan registros 4663. Eso lo hace barato por defecto y devastadoramente efectivo una vez afinado.

Si solo auditas una cosa con 4663, audita el acceso a almacenes de credenciales y datos compartidos de alto valor. La relación señal-ruido está entre las mejores de todo el catálogo de auditoría.

## Dónde se dispara

Siempre en el host que posee el objeto — el file server para una SACL de archivo, la workstation para una SACL de registro local, el DC para una SACL de objeto AD. No hay registro centralizado; si quieres visibilidad a escala del estate sobre un share sensible, necesitas reenviar `Security` desde el file server que lo aloja.

## Qué contiene el registro

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

Los campos:

- **`ObjectType`** — `File`, `Key` (registro), `Process`, `Token`, `Directory`, `Section`, o cualquier clase de objeto que soporte SACLs.
- **`ObjectName`** — la ruta completa. Para archivos es una ruta Windows; para claves de registro, la ruta completa bajo `\REGISTRY\MACHINE\…` (nota: no la notación `HKLM\…` que escribirías en regedit).
- **`AccessList`** — lo que se intentó, como lista de nombres de derechos de acceso decodificados (uno por token `%%NNNN`). Los valores decodificados comunes:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — la bitmask cruda de `STANDARD_RIGHTS_*` y derechos específicos del objeto realmente solicitados.
- **`ProcessName`** + **`ProcessId`** — el proceso que abrió el handle. El pivot a [4688](/es/blog/event-id-4688-process-creation) / [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) para el contexto completo del proceso.
- **`SubjectLogonId`** — pivot a [4624](/es/blog/understanding-event-id-4624) para la sesión originadora, la IP de origen si es un network logon, y el usuario.

## Configurar 4663 — la parte que realmente cuesta trabajo

Hay tres capas de configuración; si falta cualquiera, no hay registros.

1. **Política de auditoría**: habilitar *Object Access → Audit File System* y/o *Audit Registry* para éxito y/o fallo. Vía Group Policy o `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL en el objeto**: clic derecho → Properties → Security → Advanced → pestaña Auditing (GUI de Windows), o vía `Set-Acl` / `icacls /audit`. Especificas *qué principal* (frecuentemente `Everyone` o `Authenticated Users`), *qué derechos*, y *si auditar éxito, fallo o ambos*.
3. **Para el registro**: mismo flujo, accedido vía `regedit` → clave → Permissions → Advanced → Auditing.

Sin (1) los registros nunca se escriben. Sin (2) Windows no tiene idea de que querías auditar algo. Sin (3) solo estás auditando archivos.

Las SACLs a establecer en cada servidor:

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — almacenes de credenciales locales. Audita `Everyone : ReadData : Success`. Cualquier cosa leyéndolos que no sea `LocalSystem` es un intento de credential-dumping.
- **`%TEMP%\lsass.dmp`** y cualquier `*.dmp` en `C:\Windows\Temp` — minidumps de procesos. Audita `Everyone : WriteData : Success`. Un proceso escribiendo un `.dmp` aquí es o un crash dump (Windows) o un operador de Mimikatz (todos los demás).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** y **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — directorios de master keys DPAPI. Audita `ReadData : Success`. Cualquier persona leyéndolos desde fuera de la propia sesión del usuario está robando secretos protegidos.
- **`HKLM\SECURITY`** y **`HKLM\SAM`** — equivalentes de registro. Audita `ReadData : Success`.
- **Shares de archivos sensibles** — finanzas, legal, payroll. Audita `WriteData + DELETE : Success` para detectar barridos de cifrado de ransomware y eliminaciones masivas.

## Los patrones de triage

### 1. Lectura del SAM / hive SYSTEM

Cualquier 4663 con `ObjectName` terminando en `\config\SAM`, `\config\SECURITY`, o `\config\SYSTEM`, donde `ProcessName` no es `services.exe` / `lsass.exe` / `wininit.exe` y `SubjectUserSid` no es `S-1-5-18`. Esto es `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy`, o cualquier herramienta de credential-dumping con acceso a hives a nivel de archivo.

### 2. Archivo de dump de LSASS escrito

Un 4663 `WriteData` para un archivo `.dmp` en `C:\Windows\Temp\`, `C:\ProgramData\`, o `%TEMP%`, con `ProcessName` de `rundll32.exe`, `procdump*.exe`, callers relacionados con `comsvcs.dll`, o un binario renombrado. Este es el patrón de minidump de LSASS. Cruza-referencia con [4688](/es/blog/event-id-4688-process-creation) para el `CommandLine` — `comsvcs.dll MiniDump` es la codificación más común.

### 3. Barrido de cifrado de ransomware

Muchos 4663 con `AccessMask` incluyendo `WriteData + DELETE` contra archivos en un share sensible en cuestión de segundos, todos desde el mismo `SubjectLogonId` y `ProcessName`. Un proceso de backup real toca archivos en un patrón medible y throttled; el ransomware barre un árbol de directorios tan rápido como permite el disco.

### 4. Robo de master keys DPAPI

4663 `ReadData` en archivos bajo `\AppData\Roaming\Microsoft\Protect\<sid>\` por cualquier proceso distinto de la propia sesión del usuario. El patrón clásico es `SubjectUserSid` siendo un SID *diferente* del que aparece en la ruta.

### 5. Lectura de archivo de contraseñas de Group Policy preferences

4663 `ReadData` en archivos que coincidan con `\SYSVOL\<domain>\Policies\*\Groups.xml` (o `Services.xml`, `Drives.xml`). Este es el ataque `Get-GPPPassword` — viejo, pero los archivos SYSVOL a menudo todavía existen en dominios legacy.

## Regla Sigma de ejemplo — lectura del hive SAM

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## KQL de ejemplo — barrido de cifrado de ransomware

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

100 archivos distintos escritos-o-eliminados por minuto bajo una sesión de logon es un barrido, sin discusión.

## Splunk de ejemplo — acceso a master key DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapeo ATT&CK

- **T1003.002 — OS Credential Dumping: Security Account Manager**: lecturas del hive SAM.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: lecturas del hive SECURITY.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: escrituras `.dmp` (combinado con contexto de proceso).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**: acceso a `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**: lecturas de `Groups.xml` en SYSVOL.
- **T1486 — Data Encrypted for Impact**: patrones masivos de WriteData + DELETE (ransomware).
- **T1565.001 — Stored Data Manipulation**: escrituras arbitrarias en data shares monitorizados.

## Gestión de volumen — la trampa de las SACLs

Configurar ingenuamente `Everyone : All access : Success+Failure` en un directorio ocupado producirá cientos de miles de registros 4663 por minuto y enterrará tu colección. Las SACLs son instrumentos de precisión. Audita:

- **Solo los tipos de acceso que te importan** (`ReadData` para almacenes de credenciales; `WriteData + DELETE` para data shares; rara vez ambos).
- **Solo éxito** — los fallos son más raros y raramente interesantes.
- **Archivos específicos**, no unidades enteras. El archivo SAM, no todo `C:\Windows\System32\config\`. El share de HR, no todo `D:\`.
- **Principales específicos** cuando puedas — para objetos clase SAM `Everyone` está bien porque el acceso legítimo es por `LocalSystem` de todos modos; para datos compartidos, audita solo los principales que realmente tocan los datos.

Una SACL bien afinada sobre cinco objetos de alto valor produce 50-200 registros al día por host — totalmente manejable.

## Falsos positivos que parecen exactamente ataques

- **Volume Shadow Copy** (VSS) los backups generan tráfico denso de 4663 durante una ventana de backup. Etiqueta el `ProcessName` del orquestador de backup.
- **Escaneos on-access de antivirus** abren cada archivo en un directorio objetivo; las cuentas de servicio del producto AV dominarán cualquier regla 4663 ingenua. Whiteliste por SID.
- **Servicios de indexación** (Windows Search, estilo Spotlight) tocan metadatos vía `ReadAttributes` — normalmente filtrable por `AccessList`.
- **Restauraciones staged de backup** parecen escrituras de ransomware (muchos archivos, un proceso, en un directorio) pero el proceso es tu agente de backup.
- **Escaneo en tiempo real de Defender** lee todo; si auditas demasiado ampliamente, es la fuente dominante de ruido.

## Lo que 4663 no te dice

- **Contenido del acceso**: ves que un archivo fue leído/escrito, no qué fue leído/escrito. Para lo último necesitas un producto EDR o FIM (File Integrity Monitoring).
- **Por qué ocurrió el acceso**: solo el resultado del syscall. Para correlacionar con la intención del usuario, empareja con [4688](/es/blog/event-id-4688-process-creation) / [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) para el contexto completo del proceso que llama.
- **Handles cerrados**: 4663 se dispara al *abrir* el handle. Los eventos de cierre son 4658, rara vez útiles para detección de ataques.
- **Rutas de red transparentemente**: el acceso SMB a un share dispara 4663 en el *servidor*; el cliente no ve nada. Necesitas colección del lado del servidor.
- **Acceso fallido por defecto**: muchos shops solo auditan `Success`; configura `Failure` solo si realmente te importan los intentos de acceso frustrados.

## Dónde encaja 4663 en una timeline

Cadena clásica de credential dump de LSASS:

1. [**4624**](/es/blog/understanding-event-id-4624) — logon de admin (LogonType 3 o 10).
2. [**4672**](/es/blog/event-id-4672-special-privileges) — SeDebugPrivilege concedido con la sesión.
3. [**4688**](/es/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` a `C:\Windows\Temp\lsass.dmp` por `rundll32.exe`. **Oro forense — prueba de staging de exfil.**
5. [**4688**](/es/blog/event-id-4688-process-creation) — movimiento del archivo / archivado (el operador extrayendo el dump).
6. [**1102**](/es/blog/event-id-1102-cleared-log) — Security log borrado (algunos operadores hacen esto; muchos lo olvidan).

El 4663 del paso 4 es la señal más barata y específica de la cadena — identifica directamente el artefacto de robo de credenciales por nombre, en disco, con el proceso llamante adjunto. Las lecturas del hive SAM, acceso a master keys DPAPI y lecturas de Groups.xml en SYSVOL funcionan igual.

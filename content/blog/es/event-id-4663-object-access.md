---
title: "Event ID 4663 explicado: auditoría de acceso a archivos y registro con SACLs"
description: "4663 es el registro de auditoría de objeto por acceso. Configura SACLs en los archivos y claves correctos y obtienes un log por byte de quién tocó qué. Útil para ransomware, exfiltración y robo de credential stores."
date: "2026-05-24"
---

El Event ID **4663**, "Se intentó acceder a un objeto", se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que se toca un archivo, clave de registro u objeto del kernel auditado de una forma que coincida con su System Access Control List. A diferencia de la mayoría de registros de Security, 4663 no produce nada por defecto. Tienes que *configurar* la SACL sobre el objeto primero. Por eso la mayoría de entornos no lo tienen. También por eso, los que sí lo tienen tienen una ventaja de detección casi injusta sobre un pequeño conjunto de técnicas.

Si instrumentas 4663 sobre exactamente cinco cosas e ignoras el resto, atraparás staging de credential-dump, barridos de ransomware y robo de DPAPI más barato que cualquier EDR.

## Dónde se dispara

En el host que posee el objeto. Las SACLs de archivos se disparan en el file server. Las SACLs de registro local se disparan en la estación de trabajo. Las SACLs de objetos AD se disparan en el DC. No hay registro central. Para tener visibilidad a nivel de parque sobre un share sensible, necesitas reenviar Security del file server que lo aloja. Esto pilla a la gente continuamente.

## Los campos del registro

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

Los que importan:

- `ObjectType`. `File`, `Key` (registro), `Process`, `Token`, `Directory`, `Section`. Cualquier clase de objeto que soporte SACLs.
- `ObjectName`. Ruta completa. Para archivos, ruta Windows. Para claves de registro, la ruta completa bajo `\REGISTRY\MACHINE\...` (no el `HKLM\...` que escribirías en regedit).
- `AccessList`. Lo que se intentó, como tokens de derecho de acceso decodificados. Los comunes:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Bitmask en bruto de `STANDARD_RIGHTS_*` y derechos específicos del objeto realmente solicitados.
- `ProcessName` y `ProcessId`. El proceso que abrió el handle. Pivota a [4688](/es/blog/event-id-4688-process-creation) o a [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) para el contexto completo del proceso.
- `SubjectLogonId`. Pivota a [4624](/es/blog/understanding-event-id-4624) para la sesión originaria, la IP origen si es logon de red, y el usuario.

## Encender 4663 son tres pasos y la gente se salta uno

1. **Política de auditoría**. Habilita las sub-políticas *Object Access* para File System y/o Registry, success y/o failure. Group Policy o `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL en el objeto**. Propiedades, pestaña Seguridad, Avanzado, pestaña Auditoría en la GUI. O `Set-Acl`, `icacls /audit`. Especificas qué principal, qué derechos y si auditar success, failure o ambos.
3. **Para registro**, mismo flujo vía Permisos de la clave de regedit, Avanzado, Auditoría.

Sin (1) los registros nunca se escriben. Sin (2) Windows no tiene ni idea de que querías auditar nada. Sin (3) solo estás auditando archivos. La gente se salta más a menudo (2) porque el paso (1) parece que debería bastar. No basta.

Las SACLs que se ganan su sitio en todo servidor:

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Audita `Everyone : ReadData : Success`. Cualquier cosa leyendo esto que no sea `LocalSystem` es credential dumping.
- Archivos `*.dmp` en `C:\Windows\Temp` y `%TEMP%`. Audita `Everyone : WriteData : Success`. Un proceso escribiendo un `.dmp` aquí es o Windows tras un crash, o un operador de Mimikatz.
- `C:\ProgramData\Microsoft\Crypto\RSA` y `C:\Users\*\AppData\Roaming\Microsoft\Protect`. Directorios de master-keys DPAPI. Audita `ReadData : Success`. Cualquier cosa leyendo esto fuera de la propia sesión del usuario está robando secretos.
- `HKLM\SECURITY` y `HKLM\SAM`. Equivalentes de registro. Misma auditoría.
- Shares de archivos sensibles: finanzas, legal, nóminas. Audita `WriteData + DELETE : Success` para cazar barridos de ransomware y borrados masivos.

## Los patrones que de verdad cazarás

### Lectura de hive SAM o SYSTEM

Cualquier 4663 con `ObjectName` terminando en `\config\SAM`, `\config\SECURITY` o `\config\SYSTEM`, donde `ProcessName` no sea `services.exe`, `lsass.exe` o `wininit.exe`, y `SubjectUserSid` no sea `S-1-5-18`. Esto es `reg save HKLM\SAM`, `esentutl /y` contra una shadow copy, o cualquier herramienta de credential-dumping con acceso a hive a nivel de archivo. Cruza con el [registro](https://www.registryparser.com) para cualquier archivo de hive de backup dejado atrás.

### Minidump de LSASS escrito

Un 4663 `WriteData` para un archivo `.dmp` en `C:\Windows\Temp\`, `C:\ProgramData\` o `%TEMP%`, con `ProcessName` de `rundll32.exe`, `procdump*.exe` o cualquier cosa llamando a `comsvcs.dll`. El de manual es `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Cruza con [4688](/es/blog/event-id-4688-process-creation) para la `CommandLine`. El 4663 caza esto incluso cuando el EDR estaba dormido.

### Barrido de cifrado de ransomware

Muchos 4663 con `AccessMask` incluyendo `WriteData + DELETE` contra archivos en un share sensible en segundos, todos del mismo `SubjectLogonId` y `ProcessName`. Un proceso de backup real toca archivos en un patrón medido y throttleado. El ransomware barre un árbol de directorios tan rápido como el disco permite. La forma lo delata.

### Robo de master-key DPAPI

4663 `ReadData` sobre archivos bajo `\AppData\Roaming\Microsoft\Protect\<sid>\` por cualquier proceso distinto a la propia sesión del usuario. La señal definitiva es que `SubjectUserSid` sea un SID *distinto* del embebido en la ruta.

### Lectura de archivo de contraseñas de Group Policy Preferences

4663 `ReadData` sobre archivos que coinciden con `\SYSVOL\<domain>\Policies\*\Groups.xml`, o `Services.xml`, `Drives.xml`, `ScheduledTasks.xml`. Esto es `Get-GPPPassword`. La técnica es vieja. Los archivos SYSVOL a menudo siguen existiendo en dominios legacy, y te sorprendería cuántas veces alguien saca la AES key ofuscada de MSDN y se va con una credencial de dominio.

## Sigma: lectura de hive SAM

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

## KQL: barrido de cifrado de ransomware

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

100 archivos distintos escritos-o-borrados por minuto bajo una sesión de logon es un barrido. Punto.

## Splunk: acceso a master-key DPAPI

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## Mapeo ATT&CK

- T1003.002 OS Credential Dumping: Security Account Manager. Lecturas de hive SAM.
- T1003.004 LSA Secrets. Lecturas de hive SECURITY.
- T1003.001 LSASS Memory. Escrituras `.dmp` (combinadas con contexto de proceso).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Acceso a `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. Lecturas de SYSVOL `Groups.xml`.
- T1486 Data Encrypted for Impact. Patrones masivos de `WriteData + DELETE`.
- T1565.001 Stored Data Manipulation. Escrituras arbitrarias sobre shares de datos monitorizados.

## La trampa del volumen de SACLs

Poner `Everyone : Todo el acceso : Success+Failure` sobre un directorio cargado produce cientos de miles de 4663s por minuto y entierra la colección. Las SACLs son instrumentos de precisión. Audita:

- Solo los tipos de acceso que te importan. ReadData para credential stores. WriteData + DELETE para shares de datos. Rara vez ambos a la vez.
- Solo success. Los failures son más raros y rara vez interesantes en este corpus.
- Archivos específicos, no unidades enteras. El archivo SAM, no todo `C:\Windows\System32\config\`. El share de RRHH, no todo `D:\`.
- Principals específicos cuando puedas. Para objetos de clase SAM, `Everyone` está bien porque el acceso legítimo es por `LocalSystem` igualmente. Para datos compartidos, audita solo a los principals que realmente tocan los datos.

Una SACL bien afinada sobre cinco objetos de alto valor produce 50 a 200 registros al día por host. Totalmente manejable.

## Falsos positivos que parecen idénticos a ataques

- Los backups de Volume Shadow Copy generan tráfico 4663 denso durante la ventana de backup. Etiqueta el `ProcessName` del orquestador de backup.
- Los escaneos antivirus on-access abren todos los archivos en un directorio objetivo. Las cuentas de servicio del producto AV dominarán cualquier regla ingenua de 4663. Whitelist por SID.
- Los servicios de indexado (Windows Search) golpean metadatos vía `ReadAttributes`. Normalmente filtrable por `AccessList`.
- Restauraciones backup-staged parecen escrituras de ransomware (muchos archivos, un proceso, en un directorio). El proceso te dice la diferencia.
- El scanning en tiempo real de Defender lee todo. Si auditas demasiado amplio, domina el ruido.

## Lo que 4663 no te dice

- El contenido del acceso. Ves que un archivo fue leído o escrito, no qué fue leído o escrito. Para eso, EDR o FIM.
- Por qué pasó el acceso. Para correlacionar con intención de usuario, empareja con [4688](/es/blog/event-id-4688-process-creation) o [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) para el contexto completo del proceso llamante.
- Handles cerrados. 4663 se dispara en el *abrir* del handle. Los eventos de cierre son 4658, raramente útiles para detección de ataques.
- Rutas de red de forma transparente. El acceso SMB a un share dispara 4663 en el *servidor*. El cliente no ve nada. Necesitas colección del lado del servidor.
- Acceso fallido por defecto. Muchos shops solo auditan Success. Configura Failure solo si genuinamente te importan los intentos frustrados.

## Dónde encaja 4663 en una timeline

Cadena clásica de credential dump de LSASS:

1. [4624](/es/blog/understanding-event-id-4624). Logon de admin, LogonType 3 o 10.
2. [4672](/es/blog/event-id-4672-special-privileges). SeDebugPrivilege concedido con la sesión.
3. [4688](/es/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` a `C:\Windows\Temp\lsass.dmp` por `rundll32.exe`. Oro forense. Prueba de exfiltración en staging.
5. [4688](/es/blog/event-id-4688-process-creation). Move o archive del archivo (operador extrayendo el dump).
6. [1102](/es/blog/event-id-1102-cleared-log). Log de Security borrado. Algunos operadores hacen esto. Muchos olvidan.

El paso 4 es la señal más barata y específica de la cadena. Identifica directamente el artefacto de robo de credenciales por nombre, en disco, con el proceso llamante adjunto. Las lecturas de hive SAM, el acceso a master-keys DPAPI y las lecturas de Groups.xml en SYSVOL funcionan igual.

## Lectura adicional

- [Documentación Microsoft para 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)

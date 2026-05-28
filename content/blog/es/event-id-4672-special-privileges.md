---
title: "Event ID 4672 explicado: detectar logons privilegiados en Windows"
description: "4672 se dispara cuando un logon recibe privilegios sensibles como SeDebugPrivilege o SeTcbPrivilege. Léelo como la señal de 'este logon es equivalente a admin' y el resto de la política de auditoría encaja sola."
date: "2026-05-24"
---

El Event ID **4672**, "Privilegios especiales asignados al nuevo logon", se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que a una sesión de logon se le concede uno de un conjunto fijo de privilegios sensibles de Windows. En la práctica, cada logon exitoso equivalente a administrador produce un 4672, escrito inmediatamente después del [4624](/es/blog/understanding-event-id-4624) correspondiente. En la mayoría de estaciones de trabajo el 4672 es raro. En controladores de dominio y jumpboxes admin es constante. Esa asimetría es lo que lo hace útil.

Si esta semana filtras Security por un solo campo, ejecuta "todos los 4672 de los últimos siete días". Es la consulta de "muéstrame cada sesión privilegiada del parque" más barata que puedes escribir.

## Dónde se dispara

En el host donde el logon realmente ocurrió, igual que [4624](/es/blog/understanding-event-id-4624). Un logon de red a `SERVER01` produce el 4624 y el 4672 en `SERVER01`, no en la estación de trabajo originaria. Para detectar algo desde 4672 a escala necesitas como mínimo colección de Security desde servidores y DCs. Estaciones de trabajo de admin y jumphosts si te puedes permitir el volumen.

## Qué contiene el registro

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

Los campos:

- `SubjectLogonId`. El mismo `LogonId` del [4624](/es/blog/understanding-event-id-4624) correspondiente. Este es tu pivote. Cada 4672 ata exactamente un 4624 (y cada registro posterior en esa sesión) al conjunto de privilegios que el logon obtuvo.
- `PrivilegeList`. El bolso de privilegios real. Windows registra solo los privilegios "sensibles" definidos en la política de auditoría. Un logon puede tener más privilegios de los que el registro muestra. Los omitidos (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc.) no son relevantes para la seguridad y se podan de este registro a propósito.
- `Subject*`. A quién pertenece el logon. Casi siempre idéntico al 4624 correspondiente.

No hay `IpAddress`, ni `LogonType`, ni `WorkstationName` en el propio 4672. Para conseguirlos, joineas al 4624 vía `SubjectLogonId`. Los analistas que intentan alertar sobre 4672 solo, a menudo se pierden esto y acaban con registros que no pueden enriquecer.

## Los privilegios y qué significan

| Privilegio | Nombre mostrado | Por qué importa |
|---|---|---|
| `SeDebugPrivilege` | Depurar programas | Leer/escribir la memoria de cualquier proceso, incluyendo `lsass.exe`. Mimikatz necesita esto. |
| `SeTcbPrivilege` | Actuar como parte del SO | Efectivamente `LocalSystem`. Debería aparecer solo para LocalSystem. |
| `SeImpersonatePrivilege` | Suplantar a un cliente tras auth | El privilegio usado por la familia Potato (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). |
| `SeAssignPrimaryTokenPrivilege` | Reemplazar token de proceso | Herramientas de suplantación de token. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | Saltar ACLs para leer/escribir archivos arbitrarios incluyendo hives del registro. `reg save HKLM\SAM` funciona con esto. |
| `SeTakeOwnershipPrivilege` | Tomar propiedad | Sobrescribir ACLs de archivos. |
| `SeLoadDriverPrivilege` | Cargar drivers | Requerido para BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Gestionar log de auditoría | Leer o borrar Security. Requerido para disparar [1102](/es/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modificar firmware | Bootkits, manipulación EFI. |
| `SeChangeNotifyPrivilege` | Saltar comprobación de travesía | Común en la mayoría de logons. No es señal de triaje. |

Algunos los esperas en cada logon admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Otros deberían ser más raros (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). La señal es el privilegio *inesperado* en la cuenta *equivocada*.

## Los patrones

### Baseline de quién recibe 4672

En un parque saludable, los productores de 4672 son un conjunto pequeño y conocido:

- `LocalSystem` (S-1-5-18). Cada host, todo el tiempo, al arrancar servicios.
- `NetworkService` (S-1-5-20). Común en servidores ejecutando servicios capaces de suplantación.
- Un puñado de administradores, identificados por SID en lugar de por nombre.

Cualquier otro es un nuevo admin del que no sabías, un evento de escalada de privilegios o una cuenta mal configurada.

La consulta de baseline más barata: distinct `SubjectUserSid` de 4672 sobre los últimos 30 días, ordenado por frecuencia. Cualquier cosa fuera del top N merece una mirada.

### SeImpersonatePrivilege en una cuenta no privilegiada

Si un 4672 muestra `SeImpersonatePrivilege` en una cuenta que no es admin y no es un SID `*Service`, es casi seguro una escalada Potato. Estos exploits dan a un llamante con `IIS_IUSRS` o token de servicio `SYSTEM`. El 4672 se dispara *al adquirir el privilegio*. Eso es antes que cualquier proceso visible engendrado con el nuevo privilegio.

### SeDebugPrivilege sin grupo admin

`SeDebugPrivilege` se concede a admins locales por política. En una cuenta no admin, o se modificó la política (normalmente por un atacante para habilitar acceso a LSASS) o un atacante se ha inyectado en un proceso admin.

### Logon privilegiado fuera del horario laboral

Un 4672 para una cuenta admin real a las 03:00 un domingo es la alerta after-hours más barata que hay. Combina con el `LogonType` e `IpAddress` del 4624 correspondiente para contexto.

### Drift de cuenta de servicio

Una cuenta de servicio que históricamente solo dispara `SeImpersonatePrivilege` y `SeAssignPrimaryTokenPrivilege`, que de repente produce 4672 con `SeBackupPrivilege` y `SeDebugPrivilege`, significa que alguien cambió sus pertenencias a grupos. Empareja con 4732 o 4728 para encontrar el cambio de membresía.

## Sigma: SeDebugPrivilege en un no-admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Ajusta `filter_known_admins` por entorno. Algunos shops usan una lista de SIDs en lugar de un patrón de nombres.

## KQL: escalada de familia Potato

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Splunk: baseline de logons admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Ejecútalo semanalmente. Las anomalías salen como cuentas nuevas en el top 50.

## Mapeo ATT&CK

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege en cuentas no privilegiadas.
- T1003.001 LSASS Memory. SeDebugPrivilege es la precondición.
- T1068 Exploitation for Privilege Escalation. Cualquier ganancia inesperada de privilegios.
- T1078 Valid Accounts. 4672 para cuentas admin legítimas desde orígenes inusuales.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege se requiere para llamar a `ClearEventLog`. Un 4672 portando este privilegio justo antes de [1102](/es/blog/event-id-1102-cleared-log) es el rastro de migas.

## Falsos positivos que parecen ataques

- El software de backup (Veeam, Commvault) dispara rutinariamente 4672 con `SeBackupPrivilege` + `SeRestorePrivilege` desde cuentas de servicio. Baseline por SID de cuenta de servicio.
- Agentes de monitorización (SCOM, recolectores WMI propios) disparan 4672 ampliamente. Etiqueta el host del agente.
- Algunos runners de scripts de logon bajo contextos privilegiados producen cadenas de 4672 en el momento del logon.
- Hyper-V, VMM, hosts de contenedores generan 4672 denso desde `LocalSystem` y cuentas de servicio gestionadas.

La señal es el productor *nuevo*, no el *recurrente*. Un productor de 4672 que ha disparado diariamente durante el último año es configuración. Uno que acaba de aparecer esta semana es la pista.

## Lo que 4672 no te dice

- Sin información de proceso. Ves la concesión del privilegio, no qué hizo el proceso privilegiado. Para seguirlo adelante, pivota `SubjectLogonId` a registros [4688](/es/blog/event-id-4688-process-creation) o [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) en la misma sesión.
- Sin IP origen directa. Joineas a [4624](/es/blog/understanding-event-id-4624) vía `SubjectLogonId`.
- No cada acción privilegiada. Solo se registra la *concesión en el logon*. Usos posteriores (p. ej. `RtlAdjustPrivilege` alternando `SeDebugPrivilege`) producen registros 4673/4674, no otro 4672.
- Se pierde si el auditing de Special Logon está apagado. La sub-política de auditoría es *Audit Special Logon*. Activa por defecto en Windows moderno, pero merece la pena verificarla.

## Dónde encaja 4672 en una timeline

La cadena clásica de escalada y limpieza:

1. [4624](/es/blog/understanding-event-id-4624). LogonType 3 desde una IP controlada por el atacante, usuario de bajo privilegio.
2. *(silencioso)*. Escalada basada en SeImpersonatePrivilege (PrintSpoofer o similar).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege concedidos a una nueva sesión de logon ejecutándose como LocalSystem. Escalada visible aquí.
4. [4688](/es/blog/event-id-4688-process-creation). `cmd.exe` o `powershell.exe` como SYSTEM vía el token suplantado.
5. [4104](/es/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` o `comsvcs.dll MiniDump` contra LSASS. SeDebugPrivilege es lo que hace que esto funcione.
6. [1102](/es/blog/event-id-1102-cleared-log). Log de Security borrado. SeSecurityPrivilege del paso 3 lo habilitó.
7. **4672**. Segunda sesión privilegiada como domain admin extraída de la memoria de LSASS.

Los 4672 en los pasos 3 y 7 son los puntos de detección más baratos. Sin ellos estás ensamblando la suplantación a partir de eventos de proceso solos. Más lento, más fácil de perder.

## Lectura adicional

- [Documentación Microsoft para 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)

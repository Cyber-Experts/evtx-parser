---
title: "Event ID 4672 explicado: detectar logons privilegiados en Windows"
description: "4672 se dispara cuando un logon recibe privilegios sensibles como SeDebugPrivilege o SeTcbPrivilege. Léelo como la señal «este logon es equivalente a admin» y el resto encaja."
date: "2026-05-24"
---

El Event ID **4672** — «Privilegios especiales asignados a nuevo logon» — se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que una sesión de logon recibe uno de un conjunto fijo de privilegios sensibles de Windows. En la práctica eso significa: cada logon exitoso equivalente-a-administrador produce un 4672, inmediatamente después del [4624](/es/blog/understanding-event-id-4624) correspondiente. En la mayoría de workstations, 4672 es raro; en domain controllers y jumpboxes de admin, es constante. Esa asimetría es lo que lo hace útil.

Si solo filtras registros Security por un campo, «dame todos los 4672 de la última semana» es la consulta «muéstrame cada sesión privilegiada en el estate» más barata que puedes ejecutar.

## Dónde se dispara

Siempre en el host donde el logon realmente ocurrió — igual que [4624](/es/blog/understanding-event-id-4624). Un network logon a `SERVER01` produce el 4624 y (si es privilegiado) el 4672 en `SERVER01`, no en la workstation originadora. Para detectar cualquier cosa desde 4672 a escala, necesitas colección de Security desde servidores y DCs como mínimo; desde workstations de admin y jumphosts si puedes permitirte el volumen.

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

- **`SubjectLogonId`** — el mismo `LogonId` que aparece en el [4624](/es/blog/understanding-event-id-4624) correspondiente. Este es tu pivot: cada 4672 ata exactamente un 4624 (y cada registro subsiguiente en esa sesión) al conjunto de privilegios que el logon obtuvo.
- **`PrivilegeList`** — la bolsa real de privilegios. Windows solo registra aquí un conjunto fijo de privilegios «sensibles» (definidos en la política de auditoría); un logon puede sostener más privilegios de los que muestra el registro. Los omitidos — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc. — no son relevantes para seguridad y se podan de este registro a propósito.
- **`Subject*`** — a quién pertenece el logon. Casi siempre idéntico a los mismos campos en el 4624 correspondiente.

No hay `IpAddress`, no `LogonType`, no `WorkstationName` en el propio 4672. Para obtenerlos haces join al 4624 vía `SubjectLogonId`.

## Los privilegios y lo que significan

| Privilegio | Nombre mostrado | Por qué importa |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Leer/escribir la memoria de cualquier proceso — incluido `lsass.exe`. Mimikatz lo necesita. |
| `SeTcbPrivilege` | Act as part of the operating system | Efectivamente `LocalSystem`. Debería aparecer solo para LocalSystem mismo. |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | El privilegio usado por las familias de exploits `SeImpersonatePrivilege` (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Herramientas de token-impersonation. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | Eludir ACLs para leer/escribir archivos arbitrarios — incluidos hives de registro. `reg save HKLM\SAM` funciona con estos. |
| `SeTakeOwnershipPrivilege` | Take ownership of files | Sobreescribir ACLs de archivo. |
| `SeLoadDriverPrivilege` | Load and unload device drivers | Requerido para ataques BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Manage auditing and security log | Leer/borrar el Security event log. Requerido para disparar [1102](/es/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkits, tampering de EFI. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Común en la mayoría de logons; no es señal de triage. |

Algunos de estos los esperas en cada logon de admin (`SeDebugPrivilege`, `SeBackupPrivilege`). Otros deberían ser más raros (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). La señal está en el privilegio *inesperado* apareciendo en la cuenta *equivocada*.

## Los patrones de triage

### 1. Baseline de quién recibe 4672

En un estate saludable, los productores de 4672 son un conjunto *pequeño y conocido*:

- `LocalSystem` (S-1-5-18) — cada host, todo el tiempo, en arranque de servicios.
- `NetworkService` (S-1-5-20) — común en servidores corriendo servicios capaces de impersonation.
- Un puñado de administradores, identificados por SID en lugar de nombre.

Cualquiera más generando un 4672 es: un admin nuevo del que no sabías, un evento de escalada de privilegios o una cuenta mal configurada.

La consulta de baseline más barata: `SubjectUserSid` distintos de 4672 en los últimos 30 días, ordenados por frecuencia. Cualquier cosa fuera de los Top N productores merece una mirada.

### 2. SeImpersonatePrivilege en una cuenta sin privilegios

Si un 4672 muestra `SeImpersonatePrivilege` en una cuenta que no es admin y no es un SID `*Service`, es casi seguro una escalada de la familia «Potato» (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). Estos exploits dan al caller con token de `IIS_IUSRS` o de servicio el `SYSTEM`. El 4672 se dispara *al adquirirse el privilegio* — antes que cualquier proceso visible spawneado con el nuevo privilegio.

### 3. SeDebugPrivilege sin grupo admin

`SeDebugPrivilege` se otorga a admins locales por política. Verlo en una cuenta no-admin es señal de que la política ha sido modificada — usualmente por un atacante para habilitar acceso a LSASS — o que un atacante ha inyectado en un proceso admin.

### 4. Logon privilegiado fuera del horario laboral

Un 4672 para una cuenta admin real a las 03:00 de un domingo es la alerta «actividad admin fuera de horario» más barata que existe. Combina con el `LogonType` y `IpAddress` del 4624 correspondiente para contexto.

### 5. Drift de cuenta de servicio

Una cuenta de servicio que históricamente solo dispara `SeImpersonatePrivilege` y `SeAssignPrimaryTokenPrivilege` produciendo de pronto 4672 con `SeBackupPrivilege` y `SeDebugPrivilege` significa que alguien cambió sus pertenencias a grupos. Empareja con 4732/4728 para encontrar el cambio de pertenencia.

## Regla Sigma de ejemplo — SeDebugPrivilege en un no-admin

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
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Ajusta `filter_known_admins` por entorno; algunos shops usan una lista de SIDs en lugar de un patrón de nombre.

## KQL de ejemplo — escalada de familia Potato

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

## Splunk de ejemplo — baseline de logons de admin

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Ejecútalo semanalmente; las anomalías aparecen como cuentas nuevas en el top 50.

## Mapeo ATT&CK

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**: SeImpersonatePrivilege en cuentas sin privilegios.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: SeDebugPrivilege es la precondición.
- **T1068 — Exploitation for Privilege Escalation**: cualquier ganancia inesperada de privilegio.
- **T1078 — Valid Accounts**: 4672 para cuentas admin legítimas desde orígenes inusuales.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: SeSecurityPrivilege se requiere para llamar a `ClearEventLog`; un 4672 con este privilegio justo antes de [1102](/es/blog/event-id-1102-cleared-log) es el rastro de migajas.

## Falsos positivos que parecen exactamente ataques

- **Software de backup** (Veeam, Commvault) rutinariamente dispara 4672 con `SeBackupPrivilege` + `SeRestorePrivilege` desde cuentas de servicio. Baseline por SID de cuenta de servicio.
- **Agentes de monitorización** (SCOM, colectores WMI personalizados) que leen datos relevantes para seguridad disparan 4672 ampliamente. Etiqueta el host del agente.
- **Algunos runners de logon-script** bajo contextos privilegiados producen cadenas de 4672 en tiempo de logon.
- **Hosts Hyper-V / VMM / contenedores** generan tráfico denso de 4672 desde `LocalSystem` y cuentas de servicio gestionadas.

La señal está en el productor *nuevo*, no en el *recurrente*. Un productor de 4672 que ha disparado diariamente durante el último año es configuración; uno que acaba de aparecer esta semana es la pista.

## Lo que 4672 no te dice

- **Sin información de proceso**: ves el otorgamiento del privilegio, no qué hizo el proceso privilegiado. Para seguirlo hacia adelante, pivota `SubjectLogonId` a registros [4688](/es/blog/event-id-4688-process-creation) / [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) en la misma sesión.
- **Sin IP de origen** directamente: tienes que hacer join a [4624](/es/blog/understanding-event-id-4624) vía `SubjectLogonId` para obtenerla.
- **No cada acción privilegiada**: solo el *otorgamiento en logon* se registra. Usos subsiguientes (p.ej., `RtlAdjustPrivilege` alternando `SeDebugPrivilege` on/off) producen registros 4673/4674, no otro 4672.
- **Se pierde si Special Logon auditing está apagado**: la subcategoría de auditoría es *Audit Special Logon*, que debe estar habilitada para eventos de éxito. Está activada por defecto en Windows moderno pero conviene verificar.

## Dónde encaja 4672 en una timeline

La cadena de escalada-y-limpieza de libro de texto:

1. [**4624**](/es/blog/understanding-event-id-4624) — LogonType 3 desde una IP controlada por el atacante, usuario de bajo privilegio.
2. *(silencio)* — escalada basada en `SeImpersonatePrivilege` (PrintSpoofer o similar).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` otorgados a una nueva sesión de logon corriendo como `LocalSystem`. **Escalada visible aquí.**
4. [**4688**](/es/blog/event-id-4688-process-creation) — `cmd.exe` o `powershell.exe` corriendo como SYSTEM vía el token impersonado.
5. [**4104**](/es/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` o `comsvcs.dll MiniDump` contra LSASS — SeDebugPrivilege es lo que hace que esto funcione.
6. [**1102**](/es/blog/event-id-1102-cleared-log) — Security log borrado. SeSecurityPrivilege del paso 3 habilitó esto.
7. **4672** — segunda sesión privilegiada como domain admin extraído de la memoria de LSASS.

Los 4672 en los pasos 3 y 7 son los puntos de detección más baratos de la cadena. Sin ellos, estás reconstruyendo la impersonation solo desde eventos de proceso — más lento, y más fácil de perder.

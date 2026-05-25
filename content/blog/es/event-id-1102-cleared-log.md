---
title: "Event ID 1102 explicado: log de auditoría de seguridad borrado (y qué sobrevive)"
description: "1102 es el único evento que no puedes suprimir sin dejar más evidencia. Aquí está qué te dice y qué sobrevive al borrado."
date: "2026-05-17"
---

El Event ID **1102** es el registro que Windows escribe en el [canal `Security`](/es/blog/what-is-an-evtx-file) cuando el log de auditoría es borrado. Es — por diseño — uno de los registros más difíciles de suprimir para un atacante, porque suprimirlo requiere o bien reemplazar con éxito el servicio EventLog antes de que arranque o aceptar que el acto de borrar deja a su vez un 1102.

Para los defensores esto significa: si ves un 1102, alguien con privilegios suficientes borró deliberadamente la pista de auditoría. Eso casi nunca es una acción administrativa normal.

## Qué hay en el registro

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Nota el bloque `UserData` en lugar del usual `EventData` — 1102 es uno de los registros que usa un esquema estructurado de user-data. Los campos te dicen *quién* borró el log bajo qué sesión de logon. Pivotando sobre `SubjectLogonId` encuentras el [4624](/es/blog/understanding-event-id-4624) correspondiente y obtienes la IP de origen y el tipo de logon que produjo la sesión privilegiada.

## Qué se dispara también cuando se dispara un 1102

Un borrado de log rara vez es la *única* acción anti-forense. Compañeros comunes, en orden cronológico aproximado:

- **104** en el canal `System` — mismo acto, registrado por el SCM. Si 104 está presente pero 1102 no, el atacante solo borró el Security log y olvidó System.
- **4719** — «Se modificó la política de auditoría del sistema». A veces un atacante reduce la cobertura de auditoría *antes* de borrar, para dejar menos registros en la siguiente ronda.
- **4616** — «Se cambió la hora del sistema». El desfase horario pre-borrado dificulta la reconstrucción de la timeline.
- **Una brecha en los 4624** durante una hora o dos antes del 1102 — el atacante puede haber usado un canal lateral no registrado.

## Qué sobrevive a un borrado

Borrar el event log en memoria no toca:

- **Otros canales**: `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canales de eventos reenviados — ninguno de estos se borra con un wipe de Security.
- **Eventos reenviados**: si Windows Event Forwarding (WEF) está configurado hacia un colector central, los registros borrados ya están en otro host.
- **El propio archivo en disco**: un `Security.evtx` borrado se reemplaza por un archivo nuevo; los clusters del archivo *eliminado* anterior a menudo persisten en espacio no asignado y pueden carvearse con herramientas NTFS.
- **Entradas del USN journal** sobre el reemplazo del archivo: incluso la operación de borrado deja artefactos a nivel de filesystem.

Un borrado de log «exitoso» rara vez es tan limpio como espera el atacante.

## Regla Sigma de ejemplo — log borrado

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

Si ves un 1102 fuera de una ventana de mantenimiento aprobada, trátalo como un incidente — sin discusión.

## KQL de ejemplo — correlación log clear + sesión privilegiada

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Cada 1102 se remonta a un [4672](/es/blog/event-id-4672-special-privileges) otorgando `SeSecurityPrivilege` — que a su vez se remonta a un [4624](/es/blog/understanding-event-id-4624). El join completa la imagen.

## Splunk de ejemplo — cadena anti-forense de compañeros

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un `LogonId` que tocó política de auditoría (4719) o la hora del sistema (4616) y luego borró un log (1102/104) es la cadena de tampering.

## Mapeo ATT&CK

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**: la técnica titular. 1102 *es* el indicador primario de esta técnica.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: 4719 (audit policy changed) precediendo a 1102 mapea aquí.
- **T1070.006 — Indicator Removal: Timestomp**: emparejado con 4616 (system time changed) en la misma cadena.
- **T1078.003 — Valid Accounts: Local Accounts**: 1102 por un Administrator local que no debería haber iniciado sesión a esa hora.

## Falsos positivos — raros pero reales

- **Workflows de migración / decom**: técnicos borrando el log en un host que se está desmantelando. Siempre debería estar tickeado.
- **Laboratorios forenses / de testing**: workflows de borrar-y-reproducir durante el desarrollo de detecciones.
- **Algunas herramientas legacy** borran el log para resetear baselines — casi siempre un error procedimental, pero real.

La señal es tan directamente anti-forense que incluso los 1102 legítimos deberían ser investigados y documentados a posteriori. No hay razón «segura» para un 1102 en operación normal.

## Por qué esto importa para el parsing

Cuando [cargas un archivo .evtx en una herramienta forense](/es/blog/how-to-open-an-evtx-file), la *primera* búsqueda que merece la pena ejecutar es `EventID:1102` y `EventID:104`. Si cualquiera está presente, el log que tienes tiene huecos conocidos y cualquier timeline que construyas a partir de él es incompleta. Anótalo bien fuerte en el informe.

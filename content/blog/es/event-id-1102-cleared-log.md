---
title: "Event ID 1102 explicado: registro de auditoría de Security borrado (y lo que sobrevive)"
description: "1102 es el único evento que no puedes suprimir sin dejar más pruebas. Esto es lo que te dice, lo que sobrevive al borrado y dónde mirar cuando lo veas."
date: "2026-05-17"
---

El Event ID **1102** es lo que Windows escribe en el [canal `Security`](/es/blog/what-is-an-evtx-file) cuando alguien borra el registro de auditoría. Por diseño, es uno de los registros más difíciles de suprimir para un atacante. Suprimirlo limpiamente requiere reemplazar el binario del servicio EventLog antes de que arranque, o aceptar que el acto de borrar deja un 1102 propio. La mayoría de operadores eligen la segunda opción, esperando que nadie esté prestando atención.

Si ves 1102, alguien con suficiente privilegio borró deliberadamente el rastro de auditoría. Esto prácticamente nunca es una acción admin rutinaria, y cuando lo es, debería tener un ticket. Trata cada 1102 fuera de una ventana de mantenimiento aprobada como un incidente hasta que se demuestre lo contrario.

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

Nota el bloque `UserData` en lugar del `EventData` habitual. 1102 usa un esquema estructurado user-data, que confunde a algunos parsers ingenuos que solo miran `EventData`. Los campos te dicen quién borró el log bajo qué sesión de logon. Pivota en `SubjectLogonId` al [4624](/es/blog/understanding-event-id-4624) correspondiente y tendrás la IP origen, el tipo de logon y la credencial que produjo la sesión privilegiada.

## Qué cabalga al lado

Un borrado de log raramente es la única acción anti-forense de la cadena. Los registros que tienden a dispararse cerca, en orden cronológico aproximado:

- **104** en el canal `System`. El mismo acto que 1102 pero registrado por el SCM para canales no-Security. Si 104 está presente y falta 1102, el atacante solo borró Security y se olvidó de System.
- **4719**, "se cambió la política de auditoría del sistema". A veces el atacante reduce la cobertura de auditoría *antes* de borrar, para dejar menos registros la próxima vez.
- **4616**, "se cambió la hora del sistema". El timestomping previo al borrado dificulta la reconstrucción de la timeline.
- Un hueco en 4624s en la hora o dos antes de 1102. El atacante puede haber usado un canal lateral no registrado para entrar.

## Qué sobrevive a un borrado

Borrar el event log en memoria no toca:

- Otros canales. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, canales de eventos reenviados. Ninguno se borra con un wipe de Security.
- Eventos reenviados. Si Windows Event Forwarding está enviando Security a un recolector, los registros borrados ya están en otro host. Los RecordIDs y timestamps originales se preservan.
- El propio archivo en disco. Una `Security.evtx` borrada se reemplaza por un archivo fresco. Los clusters del archivo anterior a menudo persisten en espacio no asignado. Los registros EVTX [carvan limpiamente](/es/blog/carve-deleted-evtx-records) de esos clusters.
- Entradas del [diario USN](https://www.usnparser.com) para el reemplazo del archivo. Incluso el acto de borrar deja artefactos a nivel de sistema de archivos.
- La entrada [MFT](https://www.mftparser.com) para el archivo nuevo, que lleva un timestamp de creación que debería coincidir con el 1102 con un segundo de margen.

Un borrado de log "exitoso" raramente es tan limpio como el atacante espera.

## Sigma: log borrado

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
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

## KQL: borrado correlacionado con sesión privilegiada

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

Todo 1102 rastrea hasta un [4672](/es/blog/event-id-4672-special-privileges) que concede `SeSecurityPrivilege`, que rastrea hasta un [4624](/es/blog/understanding-event-id-4624). El join completa la imagen.

## Splunk: la cadena de manipulación

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

Un LogonId que tocó la política de auditoría (4719) o la hora del sistema (4616) y luego borró un log (1102/104) es la cadena de manipulación.

## Mapeo ATT&CK

- T1070.001 Indicator Removal: Clear Windows Event Logs. El titular. 1102 *es* el indicador primario.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 antes de 1102 mapea aquí.
- T1070.006 Indicator Removal: Timestomp. Emparejado con 4616 en la misma cadena.
- T1078.003 Valid Accounts: Local Accounts. 1102 por un Administrador local que no debería haber estado conectado en ese momento.

## Falsos positivos, raros pero reales

- Workflows de migración o decom. Técnicos borrando logs en un host que se decomisiona. Siempre debería tener ticket.
- Laboratorios forenses ejecutando bucles de borrado y reproducir durante el desarrollo de detección.
- Algunas herramientas legacy borran el log para "resetear baselines". Casi siempre un error de procedimiento, pero real.

No hay una razón segura para un 1102 en operaciones normales. Incluso los legítimos deberían investigarse y documentarse a posteriori.

## Cuando encuentras uno en el paquete

Cuando cargas un [archivo .evtx en una herramienta forense](/es/blog/how-to-open-an-evtx-file), las primeras dos búsquedas que vale la pena ejecutar son `EventID:1102` y `EventID:104`. Si alguno está presente, el log que tienes tiene huecos conocidos. Cualquier timeline construida con él está incompleta. Anótalo en alto en el informe. Luego ve a ver qué sobrevivió: el [registro](https://www.registryparser.com), el [diario USN](https://www.usnparser.com), la [MFT](https://www.mftparser.com), [prefetch](https://www.prefetchparser.com) y [AmCache](https://www.amcacheparser.com). Juntos reconstruyen la mayoría de lo que 1102 intentó borrar.

Herramientas como `Invoke-Phant0m` saltan el 1102 por completo suspendiendo los hilos del servicio de eventos en lugar de borrar. Si ves un silencio de varias horas en Security sin 1102 y sin apagado del sistema, esa es la otra forma del mismo problema.

## Lectura adicional

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Documentación Microsoft para 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)

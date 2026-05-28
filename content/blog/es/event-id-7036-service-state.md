---
title: "Event ID 7036 explicado: cambios de estado de servicio para triaje DFIR"
description: "7036 se dispara cada vez que un servicio arranca o se detiene. Emparejado con 7045 confirma si la persistencia realmente se ejecutó. Por sí solo revela abuso de servicios, evasión de defensa y anomalías de arranque."
date: "2026-05-24"
---

El Event ID **7036**, "El servicio {service} entró en el estado {state}", se dispara en el [canal `System`](/es/blog/what-is-an-evtx-file) cada vez que el Service Control Manager ve una transición de servicio. Cada arranque, parada, pausa y reanudación produce uno. Por sí solo es de alto volumen y fácil de descartar. Emparejado con [7045](/es/blog/service-creation-event-id-7045) es la diferencia entre "se instaló un backdoor" y "se instaló un backdoor y se ejecutó".

Para respuesta a incidentes, este es el registro más barato de "¿se ejecutó?" que el SO te da.

## Dónde vive

Canal `System` en el host donde el servicio corrió. Sin involucración de DC, sin preocupación por reenvío por canal. Está ahí mismo en `System.evtx`. Provider: `Service Control Manager`.

## Qué contiene el registro

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

Eso es todo. Dos parámetros y un tag binario. Mucho más pequeño que la mayoría de registros de Security, por eso los analistas lo saltan.

- `param1`. El *nombre de visualización* del servicio (no el nombre corto). `Background Intelligent Transfer Service` aquí es el nombre de cara al usuario de `BITS`. Para pivotar a la definición del servicio normalmente necesitas el nombre corto. El SCM lo estampa en `Binary` como un blob UTF-16 (`42 00 49 00 54 00 53 00` decodifica a `BITS`).
- `param2`. El nuevo estado: `running`, `stopped`, `paused`, `resumed` o estados intermedios pendientes (`start pending`, `stop pending`). `running` y `stopped` son sobre los que la mayoría de reglas se centran.

No hay `AccountName`, ni `ImagePath`, ni `ProcessId`. 7036 te dice *qué* cambió de estado, no *quién* lo disparó. Para conseguir el por qué, empareja con otros registros.

## 7036, 7045, 7035, 7034: cuál es cuál

Cuatro eventos relacionados con servicios del canal System se confunden constantemente:

| Evento | Cuándo | Qué te da |
|---|---|---|
| **7045** | Servicio instalado | Nombre de visualización, nombre corto, `ImagePath`, `AccountName`, `StartType`. El punto de persistencia. |
| **7036** | Arranque/parada de servicio | Solo nombre de visualización. El punto de ejecución. |
| **7035** | Control de servicio enviado | Quién inició arranque/parada (SID), qué control se envió. Raramente activo por defecto. |
| **7034** | Servicio crasheó inesperadamente | Servicio terminado sin un stop limpio. |

El patrón importa: un 7045 seguido segundos después por un 7036 `running` para el mismo nombre de visualización es la secuencia clásica de "instalado y ejecutado". Un 7045 *sin* un 7036 coincidente significa que el servicio se registró pero nunca se ejecutó: o el atacante limpió, el instalador abortó, o el arranque se difirió.

## Los patrones de triaje

### Verificación de persistencia: emparejar con 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Tres registros, un evento de ejecución lateral PsExec. El par 7036 te dice que el servicio realmente corrió (no solo se instaló). Para un backdoor *persistente* el segundo 7036 (stopped) puede faltar o aparecer horas después cuando el host reinicia.

Un 7045 sin un 7036 `running` en minutos es su propia anomalía. Investiga por qué la instalación no se disparó. Causas comunes: en cola para el próximo reboot, puesto a arranque manual y el atacante no lo había disparado todavía, arranque falló (busca errores 7034 / 7000).

### Evasión de defensa: detener servicios de seguridad

El patrón más abusado. Un atacante detiene `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc` o el servicio de un producto EDR. Cada uno genera un 7036 `stopped` para el nombre de visualización correspondiente. Si se está intentando manipular política de auditoría o Defender, este es uno de los registros que sobreviven.

Nombres para alertar (nombres de visualización; varían por versión de Defender o EDR):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Cualquier cosa que matchee `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` para cualquiera de estos, especialmente fuera de una ventana de mantenimiento programada, debería ser una alerta dura. Muchos atacantes usan `sc stop`, `net stop`, `Stop-Service` o `taskkill /im`. Los cuatro producen un 7036.

### Typosquatting de nombre de servicio

7036 se dispara para el nombre de visualización incluso cuando el servicio subyacente es malicioso. Vigila nombres de visualización que parecen legítimos pero no coinciden con ningún servicio Microsoft instalado: `Windows Update Service` (nombre real es `Windows Update`), `Windows Defender Service` (nombre real es `Windows Defender Antivirus Service`), `Microsoft Telemetry` (no existe tal servicio). Baseline nombres de visualización de un host conocido bueno y haz diff.

### Anomalías de arranque

Tras un reboot el SCM levanta servicios de auto-arranque en un orden aproximadamente estable. Un nuevo servicio auto-arranque apareciendo en la secuencia 7036 de arranque, especialmente uno que no estaba en el arranque anterior, es un nuevo punto de persistencia. Cruza con el 7045 correspondiente en o antes del apagado anterior.

## Sigma: servicio de seguridad detenido

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL: secuencia 7045 a 7036

El pivote titular. Instalación de persistencia seguida de ejecución en 5 minutos en el mismo host:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

`DisplayName` de 7036 no siempre será literalmente igual a `ServiceName` de 7045 (uno es display, otro es short). Matchea heurísticamente o precomputa un mapa para el pequeño conjunto de servicios que importan.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapeo ATT&CK

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` para servicios de seguridad.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` emparejado con 7045 para el mismo servicio.
- T1569.002 System Services: Service Execution. 7036 `running` para un `ImagePath` apuntando a un binario no estándar, a menudo parte de movimiento lateral (PsExec, ejecución remota basada en SCM, Impacket `psexec.py`).
- T1489 Service Stop. Apuntado a disponibilidad (ransomware deteniendo SQL Server antes de cifrar bases de datos).

## Falsos positivos que parecen exactamente ataques

- Windows Update reinicia una docena de servicios en una secuencia predecible. Recurrente y rápido.
- Las actualizaciones de firmas de Defender a veces reinician `WinDefend` en sí. Un `stopped` rápidamente seguido de `running` desde `MsSecFlt.exe` es el patrón normal. El malicioso es *no* `running` tras el `stopped`.
- Las actualizaciones de EDR detienen y reinician el servicio EDR. Etiqueta las ventanas de upgrade del vendor.
- Sleep e hibernación del sistema generan tandas de `stopped` al dormir y `running` al despertar. No alertes sobre estos aisladamente.
- Las cargas de trabajo de contenedores e Hyper-V suben y bajan servicios constantemente.

## Lo que 7036 no te dice

- Sin `AccountName`. Saca eso del 7045 correspondiente o de la base de datos del SCM.
- Sin PID. No puedes mapear un 7036 directamente a un registro [4688](/es/blog/event-id-4688-process-creation) o [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) sin correlacionar por `ImagePath` y timestamp. La caché de [prefetch](https://www.prefetchparser.com) es la corroboración secundaria cuando 4688 estaba apagado.
- Sin iniciador. No ves quién llamó a Stop-Service. Para eso necesitas 7035 (a menudo deshabilitado por defecto), [4688](/es/blog/event-id-4688-process-creation) para el `net stop` / `sc stop` / `taskkill` llamante, o [4104](/es/blog/powershell-4104-scriptblock) para `Stop-Service`.
- Mapeo de nombre corto de servicio. El nombre de visualización está en `param1`. El nombre corto está en el blob binario y debe decodificarse. La mayoría de parsers hacen esto automáticamente. Si consultas `EventData` crudo tienes que manejarlo tú.

## Dónde encaja 7036 en una timeline

Ejecución lateral más evasión de defensa:

1. [4624](/es/blog/understanding-event-id-4624). LogonType 3 desde un host controlado por el atacante, AuthenticationPackage Kerberos.
2. [4688](/es/blog/event-id-4688-process-creation). `services.exe` engendrando un hijo para operaciones SCM (o `psexesvc.exe` de PsExec).
3. [7045](/es/blog/service-creation-event-id-7045). Servicio instalado, `ImagePath` fuera de rutas de instalación estándar.
4. **7036 `running`**. La instalación realmente se disparó. Confirmación de ejecución.
5. **7036 `stopped`** para `WinDefend` o EDR. Evasión de defensa antes de que corra la payload.
6. [4688](/es/blog/event-id-4688-process-creation). Proceso payload bajo la cuenta del servicio.
7. **7036 `stopped`** para el servicio instalador. Limpieza.

7036 aparece en los pasos 4, 5 y 7. Tres etapas distintas de la misma intrusión. Por sí solo es difícil de usar. En contexto ata el registro de persistencia (7045) a la ejecución real y a las acciones de evasión de defensa circundantes.

## Lectura adicional

- [Documentación Microsoft: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

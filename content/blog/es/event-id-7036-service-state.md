---
title: "Event ID 7036 explicado: cambios de estado de servicio para triage DFIR"
description: "7036 se dispara cada vez que un servicio arranca o se detiene. Con 7045 confirma si la persistencia se ejecutó — y solo, revela abuso de servicios y evasión de defensas."
date: "2026-05-24"
---

El Event ID **7036** — «El servicio {service} entró en el estado {state}» — se dispara en el [canal `System`](/es/blog/what-is-an-evtx-file) cada vez que el Service Control Manager (SCM) ve una transición de servicio. Cada arranque, parada, pausa y reanudación de servicio produce uno. Por sí solo es de alto volumen y fácil de descartar; emparejado con [7045](/es/blog/service-creation-event-id-7045) (servicio instalado) es la diferencia entre *un backdoor fue instalado* y *un backdoor fue instalado y se ejecutó*.

Para respuesta a incidentes, este es el registro «¿se ejecutó?» más barato que el SO te da.

## Dónde vive

Siempre el canal **`System`** en el host donde corrió el servicio. Sin participación del DC, sin forwarding por canal del que preocuparse — está ahí mismo en `System.evtx`. El proveedor es `Service Control Manager`.

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

Eso es todo. Dos parámetros y un tag binario — mucho más pequeño que la mayoría de registros Security, razón por la cual los analistas lo saltan.

- **`param1`** — el *nombre mostrado* del servicio (no el nombre corto). `Background Intelligent Transfer Service` aquí es el nombre de cara al usuario para `BITS`. Para pivotar a la definición del servicio a menudo necesitarás el nombre corto; el SCM también lo estampa en `Binary` como un blob codificado UTF-16 (el `42 00 49 00 54 00 53 00` aquí decodifica a `BITS`).
- **`param2`** — el nuevo estado: `running`, `stopped`, `paused`, `resumed`, o uno de un puñado de intermedios pendientes (`start pending`, `stop pending`). Las transiciones `running` y `stopped` son las que la mayoría de reglas usan como clave.

No hay `AccountName`, no `ImagePath`, no `ProcessId` — 7036 te dice *qué* cambió de estado, no *quién* disparó el cambio. Para obtener el porqué, empareja con otros registros (ver abajo).

## 7036 vs 7045 vs 7035 vs 7034

Cuatro eventos del canal System relacionados con servicios se confunden constantemente:

| Evento | Cuándo | Qué te da |
|---|---|---|
| **7045** | Servicio instalado | Nombre mostrado, nombre corto, `ImagePath`, `AccountName`, `StartType`. El punto de persistencia. |
| **7036** | Arranque/parada de servicio | Solo nombre mostrado. El punto de ejecución. |
| **7035** | Control de servicio enviado | Quién inició el arranque/parada (SID), qué control se envió. Rara vez activado por defecto; valioso cuando lo está. |
| **7034** | Servicio crasheó inesperadamente | Servicio que terminó sin una parada limpia. Acción de recuperación. |

El patrón importa: **un 7045 seguido segundos después de un 7036 `running` para el mismo nombre mostrado es la secuencia de libro «instalado y ejecutado».** Un 7045 *sin* 7036 correspondiente significa que el servicio fue registrado pero nunca ejecutado — el atacante limpió, el instalador abortó, o el arranque fue diferido.

## Los patrones de triage

### 1. Verificación de persistencia — empareja con 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Tres registros, un evento de ejecución lateral PsExec. El par 7036 te dice que el servicio realmente corrió (no solo se instaló). Para un backdoor *persistente* el segundo 7036 (stopped) puede estar ausente o puede aparecer horas/días después cuando el host se reinicia.

Un 7045 sin un 7036 `running` en minutos es su propia anomalía — investiga por qué la instalación no se disparó. Causas comunes: el instalador está staged para el próximo reboot, el servicio fue configurado a manual start y el atacante aún no lo había triggereado, o el arranque falló (busca errores 7034 / 7000).

### 2. Señal de evasión de defensas — detener servicios de seguridad

El patrón más abusado: un atacante detiene `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc`, o el servicio de un producto EDR. Cada uno genera un 7036 `stopped` para el nombre mostrado correspondiente. Si se intenta tampering de audit-policy / Defender, este es uno de los registros que sobrevive.

Los nombres a alertar (nombres mostrados; varían según versión de Defender / EDR):

- `Windows Defender Antivirus Service` → servicio `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` → `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` → `Sense`
- `Security Center` → `wscsvc`
- `Windows Event Log` → `EventLog`
- Cualquier cosa coincidiendo con `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

Un 7036 `stopped` para cualquiera de estos — especialmente fuera de una ventana de mantenimiento programada — debería ser una alerta dura. Muchos atacantes usan `sc stop`, `net stop`, `Stop-Service`, o `taskkill /im` — los cuatro producen un 7036.

### 3. Typosquatting de nombre de servicio

7036 se dispara para el nombre mostrado incluso cuando el servicio subyacente es malicioso. Vigila nombres mostrados que parecen legítimos pero no coinciden con ningún servicio Microsoft instalado: `Windows Update Service` (nombre real es `Windows Update`), `Windows Defender Service` (nombre real es `Windows Defender Antivirus Service`), `Microsoft Telemetry` (no existe tal servicio). Ejecuta un baseline de nombres mostrados desde un host known-good y diffea.

### 4. Anomalías de arranque

Tras un reboot el SCM levanta los servicios auto-start en un orden aproximadamente estable. Un nuevo servicio auto-start apareciendo en la secuencia de 7036 de arranque — especialmente uno que no estaba en el arranque anterior — es un nuevo punto de persistencia. Cruza-referencia con el 7045 correspondiente en o antes del shutdown previo.

## Regla Sigma de ejemplo — servicio de seguridad detenido

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

## KQL de ejemplo — secuencia 7045 → 7036

El pivot titular. Instalación de persistencia seguida de ejecución en 5 minutos en el mismo host:

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

El `DisplayName` de 7036 no siempre será literalmente igual a `ServiceName` de 7045 (uno es display, otro es corto) — coincide heurísticamente o precomputa un mapa para el pequeño conjunto de servicios que importan.

## Splunk de ejemplo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## Mapeo ATT&CK

- **T1562.001 — Impair Defenses: Disable or Modify Tools**: 7036 `stopped` para servicios de seguridad.
- **T1543.003 — Create or Modify System Process: Windows Service**: 7036 `running` emparejado con 7045 para el mismo servicio.
- **T1569.002 — System Services: Service Execution**: 7036 `running` para un `ImagePath` apuntando a un binario no estándar, frecuentemente como parte de movimiento lateral (PsExec, ejecución remota basada en SCM).
- **T1489 — Service Stop**: dirigido a disponibilidad — detener servicios para habilitar otras acciones (ransomware deteniendo SQL Server antes de cifrar bases de datos).

## Falsos positivos que parecen exactamente ataques

- **Windows Update rutinario** reinicia una docena de servicios en una secuencia predecible. El patrón es recurrente y rápido.
- **Actualizaciones de firmas de Defender** a veces reinician `WinDefend` mismo — un `stopped` seguido rápidamente de `running` desde `MsSecFlt.exe` es el patrón normal. El malicioso es *sin* `running` tras el `stopped`.
- **Actualizaciones de EDR** detienen y reinician el servicio EDR. Etiqueta las ventanas de actualización del vendor.
- **Sleep / hibernate del sistema** genera batches de registros `stopped` al dormir y `running` al despertar. Combinado con eventos `wake source` estos son obvios; no alertes sobre ellos aisladamente.
- **Workloads de Container / Hyper-V** levantan y bajan servicios constantemente.

## Lo que 7036 no te dice

- **Sin `AccountName`**: el registro no dice bajo qué contexto de seguridad corre el servicio. Saca eso del 7045 correspondiente o de la base de datos SCM.
- **Sin PID**: no puedes mapear un 7036 directamente a un registro [4688](/es/blog/event-id-4688-process-creation) / [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) sin correlacionar por `ImagePath` y timestamp.
- **Sin iniciador**: no ves *quién* llamó a Stop-Service. Para eso necesitas 7035 (a menudo deshabilitado por defecto), [4688](/es/blog/event-id-4688-process-creation) para el `net stop` / `sc stop` / `taskkill` llamante, o [4104](/es/blog/powershell-4104-scriptblock) para `Stop-Service`.
- **Mapeo nombre-corto-servicio**: el nombre mostrado está en `param1`; el nombre corto está en el blob binario y debe ser decodificado. La mayoría de parsers lo hacen automáticamente; si consultas `EventData` crudo tienes que manejarlo.

## Dónde encaja 7036 en una timeline

El combo de ejecución lateral + evasión de defensas:

1. [**4624**](/es/blog/understanding-event-id-4624) — LogonType 3 desde un host controlado por el atacante, AuthenticationPackage Kerberos.
2. [**4688**](/es/blog/event-id-4688-process-creation) — `services.exe` spawneando un hijo para operaciones SCM (o `psexesvc.exe` de PsExec).
3. [**7045**](/es/blog/service-creation-event-id-7045) — servicio instalado, `ImagePath` fuera de rutas de instalación estándar.
4. **7036** `running` — la instalación realmente se disparó. **Esta es tu confirmación de ejecución.**
5. **7036** `stopped` para `WinDefend` / EDR — evasión de defensas antes de que corra el payload.
6. [**4688**](/es/blog/event-id-4688-process-creation) — proceso payload bajo la cuenta de servicio.
7. **7036** `stopped` para el servicio instalador — limpieza.

7036 aparece en los pasos 4, 5 y 7 — tres etapas diferentes de la misma intrusión. Por sí solo es difícil de usar; en contexto ata el registro de persistencia (7045) a la ejecución real y a las acciones de evasión de defensas circundantes.

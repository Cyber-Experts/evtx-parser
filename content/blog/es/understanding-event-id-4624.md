---
title: "Event ID 4624 de Windows: decodificar cada inicio de sesión"
description: "Qué contiene realmente un registro 4624, por qué el campo LogonType importa más que el propio evento, y cómo leerlos a escala."
date: "2026-05-17"
---

El event ID 4624 — «Se inició sesión correctamente en una cuenta» — se registra en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que Windows autentica una identidad. Es el registro más voluminoso en la mayoría de estaciones y la columna vertebral de casi toda investigación de IR. Saber leerlo no es negociable.

## Qué hay dentro de un registro 4624

Lo interesante vive en `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Los campos `Subject*` son el contexto de seguridad que *solicitó* el inicio de sesión (a menudo `S-1-5-18` para SYSTEM durante arranques de servicios). Los campos `Target*` son la identidad que finalmente se autenticó. Confundirlos cuesta horas a un analista.

## LogonType es el campo que importa

Windows define diez tipos de inicio de sesión; en la práctica solo unos pocos guían el triaje:

- **2 — Interactive**: inicio físico o por consola.
- **3 — Network**: SMB, RPC, WinRM, cualquier cosa por la red. La gran mayoría del tráfico normal.
- **4 — Batch**: tareas programadas ejecutándose con cuenta de usuario.
- **5 — Service**: servicio iniciado bajo una cuenta específica.
- **7 — Unlock**: desbloqueo tras un protector de pantalla.
- **8 — NetworkCleartext**: raro, sospechoso — credenciales en texto plano (Basic en IIS, equipos antiguos).
- **9 — NewCredentials**: `runas /netonly`, usado a menudo por atacantes para llevar credenciales de dominio a una máquina donde solo tienen permisos locales.
- **10 — RemoteInteractive**: RDP. Se combina con `IpAddress` para atribución de origen.
- **11 — CachedInteractive**: cuenta de dominio iniciada con credenciales en caché (sin DC alcanzable).

Un 4624 con LogonType **10** desde una IP externa a las 03:00 un domingo cuenta otra historia que 50 LogonType **3** desde un servidor de backup a las 02:00.

## Con qué encadenarlo

Un 4624 exitoso por sí solo rara vez es un hallazgo. Lo es cuando se combina con:

- [**4625**](/es/blog/detecting-4625-brute-force) precediéndolo desde la misma fuente — un éxito tras una ráfaga de fallos es la firma de manual de fuerza-bruta-con-éxito.
- [**4672**](/es/blog/event-id-4672-special-privileges) (privilegios especiales asignados) — marca los inicios de sesión que otorgaron privilegios como `SeDebugPrivilege`, útil para detectar uso de cuentas privilegiadas.
- **4648** (inicio con credenciales explícitas) — captura `runas` y otros patrones de paso de credenciales.

## Leerlo a escala

El parser de esta página extrae estos campos directamente del XML del registro y los muestra en la tabla. Filtra por `LogonType` mediante los buckets de la timeline y el filtro de texto (`4624` en la búsqueda), exporta el conjunto filtrado como CSV y pivota sobre `SubjectUserSid` + `IpAddress` en la herramienta que prefieras. El XML completo de cada registro está a un clic.

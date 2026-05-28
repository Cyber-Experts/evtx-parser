---
title: "Triaje de EVTX: qué leer primero cuando tienes una hora y un host"
description: "Un orden de operaciones de profesional para triar Windows Event Logs durante incident response: qué canales importan, qué event IDs te mienten y dónde hace el trabajo pesado Sysmon."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

Si alguien te entrega un bundle EVTX de un host que cree comprometido y te da una hora, no tienes tiempo para elegancia. Tienes tiempo para un orden de operaciones que ha funcionado suficientes veces como para que confíes en él antes de leer un solo registro.

Este es el mío. No es la referencia completa y no es lo correcto para cada caso, las investigaciones internas a fuego lento necesitan una postura completamente distinta, pero para la pregunta estándar "¿está esto comprometido y cómo?", esto es lo que ejecuto.

## Qué canales realmente compensan el tiempo

Una instalación de Windows por defecto trae bastante más de trescientos canales EVTX. Vas a mirar quizá siete de ellos. Los que consistentemente importan:

- `Security.evtx` logons, uso de privilegios, cambios de cuenta. Primera parada para cada incidente interactivo.
- `Microsoft-Windows-Sysmon%4Operational.evtx` si Sysmon está desplegado (y deberías rogar, suplicar, amenazar hasta que lo esté), aquí vive la señal real. Process creates con líneas de comando, file creates, conexiones de red, DNS, image loads. Todo lo que `Security.evtx` insinúa sin decirlo.
- `System.evtx` instalaciones de servicio, drivers cargados, eventos de boot, cambios de hora. A menudo el único lugar donde lateral movement deja una instalación de servicio.
- `Application.evtx` usualmente ruido, pero errores de macro de Office, excepciones .NET y algunos canales laterales de EDR afloran aquí.
- `Microsoft-Windows-PowerShell%4Operational.evtx` module logging y eventos de pipeline, si están habilitados. El log de script block `4104` es donde encuentras cada línea de PowerShell malicioso, asumiendo que el logging estaba activado. Es el segundo canal más importante después de Sysmon cuando ambos están activos.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` creación, eliminación y ejecución de tareas programadas. Se lee corto, devuelve rápido.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` suscripciones WMI y registros de consumidores. Barato de leer; atrapa un patrón de persistencia específico.

Si el host tiene Defender, agarra también `Microsoft-Windows-Windows Defender%4Operational.evtx`. La familia `1116` / `1117` es a veces la única mención contemporánea del archivo que importó.

Todo lo demás puedes dejarlo para la segunda pasada.

## Lo primero que abro no es el Security log

El reflejo por defecto es grepear `Security.evtx` por `4624`. He dejado de hacer eso en la primera pasada y probablemente tú también deberías. El Security log en un servidor ocupado loguea miles de logons legítimos por hora. Te ahogas en el ruido antes de haber formulado la pregunta.

Lo que abro primero, cuando existe, es `Sysmon%4Operational.evtx` filtrado a `EventID=1` (process create) dentro de la ventana sospechada. Sysmon te da el proceso padre, la línea de comandos tal como se invocó realmente, el usuario, el integrity level, y los hashes tanto del padre como del hijo. Eso es suficiente para leer una historia de la pantalla.

Si Sysmon no está presente (y en un número deprimente de estados Windows corporativos todavía no lo está), mi siguiente movimiento es `Security.evtx` filtrado a `4688` *con auditoría de línea de comandos habilitada*. Si las líneas de comando no están auditadas obtienes el nombre del programa solo, que es apenas útil, en ese punto salto a AmCache, Prefetch y el [USN journal](https://www.usnparser.com) para reconstruir qué se ejecutó.

El corolario que vale la pena decir en voz alta: una investigación EVTX sin Sysmon y sin líneas de comando `4688` es en gran parte un juego de adivinanzas. Si estás leyendo esto antes de un incidente, arregla eso primero.

## Los event IDs que dejas de tener que buscar

Aprendes estos de memoria con el tiempo. La versión corta, con la forma en que pienso cada uno en IR:

- `4624` logon exitoso. Lee `LogonType` primero: `3` es red (file share, herramienta remota), `10` es RDP / Terminal Services, `2` es interactivo, `9` es `runas` con credenciales explícitas. `5` es servicio. El `LogonType` lleva más significado que el evento en sí.
- `4625` logon fallido. Ráfagas son ataques spray; aislados a través de muchas cuentas son credential stuffing.
- `4634` / `4647` logoff y logoff iniciado por usuario. Útil para cerrar el corchete de una sesión.
- `4648` logon con credenciales explícitas. El que realmente quieres para atribución de lateral movement: cuando la cuenta A usa las credenciales de la cuenta B para iniciar un proceso o conectarse a algún lugar, este es el registro. La mayoría de los defensores lo subutilizan.
- `4672` privilegios especiales asignados al logon. La línea "esta cuenta acaba de volverse admin". Empareja con el `4624` que sigue.
- `4688` process create. Útil solo cuando la auditoría de línea de comandos está habilitada (Group Policy: *Audit Process Creation* y *Include command line in process creation events*). Sin eso, obtienes nombres de programa.
- `4697` servicio instalado. Lateral movement vía PsExec, Impacket-`smbexec`, y tooling similar vive aquí.
- `4720` / `4732` / `4738` cuenta creada, cambio de pertenencia a grupo, cuenta cambiada. A la persistencia le encantan estos.
- `1102` el Security log fue limpiado. Si ves esto, el resto del security log hasta ese punto es sospechoso o ausente. El hecho de que el evento exista en absoluto es la pistola humeante.
- `5140` / `5145` recurso compartido de red accedido. El último loguea el nombre del archivo; si está activado, lateral movement vía SMB es auditable en detalle.
- `7045` servicio instalado (System log). Refleja `4697` pero del canal System.
- `Sysmon 1` process create con contexto completo. El event ID más útil en DFIR si Sysmon está activado.
- `Sysmon 3` conexión de red. Atrapa C2 saliente incluso cuando Defender no lo hizo.
- `Sysmon 10` process access. El que atrapa credential dumping desde `lsass.exe`.
- `Sysmon 11` file create. Atrapa actividad de dropper que no tuvo oportunidad de ejecutarse.
- `PowerShell 4104` script block logging. Registra el texto completo de cada comando PowerShell, incluidos los ofuscados (desofuscados post-decode en muchos casos).

Mantengo una hoja chuleta impresa junto a mi escritorio y tú también deberías. No es glamoroso y ahorra minutos reales.

## Los eventos que te mienten o son fáciles de malinterpretar

`4624 Type 3` desde `\\NT AUTHORITY\ANONYMOUS LOGON` no es "el atacante está dentro". Usualmente es una enumeración de share mal configurada, un escáner de vulnerabilidades o uno de media docena de mecanismos internos de Windows. Valida antes de escalar.

`4625` contra una sola cuenta de servicio a razón de uno por minuto es casi siempre una credencial obsoleta cacheada en algún lugar. Mira el campo de workstation origen antes de llamarlo brute force.

Las marcas de tiempo en Security.evtx son hora local en el host que las generó por defecto en algunas herramientas, UTC en otras. Cuando cargas un bundle en una nueva herramienta, haz una verificación de cordura encontrando un logon que puedas correlacionar con un evento externo conocido (una actualización de ticket, una sesión VPN) y confirma los offsets. He visto reportes enteros sesgados por 4 horas porque alguien se olvidó de comprobar.

El borrado del event log (`1102`) usualmente es ruidoso, pero la eliminación selectiva de registros es otra bestia. `wevtutil cl` limpia el canal entero, lo cual es detectable. Herramientas como `phant0m` e `Invoke-Phant0m` en cambio suspenden los hilos del servicio de eventos, lo cual no deja evento de limpieza pero crea un hueco visible. Busca el hueco, no solo el `1102`.

Los forwarded events (`Microsoft-Windows-EventLog%4ForwardedEvents`) preservan el RecordID original del host de origen y las marcas de tiempo originales. Si tienes un suscriptor WEC que sobrevivió al incidente, esas copias son a veces el único registro intacto que queda.

Si el Security log muestra `1100` (shutdown del servicio de eventos) seguido de un hueco inexplicado, estás mirando uno de los intentos más limpios de borrar evidencia. Cross-valida contra [hives de registro](https://www.registryparser.com), la [Master File Table](https://www.mftparser.com) y Prefetch.

## Tallado y recuperación, cuando faltan registros

Los registros EVTX pueden ser tallados de disco no asignado y de [pagefile.sys](https://www.pagefilesysparser.com) cuando el archivo vivo ha sido limpiado o rotado. La cabecera de registro (magia `2a 2a 00 00`) es distintiva suficiente para que el tallado por firma funcione razonablemente bien. `hayabusa` de Yamato Security y `evtx_dump` manejan ambos archivos malformados con streams de registros parcheados.

Si estás lidiando con un host donde sospechas que el log ha sido manipulado, también intenta recuperar registros EVTX de un [volcado de RAM](https://www.ramparser.com). El servicio de event log cachea registros recientes en memoria; una instantánea tomada cerca del incidente a veces contiene registros que nunca llegaron al disco.

## A dónde ir desde un hit

Un solo evento rara vez cierra un caso. Los puntos de pivote a los que echo mano, en orden:

- Un `4624` sospechoso busca el `4672` correspondiente, los fallos `4625` precedentes, y qué proceso se creó con ese token después (Sysmon 1 con `LogonId` coincidente).
- Una instalación de servicio `7045` o `4697` verifica `Microsoft-Windows-TaskScheduler%4Operational.evtx` para tareas posteriores, y el [registro](https://www.registryparser.com) `HKLM\SYSTEM\CurrentControlSet\Services\` para la ruta del binario.
- Un Sysmon 10 contra `lsass.exe` árbol de procesos del proceso solicitante, drops de archivo en el directorio de trabajo, conexiones de red a destinos no corporativos.
- Un PowerShell 4104 con contenido ofuscado descodifica en un sandbox, luego busca el mismo payload aterrizando en otros hosts (la mayoría de los actores empresariales reutilizan).

## Leer EVTX en el navegador

El parser en este sitio lee EVTX enteramente del lado del cliente: suelta un archivo y obtienes una tabla ordenable y filtrable con canal, RecordID, EventID, hora, computer y el XML renderizado. Sin subida, lo cual importa porque EVTX de entornos regulados casi siempre contiene PII que no quieres cruzando un límite de vendor.

## Lecturas adicionales

- [JPCERT/CC "Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) el documento único más útil sobre correlación de eventos de lateral movement. Vale una lectura lenta.
- [EvtxECmd](https://github.com/EricZimmerman/evtx) de Eric Zimmerman parser offline con las salidas canónicas de mapeo de campos.
- La configuración de Sysmon que Microsoft Threat Intelligence (antes SwiftOnSecurity) mantiene como baseline: [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Empieza desde aquí, no escribas la tuya desde cero.

La versión cínica de todo lo anterior: con Sysmon y auditoría de línea de comandos, EVTX te da el 80% de lo que necesitas para reconstruir una intrusión. Sin ellos, estás haciendo forensia sobre la silueta del evento en lugar del evento en sí.

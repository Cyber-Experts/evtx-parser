---
title: "Empieza aquí: guía de .evtx para el analista DFIR"
description: "Qué es .evtx, qué canales importan, los Event IDs que hay que conocer y dónde encontrar cada uno en disco. Un punto de partida para todo lo demás del blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` es el formato binario del Registro de eventos de Windows que Microsoft introdujo con Vista para reemplazar el antiguo `.evt`. Es la columna vertebral de toda respuesta a incidentes en Windows: inicios de sesión, instalaciones de servicios, tareas programadas, líneas de comando de PowerShell, árboles de procesos de Sysmon. Todo eso se serializa en este formato. Esta entrada es el índice. Una orientación en una pantalla y luego enlaces a las entradas más profundas sobre los canales y Event IDs que realmente importan en un caso.

¿Nuevo con `.evtx`? Empieza por [qué es un archivo .evtx](/es/blog/what-is-an-evtx-file) y [cómo abrir uno](/es/blog/how-to-open-an-evtx-file). El resto de esta entrada asume que ya estás cómodo con el formato y quieres saber qué leer primero cuando un host está ardiendo.

## Dónde están los archivos

Los registros activos están en `C:\Windows\System32\winevt\Logs\`. Un canal, un archivo `.evtx`. Los predeterminados que siempre tendrás:

- `Security.evtx`. Inicios de sesión, uso de privilegios, cambios de política de auditoría. El valor forense más alto en la mayoría de los casos.
- `System.evtx`. Controladores, servicios, errores a nivel del sistema operativo.
- `Application.evtx`. Errores a nivel de aplicación.
- `Setup.evtx` y `ForwardedEvents.evtx`. Registros de instalación y tráfico WEF reenviado.

Más los canales por aplicación bajo `Microsoft-Windows-*`. Los que se ganan su sitio en un caso:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Solo presente si Sysmon está instalado. Vale oro cuando lo está.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Registro de bloques de script y módulos.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Creación y ejecución de tareas programadas.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo de vida de sesiones RDP.

Para los detalles profundos de cómo se distribuye un archivo (los chunks de 64 KB, las tablas de plantillas XML, BinXML), consulta [el análisis profundo a nivel de chunk](/es/blog/evtx-file-format-chunks).

## Los Event IDs que hay que conocer

La lista corta que cubre la mayor parte de aquello sobre lo que pivota un analista:

- [**4624** inicio de sesión correcto](/es/blog/understanding-event-id-4624). Léelo a través de `LogonType`. El campo decide si miras consola (2), red (3), RDP (10) o `runas /netonly` (9).
- [**4625** inicio de sesión fallido](/es/blog/detecting-4625-brute-force). Las ráfagas son reconocimiento, fuerza bruta o pulverización de contraseñas según qué campos se agrupen.
- [**1102** Registro de seguridad borrado](/es/blog/event-id-1102-cleared-log). Si lo ves, el registro que tienes en la mano tiene un hueco conocido. Anótalo en grande.
- [**4104** bloque de script de PowerShell](/es/blog/powershell-4104-scriptblock). El cuerpo del script *después* de decodificación y reflexión. El control defensivo gratuito más útil de la plataforma.
- [**7045** servicio instalado](/es/blog/service-creation-event-id-7045). Una de las técnicas de persistencia más citadas de MITRE ATT&CK (T1543.003). También la firma de PsExec.
- [**Sysmon 1** creación de proceso](/es/blog/sysmon-event-id-1-process-create). El registro de creación de proceso más rico que Windows puede producir cuando Sysmon está presente.

Para el flujo de trabajo que los une, lee [Triage de EVTX cuando tienes una hora y un host](/es/blog/evtx-triage-incident-response).

## Cómo encaja este sitio

El parser de la portada es el crate de Rust [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compilado a WebAssembly y ejecutado dentro de un Web Worker. Sueltas un `.evtx`, el worker recorre los chunks y obtienes una línea temporal de eventos filtrable más el XML por registro. Todo en el navegador, nada se sube. Úsalo para triage ad hoc cuando no quieras montar un EDR o sacar un archivo de un sistema que no es tuyo.

Si estás [recogiendo `.evtx` de un host vivo](/es/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), esa entrada cubre los cuatro métodos estándar con los compromisos de cadena de custodia que hace cada uno.

EVTX rara vez es el único artefacto que necesitas. Combínalo con parsers de [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [diario USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [prefetch](https://www.prefetchparser.com) y [LNK](https://www.lnkparser.com). Cuando hace falta cavar más hondo, el parseo del [archivo de paginación](https://www.pagefilesysparser.com) y del [volcado de RAM](https://www.ramparser.com) recupera lo que perdieron los registros en disco. Para líneas temporales de actividad del usuario, [SRUM](https://www.srumparser.com), [jump lists](https://www.jumplistparser.com), [papelera de reciclaje](https://www.recyclebinparser.com), [recent file cache](https://www.recentfilecacheparser.com) y [historial del navegador](https://www.browserforensics.app) cubren los huecos que EVTX no puede llenar.

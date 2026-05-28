---
title: "Borrado del registro de eventos y los huecos que sobreviven"
description: "Cómo los atacantes borran los registros de eventos de Windows, qué pruebas quedan en disco y en canales reenviados, y la diferencia entre wevtutil cl y herramientas de suspensión de hilos como Invoke-Phant0m."
date: "2026-05-27"
tags:
  - evtx
  - anti-forensics
  - dfir
  - incident-response
  - log-tampering
author: "Florian Amette"
---

El borrado de registros de eventos es la técnica anti-forense que todo operador aprende primero y la que deja el rastro más utilizable. Esa segunda parte es contraintuitiva. Todo el sentido de borrar logs es eliminar pruebas, y un atacante que logre borrar `Security.evtx` ha eliminado miles de eventos que querías leer. Pero el acto de borrar es en sí ruidoso, las técnicas que intentan ser más silenciosas dejan una firma distinta e igualmente diagnóstica, y los canales que la mayoría de operadores olvidan preservan suficiente para reconstruir lo borrado.

Saber qué sobrevive importa porque cambia la pregunta que haces al host. "Qué hay en el log de Security" se convierte en "qué falta en el log de Security, y a dónde más fueron esos eventos".

## 1102, 104, 1100: la forma ruidosa

El reflejo por defecto de un operador que quiere el log de Security fuera es `wevtutil cl Security`. Esto produce:

- Un único `EventID=1102` en `Security.evtx`, generado inmediatamente tras el borrado, registrando la cuenta que lo realizó y la hora. Este evento sobrevive en el log borrado porque es el primer evento escrito en el archivo recién borrado. Trátalo como la pistola humeante. El nombre de cuenta, la estación origen y la hora del borrado están todos en los datos del evento.
- Un `EventID=104` correspondiente en `System.evtx` del proveedor `Microsoft-Windows-Eventlog`, con el nombre del canal borrado. Es el espejo en System de `1102`. A veces solo sobrevive uno de los dos porque el operador borró múltiples canales y el orden importa.
- Un `1100` del servicio Event Log indicando apagado del servicio, si el operador detuvo el servicio antes de borrar. La combinación de `1100` seguida de un hueco inexplicado seguida de `1102` es el patrón clásico de "apagar, manipular, reiniciar".

Estos tres eventos son la firma ruidosa. Un atacante que sabe lo que hace no los generará, o los generará y luego borrará *otra vez* para eliminarlos, lo que produce un segundo `1102` y un log superviviente aún menor. Cada pasada de borrado deja un `1102`. El hecho de que un host tenga múltiples `1102` en su historia es en sí anómalo.

Los eventos que se borran no son las únicas víctimas. Borrar un canal resetea el archivo EVTX subyacente, lo que significa que el archivo en disco se reescribe. Los chunks del archivo viejo quedan no asignados. Son recuperables del disco si se imagena el host en una ventana razonable, que es la otra rama de esta historia (cubierta en el post de carving).

## `wevtutil cl` frente a suspensión de hilos

Un operador más sofisticado no borra los logs en absoluto. Suspende los hilos del servicio Windows Event Log (`eventlog`), hace la cosa ruidosa que quiere hacer, y reanuda los hilos. Mientras los hilos están suspendidos, los eventos generados por el SO y aplicaciones se ponen en cola en la infraestructura ETW pero no se escriben al archivo EVTX. Al reanudar los hilos, la cola se vacía mayormente, pero los eventos que desbordaron el buffer durante la ventana de suspensión se pierden para siempre.

Esto es lo que hace `Invoke-Phant0m` (PowerShell, por Halil Dalabasmaz). El módulo de Mimikatz `event::drop` hace algo similar pero opera enganchando el callback ETW dentro del proceso del servicio. Ambos dejan:

- Sin `1102`. No se borró nada.
- Sin `104`. Misma razón.
- Un hueco. Eventos de antes y después de la ventana de suspensión están presentes; los de dentro faltan. Esa es la detección.

El hueco es detectable de dos formas. La primera es una comprobación de cordura de RecordID contiguos: la cabecera de chunk EVTX registra `FirstEventRecordIdentifier` y `LastEventRecordIdentifier`, y puedes verificar que los IDs de registro son monótonos entre chunks. La suspensión no rompe el contador de RecordID (el servicio está suspendido, no el proveedor ETW del kernel), pero los timestamps dentro del chunk mostrarán una ventana sin eventos de proveedores activos, que en un controlador de dominio es escandalosamente obvio.

La segunda es la correlación contra canales que no puedes suspender sin volver a elevar. El canal `Microsoft-Windows-EventLog%4Operational.evtx` registra el ciclo de vida del propio servicio de event log. La suspensión de hilos no genera eventos explícitos de "hilo suspendido" aquí, pero el heartbeat interno del servicio (eventos `105`, `106`, y eventos de depuración específicos del proveedor cuando el canal Operational está a verbosidad alta) a veces registra la inconsistencia.

La tercera, más difícil, es el rastro [Sysmon](https://github.com/SwiftOnSecurity/sysmon-config). Sysmon escribe a su propio canal mediante su propio driver y no se ve afectado por la suspensión del servicio event log. Un host con Sysmon tendrá un registro continuo de creaciones de procesos y cargas de imagen a través de la ventana de suspensión. Cruza el tiempo del supuesto hueco en `Security.evtx` contra el canal `Operational` de Sysmon; si Sysmon muestra un proceso `powershell.exe` con contenido de línea de comandos que coincida con el código fuente de Phant0m (o cualquiera de las docenas de variantes públicas) corriendo al inicio del hueco, tienes tu respuesta.

## El canal de eventos reenviados

Windows Event Collector (WEC) es el mecanismo estándar para reenviar eventos a un colector central. Los eventos reenviados llegan al colector en `Microsoft-Windows-EventLog%4ForwardedEvents` (en los suscriptores Windows Event Collector) y conservan el campo `Computer` del host originario, el `RecordID` original y los timestamps originales.

Si tu entorno tiene WEC y el colector mismo no fue comprometido, el canal de eventos reenviados es a veces el único registro intacto de lo que pasó en un host cuyo log local fue borrado. Los eventos son idénticos byte a byte a los generados en el host originario (módulo metadatos añadidos por el colector), y el `RecordID` del host originario te permite coser la copia reenviada de vuelta en la línea temporal del RecordID del log local.

La pega: las subscripciones WEC son pull por defecto, con heartbeat de 15 minutos. Un atacante de movimientos rápidos puede borrar el log local entre heartbeats de forwarding y el colector solo tendrá los eventos previos al último pull exitoso. Configura las subscripciones en modo `MinLatency` (push, con latencia de batch de 30 segundos) en los canales que te importan. Cuesta throughput de red y colector; se paga la primera vez que lo necesitas.

La otra pega: WEC no reenvía por defecto. Si nadie configuró la subscripción, el canal del colector está vacío. Comprueba el estado de subscripción en colectores candidatos antes de apostar una investigación a esta vía probatoria.

## Borrado selectivo y la cuestión a nivel EVTX

El borrado selectivo de registros (eliminar eventos específicos de un EVTX vivo dejando el resto) es teóricamente posible editando el archivo con conocimiento del formato y recalculando los CRCs de chunk. En la práctica nadie lo hace en operaciones vivas porque el servicio event log tiene el archivo abierto y bloqueado; no puedes editarlo desde user-land sin tirar el servicio, y tirar el servicio genera eventos `1100`/`105`.

Lo que sí pasa en libertad es la manipulación offline a posteriori. Un operador que exfiltra el archivo EVTX, lo edita en su propia máquina y lo re-sube para reemplazar el archivo vivo (tras detener el servicio) dejará:

- CRCs inconsistentes en los chunks editados, salvo que recalcule correctamente tanto el CRC de cabecera de chunk como el CRC de la región de registros.
- `LastEventRecordNumber` inconsistentes en cabeceras de chunk si tampoco las actualizó.
- Discontinuidades en RecordIDs a través de límites de chunk.

Cualquier parser decente las marca. `evtx_dump` avisará de mismatch de CRC por defecto. `EvtxECmd` registra la discrepancia en su salida. Trata cualquier aviso de CRC durante el parseo de un EVTX de un host presuntamente comprometido como un indicador potencial de manipulación e imagena el disco subyacente antes de hacer nada más.

## Lo que sale solo en `Microsoft-Windows-EventLog%4Operational.evtx`

Este canal es separado de `Security.evtx` y la mayoría de atacantes lo ignoran. Registra:

- Inicio y parada del servicio event log (`105`, `106`).
- Cambios de estado de canal (subscripción iniciada, canal habilitado/deshabilitado).
- Eventos de registro de manifiesto.

Cuando el servicio Event Log se reinicia (porque el operador usó `Stop-Service eventlog`, o porque parchearon algo y rebootearon), obtienes eventos aquí que emparejan con la familia `1100`/`105`/`106`. Si `Security.evtx` muestra `1100` a la hora T y `EventLog%4Operational.evtx` muestra un cambio de estado de servicio correspondiente a la misma T, el apagado fue ordenado. Si `Security.evtx` muestra un hueco sin `1100` pero `EventLog%4Operational.evtx` muestra que el servicio fue reiniciado, el servicio crasheó o fue matado sin apagado ordenado, lo que es sospechoso en sí.

Este canal es pequeño y se lee rápido. Añádelo a tu checklist de triaje por defecto.

## Cross-validación contra artefactos de host

Cuando el log de Security se ha ido o ha sido doctored, los artefactos que sobreviven son los sospechosos habituales:

- La [Master File Table](https://www.mftparser.com) del propio archivo EVTX. Los timestamps `$STANDARD_INFORMATION` y `$FILE_NAME` mostrarán cuándo se reescribió el archivo por borrado.
- El [diario USN](https://www.usnparser.com) para eventos `DATA_OVERWRITE` y `DATA_TRUNCATION` en `Security.evtx`. Estos muestran el borrado en términos de journal con timestamps de alta resolución.
- [Prefetch](https://www.prefetchparser.com) para ejecución de `wevtutil.exe`, o para ejecuciones de `powershell.exe` que cuadraran con el borrado sospechoso.
- [Shimcache](https://www.shimcacheparser.com) y [AmCache](https://www.amcacheparser.com) para el tooling que el operador trajo para realizar el borrado, particularmente si usó un binario no por defecto.
- Artefactos de [volcado RAM](https://www.ramparser.com) si capturaste uno. La caché en memoria del servicio event log tendrá registros que nunca se flushearon al disco.

El log de Security es una fuente. Trátalo como una fuente. La investigación que depende solo de él está a un archivo manipulado de ser inútil. El [parser de este sitio](https://www.evtxparser.com) marca mismatches de CRC de chunk y huecos de RecordID en su salida, que es el chequeo barato de primera pasada para saber si miras un log manipulado antes de haber invertido una hora leyéndolo.

## Lectura adicional

- El [código fuente de Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) de Halil Dalabasmaz. Lee lo que hace. La detección se sigue directamente.
- La [entrada del ThreatHunter-Playbook sobre 1102](https://threathunterplaybook.com/hunts/windows/180815-WindowsLogCleared.html) de Roberto Rodriguez y el material de detección de clearing adyacente.
- La documentación de Microsoft sobre [subscripciones de Windows Event Collector](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription) para la configuración WEC que te da la red de seguridad de eventos reenviados.

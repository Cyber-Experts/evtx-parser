---
title: "Ejecutar reglas Sigma sobre EVTX en el navegador"
description: "2.395 reglas de SigmaHQ sobre registros .evtx de Windows sin instalar Hayabusa ni Chainsaw: detección Sigma en el navegador, contexto ATT&CK, pivotes y sus propias reglas YAML."
date: "2026-09-29"
tags:
  - evtx
  - dfir
  - threat-hunting
  - sigma
  - sysmon
author: "Florian Amette"
---

Sigma es lo más parecido a un idioma común que tiene la ingeniería de detección. Una regla describe *cómo* se ve lo sospechoso — un proceso, una escritura en el registro, un inicio de sesión del tipo equivocado — y un backend la traduce al idioma de su SIEM. Para registros de eventos que están en el portátil de un analista, la respuesta habitual es una herramienta de línea de comandos como Hayabusa o Chainsaw: descargar un binario, apuntarlo a una carpeta de archivos `.evtx`, leer el CSV.

Funciona, pero supone que puede ejecutar un binario sin firmar en la máquina donde está la evidencia y que tiene tiempo para prepararlo. Este visor ahora ejecuta el conjunto de reglas de SigmaHQ directamente en la pestaña del navegador, junto a los eventos. No se instala nada y no se sube nada.

## Qué obtiene al soltar un registro

Abra uno o varios archivos `.evtx` como siempre. En cuanto termina el análisis, el Web Worker del parser ejecuta cada regla incluida sobre cada registro, y la pestaña **Sigma** muestra una insignia con el número de reglas que detectaron algo.

Dentro de la pestaña:

- Las reglas detectadas se agrupan por nivel — crítico, alto, medio, bajo, informativo — con el número de eventos de cada una.
- Al seleccionar una regla se muestran su descripción, las tácticas y técnicas de MITRE ATT&CK (enlazadas a attack.mitre.org), los falsos positivos que documentó el autor, las referencias, la fuente de registros y el ID de la regla.
- Los eventos detectados se listan con los campos que la regla comprobó realmente. Haga clic en una marca de tiempo para abrir el evento en la tabla principal; **Alrededor de este evento** fija el rango horario en una ventana a su alrededor para ver qué pasó justo antes y justo después.
- **Ver en la tabla de eventos** limita la tabla a las detecciones de esa regla, de modo que la búsqueda, la barra de campos y las exportaciones trabajan sobre ellas.
- El rango horario existente se aplica: acótelo a la ventana del incidente y los contadores lo siguen.
- **Exportar detecciones** genera un CSV o un JSON con el ID, el título y el nivel de la regla, el número de registro, la hora, el equipo, el canal y los valores de los campos clave.

Si los ID de evento implicados le resultan nuevos, [Sysmon Event ID 1](/es/blog/sysmon-event-id-1-process-create) y [Security 4688](/es/blog/event-id-4688-process-creation) son los dos registros que acaban examinando la mayoría de las reglas.

## Qué reglas, y cómo se corresponden con EVTX

El conjunto de reglas es `rules/windows/**` de una versión fijada de SigmaHQ (r2026-07-01 en el momento de escribir). Se descarga al compilar y se distribuye con el sitio como un archivo JSON, así que el navegador nunca contacta con GitHub; la Content Security Policy del sitio tampoco lo permitiría. De 2.403 reglas de Windows, se ejecutan 2.395. Las 8 excluidas usan las categorías `file_access` y `file_rename`, que proceden de proveedores ETW que nunca escriben en un archivo `.evtx`. Las reglas obsoletas no se importan.

Una regla Sigma nombra una fuente de registros, no un archivo. La correspondencia es la que usan Hayabusa, Chainsaw y pySigma:

- `category: process_creation` se aplica a Sysmon Event ID 1 **y** a Security 4688. En el 4688 los campos se traducen: `Image` lee `NewProcessName`, `ParentImage` lee `ParentProcessName`, `IntegrityLevel` se deriva de `MandatoryLabel` y los ID de proceso hexadecimales se convierten.
- Las demás categorías de Sysmon corresponden a sus Event ID: conexiones de red al 3, cargas de imagen al 7, acceso a procesos al 10, creación de archivos al 11, registro al 12–14, DNS al 22.
- `ps_script` y `ps_module` leen los 4104 y 4103 de PowerShell Operational; las reglas clásicas `ps_classic_start` leen el 400 de Windows PowerShell, donde `HostApplication=` y similares se extraen del bloque `Data`.
- `service: security`, `system`, `windefend`, `taskscheduler`, `bits-client` y una cuarentena más corresponden a su canal.

Un 4688 no tiene `OriginalFileName`, `Hashes` ni `CurrentDirectory`, así que las reglas que solo dependen de esos campos no pueden dispararse con él. Es una propiedad del registro, no del motor: si quiere que esas reglas funcionen, recopile Sysmon.

## Traiga sus propias reglas

El botón **Sus reglas** acepta YAML pegado en un cuadro de texto o archivos `.yml` soltados encima (varias reglas separadas por `---` no son problema). Cada regla se analiza y compila en el worker; los errores se indican regla por regla y las válidas se suman a la siguiente ejecución:

```yaml
title: Servicio instalado desde un perfil de usuario
id: 3b0f0b6e-6b1d-4e36-9a44-6d2f7d8f7a11
author: Su nombre
level: high
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains: '\Users\'
  condition: selection
```

Sus reglas se quedan en el almacenamiento local de este navegador para sobrevivir a una recarga. Nunca se envían a ninguna parte.

## Qué admite el motor

El motor implementa la parte de detección de la especificación Sigma: selecciones como mapas y listas, búsquedas por palabras clave, comodines con las reglas de escape de Sigma y los modificadores `contains`, `startswith`, `endswith`, `all`, `exists`, `re` (con `i`, `m`, `s`), `cased`, `base64`, `base64offset`, `utf16le`, `utf16be`, `wide`, `windash`, `cidr`, `gt`, `gte`, `lt`, `lte` y `fieldref`. Las condiciones admiten `and`, `or`, `not`, paréntesis, `1 of`, `all of` y `them`.

Hay dos cosas que deliberadamente no se admiten, y la herramienta lo dice en lugar de saltárselas en silencio: las condiciones de agregación (`| count() by …`) y las reglas de correlación de Sigma. Ninguna de las reglas de Windows incluidas las usa; si pega una, aparece como no cargada junto con el motivo.

## ¿Es lo bastante rápido?

Ejecutar 2.400 reglas de forma ingenua sobre cada evento sería lento: un solo registro de creación de proceso de Sysmon es candidato para unas 1.200 reglas. El motor agrupa las reglas por canal y Event ID y da a cada regla un prefiltro literal — por ejemplo, `Image` debe terminar en `\certutil.exe` o `CommandLine` debe contener `urlcache`. Esos literales se indexan por campo, las subcadenas en un autómata de Aho–Corasick, de modo que cada registro solo ejecuta el puñado de reglas cuyo prefiltro se activó. En la batería de pruebas, 200.000 eventos sintéticos contra el conjunto completo tardan unos cinco segundos, y el worker informa del progreso y sigue respondiendo mientras tanto.

Para una colección muy grande — los registros de todo un dominio — una herramienta nativa en una estación de trabajo seguirá siendo más rápida. Para el equipo que tiene delante, normalmente termina antes de que acabe de leer el panel de hallazgos. Si necesita un punto de partida para esa primera hora, vea [qué leer primero en el triaje de EVTX](/es/blog/evtx-triage-incident-response).

## Mérito a quien corresponde

Las reglas son obra de la comunidad SigmaHQ y se publican bajo la Detection Rule License 1.1. Cada detección muestra «Regla de *autor* · SigmaHQ · DRL 1.1» con un enlace a la regla original, y cada fila exportada lleva la misma atribución. Si una regla le ayuda a cerrar un caso, su sección de referencias suele apuntar a la investigación que la respalda; merece la pena leerla.

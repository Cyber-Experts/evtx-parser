---
title: "El formato de archivo EVTX, descodificado"
description: "Un recorrido práctico por el formato binario EVTX: cabecera del archivo, chunks ELFCHNK, plantillas BinXML, arrays de sustitución y por qué parsear esto es más difícil de lo que parece."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

El viejo formato EVT era casi legible con un editor hexadecimal y paciencia. EVTX no lo es. Microsoft lo reemplazó en Vista con algo diseñado para throughput de escritura y consumo por máquina, y el efecto colateral es que todo el que quiere leer un archivo EVTX termina reimplementando las mismas pocas cientos de páginas de las notas de reverse-engineering de Andreas Schuster. El formato está documentado en `[MS-EVEN6]` solo a nivel de protocolo. La estructura on-disk tienes que descifrarla tú mismo o tomarla prestada de `libevtx`.

Este post es la versión de eso que ojalá hubiera tenido cuando empecé.

## La cabecera del archivo, brevemente

Cada archivo EVTX abre con una cabecera de 4096 bytes. La magia es `ElfFile\0` en offset 0. Después de eso los campos que realmente te importan durante el triaje:

- `FirstChunkNumber` y `LastChunkNumber` índices de chunk, no offsets de bytes.
- `NextRecordIdentifier` el siguiente RecordID que se escribiría. Útil para detectar truncamiento.
- `HeaderSize` casi siempre 128, con el resto de los 4096 bytes rellenado con ceros.
- `MinorVersion` / `MajorVersion` `3.1` es la versión que escribe cada Windows moderno.
- `FileFlags` bit 0 puesto significa que el archivo está sucio (no cerrado limpiamente), bit 1 significa que ha estado "lleno" y está rotando. Ambos importan para la interpretación forense.
- Un CRC32 sobre los primeros 120 bytes de la cabecera. Las herramientas que ignoran el CRC parsearán alegremente cabeceras corruptas; las que lo aplican rechazarán archivos de los que aún puedes recuperar registros. Saber cuál es la tuya.

Después de la cabecera, obtienes una secuencia de chunks de 65.536 bytes. Siempre 64 KB, siempre alineados. Esta es la unidad que Windows escribe atómicamente, y es la unidad que tallas.

## ELFCHNK: la cabecera del chunk

Cada chunk empieza con `ElfChnk\0` en el límite del chunk. La cabecera es de 512 bytes y lleva los campos que hacen posible el parseo:

- `FirstEventRecordNumber` y `LastEventRecordNumber` el rango de RecordID cubierto por este chunk.
- `FirstEventRecordIdentifier` y `LastEventRecordIdentifier` lo mismo, conservado por legacy.
- `FirstEventRecordOffset` dónde empiezan los bytes del primer registro dentro de este chunk.
- `LastEventRecordOffset` dónde empieza el último registro. Si esto está pasado del final del chunk poblado, el chunk ha sido escrito parcialmente; el writer crasheó.
- Una `StringTable` y una `TemplateTable`, ambas tablas hash indexadas por hashes estilo FNV, apuntando dentro del payload BinXML del chunk.
- Dos CRCs: uno sobre la cabecera, uno sobre el área de registros.

Las tablas de strings y plantillas son la parte que despista a la gente. Plantillas y strings se almacenan *una vez por chunk* y se referencian por offset dentro del chunk. Esto significa que no puedes parsear significativamente un registro de forma aislada. Necesitas su chunk envolvente, con sus tablas resueltas, para renderizar el XML del registro. Talla un registro sin su chunk y obtendrás un array de sustitución sin plantilla en la que sustituir.

`NumLogRecords` vive implícitamente como `LastEventRecordNumber - FirstEventRecordNumber + 1`. Alguna documentación temprana lo nombraba; los parsers modernos lo calculan.

## Codificación de EventRecord

Pasada la cabecera del chunk obtienes registros, espalda con espalda, hasta que el chunk esté lleno o el resto esté en ceros. Cada registro empieza con la magia `2a 2a 00 00` (lo que hace factible el carving por firma desde disco crudo, más sobre eso en otro post) seguido de:

- `Size` longitud total del registro incluyendo la repetición de tamaño al final.
- `EventRecordIdentifier` el RecordID monotónicamente creciente.
- `WriteTime` un FILETIME de Windows, ticks de 100 ns desde 1601-01-01 UTC.
- El payload BinXML.
- `Size` otra vez, repetido al final para que un lector pueda recorrer registros hacia atrás.

El payload BinXML es donde empieza el trabajo de verdad.

## BinXML y el modelo plantilla/sustitución

BinXML es un stream de tokens que codifica XML como opcodes binarios. Los opcodes que importan:

- `0x00` end-of-stream.
- `0x01` open start tag (con atributos).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, seguido de un `ValueType` y los bytes del valor.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` normal substitution.
- `0x0e` conditional substitution.
- `0x0f` start of stream (con un preámbulo de 3 bytes).

El writer del log de eventos de Windows casi nunca emite XML crudo para un evento. Emite una *instancia de plantilla* (`0x0c`), que referencia una definición de plantilla (almacenada una vez por chunk por ID) y suministra un *array de sustitución* que contiene los valores de variable para esa plantilla. Para renderizar un único registro XML legible por humanos necesitas:

1. Localizar la plantilla en la tabla de plantillas del chunk por su ID y offset.
2. Recorrer el BinXML de la plantilla, tratándolo como un esqueleto con placeholders de sustitución numerados.
3. Para cada placeholder, buscar la entrada correspondiente en el array de sustitución, verificar su tipo contra el tipo declarado del placeholder, e inlinearla.

El array de sustitución tiene entradas tipadas: UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, más strings ya sea en UTF-16LE inline o por referencia de offset, más arrays de cualquiera de los anteriores. El tipo 0x21 es "BinXML" lo que significa que la sustitución es en sí misma un stream BinXML anidado, lo que significa que los parsers necesitan recursar. Aquí es donde caen las implementaciones ingenuas.

Dos trampas que vale la pena señalar:

- Las plantillas pueden ser referenciadas desde *otros* registros en el mismo chunk por offset. Si construyes un parser que resuelve plantillas solo cuando ve su declaración inline, vas a perder registros que referencian una plantilla anterior solo por ID.
- El tipo de "conditional substitution" (`0x0e`) significa: sustituir si el valor no es nulo, en caso contrario omitir el elemento padre. Saltarse esta distinción produce XML que parece bien pero tiene elementos vacíos donde el log real no tendría nada.

## Por qué esto es más difícil que parsear EVT

EVT era un archivo plano de registros de forma fija. Los strings se almacenaban inline. Podías escribir un parser en una tarde.

EVTX es un formato paginado, optimizado para escritura, autodeduplicante. El mismo string ("Microsoft-Windows-Security-Auditing") se almacena una vez por chunk y se referencia desde cada registro que lo usa. El mismo esqueleto XML ("un evento 4624") se almacena una vez por chunk como plantilla, y cada registro 4624 en ese chunk es un array de sustitución contra él. El estado entre registros importa. El estado entre chunks no, lo que es la gracia salvadora: pierde un chunk y pierdes sus registros, pero el resto del archivo es recuperable.

Esta deduplicación es lo que hace EVTX lo suficientemente pequeño como para mantenerlo en hosts ocupados y lo que hace que los parsers ingenuos estén mal. Si alguna vez has visto un EVTX "parseado" donde el campo `Provider` de cada registro dice "Unknown", has visto un parser que no resolvió la tabla de strings.

## Las herramientas que realmente funcionan

- `python-evtx` (Willi Ballenthin) lento, Python puro, pero la implementación de referencia más limpia. Lee su código fuente antes de escribir el tuyo.
- `evtx_dump` del crate Rust `evtx` de Omer Ben-Amram rápido, robusto, el default para volcado por línea de comandos. Salida JSONL que se pipea a cualquier cosa.
- `libevtx` y `evtxtools` (Joachim Metz) biblioteca C, la referencia canónica para el formato. Los bindings Python (`pyevtx`) son más lentos que `python-evtx` en algunas cargas pero manejan mejor los casos extremos.
- `EvtxECmd` de Eric Zimmerman .NET, sin duda el mejor para trabajo de campo de IR por su sistema de maps. Los maps son archivos YAML que aplanan las sustituciones de EventData en columnas nombradas, que es lo que quieres para trabajo de grep y timeline. Empareja con `Timeline Explorer`.
- El parser en este sitio basado en navegador, útil cuando no quieres subir datos regulados a un vendor y no tienes tu kit en la caja desde la que trabajas.

Si estás escribiendo un parser desde cero (no lo hagas, pero si debes), el corpus de prueba contra el que validar son las muestras EVTX públicas del repo del [póster SANS DFIR](https://github.com/forensicmatt/EVTX-ETW-Resources) y los logs de muestra `hayabusa` de Yamato Security. Cubren los casos de chunk malformado y registro parcial en los que tu código va a equivocarse en la primera pasada.

La otra cosa que vale la pena decir: el formato se comparte con otros artefactos de Windows. La misma codificación FILETIME aparece en el [registro](https://www.registryparser.com), en marcas de tiempo `$STANDARD_INFORMATION` de [MFT](https://www.mftparser.com), en cabeceras de [Prefetch](https://www.prefetchparser.com). Vuélvete bueno leyendo FILETIME mentalmente y mucha forensia de Windows se vuelve más silenciosa.

## Lecturas adicionales

- El original de Andreas Schuster ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007). El paper de reverse-engineering que cita todo desde entonces.
- La [especificación de formato libevtx de Joachim Metz](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc). Lo más cercano a una referencia completa.
- El [código fuente de python-evtx de Willi Ballenthin](https://github.com/williballenthin/python-evtx). Lee `Evtx/Nodes.py` para la jerarquía de nodos BinXML.
- El [crate Rust evtx de Omer Ben-Amram](https://github.com/omerbenamram/evtx). El camino rápido sobre el que se asienta la mayoría del tooling moderno.

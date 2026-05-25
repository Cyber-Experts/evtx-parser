---
title: "Formato de archivo EVTX explicado: chunks, plantillas e internos de BinXML"
description: "Cómo se distribuye un archivo .evtx a nivel de byte — cabecera de archivo, chunks de 64 KB, la tabla de plantillas y el stream de registros BinXML que la referencia."
date: "2026-05-17"
---

El [formato Windows Event Log — `.evtx`](/es/blog/what-is-an-evtx-file) — fue introducido con Windows Vista para reemplazar el `.evt` orientado a líneas. Es un contenedor binario, append-only, chunked, diseñado para ser escrito por un único proceso (el servicio EventLog) y rotado o sellado cuando se llena. Entender cómo está distribuido hace que los casos de recuperación forense — archivos parciales, dirty chunks, carving — sean mucho más fáciles.

## Cabecera de archivo

Cada `.evtx` comienza con una cabecera de 4 KB (magic `ElfFile\0\0`, versión, conteo de chunks, índices del chunk más antiguo/actual, y un CRC32). La cabecera se reescribe in-place cada vez que el archivo es rotado o un chunk es sellado, lo que hace que sus flags `Dirty` y `Full` sean indicadores útiles: un archivo con `Dirty` configurado estaba abierto cuando el host crasheó o la imagen de disco fue adquirida en vivo.

Tras la cabecera viene una secuencia de chunks de tamaño fijo.

## Chunks (64 KB)

Cada chunk es exactamente 64 KB y tiene su propia cabecera de 512 bytes (magic `ElfChnk\0`, IDs de log record del primer y último registro del chunk, offsets de archivo, dos CRC32 — uno para la cabecera, uno para los datos del registro). Los chunks son independientes: puedes carvear un chunk de espacio no asignado y parsearlo sin el resto del archivo. Esto es lo que hace que EVTX sea recuperable desde fragmentos de disco.

Dentro de un chunk:

- **Tabla de strings** — strings internados dentro de este chunk, referenciados por offset.
- **Tabla de plantillas** — plantillas XML usadas por registros en este chunk, también indexadas por offset.
- **Registros** — un stream de registros BinXML, cada uno referenciando una plantilla más valores de sustitución por registro.

## BinXML y plantillas

Los registros EVTX no se almacenan como texto XML. Se almacenan como **BinXML**, una representación binaria tokenizada de un documento XML. Para ahorrar espacio, el esqueleto estructural (nombres de elementos, nombres de atributos, la forma del árbol) se factoriza en una **plantilla** almacenada una vez en la tabla de plantillas del chunk. Cada registro entonces dice «usa la plantilla ID 5, con valores [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]».

Para reconstruir el XML de un registro, un parser:

1. Lee el stream de tokens del registro.
2. Busca la plantilla por ID en la tabla de plantillas del chunk.
3. Sustituye los valores por registro en las posiciones de placeholder de la plantilla.
4. Emite el XML resultante.

Por eso los [parsers](/es/blog/how-to-open-an-evtx-file) (incluido el que alimenta esta página, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) necesitan rastrear el contexto chunk-local — los IDs de plantilla no son globales en todo el archivo.

## Chunks sellados vs dirty

Cuando el servicio EventLog termina de escribir un chunk y se mueve al siguiente, calcula y escribe el CRC32 del chunk y marca la cabecera del chunk como `Full`. Un archivo limpio tiene cada chunk en este estado excepto el último.

Un chunk `Dirty` — tiempo de última modificación posterior a la última actualización de la cabecera del archivo — es la cola viva. A menudo es parseable, pero las herramientas a veces se niegan a leerlo porque el stream de registros puede terminar a mitad de token. Para forense esto importa: un atacante que adquirió un host a mitad de escritura verá un dirty trailing chunk, y el comportamiento de tu parser en ese chunk necesita ser conocido (¿salta, da error o recupera lo que puede?).

## Implicaciones prácticas para el parsing

- Un `.evtx` truncado — común cuando [recolectas desde un host vivo](/es/blog/collecting-evtx-from-live-system) — a menudo todavía es mayormente recuperable, porque cada chunk completo es independiente.
- Los chunks carveados de no-asignado pueden envolverse con una cabecera de archivo sintética y parsearse.
- Un parse fallido de un chunk no significa fallo del archivo — los parsers robustos siguen al siguiente chunk.
- El CRC32 del chunk es lo que señala tampering: un registro modificado que no recomputa el CRC es detectable.

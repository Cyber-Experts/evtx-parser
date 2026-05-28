---
title: "Formato de archivo EVTX explicado: chunks, plantillas e internos de BinXML"
description: "Cómo se dispone un archivo .evtx a nivel de byte: cabecera de archivo, chunks de 64 KB, la tabla de plantillas y el flujo de registros BinXML que la referencia."
date: "2026-05-17"
---

El [formato de Registro de eventos de Windows `.evtx`](/es/blog/what-is-an-evtx-file) llegó con Vista para reemplazar al `.evt` orientado a líneas. Es un contenedor binario, append-only, en chunks, escrito por un único proceso (el servicio EventLog) y rotado al llenarse. La mayoría de analistas nunca necesitan saber cómo está dispuesto a nivel de byte. Los que carvan registros de espacio no asignado, parsean a mano chunks dañados o discuten con un parser que se niega a leer un archivo truncado, sí.

Este post es la versión práctica. Suficientes internos para depurar un parseo roto, no tantos como para acabar escribiendo tu propio parser desde cero.

## Cabecera de archivo

Cada `.evtx` empieza con una cabecera de 4 KB. El magic es `ElfFile\0\0`. Los campos relevantes para un investigador son versión, conteo de chunks, índices de chunk más antiguo y actual, y un CRC32 sobre la propia cabecera. La cabecera se reescribe en su sitio cada vez que el archivo rota o se sella un chunk, así que sus flags `Dirty` y `Full` son pistas útiles. Un archivo con `Dirty` puesto estaba abierto cuando el host crasheó o cuando se adquirió la imagen de disco en vivo.

Tras la cabecera viene una secuencia de chunks de tamaño fijo.

## Chunks: 64 KB cada uno

Cada chunk son exactamente 65.536 bytes y tiene su propia cabecera de 512 bytes. El magic del chunk es `ElfChnk\0`. La cabecera lleva los RecordIDs del primer y último registro del chunk, los offsets del archivo y dos CRC32: uno sobre la cabecera, otro sobre los datos del registro.

Los chunks son independientes. Puedes carvar un chunk de espacio no asignado y parsearlo sin el resto del archivo. Esto es lo que hace EVTX [recuperable desde fragmentos de disco](/es/blog/carve-deleted-evtx-records), y también lo que hace el formato más amigable para el utillaje forense que algo comprimido sobre todo el archivo.

Dentro de un chunk:

- **Tabla de strings.** Strings internados dentro de este chunk, referenciados por offset.
- **Tabla de plantillas.** Plantillas XML usadas por registros en este chunk, también indexadas por offset.
- **Registros.** Un flujo de registros BinXML, cada uno referenciando una plantilla más valores de sustitución por registro.

## BinXML y plantillas

Los registros EVTX no se almacenan como texto XML. Se almacenan como **BinXML**, una representación binaria tokenizada de un documento XML. Para ahorrar espacio, el esqueleto estructural (nombres de elementos, nombres de atributos, forma del árbol) se factoriza en una **plantilla** almacenada una vez en la tabla de plantillas del chunk. Cada registro entonces dice "usa plantilla ID 5, con valores [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

Para reconstruir el XML de un registro, un parser:

1. Lee el flujo de tokens del registro.
2. Busca la plantilla por ID en la tabla de plantillas del chunk.
3. Sustituye los valores por registro en las posiciones de marcador de la plantilla.
4. Emite el XML resultante.

Por eso los parsers (el [parser de navegador de este sitio](/es/blog/how-to-open-an-evtx-file), el crate [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) en Rust que envuelve, y python-evtx, todos comparten este requisito) necesitan rastrear contexto local al chunk. Los IDs de plantilla no son globales en el archivo. Dos chunks pueden tener tablas de plantillas totalmente distintas; el mismo número de ID de plantilla significa cosas distintas en cada uno.

Esta es también la razón más común por la que los analistas ven "XML basura" cuando intentan decodificar a mano un registro que sacaron con `xxd`. Sin la tabla de plantillas, los valores de sustitución son solo una bolsa de valores tipados sin esquema.

## Chunks sellados frente a dirty

Cuando el servicio EventLog acaba de escribir un chunk y pasa al siguiente, calcula y escribe el CRC32 del chunk y marca la cabecera del chunk como `Full`. Un archivo limpio tiene cada chunk en este estado salvo el último.

Un chunk `Dirty` (hora de última modificación tras la última actualización de la cabecera del archivo) es la cola en vivo. A menudo es parseable, pero las herramientas a veces se niegan a leerlo porque el flujo de registros puede terminar en medio de un token. Para forense esto importa: un bundle [recogido desde un host vivo](/es/blog/collecting-evtx-from-live-system) tendrá un chunk dirty al final en el canal activo, y el comportamiento de tu parser en ese chunk hay que conocerlo. ¿Salta el chunk, errora en el archivo o recupera lo que puede?

EvtxECmd, hayabusa y python-evtx recuperan chunks dirty con tolerancia variable. El Event Viewer nativo es el más estricto y rechazará el archivo de plano más a menudo que los otros.

## Implicaciones prácticas

- Un `.evtx` truncado, común cuando [recoges desde un host vivo](/es/blog/collecting-evtx-from-live-system), suele ser mayormente recuperable. Cada chunk completo es independiente.
- Los chunks carvados desde no asignado pueden envolverse con una cabecera de archivo sintética y parsearse. Así libevtx y python-evtx recuperan de `pagefile.sys` (ver [parser de pagefile](https://www.pagefilesysparser.com)) y de pasadas de carving de [volcado RAM](https://www.ramparser.com).
- Un parseo fallido de un chunk no significa fallo del archivo. Los parsers robustos siguen al siguiente chunk y reportan el malo por separado.
- El CRC32 del chunk es lo que marca manipulación. Un registro modificado que no recompute el CRC es detectable. La mayoría de atacantes no se molestan porque borrar el log (disparando [1102](/es/blog/event-id-1102-cleared-log)) es el camino más fácil. Los cuidadosos usan Phant0m, que deja el archivo en paz por completo.

## Lectura adicional

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (trabajo original de ingeniería inversa)
- [Documentación de libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (la especificación de formato más exhaustiva que hay)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (parser Rust, la build WASM impulsa el parser de navegador de este sitio)

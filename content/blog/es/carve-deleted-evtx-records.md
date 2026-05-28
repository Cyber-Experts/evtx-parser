---
title: "Carving de registros EVTX borrados y recuperación de logs rotados"
description: "Carving por firma de registros EVTX en espacio no asignado, pagefile y memoria, y las herramientas que manejan chunks malformados con elegancia cuando al log vivo le falta lo que necesitas."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

El log de Security de un controlador de dominio cargado se sobrescribe en horas, no en días. El tamaño de canal por defecto son 20 MB, lo que en un host ruidoso son unos pocos miles de registros. Para cuando imagenes el disco en respuesta a un incidente que empezó hace tres semanas, los eventos que realmente querías ya han salido del archivo vivo y están en espacio no asignado, en el pagefile y posiblemente en la hibernación. Recuperarlos por carving es parte rutinaria de cualquier investigación basada en EVTX, y la mayoría de defensores lo saltan porque tratan el archivo vivo como fuente de la verdad.

No lo es. El archivo vivo son los últimos 20 MB. El disco tiene el resto.

## La firma: `2a 2a 00 00`

Todo registro EVTX empieza con el magic de 4 bytes `2a 2a 00 00`. Eso es `**` seguido de dos bytes nulos. Esta firma es lo suficientemente distintiva como para que escanear una imagen de disco bruta con `bulk_extractor`, `scalpel` o incluso un grep de cuatro bytes propio devuelva un conjunto útil de candidatos. La densidad de la firma en un volumen Windows es baja; la mayoría de los aciertos son registros reales.

La estructura que sigue al magic está lo suficientemente bien definida como para validar aciertos barato:

- Bytes 4-7: `Size` (uint32). Debe ser plausible (32 bytes mínimo, típicamente bajo 4 KB).
- Bytes 8-15: `EventRecordIdentifier` (uint64). Debe ser un RecordID razonable para la ventana temporal.
- Bytes 16-23: `WriteTime` como FILETIME. Debe caer entre Vista (la primera versión con EVTX) y ahora.
- Bytes `Size-4` a `Size`: el mismo valor `Size`, repetido como marcador de cola.

Un candidato donde el `Size` de cabecera coincide con el `Size` de cola, el FILETIME parsea a una fecha plausible y el RecordID está en rango, es casi con certeza un registro real. Los falsos positivos caen prácticamente a cero con estas cuatro comprobaciones.

El reto es qué hacer con los bytes entre cabecera y cola.

## El problema del chunk

Los registros EVTX referencian plantillas y strings almacenados una vez por chunk. Un registro carvado aislado tiene arrays de sustitución sin plantilla a la que aplicarlos. Puedes leer los valores tipados directamente del array de sustitución, lo que basta para recuperar datos a nivel de campo ("el usuario X inició sesión a la hora T desde la IP Y"), pero el XML renderizado que obtendrías de un parser vivo no es reconstruible sin el chunk.

Esta es la diferencia entre dos resultados de carving:

- **Carving solo de registro**: recuperas RecordID, timestamp, EventID y los valores de sustitución. Puedes construir una vista campo a campo del evento, pero no el XML renderizado legible.
- **Carving de chunk**: encuentras un chunk (magic `ElfChnk\0`, alineado a 64 KB) y recuperas su tabla de plantillas junto con los registros. Ahora lo tienes todo.

`ElfChnk\0` también se puede carvar por firma. La alineación de 64 KB ayuda porque los chunks aterrizan en límites de sector en disco; un escaneo de firma alineado por offset es rápido. La mayoría de herramientas de carving soportan ambos modos, y deberías ejecutar ambos. Los chunks te dan eventos legibles; los registros huérfanos te dan el resto cuando no sobrevivió un chunk envolvente.

## Dónde viven los bytes

Los lugares que merecen escaneo, por rendimiento:

- **Clusters no asignados en el volumen que aloja `%SystemRoot%\System32\winevt\Logs\`**. Cuando un archivo EVTX rota o se borra, los contenidos viejos quedan no asignados. NTFS no pone a cero los clusters no asignados, así que los bytes son recuperables hasta que se reutilicen. En un servidor con poca rotación de escritura, esto pueden ser semanas.
- **Slack space en el archivo EVTX vivo**. Los archivos EVTX se escriben en chunks de 64 KB. El último chunk del archivo a menudo está parcialmente lleno, con el slack conteniendo la generación anterior de datos escritos en esos bytes antes de que el chunk actual se redimensionara hacia abajo. Vale la pena escanearlo.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. El servicio de event log cachea registros y plantillas recientes en memoria. Las páginas que respaldan esas estructuras se intercambian bajo presión de memoria. El pagefile es una mina de oro para registros que nunca se descargaron a disco porque el host se cayó o lo mataron antes de que llegaran.
- **`hiberfil.sys`**. Snapshot comprimido de la memoria física al hibernar. Descomprime con `Volatility 3` o Hibr2Bin y busca en la memoria bruta resultante las firmas de registro.
- **[Volcado RAM](https://www.ramparser.com)** capturado durante respuesta en vivo. El working set del servicio de event log contendrá registros recientes y las plantillas necesarias para renderizarlos.
- **Shadow copies (VSS)**. Los snapshots antiguos del volumen contienen versiones antiguas de los archivos EVTX vivos. `vshadow` o `vssadmin list shadows` seguido de `mklink /d` para montar el shadow te da una copia de la generación anterior del archivo con los registros que estaban vivos en el momento del shadow.

VSS es la fuente con mayor palanca en hosts que lo tienen habilitado y no han sido manipulados a nivel VSS. Un servidor Windows moderno tiene típicamente 7-30 días de shadow copies. Si el incidente ocurrió hace tres semanas, el shadow del momento del incidente puede tener el log vivo tal como existía entonces, sin manipular.

## Herramientas que manejan entrada malformada

Un archivo EVTX limpio es raro en escenarios de carving. Vas a tener chunks parciales, registros sin cola, plantillas que referencian offsets fuera del chunk y fallos de CRC por todas partes. Los parsers que manejan esto no son los mismos que los que manejan archivos limpios.

- **`EvtxECmd`** (Eric Zimmerman). Lo mejor de su clase para trabajo de campo IR. Pasa `--inc` para incluir registros que fallaron en el parsing normal y emitirá lo que pudo leer de registros parciales. La salida CSV es lo que quieres para trabajo de timeline.
- **`hayabusa`** (Yamato Security). Construido para hunting sobre grandes corpus EVTX, con reglas estilo sigma. Maneja chunks parciales de forma razonable y es rápido. El filtro `--exclude-status` te permite reducir ruido de registros corruptos.
- **`evtx_dump`** (la crate de Rust de Omer Ben-Amram). Robusto frente a estructuras malformadas, salida JSONL. Bueno para encadenar con `jq` o un SIEM.
- **`evtxtools`** (Joachim Metz, parte de libevtx). La implementación de referencia canónica del formato. Más lento que los otros pero te dice exactamente qué campo falló qué validación cuando un registro está parcialmente recuperado, que es lo que quieres al depurar salida de carving.
- **`bulk_extractor`** con el scanner EVTX. El paso de carving en sí. Saca registros candidatos con sus offsets en la imagen origen para validación posterior.

Un pipeline práctico:

1. `bulk_extractor -E evtx -o out/ image.dd` para carvar registros y chunks candidatos de la imagen de disco.
2. Reensambla los chunks en archivos EVTX sintéticos concatenando los chunks carvados con una cabecera de archivo forjada. Los ejemplos de `libevtx` incluyen un reensamblador de chunks compatible con `evtxexport`.
3. Ejecuta `EvtxECmd` sobre el archivo reensamblado con `--inc` para volcar todo lo legible a CSV.
4. Diferencia los RecordIDs carvados contra los RecordIDs del archivo vivo para encontrar los registros que no estaban en el log vivo.

La salida del paso 4 es lo que te da el carving: los eventos que el atacante o el tiempo han retirado del archivo vivo.

## Cuando el log vivo no muestra nada porque rotó

El caso común para el carving no es el borrado anti-forense; es el rollover. Un incidente de hace 30 días en un host con un log de Security de 20 MB y 50 eventos por segundo ha rotado el archivo entero docenas de veces. El log vivo muestra las últimas horas. Todo lo demás está en no asignado.

El carving aquí es sencillo porque no ha habido manipulación. Escaneas no asignado, encuentras chunks, reensamblas. El rendimiento depende de cuánta rotación de escritura ha tenido el volumen desde el rollover. Un volumen servidor con archivos de sistema mayoritariamente estáticos y el directorio EVTX como fuente de escritura dominante mantendrá los chunks antiguos intactos durante mucho tiempo. Un volumen con escrituras de aplicación intensas sobrescribirá las regiones no asignadas más rápido.

Un truco que ayuda: el directorio EVTX está en `%SystemRoot%\System32\winevt\Logs\`, que es uno de los puntos más fríos del volumen en términos de escrituras competidoras. Las cadenas de clusters que se liberaron cuando el archivo EVTX rotó suelen permanecer no asignadas durante semanas. Lo mismo no es cierto para volúmenes que alojan datos de aplicación.

## Qué hacer con lo que recuperas

Los registros carvados van a la misma timeline que los registros vivos. El RecordID y el WriteTime sobreviven al carving y son las claves de join. Un `4624 Type 3` carvado en el momento del supuesto acceso inicial es tan útil como uno vivo, con la salvedad de que no necesariamente puedes renderizar su XML completo.

Cruzar referencias contra:

- Las entradas de la [Master File Table](https://www.mftparser.com) para `Security.evtx` para ver cuándo se reescribió el archivo por borrado o rollover.
- El [diario USN](https://www.usnparser.com) para eventos `DATA_OVERWRITE` en el archivo EVTX, lo que da timestamps de alta resolución para cada rollover.
- [Prefetch](https://www.prefetchparser.com) para los binarios que se ejecutaron durante el hueco, ya que `Prefetch` es independiente de `Security.evtx` y sobrevive al borrado del log.
- [AmCache](https://www.amcacheparser.com) y [Shimcache](https://www.shimcacheparser.com) para evidencia de primera ejecución.
- Las colmenas del [registro](https://www.registryparser.com) en shadow copies para el estado en el momento del incidente.

Un registro carvado que cuadra con una entrada de Prefetch y un timestamp MFT en un binario sospechoso es un hallazgo. Un registro carvado solo es una pista que vale la pena perseguir.

## Lectura adicional

- El trabajo original de carving de Andreas Schuster en el [paper DFRWS 2007](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). Las heurísticas de carving de toda herramienta moderna remontan aquí.
- La documentación de [EvtxECmd](https://github.com/EricZimmerman/evtx) de Eric Zimmerman y el flag `--inc` para manejo de registros parciales.
- [hayabusa](https://github.com/Yamato-Security/hayabusa) de Yamato Security y su corpus de muestra adjunto, útil para probar pipelines de carving.
- [bulk_extractor](https://github.com/simsong/bulk_extractor) de Simson Garfinkel y su módulo scanner EVTX.

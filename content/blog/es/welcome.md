---
title: "Leer el formato binario del registro de eventos de Windows"
description: "Un breve repaso sobre cómo se organizan los archivos .evtx, qué contiene cada evento y por qué este formato importa en forense."
date: "2026-05-16"
---

El registro de eventos de Windows — `.evtx` — es el formato binario que Microsoft introdujo con Windows Vista para reemplazar al antiguo `.evt`. Es la columna vertebral de casi cualquier respuesta a incidentes en Windows: inicios de sesión, arranques de servicio, líneas de comando de PowerShell, creaciones de procesos de Sysmon y una larga lista de canales específicos de proveedores se serializan en él.

## Cómo está organizado un archivo

Cada `.evtx` comienza con un encabezado de 4 KB (firma `ElfFile\0`, checksum y número de bloques), seguido por una secuencia de bloques de 64 KB. Cada bloque tiene su propio encabezado (`ElfChnk`), una tabla de plantillas XML usadas en el bloque y un flujo de registros binarios que referencian esas plantillas por ID. El parser reconstruye cada evento enlazando los marcadores de la plantilla con los valores propios del registro.

## Qué aspecto tiene un registro

Una vez decodificado, cada registro es un documento XML con dos partes principales:

- `<System>` — nombre del proveedor, canal, ID de evento, nivel (1 Crítico → 5 Detallado), nombre del equipo, contexto de seguridad y marca de tiempo UTC en que se escribió.
- `<EventData>` — parámetros propios del proveedor: cuenta objetivo en un inicio de sesión, ruta de la imagen en una creación de proceso, etc.

El ID de evento por sí solo rara vez basta para el triage; la señal forense está en la carga útil de `<EventData>`.

## Cómo lo lee esta herramienta

El parser es el crate de Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx), compilado a WebAssembly y cargado en un Web Worker. Cuando sueltas un archivo, el worker lo carga en memoria, recorre cada bloque y reconstruye el XML de cada registro. Nada viaja por la red — desconecta el wifi si quieres comprobarlo.

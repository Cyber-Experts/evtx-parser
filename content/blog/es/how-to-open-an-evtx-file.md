---
title: "Cómo abrir un archivo .evtx (5 métodos, sin instalación obligatoria)"
description: "Cinco formas de abrir un archivo .evtx de Windows — en tu navegador, en el Visor de eventos, con wevtutil, con EvtxECmd o con python-evtx. Elige según el SO y la fricción que toleres."
date: "2026-05-24"
howto:
  name: "Cómo abrir un archivo .evtx"
  steps:
    - name: "Ábrelo en tu navegador (sin instalación)"
      text: "Ve a la página principal del parser EVTX y arrastra tu archivo .evtx a la zona de carga. El archivo se procesa localmente en un Web Worker usando un parser EVTX en Rust compilado a WebAssembly. No se sube nada — desconecta tu red si quieres verificarlo. Funciona en Windows, macOS y Linux."
    - name: "Ábrelo en el Visor de eventos (solo Windows)"
      text: "Ejecuta eventvwr.msc, elige Acción → Abrir registro guardado…, navega hasta el archivo .evtx, ponle nombre a la vista y pulsa Aceptar. Sirve para navegar por un canal; flojo para filtrar entre miles de registros."
    - name: "Vuélcalo con wevtutil o Get-WinEvent (línea de comandos de Windows)"
      text: "Ejecuta wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt para exportar todos los registros como texto. Desde PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 devuelve objetos parseados que puedes seguir encadenando."
    - name: "Parsea con EvtxECmd (CLI multiplataforma)"
      text: "Descarga EvtxECmd de las herramientas de Eric Zimmerman y ejecuta EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv para aplanar cada registro (incluidos todos los campos de EventData) en una fila CSV por evento. Corre nativo en Windows y en macOS/Linux vía .NET."
    - name: "Scriptéalo con python-evtx (Python multiplataforma)"
      text: "pip install python-evtx y luego ejecuta python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml para obtener cada registro como XML en stdout. Más lento que el parser de Rust pero fácil de embeber en pipelines y notebooks de Jupyter."
---

Un archivo `.evtx` es el formato binario de Windows Event Log ([qué contiene →](/es/blog/what-is-an-evtx-file)). No puedes leerlo con un editor de texto — es BinXML dentro de contenedores binarios en chunks. Abajo están los cinco métodos que cubren cada caso realista, ordenados de «arrastra el archivo y listo» a «engánchalo a un pipeline de Python».

## Método 1 — ábrelo en tu navegador (sin instalación)

La vía más rápida en cualquier sistema operativo: arrastra el `.evtx` al parser de la [página principal de este sitio](/es). El archivo se carga en la memoria de tu navegador y lo procesa localmente un Web Worker que ejecuta el crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilado a WebAssembly. Nada sale de tu máquina — puedes confirmarlo desconectándote de la red antes de soltar el archivo.

Obtienes la misma vista a nivel de registro que produce una herramienta de escritorio: una timeline filtrable, el `<EventData>` completo aplanado en la tabla, el XML completo a un clic y exportación CSV/JSON del conjunto filtrado. Lo mejor para triaje puntual cuando no quieres instalar nada, no quieres subir nada o estás en una máquina que no es tuya.

**Limitaciones.** Los topes de memoria del navegador hacen que archivos de más de ~500 MB vayan lentos. Para registros archivados de varios gigabytes, baja a una herramienta nativa.

## Método 2 — Visor de eventos (solo Windows, integrado)

Toda instalación de Windows incluye el Visor de eventos. Lánzalo con `eventvwr.msc`, después **Acción → Abrir registro guardado…** y elige el `.evtx`. El Visor de eventos te ofrecerá importar el archivo a tu vista actual; acepta y podrás navegarlo como cualquier canal en vivo.

```text
Action → Open Saved Log… → Browse → select .evtx → OK
```

Bueno para: navegar un único archivo, mirar el mensaje formateado de un registro, copiar y pegar una vista XML. Flojo para: filtrar miles de registros (la UI se ralentiza), exportación masiva o lanzar consultas que quieras scriptear.

## Método 3 — wevtutil / Get-WinEvent (línea de comandos de Windows)

`wevtutil` es la herramienta integrada de Windows para gestión de registros; `Get-WinEvent` es su contraparte en PowerShell. Ambas funcionan sobre archivos `.evtx` guardados, no solo sobre canales en vivo.

Volcar todos los registros de un `.evtx` guardado a texto:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrar con XPath (aquí, cada 4624 en las últimas 24 horas):

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell con la misma intención, pero devolviendo objetos tipados:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Bueno para: extracción scripteada, trabajos programados, filtrado quirúrgico. La contrapartida es la verbosidad — XPath contra XML es preciso pero no amigable.

## Método 4 — EvtxECmd (CLI multiplataforma, el estándar DFIR)

[`EvtxECmd` de Eric Zimmerman](https://ericzimmerman.github.io/) es el parser al que la mayoría de los profesionales de IR recurre por defecto. Corre nativo en Windows y en macOS / Linux bajo .NET, parsea más rápido que `wevtutil` y aplana cada campo de `<EventData>` en una columna CSV. Una fila por registro.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Para procesar de una pasada toda una carpeta `winevt\Logs\`, con maps que decodifican campos de eventos conocidos en columnas amigables:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Bueno para: parseo masivo de colecciones multi-archivo, importación a un SIEM o a un notebook, flujo de analista multiplataforma. EvtxECmd es la respuesta correcta para casi cualquier tarea de «parsea esto offline».

## Método 5 — python-evtx (encajarlo en un pipeline)

Cuando el archivo tiene que alimentar un pipeline de Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) es el parser en Python puro.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

En un notebook o script:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Más lento que el crate de Rust (Python interpretado sobre chunks binarios) pero la elección correcta cuando ya estás dentro de un toolchain de Python — notebooks forenses de Jupyter, trabajos de threat hunting, enriquecimiento personalizado.

## Qué método usar y cuándo

- **Solo quieres mirar el archivo**: arrástralo al [parser de la página principal](/es). La vía más rápida, cero instalación.
- **Estás en un endpoint Windows con admin y el archivo es pequeño**: Visor de eventos.
- **Necesitas scriptear una extracción puntual**: `wevtutil` o `Get-WinEvent`.
- **Estás haciendo DFIR real sobre colecciones multicanal**: EvtxECmd.
- **Estás construyendo un pipeline en Python**: `python-evtx`.

## Errores comunes y cómo leerlos

- **«El archivo no parece ser válido»** en el Visor de eventos suele significar que el último chunk está sucio (el archivo se copió mientras el servicio EventLog aún escribía). La mayoría de los parsers lo manejan — prueba con [el parser de navegador](/es) o `EvtxECmd`, que ambos reportan los chunks sucios como advertencia y continúan.
- **«Acceso denegado»** desde `wevtutil` contra un archivo en `winevt\Logs\` es el servicio EventLog reteniendo un bloqueo exclusivo. Consulta [recolectar .evtx de un sistema en vivo](/es/blog/collecting-evtx-from-live-system) para las cuatro maneras estándar de sortearlo.
- **Salida vacía de `Get-WinEvent`** sobre un registro guardado: pasa el archivo con `-Path`, no con `-LogName`. `-LogName` solo lee canales en vivo.
- **PowerShell `Get-WinEvent` dice «No se encontraron eventos que coincidan con los criterios de selección especificados»** — tus claves de `-FilterHashtable` son sensibles a mayúsculas en algunas propiedades. Prueba primero sin el filtro para confirmar que el archivo parsea.

Para contexto sobre qué hay realmente dentro de un `.evtx` y por qué el formato es como es, consulta [¿Qué es un archivo .evtx?](/es/blog/what-is-an-evtx-file).

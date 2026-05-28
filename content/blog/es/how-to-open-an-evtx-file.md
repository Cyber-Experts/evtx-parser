---
title: "Cómo abrir un archivo .evtx (5 métodos, sin instalación requerida)"
description: "Cinco formas de abrir un archivo .evtx de Windows: en tu navegador, en Event Viewer, con wevtutil, con EvtxECmd o con python-evtx. Elige por SO del host y cuánta fricción aguantas."
date: "2026-05-24"
howto:
  name: "Cómo abrir un archivo .evtx"
  steps:
    - name: "Ábrelo en tu navegador (sin instalar)"
      text: "Ve a la página principal del parser EVTX, suelta tu archivo .evtx en la zona de carga. El archivo se parsea localmente en un Web Worker usando un parser EVTX Rust compilado a WebAssembly. Nada se sube. Funciona en Windows, macOS y Linux."
    - name: "Ábrelo en Event Viewer (solo Windows)"
      text: "Lanza eventvwr.msc, elige Acción luego Abrir registro guardado, navega al archivo .evtx, nombra la vista y haz clic en OK. Bueno para navegar un canal; débil para filtrar a través de miles de registros."
    - name: "Vuélcalo con wevtutil o Get-WinEvent (línea de comandos de Windows)"
      text: "Ejecuta wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt para exportar cada registro como texto. Desde PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 devuelve objetos parseados que puedes pipear más adelante."
    - name: "Parsea con EvtxECmd (CLI multiplataforma)"
      text: "Descarga EvtxECmd de las herramientas de Eric Zimmerman, luego ejecuta EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv para aplanar cada registro (incluidos todos los campos EventData) en una fila CSV por evento."
    - name: "Hazlo script con python-evtx (Python multiplataforma)"
      text: "pip install python-evtx, luego ejecuta python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml para obtener cada registro como XML en stdout. Más lento que el parser Rust pero fácil de embeber en pipelines y notebooks Jupyter."
---

Un archivo `.evtx` es el formato binario de Windows Event Log ([qué hay dentro de uno](/en/blog/what-is-an-evtx-file)). No puedes leerlo con un editor de texto. Es BinXML dentro de contenedores binarios troceados. Hay cinco métodos que cubren cada caso realista, en orden aproximado desde "suelta el archivo y has terminado" hasta "cablearlo en un pipeline Python".

## Método 1: ábrelo en tu navegador, sin instalar

El camino más rápido en cualquier sistema operativo. Suelta el `.evtx` en el parser de la [página principal de este sitio](/en). El archivo se lee en la memoria de tu navegador y se parsea localmente por un Web Worker que corre el crate [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilado a WebAssembly. Nada sale de tu máquina. Confirma desconectando de la red antes de soltar el archivo.

Obtienes la misma vista a nivel de registro que produce una herramienta de escritorio: timeline filtrable, `<EventData>` completo aplanado en la tabla, XML completo a un clic, exportación CSV/JSON del conjunto filtrado. Adecuado para triaje ad-hoc cuando no quieres instalar nada, no quieres subir nada, o estás en una máquina que no es tuya.

Limitación. Los topes de memoria del navegador significan que los archivos mayores de unos 500 MB se vuelven lentos. Para logs archivados de varios gigabytes, baja a una herramienta nativa.

## Método 2: Event Viewer, solo Windows, integrado

Cada instalación de Windows trae Event Viewer. Lanza `eventvwr.msc`, luego **Acción / Abrir registro guardado** y elige el `.evtx`. Event Viewer se ofrece a importar el archivo a tu vista actual. Acepta y puedes navegarlo como cualquier canal en vivo.

```text
Acción -> Abrir registro guardado -> Examinar -> seleccionar .evtx -> OK
```

Bueno para navegar un solo archivo, mirar el mensaje formateado amigable de un registro, copiar y pegar una vista XML. Débil para filtrar miles de registros (la UI se vuelve lenta), exportación masiva o ejecutar consultas que quieres scriptear. También el más estricto sobre chunks finales sucios: rechazará archivos que otras herramientas aceptan.

## Método 3: wevtutil y Get-WinEvent, línea de comandos de Windows

`wevtutil` es el integrado de Windows para gestión de logs. `Get-WinEvent` es su contraparte PowerShell. Ambos funcionan en archivos `.evtx` guardados, no solo en canales en vivo.

Volcar cada registro de un `.evtx` guardado a texto:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filtrar con XPath. Cada 4624 en las últimas 24 horas:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell con la misma intención, pero devolviendo objetos tipados:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Bueno para extracción scripteada, trabajos programados, filtrado quirúrgico. La contrapartida es la verbosidad. XPath contra XML es preciso pero no amigable.

## Método 4: EvtxECmd, el estándar DFIR

El [`EvtxECmd` de Eric Zimmerman](https://ericzimmerman.github.io/) es el parser al que la mayoría de practicantes de IR recurren por defecto. Corre nativamente en Windows y en macOS / Linux bajo .NET. Parsea más rápido que `wevtutil` y aplana cada campo `<EventData>` en una columna CSV. Una fila por registro.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

Para una carpeta entera de `winevt\Logs\` en una pasada, con maps que descodifican campos de eventos conocidos en columnas amigables:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Adecuado para parseo masivo de colecciones multi-archivo, importación a un SIEM o notebook, flujo de trabajo de analista multiplataforma. EvtxECmd es la respuesta correcta para casi cada tarea de "parsea esto offline". Empareja con el target `EventLogs` de KAPE y tienes una engagement de un comando.

## Método 5: python-evtx, scriptea en un pipeline

Cuando el archivo necesita alimentar un pipeline Python, [`python-evtx`](https://github.com/williballenthin/python-evtx) es el parser Python puro.

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

Más lento que el crate Rust (Python interpretado en chunks binarios) pero la llamada correcta cuando ya estás dentro de un toolchain Python: notebooks forenses Jupyter, trabajos de threat-hunting, enriquecimiento personalizado, uniendo datos EVTX a artefactos de [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com) o [prefetch](https://www.prefetchparser.com) del mismo caso.

## Qué método usar cuándo

- Solo quieres mirar el archivo: suéltalo en el [parser de la página principal](/en). Más rápido, cero instalación.
- Endpoint Windows con admin y el archivo es pequeño: Event Viewer.
- Extracción única scripteada: `wevtutil` o `Get-WinEvent`.
- DFIR real en colecciones multi-canal: EvtxECmd.
- Construyendo un pipeline en Python: `python-evtx`.

## Errores comunes y cómo leerlos

- "El archivo no parece ser válido" en Event Viewer casi siempre significa que el chunk final está sucio (el archivo se copió mientras el servicio EventLog seguía escribiendo). La mayoría de parsers manejan esto. Prueba [el parser del navegador](/en) o `EvtxECmd`, que ambos reportan chunks sucios como advertencia y continúan.
- "Acceso denegado" de `wevtutil` contra un archivo en `winevt\Logs\` es el servicio EventLog manteniendo un lock exclusivo. Mira [recolectar .evtx de un sistema vivo](/en/blog/collecting-evtx-from-live-system) para las cuatro formas estándar de rodearlo.
- Salida vacía de `Get-WinEvent` en un log guardado. Pasa el archivo con `-Path`, no `-LogName`. `-LogName` solo lee canales en vivo.
- PowerShell `Get-WinEvent` dice "No se encontraron eventos que coincidan con los criterios de selección especificados". Las claves de tu `-FilterHashtable` son sensibles a mayúsculas en algunas propiedades. Prueba primero sin el filtro para confirmar que el archivo se parsea.

Para fondo sobre qué hay realmente dentro de un `.evtx` y por qué el formato se ve como se ve, mira [el deep dive a nivel de chunk](/en/blog/evtx-file-format-chunks).

## Lecturas adicionales

- [Herramientas de Eric Zimmerman](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)

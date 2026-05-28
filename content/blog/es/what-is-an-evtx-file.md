---
title: "¿Qué es un archivo .evtx? El formato del Registro de eventos de Windows explicado"
description: "Un archivo .evtx es un Registro de eventos de Windows binario. Dónde viven, qué hay dentro, en qué se diferencian de .evt y cómo abrirlos. Sin instalar nada."
date: "2026-05-24"
faq:
  - question: "¿Qué es un archivo .evtx?"
    answer: "Un archivo .evtx es el formato binario del Registro de eventos de Windows introducido con Windows Vista. Almacena eventos del sistema, de seguridad y de aplicaciones escritos por el servicio EventLog. Cada máquina Windows tiene decenas de archivos .evtx en C:\\Windows\\System32\\winevt\\Logs\\, uno por canal."
  - question: "¿Dónde se almacenan los archivos .evtx en Windows?"
    answer: "La ubicación por defecto es C:\\Windows\\System32\\winevt\\Logs\\. Los tres archivos con más tráfico son Security.evtx, System.evtx y Application.evtx. Los canales por aplicación viven en la misma carpeta bajo nombres como Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "¿Cuál es la diferencia entre .evtx y .evt?"
    answer: ".evt es el formato binario heredado que Windows usó hasta XP y Server 2003. .evtx lo reemplazó en Windows Vista (2007) con un diseño en chunks basado en BinXML que admite metadatos de evento más ricos, registros más grandes y consultas estructuradas vía wevtutil y Get-WinEvent. Los dos formatos no son intercambiables."
  - question: "¿Cómo abro un archivo .evtx?"
    answer: "Herramientas integradas de Windows: Visor de eventos (eventvwr.msc), wevtutil desde la línea de comandos o Get-WinEvent desde PowerShell. Multiplataforma: ábrelo en el parser basado en navegador de este sitio (sin instalación, sin subida) o usa evtxecmd en la línea de comandos. Consulta nuestra entrada how-to-open-an-evtx-file para conocer todas las opciones."
  - question: "¿Puedo abrir un archivo .evtx en macOS o Linux?"
    answer: "Sí. Las herramientas nativas de Windows no funcionarán, pero varios parsers multiplataforma sí: el parser basado en navegador de este sitio (cualquier SO con un navegador moderno), python-evtx, el crate evtx de Rust y evtxecmd vía .NET. Ninguno requiere un host Windows."
---

Un archivo `.evtx` es el formato binario del Registro de eventos de Windows que Microsoft lanzó con Vista en 2007 para reemplazar al antiguo `.evt`. Cada evento que el sistema operativo, un controlador, un servicio o una aplicación escribe en el Registro de eventos de Windows aterriza en un archivo `.evtx` en disco. Son la columna vertebral de toda investigación en Windows. Si haces DFIR sobre Windows, pasarás más tiempo dentro de estos archivos que con cualquier otra clase de artefacto.

## Respuesta rápida

Los archivos `.evtx` los escribe el servicio EventLog de Windows en `C:\Windows\System32\winevt\Logs\`. Un archivo por **canal** (`Security.evtx`, `System.evtx`, `Application.evtx`, más canales por aplicación). Internamente, cada archivo es un contenedor binario en chunks de registros codificados en `BinXML`. No es texto plano. Se leen con el Visor de eventos, `wevtutil`, `Get-WinEvent` o un parser de terceros.

## Dónde viven los archivos .evtx

Ubicación estándar en cada versión soportada de Windows (de Vista a Windows 11 y Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Cada archivo `.evtx` se corresponde con un canal de eventos. Los predeterminados:

- `Security.evtx`. Inicios de sesión, uso de privilegios, cambios en la política de auditoría. El de mayor valor forense en la mayoría de los casos.
- `System.evtx`. Controladores, servicios, errores a nivel de kernel.
- `Application.evtx`. Errores y eventos informativos a nivel de aplicación.
- `Setup.evtx`. Registros de instalación.
- `ForwardedEvents.evtx`. Eventos recolectados de otros equipos mediante Windows Event Forwarding (WEF).

Los canales por aplicación se almacenan en la misma carpeta con `%4` haciendo de separador de ruta:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Eventos de procesos, red y archivos de Sysmon (cuando está instalado).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Registro de scriptblock y de módulos de PowerShell.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Creaciones y ejecuciones de tareas programadas.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. Ciclo de vida de sesiones RDP.

Los canales rotados producen archivos con marca de tiempo en la misma carpeta (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). El servicio EventLog mantiene abierto el archivo activo mientras Windows está en ejecución, que es la razón completa por la que hay [una entrada de recolección sobre cómo sacar estos archivos de un host vivo](/es/blog/collecting-evtx-from-live-system).

## Qué hay dentro de un archivo .evtx

El archivo es un contenedor binario, no texto plano. A una cabecera de 4 KB (magic `ElfFile\0`) le sigue una secuencia de **chunks** de 64 KB. Cada chunk tiene su propia cabecera (`ElfChnk`), una tabla con las **plantillas** XML que aparecen dentro de él y un flujo de registros que referencian esas plantillas por ID. Un parser reconstruye cada evento sustituyendo los valores a nivel de registro en los marcadores de posición de la plantilla. Esto es lo que hace que `.evtx` sea más compacto en disco que XML literal.

Una vez decodificado, cada registro es un documento XML con dos mitades:

- `<System>`. Nombre del proveedor, canal, Event ID, nivel (1 Critical hasta 5 Verbose), nombre del equipo, contexto de seguridad y marca de tiempo de escritura en UTC.
- `<EventData>`. Parámetros específicos del proveedor: la cuenta destino en un inicio de sesión, la ruta de la imagen en una creación de proceso, la clave del registro en una escritura auditada, etc.

El Event ID por sí solo rara vez basta para el triaje. La señal forense vive en `<EventData>`. Para la mecánica del formato a fondo (chunks, BinXML, plantillas, recuperación de chunks sucios), consulta [el análisis a nivel de chunk](/es/blog/evtx-file-format-chunks).

## .evtx vs .evt: por qué cambió el formato

El formato heredado `.evt` que Windows usó hasta XP y Server 2003 tenía tres límites duros que el nuevo formato vino a resolver:

- **Cadenas de tamaño fijo.** Los registros `.evt` llevaban referencias a la tabla de mensajes en lugar del mensaje completo. Las composiciones en tiempo de renderizado se rompían cuando las DLL de origen faltaban o se actualizaban.
- **Sin consultas estructuradas.** Filtrar exigía leer y parsear cada registro de forma lineal.
- **Un único canal por archivo.** Los registros personalizados de aplicación necesitaban sus propios formatos no estándar.

`.evtx` (Vista, 2007) introdujo registros BinXML, archivos por canal con anidamiento arbitrario, filtrado estilo XPath vía `wevtutil qe` y `Get-WinEvent -FilterHashtable`, y un diseño en chunks que sobrevive a escrituras parciales. La contrapartida fue una ruptura total de compatibilidad. `.evt` y `.evtx` no son intercambiables, y la única herramienta integrada que lee `.evt` en un Windows moderno es `wevtutil` con el flag legacy (y solo para exportar a `.evtx`).

## Cómo abrir un archivo .evtx

Cinco rutas habituales, en orden aproximado de fricción:

1. **En tu navegador, sin instalar.** Arrastra el archivo al parser de la página principal de este sitio. Ejecuta el crate de Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) compilado a WebAssembly dentro de un Web Worker. Nada sale de tu máquina. Adecuado para triaje puntual cuando no quieres levantar una VM forense.
2. **Visor de eventos (`eventvwr.msc`).** La GUI integrada de Windows. Acción / Abrir registro guardado / selecciona el `.evtx`. Bueno para navegar, débil para filtrar a escala.
3. **`wevtutil` / `Get-WinEvent`.** Línea de comandos y PowerShell, ambos vienen con Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` vuelca todos los registros. `Get-WinEvent -Path` devuelve objetos que puedes encadenar a `Where-Object`.
4. **EvtxECmd.** El parser de Eric Zimmerman. Multiplataforma vía .NET, rápido, produce CSV con una fila por registro y el `<EventData>` completo aplanado.
5. **`python-evtx`.** Python puro, fácil de scriptear. Más lento que el crate de Rust pero útil cuando ya tienes una cadena de herramientas en Python.

Para un recorrido completo de cada método con los comandos que realmente ejecutarías, consulta [Cómo abrir un archivo .evtx](/es/blog/how-to-open-an-evtx-file).

## Cuándo te encuentras con .evtx en el mundo real

- **Respuesta a incidentes.** Extraídos de un host comprometido como parte del triaje. Los canales de interés dependen de la pista: `Security` para inicios de sesión y abuso de privilegios, `Sysmon` para árboles de procesos, `PowerShell` para el contenido de scriptblock. Combina con parsers de [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [diario USN](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com) y [prefetch](https://www.prefetchparser.com) para corroborar la ejecución.
- **Auditorías de cumplimiento.** Los auditores piden `Security.evtx` sobre una ventana definida para verificar el historial de inicios de sesión y cambios de política.
- **Depuración de aplicaciones.** `Application.evtx` más los canales por proveedor a menudo guardan contexto de errores y caídas que los propios registros de la aplicación no tienen.
- **Threat hunting.** Reglas de cola larga contra `.evtx` archivados (o un SIEM reenviando el canal en vivo) detectan patrones de combustión lenta como RDP fuera de horario o deriva del `LogonType` de una cuenta de servicio.

El pivote más útil con diferencia es el Event ID. Para la lista corta que se gana su sitio en un SOC real ([4624](/es/blog/understanding-event-id-4624), [4625](/es/blog/detecting-4625-brute-force), [1102](/es/blog/event-id-1102-cleared-log), [4104](/es/blog/powershell-4104-scriptblock), [7045](/es/blog/service-creation-event-id-7045), [Sysmon 1](/es/blog/sysmon-event-id-1-process-create)), consulta [la orientación inicial](/es/blog/welcome).

## Lectura adicional

- [Documentación de Microsoft: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [Especificación del formato EVTX de libevtx](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (parser en Rust)](https://github.com/omerbenamram/evtx)

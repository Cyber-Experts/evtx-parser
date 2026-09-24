---
title: "Cómo recolectar logs .evtx de un sistema Windows en vivo (4 métodos)"
description: "Cuatro maneras de sacar .evtx de un host Windows vivo: wevtutil, FTK Imager, KAPE, NTFS crudo. Con los compromisos de cadena de custodia de cada uno y los comandos que realmente ejecutarás."
date: "2026-05-17"
howto:
  name: "Cómo recolectar logs .evtx de un sistema Windows en vivo"
  steps:
    - name: "Exportar con wevtutil"
      text: "Ejecuta wevtutil epl Security C:\\triage\\Security.evtx como administrador para sellar una copia portable del canal Security activo sin tomar el archivo vivo."
    - name: "Adquirir con FTK Imager"
      text: "Abre FTK Imager, Add Evidence Item, navega hasta \\Windows\\System32\\winevt\\Logs\\, selecciona los archivos de canal (incluidos los *.evtx archivados) y Export Files. FTK lee NTFS directamente, saltándose los bloqueos de archivo del servicio EventLog."
    - name: "Recolección masiva con KAPE"
      text: "Ejecuta kape.exe --tsource C: --target EventLogs --tdest C:\\triage para sacar todos los .evtx bajo winevt\\Logs\\ en una pasada, con metadatos de cadena de custodia. Combínalo con el módulo EvtxECmd para parsear al recolectar."
    - name: "Lectura NTFS cruda"
      text: "Cuando se sospecha manipulación, usa RawCopy o tsk_recover para abrir el volumen por debajo de la capa del sistema de archivos (\\\\.\\PhysicalDriveN o \\\\.\\C:) y leer cada .evtx byte a byte desde la MFT. El servicio EventLog no puede bloquear esta ruta."
---

El primer problema duro en un trabajo de event log no es parsear. Es sacar los archivos del host sin que el servicio EventLog te dé un manotazo. En una máquina Windows en marcha, el servicio mantiene handles abiertos a los [archivos `.evtx`](/es/blog/what-is-an-evtx-file) activos en `C:\Windows\System32\winevt\Logs\`, así que un `copy` ingenuo devuelve errores de violación de uso compartido. Cuatro métodos cubren casi todos los casos con los que me he topado.

## wevtutil y Get-WinEvent: integrados, los más rápidos

La ruta más barata usa la API documentada por Microsoft:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Eso produce un `.evtx` sellado con todos los registros actualmente en el canal. Sin herramientas de terceros, shell de administrador requerida. La pega que vale la pena decir en voz alta: `epl` solo captura el log activo. Los archivos `Archive-Security-*.evtx` rotados en el mismo directorio se quedan atrás. Si la rotación ocurrió hace poco y los registros que quieres están en un archivo, este método los pierde.

PowerShell hace registros parseados en su lugar:

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

Eso te da un CSV, no un `.evtx`. Conveniente para triaje ad-hoc en la máquina. Inútil para [recuperación a nivel de chunk, inspección de chunks sucios o carving desde espacio no asignado](/es/blog/evtx-file-format-chunks), porque has tirado la fidelidad binaria.

## FTK Imager: adquisición a nivel NTFS

Cuando quieres el archivo, no los registros, FTK Imager es el caballo de batalla. Añade la unidad viva como evidencia (Physical Drive o Logical Drive), navega hasta `\Windows\System32\winevt\Logs\`, clic derecho sobre los archivos de canal y Export Files. FTK lee directamente las estructuras NTFS subyacentes, lo que esquiva el bloqueo del sistema de archivos que el servicio EventLog mantiene. También captura los archivos `Archive-*.evtx` archivados que `wevtutil epl` se salta.

Compromiso: FTK lee archivos que pueden estar a mitad de escritura. El chunk final del canal activo puede estar sucio. La mayoría de parsers manejan eso con elegancia (incluyendo el [parser de navegador de este sitio](/es/blog/how-to-open-an-evtx-file)) pero verifica en el banco antes de escribirlo en un informe. Las entradas correspondientes del [diario USN](https://www.usnparser.com) son corroboración útil cuando sospechas que el servicio EventLog hizo algo no estándar durante la adquisición.

## KAPE: recolección masiva a velocidad IR

Cuando el engagement tiene más de un host, el Kroll Artifact Parser and Extractor se paga en una hora.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

El target `EventLogs` barre todos los `.evtx` bajo `winevt\Logs\` (más los `.evt` heredados y las copias en `Windows.old`). Combínalo con el módulo `!EZParser` o `EvtxECmd` y KAPE también ejecutará EvtxECmd contra la colección al salir, dándote CSVs parseadas junto a la evidencia cruda. Ya que estás, los targets `RegistryHives`, `FileSystem` y `Prefetch` recogen los datos de [registro](https://www.registryparser.com), [MFT](https://www.mftparser.com), [diario USN](https://www.usnparser.com) y [prefetch](https://www.prefetchparser.com) que querrás de todos modos.

La salida de KAPE viene con metadatos de copy log. Eso importa para la cadena de custodia más de lo que la gente le reconoce.

## Lectura NTFS cruda: cuando sospechas manipulación

Para máxima fidelidad, baja por debajo de la capa del sistema de archivos. `tsk_recover` e `icat` del Sleuth Kit, o `RawCopy.exe` de Joakim Schicht, abren el volumen vía `\\.\PhysicalDriveN` o `\\.\C:`, recorren la MFT y emiten el contenido del archivo byte a byte. El servicio EventLog no puede bloquear esto porque la lectura no pasa por la API de archivos Win32.

Usa esto cuando un rootkit esté en juego, cuando tengas razón para pensar que un driver filtro de kernel está interceptando lecturas de `\winevt\Logs\`, o cuando simplemente no confíes en el SO en marcha. Combina el resultado con un [volcado RAM](https://www.ramparser.com) tomado en el mismo momento. El servicio event log cachea registros recientes en memoria, y un snapshot tomado minutos antes de la manipulación a veces contiene registros que nunca llegaron al disco.

## Cuál cuándo

- Un host, tienes admin, tienes una hora: `wevtutil epl` para cada canal que importe, comprime el directorio, listo.
- Imagen de disco ya en mano: FTK Imager o `tsk_recover` contra la imagen. Más rápido que el host vivo, y no tienes que coordinarte con el SOC.
- Múltiples hosts, engagement IR real: KAPE. Nada se le acerca en throughput.
- Sospecha de manipulación en vivo o rootkit: RawCopy o TSK contra el volumen, con la red del host aislada.

Sea cual sea el que elijas, documéntalo. Las CSVs parseadas no dicen nada de procedencia. Una línea en las notas del caso que diga `KAPE 1.3.0.2 EventLogs target, hash file attached` es la diferencia entre una prueba y una opinión.

## Lectura adicional

- [Documentación de KAPE](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)

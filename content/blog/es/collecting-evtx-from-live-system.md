---
title: "Cómo recolectar registros .evtx de un sistema Windows en vivo (4 métodos)"
description: "Cuatro formas de extraer .evtx de un host Windows en vivo — wevtutil, FTK Imager, KAPE, NTFS crudo — con sus compromisos de cadena de custodia y los comandos que realmente vas a ejecutar."
date: "2026-05-17"
howto:
  name: "Cómo recolectar registros .evtx de un sistema Windows en vivo"
  steps:
    - name: "Exportar con wevtutil"
      text: "Ejecuta wevtutil epl Security C:\\triage\\Security.evtx como administrador para sellar una copia portable del canal Security activo sin tocar el archivo en uso."
    - name: "Adquirir con FTK Imager"
      text: "Abre FTK Imager, Add Evidence Item → Physical or Logical Drive, navega a \\Windows\\System32\\winevt\\Logs\\, selecciona los archivos de canal (incluidos los *.evtx archivados) y Export Files. FTK lee NTFS directamente y evita los bloqueos del servicio EventLog."
    - name: "Recolección masiva con KAPE"
      text: "Ejecuta kape.exe --tsource C: --target EventLogs --tdest C:\\triage para extraer en una sola pasada todos los .evtx bajo winevt\\Logs\\ con metadatos de cadena de custodia. Combínalo con el módulo WindowsEventLogs para parsear durante la recolección."
    - name: "Lectura NTFS cruda"
      text: "Cuando se sospeche manipulación, usa RawCopy o tsk_recover para abrir el volumen por debajo de la capa del sistema de archivos (\\\\.\\PhysicalDriveN o \\\\.\\C:) y leer cada .evtx byte a byte desde la MFT. El servicio EventLog no puede bloquear esta ruta."
---

El primer problema duro en una investigación de event log no es el parsing, es *conseguir los archivos*. En un host Windows en ejecución, el servicio EventLog mantiene handles abiertos sobre los [`.evtx` activos](/es/blog/what-is-an-evtx-file) en `C:\Windows\System32\winevt\Logs\`, lo que significa que un `copy` ingenuo falla. Cuatro enfoques cubren casi todos los casos.

## Integrado: wevtutil / Get-WinEvent

El método más simple exporta registros (no el archivo) vía la API documentada:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

Esto produce un `.evtx` sellado con todos los registros actualmente en el log. Rápido, no requiere herramientas de terceros y se ejecuta como administrador. La desventaja: no captura los `.evtx` archivados (rotados), solo el activo.

Equivalente en PowerShell:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` devuelve registros parseados, no el archivo. Útil para un CSV de triage rápido, pero pierde la fidelidad binaria necesaria para análisis forense más profundo — [recuperación a nivel de chunk, inspección de dirty chunks, carving](/es/blog/evtx-file-format-chunks).

## FTK Imager

Para adquisición completa de disco o a nivel de filesystem, FTK Imager es el estándar. Añade la unidad en vivo como evidencia (Physical Drive o Logical Drive), navega a `\Windows\System32\winevt\Logs\`, clic derecho sobre los archivos del canal y Export Files. FTK lee las estructuras NTFS subyacentes directamente, evitando el lock de filesystem que mantiene el servicio EventLog. También exporta los `*.evtx` archivados (los que llevan timestamp en el nombre) que `wevtutil` no toca.

El compromiso es que FTK lee archivos que pueden estar en pleno proceso de escritura — el `.evtx` resultante puede tener un dirty trailing chunk. La mayoría de parsers ([incluido este](/es/blog/how-to-open-an-evtx-file)) lo manejan con elegancia, pero conviene verificar.

## KAPE

Para respuesta a incidentes a escala, Kroll Artifact Parser and Extractor (KAPE) automatiza la recolección de todos los archivos forensemente relevantes en una pasada:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

El target `EventLogs` extrae todos los `.evtx` bajo `winevt\Logs\` más los archivos de event tracing relacionados. Combínalo con el módulo `WindowsEventLogs` para ejecutar también un parse inmediato y producir un CSV junto a los archivos crudos. Recomendado para cualquier engagement de IR que toque más de un host.

## Lectura NTFS cruda

Para máxima fidelidad — útil cuando sospechas que las APIs del filesystem en vivo están siendo interceptadas o quieres adquisición bit a bit — lee el volumen por debajo de la capa de filesystem. Herramientas como [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) o `RawCopy.exe` de Eric Zimmerman abren el volumen vía `\\.\PhysicalDriveN` o `\\.\C:`, recorren la MFT y emiten el contenido del archivo byte a byte. El servicio EventLog no puede bloquearlo porque la lectura evita por completo la capa del filesystem.

## Cuándo usar cada uno

- **Triage rápido en un solo host, tienes admin**: `wevtutil`.
- **Adquisición forense completa, ya tienes una imagen de disco**: FTK Imager o `tsk_recover` contra la imagen.
- **Engagement de IR, múltiples hosts**: KAPE.
- **Sospecha de rootkit o tampering en vivo**: NTFS crudo vía RawCopy o TSK sobre el volumen vivo, con el host aislado de red.

Elijas la que elijas, documéntala. La cadena de procedencia importa en los informes de incidentes — un CSV parseado no dice nada sobre si vino de un host en vivo con el servicio EventLog corriendo o de una imagen sellada.

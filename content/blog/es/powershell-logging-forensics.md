---
title: "Logging de PowerShell: qué obtienes con module logging y script block logging activados"
description: "La diferencia práctica entre PowerShell module logging, script block logging, transcripciones y buffers AMSI, y las configuraciones GPO que realmente activan las útiles."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Cualquier toolkit de adversario digno de preocupación corre PowerShell en algún momento. Los beacons de Cobalt Strike lo lanzan. Empire y Covenant están construidos sobre él. Las guías de living-off-the-land empiezan con él. La buena noticia es que desde PowerShell 5.0, Microsoft ha enviado logging que, cuando se configura correctamente, captura el texto literal de todo lo que PowerShell ejecuta, incluidos payloads ofuscados después de la desofuscación. La mala noticia es que "cuando se configura correctamente" está haciendo mucho trabajo en esa frase. La mayoría de los entornos en los que entro tienen uno de los cuatro logs relevantes activado, no los cuatro, y no el más útil.

Este post es lo que realmente obtienes, qué vale la pena activar y dónde están las brechas.

## Los cuatro logs, en orden de utilidad

PowerShell escribe a `Microsoft-Windows-PowerShell%4Operational.evtx`. Los event IDs que importan:

- `4104` script block logging. El texto literal de cada script block que PowerShell compila y ejecuta. Si un block es marcado como sospechoso por las heurísticas integradas, se loguea con severidad Warning; si no, con Verbose, que está apagado por defecto. Este es el evento que quieres.
- `4103` module logging. Registra ejecución de pipeline por módulo, con binding de parámetros. Menos prosa que `4104`, más estructurado. Útil para "qué cmdlets corrieron" sin el cuerpo del script.
- `4105` y `4106` pipeline iniciada y pipeline detenida. Útiles para acotar, no para contenido.
- `400` / `403` (legacy, era PowerShell 2.0) cambios de estado del engine. Los eventos forense-históricos. Todavía verás estos en hosts donde alguien forzó un ataque de downgrade a PS 2.0.

Si puedes activar exactamente una cosa, activa `4104` en Verbose. Todo lo demás es suplementario.

## Lo que `4104` realmente captura

Un evento `4104` contiene el texto completo de un script block tal como PowerShell lo compiló. Dos cosas se siguen de "tal como PowerShell lo compiló":

- El texto en el evento es la representación *post-desofuscación* en la mayoría de los casos. Si un operador ejecuta `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`, obtienes tanto la llamada externa `iex` (que es por sí misma un `4104`) como un *segundo* `4104` para el script block decodificado interno, porque PowerShell tuvo que compilar ese block para correrlo. Esta es la propiedad más valiosa del logging `4104`.
- Los scripts grandes se dividen entre múltiples eventos usando `MessageNumber` y `MessageTotal` en los datos del evento. Un script de 50 KB se vuelve una cadena de eventos que tienes que reensamblar antes del análisis. La mayoría de las herramientas hacen esto; algunas no. Si tu parser te está mostrando fragmentos, verifica si maneja la cadena.

El campo `Path` muestra el archivo fuente si lo había. `Path` vacío más un cuerpo de script totalmente inline equivale a "esto vino por el cable o desde memoria" y es la mejor heurística para encontrar actividad de operador interactiva versus scripts programados.

El `ScriptBlockId` es un GUID. Las re-ejecuciones del mismo block en el mismo host típicamente reutilizan el GUID (por la caché), lo cual es conveniente para encontrar "cada host en el que corrió este código" si tienes un SIEM con búsqueda cross-host.

## Module logging: lo que `4103` agrega

Module logging es más antiguo y ruidoso que script block logging. Engancha la capa de ejecución de pipeline, así que por cada invocación de cmdlet en un módulo logueado obtienes un `4103` con el nombre del cmdlet, los parámetros bindeados y una cadena de payload.

En IR moderno, `4103` es más útil en tres casos:

- El atacante usó cmdlets que bindean parámetros interesantes (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` muestra la fuente; `4103` muestra los valores de parámetros resueltos después de la expansión de variables.
- El atacante usó comandos codificados. `powershell -enc <base64>` produce un `4103` con el texto decodificado en el payload antes de que se emita el `4104` correspondiente.
- El atacante deshabilitó `4104` (es alcanzable por edición de registro si tienen admin local). `4103` vive bajo una ruta de logging separada y a veces se deja activado cuando `4104` es silenciado.

La trampa: module logging loguea solo los módulos que están explícitamente habilitados. La configuración GPO quiere `*` (loguear todo) o una lista de nombres de módulos. `*` es la respuesta en cualquier entorno que tome el logging en serio. La objeción de "impacto en rendimiento" que vas a oír es real para cargas PowerShell muy pesadas y errónea para escritorios de flota ordinarios.

## Las transcripciones no son script block logs

Hay una configuración separada llamada "Turn on PowerShell Transcription" que escribe la entrada y salida de cada sesión a un archivo de texto bajo un directorio configurado. Esto no es lo mismo que `4104` y la gente las confunde constantemente.

Las diferencias que importan:

- Las transcripciones incluyen la *salida* de los cmdlets. `4104` no. Si quieres saber lo que `Get-ADUser` realmente devolvió, las transcripciones lo son.
- Las transcripciones son archivos de texto. Son trivialmente borrables y trivialmente modificables en un host comprometido. Los eventos `4104` van a un canal EVTX que requiere limpieza de log o peor para perturbar.
- Las transcripciones van por defecto a la carpeta de documentos del usuario a menos que `OutputDirectory` esté establecido. Si no estableces `OutputDirectory` a un share de red de solo escritura, las transcripciones no son evidencia; son una cortesía.

Activa las transcripciones con `OutputDirectory` apuntando a una ruta UNC donde el usuario que escribe tenga permisos NTFS de solo escritura (sin lectura, sin borrado). Eso te da el rastro de salida de cmdlets que `4104` no da, sin darle al atacante la opción de alterar o eliminar su propio historial.

## AMSI y el ángulo del buffer

AMSI (la Antimalware Scan Interface) es el hook de runtime que permite a Defender y a otros productos AV inspeccionar el contenido de scripts PowerShell antes de la ejecución. Dos consecuencias para la forensia:

- Incluso si el atacante deshabilita el logging de PowerShell, AMSI todavía ve el contenido del script justo antes de la ejecución, y Defender loguea un `1116` o `1117` en `Microsoft-Windows-Windows Defender%4Operational.evtx` si el contenido coincide con una firma. El evento de Defender incluye el texto del script, parcialmente, en el registro de detección de amenaza. En hosts donde script block logging estaba apagado, este es a veces el único lugar donde vive el código malicioso.
- Las técnicas de "bypass AMSI" que usan los atacantes (parcheo de `amsi.dll!AmsiScanBuffer` en memoria, proporcionar un `AmsiContext` falsificado, COM hijack del proveedor AMSI) generan ellos mismos típicamente eventos `4104` para el código de bypass, *antes* de que el bypass entre en efecto. El bypass no puede apagar el logging retroactivamente. Así que incluso en hosts donde el operador neutralizó exitosamente AMSI, el momento en que lo hizo está registrado.

El patrón a buscar en `4104`: pequeños script blocks que contienen las cadenas `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect`, o `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`. Estas son las firmas de cada bypass común.

## Activando el logging

Las configuraciones GPO viven bajo `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. Las tres que quieres habilitadas:

- "Turn on PowerShell Script Block Logging" habilitada. Marca "Log script block invocation start / stop events" si quieres los eventos `4105`/`4106` de acotación; apagado por defecto y usualmente no vale el volumen.
- "Turn on Module Logging" habilitada. Nombres de módulos: `*`.
- "Turn on PowerShell Transcription" habilitada. `OutputDirectory`: una ruta UNC. `Include invocation headers`: marcado.

Las rutas de registro correspondientes si las estás estableciendo fuera de GPO:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

Aplica a las OUs que contienen máquinas que tendrías que investigar. Eso es "todas ellas" en cualquier organización seria.

## Cómo se ve esto durante una investigación

Un compromiso donde script block logging estaba activado te dice, en orden:

1. El primer `4104` con un script block no trivial desde un padre no estándar. Hora de primera ejecución.
2. La cadena de `4104`s a medida que el loader se desempaqueta a sí mismo. Cada capa de ofuscación pelada y logueada.
3. Los cmdlets de runtime del framework C2 (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, cada nombre de cmdlet ofensivo común y sus variantes renombradas).
4. Los comandos hands-on-keyboard del operador interactivo. Se leen como una sesión de shell grabada, porque eso es lo que son.

Cruza-referencia contra [Prefetch](https://www.prefetchparser.com) para encontrar cuándo corrió `powershell.exe`, [archivos LNK](https://www.lnkparser.com) para archivos que el operador abrió, [AmCache](https://www.amcacheparser.com) para el hash del propio binario PowerShell (se renombra a veces), y el [registro](https://www.registryparser.com) para el estado de GPO para confirmar que el logging realmente estaba activado en el momento de los eventos que estás leyendo.

Un compromiso donde script block logging estaba apagado te dice casi nada sobre PowerShell, y mucho sobre tu postura de detección. Arregla eso primero.

## Lecturas adicionales

- [Documentación de logging de PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows) de Microsoft. La referencia oficial.
- Post de FireEye / Mandiant [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility). Antiguo pero todavía el writeup más limpio con perspectiva de campo.
- Proyecto [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) de Daniel Bohannon. El toolkit de desofuscación que complementa el análisis `4104`.

---
title: "«No se encuentra la descripción del id. de evento»: solución"
description: "Por qué el Visor de eventos no encuentra la descripción de un Event ID, qué significan códigos como %%1833 y cómo leer el evento igualmente, sin conexión."
date: "2026-09-24"
tags:
  - evtx
  - dfir
  - event-viewer
  - troubleshooting
  - windows-event-log
author: "Florian Amette"
faq:
  - question: "¿Qué significa «The description for Event ID X from source Y cannot be found»?"
    answer: "El registro en sí está bien. Un registro .evtx solo almacena el Event ID, el nombre del proveedor y las cadenas de inserción (EventData / UserData). La frase que normalmente lees en el Visor de eventos es una plantilla guardada en la DLL de mensajes del proveedor, en la máquina que muestra el registro. Si ese proveedor no está registrado en tu máquina, el Visor no puede construir la frase y muestra este error seguido de las cadenas de inserción en bruto."
  - question: "¿Se han perdido o dañado los datos del evento?"
    answer: "No. Todos los campos siguen en el registro. Abre la pestaña Detalles (Vista XML) del Visor de eventos, o lee los campos de EventData con Get-WinEvent, wevtutil o un parser. Solo falta el texto legible que los envuelve."
  - question: "¿Qué significa %%1833 en un evento?"
    answer: "%%1833 es una referencia a un mensaje de parámetro que se resuelve desde msobjs.dll, el archivo de mensajes de parámetros del proveedor de auditoría de seguridad. %%1833 significa Impersonation (campo ImpersonationLevel del 4624). Otros frecuentes: %%1842 Yes, %%1843 No, %%2313 Unknown user name or bad password, %%1936/%%1937/%%1938 tipo de elevación del token 1/2/3."
  - question: "¿Cómo exporto un .evtx para que se abra con descripciones en otro equipo?"
    answer: "En la máquina de origen, en el Visor de eventos, usa Guardar todos los eventos como, elige .evtx y selecciona la opción de mostrar información para los idiomas deseados. El Visor escribe una carpeta LocaleMetaData con archivos .MTA junto al .evtx. Copia ambos juntos. wevtutil archive-log (wevtutil al) hace lo mismo desde la línea de comandos."
  - question: "¿Puedo leer el evento sin instalar el proveedor?"
    answer: "Sí. En DFIR rara vez necesitas el mensaje renderizado: los campos de EventData contienen todos los valores que mostraría el mensaje. El parser en navegador de evtxparser.com además muestra una descripción de una línea para los eventos DFIR habituales y decodifica sin conexión los códigos %%, los códigos NTSTATUS y los tipos de cifrado Kerberos, sin subir el archivo."
---

Copias un `Security.evtx` de un host sospechoso, lo abres en tu estación de análisis y cada registro muestra:

> The description for Event ID 4625 from source Microsoft-Windows-Security-Auditing cannot be found. Either the component that raises this event is not installed on your local computer or the installation is corrupted. You can install or repair the component on the local computer. If the event originated on another computer, the display information had to be saved with the event.

En un Windows en español, el mismo mensaje empieza con «No se encuentra la descripción del id. de evento 4625 en el origen Microsoft-Windows-Security-Auditing.» Después aparece un bloque de valores en bruto: `%%2313`, `0xC000006A`, `0x17`. No hay nada roto ni perdido. Es un fallo de *renderizado*, no de datos. Este artículo explica dónde vive realmente el texto de la descripción, por qué desaparece, cómo arreglarlo cuando lo necesitas y por qué, para el triaje, normalmente no lo necesitas. (Si solo quieres los eventos legibles ya: [el parser en navegador](/es) renderiza descripciones y decodifica esos códigos sin conexión.)

## Qué significa realmente el error

Un registro `.evtx` no almacena la frase que lees en el Visor de eventos. Almacena el bloque `<System>` (proveedor, Event ID, hora, equipo) y las **cadenas de inserción** en `<EventData>` o `<UserData>` ([qué hay dentro de un registro](/es/blog/what-is-an-evtx-file)). La frase («An account failed to log on. Subject: … Failure Reason: …» en un Windows en inglés) es una plantilla con marcadores `%1`, `%2` guardada en un **recurso de tabla de mensajes** dentro de una DLL o EXE que pertenece al proveedor del evento.

Dónde busca Windows ese archivo depende del tipo de proveedor:

- **Los orígenes de eventos clásicos (legacy)** se registran en `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`, con la ruta en el valor `EventMessageFile` (y opcionalmente `ParameterMessageFile` y `CategoryMessageFile`).
- **Los proveedores basados en manifiesto** (Vista en adelante, la familia `Microsoft-Windows-*`) se registran en `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. Los valores `MessageFileName`, `ResourceFileName` y `ParameterFileName` apuntan a los binarios que contienen el manifiesto compilado (recurso `WEVT_TEMPLATE`) y la tabla de mensajes.

La clave: **el Visor de eventos renderiza el mensaje en la máquina donde consultas el registro**, con el registro de Windows y las DLL de esa máquina. La máquina que escribió el evento no interviene en la visualización. Si el proveedor no está registrado localmente, no hay plantilla y obtienes el error seguido de las cadenas de inserción en bruto.

## Causas habituales

- **El registro viene de otro host.** El caso DFIR clásico. Un agente de terceros, un EDR, una instancia de SQL Server o una aplicación de negocio del host de origen no tienen proveedor en tu estación de análisis. Abrir el archivo en macOS, Linux o una VM limpia tiene el mismo efecto: ningún proveedor de Windows.
- **Se desinstaló el software.** El desinstalador eliminó la DLL, pero los eventos antiguos siguen haciendo referencia al origen.
- **DLL ausente, dañada o movida.** El registro apunta a una ruta que ya no existe, o `EventMessageFile` está guardado como `REG_SZ` en lugar de `REG_EXPAND_SZ`, así que `%SystemRoot%` nunca se expande.
- **Desajuste 32/64 bits.** Un instalador de 32 bits escribió su DLL en lo que creía que era `System32` (en realidad `SysWOW64`, por la redirección del sistema de archivos), mientras que la pila de Event Log de 64 bits lee la ruta registrada como el `System32` real.
- **Idioma.** La tabla de mensajes del proveedor existe pero no en el idioma de visualización, o abriste una exportación guardada «con información de visualización» para un idioma distinto del de tu visor.

## Los códigos %%: mensajes de parámetros

Incluso cuando la descripción principal se renderiza, algunos campos muestran `%%1833` o `%%2313` en lugar de palabras. Son referencias a **mensajes de parámetros**: el valor es un identificador en una segunda tabla de mensajes, el `ParameterMessageFile` / `ParameterFileName` del proveedor. Para el proveedor de auditoría de seguridad ese archivo es `msobjs.dll`. Sin conexión, esas referencias quedan sin resolver. Las que conviene saberse de memoria (etiquetas tal como las muestra un Windows en inglés):

| Código | Significado | Dónde aparece |
|--------|-------------|---------------|
| `%%1833` | Impersonation | 4624 `ImpersonationLevel` |
| `%%1840` | Delegation | 4624 `ImpersonationLevel` |
| `%%1842` / `%%1843` | Yes / No | 4624 `VirtualAccount`, `ElevatedToken` |
| `%%1936` | Tipo 1, token completo (UAC desactivado o admin integrado) | 4688 `TokenElevationType` |
| `%%1937` | Tipo 2, token elevado | 4688 `TokenElevationType` |
| `%%1938` | Tipo 3, token limitado | 4688 `TokenElevationType` |
| `%%2307` | Account locked out (cuenta bloqueada) | 4625 `FailureReason` |
| `%%2310` | Account currently disabled (cuenta deshabilitada) | 4625 `FailureReason` |
| `%%2313` | Unknown user name or bad password | 4625 `FailureReason` |
| `%%2080` | Account Disabled | 4720 `UserAccountControl` |
| `%%2082` | 'Password Not Required' - Enabled | 4720 `UserAccountControl` |
| `%%2084` | 'Normal Account' - Enabled | 4720 `UserAccountControl` |
| `%%1537` | DELETE | 4663 `AccessList` |
| `%%4416` / `%%4417` | ReadData / WriteData | 4663 `AccessList` |

El triplete `%%2080 %%2082 %%2084` es la firma normal de una cuenta recién creada en un [4720](/es/blog/event-id-4720-account-created). Un `%%1937` en un [4688](/es/blog/event-id-4688-process-creation) es un proceso iniciado con un token de administrador completo tras un aviso de UAC.

Los valores hexadecimales no son códigos `%%`. Los campos `Status` / `SubStatus` del [4625](/es/blog/detecting-4625-brute-force) son códigos NTSTATUS: `0xC000006A` es una contraseña incorrecta para una cuenta válida, `0xC0000064` un nombre de usuario que no existe, `0xC0000234` una cuenta bloqueada. `TicketEncryptionType` en el [4769](/es/blog/event-id-4769-kerberoasting) es un etype de Kerberos: `0x17` es RC4-HMAC, `0x12` AES256. Ambos se muestran como hexadecimal en bruto incluso cuando el proveedor está presente.

## Solución 1: exportar con información de visualización

Si todavía tienes acceso al host de origen, exporta el registro para que viaje con sus mensajes. En el Visor de eventos: clic derecho sobre el registro, **Guardar todos los eventos como…**, elige `.evtx` y en el siguiente diálogo selecciona mostrar información para los idiomas deseados (**Display information for these languages** en un Windows en inglés). El Visor escribe una carpeta `LocaleMetaData` junto al archivo, con un `.MTA` por idioma. Mantén la carpeta junto al `.evtx` al copiarlo; el Visor de la máquina de análisis la utiliza.

Desde la línea de comandos:

```powershell
wevtutil epl Security C:\ir\Security.evtx
wevtutil al C:\ir\Security.evtx /l:en-US
```

`wevtutil al` (archive-log) añade los metadatos de idioma a un archivo exportado. Para recolección a escala, consulta [recolectar EVTX de un sistema en vivo](/es/blog/collecting-evtx-from-live-system).

## Solución 2: instalar o reparar el proveedor

En una máquina que administras, cuando los eventos de tu propio software no se renderizan:

- Reinstala o repara la aplicación dueña del origen.
- Revisa `EventMessageFile` en `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>\<Source>`: la ruta debe existir y el tipo de valor debería ser `REG_EXPAND_SZ` si contiene `%SystemRoot%`.
- Para proveedores con manifiesto, comprueba `Get-WinEvent -ListProvider <Name>`; si falla o no lista mensajes, el registro del manifiesto está roto (`wevtutil im <manifest>.man` lo vuelve a registrar, con los binarios en su sitio).

## Solución 3: renderizar en el host de origen

`Get-WinEvent` solo rellena la propiedad `Message` cuando el proveedor está presente localmente. En el host de origen (o en una máquina con el mismo software instalado) esto funciona:

```powershell
Get-WinEvent -Path .\Security.evtx -MaxEvents 20 | Select-Object TimeCreated, Id, Message
```

En tu estación, el mismo comando devuelve un `Message` vacío, pero `.Properties` y `.ToXml()` siguen exponiendo todos los valores. Más recetas de filtrado en [consultar EVTX con Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent) (en inglés).

## Solución 4: normalmente no necesitas el mensaje

En DFIR, la frase renderizada es una comodidad. Todos los valores que mostraría están en `<EventData>`: `TargetUserName`, `LogonType`, `IpAddress`, `Status`, `SubStatus`. La pestaña **Detalles** (Vista XML) del Visor los muestra aunque la pestaña General muestre el error. Quien analiza a escala lee los campos directamente de todos modos, y así es como conviene abordar el [4624](/es/blog/understanding-event-id-4624) y el resto de la [familia de eventos de inicio de sesión](/en/blog/windows-logon-events-explained): los nombres de campo son estables entre versiones e idiomas de Windows; el texto renderizado no.

## Leer eventos sin conexión en el navegador

El [parser EVTX](/es) muestra ahora una descripción legible de una línea para unos 60 eventos DFIR habituales: inicios de sesión y fallos 4625, cambios de cuentas y grupos, Kerberos 4768/4769/4771, NTLM 4776, servicios 7045/4697, tareas programadas, Sysmon, PowerShell 4104 y RDP. También decodifica en línea los códigos `%%`, los códigos NTSTATUS (`0xC000006A` contraseña incorrecta, `0xC0000064` usuario desconocido) y los tipos de cifrado de tickets Kerberos (`0x17` RC4). No necesita DLL de proveedores ni Windows; el archivo se analiza en tu navegador y nunca se sube. Para otras formas de abrir el archivo, consulta [cómo abrir un archivo EVTX](/es/blog/how-to-open-an-evtx-file).

## Checklist

- El error significa que **la máquina que visualiza** no tiene el proveedor, no que el registro esté dañado.
- Lee `<EventData>` en la pestaña Detalles, con `.Properties` de `Get-WinEvent` o con un parser.
- Decodifica las referencias `%%` con la tabla anterior; decodifica `Status` / `SubStatus` como NTSTATUS.
- ¿Necesitas el texto renderizado para un informe? Vuelve a exportar en el host de origen con información de visualización (`LocaleMetaData`) o `wevtutil al`.
- Para tu propio software, corrige `EventMessageFile` o vuelve a registrar el manifiesto.

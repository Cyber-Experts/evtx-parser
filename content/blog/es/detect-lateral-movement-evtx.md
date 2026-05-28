---
title: "Detectar movimiento lateral en Security.evtx"
description: "Cómo las herramientas adversarias reales se mueven de host a host en parques Windows, y las combinaciones precisas de Event ID en Security.evtx que cazan a PsExec, Impacket y WMIExec."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

El movimiento lateral es donde la mayoría de las intrusiones pasan de "tienen un punto de apoyo" a "son dueños del dominio". También es donde el logging de Windows es más útil y más engañoso. Los eventos que necesitas están todos en `Security.evtx` y `System.evtx`. Leerlos aisladamente no te llevará a ningún lado. Leerlos en los pares correctos, con la correlación cross-host correcta, es lo que separa una timeline útil de un muro de `4624`s.

Esta es la parte de una investigación donde dejo de scrollear y empiezo a grepear por `LogonId`.

## El esqueleto: qué pasa cuando un atacante se mueve

No hay un patrón universal de movimiento lateral, pero sí una *forma* universal:

1. El atacante se autentica desde el host A al host B, ya sea con el token del usuario actual (pass-the-hash, pass-the-ticket o un TGT/TGS Kerberos robado) o con credenciales explícitas para otra cuenta.
2. Algo en el host B ejecuta su payload: un servicio, una tarea programada, un WMI process create, una sesión de PowerShell remoto o una invocación DCOM.
3. Vuelven a salir a buscar tooling, secretos o el siguiente salto.

Cada paso deja eventos. La pregunta es si estás mirando los correctos, y si el tooling ha sido instrumentado siquiera.

## 4624 LogonType 3 es la puerta principal

Un logon de red exitoso, `EventID=4624` con `LogonType=3`, es la primitiva de movimiento lateral más común en el log. También es el evento más ruidoso que Windows genera. Un file server en una oficina de 500 puestos produce decenas de miles de estos al día, todos legítimos. Filtrar solo por `LogonType=3` no te llevará a ningún lado.

Lo que sí te lleva a algún lado:

- `IpAddress` y `WorkstationName` en los datos del evento. Las anomalías se agrupan aquí. Una estación de trabajo logueándose en un servidor desde una subred distinta a las 02:14 UTC no es nada despreciable.
- `AuthenticationPackageName` y `LogonProcessName`. Los logons NTLM (`NTLM` / `NtLmSsp`) entre hosts unidos al dominio en un entorno Kerberos son sospechosos por defecto. Un entorno Kerberos limpio debería ser solo Kerberos para auth intra-dominio, con NTLM cayendo solo para acceso por nombre no-DNS y legacy.
- Patrones de `TargetUserName`. Cuentas de servicio logueándose interactivamente son banderas rojas. Cuentas de domain admin logueándose en estaciones de trabajo son banderas rojas.

El pivote que quieres: empareja cada `4624 Type 3` interesante con el `4672` (privilegios especiales) correspondiente sobre el mismo `TargetLogonId`. Si el logon obtuvo privilegios de admin, tienes un candidato para abuso de credenciales. Si no, el atacante opera con un token de menor privilegio y tienes tiempo.

## 4648 es el evento que la mayoría de defensores infrautiliza

`4648`, "se intentó un logon usando credenciales explícitas", se genera cuando un proceso ejecutándose como cuenta A invoca credenciales para la cuenta B para hacer algo. Este es el evento que quieres para atribución. Cuando `mimikatz` o `Rubeus` inyecta un ticket y el operador ejecuta `net use \\TARGET /user:CORP\admin <pass>`, obtienes un `4648` en el host originario mostrando ambas cuentas y el destino.

Los campos que importan:

- `SubjectUserName` / `SubjectLogonId`: quién inició.
- `TargetUserName` / `TargetServerName`: las credenciales de quién, contra qué.
- `ProcessName`: qué binario hizo la invocación. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (para ejecución basada en WMI), y cada vez más `pwsh.exe` son los sospechosos habituales.

`4648` es el enlace entre un host comprometido y el siguiente salto. Si tienes un host sospechoso, vuelca `4648` de su log de Security primero. Te dirá qué credenciales tiene el atacante y dónde intentó usarlas, en orden temporal, en un solo sitio.

## 4672 y la historia de privilegios

`4672` se deja inmediatamente después de `4624` para cualquier logon que acabe con al menos un privilegio sensible (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc.). Se genera para cada logon de un miembro de `Administrators`, `Domain Admins` o de cualquier cuenta con privilegios que elevan el token.

Trátalo como una etiqueta, no como un hallazgo. La consulta útil es "muéstrame cada `4672` seguido en 60 segundos por un `4624 Type 3` desde una IP origen que no sea DC", que saca a la luz uso de tokens admin desde estaciones de trabajo que no deberían emitirlos. La consulta no-útil es "muéstrame cada `4672`", que devolverá cada arranque de servicio en cada servidor.

## 4697 y 7045: servicios como ejecución remota

PsExec, `psexec.py` de Impacket y `smbexec.py` funcionan escribiendo un binario de servicio en el share `ADMIN$` del objetivo, registrándolo vía el Service Control Manager, arrancándolo y desmontándolo. Esto deja:

- `5145` en el objetivo mostrando acceso a `\\target\ADMIN$` con el nombre del archivo escrito (si el auditing de acceso a objetos está activo).
- `7045` en `System.evtx` mostrando la instalación del servicio. La ruta del binario del servicio y el nombre del servicio están en los datos del evento. PsExec usa por defecto `PSEXESVC` en `%SystemRoot%`; Impacket randomiza ambos, con patrones que varían por versión y están bien documentados.
- `4697` en `Security.evtx` para la misma instalación de servicio si tienes la política de auditoría de sistema configurada.
- `4624 Type 3` desde la estación de trabajo origen del operador.

La firma es la *combinación*: `4624 Type 3` desde un origen inusual, inmediatamente seguido de `5145` a `ADMIN$`, inmediatamente seguido de `7045` para un servicio cuyo binario vive en algún sitio donde no debería. Cada evento solo es plausible. La combinación, en segundos, con el mismo `LogonId` enlazándolos, no lo es.

Nombres de servicio a vigilar en `7045`: cadenas aleatorias de 8 caracteres minúsculas (default Impacket), `PSEXESVC` (default PsExec), `WinExec` o sus variantes, cualquier cosa con una ruta de binario bajo `C:\Windows\` que no esté firmada y no esté en el conjunto normal de servicios del sistema.

## 5140 y 5145: acceso a shares SMB en detalle

`5140` registra que se accedió a un share; `5145` registra el nombre del archivo accedido dentro del share, *si* el auditing de acceso a objetos para el share está activado. La mayoría de los entornos no activan `5145` por el ruido. La mayoría de los entornos también desean tenerlo durante un incidente.

Para movimiento lateral, los eventos `5145` que importan son accesos a `ADMIN$`, `C$`, `IPC$` y cualquier ruta `SYSVOL`/`NETLOGON` desde orígenes inusuales. `psexec.py` escribe su binario de servicio escribiendo a `\\target\ADMIN$\<random>.exe`. `secretsdump.py` lee `\\target\C$\Windows\System32\config\SAM` (y SYSTEM y SECURITY). Cada uno de esos es un `5145` con un `RelativeTargetName` que debería destacar.

Empareja `5145` con el [diario USN](https://www.usnparser.com) en el objetivo. El diario tendrá un `FILE_CREATE` para el mismo archivo con el mismo timestamp, lo que te da una confirmación de segunda fuente de que el archivo realmente aterrizó, y una referencia de registro [MFT](https://www.mftparser.com) que perseguir.

## WMI como vector de movimiento lateral

La ejecución remota basada en WMI (`wmic /node:... process call create`, `wmiexec.py` de Impacket, `Invoke-WmiMethod` de PowerShell) es más difícil de detectar en Security.evtx solo porque no instala un servicio. Obtienes:

- `4624 Type 3` en el objetivo.
- Una creación de proceso en el objetivo con `WmiPrvSE.exe` como padre. Esto está en Sysmon `EventID=1` si Sysmon está activo. En `4688` es el mismo cuadro si el auditing de línea de comandos está activo.
- Eventos WMI en `Microsoft-Windows-WMI-Activity%4Operational.evtx` mostrando el consumer.

Si Sysmon no está activo, el movimiento lateral basado en WMI es mayormente invisible en logs de eventos con config por defecto. Esta es una de las razones por las que toda baseline de configuración empuja Sysmon con fuerza.

## Correlacionar entre hosts

El movimiento lateral es un problema de grafos. Un `4648` en el host A nombrando al host B y la cuenta `corp\admin` es una arista. El `4624 Type 3` correspondiente en el host B desde la IP del host A, con `TargetUserName=admin`, es el otro extremo de la misma arista. El `4769` (ticket de servicio Kerberos) en el DC mostrando la solicitud de ticket para `cifs/hostB` desde `admin@CORP` es el tercer testigo.

En la práctica quieres todo de:

- Eventos de logon del `Security.evtx` del host origen.
- Eventos de logon del `Security.evtx` del host objetivo.
- Eventos TGT (`4768`) y TGS (`4769`) del `Security.evtx` del controlador de dominio.
- Eventos reenviados desde cualquier recolector WEC, que a veces tienen la única copia intacta si el log local de un host fue borrado.

Átalos por `LogonId` dentro de un host y por timestamp + cuenta + IP entre hosts. El paper clásico de JPCERT/CC lo expone en detalle y es el mejor documento gratuito sobre el tema.

Para los artefactos del lado del host que sobreviven al borrado del log, apóyate en [Prefetch](https://www.prefetchparser.com) como evidencia de ejecución de tooling de atacante, la clave `Services` del [registro](https://www.registryparser.com) para el rastro de un binario de servicio instalado y removido, y los [archivos LNK](https://www.lnkparser.com) y [jump lists](https://www.jumplistparser.com) como evidencia de archivos que un operador abrió durante una sesión hands-on.

## Lectura adicional

- ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) de JPCERT/CC. La referencia. Léela dos veces.
- La [matriz de Lateral Movement](https://attack.mitre.org/tactics/TA0008/) de MITRE ATT&CK y los mapeos de data source por técnica.
- El [directorio examples](https://github.com/fortra/impacket/tree/master/examples) de Impacket. Si no has leído lo que `psexec.py`, `wmiexec.py` y `smbexec.py` realmente hacen en cable, tus detecciones son conjeturas.

---
title: "Configuración de Sysmon que atrapa adversarios reales"
description: "Una visión opinada sobre Sysmon: qué event IDs realmente importan en IR, por qué olafhartong/sysmon-modular es la baseline correcta, y los errores de configuración que te ciegan ante ataques reales."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon es la única cosa con mayor apalancamiento que puedes desplegar en un endpoint Windows. Es gratuito, está firmado por Microsoft, y un Sysmon bien configurado convierte a Windows de una caja negra a algo que realmente puedes investigar. Un Sysmon mal configurado, por otro lado, es el mismo coste de espacio en disco con la mayor parte de la visibilidad excluida por filtros demasiado agresivos. He entrado en más entornos con el segundo que con el primero.

Esta es la postura de configuración que defiendo en cada engagement que toca visibilidad de endpoint.

## Los EIDs que se ganan su espacio en disco

Sysmon define 29 event IDs a partir de la versión 15. No necesitas todos. Los que devuelven el almacenamiento que cuestan, en orden de retorno por byte:

- **EID 1 Process create**. El evento más útil en DFIR. Proceso padre, proceso hijo, línea de comandos, integrity level, usuario, ambos hashes de proceso y el process GUID. Si no logueas nada más de Sysmon, loguea esto.
- **EID 3 Network connection**. Cada conexión TCP/UDP saliente con proceso origen, IP destino, puerto y la imagen del proceso. El evento de detección de C2. El filtro es esencial aquí (una instalación por defecto loguea cada petición de navegador y tu retención arde en una semana), pero el valor por evento es extremo. Atrapa salidas a destinos inusuales desde procesos inusuales (`rundll32.exe` a una IP residencial, `mshta.exe` a cualquier cosa).
- **EID 7 Image loaded**. Cargas de DLL y driver con el hash de la imagen cargada y estado de firma. Así atrapas DLL search-order hijacking, sideloading y drivers sin firmar. Caro loguear todo; barato y alto rendimiento loguear módulos sin firmar y módulos cargados desde ubicaciones no estándar.
- **EID 10 Process accessed**. Eventos de acceso a memoria cross-process con el proceso origen, proceso destino, máscara de acceso otorgada, y el call trace. Este es el evento de credential dumping. `mimikatz` abre `lsass.exe` con `PROCESS_VM_READ` (`0x10`) y `PROCESS_QUERY_INFORMATION` (`0x400`). Cada dumper moderno lo hace. La detección se escribe sola.
- **EID 11 File created**. Creaciones de archivo nuevo con el proceso que escribe. Atrapa actividad de dropper que no llegó a ejecutarse, staging de ransomware y la mayoría de escrituras de payload mediadas por LOLBin.

Estos cinco son la base. Si solo tienes esos, bien configurados, has atrapado la mayor parte de lo que llamarías una intrusión real antes de que se convierta en una.

El siguiente nivel que vale la pena activar:

- **EID 8 CreateRemoteThread**. Inyección de hilo a través de fronteras de proceso. El evento clásico de process injection.
- **EID 13 Registry value set**. Persistencia vía registro. Afina a las claves run, servicios, image file execution options, y las rutas de COM hijack.
- **EID 17/18 Named pipe created/connected**. Los beacons Cobalt Strike y muchos frameworks de post-explotación usan named pipes para SMB y comunicaciones inter-proceso. Los nombres de pipe a menudo son defaults que sobreviven de engagement a engagement.
- **EID 22 DNS query**. DNS saliente con el proceso solicitante. Atrapa C2 basado en DNS (DGA, DNS tunnel) cuando EID 3 perdió la conexión porque nunca abrió un socket TCP/UDP.
- **EID 25 Process tampering**. Eventos de manipulación de imagen (process hollowing, doppelganging). Sysmon 13+.

EID 12 (registry key/value create), 14 (registry key/value renamed), 15 (file stream created con FileCreateStreamHash) y 23 (file delete con archive) son útiles en investigaciones específicas pero producen demasiado volumen para loguear en todas partes por defecto. Actívalos para un host que estés observando de cerca o para rutas específicas.

EID 2 (process changed file creation time) es un evento anti-timestomp de nicho. Vale la pena en servidores de archivos. Opcional en otros lugares.

EID 4, 5, 6 (eventos de estado Sysmon) son operacionales, no de detección. Loguéalos para que puedas saber cuándo Sysmon fue manipulado.

## Por qué `olafhartong/sysmon-modular` es el punto de partida correcto

Hay media docena de configs Sysmon públicos de calidad variable. Los dos más citados son `sysmon-config` de SwiftOnSecurity y `sysmon-modular` de Olaf Hartong. Ambos son buenos. `sysmon-modular` es al que empujo por su estructura.

El layout modular divide los filtros por EID y por técnica en archivos XML individuales que se concatenan en el despliegue. Los beneficios que esto te da:

- **Diffabilidad**. Los cambios al filtro de una sola técnica aparecen como un diff de archivo único en git. Compáralo con un XML monolítico de 4000 líneas donde un pequeño cambio desaparece en el ruido.
- **Overlays por entorno**. Comiteas el árbol upstream y haces layer con tus exclusiones específicas del entorno encima en tus propios archivos. Cuando upstream actualiza un filtro, haces `git merge` y tus overlays sobreviven.
- **Autoría guiada por cobertura**. Los filtros están organizados por técnica MITRE ATT&CK. Puedes ver de un vistazo para qué técnicas tienes cobertura y cuáles no. El análisis de brechas es el árbol de archivos.
- **Mantenimiento activo**. Hartong actualiza el repo contra nuevas técnicas y nuevas versiones de Sysmon. El config SwiftOnSecurity tiene largos tramos de estancamiento entre actualizaciones.

Empieza desde `sysmon-modular`. Comitéalo en tu árbol de gestión de config. Haz layer con tus exclusiones. No escribas el tuyo desde cero; te perderás cosas.

## Los errores de configuración que te ciegan

Los patrones que veo en engagements reales que cuestan más visibilidad:

**Excluir demasiado agresivamente en EID 1**. El instinto es excluir cada proceso legítimo parlanchín para mantener el volumen manejable. El error es excluir por ruta padre o imagen sin pensar en lo que un atacante puede generar desde ese padre. Si excluyes cada hijo de `services.exe`, has excluido el lugar exacto donde corren los binarios de servicio instalados por PsExec. Excluye por `User` (cuentas de sistema corriendo binarios conocidos como buenos), por `IntegrityLevel`, y por coincidencia precisa de `CommandLine`, no solo por padre.

**Excluir EID 3 por nombre de imagen**. "Excluir todas las conexiones de red desde `chrome.exe`" es la regla mala canónica. Lo primero que un atacante hace cuando necesita evadir el logging de EID 3 es secuestrar un proceso de navegador. Excluye por rango de IP destino (RFC1918 a RFC1918, tu propia infra), por puerto (el conjunto de puertos IPC que has validado), o por tupla proceso+destino. Nunca por imagen sola.

**No loguear EID 7 en absoluto**. El logging de Image load es el EID Sysmon más pesado por volumen. La tentación de desactivarlo es fuerte. El coste de desactivarlo es que el DLL sideloading, la técnica más común en intrusiones modernas, es invisible para ti. El camino del medio: filtrar `Image load` a módulos sin firmar, módulos cargados desde `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%` y `%PROGRAMDATA%`, y módulos con nombres que coincidan con listas conocidas de abuso. Esto reduce el volumen en un orden de magnitud y mantiene la señal.

**Faltar EID 11 enteramente en rutas escribibles por usuario**. EID 11 logueado para `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%` y `%PUBLIC%` atrapa casi cada dropper. Algunos configs excluyen estos por el volumen. El volumen es el punto: ahí es donde ocurren las escrituras que importan.

**No incluir el algoritmo de hash que quieres**. El elemento `<HashAlgorithms>` controla qué hashes Sysmon calcula. El default es solo SHA1. `IMPHASH` es el import-hash, usado mucho en rastreo de malware; `SHA256` es lo que la mayoría de plataformas de threat intel usa como clave. Establece `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` para que los eventos se alineen con lo que usan tus datos de intel.

**No loguear líneas de comando en el padre**. Sysmon EID 1 loguea tanto `CommandLine` (hijo) como `ParentCommandLine` (padre). Algunos configs deshabilitan `ParentCommandLine`. Esto mata el pivote más útil en investigación de árbol de procesos; sin él tienes un nombre de imagen padre pero no idea de qué argumentos iniciaron ese padre.

**No habilitar EID 22 (DNS) en absoluto**. El logging de DNS es reciente (Sysmon 10+) y muchos configs son anteriores. Actívalo. Filtra hosts parlanchines (`*.windowsupdate.com`, tu AD interno), loguea todo lo demás.

## El compromiso de espacio en disco

Un Sysmon bien configurado en una workstation típica produce 100-500 MB de EVTX por día. En un servidor ocupado, 1-5 GB. El tamaño de canal por defecto es 64 MB, lo que significa que el archivo `Microsoft-Windows-Sysmon%4Operational.evtx` rota en horas y tu retención utilizable es corta.

La solución es de dos pasos. Primero, eleva el tamaño del canal. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` lo establece a 4 GB, lo que te da días a semanas en la mayoría de hosts. Segundo, reenvía a un collector central con mayor retención. WEC funciona; los agentes SIEM funcionan; el repo [Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) tiene el XML para la suscripción del canal.

La retención centralizada importa más que la retención local porque el archivo local es lo que el atacante puede limpiar. Una copia reenviada en un collector al que no pueden alcanzar es el registro durable. Configura ambos.

## Cómo se ve un buen Sysmon en una investigación

Un host con `sysmon-modular` desplegado, todos los cinco EIDs core logueando, EID 7 filtrado a módulos interesantes y reenviando a un collector, te da:

- Un árbol de procesos para cada ejecución en el host, con líneas de comando, hashes y el contexto de usuario.
- Cada conexión de red saliente con el proceso originador.
- Cada carga de DLL desde un directorio escribible por usuario.
- Cada acceso de memoria contra `lsass.exe`.
- Cada creación de archivo en `%TEMP%` y `%APPDATA%`.
- Cada consulta DNS con el proceso solicitante.

La historia de la intrusión se lee sola de estos datos. No necesitas adivinar. No necesitas tallar. La lees, de arriba a abajo, y las brechas en la historia son las preguntas a perseguir. Cruza-referencia con [AmCache](https://www.amcacheparser.com) y [Prefetch](https://www.prefetchparser.com) para evidencia de ejecución de binarios, el [registro](https://www.registryparser.com) para persistencia, y el [USN journal](https://www.usnparser.com) para las mutaciones de sistema de archivos que el EID 11 de Sysmon puede haber perdido si su filtro estaba apagado. El parser en este sitio lee canales Sysmon con la misma fidelidad que Security.evtx.

Sin Sysmon, tienes `Security.evtx` y una lista de deseos.

## Lecturas adicionales

- [sysmon-modular](https://github.com/olafhartong/sysmon-modular) de Olaf Hartong. El repo. Lee el README, luego lee tres o cuatro de los archivos XML específicos de técnica para tener una idea del estilo de filtro.
- [Documentación Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) de Microsoft. La referencia oficial; delgada pero precisa.
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) de Roberto Rodriguez. Cazas guiadas por Sysmon con las consultas explicadas.
- El [sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide) de TrustedSec. El doc de referencia para semántica de filtros.

---
title: "Event ID 4625 explicado: detectar fuerza bruta, sprays y enumeración"
description: "4625 es el registro de logon fallido. Léelo bien y detectarás password sprays, credential stuffing y abuso de Kerberos antes de que se conviertan en éxito."
date: "2026-05-17"
---

El Event ID 4625, "Una cuenta no pudo iniciar sesión", se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que un intento de autenticación es rechazado. Es el registro más útil para cazar ataques de credenciales en vuelo. También es el registro que los analistas leen mal con más frecuencia, porque el mensaje de cabecera es genérico y la respuesta vive dos campos más abajo.

## Los campos que deciden la llamada

Un registro típico:

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
```

`Status` y `SubStatus` juntos te dicen por qué falló el logon. El par que realmente te importa es `SubStatus`. Los códigos que merece la pena memorizar:

- `0xC0000064`: la cuenta no existe. Enumeración de nombres de usuario.
- `0xC000006A`: contraseña incorrecta. El clásico.
- `0xC0000234`: cuenta bloqueada.
- `0xC0000072`: cuenta deshabilitada.
- `0xC0000071`: contraseña expirada.
- `0xC0000133`: desfase de reloj en Kerberos. Común en intentos de AS-REP roasting donde el atacante falsificó una hora.
- `0xC000018B`: SID equivocado, la estación piensa que está en un dominio en el que no está. Raro e interesante.

Una ráfaga de `0xC0000064` con nombres de usuario válidos e inválidos mezclados es reconocimiento. Una ráfaga de `0xC000006A` contra una cuenta es fuerza bruta. Una ráfaga de `0xC000006A` contra muchas cuentas usando la *misma* contraseña es un spray. Mismo Event ID, tres incidentes diferentes.

## Las consultas de triaje que se ganan su sitio

1. Detección de spray. Agrupa 4625 por `IpAddress` (o `WorkstationName` si el campo IP está vacío), cuenta `TargetUserName` distintos en 10 minutos. Más de cinco cuentas por origen en esa ventana es sospechoso casi en cualquier sitio.
2. Fuerza bruta. Agrupa por `TargetUserName`, cuenta fallos por minuto. Más de diez por minuto contra una cuenta es casi siempre automatizado.
3. Causa raíz del bloqueo. Empareja 4740 (cuenta bloqueada) con los 4625 precedentes. El campo `WorkstationName` te dirá qué dispositivo disparó el bloqueo. La mayor parte del tiempo es un servidor unido al dominio con una credencial cacheada obsoleta, no un atacante. El triaje importa porque el helpdesk trata a ambos igual y el SOC tiene que elegir cuál escalar.

## El "después" decide la respuesta

Una ráfaga de 4625 seguida de un [4624](/es/blog/understanding-event-id-4624) desde la misma `IpAddress` es el caso accionable. El atacante encontró una credencial que funciona. La progresión en la timeline es inconfundible: fallos densos, silencio súbito, un único éxito.

## Sigma: password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window. The password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## KQL: fuerza bruta contra una cuenta

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk: enumeración que deriva en fuerza bruta

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

La señal es la *progresión*: enumeración para encontrar nombres de usuario válidos primero, luego intentos de contraseña dirigidos. Un operador real con una lista de usuarios fresca producirá ambas formas en minutos.

## Mapeo ATT&CK

- T1110.001 Brute Force: Password Guessing. Una sola cuenta, muchos fallos `0xC000006A`.
- T1110.003 Brute Force: Password Spraying. Muchas cuentas, un origen, pocos fallos cada una.
- T1110.004 Credential Stuffing. Muchas cuentas, un origen, mezcla de `0xC0000064` (cuenta no existe, fallo de lista filtrada) y `0xC000006A` (acierto).
- T1078 Valid Accounts. Ráfaga 4625 seguida de éxito [4624](/es/blog/understanding-event-id-4624) desde el mismo origen. Compromiso.
- T1556 Modify Authentication Process. `LogonProcessName` anómalo (cualquier cosa distinta de `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, `Schannel`) sugiere manipulación.

## Falsos positivos que llevan el disfraz

- Credenciales guardadas que se quedan obsoletas tras un cambio de contraseña. Las unidades mapeadas, tareas programadas o configuraciones de servicio del usuario reintentan la contraseña vieja. La forma es un `TargetUserName`, una `IpAddress`, cadencia constante de `0xC000006A`. Encuentra el host con la credencial obsoleta y arréglalo antes de alertar.
- Automatización mal configurada. Un script con la contraseña equivocada reintentando en bucle. Misma forma que la fuerza bruta. Habla con el propietario primero.
- Los escáneres de vulnerabilidades durante escaneos autenticados producen tráfico 4625 denso. Etiqueta las IPs del escáner.
- Churn de la política de bloqueo. Procedimientos de helpdesk que desbloquean agresivamente crean ciclos repetidos 4625 a 4740 a 4624. Molesto. No malicioso.

## Lo que oculta 4625

Los fallos Kerberos y NTLMv2 que llegan por un DC no siempre traen una `IpAddress` útil. El campo puede estar vacío o ser `-`. Para esos, pivotas a los registros del DC: [4768](/es/blog/event-id-4768-kerberos-tgt) y 4771 para fallos de pre-auth de Kerberos. "Sin IP de origen, sin investigación" es el instinto equivocado. Mira el log del DC en su lugar.

Los campos `LogonProcessName` y `AuthenticationPackageName` te dicen qué pila de autenticación manejó el intento. Valores útiles: `NtLmSsp` (NTLM), `Kerberos`, `Negotiate` (escoge uno de los dos), `User32` (consola local), `Schannel` (respaldado por TLS). Cualquier otra cosa, mira con más detenimiento.

## Lectura adicional

- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1110: Brute Force](https://attack.mitre.org/techniques/T1110/)

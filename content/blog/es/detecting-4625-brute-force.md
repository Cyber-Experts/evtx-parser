---
title: "Event ID 4625 explicado: detectar fuerza bruta, sprays y enumeración"
description: "4625 es el registro de inicio de sesión fallido. Léelo bien y detectas password sprays, credential stuffing y abuso de Kerberos antes de que tengan éxito."
date: "2026-05-17"
---

El Event ID 4625 — «No se pudo iniciar sesión en una cuenta» — se dispara en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que un intento de autenticación es rechazado. Es el registro más útil para cazar actividad de ataques de credenciales, pero solo si lees los campos correctos.

## Los campos que realmente importan

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

La combinación de `Status` y `SubStatus` te dice *por qué* falló el inicio de sesión:

- `0xc0000064` — la cuenta no existe (enumeración de usuarios).
- `0xc000006a` — contraseña incorrecta (el clásico).
- `0xc0000234` — cuenta bloqueada.
- `0xc0000072` — cuenta deshabilitada.
- `0xc0000071` — contraseña expirada.
- `0xc0000133` — desfase de reloj en un ticket Kerberos (común durante AS-REP roasting).
- `0xc000018b` — SID incorrecto — la workstation no está en el dominio que cree.

Una ráfaga de `0xc0000064` contra nombres de usuario válidos e inválidos es reconocimiento. Una ráfaga de `0xc000006a` contra una cuenta es fuerza bruta. Una ráfaga de `0xc000006a` contra muchas cuentas con la *misma contraseña* es un password spray.

## Los patrones

Las consultas de triage más simples:

1. **Detección de spray**: agrupa registros 4625 por `IpAddress` (o `WorkstationName` si la IP no está registrada), cuenta `TargetUserName` distintos en 10 minutos. >5 cuentas por origen en esa ventana es sospechoso casi en todas partes.
2. **Fuerza bruta**: agrupa por `TargetUserName`, cuenta fallos por minuto. >10 por minuto contra una cuenta suele ser un bot.
3. **Causa raíz de bloqueo**: empareja 4740 (cuenta bloqueada) con los 4625 precedentes — el campo `WorkstationName` mostrará qué dispositivo provocó el bloqueo, lo cual es crítico porque a menudo es un servidor unido al dominio con una credencial almacenada obsoleta, no un atacante.

## El «después» importa tanto como el «antes»

Una ráfaga de 4625 seguida de un [4624](/es/blog/understanding-event-id-4624) desde la misma `IpAddress` es el caso accionable — el atacante encontró una credencial válida. El parser de esta página te permite filtrar la tabla por una IP de origen y observar las transiciones de nivel y event ID a lo largo del tiempo en la timeline. El patrón ráfaga-luego-pico es inconfundible.

## Regla Sigma de ejemplo — password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
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

## KQL de ejemplo — fuerza bruta contra una cuenta

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Splunk de ejemplo — enumeración antes de la fuerza bruta

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

La señal es la *progresión* — enumeración para encontrar nombres de usuario válidos, luego fuerza bruta contra esos.

## Mapeo ATT&CK

- **T1110.001 — Brute Force: Password Guessing**: una sola cuenta, muchos fallos `0xC000006A`.
- **T1110.003 — Brute Force: Password Spraying**: muchas cuentas, pocos fallos por cuenta, un origen.
- **T1110.004 — Brute Force: Credential Stuffing**: muchas cuentas, un origen, frecuentemente `0xC0000064` (cuenta inexistente) por fallos de la lista filtrada intercalados con aciertos `0xC000006A`.
- **T1078 — Valid Accounts**: 4625 seguido de un [4624](/es/blog/understanding-event-id-4624) exitoso desde el mismo origen = compromiso.
- **T1556 — Modify Authentication Process**: `LogonProcessName` anómalo (cualquier cosa distinta de `User32`, `NtLmSsp`, `Kerberos`, `Advapi` o `Schannel`) sugiere manipulación de la autenticación.

## Falsos positivos que parecen ataques

- **Credenciales almacenadas que quedan obsoletas** tras un cambio de contraseña. Las unidades mapeadas del usuario, tareas programadas o configuraciones de cuentas de servicio siguen reintentando la contraseña vieja. El patrón: un `TargetUserName`, una `IpAddress` (a veces un `WorkstationName`), cadencia estable de `0xC000006A`. Caza el host con la credencial obsoleta y corrígelo.
- **Automatización mal configurada**: un script con una contraseña incorrecta reintentando en bucle. Misma forma que la fuerza bruta; habla con el propietario antes de alertar.
- **Escáneres de vulnerabilidades** durante escaneos autenticados producen tráfico denso de 4625. Etiqueta las IPs de escáner.
- **Mala configuración de la política de bloqueo**: procedimientos de helpdesk que desbloquean demasiado agresivamente pueden producir ciclos repetidos de 4625 → 4740 → 4624.

## Lo que no ves en 4625

Los fallos de NTLMv2 y Kerberos provenientes de un domain controller no siempre llevan una `IpAddress` útil — el campo puede estar vacío o ser `-`. Para esos necesitas los eventos correspondientes del DC ([4768](/es/blog/event-id-4768-kerberos-tgt)/4771 para fallos de pre-auth de Kerberos) o datos de nivel de red. No concluyas «sin IP de origen, sin investigación» — pivota al canal del DC.

Los campos `LogonProcessName` y `AuthenticationPackageName` te dicen qué pila de autenticación manejó el intento. Los más útiles son `NtLmSsp` (NTLM), `Kerberos` y `Negotiate` (que escoge uno de los dos). `User32` es consola local; `Schannel` es basado en TLS.

---
title: "Event ID 4769 explicado: tickets de servicio Kerberos y kerberoasting"
description: "4769 es el registro del DC de cada solicitud de ticket de servicio. Léelo a través del tipo de cifrado y detectarás kerberoasting. Léelo con 4768 y detectarás pass-the-ticket."
date: "2026-05-24"
---

El Event ID **4769**, "Se solicitó un ticket de servicio Kerberos", se dispara en cada Domain Controller cada vez que una cuenta solicita un ticket TGS (Ticket Granting Service) para un servicio. Cada conexión SMB, cada login SQL, cada acierto SSO web produce uno en el DC que manejó la solicitud. Es el registro de mayor volumen en el [canal Security](/es/blog/what-is-an-evtx-file) en un DC cargado, y el único lugar donde el kerberoasting aparece de forma fiable antes de que las credenciales se craqueen offline.

Si solo instrumentas tres registros de Security de tus DCs, este es uno de ellos.

## Dónde vive

`4769` se escribe únicamente en el canal Security del **Domain Controller emisor**. No el cliente, no el servicio destino. Para ver todos los registros 4769 de un dominio, tienes que recoger de cada DC. El target `EventLogs` de KAPE en un DC, o reenviar Security vía WEF a un colector, funcionan ambos. WEF es lo que usan los shops maduros.

## Qué contiene el registro

```xml
<Data Name="TargetUserName">alice@CORP.LOCAL</Data>
<Data Name="TargetDomainName">CORP.LOCAL</Data>
<Data Name="ServiceName">MSSQLSvc/db01.corp.local:1433</Data>
<Data Name="ServiceSid">S-1-5-21-...-1234</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">50213</Data>
<Data Name="Status">0x0</Data>
<Data Name="LogonGuid">{...}</Data>
<Data Name="TransmittedServices">-</Data>
```

Los campos que mueven el triaje:

- `TargetUserName`. El solicitante (la cuenta de usuario, en formato `user@DOMAIN`).
- `ServiceName`. El SPN que se solicita. Una cuenta de usuario aquí (en lugar de `host/...` o una clase de servicio) es sospechosa.
- `TicketEncryptionType`. El campo que decide si este registro importa. Los dominios modernos corren `0x12` (AES-256-CTS-HMAC-SHA1-96) o `0x11` (AES-128). **`0x17` es RC4-HMAC**: legacy, débil y el *único* tipo de cifrado que solicitan Mimikatz y el modo `kerberoast` de Rubeus. Un 4769 para un ticket de cuenta de servicio con `0x17` es una huella clásica de kerberoasting.
- `Status`. `0x0` es éxito. Cualquier otra cosa es denegado (códigos documentados en `[MS-KILE]`).
- `IpAddress`. Host solicitante. Empareja con [4624](/es/blog/understanding-event-id-4624) en ese host para ver el logon que produjo la sesión.

## TicketEncryptionType: el campo que decide

| Valor | Algoritmo | Estado |
|---|---|---|
| 0x01 | DES-CBC-CRC | Deshabilitado por defecto desde Win7 |
| 0x03 | DES-CBC-MD5 | Deshabilitado por defecto desde Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (default para la mayoría de cuentas) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Requerido para kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 de grado export, raro al desvanecimiento |

Si el dominio ha sido baselineado y `msDS-SupportedEncryptionTypes` puesto a AES-only en cuentas de servicio, `0x17` no debería aparecer para esas cuentas en absoluto. Los atacantes solicitan `0x17` explícitamente porque crakear tickets de servicio cifrados RC4 es computacionalmente barato. AES no. La herramienta de cracking *tiene* que solicitar 0x17.

Este es el campo de señal más alta del registro.

## El patrón de kerberoasting

El kerberoasting (T1558.003) funciona así:

1. El atacante se autentica con cualquier usuario de dominio (no hace falta admin).
2. El atacante enumera SPNs registrados en cuentas de usuario (no cuentas de equipo), típicamente vía LDAP `(servicePrincipalName=*)` filtrado a objetos de usuario.
3. El atacante solicita un TGS para cada SPN con `etype=23` (RC4) vía el protocolo Kerberos estándar. El 4769 que estás buscando.
4. El DC emite alegremente el ticket, cifrado con el hash NTLM de la cuenta de servicio.
5. El atacante saca el blob cifrado y lo crackea offline en Hashcat (`-m 13100`).

La huella 4769:

- `ServiceName` es `MSSQLSvc/...`, `HTTP/...`, `LDAP/...` o cualquier SPN apuntando a una cuenta de usuario (no `host/...` o `cifs/...`, que son cuentas de equipo).
- `TicketEncryptionType` es `0x17`.
- Una ráfaga en una ventana corta, desde la misma fuente, para muchos SPNs.

Un patrón relacionado, **AS-REP roasting** (T1558.004), usa [4768](/es/blog/event-id-4768-kerberos-tgt) en su lugar, apuntando a cuentas con `DONT_REQUIRE_PREAUTH`. Registro distinto, misma familia.

## Pass-the-ticket, golden, silver

4769 también revela falsificación de tickets, pero la señal es más sutil.

- Un 4769 *sin* un 4768 precedente para el mismo `LogonGuid` desde el mismo host en una ventana razonable: sospecha de golden ticket. El atacante presentó un TGT forjado y se fue directo a solicitudes TGS.
- Un 4769 *y* la autenticación de servicio resultante en el destino *sin* un 4769 visible en ningún DC: sospecha de silver ticket. El atacante forjó el TGS en sí. Al DC nunca se le preguntó.
- Mismatch de `LogonGuid` entre 4624 en el destino y el 4769 que supuestamente emitió el ticket: ticket forjado.

Son patrones de detección por ausencia. Requieren cobertura completa de logs en todos los DCs y servicios destino. Lagunas en la cobertura WEF producen falsos positivos idénticos. Caracteriza tu colección antes de alertar.

## Workflow de triaje

1. Filtra todos los 4769 a través del corpus de DCs para `TicketEncryptionType == 0x17`.
2. Agrupa por `IpAddress` y `TargetUserName` sobre ventanas de 30 minutos. Cuenta `ServiceName` distintos por fuente.
3. Más de 3 SPNs distintos solicitados como 0x17 desde una fuente en 30 minutos es kerberoasting casi en todas partes.
4. Pivota la IP origen a su [4624](/es/blog/understanding-event-id-4624) para encontrar la credencial que inició el ataque.
5. Pivota los SPNs solicitados a las cuentas de servicio dueñas. Rota esas contraseñas. Resetea hashes crackeados en horas, no días.

## Sigma

```yaml
title: Kerberoasting via RC4 Service Ticket Request
id: 9bb37f72-3a4f-4a3a-9d8e-3a91c4f74a0f
status: stable
description: Service ticket requests using RC4 encryption type for SPNs registered to user accounts.
references:
  - https://attack.mitre.org/techniques/T1558/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    ServiceName|startswith:
      - 'MSSQLSvc/'
      - 'HTTP/'
      - 'TERMSRV/'
      - 'LDAP/'
  filter_machine:
    ServiceName|endswith: '$'
  condition: selection and not filter_machine
falsepositives:
  - Legacy applications that only support RC4
  - Pre-AES domains still in transition
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

`filter_machine` excluye SPNs de cuenta de equipo (que siempre acaban en `$`). El kerberoasting solo apunta a SPNs de cuenta de usuario.

## KQL y Splunk

```kusto
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17"
| where ServiceName !endswith "$"
| summarize SPNs=dcount(ServiceName), Services=make_set(ServiceName, 10)
    by IpAddress, TargetUserName, bin(TimeGenerated, 30m)
| where SPNs >= 3
| order by TimeGenerated desc
```

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapeo ATT&CK

- T1558.003 Kerberoasting. El titular.
- T1558.001 Golden Ticket. 4769 sin 4768 del mismo `LogonGuid`.
- T1558.002 Silver Ticket. 4769 ausente para una auth de servicio observada en el destino.
- T1078 Valid Accounts. 4769 desde una IP inesperada para una cuenta de servicio conocida.
- T1550.003 Pass the Ticket. 4769 seguido de [4624](/es/blog/understanding-event-id-4624) LogonType 3 con `LogonProcessName: Kerberos`.

## Falsos positivos que verás

- Aplicaciones legacy (algunos conectores antiguos de SQL Server, ciertas apps Java/JBoss) solicitan RC4 explícitamente. `0x17` constante en horario diurno desde un conjunto pequeño de hosts estables. Baseline y excluye.
- Los dominios pre-AES durante una transición de endurecimiento de Kerberos emiten `0x17` ampliamente hasta que `msDS-SupportedEncryptionTypes` esté puesto en cada cuenta. Molesto. No malicioso.
- Los escáneres de vulnerabilidades (Tenable, Qualys, scripts de enumeración de BloodHound) replican tráfico de kerberoasting. Etiqueta hosts de escáner.
- Las herramientas de migración de cuentas durante movimientos cross-forest pueden solicitar combinaciones inusuales.

La señal es el patrón de *ráfaga*, no el registro individual. `0x17` constante desde un host es configuración. `0x17` en ráfaga a muchos SPNs desde un host en minutos es el ataque.

## Lo que 4769 no te dice

El registro no incluye el ticket cifrado en sí. El cracking ocurre sobre lo que sea que el atacante exfiltró, no en el cable desde el DC. No puedes, solo desde 4769, distinguir "ticket emitido y nunca usado" de "ticket crackeado, credenciales reutilizadas". Para la segunda mitad de la cadena necesitas el [4624](/es/blog/understanding-event-id-4624) resultante en el servicio destino (LogonType 3, AuthenticationPackage Kerberos), e idealmente [4688](/es/blog/event-id-4688-process-creation) o [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) mostrando qué corrió tras reutilizar la credencial. Trata 4769 como el canario, no como la alarma.

## Dónde encaja 4769 en una timeline

Cadena clásica de kerberoasting post-explotación:

1. [4624](/es/blog/understanding-event-id-4624) en una estación. Acceso inicial vía credenciales de usuario phisheadas.
2. **4769** ×N desde esa estación a un DC, todos `etype=0x17`, todos apuntando a cuentas de servicio con SPN de usuario en 5 minutos. Kerberoasting.
3. *(Offline, invisible)*. El atacante crackea el hash de la cuenta de servicio más débil en Hashcat.
4. [4768](/es/blog/event-id-4768-kerberos-tgt). Solicitud TGT como la cuenta de servicio comprometida, desde un host distinto.
5. 4624 LogonType 3 en un servidor de alto valor, AuthenticationPackage Kerberos.
6. [7045](/es/blog/service-creation-event-id-7045). Servicio instalado para persistencia bajo la cuenta comprometida.

La ráfaga 4769 en el paso 2 es tu punto de detección más temprano y barato. Horas o días antes de que el atacante vuelva como la cuenta de servicio.

## Lectura adicional

- [Documentación Microsoft para 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
- [MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
- [Sean Metcalf: Kerberoasting Without Mimikatz](https://adsecurity.org/?p=2293)

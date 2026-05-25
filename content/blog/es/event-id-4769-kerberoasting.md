---
title: "Event ID 4769 explicado: service tickets Kerberos y kerberoasting"
description: "4769 es el registro del DC de cada solicitud de service ticket. Léelo a través del tipo de cifrado y detectas kerberoasting; léelo con 4768 y detectas pass-the-ticket."
date: "2026-05-24"
---

El Event ID **4769** — «Se solicitó un service ticket Kerberos» — se dispara en cada Domain Controller cada vez que cualquier cuenta solicita un ticket TGS (Ticket Granting Service) para un servicio. Cada conexión SMB, cada login SQL, cada hit de SSO web produce uno de estos en el DC que manejó la solicitud. Es el registro de mayor volumen en el [canal Security](/es/blog/what-is-an-evtx-file) en un DC ocupado — y el único lugar donde el kerberoasting aparece fiablemente antes de que las credenciales sean crackeadas offline.

Si solo llegas a instrumentar tres registros Security de tus domain controllers, este es uno de ellos.

## Dónde vive

`4769` se escribe en el canal `Security` del **Domain Controller emisor** — no en el cliente y no en el servicio objetivo. Para ver todos los registros 4769 de un dominio, tienes que recolectar de cada DC. El target `EventLogs` de KAPE en un DC, o reenviar `Security` vía WEF a un colector, ambos funcionan; la ruta WEF es la que la mayoría de shops maduros usan.

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

Los campos que conducen el triage:

- **`TargetUserName`** — el *solicitante* (la cuenta de usuario, en forma `user@DOMAIN`).
- **`ServiceName`** — el SPN solicitado. Una cuenta de usuario aquí (en lugar de `host/...` o una clase de servicio) es sospechoso.
- **`TicketEncryptionType`** — el valor que decide si este registro importa. Los dominios modernos corren `0x12` (AES-256-CTS-HMAC-SHA1-96) o `0x11` (AES-128). **`0x17` es RC4-HMAC** — legacy, débil, y el *único* tipo de cifrado que el modo `kerberoast` de Mimikatz/Rubeus solicita. Un 4769 para un ticket de cuenta de servicio con `0x17` es una huella digital de kerberoasting de libro de texto.
- **`Status`** — `0x0` es éxito; cualquier otra cosa significa denegado (códigos de estado documentados en `[MS-KILE]`).
- **`IpAddress`** — el host solicitante. Empareja con [4624](/es/blog/understanding-event-id-4624) en ese host para ver el logon que produjo la sesión.

## TicketEncryptionType — el campo que importa

La tabla completa, abreviada:

| Valor | Algoritmo | Estado |
|---|---|---|
| 0x01 | DES-CBC-CRC | Deshabilitado por defecto desde Win7 |
| 0x03 | DES-CBC-MD5 | Deshabilitado por defecto desde Win7 |
| 0x11 | AES-128-CTS-HMAC-SHA1-96 | Moderno |
| 0x12 | AES-256-CTS-HMAC-SHA1-96 | Moderno (default para la mayoría de cuentas) |
| **0x17** | **RC4-HMAC-MD5** | **Legacy. Requerido para kerberoasting.** |
| 0x18 | RC4-HMAC-EXP | RC4 grado export, extremadamente raro |

Si el dominio ha sido baselined y `msDS-SupportedEncryptionTypes` está configurado a solo-AES en cuentas de servicio, `0x17` no debería aparecer para esas cuentas en absoluto. Los atacantes solicitan `0x17` explícitamente porque crackear service tickets cifrados con RC4 es computacionalmente barato; AES no. La herramienta de cracking necesita el hash RC4, así que la solicitud *tiene que* ser 0x17.

Este es el campo de mayor señal del registro.

## El patrón de kerberoasting

El kerberoasting (MITRE T1558.003) funciona así:

1. El atacante se autentica con cualquier cuenta de usuario de dominio (no se necesitan derechos de admin).
2. El atacante enumera SPNs registrados a cuentas de usuario (no cuentas de equipo), típicamente vía LDAP `(servicePrincipalName=*)` filtrado a objetos de usuario.
3. El atacante solicita un TGS para cada SPN con `etype=23` (RC4) vía el protocolo Kerberos estándar. **Este es el 4769 que estás buscando.**
4. El DC felizmente emite el ticket, cifrado con el hash NTLM de la *cuenta de servicio*.
5. El atacante extrae el blob cifrado de la memoria (o del cable) y lo craquea offline con Hashcat (`-m 13100`).

La huella digital 4769:

- `ServiceName` es `MSSQLSvc/...`, `HTTP/...`, `LDAP/...`, o cualquier SPN apuntando a una cuenta de *usuario* (no `host/...` o `cifs/...` que son cuentas de equipo).
- `TicketEncryptionType` es `0x17`.
- Una ráfaga de estas solicitudes en una ventana corta, desde el mismo origen, para muchos SPNs, es el delator absoluto.

Un segundo patrón relacionado — **AS-REP roasting** (T1558.004) — usa [4768](/es/blog/event-id-4768-kerberos-tgt) en su lugar (la solicitud TGT), apuntando a cuentas con `DONT_REQUIRE_PREAUTH` configurado. Registro diferente, misma familia de ataques.

## Pass-the-ticket / golden / silver tickets

4769 también revela forja de tickets, pero la señal es más sutil.

- Un 4769 *sin* un 4768 precedente (solicitud TGT) para el mismo `LogonGuid` desde el mismo host en una ventana razonable — sospecha de **golden ticket**. El atacante presentó un TGT forjado y caminó directamente a solicitudes TGS sin nunca pedir un TGT real.
- Un 4769 *y* la autenticación de servicio resultante en el objetivo *sin* un 4769 visible en ningún DC — sospecha de **silver ticket**. El atacante forjó el TGS mismo; al DC nunca se le preguntó.
- `LogonGuid` no coincidente entre 4624 en el servicio objetivo y el 4769 supuestamente emitiendo el ticket — ticket forjado.

Estos son patrones de detección-por-ausencia, lo que significa que requieren cobertura completa de logs en todos los DCs y los servicios objetivo. Brechas en cobertura WEF producen falsos positivos de aspecto idéntico; caracteriza tu colección antes de alertar.

## Workflow de triage

1. Filtra todos los 4769 en el corpus de DCs por `TicketEncryptionType == 0x17`.
2. Agrupa por `IpAddress` y por `TargetUserName` en ventanas de 30 minutos. Cuenta `ServiceName` distintos por origen.
3. >3 SPNs distintos solicitados como 0x17 desde un origen en 30 minutos es kerberoasting casi en todas partes.
4. Pivota la IP de origen a su [4624](/es/blog/understanding-event-id-4624) en el host originador — encuentra la credencial que inició el ataque.
5. Pivota los SPNs solicitados a las cuentas de servicio que los poseen. Rota esas contraseñas. Resetea los hashes crackeados en horas, no días.

## Regla Sigma de ejemplo

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

La cláusula `filter_machine` excluye SPNs de cuentas de equipo (que siempre terminan en `$`); el kerberoasting solo apunta a SPNs de cuentas de usuario.

## KQL / Splunk de ejemplo

KQL (Defender XDR / Sentinel vía `SecurityEvent`):

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

Splunk:

```spl
index=wineventlog EventCode=4769 TicketEncryptionType="0x17"
| search ServiceName!="*$"
| bucket _time span=30m
| stats dc(ServiceName) AS SPNs values(ServiceName) AS Services BY _time IpAddress TargetUserName
| where SPNs >= 3
```

## Mapeo ATT&CK

El corpus de 4769 cubre:

- **T1558.003 — Kerberoasting**: el caso de uso titular.
- **T1558.001 — Golden Ticket**: 4769 sin 4768 desde el mismo `LogonGuid`.
- **T1558.002 — Silver Ticket**: 4769 ausente para una autenticación de servicio observada en el objetivo.
- **T1078 — Valid Accounts**: 4769 desde una IP inesperada para una cuenta de servicio conocida.
- **T1550.003 — Pass the Ticket**: 4769 seguido de [4624](/es/blog/understanding-event-id-4624) LogonType 3 con `LogonProcessName: Kerberos`.

## Falsos positivos que verás

- **Aplicaciones legacy** (algunos conectores viejos de SQL Server, algunas apps Java/JBoss) solicitan RC4 explícitamente. Aparecen como tráfico 0x17 estable, diurno, desde un pequeño conjunto de hosts estables. Baseline y excluye.
- **Dominios pre-AES** durante una transición de hardening Kerberos emitirán 0x17 ampliamente hasta que `msDS-SupportedEncryptionTypes` esté configurado en cada cuenta. Molesto; no malicioso.
- **Escáneres de vulnerabilidades** (Tenable, Qualys, scripts de enumeración BloodHound) replican tráfico de kerberoasting. Etiqueta hosts de escáner.
- **Herramientas de migración de cuentas** durante movimientos cross-forest pueden solicitar combinaciones inusuales de tickets.

La señal es el patrón de *ráfaga*, no el registro individual. 0x17 estable desde un host es configuración; 0x17 a ráfagas a muchos SPNs desde un host en minutos es el ataque.

## Lo que 4769 no te dice

El registro no incluye el ticket cifrado en sí — el cracking ocurre sobre lo que sea que el atacante exfiltró, no sobre el cable desde el DC. No puedes, desde 4769 solo, distinguir «ticket fue emitido y nunca usado» de «ticket fue crackeado, credenciales reutilizadas». Para la segunda mitad de la cadena necesitas el [4624](/es/blog/understanding-event-id-4624) resultante en el servicio objetivo (LogonType 3, AuthenticationPackage Kerberos), e idealmente [4688](/es/blog/event-id-4688-process-creation) o [Sysmon 1](/es/blog/sysmon-event-id-1-process-create) mostrando qué corrió después de que la credencial fue reutilizada. Trata 4769 como el canario, no la alarma.

## Dónde encaja 4769 en una timeline

Cadena clásica de kerberoasting post-explotación:

1. [**4624**](/es/blog/understanding-event-id-4624) en una workstation — acceso inicial vía credenciales de usuario phisheadas.
2. **4769** ×N desde esa IP de workstation a un DC, todos `etype=0x17`, todos apuntando a cuentas de servicio user-SPN en 5 minutos — kerberoasting.
3. *(Offline, invisible)* — el atacante craquea el hash de la cuenta de servicio más débil en Hashcat.
4. **4768** — solicitud TGT como la cuenta de servicio comprometida, desde un host diferente.
5. **4624** LogonType 3 en un servidor de alto valor, AuthenticationPackage Kerberos, usando la cuenta de servicio.
6. [**7045**](/es/blog/service-creation-event-id-7045) — servicio instalado para persistencia bajo la cuenta comprometida.

La ráfaga de 4769 en el paso 2 es tu punto de detección más temprano y barato — horas o días antes de que el atacante regrese como la cuenta de servicio.

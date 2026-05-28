---
title: "Event ID 4768 explicado: solicitudes de TGT Kerberos y AS-REP roasting"
description: "4768 es el registro del DC de cada TGT emitido. Léelo a través del código de resultado y el flag de pre-auth y detectarás AS-REP roasting, fuerza bruta y abuso de delegación sin restricciones."
date: "2026-05-24"
---

El Event ID **4768**, "Se solicitó un ticket de autenticación Kerberos (TGT)", se dispara en un Domain Controller cada vez que alguien pide un Ticket Granting Ticket. Todo logon de dominio empieza con uno de estos. Empareja con [4769](/es/blog/event-id-4769-kerberoasting) (ticket de servicio) y ves todo el ciclo de vida Kerberos de cada cuenta del forest.

En un DC, 4768 es el registro de mayor volumen en el [canal Security](/es/blog/what-is-an-evtx-file) después de 4624. La mayoría es ruido. Las rebanadas de alta señal viven en dos campos específicos, y uno de ellos es la huella de AS-REP roasting.

## Dónde se dispara

Como [4769](/es/blog/event-id-4769-kerberoasting), 4768 aterriza solo en el **Domain Controller** emisor. El cliente no lo ve. El servicio destino no lo ve. Para detectar algo desde 4768, necesitas colección de Security de cada DC. Estilo KAPE para engagements puntuales, WEF para estado estable.

## Qué contiene el registro

```xml
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetSid">S-1-5-21-...-1107</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-...-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x12</Data>
<Data Name="PreAuthType">2</Data>
<Data Name="IpAddress">::ffff:10.0.0.42</Data>
<Data Name="IpPort">52814</Data>
<Data Name="CertIssuerName">-</Data>
<Data Name="CertSerialNumber">-</Data>
<Data Name="CertThumbprint">-</Data>
```

Los campos que importan:

- `TargetUserName`. La cuenta solicitando un TGT. Siempre una cuenta de usuario o equipo. `ServiceName` es siempre `krbtgt`.
- `Status`. Código de resultado Kerberos. `0x0` es éxito. Los fallos son lo que hace útil a 4768: `0x6` usuario desconocido, `0x12` cliente bloqueado, `0x17` contraseña expirada, `0x18` contraseña incorrecta.
- `TicketEncryptionType`. Mismo encoding que 4769: `0x12` y `0x11` AES (moderno), **`0x17` RC4** (legacy, también la huella de AS-REP roasting).
- `PreAuthType`. `2` es la pre-auth estándar de encrypted-timestamp. `0` significa **no se usó pre-auth** (el prerrequisito de AS-REP roasting). `15`, `16`, `17` son valores de pre-auth basada en certificado PKINIT.
- `IpAddress`. Host solicitante. Empareja con el [4624](/es/blog/understanding-event-id-4624) del lado cliente para contexto completo.
- `CertIssuerName`, `CertSerialNumber`, `CertThumbprint`. Rellenados para PKINIT (logon con smart card o certificado). Vacíos para logons basados en contraseña.

## Los dos patrones de ataque que revela 4768

### AS-REP roasting (T1558.004)

El uso titular. Algunas cuentas tienen `DONT_REQUIRE_PREAUTH` puesto en `userAccountControl` (UAC bit 22 = `0x400000`). Para esas cuentas, el DC responde a una solicitud TGT **sin** requerir la pre-auth de encrypted-timestamp. La AS-REP que devuelve contiene material que un atacante puede crackear offline para recuperar el hash de la contraseña de la cuenta.

La huella 4768 de un AS-REP roast en progreso:

- `PreAuthType = 0` (sin pre-auth).
- `TicketEncryptionType = 0x17` (RC4, lo que necesita la herramienta de cracking).
- `Status = 0x0` (el DC emitió felizmente la AS-REP).
- A menudo en clusters. Un atacante lanza por lotes docenas de cuentas para probar cuáles tienen pre-auth deshabilitado.

Las cuentas reales con `DONT_REQUIRE_PREAUTH` existen casi exclusivamente por compatibilidad legacy: clientes Kerberos Unix muy antiguos, algunas appliances ancestrales. Son pocas en número y predecibles en localización. Un 4768 con `PreAuthType=0` para una cuenta que no tiene asuntos con Kerberos sin pre-auth es la señal.

### Fuerza bruta o spray de contraseñas

La pre-auth Kerberos fallida produce 4768 con `Status=0x18` ("contraseña incorrecta"). A diferencia de [4625](/es/blog/detecting-4625-brute-force) (que captura fallos NTLM), 4768 es donde aterrizan los ataques de contraseña basados en Kerberos. Los toolkits modernos (Rubeus, kerbrute) hablan Kerberos directamente porque el DC falla silenciosamente en intentos NTLM más rápido de lo que responde a los Kerberos, y muchos SOCs solo vigilan 4625.

La huella de fuerza bruta de 4768:

- Muchos registros `Status=0x18` para el mismo `TargetUserName` desde la misma IP origen en una ventana corta. Fuerza bruta.
- Muchos registros `Status=0x18` a través de muchos valores `TargetUserName` desde una IP origen, cada uno golpeado una o dos veces. Password spray.
- Una ráfaga de `Status=0x6` ("usuario desconocido") precediendo a `Status=0x18` desde la misma fuente. Enumeración de usuarios confirmada antes de que empiece la bruta.

## Códigos de estado que mueven el triaje

| Status | Significado | Lectura del campo |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Éxito. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | El nombre de usuario no existe. Ráfagas = enumeración. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Cuenta bloqueada, deshabilitada o expirada. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Contraseña expirada. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Contraseña incorrecta. Ráfagas = fuerza bruta o spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Devuelto al cliente primero en una solicitud TGT fresca. El éxito real sigue. No alertes sobre estos solos. |
| `0x25` | KRB_AP_ERR_SKEW | Desfase de reloj > 5 min. A menudo intentos de AS-REP roasting desde un host con reloj deliberadamente equivocado. |

## Workflow de triaje: AS-REP roasting

1. Filtra 4768 a través de todos los DCs para `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Agrupa por `IpAddress`. Una sola cuenta desde un host de migración conocido es configuración. Múltiples cuentas desde una fuente es el ataque.
3. Pivota cada `TargetUserName` a su `userAccountControl`. ¿Realmente necesita `DONT_REQUIRE_PREAUTH` estar puesto? Casi con certeza no.
4. IP origen al [4624](/es/blog/understanding-event-id-4624) en ese host para encontrar la credencial que autenticó para lanzar el ataque.
5. Rota la contraseña de cada cuenta crackeada. Quita `DONT_REQUIRE_PREAUTH` de cuentas que no lo necesitan.

## Workflow de triaje: fuerza bruta Kerberos

1. Filtra 4768 por `Status == 0x18`.
2. Agrupa por `IpAddress` sobre ventanas de 15 minutos. Cuenta `TargetUserName` distintos.
3. Más de 5 cuentas de una fuente en 15 minutos es spray. Más de 10 fallos contra una cuenta en la misma ventana es fuerza bruta.
4. Cruza contra `Status == 0x6` desde la misma fuente. Enumeración antes de la bruta es el orden de manual.

## Sigma: AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption. The AS-REP roasting fingerprint.
references:
  - https://attack.mitre.org/techniques/T1558/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: '0'
    TicketEncryptionType: '0x17'
    Status: '0x0'
  condition: selection
falsepositives:
  - Legacy Unix Kerberos clients explicitly configured without pre-auth
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL: spray de contraseñas Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk: AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapeo ATT&CK

- T1558.004 AS-REP Roasting. Detección titular sobre `PreAuthType=0 + etype=0x17`.
- T1110 Brute Force y sub-técnicas `.001` Password Guessing y `.003` Password Spraying. Patrones `Status=0x18`.
- T1558.001 Golden Ticket. Un TGT forjado evita 4768 completamente. La detección aquí es por *ausencia*: un [4769](/es/blog/event-id-4769-kerberoasting) sin un 4768 precedente desde la misma fuente y ventana es la sospecha.
- T1187 Forced Authentication. No directamente visible en 4768 pero las solicitudes TGT resultantes lo serán.

## Falsos positivos que parecen ataques

- Las pilas Java o Unix Kerberos antiguas en silos de app legacy a veces hacen default a RC4 sin pre-auth. Se muestran como tráfico 4768 constante en horario diurno desde un host estable. Baseline.
- Migración PKINIT durante despliegues de smart card. Cambios `PreAuthType=15/16/17` legítimos parecen anómalos si no los has visto antes. Vigila la ventana del despliegue.
- Bugs de librerías Kerberos. Ciertos clientes re-solicitan TGTs agresivamente en desfase de tiempo, generando ruido. Cruza con `Status=0x25`.
- Travesía de trust de dominio. La autenticación cross-forest produce 4768 en cada lado. La `IpAddress` es un DC del otro forest. Etiquétalo.

## Lo que 4768 no te dice

El registro no incluye el material real de AS-REP que el atacante capturó (que es lo que crackea offline). Ves que la solicitud se emitió. No ves qué datos se devolvieron más allá de los metadatos. Tampoco ves la perspectiva del cliente: qué aplicación lanzó la solicitud, en qué contexto de usuario corría. Para eso necesitas el [4624](/es/blog/understanding-event-id-4624) del lado cliente, y [4688](/es/blog/event-id-4688-process-creation) si `kerbrute.exe` o Rubeus corrió localmente.

Nota también que 4768 se dispara solo para la solicitud TGT inicial y en renovaciones. Una vez que un cliente tiene un TGT válido en caché, no habla con el KDC de nuevo para TGT hasta renovación. Los tickets de servicio que deriva generan [4769](/es/blog/event-id-4769-kerberoasting), no 4768. Un atacante que roba un TGT de larga duración (golden ticket) puede emitir 4769 arbitrarios sin producir nunca otro 4768.

## Dónde encaja 4768 en una timeline

AS-REP roasting de principio a fin:

1. [4624](/es/blog/understanding-event-id-4624). Logon de dominio inicial de bajo privilegio (credencial phisheada).
2. *(LDAP, a veces un 4662 si la SACL está puesta)*. El atacante enumera `userAccountControl` para cuentas con `DONT_REQUIRE_PREAUTH`.
3. Ráfaga **4768**. `PreAuthType=0`, `etype=0x17`, `Status=0x0` para cada cuenta candidata. El punto de detección.
4. *(Offline, invisible)*. El atacante crackea el material AS-REP recuperado en Hashcat (modo 18200).
5. **4768**. Nueva solicitud TGT como la cuenta comprometida, esta vez normalmente pre-autenticada.
6. [4769](/es/blog/event-id-4769-kerberoasting). Tickets de servicio para todo lo que la cuenta comprometida puede alcanzar.
7. [4624](/es/blog/understanding-event-id-4624) LogonType 3 en el servicio destino.

El paso 3 es el canario. El paso 5 en adelante es el compromiso real. La ventana entre ellos, minutos a días, es la única ventana donde un defensor puede actuar antes de que la credencial esté viva en libertad.

## Lectura adicional

- [Documentación Microsoft para 4768](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768)
- [MITRE ATT&CK T1558.004](https://attack.mitre.org/techniques/T1558/004/)
- [Sean Metcalf: AS-REP Roasting](https://adsecurity.org/?p=3293)

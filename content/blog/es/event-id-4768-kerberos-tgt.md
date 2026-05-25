---
title: "Event ID 4768 explicado: solicitudes Kerberos TGT y AS-REP roasting"
description: "4768 es el registro del DC de cada TGT emitido. Léelo a través del código de resultado y la flag de pre-auth y detectas AS-REP roasting, fuerza bruta y abuso de delegación sin restricciones."
date: "2026-05-24"
---

El Event ID **4768** — «Se solicitó un ticket de autenticación Kerberos (TGT)» — se dispara en un Domain Controller cada vez que alguien pide un Ticket Granting Ticket. Cada logon de dominio empieza con uno de estos. Empareja con [4769](/es/blog/event-id-4769-kerberoasting) (service ticket) y ves el ciclo de vida Kerberos completo de cada cuenta en el bosque.

En un DC, 4768 es el registro de mayor volumen en el [canal Security](/es/blog/what-is-an-evtx-file) tras 4624. La mayoría es ruido; los slices de alta señal viven en dos campos específicos — y uno de ellos es la huella digital de AS-REP roasting.

## Dónde se dispara

Como [4769](/es/blog/event-id-4769-kerberoasting), 4768 aterriza solo en el **Domain Controller** emisor. El cliente no lo ve; el servicio objetivo no lo ve. Para detectar cualquier cosa desde 4768, necesitas colección Security desde cada DC — al estilo KAPE para engagements puntuales, WEF para estado estable.

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

- **`TargetUserName`** — la cuenta solicitando un TGT. Siempre una cuenta de usuario o de equipo; `ServiceName` siempre es `krbtgt`.
- **`Status`** — código de resultado Kerberos. `0x0` es éxito. Los fallos son lo que hace útil a 4768: `0x6` = usuario desconocido, `0x12` = cliente bloqueado, `0x17` = contraseña expirada, `0x18` = contraseña incorrecta.
- **`TicketEncryptionType`** — misma codificación que 4769: `0x12`/`0x11` AES (moderno), **`0x17` RC4** (legacy, también la huella digital de AS-REP roasting).
- **`PreAuthType`** — `2` es la pre-auth estándar de encrypted-timestamp; `0` significa **no se usó pre-auth** (el prerrequisito de AS-REP roasting); `15`/`16`/`17` son valores de pre-auth basados en certificado PKINIT.
- **`IpAddress`** — host solicitante. Empareja con el [4624](/es/blog/understanding-event-id-4624) del lado cliente para contexto completo.
- **`CertIssuerName` / `CertSerialNumber` / `CertThumbprint`** — poblado para PKINIT (logon por smart-card / certificado). Vacío para logons basados en contraseña.

## Los dos patrones de ataque que 4768 revela

### 1. AS-REP roasting (T1558.004)

El uso titular. Algunas cuentas tienen la flag `DONT_REQUIRE_PREAUTH` configurada en `userAccountControl` (bit UAC 22 = `0x400000`). Para esas cuentas, el DC responde a una solicitud TGT **sin** requerir la pre-auth de encrypted-timestamp — lo que significa que el AS-REP que devuelve contiene material que un atacante puede crackear offline para recuperar el hash de contraseña de la cuenta.

La huella digital 4768 de un AS-REP roast en progreso:

- `PreAuthType` es `0` (sin pre-auth).
- `TicketEncryptionType` es `0x17` (RC4 — lo que la herramienta de cracking necesita).
- `Status` es `0x0` (el DC felizmente emitió el AS-REP).
- A menudo se agrupa: un atacante batchea docenas de cuentas para probar cuáles tienen pre-auth deshabilitado.

Las cuentas reales con `DONT_REQUIRE_PREAUTH` existen casi exclusivamente para compatibilidad legacy (clientes Unix Kerberos muy viejos, algunos appliances antiguos). Son pequeñas en número y predecibles en ubicación. Un 4768 con `PreAuthType=0` para una cuenta que no tiene *ningún asunto* usando Kerberos sin pre-auth es la señal.

### 2. Fuerza bruta / spray basado en contraseña

Pre-auth Kerberos fallida produce 4768 con `Status=0x18` («contraseña incorrecta»). A diferencia de [4625](/es/blog/detecting-4625-brute-force) (que captura fallos NTLM), 4768 es donde aterrizan los ataques de contraseña basados en Kerberos. Los toolkits modernos (Rubeus, kerbrute) hablan Kerberos directamente porque el DC falla silenciosamente en intentos NTLM más rápido de lo que responde a los Kerberos — y muchos SOCs solo miran 4625.

La huella digital 4768 de fuerza bruta:

- Muchos registros `Status=0x18` para el mismo `TargetUserName` desde la misma IP de origen en una ventana corta — fuerza bruta clásica.
- Muchos registros `Status=0x18` a través de muchos valores de `TargetUserName` desde la misma IP de origen, cada cuenta tocada una o dos veces — password spray.
- Una ráfaga de `Status=0x6` («usuario desconocido») precediendo a un `Status=0x18` desde el mismo origen — enumeración de usuarios confirmada antes de que comience la brute.

## Los códigos de Status que verás

La lista completa es grande; estos son los que conducen el triage:

| Status | Significado | Lo que usualmente significa en la práctica |
|---|---|---|
| `0x0` | KDC_ERR_NONE | Éxito. |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | El nombre de usuario no existe. Ráfagas = enumeración. |
| `0x12` | KDC_ERR_CLIENT_REVOKED | Cuenta bloqueada / deshabilitada / expirada. |
| `0x17` | KDC_ERR_KEY_EXPIRED | Contraseña expirada. |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Contraseña incorrecta. Ráfagas = fuerza bruta o spray. |
| `0x19` | KDC_ERR_PREAUTH_REQUIRED | Devuelto al cliente *primero* en una solicitud TGT fresca; un éxito real sigue. No alertes sobre estos solos. |
| `0x25` | KRB_AP_ERR_SKEW | Desfase de reloj > 5 min entre cliente y DC. A menudo intentos de AS-REP roasting desde un host con reloj deliberadamente incorrecto. |

## Workflow de triage — AS-REP roasting

1. Filtra 4768 en todos los DCs para `PreAuthType == 0` AND `TicketEncryptionType == 0x17`.
2. Agrupa por `IpAddress`. Una sola cuenta desde un host de migración conocido es configuración; múltiples cuentas desde un origen es el ataque.
3. Pivota cada `TargetUserName` a su `userAccountControl` — ¿realmente necesita `DONT_REQUIRE_PREAUTH` estar establecido? Casi seguro que no.
4. IP de origen → [4624](/es/blog/understanding-event-id-4624) en ese host para encontrar la credencial que se autenticó para lanzar el ataque.
5. Rota la contraseña de cada cuenta crackeada; elimina `DONT_REQUIRE_PREAUTH` de las cuentas que no lo necesitan.

## Workflow de triage — fuerza bruta Kerberos

1. Filtra 4768 para `Status == 0x18`.
2. Agrupa por `IpAddress` en ventanas de 15 minutos; cuenta `TargetUserName` distintos.
3. >5 cuentas desde un origen en 15 minutos es spray; >10 fallos contra una cuenta en la misma ventana es fuerza bruta.
4. Cruza-verifica contra `Status == 0x6` desde el mismo origen — enumeración antes de la brute es el orden de libro de texto.

## Regla Sigma de ejemplo — AS-REP roasting

```yaml
title: AS-REP Roasting via Kerberos TGT Request Without Pre-Authentication
id: 4d3f9d18-cb29-4e7c-8e9c-7d3c4f4b1a3b
status: stable
description: Successful TGT issued with no pre-authentication and RC4 encryption — the AS-REP roasting fingerprint.
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
  - Accounts intentionally set with DONT_REQUIRE_PREAUTH for legacy interop (should be a vanishingly small set)
level: high
tags:
  - attack.credential_access
  - attack.t1558.004
```

## KQL de ejemplo — password spray Kerberos

```kusto
SecurityEvent
| where EventID == 4768
| where Status == "0x18"
| summarize Accounts=dcount(TargetUserName), AccountList=make_set(TargetUserName, 10)
    by IpAddress, bin(TimeGenerated, 15m)
| where Accounts >= 5
| order by TimeGenerated desc
```

## Splunk de ejemplo — AS-REP roasting

```spl
index=wineventlog EventCode=4768 PreAuthType=0 TicketEncryptionType="0x17" Status="0x0"
| stats values(TargetUserName) AS Targets dc(TargetUserName) AS NumTargets BY IpAddress
| where NumTargets >= 2
```

## Mapeo ATT&CK

- **T1558.004 — AS-REP Roasting**: la detección titular en `PreAuthType=0 + etype=0x17`.
- **T1110 — Brute Force** y sub-técnicas `.001` Password Guessing y `.003` Password Spraying — patrones `Status=0x18`.
- **T1558.001 — Golden Ticket**: un TGT forjado evita 4768 por completo. La detección aquí es por *ausencia* — un [4769](/es/blog/event-id-4769-kerberoasting) (solicitud TGS) sin un 4768 precedente desde el mismo origen/ventana es la sospecha.
- **T1187 — Forced Authentication**: no directamente visible en 4768 pero las solicitudes TGT resultantes sí.

## Falsos positivos que parecen ataques

- **Stacks Kerberos viejos de Java / Unix** en silos de apps legacy a veces hacen default a RC4 sin pre-auth. Aparecen como tráfico 4768 estable, diurno, desde un host estable. Baseline.
- **Migración PKINIT** durante rollouts de smart-card: flips legítimos a `PreAuthType=15/16/17` parecen anómalos si no los has visto antes. Vigila la ventana de rollout.
- **Bugs de librerías Kerberos**: ciertos clientes re-solicitan TGTs agresivamente en time skew, generando ruido. Cruza-verifica con `Status=0x25`.
- **Traversal de trust de dominio**: la autenticación cross-forest produce 4768 en cada lado. La `IpAddress` será un DC del otro forest; etiquétalo.

## Lo que 4768 no te dice

El registro **no** incluye el material AS-REP real que el atacante capturó (que es lo que crackean offline). Ves que la solicitud se emitió; no ves qué datos se devolvieron más allá de los metadatos. Tampoco ves la perspectiva del *cliente* — qué aplicación lanzó la solicitud, en qué contexto de usuario corrió, etc. Para eso necesitas el [4624](/es/blog/understanding-event-id-4624) del lado cliente (y [4688](/es/blog/event-id-4688-process-creation) si `kerbrute.exe` corrió localmente).

Nota también que 4768 se dispara solo para la solicitud TGT *inicial* y en renovaciones. Una vez que un cliente tiene un TGT válido cacheado, no habla con el KDC de nuevo para TGT hasta la renovación; los tickets de *servicio* que deriva generan [4769](/es/blog/event-id-4769-kerberoasting), no 4768. Los dos registros describen etapas diferentes del mismo protocolo — y un atacante que roba un TGT de larga vida (golden ticket) puede emitir 4769 arbitrarios sin producir otro 4768.

## Dónde encaja 4768 en una timeline

La cadena de AS-REP roasting de principio a fin:

1. [**4624**](/es/blog/understanding-event-id-4624) — logon inicial de dominio de bajo privilegio (credencial phisheada).
2. *(LDAP, a veces un 4662 si la SACL está configurada)* — el atacante enumera flags `userAccountControl` para cuentas con `DONT_REQUIRE_PREAUTH`.
3. Ráfaga de **4768** — `PreAuthType=0`, `etype=0x17`, `Status=0x0` para cada cuenta candidata. **Este es el punto de detección.**
4. *(Offline, invisible)* — el atacante craquea el material AS-REP recuperado en Hashcat (modo 18200) y recupera la contraseña en texto plano.
5. **4768** — nueva solicitud TGT como la cuenta comprometida, esta vez con pre-auth normal.
6. [**4769**](/es/blog/event-id-4769-kerberoasting) — service tickets para todo lo que la cuenta comprometida puede alcanzar.
7. [**4624**](/es/blog/understanding-event-id-4624) LogonType 3 en el servicio objetivo.

El paso 3 es el canario. El paso 5 en adelante es el compromiso real. La ventana entre ellos — de minutos a días — es la única ventana donde un defensor puede actuar antes de que la credencial esté viva en el mundo.

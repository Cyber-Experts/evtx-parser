---
title: "Event ID 4720 explicado: detectar creación de cuentas rogue en AD"
description: "4720 se dispara cada vez que se crea una cuenta de usuario — local o en AD. Léelo con 4722/4724/4732 y detectas cuentas de persistencia y movimiento lateral en minutos."
date: "2026-05-24"
---

El Event ID **4720** — «Se creó una cuenta de usuario» — se escribe en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que se aprovisiona una nueva cuenta de usuario. En un domain controller se dispara para cada nuevo usuario AD; en una workstation o servidor miembro se dispara para cada nueva cuenta local. En un shop maduro, el tráfico 4720 es abrumadoramente HR-driven y predecible. Esa predictibilidad es lo que lo hace útil: un atacante creando una cuenta backdoor destaca precisamente porque el tráfico legítimo es tan regular.

Este es uno de los registros de detección de persistencia más baratos que la plataforma produce.

## Dónde se dispara

- **Cuentas de dominio**: 4720 aterriza en el DC que manejó la creación. Recolecta en todos los DCs.
- **Cuentas locales**: 4720 aterriza en el host donde se creó la cuenta. Capturar esto desde workstations miembro requiere WEF o colección por host — muchos shops se saltan el forwarding de Security de workstations y pierden esta señal por completo.

Si el atacante crea una cuenta *local* en un servidor que ya ha comprometido (a menudo como credencial de respaldo), el 4720 estará solo en ese servidor. La cobertura importa.

## Qué contiene el registro

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

Los campos que conducen las investigaciones:

- **`TargetUserName`** — la nueva cuenta. El nombre literal es la primera señal de triage: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, parecidos a cuentas legítimas (`administrator`, `administr0r`), y cadenas aleatorias cortas, todos merecen una mirada más cercana.
- **`SubjectUserName` / `SubjectLogonId`** — *quién* la creó. Pivot al [4624](/es/blog/understanding-event-id-4624) que creó esa sesión. Un 4720 desde `LocalSystem` en una workstation fuera del horario laboral no es un workflow de aprovisionamiento real.
- **`UserAccountControl`** — el conjunto *inicial* de flags UAC. `0x10` (el ejemplo) es `NORMAL_ACCOUNT`; los flags peligrosos aparecen en registros 4738 (account changed) subsiguientes. El mapa de bits UAC completo está en MS-SAMR.
- **`PrimaryGroupId`** — 513 (Domain Users) es normal; 512 (Domain Admins) en una cuenta nueva es una anomalía a gritos que nunca debería ocurrir en un workflow de aprovisionamiento real.
- **`SidHistory`** — un `SidHistory` no vacío en una cuenta *recién creada* es una señal fuerte de una herramienta de migración — o, en el contexto equivocado, un artefacto de autenticación forjado.

## Los registros con los que 4720 no viene solo

La creación de cuenta casi nunca es un evento único. La secuencia mínima:

| Evento | Significado | Por qué te importa |
|---|---|---|
| **4720** | Cuenta de usuario creada | El titular. |
| **4722** | Cuenta de usuario habilitada | La cuenta se configura para permitir logon. Si 4722 está ausente, la cuenta existe pero aún no puede iniciar sesión. |
| **4724** | Reseteo de contraseña (admin-driven) | Alguien — posiblemente no el creador — estableció o reseteó la contraseña. |
| **4738** | Cuenta de usuario modificada | Flags UAC, expiración, grupo, cambios de atributos. |
| **4732** | Miembro añadido a un grupo local con seguridad habilitada | Si el grupo local es `Administrators`, este es el otorgamiento de privilegio. |
| **4728** | Miembro añadido a un grupo global con seguridad habilitada | Si el grupo global es `Domain Admins` o `Enterprise Admins`, escalada. |
| **4756** | Miembro añadido a un grupo universal con seguridad habilitada | `Schema Admins`, `Enterprise Admins`, delegaciones personalizadas. |

Una cuenta backdoor rara vez se crea y se deja con privilegio por defecto. La cadena completa — `4720 → 4722 → 4724 → 4738 (flags UAC) → 4732/4728 (group add)` — se completa en segundos y es el evento de persistencia real.

## Patrones de triage

1. **Cuenta nueva → grupo admin en minutos**: 4720 seguido de 4732/4728 a un grupo privilegiado dentro de una hora, donde el group add privilegiado *no* fue precedido por un ticket en el sistema de change-management. Empareja `TargetSid` del 4720 con `MemberSid` en 4732/4728.
2. **Creación fuera de horario**: 4720 fuera del horario laboral por un `SubjectUserName` que no es una cuenta de servicio haciendo aprovisionamiento automatizado.
3. **Nombre parecido**: `Levenshtein(TargetUserName, real_admin_name) <= 2` contra la tabla de usuarios existente. `administrato`, `administr0r`, `helpd3sk` — todos son casos reales.
4. **Creada por una cuenta recientemente comprometida**: 4720 donde `SubjectLogonId` se remonta a un 4624 desde una IP inusual, o un 4624 LogonType 3 desde una workstation que el sujeto normalmente no usa.
5. **Creada por `LocalSystem` en una workstation**: 4720 con `SubjectUserSid = S-1-5-18` en cualquier cosa que no sea un domain controller o servidor de aprovisionamiento conocido. Casi siempre malicioso.
6. **`PrimaryGroupId == 512`**: nunca ocurre en aprovisionamiento normal. Alerta dura.

## Regla Sigma de ejemplo

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

Una variante de alta confianza: combina 4720 con un 4732/4728 a un grupo privilegiado dentro de 1 hora, scopeado por `TargetSid`.

## KQL de ejemplo — 4720 + otorgamiento de privilegio

KQL (Sentinel) — el pivot «cuenta nueva → grupo admin»:

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Splunk de ejemplo

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## Mapeo ATT&CK

- **T1136.001 — Create Account: Local Account** para cuentas locales de workstation/servidor.
- **T1136.002 — Create Account: Domain Account** para creaciones registradas en DC.
- **T1136.003 — Create Account: Cloud Account** — *no* dispara 4720 (las creaciones de cuenta cloud están en los audit logs de Azure AD / unified audit log, no en Windows Security).
- **T1098 — Account Manipulation** cuando 4720 es seguido por escalada de grupo o cambios de atributos.

## Falsos positivos que parecen exactamente ataques

- **Herramientas de migración masiva** (ADMT, Quest Migration Manager) crean cuentas a velocidad con `SidHistory` configurado. La forma del tráfico es idéntica a un atacante rápido; baseline las ventanas de migración conocidas.
- **Pipelines de joiner** en workflows de aprovisionamiento HR-driven disparan 4720 a horas predecibles. Si alertas en cada 4720 fuera de horario te enterrarás en runs del sistema HR que se desplazan más allá de medianoche.
- **Herramientas de gestión estilo SCCM / Intune / Jamf** crean cuentas locales para aprovisionamiento de SO. El `SubjectUserSid` será `S-1-5-18` (LocalSystem) en hosts de build conocidos; etiqueta esos hosts.
- **Instaladores de servicio** para algunos productos legacy crean una cuenta de servicio local en el primer run. Baseline el instalador.

Las detecciones sólidas de 4720 siempre combinan la creación con una señal de seguimiento (group add, cambio de contraseña a un patrón débil conocido, login inmediato desde un host inusual). La creación standalone es demasiado ruidosa.

## Lo que 4720 no te dice

El registro no incluye la *contraseña* de la nueva cuenta (Windows nunca registra eso, en ningún sitio). Tampoco incluye el SID del *dominio objetivo* explícitamente; lees el dominio desde `TargetDomainName` o lo derivas de la porción de dominio del `TargetSid`.

Las creaciones de cuenta local en workstations miembro son invisibles al DC. Si no estás recolectando Security desde workstations (la mayoría de shops no lo hacen), te perderás cada cuenta backdoor local. Sysmon y un EDR de verdad cubren parte del hueco (patrones de creación de archivos / cambios en registro cuando se toca el SAM local), pero el forwarding de 4720 es la forma más barata.

## Dónde encaja 4720 en una timeline

La cadena de persistencia de libro de texto:

1. [**4624**](/es/blog/understanding-event-id-4624) — logon de dominio inicial por un usuario phisheado.
2. Ráfaga de [**4769**](/es/blog/event-id-4769-kerberoasting) — kerberoasting contra cuentas de servicio de dominio.
3. **4624** como cuenta de servicio comprometida en un servidor miembro.
4. [**4688**](/es/blog/event-id-4688-process-creation) — `net user svc_backup2 P@ssw0rd! /add /domain` (o lo mismo vía PowerShell `New-ADUser`).
5. **4720** — cuenta creada en el DC.
6. **4724** — contraseña establecida.
7. **4722** — cuenta habilitada.
8. **4728** — añadida a Domain Admins.
9. [**7045**](/es/blog/service-creation-event-id-7045) — servicio instalado en un servidor, corriendo bajo la nueva cuenta.

Si instrumentas 4720 solo, atrapas la persistencia en el paso 5 — antes de que los pasos 6-9 hagan ningún daño. Ese es el valor.

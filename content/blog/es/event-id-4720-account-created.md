---
title: "Event ID 4720 explicado: detectar creación de cuentas maliciosas en AD"
description: "4720 se dispara cada vez que se crea una cuenta de usuario, local o de dominio. Léelo con 4722, 4724 y 4732 y atrapas cuentas de persistencia y movimiento lateral en minutos."
date: "2026-05-24"
---

El Event ID **4720**, "Se creó una cuenta de usuario", aterriza en el [canal `Security`](/es/blog/what-is-an-evtx-file) cada vez que se aprovisiona un nuevo usuario. En un controlador de dominio se dispara para cada nuevo usuario de AD. En una estación de trabajo o servidor miembro se dispara para cada nueva cuenta local. En un shop maduro, el tráfico de 4720 es abrumadoramente impulsado por RRHH y predecible. Esa predictibilidad es lo que lo hace útil. Un atacante creando una cuenta backdoor destaca precisamente porque el tráfico legítimo es tan regular.

Este es uno de los registros de detección de persistencia más baratos que produce la plataforma. He cerrado casos solo con él.

## Dónde se dispara

- Cuentas de dominio: 4720 aterriza en el DC que manejó la creación. Recoge a través de todos los DCs.
- Cuentas locales: 4720 aterriza en el host donde se creó la cuenta. Capturar esto desde estaciones miembro requiere WEF o colección por host. Muchos shops se saltan el reenvío de Security de estaciones y pierden esta señal completamente.

Si el atacante crea una cuenta *local* en un servidor que ya ha comprometido (a menudo como credencial de respaldo), el 4720 estará solo en ese servidor. La cobertura importa más que las reglas.

## Qué hay en el registro

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

Los campos que mueven las investigaciones:

- `TargetUserName`. La nueva cuenta. El nombre literal es la primera señal de triaje: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, lookalikes de cuentas legítimas (`administrator`, `administr0r`) y cadenas aleatorias cortas, todas merecen una mirada más cercana.
- `SubjectUserName` y `SubjectLogonId`. Quién la creó. Pivota al [4624](/es/blog/understanding-event-id-4624) que creó esa sesión. Un 4720 desde `LocalSystem` en una estación de trabajo fuera de horario no es un workflow de aprovisionamiento real.
- `UserAccountControl`. El conjunto *inicial* de flags UAC. `0x10` (en el ejemplo) es `NORMAL_ACCOUNT`. Los flags peligrosos aparecen en registros 4738 posteriores.
- `PrimaryGroupId`. 513 (Domain Users) es normal. 512 (Domain Admins) en una cuenta nueva es a gritos y nunca debería pasar en un workflow de aprovisionamiento real.
- `SidHistory`. No vacío en una cuenta recién creada es o una herramienta de migración o, en el contexto equivocado, un artefacto de autenticación forjado.

## 4720 nunca viene solo

La creación de cuenta casi nunca es un evento único. La secuencia mínima:

| Evento | Significado | Por qué te importa |
|---|---|---|
| **4720** | Cuenta de usuario creada | El titular. |
| **4722** | Cuenta de usuario habilitada | La cuenta se establece para permitir logon. Si falta 4722, la cuenta existe pero no puede loguearse todavía. |
| **4724** | Reset de contraseña (impulsado por admin) | Alguien, posiblemente no el creador, estableció o reseteó la contraseña. |
| **4738** | Cuenta de usuario cambiada | Flags UAC, expiración, grupo, cambios de atributo. |
| **4732** | Miembro añadido a un grupo local habilitado para seguridad | Si el grupo local es `Administrators`, esta es la concesión de privilegio. |
| **4728** | Miembro añadido a un grupo global habilitado para seguridad | Si el grupo global es `Domain Admins` o `Enterprise Admins`, escalada. |
| **4756** | Miembro añadido a un grupo universal habilitado para seguridad | `Schema Admins`, `Enterprise Admins`, delegaciones personalizadas. |

Una cuenta backdoor raramente se crea y se deja con privilegio por defecto. La cadena completa (4720, 4722, 4724, 4738, 4732/4728) se completa en segundos y es el evento de persistencia real.

## Patrones de triaje

1. **Cuenta nueva en grupo admin en minutos**. 4720 seguido de 4732 o 4728 a un grupo privilegiado en una hora, donde el añadido al grupo privilegiado no estuvo precedido por un ticket. Empareja `TargetSid` del 4720 con `MemberSid` en 4732/4728.
2. **Creación fuera de horario**. 4720 fuera del horario laboral por un `SubjectUserName` que no es una cuenta de servicio ejecutando aprovisionamiento automatizado.
3. **Nombre lookalike**. `Levenshtein(TargetUserName, real_admin_name) <= 2` contra la tabla de usuarios existente. `administrato`, `administr0r`, `helpd3sk`. Todas reales.
4. **Creado por una cuenta recientemente comprometida**. 4720 donde `SubjectLogonId` rastrea hacia un 4624 desde una IP inusual, o un 4624 LogonType 3 desde una estación de trabajo que el sujeto normalmente no usa.
5. **Creado por LocalSystem en una estación de trabajo**. 4720 con `SubjectUserSid = S-1-5-18` en cualquier cosa que no sea un controlador de dominio o servidor de aprovisionamiento conocido. Casi siempre malicioso.
6. **PrimaryGroupId == 512**. Nunca pasa en aprovisionamiento normal. Alerta dura.

## Sigma

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

Una variante de alta confianza combina 4720 con un 4732 o 4728 a un grupo privilegiado en 1 hora, scopeado por `TargetSid`.

## KQL: 4720 más concesión de privilegio

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

## Splunk

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

- T1136.001 Create Account: Local Account. Cuentas locales de estación de trabajo y servidor.
- T1136.002 Create Account: Domain Account. Creaciones registradas en DC.
- T1136.003 Create Account: Cloud Account. *No* dispara 4720. Las creaciones en cloud viven en los audit logs de Entra ID / unified audit log.
- T1098 Account Manipulation. Cuando a 4720 le siguen escalada de grupo o cambios de atributo.

## Falsos positivos que parecen ataques

- Las herramientas de migración masiva (ADMT, Quest Migration Manager) crean cuentas a velocidad con `SidHistory` puesto. La forma es idéntica a un atacante rápido. Baseline ventanas de migración conocidas.
- Los pipelines de joiner en workflows de aprovisionamiento impulsados por RRHH disparan 4720 en momentos predecibles. Alertar sobre cada 4720 fuera de horario te enterrará en ejecuciones de RRHH que se derraman pasada la medianoche.
- Las herramientas de gestión estilo SCCM, Intune y Jamf crean cuentas locales para aprovisionamiento de OS. `SubjectUserSid` es `S-1-5-18` en hosts de build conocidos. Etiqueta esos.
- Los instaladores de servicio para algunos productos legacy crean una cuenta de servicio local en la primera ejecución. Baseline el instalador.

Las detecciones sólidas de 4720 siempre combinan la creación con una señal de seguimiento (añadido a grupo, cambio de contraseña a un patrón débil conocido, login inmediato desde un host inusual). La creación independiente es demasiado ruidosa.

## Lo que 4720 no te dice

El registro no incluye la contraseña de la nueva cuenta (Windows nunca logea eso, en ningún lado). Tampoco incluye el SID del dominio destino explícitamente. Lees el dominio de `TargetDomainName` o lo derivas de la porción de dominio de `TargetSid`.

Las creaciones de cuentas locales en estaciones miembro son invisibles para el DC. Si no estás recolectando Security de estaciones de trabajo (la mayoría de shops no lo hacen), pierdes toda cuenta backdoor local. Sysmon y un EDR real llenan parte del hueco (patrones de creación de archivo y cambio de registro cuando se toca el SAM local), pero el reenvío de 4720 es el control más barato. El snapshot de hive del [registro](https://www.registryparser.com) es la corroboración cuando el reenvío de log estaba apagado.

## Dónde encaja 4720 en una timeline

La cadena de persistencia de manual:

1. [4624](/es/blog/understanding-event-id-4624). Logon inicial de dominio por un usuario phisheado.
2. Ráfaga de [4769](/es/blog/event-id-4769-kerberoasting). Kerberoasting contra cuentas de servicio de dominio.
3. 4624 como una cuenta de servicio comprometida en un servidor miembro.
4. [4688](/es/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (o `New-ADUser` vía PowerShell).
5. **4720**. Cuenta creada en el DC.
6. 4724. Contraseña establecida.
7. 4722. Cuenta habilitada.
8. 4728. Añadido a Domain Admins.
9. [7045](/es/blog/service-creation-event-id-7045). Servicio instalado en un servidor, ejecutándose bajo la nueva cuenta.

Instrumenta solo 4720 y atrapas la persistencia en el paso 5, antes de que los pasos 6 a 9 hagan ningún daño. Ese es el valor.

## Lectura adicional

- [Documentación Microsoft para 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)

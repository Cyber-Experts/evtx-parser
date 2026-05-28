---
title: "Event ID 4624 explicado: logon exitoso de Windows y referencia LogonType"
description: "Qué contiene realmente un registro 4624, por qué el campo LogonType importa más que el evento en sí, y cómo leerlos a escala."
date: "2026-05-17"
---

El event ID 4624, "Una cuenta se ha iniciado sesión correctamente", aterriza en el [canal `Security`](/en/blog/what-is-an-evtx-file) cada vez que Windows autentica una identidad. Es el registro de mayor tráfico en la mayoría de workstations y la espina dorsal de casi cada investigación IR. Saber cómo leer uno no es opcional.

## Qué hay dentro de un registro 4624

Las partes interesantes viven en `<EventData>`:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="TargetUserName">alice</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">LAPTOP-01</Data>
<Data Name="IpAddress">10.0.0.42</Data>
<Data Name="LogonGuid">{...}</Data>
```

Los campos `Subject*` son el contexto de seguridad que *solicitó* el logon (a menudo `S-1-5-18` para SYSTEM durante arranques de servicio). Los campos `Target*` son la identidad que terminó autenticada. Confundir los dos cuesta horas a los analistas. He visto un analista senior escalar sobre un `Subject` que resultó ser SYSTEM ejecutando un servicio interno. Lee ambos, dos veces, antes de hacer la llamada.

## LogonType es el campo que decide

Windows trae diez tipos de logon. En la práctica solo un puñado conducen el triaje:

- **2 Interactivo**. Logon físico o de consola.
- **3 Red**. SMB, RPC, WinRM, cualquier cosa por el cable. La vasta mayoría del tráfico normal.
- **4 Batch**. Tareas programadas corriendo como usuario.
- **5 Servicio**. Un servicio iniciado bajo una cuenta específica.
- **7 Unlock**. Workstation desbloqueada tras bloqueo de pantalla.
- **8 NetworkCleartext**. Raro y sospechoso. Credenciales enviadas en texto plano (Basic auth en IIS, impresoras antiguas, simple bind LDAP mal configurado).
- **9 NewCredentials**. `runas /netonly`. A menudo usado por atacantes llevando credenciales de dominio a una máquina sobre la que solo tienen derechos locales.
- **10 RemoteInteractive**. RDP. Empareja con `IpAddress` para atribución de origen.
- **11 CachedInteractive**. Cuenta de dominio logueada con credenciales en caché. Sin DC alcanzable.

Un 4624 con LogonType **10** desde una IP externa a las 03:00 de un domingo cuenta una historia muy diferente a 50 registros LogonType **3** desde un servidor de backup a las 02:00.

## Con qué encadenarlo

Un 4624 exitoso solo rara vez es un hallazgo. Se vuelve uno cuando se empareja con:

- [4625](/en/blog/detecting-4625-brute-force) precediéndolo desde la misma fuente. Un éxito tras una ráfaga de fallos es la firma de libro de texto brute-force-luego-éxito.
- [4672](/en/blog/event-id-4672-special-privileges). Marca logons que otorgaron privilegios como `SeDebugPrivilege`.
- 4648 (logon con credenciales explícitas). Captura `runas` y otros patrones de pasaje de credenciales. La mayoría de defensores lo subutilizan.
- [7045](/en/blog/service-creation-event-id-7045) siguiéndolo con LogonType 3. Instalación de servicio tras un logon de red es la firma de PsExec.

## Los cinco patrones

Los que realmente disparan alertas en un SOC real, en orden aproximado de cuán a menudo se ganan su utilidad:

1. **Brute-force-luego-éxito.** Una ráfaga de [4625](/en/blog/detecting-4625-brute-force) desde una IP fuente seguida en minutos por un 4624 desde la misma IP para el mismo `TargetUserName`. El atacante encontró una credencial funcional. La captura más barata en el catálogo de auditoría.
2. **RDP fuera de horario.** 4624 con `LogonType=10` desde IP externa fuera de horas de oficina. Etiqueta IPs de egress VPN admin conocidas. Todo lo demás es una pista real.
3. **`runas /netonly`.** 4624 con `LogonType=9`. El uso legítimo es raro (herramientas admin usando credenciales de dominio foráneo). El uso de atacante es un patrón de pivote de credenciales tras capturar credenciales de un host en el que no quieren aparecer.
4. **NetworkCleartext (LogonType=8).** Credenciales en texto plano por el cable. Causas reales son apps IIS Basic-auth antiguas, impresoras ancestrales o simple bind LDAP mal configurado. Cada una es una responsabilidad de fuga de credenciales.
5. **Drift de LogonType en cuentas de servicio.** Una cuenta de servicio que históricamente solo dispara LogonType 3 produciendo de repente LogonType 10 o LogonType 2. Casi siempre significa que alguien está usando la cuenta de servicio interactivamente. Señal fuerte de credenciales robadas.

## Sigma: logon exitoso tras ráfaga de fallos

```yaml
title: Successful Logon Following Failed Logon Burst
id: 8f3a1c20-8b1d-4c7c-8a2f-1c3d4f5a6b7c
status: stable
description: A 4624 success record for an account that just generated multiple 4625 failures from the same source. Brute-force-then-success.
references:
  - https://attack.mitre.org/techniques/T1110/
logsource:
  product: windows
  service: security
detection:
  fail_burst:
    EventID: 4625
  success:
    EventID: 4624
    LogonType:
      - 3
      - 10
  timeframe: 10m
  condition: ( fail_burst | count() by IpAddress,TargetUserName > 10 ) and success
falsepositives:
  - Users repeatedly typing passwords after a recent password change
  - SSO endpoints with retry behavior on first auth
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

## KQL: RDP fuera de horario desde IPs externas

```kusto
SecurityEvent
| where EventID == 4624
| where LogonType == 10
| where IpAddress !startswith "10."
    and IpAddress !startswith "192.168."
    and not (IpAddress startswith "172." and toint(split(IpAddress, ".")[1]) between (16 .. 31))
| extend Hour = datetime_part("Hour", TimeGenerated)
| where Hour < 7 or Hour > 20
| project TimeGenerated, Account, IpAddress, WorkstationName, Computer
| order by TimeGenerated desc
```

## Splunk: drift de LogonType en cuenta de servicio

```spl
index=wineventlog EventCode=4624 TargetUserName="svc_*"
| stats values(LogonType) AS LogonTypes count BY TargetUserName
| where mvcount(LogonTypes) > 1 OR LogonTypes!="3"
```

Las cuentas de servicio deberían producir un `LogonType` único y estable (usualmente 3 o 5). Múltiples tipos bajo la misma cuenta es la alerta.

## Mapeo ATT&CK

- T1078 Valid Accounts (y sub-técnicas `.001` Default, `.002` Domain, `.003` Local). Cada logon exitoso por una credencial comprometida se mapea aquí. 4624 es la *evidencia* de la técnica.
- T1110 Brute Force. Combinado con ráfagas de [4625](/en/blog/detecting-4625-brute-force).
- T1021 Remote Services (`.001` RDP, `.002` SMB, `.006` WinRM). El grueso del tráfico 4624 LogonType=3/10 lado-red.
- T1550 Use Alternate Authentication Material. `.002` Pass the Hash (4624 con paquete NTLM desde fuente inesperada), `.003` Pass the Ticket (4624 con paquete Kerberos sin [4769](/en/blog/event-id-4769-kerberoasting) coincidente en ningún DC).

## Falsos positivos que se ven exactamente como ataques

- Los escáneres de vulnerabilidad (Tenable, Qualys, Rapid7) generan tráfico denso 4624 LogonType=3 desde un conjunto estable de IPs scanner. Etiqueta y excluye.
- Los check-ins de cliente SCCM e Intune producen tráfico 4624 recurrente a endpoints de gestión.
- Los agentes de backup se autentican a muchos hosts en un calendario. Parece propagación. No lo es.
- Las cajas Citrix y RDS multi-sesión ven legítimamente LogonType=10 desde muchas IPs internas. Filtra por rango de origen.
- UX de cambio de contraseña. Los usuarios que acaban de cambiar una contraseña y re-tipearon la antigua dos veces producen 4625 / 4625 / 4624. Eso no es brute force, es memoria muscular.

La señal es recurrencia *inesperada* o combinaciones *novel*, no volumen crudo.

## Lo que 4624 no te dice

- Sin información de proceso. Ves el logon, no qué corrió en la sesión resultante. Pivota `LogonId` a [4688](/en/blog/event-id-4688-process-creation) o [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) para ver actividad de proceso.
- Sin proceso fuente para el logon en sí. Sabes que se usó NTLM o Kerberos, pero no qué app cliente lo inició.
- `IpAddress` puede estar vacío o `-` para logons NTLM desde un DC. El campo no es confiable en cada registro.
- Los logons interactivos en caché (Type 11) suceden cuando el DC es inalcanzable. Confirman que una credencial funcionó localmente, no que la cuenta viva esté habilitada en el DC.

## Leer a escala

El [parser de navegador en este sitio](/en/blog/how-to-open-an-evtx-file) extrae estos campos directamente del XML del registro y los expone en la tabla. Filtra por `LogonType` vía los buckets de timeline y el filtro de texto, tira el conjunto filtrado como CSV, luego pivota en `SubjectUserSid` e `IpAddress` en tu herramienta de elección. El XML completo de cada registro está a un clic. Empareja con [artefactos de caché RDP](https://www.jumplistparser.com), tracking de [archivo reciente](https://www.recentfilecacheparser.com), e [historial de navegador](https://www.browserforensics.app) cuando la cuenta de usuario en cuestión es un usuario real, no un servicio.

## Lecturas adicionales

- [Documentación Microsoft para 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)

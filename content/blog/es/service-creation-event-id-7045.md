---
title: "Event ID 7045 explicado: instalación de servicio como señal de persistencia"
description: "La creación de servicios es una de las técnicas de persistencia más ruidosas. El evento 7045 captura cada instalación — lee estos tres campos y atraparás la mayor parte."
date: "2026-05-17"
---

El Event ID **7045** — «Se instaló un servicio en el sistema» — se dispara en el [canal `System`](/es/blog/what-is-an-evtx-file) siempre que el Service Control Manager registra un nuevo servicio. Es ruidoso en un build de stock (instalaciones de drivers, actualizaciones) pero en entornos corporativos en estado estable es lo suficientemente tranquilo como para que las anomalías destaquen. También es una de las técnicas de persistencia más citadas de MITRE ATT&CK: T1543.003.

## Qué contiene el registro

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinco campos, tres de los cuales importan para IR.

## Los tres campos a leer primero

**`ImagePath`** es el campo individualmente más útil. Los servicios legítimos viven bajo `C:\Windows\System32\`, `C:\Program Files\`, o `C:\Program Files (x86)\`. Cualquier servicio cuyo binario se sienta en `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\`, o un directorio con nombre aleatorio merece una mirada más cercana. `ImagePath` también puede ser una línea `cmd.exe /c …` o `powershell.exe -e …` — esas casi siempre son maliciosas; los servicios legítimos no salen a una shell.

**`AccountName`** suele ser `LocalSystem`. Un servicio instalado bajo un usuario de dominio o una cuenta de servicio específica que no coincide con el patrón de la organización es inusual.

**`StartType`** de `auto start` significa que el servicio corre en cada arranque. `demand start` significa manual. La persistencia casi siempre quiere `auto start`; la ejecución lateral de un solo disparo puede usar `demand start` y limpiar tras sí — haciendo que el 7045 sea el único artefacto que queda.

## El patrón de ejecución lateral

Cuando un atacante ejecuta `PsExec` o cualquier herramienta que use el SCM para ejecución remota en otro host, obtienes un 7045 en el host *objetivo* con un `ImagePath` como `%SystemRoot%\PSEXESVC.exe` (default) o un equivalente renombrado. El servicio aparece, corre, y a menudo se elimina en segundos. El 7045 es la huella digital superviviente mucho después de que el servicio mismo se ha ido.

Un 7045 con `ImagePath` terminando en `.exe` seguido segundos después por [4624 LogonType **3**](/es/blog/understanding-event-id-4624) desde un host de origen específico es la firma de libro de PsExec. Variantes como SMBExec, WMIExec, y el `psexec.py` de Impacket producen valores `ImagePath` ligeramente diferentes pero el mismo patrón general.

## Lo que 7045 no te dice

7045 se dispara en la *instalación*, no en cada arranque subsiguiente. Para ver el servicio realmente corriendo necesitas 7036 («service entered the running state»). Para ver el proceso subyacente necesitas [Sysmon event 1](/es/blog/sysmon-event-id-1-process-create) o [4688](/es/blog/event-id-4688-process-creation) con la ruta `Image` coincidente.

Para servicios instalados *antes* de que el audit log empiece (p.ej., durante la instalación del SO), no hay 7045 — existen en el registro bajo `HKLM\SYSTEM\CurrentControlSet\Services\` y tienen que enumerarse desde ahí, no desde event logs.

## Workflow de triage

1. Filtra el canal System por `EventID:7045`.
2. Ordena o pivota por `ImagePath` — cualquier cosa fuera de las rutas de instalación estándar es sospechosa.
3. Para cada sospechoso, saca el 4624 correspondiente por timestamp + host de origen — encuentra la credencial que lo instaló.
4. Saca el evento Sysmon 1 con `Image` coincidiendo con `ImagePath` para ver ejecuciones reales.
5. Anota si una secuencia [**7036**](/es/blog/event-id-7036-service-state) / 7034 / 7035 muestra una ejecución de un solo disparo o un servicio persistente.

## Regla Sigma de ejemplo — servicio instalado desde ruta no estándar

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory — common for persistence and PsExec-style execution.
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1569/002/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
  suspicious_path:
    ImagePath|contains:
      - '\Windows\Temp\'
      - '\Users\'
      - '\ProgramData\'
      - '\AppData\'
      - '\Public\'
  shell_image:
    ImagePath|contains:
      - 'cmd.exe /c'
      - 'cmd /c'
      - 'powershell'
      - 'pwsh'
      - 'rundll32'
      - 'mshta'
  condition: selection and (suspicious_path or shell_image)
falsepositives:
  - Software installers that bootstrap services from a staging directory
  - Custom enterprise tooling deployed under ProgramData
level: high
tags:
  - attack.persistence
  - attack.t1543.003
```

## KQL de ejemplo — huella digital de ejecución lateral PsExec

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]);
let logons =
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM"
    | project LogonTime=TimeGenerated, LogonHost=Computer, LogonIp=IpAddress,
              LogonAccount=AccountName;
installs
| where ImagePath endswith ".exe"
| join kind=inner logons on $left.Host == $right.LogonHost
| where LogonTime between (InstallTime - 30s .. InstallTime + 30s)
| project InstallTime, Host, ServiceName, ImagePath, LogonIp, LogonAccount
| order by InstallTime desc
```

Un 4624 LogonType-3 dentro de 30 segundos de un 7045 en el mismo host es la firma de libro de PsExec.

## Splunk de ejemplo — instalador de servicio anómalo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mapeo ATT&CK

- **T1543.003 — Create or Modify System Process: Windows Service**: el mapeo titular. Servicios de larga duración iniciados bajo binarios controlados por el atacante.
- **T1569.002 — System Services: Service Execution**: servicios de corta duración usados puramente como vehículo para ejecución remota (PsExec, SMBExec, movimiento lateral basado en SCM).
- **T1078 — Valid Accounts**: cuando el principal instalador es un domain admin cuyas credenciales fueron robadas.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: servicios con nombres mostrados imitando servicios Microsoft reales pero binarios en otra parte.

## Falsos positivos que parecen exactamente ataques

- **Instaladores de software** (Chocolatey, bootstrappers MSI) frecuentemente instalan servicios desde un directorio de staging antes de mover el binario. El 7045 se dispara desde la ruta de staging aunque la instalación final esté limpia.
- **Agentes EDR / AV** instalan servicios como parte de su setup. El `ImagePath` del vendor será estable y firmado; baseline.
- **Algunas actualizaciones de Microsoft** instalan servicios de servicing temporales; estos son de corta duración y desde `LocalSystem`.
- **Workloads Container / Hyper-V** a veces registran servicios transitorios por-VM.

La señal es instalaciones *de un solo disparo* a rutas escribibles por el usuario por instaladores *no-admin o no-estándar*. Un servicio instalador firmado en `C:\Program Files\` no es el ataque.

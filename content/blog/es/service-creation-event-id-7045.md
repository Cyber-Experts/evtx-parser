---
title: "Event ID 7045 explicado: instalación de servicio como señal de persistencia"
description: "La creación de servicios es una de las técnicas de persistencia más ruidosas. El evento 7045 captura cada instalación. Lee estos tres campos y atrapas la mayoría."
date: "2026-05-17"
---

El event ID **7045**, "Se ha instalado un servicio en el sistema", se dispara en el [canal `System`](/en/blog/what-is-an-evtx-file) cada vez que el Service Control Manager registra un nuevo servicio. Es ruidoso en una build estándar (instalaciones de drivers, Windows Updates), pero en un entorno corporativo en estado estacionario se vuelve lo suficientemente silencioso como para que las anomalías destaquen. Es también una de las técnicas de persistencia más citadas de MITRE ATT&CK: T1543.003. Vale la pena conocerlo de memoria.

## Qué hay en el registro

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Cinco campos. Tres importan para IR.

## Los tres campos a leer primero

**`ImagePath`** es el campo más útil. Los servicios legítimos viven bajo `C:\Windows\System32\`, `C:\Program Files\` o `C:\Program Files (x86)\`. Cualquier servicio cuyo binario esté en `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\` o un directorio con nombre aleatorio merece una mirada más cercana. `ImagePath` también puede ser `cmd.exe /c ...` o `powershell.exe -e ...`. Esos son casi siempre maliciosos. Los servicios legítimos no salen a shell.

**`AccountName`** usualmente es `LocalSystem`. Un servicio instalado bajo un usuario de dominio, o una cuenta de servicio específica que no coincida con el patrón de la organización, es inusual.

**`StartType`** de `auto start` significa que el servicio corre en cada arranque. `demand start` significa manual. La persistencia casi siempre quiere `auto start`. Una ejecución lateral one-shot puede usar `demand start` y limpiarse después. Eso hace que el 7045 sea el único artefacto que queda.

## El patrón de ejecución lateral

Cuando un atacante corre PsExec o cualquier herramienta que usa el SCM para ejecutar remotamente en otro host, obtienes un 7045 en el host *destino* con un `ImagePath` como `%SystemRoot%\PSEXESVC.exe` (por defecto) o un equivalente renombrado. El servicio aparece, corre y a menudo se borra en segundos. El 7045 es la huella superviviente mucho después de que el servicio mismo se haya ido.

Un 7045 con `ImagePath` terminando en `.exe` seguido segundos después por un [4624 LogonType **3**](/en/blog/understanding-event-id-4624) desde un host fuente específico es la firma de libro de PsExec. Las variantes como Impacket `psexec.py`, `smbexec.py`, `wmiexec.py` producen valores de `ImagePath` ligeramente diferentes pero el mismo patrón general. La variante Impacket renombrada usualmente es el delator: un nombre de servicio como `wfDsaQbA` (ocho letras aleatorias) no viene de un sysadmin.

## Lo que 7045 no te dice

7045 se dispara en *instalación*, no en cada arranque subsiguiente. Para ver el servicio realmente corriendo necesitas [7036](/en/blog/event-id-7036-service-state) ("el servicio entró en el estado running"). Para ver el proceso subyacente necesitas [Sysmon evento 1](/en/blog/sysmon-event-id-1-process-create) o [4688](/en/blog/event-id-4688-process-creation) con el path `Image` correspondiente.

Para servicios instalados *antes* de que comience el audit log (por ejemplo, durante la instalación del SO), no hay 7045. Existen en el [registro](https://www.registryparser.com) bajo `HKLM\SYSTEM\CurrentControlSet\Services\` y tienen que enumerarse ahí, no desde event logs. El hive [AmCache](https://www.amcacheparser.com) y la caché [prefetch](https://www.prefetchparser.com) a menudo corroboran ejecuciones que no produjeron un 4688.

## Flujo de triaje

1. Filtra el canal System por `EventID:7045`.
2. Ordena o pivota por `ImagePath`. Cualquier cosa fuera de las rutas de instalación estándar es sospechosa.
3. Para cada sospechoso, tira el 4624 correspondiente por timestamp y host origen. Encuentra la credencial que lo instaló.
4. Tira Sysmon 1 por `Image` coincidiendo con el `ImagePath` para ver ejecuciones reales.
5. Nota si una secuencia [7036](/en/blog/event-id-7036-service-state) / 7034 / 7035 muestra una corrida one-shot o un servicio persistente.

## Sigma: servicio instalado desde ruta no estándar

```yaml
title: Service Installed from Non-Standard Path
id: 9e1c2f3a-7d3c-4a5f-8a3b-1d2e3f4a5b6c
status: stable
description: A new service was registered whose ImagePath sits in a user-writable directory. Common for persistence and PsExec-style execution.
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

## KQL: huella de ejecución lateral PsExec

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

## Splunk: instalador de servicio anómalo

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## Mapeo ATT&CK

- T1543.003 Create or Modify System Process: Windows Service. Servicios de larga duración iniciados bajo binarios controlados por el atacante.
- T1569.002 System Services: Service Execution. Servicios de corta vida usados puramente como vehículo para ejecución remota (PsExec, SMBExec, lateral movement basado en SCM).
- T1078 Valid Accounts. Cuando el principal que instala es un admin de dominio cuyas credenciales fueron robadas.
- T1036.005 Masquerading: Match Legitimate Name or Location. Servicios con nombres de display imitando servicios reales de Microsoft pero binarios en otra parte.

## Falsos positivos que se ven exactamente como ataques

- Los instaladores de software (Chocolatey, bootstrappers MSI) frecuentemente instalan servicios desde un directorio de staging antes de mover el binario. El 7045 se dispara desde la ruta de staging aunque la instalación final sea limpia.
- Los agentes EDR y AV instalan servicios como parte de su setup. El `ImagePath` del vendor será estable y firmado. Baseline.
- Algunas actualizaciones de Microsoft instalan servicios de servicing temporales. Cortos, desde `LocalSystem`.
- Las cargas de contenedor o Hyper-V a veces registran servicios transitorios por VM.

La señal son instalaciones *one-off* a rutas escribibles por usuario por instaladores *no-admin o no-estándar*. Un servicio de instalador firmado en `C:\Program Files\` no es el ataque.

## Lecturas adicionales

- [Documentación Microsoft para 7045](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7045)
- [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)
- [JPCERT/CC: Detecting Lateral Movement through Tracking Event Logs](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

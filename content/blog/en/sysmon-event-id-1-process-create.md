---
title: "Sysmon Event ID 1 explained: process creation for DFIR triage"
description: "Sysmon's event 1 is the richest process-creation record Windows can produce. Here's what's in it and how to triage it fast."
date: "2026-05-17"
---

Sysmon is a free Microsoft tool that augments the Windows Event Log with telemetry the base OS doesn't capture in usable form. Its event ID 1 — `ProcessCreate` — is the most-cited Sysmon record in IR playbooks. If you only ever extract one Sysmon channel from a host, this is the one.

## Where it lives and what it captures

Sysmon writes to the channel `Microsoft-Windows-Sysmon/Operational` (on disk: `Microsoft-Windows-Sysmon%4Operational.evtx`). A ProcessCreate record contains:

```xml
<Data Name="UtcTime">2026-05-17 14:02:11.123</Data>
<Data Name="ProcessGuid">{...}</Data>
<Data Name="ProcessId">7842</Data>
<Data Name="Image">C:\Windows\System32\powershell.exe</Data>
<Data Name="CommandLine">powershell -enc SQBFAFgA...</Data>
<Data Name="CurrentDirectory">C:\Users\alice\</Data>
<Data Name="User">CORP\alice</Data>
<Data Name="LogonId">0x3e7</Data>
<Data Name="Hashes">SHA256=...</Data>
<Data Name="ParentProcessGuid">{...}</Data>
<Data Name="ParentImage">C:\Program Files\Microsoft Office\winword.exe</Data>
<Data Name="ParentCommandLine">"winword.exe" /n /dde</Data>
```

The fields that drive investigations: `CommandLine` (the full argv, not just the binary), `Image` + `Hashes` (the exact binary that ran, hash usable in VT/Hybrid Analysis), and the `Parent*` set (the calling process — critical for finding macro and LOLBin chains).

## Triage in three pivots

When you have a triage Sysmon file, three queries cover most cases:

1. **Suspicious parents**: filter for `ParentImage` ending in `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, or a browser, with `Image` being a shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). A document app spawning a shell is almost always malicious.
2. **Encoded PowerShell**: `Image` ending `powershell.exe` and `CommandLine` containing `-enc`, `-encodedcommand`, or `FromBase64String`. Decode the payload, check what it does — and cross-check the [PowerShell 4104 scriptblock](/en/blog/powershell-4104-scriptblock) record on the same host to see what actually executed.
3. **LOLBins from odd locations**: signed Microsoft binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) running from `C:\Users\`, `%TEMP%`, or `C:\ProgramData\`.

## Why the parent chain matters

A single ProcessCreate is a snapshot; the chain is the story. `ProcessGuid` and `ParentProcessGuid` are GUIDs Sysmon assigns to track lineage across process exits — they're more reliable than PIDs because PIDs are reused. Reconstruct the tree (each record's `ParentProcessGuid` is some other record's `ProcessGuid`) and the kill-chain becomes obvious: Outlook → Word → PowerShell → cmd → certutil → mshta.

## Sample Sigma rule — Office app spawning shell

```yaml
title: Office Application Spawning Shell or Scripting Host (Sysmon)
id: 7a4c1f2b-6e3d-4a5f-9c2a-1b3d4e5f6a7c
status: stable
description: A Microsoft Office or document-rendering process spawned cmd, powershell, wscript, cscript, mshta, rundll32 or regsvr32.
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: sysmon
  category: process_creation
detection:
  selection:
    EventID: 1
    ParentImage|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
      - '\acrord32.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Office add-ins running approved scripts
  - Document automation pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
  - attack.initial_access
  - attack.t1566.001
```

## Sample KQL — encoded PowerShell with parent context

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` is the Defender XDR equivalent of Sysmon 1's `ParentCommandLine` — which 4688 does not provide.

## Sample Splunk — LOLBins from user-writable paths

```spl
sourcetype=xmlwineventlog source="*Sysmon/Operational"
  EventCode=1
  ( Image="*\\certutil.exe" OR Image="*\\regsvr32.exe" OR Image="*\\mshta.exe"
    OR Image="*\\bitsadmin.exe" OR Image="*\\installutil.exe" OR Image="*\\msbuild.exe" )
  ( ParentImage="*\\Users\\*" OR CommandLine="*\\Users\\*"
    OR CommandLine="*%TEMP%*" OR CommandLine="*ProgramData*" )
| table _time Computer User ParentImage Image CommandLine Hashes
```

## ATT&CK mapping

- **T1059 — Command and Scripting Interpreter** and sub-techniques `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- **T1566.001 — Phishing: Spearphishing Attachment**: Office → shell chains.
- **T1218 — System Binary Proxy Execution** and sub-techniques `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- **T1036.003 — Masquerading: Rename System Utilities**: `OriginalFileName` ≠ `Image`'s filename.
- **T1055 — Process Injection**: Sysmon 1's `IntegrityLevel` and parent chain help spot anomalous parents for processes like `lsass.exe` or `services.exe`.

## False positives that look like attacks

- **Software-update agents** routinely spawn shells under SYSTEM (Chocolatey, WinGet, vendor MSI). Tag known auto-update hosts.
- **Vulnerability scanners** mimic offensive process trees during authenticated scans. Tag scanner IPs.
- **Citrix / RDS** multi-session hosts generate dense process-create traffic that overlaps with attacker patterns. Filter by source range.
- **Defender / EDR scans** run signed Microsoft binaries from unusual paths during on-demand scans.

## Coverage caveats

Sysmon only captures what its config tells it to. The default config logs nothing; the canonical references are SwiftOnSecurity's `sysmon-config` and Olaf Hartong's `sysmon-modular`. Without a real config in place, your event 1 records will be sparse, the `CommandLine` field may be redacted, and `Hashes` may be missing. Read the host's Sysmon config alongside its logs.

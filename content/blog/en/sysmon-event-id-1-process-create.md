---
title: "Sysmon Event ID 1 explained: process creation for DFIR triage"
description: "Sysmon's event 1 is the richest process-creation record Windows can produce. Here is what is in it and how to triage it fast."
date: "2026-05-17"
---

Sysmon is a free Microsoft tool that augments the [Windows Event Log](/en/blog/what-is-an-evtx-file) with telemetry the base OS does not capture in usable form. Its event ID 1, `ProcessCreate`, is the most-cited Sysmon record in IR playbooks. If you only ever extract one Sysmon channel from a host, this is the one.

I will say what I say in every Sysmon writeup: a deployment without a real config is mostly theatre. Read [sysmon-modular](https://github.com/olafhartong/sysmon-modular) or SwiftOnSecurity's `sysmon-config` before you decide what your event 1 records actually contain.

## Where it lives and what it captures

Sysmon writes to `Microsoft-Windows-Sysmon/Operational` (on disk: `Microsoft-Windows-Sysmon%4Operational.evtx`). A ProcessCreate record contains:

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

The fields that drive investigations:

- `CommandLine`. The full argv, not just the binary.
- `Image` and `Hashes`. The exact binary that ran, hash usable in VirusTotal or Hybrid Analysis.
- The `Parent*` set. The calling process. Critical for finding macro and LOLBin chains. `ParentCommandLine` in particular is what [4688](/en/blog/event-id-4688-process-creation) cannot give you.

## Triage in three pivots

Three queries cover most cases:

1. **Suspicious parents.** Filter for `ParentImage` ending `winword.exe`, `excel.exe`, `outlook.exe`, `mshta.exe`, or a browser, with `Image` being a shell (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`). A document app spawning a shell is almost always malicious.
2. **Encoded PowerShell.** `Image` ending `powershell.exe` and `CommandLine` containing `-enc`, `-encodedcommand`, or `FromBase64String`. Decode the payload, check what it does. Cross-check the [PowerShell 4104 scriptblock](/en/blog/powershell-4104-scriptblock) on the same host to see what actually executed.
3. **LOLBins from odd locations.** Signed Microsoft binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`) running from `C:\Users\`, `%TEMP%`, or `C:\ProgramData\`.

## Why the parent chain matters

A single ProcessCreate is a snapshot. The chain is the story. `ProcessGuid` and `ParentProcessGuid` are GUIDs Sysmon assigns to track lineage across process exits. They are more reliable than PIDs because PIDs are reused. Reconstruct the tree (each record's `ParentProcessGuid` is some other record's `ProcessGuid`) and the kill chain becomes obvious: Outlook to Word to PowerShell to cmd to certutil to mshta. Reading the tree in chronological order is usually how a writeup writes itself.

## Sigma: Office app spawning shell

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

## KQL: encoded PowerShell with parent context

```kusto
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe" or FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @"(?i)\b-e(?:nc|ncodedcommand)?\b\s"
   or ProcessCommandLine contains "FromBase64String"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

`InitiatingProcessCommandLine` is the Defender XDR equivalent of Sysmon 1's `ParentCommandLine`, which [4688](/en/blog/event-id-4688-process-creation) does not provide.

## Splunk: LOLBins from user-writable paths

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

- T1059 Command and Scripting Interpreter and sub-techniques `.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript.
- T1566.001 Phishing: Spearphishing Attachment. Office to shell chains.
- T1218 System Binary Proxy Execution and sub-techniques `.005` Mshta, `.010` Regsvr32, `.011` Rundll32, `.007` Msiexec.
- T1036.003 Masquerading: Rename System Utilities. `OriginalFileName` != `Image`'s filename.
- T1055 Process Injection. Sysmon 1's `IntegrityLevel` and parent chain help spot anomalous parents for processes like `lsass.exe` or `services.exe`.

## False positives that look like attacks

- Software-update agents routinely spawn shells under SYSTEM (Chocolatey, WinGet, vendor MSI). Tag known auto-update hosts.
- Vulnerability scanners mimic offensive process trees during authenticated scans. Tag scanner IPs.
- Citrix and RDS multi-session hosts generate dense process-create traffic that overlaps with attacker patterns. Filter by source range.
- Defender or EDR scans run signed Microsoft binaries from unusual paths during on-demand scans.

## Coverage caveats

Sysmon only captures what its config tells it to. The default config logs almost nothing. The canonical references are SwiftOnSecurity's `sysmon-config` and Olaf Hartong's `sysmon-modular`. Without a real config in place, your event 1 records will be sparse, `CommandLine` may be redacted by a `<CommandLine onmatch="exclude">` rule, and `Hashes` may be missing. Read the host's Sysmon config alongside its logs. The mismatch between what an analyst thinks Sysmon is logging and what it actually logs has cost me hours more than once.

When Sysmon is not installed at all, fall back to [4688](/en/blog/event-id-4688-process-creation) with command-line auditing, then [prefetch](https://www.prefetchparser.com), [AmCache](https://www.amcacheparser.com), and the [USN journal](https://www.usnparser.com) for execution evidence.

## Further reading

- [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)

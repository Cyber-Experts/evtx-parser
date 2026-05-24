---
title: "Event ID 7045 explained: service installation as a persistence signal"
description: "Service creation is one of the loudest persistence techniques. Event 7045 captures every install — read these three fields and you'll catch most of it."
date: "2026-05-17"
---

Event ID **7045** — "A service was installed in the system" — fires on the `System` channel whenever the Service Control Manager registers a new service. It's noisy on a stock build (driver installs, updates) but in steady-state corporate environments it's quiet enough that anomalies stand out. It's also one of MITRE ATT&CK's most-cited persistence techniques: T1543.003.

## What the record contains

```xml
<Data Name="ServiceName">UpdateSrv</Data>
<Data Name="ImagePath">C:\Windows\Temp\u.exe</Data>
<Data Name="ServiceType">user mode service</Data>
<Data Name="StartType">auto start</Data>
<Data Name="AccountName">LocalSystem</Data>
```

Five fields, three of which matter for IR.

## The three fields to read first

**`ImagePath`** is the single most useful field. Legitimate services live under `C:\Windows\System32\`, `C:\Program Files\`, or `C:\Program Files (x86)\`. Any service whose binary sits in `C:\Windows\Temp\`, `C:\Users\<user>\AppData\`, `C:\ProgramData\`, or a randomly-named directory deserves a closer look. `ImagePath` can also be a `cmd.exe /c …` or `powershell.exe -e …` line — those are almost always malicious; legitimate services don't shell out.

**`AccountName`** is usually `LocalSystem`. A service installed under a domain user or a specific service account that doesn't match the org's pattern is unusual.

**`StartType`** of `auto start` means the service runs at every boot. `demand start` means manual. Persistence almost always wants `auto start`; one-shot lateral execution may use `demand start` and clean up after itself — making the 7045 the only artifact left.

## The lateral-execution pattern

When an attacker runs `PsExec` or any tool that uses the SCM to remote-execute on another host, you get a 7045 on the *target* host with an `ImagePath` like `%SystemRoot%\PSEXESVC.exe` (default) or a renamed equivalent. The service appears, runs, and is often deleted within seconds. The 7045 is the surviving fingerprint long after the service itself is gone.

A 7045 with `ImagePath` ending in `.exe` followed seconds later by [4624 LogonType **3**](/en/blog/understanding-event-id-4624) from a specific source host is the textbook PsExec signature. Variants like SMBExec, WMIExec, and Impacket's `psexec.py` produce slightly different `ImagePath` values but the same overall pattern.

## What 7045 doesn't tell you

7045 fires on *installation*, not on each subsequent start. To see the service actually running you need 7036 ("service entered the running state"). To see the underlying process you need [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) or 4688 with the matching `Image` path.

For services installed *before* the audit log starts (e.g., during OS install), there's no 7045 — they exist in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\` and have to be enumerated there, not from event logs.

## Triage workflow

1. Filter the System channel for `EventID:7045`.
2. Sort or pivot by `ImagePath` — anything outside the standard install paths is suspect.
3. For each suspect, pull the matching 4624 by timestamp + source host — find the credential that installed it.
4. Pull Sysmon event 1 by `Image` matching the `ImagePath` to see actual executions.
5. Note whether a [**7036**](/en/blog/event-id-7036-service-state) / 7034 / 7035 sequence shows a one-shot run or a persistent service.

## Sample Sigma rule — service installed from non-standard path

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

## Sample KQL — PsExec lateral execution fingerprint

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

A 4624 LogonType-3 within 30 seconds of a 7045 on the same host is the textbook PsExec signature.

## Sample Splunk — anomalous service installer

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7045
| eval suspicious=if(match(ImagePath, "(?i)(\\\\Windows\\\\Temp\\\\|\\\\Users\\\\|\\\\ProgramData\\\\|cmd\\.exe|powershell|rundll32|mshta)"), 1, 0)
| where suspicious=1
| table _time host ServiceName ImagePath AccountName StartType
```

## ATT&CK mapping

- **T1543.003 — Create or Modify System Process: Windows Service**: the headline mapping. Long-running services started under attacker-controlled binaries.
- **T1569.002 — System Services: Service Execution**: short-lived services used purely as a vehicle for remote execution (PsExec, SMBExec, SCM-based lateral movement).
- **T1078 — Valid Accounts**: when the installing principal is a domain admin whose credentials were stolen.
- **T1036.005 — Masquerading: Match Legitimate Name or Location**: services with display names mimicking real Microsoft services but binaries elsewhere.

## False positives that look exactly like attacks

- **Software installers** (Chocolatey, MSI bootstrappers) frequently install services from a staging directory before moving the binary. The 7045 fires from the staging path even though the final install is clean.
- **EDR / AV agents** install services as part of their setup. The vendor's `ImagePath` will be stable and signed; baseline.
- **Some Microsoft updates** install temporary servicing services; these are short-lived and from `LocalSystem`.
- **Container / Hyper-V** workloads sometimes register transient services per-VM.

The signal is *one-off* installs to user-writable paths by *non-admin or non-standard* installers. A signed installer service in `C:\Program Files\` is not the attack.

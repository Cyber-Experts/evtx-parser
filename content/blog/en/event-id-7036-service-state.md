---
title: "Event ID 7036 explained: service state changes for DFIR triage"
description: "7036 fires every time a service starts or stops. Paired with 7045 it confirms whether persistence actually ran. On its own it reveals service abuse, defense evasion, and boot anomalies."
date: "2026-05-24"
---

Event ID **7036**, "The {service} service entered the {state} state", fires on the [`System` channel](/en/blog/what-is-an-evtx-file) every time the Service Control Manager sees a service transition. Each start, stop, pause, and resume produces one. By itself it is high-volume and easy to dismiss. Paired with [7045](/en/blog/service-creation-event-id-7045) it is the difference between "a backdoor was installed" and "a backdoor was installed and ran".

For incident response, this is the cheapest "did it execute" record the OS gives you.

## Where it lives

`System` channel on the host the service ran on. No DC involvement, no per-channel forwarding to worry about. It is right there in `System.evtx`. Provider: `Service Control Manager`.

## What the record contains

```xml
<UserData>
  <EventXML>
    <param1>Background Intelligent Transfer Service</param1>
    <param2>running</param2>
    <Binary>42004900540053000000</Binary>
  </EventXML>
</UserData>
```

That is it. Two parameters and a binary tag. Much smaller than most Security records, which is why analysts skip it.

- `param1`. The *display name* of the service (not the short name). `Background Intelligent Transfer Service` here is the user-facing name for `BITS`. To pivot to the service definition you usually need the short name. The SCM stamps that into `Binary` as a UTF-16 blob (`42 00 49 00 54 00 53 00` decodes to `BITS`).
- `param2`. The new state: `running`, `stopped`, `paused`, `resumed`, or pending intermediates (`start pending`, `stop pending`). `running` and `stopped` are what most rules key on.

There is no `AccountName`, no `ImagePath`, no `ProcessId`. 7036 tells you *what* changed state, not *who* triggered it. To get the why, pair with other records.

## 7036, 7045, 7035, 7034: which is which

Four service-related System-channel events get confused constantly:

| Event | When | What it gives you |
|---|---|---|
| **7045** | Service installed | Display name, short name, `ImagePath`, `AccountName`, `StartType`. The persistence point. |
| **7036** | Service start/stop | Display name only. The execution point. |
| **7035** | Service control sent | Who initiated start/stop (SID), what control was sent. Rarely on by default. |
| **7034** | Service crashed unexpectedly | Service terminated without a clean stop. |

The pattern matters: a 7045 followed seconds later by a 7036 `running` for the same display name is the textbook "installed and ran" sequence. A 7045 with *no* matching 7036 means the service was registered but never executed: either the attacker cleaned up, the installer aborted, or the start was deferred.

## The triage patterns

### Persistence verification: pair with 7045

```
[7045] "A service was installed: PSEXESVC, C:\Windows\PSEXESVC.exe, LocalSystem, demand start"
[7036] "The PSEXESVC service entered the running state"
[7036] "The PSEXESVC service entered the stopped state"
```

Three records, one PsExec lateral execution event. The 7036 pair tells you the service actually ran (not just got installed). For a *persistent* backdoor the second 7036 (stopped) may be missing or may appear hours later when the host reboots.

A 7045 with no 7036 `running` within minutes is its own anomaly. Investigate why the install did not fire. Common causes: staged for next reboot, set to manual start and the attacker had not triggered it yet, start failed (look for 7034 / 7000 errors).

### Defense-evasion: stopping security services

The most-abused pattern. An attacker stops `WinDefend`, `MsMpEng`, `Sense`, `SecurityHealthService`, `EventLog`, `WdNisSvc`, or an EDR product's service. Each generates a 7036 `stopped` for the corresponding display name. If audit-policy or Defender tampering is being attempted, this is one of the records that survives.

Names worth alerting on (display names; vary by Defender or EDR version):

- `Windows Defender Antivirus Service` -> `WinDefend`
- `Microsoft Defender Antivirus Network Inspection Service` -> `WdNisSvc`
- `Windows Defender Advanced Threat Protection Service` -> `Sense`
- `Security Center` -> `wscsvc`
- `Windows Event Log` -> `EventLog`
- Anything matching `*CrowdStrike*`, `*SentinelOne*`, `*Carbon*`, `*Cylance*`, `*Sophos*`, `*ESET*`, `*Symantec*`

A 7036 `stopped` for any of these, especially outside a scheduled maintenance window, should be a hard alert. Many attackers use `sc stop`, `net stop`, `Stop-Service`, or `taskkill /im`. All four produce a 7036.

### Service-name typosquatting

7036 fires for the display name even when the underlying service is malicious. Watch for display names that look legitimate but do not match any installed Microsoft service: `Windows Update Service` (real name is `Windows Update`), `Windows Defender Service` (real name is `Windows Defender Antivirus Service`), `Microsoft Telemetry` (no such service). Baseline display names from a known-good host and diff.

### Boot anomalies

After a reboot the SCM brings up auto-start services in a roughly stable order. A new auto-start service appearing in the boot 7036 sequence, especially one that was not there in the prior boot, is a new persistence point. Cross-reference with the matching 7045 on or before the previous shutdown.

## Sigma: security service stopped

```yaml
title: Security Service Stopped via 7036
id: 1d0b3a3a-94a4-44f7-9d29-3c0fbf2c9a91
status: stable
description: A security/defense service transitioned to the stopped state.
references:
  - https://attack.mitre.org/techniques/T1562/001/
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7036
    param2: 'stopped'
  defender:
    param1|contains:
      - 'Windows Defender'
      - 'Microsoft Defender'
      - 'Microsoft Monitoring'
      - 'Windows Event Log'
      - 'Security Center'
      - 'CrowdStrike'
      - 'SentinelOne'
      - 'Carbon Black'
      - 'Cylance'
      - 'Sophos'
      - 'ESET'
      - 'Symantec'
  condition: selection and defender
falsepositives:
  - Scheduled maintenance windows
  - Vendor uninstall / upgrade workflows
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001
```

## KQL: 7045 to 7036 sequence

The headline pivot. Persistence install followed by execution within 5 minutes on the same host:

```kusto
let installs =
    Event
    | where Source == "Service Control Manager" and EventID == 7045
    | extend XmlData = parse_xml(EventData)
    | project InstallTime=TimeGenerated, Host=Computer,
              ServiceName=tostring(XmlData.EventData.Data[0]["#text"]),
              ImagePath=tostring(XmlData.EventData.Data[1]["#text"]),
              AccountName=tostring(XmlData.EventData.Data[3]["#text"]);
Event
| where Source == "Service Control Manager" and EventID == 7036
| extend XmlData = parse_xml(EventData)
| where tostring(XmlData.EventXML.param2) == "running"
| project RunTime=TimeGenerated, Host=Computer,
          DisplayName=tostring(XmlData.EventXML.param1)
| join kind=inner (installs) on Host
| where RunTime between (InstallTime .. InstallTime + 5m)
| project InstallTime, RunTime, Host, ServiceName, DisplayName, ImagePath, AccountName
| order by InstallTime desc
```

`DisplayName` from 7036 will not always literally equal `ServiceName` from 7045 (one is display, one is short). Match heuristically or precompute a map for the small set of services that matter.

## Splunk

```spl
index=wineventlog SourceName="Service Control Manager" EventCode=7036
  ( param1="*Defender*" OR param1="*Sense*" OR param1="*EventLog*" OR param1="*Security Center*" )
  param2="stopped"
| table _time host param1 param2
```

## ATT&CK mapping

- T1562.001 Impair Defenses: Disable or Modify Tools. 7036 `stopped` for security services.
- T1543.003 Create or Modify System Process: Windows Service. 7036 `running` paired with 7045 for the same service.
- T1569.002 System Services: Service Execution. 7036 `running` for an `ImagePath` pointing at a non-standard binary, often part of lateral movement (PsExec, SCM-based remote execution, Impacket `psexec.py`).
- T1489 Service Stop. Targeted at availability (ransomware stopping SQL Server before encrypting databases).

## False positives that look exactly like attacks

- Windows Update restarts a dozen services in a predictable sequence. Recurring and quick.
- Defender signature updates sometimes restart `WinDefend` itself. A `stopped` quickly followed by `running` from `MsSecFlt.exe` is the normal pattern. The malicious one is *no* `running` after the `stopped`.
- EDR upgrades stop and restart the EDR service. Tag the vendor's upgrade windows.
- System sleep and hibernate generate batches of `stopped` at sleep and `running` at wake. Do not alert on these in isolation.
- Container and Hyper-V workloads bring services up and down constantly.

## What 7036 does not tell you

- No `AccountName`. Pull that from the matching 7045 or from the SCM database.
- No PID. You cannot map a 7036 directly to a [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) record without correlating by `ImagePath` and timestamp. The [prefetch](https://www.prefetchparser.com) cache is the secondary corroboration when 4688 was off.
- No initiator. You do not see who called Stop-Service. For that you need 7035 (often disabled by default), [4688](/en/blog/event-id-4688-process-creation) for the calling `net stop` / `sc stop` / `taskkill`, or [4104](/en/blog/powershell-4104-scriptblock) for `Stop-Service`.
- Service-short-name mapping. Display name is in `param1`. Short name is in the binary blob and must be decoded. Most parsers do this automatically. If you query raw `EventData` you have to handle it yourself.

## Where 7036 fits in a timeline

Lateral execution plus defense evasion:

1. [4624](/en/blog/understanding-event-id-4624). LogonType 3 from an attacker-controlled host, AuthenticationPackage Kerberos.
2. [4688](/en/blog/event-id-4688-process-creation). `services.exe` spawning a child for SCM operations (or PsExec's `psexesvc.exe`).
3. [7045](/en/blog/service-creation-event-id-7045). Service installed, `ImagePath` outside standard install paths.
4. **7036 `running`**. The install actually fired. Execution confirmation.
5. **7036 `stopped`** for `WinDefend` or EDR. Defense evasion before the payload runs.
6. [4688](/en/blog/event-id-4688-process-creation). Payload process under the service account.
7. **7036 `stopped`** for the installer service. Cleanup.

7036 appears in steps 4, 5 and 7. Three different stages of the same intrusion. On its own it is hard to use. In context it ties the persistence record (7045) to the actual execution and to the surrounding defense-evasion actions.

## Further reading

- [Microsoft documentation: 7036](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/event-id-7036)
- [MITRE ATT&CK T1562.001](https://attack.mitre.org/techniques/T1562/001/)

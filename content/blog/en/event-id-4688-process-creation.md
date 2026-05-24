---
title: "Event ID 4688 explained: Windows process creation auditing for DFIR"
description: "4688 is the base-OS process create record — provided command-line auditing is on. Here's what's in it, how it differs from Sysmon 1, and the triage patterns that earn their keep."
date: "2026-05-24"
---

Event ID **4688** — "A new process has been created" — fires on the `Security` channel every time a process is launched. It is the closest the base OS gets to the telemetry [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) provides — and on hosts where Sysmon isn't deployed, it's the only `CommandLine` source you get. On a properly configured estate, every process create is one of these records. Read it well and you can answer "what ran" without ever opening an EDR.

## Turning it on (because the default is half-blind)

By default, 4688 is enabled but `CommandLine` is **not** captured. Without `CommandLine` the record tells you a binary path, a PID, a parent PID — and nothing about the arguments. For triage that's almost useless: `powershell.exe` is fine; `powershell.exe -enc SQBFAFgA…` is not.

The fix is a Group Policy setting:

*Computer Configuration → Administrative Templates → System → Audit Process Creation → Include command line in process creation events*

Or the registry equivalent: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled = 1`. Once set, every 4688 carries the full `CommandLine` field. The cost is log volume; the benefit is the entire investigation surface that exists below the binary name. Turn it on.

You also need the underlying audit policy to be on: `auditpol /set /subcategory:"Process Creation" /success:enable`. Many hosts have policy on but command-line off — verify both.

## What the record contains

```xml
<Data Name="SubjectUserSid">S-1-5-21-1234-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f2a4</Data>
<Data Name="NewProcessId">0x1d34</Data>
<Data Name="NewProcessName">C:\Windows\System32\cmd.exe</Data>
<Data Name="TokenElevationType">%%1937</Data>
<Data Name="ProcessId">0x0a1c</Data>
<Data Name="CommandLine">cmd.exe /c whoami /priv</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-12288</Data>
```

Fields that drive every investigation:

- **`CommandLine`** — full argv (when the GPO is on).
- **`NewProcessName`** — the binary path. Combined with `CommandLine` this is the full execution.
- **`ParentProcessName`** — the calling process. Office → cmd, browser → powershell, services → unsigned.exe are the textbook chains.
- **`SubjectUserName` / `SubjectLogonId`** — who launched it, under which session. `SubjectLogonId` pivots back to the [4624](/en/blog/understanding-event-id-4624) that created the session and to other records in the same session.
- **`TokenElevationType`** — `%%1936` Default (no elevation), `%%1937` Full (UAC consent granted), `%%1938` Limited (filtered). A `1937` in a non-admin session is a privilege transition worth a closer look.
- **`MandatoryLabel`** — integrity level SID. `S-1-16-12288` is High (elevated), `8192` is Medium, `16384` System.

## 4688 vs. Sysmon 1

They overlap; they aren't identical.

| Field | 4688 | Sysmon 1 |
|---|---|---|
| CommandLine | Yes (if GPO on) | Yes |
| Image / NewProcessName | Yes | Yes |
| Parent image | Yes (path) | Yes (path + CommandLine) |
| ParentCommandLine | No | Yes |
| ImageHash (SHA/MD5/IMPHASH) | No | Yes |
| ProcessGuid (cross-host stable) | No (PIDs only, reused) | Yes |
| User SID + name | Yes | Yes |
| Logon ID | Yes | Yes |
| CurrentDirectory | No | Yes |
| Integrity level | Yes | Yes |
| Available without install | Yes | Requires Sysmon |

When both are present, [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) is the richer record — `ParentCommandLine`, image hashes, ProcessGuid for stable parent-child chains. When only 4688 is present, you build chains with PIDs (which Windows reuses), so a long timeline can include false matches; always cross-check parent-child links against timestamps.

## The triage patterns

In a corpus of 4688 records, these patterns earn their keep:

1. **Office → shell**: `ParentProcessName` ending `winword.exe`, `excel.exe`, `outlook.exe`, `powerpnt.exe`, or `mshta.exe`, with `NewProcessName` being `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, or `regsvr32.exe`. Document apps spawning shells is the classic macro / phishing chain.
2. **Encoded PowerShell**: `NewProcessName` ending `powershell.exe` and `CommandLine` matching `-enc`, `-encodedcommand`, `-e ` (single-letter), `frombase64string`, `iex `, or `invoke-expression`. Decode the payload; cross-check the [4104 scriptblock record](/en/blog/powershell-4104-scriptblock) for the same session.
3. **LOLBins from user-writable paths**: signed Microsoft binaries (`certutil`, `regsvr32`, `mshta`, `installutil`, `bitsadmin`, `msbuild`, `csc`) launching from `C:\Users\`, `%TEMP%`, or `C:\ProgramData\`. Legitimate use of these is rare in those locations.
4. **Service host orphans**: `svchost.exe` with `ParentProcessName` ≠ `services.exe` (or `wininit.exe` for very early boot). Real `svchost` is always spawned by `services.exe`; impostors stand out.
5. **Renamed binaries**: `NewProcessName` ending in something neutral (`update.exe`, `svc.exe`, `data.exe`) under non-standard paths. Pair with Sysmon 1's `OriginalFileName` field when available — that's the one that catches renamed PsExec, Mimikatz, etc.

## Sample Sigma rule (office → shell)

```yaml
title: Office Application Spawning Shell
id: 2c8d2f4a-3c93-4b8c-bd2a-7f6b95a3b1d2
status: stable
description: An Office application launched a shell or scripting host via 4688.
references:
  - https://attack.mitre.org/techniques/T1059/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4688
    ParentProcessName|endswith:
      - '\winword.exe'
      - '\excel.exe'
      - '\powerpnt.exe'
      - '\outlook.exe'
      - '\mshta.exe'
    NewProcessName|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  condition: selection
falsepositives:
  - Legitimate macros in Office add-ins running scripts
  - Document conversion pipelines
level: high
tags:
  - attack.execution
  - attack.t1059
```

## Sample KQL / Splunk

KQL (Defender XDR / Sentinel via `SecurityEvent`):

```kusto
SecurityEvent
| where EventID == 4688
| where ParentProcessName endswith @"\winword.exe"
     or ParentProcessName endswith @"\excel.exe"
     or ParentProcessName endswith @"\outlook.exe"
| where NewProcessName endswith @"\cmd.exe"
     or NewProcessName endswith @"\powershell.exe"
     or NewProcessName endswith @"\pwsh.exe"
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| order by TimeGenerated asc
```

Splunk:

```spl
index=wineventlog EventCode=4688
   ( ParentProcessName="*\\winword.exe" OR ParentProcessName="*\\excel.exe" OR ParentProcessName="*\\outlook.exe" )
   ( NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe" OR NewProcessName="*\\pwsh.exe" )
| table _time host SubjectUserName ParentProcessName NewProcessName CommandLine
```

## ATT&CK mapping

The bulk of 4688 detection coverage falls under **T1059 — Command and Scripting Interpreter** and its sub-techniques (`.001` PowerShell, `.003` Windows Command Shell, `.005` Visual Basic, `.007` JavaScript). LOLBin patterns map to **T1218 — System Binary Proxy Execution** (`.005` Mshta, `.010` Regsvr32, `.011` Rundll32). Office → shell chains correspond to **T1566.001 — Phishing: Spearphishing Attachment** combined with T1059. Renamed-binary detections fall under **T1036.003 — Masquerading: Rename System Utilities**.

## False positives (read this before alerting)

- **Software-update agents** legitimately spawn shells: Chocolatey, WinGet, vendor MSI wrappers. Whitelist by `SubjectUserSid` (LocalSystem) plus stable `ParentProcessName` patterns rather than user accounts.
- **Vulnerability scanners and EDR products** generate process trees that look exactly like an attacker doing recon: net.exe, whoami.exe, systeminfo.exe. Tag scanner IPs / hosts and exclude.
- **Citrix / RDS multi-session boxes** see legitimate `runas /netonly` chains for cross-domain access. Investigate the user, not the pattern.
- **Logon scripts** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) fire at every logon and will appear as a recurring chain. Identify and baseline before alerting.

## What 4688 doesn't tell you

No file hash. No `ParentCommandLine`. No `ImageLoaded` (DLL injection isn't a process create). No network behaviour. For those you need [Sysmon event 1](/en/blog/sysmon-event-id-1-process-create) (the richer 4688), Sysmon 7 (image load), Sysmon 3/22 (network/DNS), and where present, an EDR's behavioural data. 4688 is the floor of process visibility — the minimum every Windows host should have. It is not a substitute for proper EDR + Sysmon on hosts that matter.

## Where 4688 fits in a timeline

For a typical post-exploitation chain on a Sysmon-less host, your timeline will read:

1. [**4624**](/en/blog/understanding-event-id-4624) — initial logon, LogonType 3 from an external IP.
2. **4624** — second logon, LogonType 9 (`runas /netonly`) under the same `SubjectLogonId` — credential pivot.
3. **4688** — `powershell.exe -enc ...` under that session.
4. [**4104**](/en/blog/powershell-4104-scriptblock) — decoded script body, fetching a second-stage payload.
5. **4688** — second-stage binary running from `%TEMP%`.
6. [**7045**](/en/blog/service-creation-event-id-7045) — service installed for persistence.

Six records tell the whole story. The PIDs in (3) and (5) connect via 4688's `ProcessId`/`NewProcessId` — but verify by timestamp because Windows recycles PIDs. With Sysmon present, the `ProcessGuid` chain replaces that fragile match.

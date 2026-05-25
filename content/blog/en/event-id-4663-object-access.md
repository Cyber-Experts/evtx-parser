---
title: "Event ID 4663 explained: file & registry access auditing with SACLs"
description: "4663 is the per-access object-audit record. Configure SACLs on the right files and keys and you get a per-byte log of who touched what — useful for ransomware, exfil, and credential-store theft."
date: "2026-05-24"
---

Event ID **4663** — "An attempt was made to access an object" — fires on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time an audited file, registry key, or kernel object is accessed in a way that matches its System Access Control List (SACL). Unlike most Security records, 4663 produces nothing on its own — you have to *configure* the SACL on the object you care about before any 4663 records exist. That makes it cheap by default and devastatingly effective once tuned.

If you only audit one thing with 4663, audit access to credential stores and high-value data shares. The signal-to-noise is among the best in the entire audit catalog.

## Where it fires

Always on the host that owns the object — the file server for a file SACL, the workstation for a local registry SACL, the DC for an AD object SACL. There is no central record; if you want estate-wide visibility on a sensitive share, you need to forward `Security` from the file server hosting it.

## What the record contains

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-1107</Data>
<Data Name="SubjectUserName">alice</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x2a4c8</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">File</Data>
<Data Name="ObjectName">C:\Windows\System32\config\SAM</Data>
<Data Name="HandleId">0x4d0</Data>
<Data Name="AccessList">%%4416 %%4423</Data>
<Data Name="AccessMask">0x80</Data>
<Data Name="ProcessId">0x1d34</Data>
<Data Name="ProcessName">C:\Windows\System32\reg.exe</Data>
<Data Name="ResourceAttributes">-</Data>
```

The fields:

- **`ObjectType`** — `File`, `Key` (registry), `Process`, `Token`, `Directory`, `Section`, or any object class that supports SACLs.
- **`ObjectName`** — the full path. For files it's a Windows path; for registry keys, the full path under `\REGISTRY\MACHINE\…` (note: not the `HKLM\…` notation you'd type into regedit).
- **`AccessList`** — what was attempted, as a list of decoded access-right names (one per `%%NNNN` token). The common decoded values:
  - `%%4416` = `ReadData (or ListDirectory)`
  - `%%4417` = `WriteData (or AddFile)`
  - `%%4418` = `AppendData (or AddSubdirectory)`
  - `%%4419` = `ReadEA` / `%%4420` = `WriteEA`
  - `%%4423` = `ReadAttributes` / `%%4424` = `WriteAttributes`
  - `%%4425` = `DELETE`
- **`AccessMask`** — the raw bitmask of `STANDARD_RIGHTS_*` and object-specific rights actually requested.
- **`ProcessName`** + **`ProcessId`** — the process that opened the handle. The pivot to [4688](/en/blog/event-id-4688-process-creation) / [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) for the full process context.
- **`SubjectLogonId`** — pivot to [4624](/en/blog/understanding-event-id-4624) for the originating session, the source IP if network logon, and the user.

## Configuring 4663 — the part that's actually work

There are three layers of configuration; missing any one of them means no records.

1. **Audit policy**: enable *Object Access → Audit File System* and/or *Audit Registry* for success and/or failure. Either via Group Policy or `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL on the object**: right-click → Properties → Security → Advanced → Auditing tab (Windows GUI), or via `Set-Acl` / `icacls /audit`. You specify *which principal* (often `Everyone` or `Authenticated Users`), *which rights*, and *whether to audit success, failure, or both*.
3. **For registry**: same flow, accessed via `regedit` → key → Permissions → Advanced → Auditing.

Without (1) the records never write. Without (2) Windows has no idea you wanted to audit anything. Without (3) you're only auditing files.

The SACLs to set on every server:

- **`C:\Windows\System32\config\SAM`**, **`SECURITY`**, **`SYSTEM`** — local credential stores. Audit `Everyone : ReadData : Success`. Anything reading these other than `LocalSystem` is a credential-dumping attempt.
- **`%TEMP%\lsass.dmp`** and any `*.dmp` in `C:\Windows\Temp` — process minidumps. Audit `Everyone : WriteData : Success`. A process writing a `.dmp` here is either a crash dump (Windows) or a Mimikatz operator (everyone else).
- **`C:\ProgramData\Microsoft\Crypto\RSA`** and **`C:\Users\*\AppData\Roaming\Microsoft\Protect`** — DPAPI master-key directories. Audit `ReadData : Success`. Anyone reading these from outside the user's own session is stealing protected secrets.
- **`HKLM\SECURITY`** and **`HKLM\SAM`** — registry equivalents. Audit `ReadData : Success`.
- **Sensitive file shares** — finance, legal, payroll. Audit `WriteData + DELETE : Success` to catch ransomware encryption sweeps and bulk deletions.

## The triage patterns

### 1. SAM / SYSTEM hive read

Any 4663 with `ObjectName` ending in `\config\SAM`, `\config\SECURITY`, or `\config\SYSTEM`, where `ProcessName` is not `services.exe` / `lsass.exe` / `wininit.exe` and `SubjectUserSid` is not `S-1-5-18`. This is `reg save HKLM\SAM`, `esentutl /y`, `vssadmin create shadow + copy`, or any credential-dumping tool with file-level hive access.

### 2. LSASS dump file written

A 4663 `WriteData` for a `.dmp` file in `C:\Windows\Temp\`, `C:\ProgramData\`, or `%TEMP%`, with `ProcessName` of `rundll32.exe`, `procdump*.exe`, `comsvcs.dll`-related callers, or a renamed binary. This is the LSASS-minidump pattern. Cross-reference with [4688](/en/blog/event-id-4688-process-creation) for the `CommandLine` — `comsvcs.dll MiniDump` is the most common encoding.

### 3. Ransomware encryption sweep

Many 4663s with `AccessMask` including `WriteData + DELETE` against files in a sensitive share within seconds, all from the same `SubjectLogonId` and `ProcessName`. A real backup process touches files in a measurable, throttled pattern; ransomware sweeps a directory tree as fast as the disk allows.

### 4. DPAPI master-key theft

4663 `ReadData` on files under `\AppData\Roaming\Microsoft\Protect\<sid>\` by any process other than the user's own session. The classic pattern is `SubjectUserSid` being a *different* SID from the one in the path.

### 5. Group Policy preference password file read

4663 `ReadData` on files matching `\SYSVOL\<domain>\Policies\*\Groups.xml` (or `Services.xml`, `Drives.xml`). This is the `Get-GPPPassword` attack — old, but the SYSVOL files often still exist on legacy domains.

## Sample Sigma rule — SAM hive read

```yaml
title: SAM Hive Read from Disk (Credential Dumping)
id: 5e1f9a3a-49a3-4f31-9c2e-8f5b1c2d3a4f
status: stable
description: A non-system process opened the SAM/SECURITY/SYSTEM registry hive file with read access.
references:
  - https://attack.mitre.org/techniques/T1003/002/
  - https://attack.mitre.org/techniques/T1003/004/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: 'File'
    ObjectName|endswith:
      - '\config\SAM'
      - '\config\SECURITY'
      - '\config\SYSTEM'
    AccessList|contains: '%%4416'
  filter_system:
    SubjectUserSid: 'S-1-5-18'
    ProcessName|endswith:
      - '\services.exe'
      - '\lsass.exe'
      - '\wininit.exe'
      - '\smss.exe'
  condition: selection and not filter_system
falsepositives:
  - Volume Shadow Copy backup processes (track by ProcessName)
  - Legitimate forensic agents (Velociraptor, GRR)
level: high
tags:
  - attack.credential_access
  - attack.t1003.002
```

## Sample KQL — ransomware encryption sweep

```kusto
SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where AccessMask in ("0x10000", "0x40000", "0x100", "0x2")  // DELETE, WriteData
| summarize Files=dcount(ObjectName), Sample=any(ObjectName)
    by SubjectLogonId, ProcessName, bin(TimeGenerated, 1m)
| where Files >= 100
| order by TimeGenerated desc
```

100 distinct files written-or-deleted per minute under one logon session is a sweep, full stop.

## Sample Splunk — DPAPI master-key access

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK mapping

- **T1003.002 — OS Credential Dumping: Security Account Manager**: SAM hive reads.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: SECURITY hive reads.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: `.dmp` writes (combined with process context).
- **T1555.004 — Credentials from Password Stores: Windows Credential Manager**: access to `\AppData\Local\Microsoft\Credentials\`.
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**: SYSVOL `Groups.xml` reads.
- **T1486 — Data Encrypted for Impact**: bulk WriteData + DELETE patterns (ransomware).
- **T1565.001 — Stored Data Manipulation**: arbitrary file writes to monitored data shares.

## Volume management — the SACL trap

Naively setting `Everyone : All access : Success+Failure` on a busy directory will produce hundreds of thousands of 4663 records per minute and bury your collection. SACLs are precision instruments. Audit:

- **Only the access types you care about** (`ReadData` for credential stores; `WriteData + DELETE` for data shares; rarely both).
- **Only success** — failures are rarer and rarely interesting.
- **Specific files**, not whole drives. The SAM file, not all of `C:\Windows\System32\config\`. The HR share, not all of `D:\`.
- **Specific principals** when you can — for SAM-class objects `Everyone` is fine because legit access is by `LocalSystem` anyway; for shared data, audit only the principals actually touching the data.

A well-tuned SACL on five high-value objects produces 50-200 records a day per host — entirely tractable.

## False positives that look exactly like attacks

- **Volume Shadow Copy** (VSS) backups generate dense 4663 traffic during a backup window. Tag the backup orchestrator's `ProcessName`.
- **Antivirus on-access scans** open every file in a target directory; AV product service accounts will dominate any naive 4663 rule. Whitelist by SID.
- **Indexing services** (Windows Search, Spotlight-style) hit metadata via `ReadAttributes` — usually filter-able by `AccessList`.
- **Backup-staged restores** look like ransomware writes (many files, one process, in a directory) but the process is your backup agent.
- **Defender real-time scanning** reads everything; if you audit too broadly, it's the dominant noise source.

## What 4663 doesn't tell you

- **Content of the access**: you see that a file was read/written, not what was read/written. For the latter you need an EDR or FIM (File Integrity Monitoring) product.
- **Why the access happened**: just the syscall outcome. To correlate to user intent, pair with [4688](/en/blog/event-id-4688-process-creation) / [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) for the calling process's full context.
- **Closed handles**: 4663 fires on handle *open*. Close events are 4658, rarely useful for attack detection.
- **Network paths transparently**: SMB access to a share fires 4663 on the *server*; the client sees nothing. You need server-side collection.
- **Failed access by default**: many shops only audit `Success`; configure `Failure` only if you genuinely care about thwarted access attempts.

## Where 4663 fits in a timeline

Classic LSASS credential dump chain:

1. [**4624**](/en/blog/understanding-event-id-4624) — admin logon (LogonType 3 or 10).
2. [**4672**](/en/blog/event-id-4672-special-privileges) — SeDebugPrivilege granted with the session.
3. [**4688**](/en/blog/event-id-4688-process-creation) — `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663** — `WriteData` to `C:\Windows\Temp\lsass.dmp` by `rundll32.exe`. **Forensic gold — proof of exfil staging.**
5. [**4688**](/en/blog/event-id-4688-process-creation) — file move / archive (the operator extracting the dump).
6. [**1102**](/en/blog/event-id-1102-cleared-log) — Security log cleared (some operators do this; many forget).

The 4663 in step 4 is the cheapest, most specific signal in the chain — it directly identifies the credential-theft artifact by name, on disk, with the calling process attached. SAM-hive reads, DPAPI master-key access, and SYSVOL Groups.xml reads work the same way.

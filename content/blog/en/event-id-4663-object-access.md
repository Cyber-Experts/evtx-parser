---
title: "Event ID 4663: An attempt was made to access an object"
description: "Event ID 4663 logs file, folder and registry access audited by a SACL: who touched what, with which access mask. Setup, key fields and hunts for ransomware and data theft."
date: "2026-05-24"
---

Event ID **4663**, "An attempt was made to access an object", fires on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time an audited file, registry key, or kernel object is touched in a way that matches its System Access Control List. Unlike most Security records, 4663 produces nothing by default. You have to *configure* the SACL on the object first. That is why most environments do not have it. It is also why the ones that do have an almost unfair detection advantage on a small set of techniques.

If you instrument 4663 on exactly five things and ignore the rest, you will catch credential-dump staging, ransomware sweeps, and DPAPI theft cheaper than any EDR can.

## Where it fires

On the host that owns the object. File SACLs fire on the file server. Local registry SACLs fire on the workstation. AD object SACLs fire on the DC. There is no central record. To get estate-wide visibility on a sensitive share, you need to forward Security from the file server hosting it. This catches people out constantly.

## The record fields

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

The ones that matter:

- `ObjectType`. `File`, `Key` (registry), `Process`, `Token`, `Directory`, `Section`. Any object class that supports SACLs.
- `ObjectName`. Full path. For files, a Windows path. For registry keys, the full path under `\REGISTRY\MACHINE\...` (not the `HKLM\...` you would type into regedit).
- `AccessList`. What was attempted, as decoded access-right tokens. The common ones:
  - `%%4416` = ReadData / ListDirectory
  - `%%4417` = WriteData / AddFile
  - `%%4418` = AppendData / AddSubdirectory
  - `%%4419` = ReadEA, `%%4420` = WriteEA
  - `%%4423` = ReadAttributes, `%%4424` = WriteAttributes
  - `%%4425` = DELETE
- `AccessMask`. Raw bitmask of `STANDARD_RIGHTS_*` and object-specific rights actually requested.
- `ProcessName` and `ProcessId`. The process that opened the handle. Pivot to [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) for the full process context.
- `SubjectLogonId`. Pivot to [4624](/en/blog/understanding-event-id-4624) for the originating session, the source IP if network logon, and the user.

## Turning 4663 on is three steps and people skip one

1. **Audit policy**. Enable *Object Access* sub-policies for File System and/or Registry, success and/or failure. Group Policy or `auditpol /set /subcategory:"File System" /success:enable /failure:enable`.
2. **SACL on the object**. Properties, Security tab, Advanced, Auditing tab in the GUI. Or `Set-Acl`, `icacls /audit`. You specify which principal, which rights, and whether to audit success, failure, or both.
3. **For registry**, same flow via regedit's key Permissions, Advanced, Auditing.

Without (1) the records never write. Without (2) Windows has no idea you wanted to audit anything. Without (3) you are only auditing files. People most often skip (2) because step (1) feels like it should be enough. It is not.

The SACLs that earn their keep on every server:

- `C:\Windows\System32\config\SAM`, `SECURITY`, `SYSTEM`. Audit `Everyone : ReadData : Success`. Anything reading these other than `LocalSystem` is credential dumping.
- `*.dmp` files in `C:\Windows\Temp` and `%TEMP%`. Audit `Everyone : WriteData : Success`. A process writing a `.dmp` here is either Windows after a crash, or a Mimikatz operator.
- `C:\ProgramData\Microsoft\Crypto\RSA` and `C:\Users\*\AppData\Roaming\Microsoft\Protect`. DPAPI master-key directories. Audit `ReadData : Success`. Anything reading these outside the user's own session is stealing secrets.
- `HKLM\SECURITY` and `HKLM\SAM`. Registry equivalents. Same audit.
- Sensitive file shares: finance, legal, payroll. Audit `WriteData + DELETE : Success` to catch ransomware sweeps and bulk deletions.

## The patterns you will actually catch

### SAM or SYSTEM hive read

Any 4663 with `ObjectName` ending in `\config\SAM`, `\config\SECURITY`, or `\config\SYSTEM`, where `ProcessName` is not `services.exe`, `lsass.exe`, or `wininit.exe`, and `SubjectUserSid` is not `S-1-5-18`. This is `reg save HKLM\SAM`, `esentutl /y` against a shadow copy, or any credential-dumping tool with file-level hive access. Cross-check the [registry](https://www.registryparser.com) for any backup hive files left behind.

### LSASS minidump written

A 4663 `WriteData` for a `.dmp` file in `C:\Windows\Temp\`, `C:\ProgramData\`, or `%TEMP%`, with `ProcessName` of `rundll32.exe`, `procdump*.exe`, or anything calling `comsvcs.dll`. The textbook is `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> lsass.dmp full`. Cross-reference [4688](/en/blog/event-id-4688-process-creation) for the `CommandLine`. The 4663 catches this even when EDR was asleep.

### Ransomware encryption sweep

Many 4663s with `AccessMask` including `WriteData + DELETE` against files in a sensitive share within seconds, all from the same `SubjectLogonId` and `ProcessName`. A real backup process touches files in a throttled, measurable pattern. Ransomware sweeps a directory tree as fast as the disk allows. The shape gives it away.

### DPAPI master-key theft

4663 `ReadData` on files under `\AppData\Roaming\Microsoft\Protect\<sid>\` by any process other than the user's own session. The dead giveaway is `SubjectUserSid` being a *different* SID from the one embedded in the path.

### Group Policy Preferences password file read

4663 `ReadData` on files matching `\SYSVOL\<domain>\Policies\*\Groups.xml`, or `Services.xml`, `Drives.xml`, `ScheduledTasks.xml`. This is `Get-GPPPassword`. The technique is old. The SYSVOL files often still exist on legacy domains, and you would be surprised how often somebody picks the obfuscated AES key off MSDN and walks away with a domain credential.

## Sigma: SAM hive read

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

## KQL: ransomware encryption sweep

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

100 distinct files written-or-deleted per minute under one logon session is a sweep. Full stop.

## Splunk: DPAPI master-key access

```spl
index=wineventlog EventCode=4663 ObjectName="*\\AppData\\Roaming\\Microsoft\\Protect\\*"
| rex field=ObjectName "Protect\\\\(?<owner_sid>S-[\\d\\-]+)\\\\"
| where SubjectUserSid != owner_sid AND SubjectUserSid != "S-1-5-18"
| table _time SubjectUserName ProcessName ObjectName
```

## ATT&CK mapping

- T1003.002 OS Credential Dumping: Security Account Manager. SAM hive reads.
- T1003.004 LSA Secrets. SECURITY hive reads.
- T1003.001 LSASS Memory. `.dmp` writes (combined with process context).
- T1555.004 Credentials from Password Stores: Windows Credential Manager. Access to `\AppData\Local\Microsoft\Credentials\`.
- T1552.006 Unsecured Credentials: Group Policy Preferences. SYSVOL `Groups.xml` reads.
- T1486 Data Encrypted for Impact. Bulk `WriteData + DELETE` patterns.
- T1565.001 Stored Data Manipulation. Arbitrary writes to monitored data shares.

## The SACL volume trap

Setting `Everyone : All access : Success+Failure` on a busy directory produces hundreds of thousands of 4663s per minute and buries the collection. SACLs are precision instruments. Audit:

- Only the access types you care about. ReadData for credential stores. WriteData + DELETE for data shares. Rarely both at once.
- Only success. Failures are rarer and rarely interesting in this corpus.
- Specific files, not whole drives. The SAM file, not all of `C:\Windows\System32\config\`. The HR share, not all of `D:\`.
- Specific principals when you can. For SAM-class objects, `Everyone` is fine because legit access is by `LocalSystem` anyway. For shared data, audit only the principals actually touching the data.

A well-tuned SACL on five high-value objects produces 50 to 200 records a day per host. Entirely tractable.

## False positives that look identical to attacks

- Volume Shadow Copy backups generate dense 4663 traffic during a backup window. Tag the backup orchestrator's `ProcessName`.
- Antivirus on-access scans open every file in a target directory. AV product service accounts will dominate any naive 4663 rule. Whitelist by SID.
- Indexing services (Windows Search) hit metadata via `ReadAttributes`. Usually filter-able by `AccessList`.
- Backup-staged restores look like ransomware writes (many files, one process, in a directory). Process tells you the difference.
- Defender real-time scanning reads everything. If you audit too broadly, it dominates the noise.

## What 4663 does not tell you

- The content of the access. You see that a file was read or written, not what was read or written. For that, EDR or FIM.
- Why the access happened. To correlate to user intent, pair with [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) for the calling process's full context.
- Closed handles. 4663 fires on handle *open*. Close events are 4658, rarely useful for attack detection.
- Network paths transparently. SMB access to a share fires 4663 on the *server*. The client sees nothing. You need server-side collection.
- Failed access by default. Many shops only audit Success. Configure Failure only if you genuinely care about thwarted attempts.

## Where 4663 fits in a timeline

Classic LSASS credential dump chain:

1. [4624](/en/blog/understanding-event-id-4624). Admin logon, LogonType 3 or 10.
2. [4672](/en/blog/event-id-4672-special-privileges). SeDebugPrivilege granted with the session.
3. [4688](/en/blog/event-id-4688-process-creation). `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <pid> C:\Windows\Temp\lsass.dmp full`.
4. **4663**. `WriteData` to `C:\Windows\Temp\lsass.dmp` by `rundll32.exe`. Forensic gold. Proof of staged exfil.
5. [4688](/en/blog/event-id-4688-process-creation). File move or archive (operator extracting the dump).
6. [1102](/en/blog/event-id-1102-cleared-log). Security log cleared. Some operators do this. Many forget.

Step 4 is the cheapest, most specific signal in the chain. It directly identifies the credential-theft artifact by name, on disk, with the calling process attached. SAM-hive reads, DPAPI master-key access, and SYSVOL Groups.xml reads work the same way.

## Further reading

- [Microsoft documentation for 4663](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4663)
- [SpecterOps: SACLs for Detection](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)
- [MITRE ATT&CK T1003](https://attack.mitre.org/techniques/T1003/)

---
title: "Event ID 4672 explained: detecting privileged logons in Windows"
description: "4672 fires whenever a logon is granted sensitive privileges like SeDebugPrivilege or SeTcbPrivilege. Read it as the 'this logon is admin-equivalent' signal and the rest of audit policy falls into place."
date: "2026-05-24"
---

Event ID **4672**, "Special privileges assigned to new logon", fires on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time a logon session is granted one of a fixed set of sensitive Windows privileges. In practice, every successful administrator-equivalent logon produces a 4672, written immediately after the corresponding [4624](/en/blog/understanding-event-id-4624). On most workstations 4672 is rare. On domain controllers and admin jumpboxes it is constant. That asymmetry is what makes it useful.

If you filter Security by one field this week, run "all 4672s in the last seven days". It is the cheapest "show me every privileged session in the estate" query you can write.

## Where it fires

On the host where the logon actually happened, same as [4624](/en/blog/understanding-event-id-4624). A network logon to `SERVER01` produces the 4624 and the 4672 on `SERVER01`, not on the originating workstation. To detect anything from 4672 at scale you need Security collection from servers and DCs at minimum. Admin workstations and jumphosts if you can afford the volume.

## What the record contains

```xml
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1a3c5</Data>
<Data Name="PrivilegeList">SeAssignPrimaryTokenPrivilege
  SeTcbPrivilege
  SeSecurityPrivilege
  SeTakeOwnershipPrivilege
  SeLoadDriverPrivilege
  SeBackupPrivilege
  SeRestorePrivilege
  SeDebugPrivilege
  SeSystemEnvironmentPrivilege
  SeImpersonatePrivilege</Data>
```

The fields:

- `SubjectLogonId`. The same `LogonId` from the matching [4624](/en/blog/understanding-event-id-4624). This is your pivot. Every 4672 ties exactly one 4624 (and every subsequent record in that session) to the privilege set the logon got.
- `PrivilegeList`. The actual privilege bag. Windows logs only the "sensitive" privileges defined in the audit policy. A logon may hold more privileges than the record shows. The omitted ones (`SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc.) are non-security-relevant and pruned from this record on purpose.
- `Subject*`. Who the logon belongs to. Almost always identical to the matching 4624.

There is no `IpAddress`, no `LogonType`, no `WorkstationName` on 4672 itself. To get those you join to the 4624 via `SubjectLogonId`. Analysts trying to alert on 4672 alone often miss this and end up with records they cannot enrich.

## The privileges and what they mean

| Privilege | Display name | Why it matters |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Read/write any process's memory, including `lsass.exe`. Mimikatz needs this. |
| `SeTcbPrivilege` | Act as part of the OS | Effectively `LocalSystem`. Should appear only for LocalSystem. |
| `SeImpersonatePrivilege` | Impersonate a client after auth | The privilege used by the Potato family (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process token | Token-impersonation tooling. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore | Bypass ACLs to read/write arbitrary files including registry hives. `reg save HKLM\SAM` works with these. |
| `SeTakeOwnershipPrivilege` | Take ownership | Override file ACLs. |
| `SeLoadDriverPrivilege` | Load drivers | Required for BYOVD (bring-your-own-vulnerable-driver). |
| `SeSecurityPrivilege` | Manage audit log | Read or clear Security. Required to fire [1102](/en/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware | Bootkits, EFI tampering. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Common on most logons. Not a triage signal. |

Some you expect on every admin logon (`SeDebugPrivilege`, `SeBackupPrivilege`). Others should be rarer (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). The signal is the *unexpected* privilege on the *wrong* account.

## The patterns

### Baseline who gets 4672

In a healthy estate, 4672 producers are a small, known set:

- `LocalSystem` (S-1-5-18). Every host, all the time, on service startup.
- `NetworkService` (S-1-5-20). Common on servers running impersonation-capable services.
- A handful of administrators, identified by SID rather than name.

Anyone else is a new admin you did not know about, a privilege-escalation event, or a misconfigured account.

The cheapest baseline query: distinct `SubjectUserSid` from 4672 over the last 30 days, sorted by frequency. Anything outside the top N is worth a look.

### SeImpersonatePrivilege on an unprivileged account

If a 4672 shows `SeImpersonatePrivilege` on an account that is not an admin and not a `*Service` SID, it is almost certainly a Potato escalation. These exploits give an `IIS_IUSRS` or service-token caller `SYSTEM`. The 4672 fires *as the privilege is acquired*. That is earlier than any visible process spawned with the new privilege.

### SeDebugPrivilege without admin group

`SeDebugPrivilege` is granted to local admins by policy. On a non-admin account, either policy was modified (usually by an attacker to enable LSASS access) or an attacker has injected into an admin process.

### Privileged logon outside business hours

A 4672 for a real admin account at 03:00 on a Sunday is the cheapest after-hours alert there is. Combine with the matching 4624's `LogonType` and `IpAddress` for context.

### Service account drift

A service account that historically only fires `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` suddenly producing 4672s with `SeBackupPrivilege` and `SeDebugPrivilege` means somebody changed its group memberships. Pair with 4732 or 4728 to find the membership change.

## Sigma: SeDebugPrivilege on a non-admin

```yaml
title: SeDebugPrivilege Granted to Non-Admin Account
id: 8a3b1d20-77e1-4a4c-8a3b-1e8f2c1b9a0f
status: stable
description: Event 4672 grants SeDebugPrivilege to an account that should not have administrative rights.
references:
  - https://attack.mitre.org/techniques/T1003/001/
  - https://attack.mitre.org/techniques/T1134/001/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4672
    PrivilegeList|contains: 'SeDebugPrivilege'
  filter_known_service_sids:
    SubjectUserSid:
      - 'S-1-5-18'  # LocalSystem
      - 'S-1-5-19'  # LocalService
      - 'S-1-5-20'  # NetworkService
  filter_known_admins:
    SubjectUserName|endswith:
      - '_adm'
      - '-admin'
      - 'admin'
  condition: selection and not (filter_known_service_sids or filter_known_admins)
falsepositives:
  - Legitimate administrators not matching the naming pattern
  - Forensic / debugging tools in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Tune `filter_known_admins` per environment. Some shops use a SID list rather than a name pattern.

## KQL: Potato-family escalation

```kusto
SecurityEvent
| where EventID == 4672
| where PrivilegeList contains "SeImpersonatePrivilege"
| where SubjectUserSid !in ("S-1-5-18", "S-1-5-19", "S-1-5-20")
| join kind=inner (
    SecurityEvent
    | where EventID == 4624
    | where AccountName !in ("LocalSystem", "NetworkService", "LocalService")
    | project LogonTime=TimeGenerated, SubjectLogonId=TargetLogonId,
              LogonType, IpAddress, AccountName
) on SubjectLogonId
| project TimeGenerated, AccountName, LogonType, IpAddress, PrivilegeList, Computer
| order by TimeGenerated desc
```

## Splunk: admin logons baseline

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Run this weekly. Anomalies show up as new accounts in the top 50.

## ATT&CK mapping

- T1134.001 Token Impersonation/Theft. SeImpersonatePrivilege on unprivileged accounts.
- T1003.001 LSASS Memory. SeDebugPrivilege is the precondition.
- T1068 Exploitation for Privilege Escalation. Any unexpected privilege gain.
- T1078 Valid Accounts. 4672 for legitimate admin accounts from unusual sources.
- T1562.002 Disable Windows Event Logging. SeSecurityPrivilege is required to call `ClearEventLog`. A 4672 carrying this privilege immediately before [1102](/en/blog/event-id-1102-cleared-log) is the breadcrumb trail.

## False positives that look like attacks

- Backup software (Veeam, Commvault) routinely fires 4672 with `SeBackupPrivilege` + `SeRestorePrivilege` from service accounts. Baseline by service-account SID.
- Monitoring agents (SCOM, custom WMI collectors) trigger 4672 broadly. Tag the agent host.
- Some logon-script runners under privileged contexts produce 4672 chains at logon time.
- Hyper-V, VMM, container hosts generate dense 4672 from `LocalSystem` and managed service accounts.

The signal is the *new* producer, not the *recurring* one. A 4672 producer that has fired daily for the last year is configuration. One that just appeared this week is the lead.

## What 4672 does not tell you

- No process information. You see the privilege grant, not what the privileged process did. To follow it forward, pivot `SubjectLogonId` to [4688](/en/blog/event-id-4688-process-creation) or [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) records in the same session.
- No source IP directly. You join to [4624](/en/blog/understanding-event-id-4624) via `SubjectLogonId`.
- Not every privileged action. Only the *grant at logon* is recorded. Subsequent uses (e.g. `RtlAdjustPrivilege` toggling `SeDebugPrivilege` on and off) produce 4673/4674 records, not another 4672.
- Missed if Special Logon auditing is off. The audit sub-policy is *Audit Special Logon*. On by default in modern Windows, but worth verifying.

## Where 4672 fits in a timeline

The textbook escalation-and-cleanup chain:

1. [4624](/en/blog/understanding-event-id-4624). LogonType 3 from an attacker-controlled IP, low-priv user.
2. *(silent)*. SeImpersonatePrivilege-based escalation (PrintSpoofer or similar).
3. **4672**. SeImpersonatePrivilege + SeTcbPrivilege granted to a new logon session running as LocalSystem. Escalation visible here.
4. [4688](/en/blog/event-id-4688-process-creation). `cmd.exe` or `powershell.exe` as SYSTEM via the impersonated token.
5. [4104](/en/blog/powershell-4104-scriptblock). `Invoke-Mimikatz` or `comsvcs.dll MiniDump` against LSASS. SeDebugPrivilege is what makes this work.
6. [1102](/en/blog/event-id-1102-cleared-log). Security log cleared. SeSecurityPrivilege from step 3 enabled this.
7. **4672**. Second privileged session as a domain admin extracted from LSASS memory.

The 4672s in steps 3 and 7 are the cheapest detection points. Without them you are piecing together impersonation from process events alone. Slower, easier to miss.

## Further reading

- [Microsoft documentation for 4672](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672)
- [SpecterOps: An Introduction to Manipulating Token Privileges](https://posts.specterops.io/an-introduction-to-manipulating-token-privileges-dbd13a6ab1c2)

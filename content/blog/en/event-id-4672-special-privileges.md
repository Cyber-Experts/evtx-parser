---
title: "Event ID 4672 explained: detecting privileged logons in Windows"
description: "4672 fires whenever a logon is granted sensitive privileges like SeDebugPrivilege or SeTcbPrivilege. Read it as the 'this logon is admin-equivalent' signal and the rest of your audit policy falls into place."
date: "2026-05-24"
---

Event ID **4672** — "Special privileges assigned to new logon" — fires on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time a logon session is granted one of a fixed set of sensitive Windows privileges. In practice that means: every successful administrator-equivalent logon produces a 4672, immediately after the corresponding [4624](/en/blog/understanding-event-id-4624). On most workstations, 4672 is rare; on domain controllers and admin jumpboxes, it's constant. That asymmetry is what makes it useful.

If you only filter Security records by one field, "give me all 4672s in the last week" is the cheapest "show me every privileged session in the estate" query you can run.

## Where it fires

Always on the host where the logon actually happened — same as [4624](/en/blog/understanding-event-id-4624). A network logon to `SERVER01` produces the 4624 and (if privileged) the 4672 on `SERVER01`, not on the originating workstation. To detect anything from 4672 at scale, you need Security collection from servers and DCs at minimum; from admin workstations and jumphosts if you can afford the volume.

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

- **`SubjectLogonId`** — the same `LogonId` that appears on the matching [4624](/en/blog/understanding-event-id-4624). This is your pivot: every 4672 ties exactly one 4624 (and every subsequent record in that session) to the privilege set that logon got.
- **`PrivilegeList`** — the actual privilege bag. Windows logs only a fixed set of "sensitive" privileges here (defined in the audit policy); a logon may hold more privileges than the record shows. The omitted ones — `SeLockMemoryPrivilege`, `SeIncreaseBasePriorityPrivilege`, etc. — are non-security-relevant and pruned from this record on purpose.
- **`Subject*`** — who the logon belongs to. Almost always identical to the same fields on the matching 4624.

There is no `IpAddress`, no `LogonType`, no `WorkstationName` on 4672 itself. To get those you join to the 4624 via `SubjectLogonId`.

## The privileges and what they mean

| Privilege | Display name | Why it matters |
|---|---|---|
| `SeDebugPrivilege` | Debug programs | Read/write any process's memory — including `lsass.exe`. Mimikatz needs this. |
| `SeTcbPrivilege` | Act as part of the operating system | Effectively `LocalSystem`. Should appear only for LocalSystem itself. |
| `SeImpersonatePrivilege` | Impersonate a client after authentication | The privilege used by `SeImpersonatePrivilege`-exploit families (PrintSpoofer, JuicyPotato, RoguePotato). |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Token-impersonation tooling. |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Backup/Restore files | Bypass ACLs to read/write arbitrary files — including registry hives. `reg save HKLM\SAM` works with these. |
| `SeTakeOwnershipPrivilege` | Take ownership of files | Override file ACLs. |
| `SeLoadDriverPrivilege` | Load and unload device drivers | Required for BYOVD (bring-your-own-vulnerable-driver) attacks. |
| `SeSecurityPrivilege` | Manage auditing and security log | Read/clear the Security event log. Required to fire [1102](/en/blog/event-id-1102-cleared-log). |
| `SeSystemEnvironmentPrivilege` | Modify firmware environment values | Bootkits, EFI tampering. |
| `SeChangeNotifyPrivilege` | Bypass traverse checking | Common on most logons; not a triage signal. |

Some of these you expect on every admin logon (`SeDebugPrivilege`, `SeBackupPrivilege`). Others should be rarer (`SeLoadDriverPrivilege`, `SeTcbPrivilege`). The signal is in the *unexpected* privilege showing up on the *wrong* account.

## The triage patterns

### 1. Baseline who gets 4672

In a healthy estate, 4672 producers are a *small, known* set:

- `LocalSystem` (S-1-5-18) — every host, all the time, on service startup.
- `NetworkService` (S-1-5-20) — common on servers running impersonation-capable services.
- A handful of administrators, identified by SID rather than name.

Anyone else generating a 4672 is either: a new admin you didn't know about, a privilege-escalation event, or a misconfigured account.

The cheapest baseline query: distinct `SubjectUserSid` from 4672 over the last 30 days, sorted by frequency. Anything outside the top N producers warrants a look.

### 2. SeImpersonatePrivilege on an unprivileged account

If a 4672 shows `SeImpersonatePrivilege` on an account that isn't an admin and isn't a `*Service` SID, it's almost certainly a "Potato" family escalation (PrintSpoofer, JuicyPotato, RoguePotato, GodPotato). These exploits give an `IIS_IUSRS` or service-token caller `SYSTEM`. The 4672 fires *as the privilege is acquired* — earlier than any visible process spawned with the new privilege.

### 3. SeDebugPrivilege without admin group

`SeDebugPrivilege` is granted to local admins by policy. Seeing it on a non-admin account is a sign that policy has been modified — usually by an attacker to enable LSASS access — or that an attacker has injected into an admin process.

### 4. Privileged logon outside business hours

A 4672 for a real admin account at 03:00 on a Sunday is the cheapest "after-hours admin activity" alert there is. Combine with the corresponding 4624's `LogonType` and `IpAddress` for context.

### 5. Service account drift

A service account that historically only fires `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` suddenly producing 4672s with `SeBackupPrivilege` and `SeDebugPrivilege` means somebody changed its group memberships. Pair with 4732/4728 to find the membership change.

## Sample Sigma rule — SeDebugPrivilege on a non-admin

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
  - Forensic / debugging tools running under non-admin accounts in dev environments
level: high
tags:
  - attack.privilege_escalation
  - attack.t1134
```

Tune `filter_known_admins` per environment; some shops use a SID list rather than a name pattern.

## Sample KQL — Potato-family escalation

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

## Sample Splunk — admin logons baseline

```spl
index=wineventlog EventCode=4672
| stats count by SubjectUserName host
| sort - count
| head 50
```

Run this weekly; anomalies show up as new accounts in the top 50.

## ATT&CK mapping

- **T1134.001 — Access Token Manipulation: Token Impersonation/Theft**: SeImpersonatePrivilege on unprivileged accounts.
- **T1003.001 — OS Credential Dumping: LSASS Memory**: SeDebugPrivilege is the precondition.
- **T1068 — Exploitation for Privilege Escalation**: any unexpected privilege gain.
- **T1078 — Valid Accounts**: 4672 for legitimate admin accounts from unusual sources.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: SeSecurityPrivilege is required to call `ClearEventLog`; a 4672 with this privilege immediately before [1102](/en/blog/event-id-1102-cleared-log) is the trail of breadcrumbs.

## False positives that look exactly like attacks

- **Backup software** (Veeam, Commvault) routinely fires 4672 with `SeBackupPrivilege` + `SeRestorePrivilege` from service accounts. Baseline by service-account SID.
- **Monitoring agents** (SCOM, custom WMI collectors) that read security-relevant data trigger 4672 broadly. Tag the agent host.
- **Some logon-script** runners under privileged contexts produce 4672 chains at logon time.
- **Hyper-V / VMM / container hosts** generate dense 4672 traffic from `LocalSystem` and managed service accounts.

The signal is in the *new* producer, not the *recurring* one. A 4672 producer that has fired daily for the last year is configuration; one that just appeared this week is the lead.

## What 4672 doesn't tell you

- **No process information**: you see the privilege grant, not what the privileged process did. To follow it forward, pivot `SubjectLogonId` to [4688](/en/blog/event-id-4688-process-creation) / [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) records in the same session.
- **No source IP** directly: you have to join to [4624](/en/blog/understanding-event-id-4624) via `SubjectLogonId` to get it.
- **Not every privileged action**: only the *grant at logon* is recorded. Subsequent uses (e.g., `RtlAdjustPrivilege` toggling `SeDebugPrivilege` on/off) produce 4673/4674 records, not another 4672.
- **Missed if Special Logon auditing is off**: the audit subcategory is *Audit Special Logon*, which must be enabled for success events. It's on by default in modern Windows but worth verifying.

## Where 4672 fits in a timeline

The textbook escalation-and-cleanup chain:

1. [**4624**](/en/blog/understanding-event-id-4624) — LogonType 3 from an attacker-controlled IP, low-priv user.
2. *(silent)* — `SeImpersonatePrivilege`-based escalation (PrintSpoofer or similar).
3. **4672** — `SeImpersonatePrivilege` + `SeTcbPrivilege` granted to a new logon session running as `LocalSystem`. **Escalation visible here.**
4. [**4688**](/en/blog/event-id-4688-process-creation) — `cmd.exe` or `powershell.exe` running as SYSTEM via the impersonated token.
5. [**4104**](/en/blog/powershell-4104-scriptblock) — `Invoke-Mimikatz` or `comsvcs.dll MiniDump` against LSASS — SeDebugPrivilege is what makes this work.
6. [**1102**](/en/blog/event-id-1102-cleared-log) — Security log cleared. SeSecurityPrivilege from step 3 enabled this.
7. **4672** — second privileged session as a domain admin extracted from LSASS memory.

The 4672s in steps 3 and 7 are the cheapest detection points in the chain. Without them you're piecing together impersonation from process events alone — slower, and easier to miss.

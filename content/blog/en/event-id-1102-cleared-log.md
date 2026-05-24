---
title: "Event ID 1102 explained: Security audit log cleared (and what survives)"
description: "1102 is the one event you can't suppress without leaving more evidence. Here's what it tells you and what survives the clear."
date: "2026-05-17"
---

Event ID **1102** is the record Windows writes to the `Security` channel when the audit log is cleared. It is — by design — one of the hardest records for an attacker to suppress, because suppressing it requires either successfully replacing the EventLog service before it boots or accepting that the act of clearing leaves a 1102 of its own.

For defenders this means: if you see 1102, somebody with sufficient privilege deliberately wiped the audit trail. That is almost never a normal admin action.

## What's in the record

```xml
<UserData>
  <LogFileCleared>
    <SubjectUserSid>S-1-5-21-1234-...-500</SubjectUserSid>
    <SubjectUserName>Administrator</SubjectUserName>
    <SubjectDomainName>CORP</SubjectDomainName>
    <SubjectLogonId>0x3e7</SubjectLogonId>
  </LogFileCleared>
</UserData>
```

Note the `UserData` block instead of the usual `EventData` — 1102 is one of the records that uses a structured user-data schema. The fields tell you *who* cleared the log under what logon session. Pivot on the `SubjectLogonId` to find the matching [4624](/en/blog/understanding-event-id-4624) and you'll get the source IP and logon type that produced the privileged session.

## What also fires when 1102 fires

A log clear is rarely the *only* anti-forensic action. Common companions, in rough chronological order:

- **104** on the `System` channel — same act, recorded by the SCM. If 104 is present but 1102 is missing, the attacker only cleared the Security log and forgot System.
- **4719** — "System audit policy was changed". Sometimes an attacker reduces audit coverage *before* clearing, to leave fewer records on the next round.
- **4616** — "The system time was changed". Pre-clearing time skew makes timeline reconstruction harder.
- **A gap in 4624s** for an hour or two before 1102 — the attacker may have used a non-logged side channel.

## What survives a clear

Clearing the in-memory event log doesn't touch:

- **Other channels**: `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, forwarded-event channels — none of these get cleared by a Security wipe.
- **Forwarded events**: if Windows Event Forwarding (WEF) is configured to a central collector, the cleared records are already on another host.
- **The on-disk file itself**: a cleared `Security.evtx` is replaced by a new file; the *deleted* prior file's clusters often persist in unallocated space and can be carved with NTFS tooling.
- **USN journal entries** for the file replacement: even the clearing operation leaves filesystem-level artifacts.

A "successful" log clear is rarely as clean as the attacker hopes.

## Sample Sigma rule — log cleared

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared) — anti-forensic actions.
references:
  - https://attack.mitre.org/techniques/T1070/001/
logsource:
  product: windows
  service: security
detection:
  selection_security:
    EventID: 1102
    Provider_Name: 'Microsoft-Windows-Eventlog'
  selection_system:
    EventID: 104
    Provider_Name: 'Microsoft-Windows-Eventlog'
  condition: selection_security or selection_system
falsepositives:
  - Legitimate administrative log clearing during maintenance (rare, should be ticketed)
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
```

If you see 1102 outside an approved maintenance window, treat as an incident — full stop.

## Sample KQL — log clear + privileged session correlation

```kusto
let clears =
    SecurityEvent
    | where EventID == 1102
    | project ClearTime=TimeGenerated, Host=Computer, ClearLogonId=SubjectLogonId,
              ClearUser=SubjectUserName;
let privileged =
    SecurityEvent
    | where EventID == 4672
    | project PrivTime=TimeGenerated, PrivLogonId=SubjectLogonId,
              PrivilegeList;
clears
| join kind=inner privileged on $left.ClearLogonId == $right.PrivLogonId
| project ClearTime, Host, ClearUser, PrivTime, PrivilegeList
| order by ClearTime desc
```

Every 1102 traces back to a [4672](/en/blog/event-id-4672-special-privileges) granting `SeSecurityPrivilege` — which traces back to a [4624](/en/blog/understanding-event-id-4624). The join completes the picture.

## Sample Splunk — companion anti-forensics chain

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

A `LogonId` that touched audit policy (4719) or system time (4616) and then cleared a log (1102/104) is the tampering chain.

## ATT&CK mapping

- **T1070.001 — Indicator Removal: Clear Windows Event Logs**: the headline technique. 1102 *is* this technique's primary indicator.
- **T1562.002 — Impair Defenses: Disable Windows Event Logging**: 4719 (audit policy changed) preceding 1102 maps here.
- **T1070.006 — Indicator Removal: Timestomp**: paired with 4616 (system time changed) in the same chain.
- **T1078.003 — Valid Accounts: Local Accounts**: 1102 by a local Administrator that shouldn't have logged on at that time.

## False positives — rare but real

- **Migration / decom workflows**: techs clearing the log on a host being decommissioned. Should always be ticketed.
- **Forensic / testing labs**: clear-and-reproduce workflows during detection development.
- **Some legacy tools** clear the log to reset baselines — almost always a procedural mistake, but a real one.

The signal is so directly anti-forensic that even legitimate 1102s should be investigated and documented after the fact. There's no "safe" reason for a 1102 in normal operations.

## Why this matters for parsing

When you load an .evtx file into a forensic tool, the *first* search worth running is `EventID:1102` and `EventID:104`. If either is present, the log you're holding has known gaps and any timeline you build from it is incomplete. Note it loudly in the report.

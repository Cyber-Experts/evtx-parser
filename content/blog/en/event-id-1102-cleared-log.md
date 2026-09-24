---
title: "Event ID 1102: The audit log was cleared (what survives)"
description: "Event ID 1102 means someone cleared the Windows Security log. Who did it, which fields prove it, what evidence survives the clear and where to look next."
date: "2026-05-17"
---

Event ID **1102** is what Windows writes to the [`Security` channel](/en/blog/what-is-an-evtx-file) when somebody clears the audit log via [event log clearing](https://www.reverseengineering.app/en/techniques/event-log-clearing). It is, by design, one of the harder records for an attacker to suppress. Suppressing it cleanly requires either replacing the EventLog service binary before it boots, or accepting that the act of clearing leaves a 1102 of its own. Most operators take the second option, hoping nobody is paying attention.

If you see 1102, somebody with sufficient privilege deliberately wiped the audit trail. That is essentially never a routine admin action, and when it is, it should be ticketed. Treat every 1102 outside an approved maintenance window as an incident until proven otherwise.

## What is in the record

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

Note the `UserData` block rather than the usual `EventData`. 1102 uses a structured user-data schema, which trips up some naive parsers that only look at `EventData`. The fields tell you who cleared the log under what logon session. Pivot on `SubjectLogonId` to the matching [4624](/en/blog/understanding-event-id-4624) and you have the source IP, logon type, and credential that produced the privileged session.

## What rides alongside

A log clear is rarely the only anti-forensic action in the chain. The records that tend to fire near it, in rough chronological order:

- **104** on the `System` channel. Same act as 1102 but recorded by the SCM for non-Security channels. If 104 is present and 1102 is missing, the attacker only cleared Security and forgot System.
- **4719**, "system audit policy was changed". Sometimes the attacker reduces audit coverage *before* clearing, to leave fewer records the next time around.
- **4616**, "the system time was changed". Pre-clearing timestomping makes timeline reconstruction harder.
- A gap in 4624s in the hour or two before 1102. The attacker may have used a non-logged side channel to get in.

## What survives a clear

Clearing the in-memory event log does not touch:

- Other channels. `System`, `Application`, `PowerShell/Operational`, `Sysmon/Operational`, `TaskScheduler/Operational`, forwarded-event channels. None of these get cleared by a Security wipe.
- Forwarded events. If Windows Event Forwarding is sending Security to a collector, the cleared records are already on another host. The originating RecordIDs and timestamps are preserved.
- The on-disk file itself. A cleared `Security.evtx` is replaced with a fresh file. The clusters of the prior file often persist in unallocated space. EVTX records [carve cleanly](/en/blog/carve-deleted-evtx-records) out of those clusters.
- [USN journal](https://www.usnparser.com) entries for the file replacement. Even the act of clearing leaves filesystem-level artifacts.
- The [MFT](https://www.mftparser.com) entry for the new file, which carries a creation timestamp that should match the 1102 within a second.

A "successful" log clear is rarely as clean as the attacker hopes.

## Sigma: log cleared

```yaml
title: Windows Security Event Log Cleared
id: 2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detect 1102 (Security log cleared) and 104 (System log cleared). Anti-forensic actions.
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

## KQL: clear correlated with privileged session

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

Every 1102 traces back to a [4672](/en/blog/event-id-4672-special-privileges) granting `SeSecurityPrivilege`, which traces back to a [4624](/en/blog/understanding-event-id-4624). The join completes the picture.

## Splunk: the tampering chain

```spl
index=wineventlog ( EventCode=1102 OR EventCode=104 OR EventCode=4719 OR EventCode=4616 )
| stats values(EventCode) AS Events earliest(_time) AS first latest(_time) AS last BY host SubjectLogonId
| where mvcount(Events) >= 2
```

A LogonId that touched audit policy (4719) or system time (4616) and then cleared a log (1102/104) is the tampering chain.

## ATT&CK mapping

- T1070.001 Indicator Removal: Clear Windows Event Logs. The headline. 1102 *is* the primary indicator.
- T1562.002 Impair Defenses: Disable Windows Event Logging. 4719 preceding 1102 maps here.
- T1070.006 Indicator Removal: Timestomp. Paired with 4616 in the same chain.
- T1078.003 Valid Accounts: Local Accounts. 1102 by a local Administrator that should not have been logged on at that time.

## False positives, rare but real

- Migration or decom workflows. Techs clearing logs on a host being decommissioned. Should always be ticketed.
- Forensic labs running clear-and-reproduce loops during detection development.
- Some legacy tools clear the log to "reset baselines". Almost always a procedural mistake, but a real one.

There is no safe reason for a 1102 in normal operations. Even the legitimate ones should be investigated and documented after the fact.

## When you find one in the bundle

When you load an [.evtx file into a forensic tool](/en/blog/how-to-open-an-evtx-file), the first two searches worth running are `EventID:1102` and `EventID:104`. If either is present, the log you are holding has known gaps. Any timeline built from it is incomplete. Note it loudly in the report. Then go look at what survived: the [registry](https://www.registryparser.com), [USN journal](https://www.usnparser.com), [MFT](https://www.mftparser.com), [prefetch](https://www.prefetchparser.com), and [AmCache](https://www.amcacheparser.com). Together they reconstruct most of what 1102 tried to erase.

Tools like `Invoke-Phant0m` skip 1102 entirely by suspending the event service threads instead of clearing. If you see a multi-hour silence in Security with no 1102 and no system shutdown, that is the other shape of the same problem.

## Further reading

- [MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)
- [Microsoft documentation for 1102](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102)

---
title: "Event ID 4720 explained: detecting rogue account creation in AD"
description: "4720 fires every time a user account is created, local or domain. Read it with 4722, 4724, and 4732 and you catch persistence and lateral-movement accounts within minutes."
date: "2026-05-24"
---

Event ID **4720**, "A user account was created", lands on the [`Security` channel](/en/blog/what-is-an-evtx-file) every time a new user is provisioned. On a domain controller it fires for every new AD user. On a workstation or member server it fires for every new local account. In a mature shop, 4720 traffic is overwhelmingly HR-driven and predictable. That predictability is what makes it useful. An attacker creating a backdoor account stands out exactly because the legitimate traffic is so regular.

This is one of the cheapest persistence-detection records the platform produces. I have closed cases on it alone.

## Where it fires

- Domain accounts: 4720 lands on the DC that handled the create. Collect across all DCs.
- Local accounts: 4720 lands on the host where the account was created. Catching this from member workstations requires WEF or per-host collection. Many shops skip workstation Security forwarding and lose this signal entirely.

If the attacker creates a *local* account on a server they have already compromised (often as a backup credential), the 4720 will be on that server only. Coverage matters more than rules.

## What is in the record

```xml
<Data Name="TargetUserName">svc_backup2</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetSid">S-1-5-21-...-1175</Data>
<Data Name="SubjectUserSid">S-1-5-21-...-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">CORP</Data>
<Data Name="SubjectLogonId">0x1f48c</Data>
<Data Name="PrivilegeList">-</Data>
<Data Name="SamAccountName">svc_backup2</Data>
<Data Name="DisplayName">-</Data>
<Data Name="UserPrincipalName">svc_backup2@corp.local</Data>
<Data Name="HomeDirectory">-</Data>
<Data Name="HomePath">-</Data>
<Data Name="ScriptPath">-</Data>
<Data Name="ProfilePath">-</Data>
<Data Name="UserWorkstations">-</Data>
<Data Name="PasswordLastSet">2026-05-24T12:04:11Z</Data>
<Data Name="AccountExpires">never</Data>
<Data Name="PrimaryGroupId">513</Data>
<Data Name="UserAccountControl">0x10</Data>
<Data Name="UserParameters">-</Data>
<Data Name="SidHistory">-</Data>
<Data Name="LogonHours">all</Data>
```

The fields that drive investigations:

- `TargetUserName`. The new account. The literal name is the first triage signal: `svc_*`, `backup*`, `admin2`, `test`, `guest2`, lookalikes of legitimate accounts (`administrator`, `administr0r`), and short random strings all warrant a closer look.
- `SubjectUserName` and `SubjectLogonId`. Who created it. Pivot to the [4624](/en/blog/understanding-event-id-4624) that created that session. A 4720 from `LocalSystem` on a workstation outside business hours is not a real provisioning workflow.
- `UserAccountControl`. The *initial* set of UAC flags. `0x10` (in the example) is `NORMAL_ACCOUNT`. The dangerous flags appear in subsequent 4738 records.
- `PrimaryGroupId`. 513 (Domain Users) is normal. 512 (Domain Admins) on a new account is screaming-loud and should never happen in a real provisioning workflow.
- `SidHistory`. Non-empty on a newly created account is either a migration tool or, in the wrong context, a forged authentication artifact.

## 4720 never comes alone

Account creation is almost never a single event. The minimum sequence:

| Event | Meaning | Why you care |
|---|---|---|
| **4720** | User account created | The headline. |
| **4722** | User account enabled | The account is set to allow logon. If 4722 is missing, the account exists but cannot log on yet. |
| **4724** | Password reset (admin-driven) | Someone, possibly not the creator, set or reset the password. |
| **4738** | User account changed | UAC flags, expiration, group, attribute changes. |
| **4732** | Member added to a security-enabled local group | If the local group is `Administrators`, this is the privilege grant. |
| **4728** | Member added to a security-enabled global group | If the global group is `Domain Admins` or `Enterprise Admins`, escalation. |
| **4756** | Member added to a security-enabled universal group | `Schema Admins`, `Enterprise Admins`, custom delegations. |

A backdoor account is rarely created and left at default privilege. The full chain (4720, 4722, 4724, 4738, 4732/4728) completes within seconds and is the actual persistence event.

## Triage patterns

1. **New account into admin group within minutes**. 4720 followed by 4732 or 4728 to a privileged group within an hour, where the privileged group add was not preceded by a ticket. Pair `TargetSid` from 4720 with `MemberSid` on 4732/4728.
2. **Off-hours creation**. 4720 outside business hours by a `SubjectUserName` that is not a service account running automated provisioning.
3. **Lookalike name**. `Levenshtein(TargetUserName, real_admin_name) <= 2` against the existing user table. `administrato`, `administr0r`, `helpd3sk`. All real.
4. **Created by a recently-compromised account**. 4720 where `SubjectLogonId` traces back to a 4624 from an unusual IP, or a 4624 LogonType 3 from a workstation the subject does not normally use.
5. **Created by LocalSystem on a workstation**. 4720 with `SubjectUserSid = S-1-5-18` on anything other than a domain controller or known provisioning server. Almost always malicious.
6. **PrimaryGroupId == 512**. Never happens in normal provisioning. Hard alert.

## Sigma

```yaml
title: Suspicious User Account Creation
id: 6f1e2db8-9a1d-44a0-b9d2-2f3c52f3b8a9
status: stable
description: A user account was created with suspicious indicators (off-hours, lookalike name, or by LocalSystem on a workstation).
references:
  - https://attack.mitre.org/techniques/T1136/001/
  - https://attack.mitre.org/techniques/T1136/002/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4720
  filter_localsystem:
    SubjectUserSid: 'S-1-5-18'
  filter_business_hours:
    EventTime|hour: [9, 10, 11, 12, 13, 14, 15, 16, 17]
  condition: selection and (filter_localsystem or not filter_business_hours)
falsepositives:
  - Legitimate provisioning automation running as SYSTEM via SCCM/Intune
  - After-hours admin workflows in 24/7 ops
level: medium
tags:
  - attack.persistence
  - attack.t1136
```

A high-confidence variant combines 4720 with a 4732 or 4728 into a privileged group within 1 hour, scoped by `TargetSid`.

## KQL: 4720 plus privilege grant

```kusto
let creates =
    SecurityEvent
    | where EventID == 4720
    | project CreateTime=TimeGenerated, NewUserSid=TargetSid, NewUser=TargetUserName,
              Creator=SubjectUserName, CreatorHost=Computer;
let privileged_groups = dynamic([
    "S-1-5-32-544",                            // Local Administrators
    "S-1-5-21-DOMAIN-512",                     // Domain Admins (replace -DOMAIN- with your domain SID)
    "S-1-5-21-DOMAIN-519"                      // Enterprise Admins
]);
SecurityEvent
| where EventID in (4732, 4728, 4756)
| where TargetSid in (privileged_groups)
| project AddTime=TimeGenerated, MemberSid, TargetSid, AdminHost=Computer
| join kind=inner (creates) on $left.MemberSid == $right.NewUserSid
| where AddTime between (CreateTime .. CreateTime + 1h)
| project CreateTime, NewUser, Creator, CreatorHost, AdminHost, AddTime, AddedToGroup=TargetSid
| order by CreateTime desc
```

## Splunk

```spl
index=wineventlog EventCode=4720
| join TargetSid type=inner
    [ search index=wineventlog (EventCode=4732 OR EventCode=4728 OR EventCode=4756)
      (TargetSid="S-1-5-32-544" OR TargetSid="*-512" OR TargetSid="*-519")
    | rename MemberSid AS TargetSid, _time AS add_time
    | fields TargetSid add_time TargetSid_Group=TargetSid ]
| where add_time - _time < 3600
| table _time TargetUserName SubjectUserName Computer add_time TargetSid_Group
```

## ATT&CK mapping

- T1136.001 Create Account: Local Account. Workstation and server local accounts.
- T1136.002 Create Account: Domain Account. DC-recorded creations.
- T1136.003 Create Account: Cloud Account. Does *not* fire 4720. Cloud creates live in Entra ID audit logs / unified audit log.
- T1098 Account Manipulation. When 4720 is followed by group escalation or attribute changes.

## False positives that look like attacks

- Bulk migration tools (ADMT, Quest Migration Manager) create accounts at speed with `SidHistory` set. The shape is identical to a fast attacker. Baseline known migration windows.
- Joiner pipelines in HR-driven provisioning workflows fire 4720 at predictable times. Alerting on every off-hours 4720 will bury you in HR runs that drift past midnight.
- SCCM, Intune, and Jamf-style management tools create local accounts for OS provisioning. `SubjectUserSid` is `S-1-5-18` on known build hosts. Tag those.
- Service installers for some legacy products create a local service account on first run. Baseline the installer.

Solid 4720 detections always combine the create with a follow-up signal (group add, password change to a known weak pattern, immediate login from an unusual host). The standalone create is too noisy.

## What 4720 does not tell you

The record does not include the password of the new account (Windows never logs that, anywhere). It also does not include the SID of the target domain explicitly. You read the domain from `TargetDomainName` or derive it from `TargetSid`'s domain portion.

Local-account creates on member workstations are invisible to the DC. If you are not collecting Security from workstations (most shops are not), you miss every local backdoor account. Sysmon and a real EDR fill some of the gap (file create and registry-change patterns when local SAM is touched), but 4720 forwarding is the cheapest control. The [registry](https://www.registryparser.com) hive snapshot is the corroboration when log forwarding was off.

## Where 4720 fits in a timeline

The textbook persistence chain:

1. [4624](/en/blog/understanding-event-id-4624). Initial domain logon by a phished user.
2. [4769](/en/blog/event-id-4769-kerberoasting) burst. Kerberoasting against domain service accounts.
3. 4624 as a compromised service account on a member server.
4. [4688](/en/blog/event-id-4688-process-creation). `net user svc_backup2 P@ssw0rd! /add /domain` (or `New-ADUser` via PowerShell).
5. **4720**. Account created on the DC.
6. 4724. Password set.
7. 4722. Account enabled.
8. 4728. Added to Domain Admins.
9. [7045](/en/blog/service-creation-event-id-7045). Service installed on a server, running under the new account.

Instrument 4720 alone and you catch the persistence at step 5, before steps 6 to 9 do any damage. That is the value.

## Further reading

- [Microsoft documentation for 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [MITRE ATT&CK T1136](https://attack.mitre.org/techniques/T1136/)

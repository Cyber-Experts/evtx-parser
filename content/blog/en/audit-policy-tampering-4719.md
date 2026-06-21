---
title: "Event ID 4719: audit policy tampering as an early warning"
description: "Why attackers change the audit policy to go dark, and how Event ID 4719 catches it — reading the subcategory and the success/failure changes, and pairing it with log clearing as an anti-forensics signal."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - anti-forensics
  - audit-policy
  - threat-hunting
author: "Florian Amette"
---

Clearing a log ([1102](/en/blog/event-id-1102-cleared-log)) destroys history that already exists. Changing the **audit policy** is quieter and arguably worse: it stops the history from ever being recorded. **Event ID 4719** ("System audit policy was changed") is the event that catches an attacker turning auditing off — and because it fires *before* the gap it creates, it's an early-warning signal. This sits with the [anti-forensics theme](/en/blog/evtx-tampering-what-survives).

## Why attackers touch the audit policy

If an intruder disables, say, the *Process Creation* or *Logon* subcategory, then [4688](/en/blog/event-id-4688-process-creation) or [4624](/en/blog/understanding-event-id-4624) simply stop being written. There is no log to clear later because nothing was logged — and a half-blind log looks normal at a glance. It's a favourite of operators who want to work without leaving the usual trail, and it often precedes the noisy actions they're hiding.

## Reading 4719

The event records *which* auditing changed and *how*:

| Field | Use |
|-------|-----|
| `SubjectUserName` / `SubjectLogonId` | **who** changed the policy — tie to their [logon](/en/blog/windows-logon-events-explained) |
| `Category` / `Subcategory` | **which** auditing area (Logon/Logoff, Detailed Tracking, Object Access, …) |
| `Subcategory GUID` | precise subcategory identifier |
| `AuditPolicyChanges` | the change: e.g. "Success removed", "Failure removed", "Success and Failure removed" |

A 4719 reading *"Subcategory: Logon, Success removed"* by a non-administrative or unexpected actor means someone just stopped logon auditing — investigate immediately.

## What's normal vs suspicious

Audit policy *does* change legitimately — GPO application, baseline rollouts, security tooling. Distinguish:

- **Benign**: changes by `SYSTEM`/GPO during policy refresh, broad and consistent across hosts, *enabling* auditing or matching a known baseline push.
- **Suspicious**: changes that **remove** Success/Failure auditing, on a single host, by an interactive user account, during an incident window — especially for high-value subcategories (Logon/Logoff, Detailed Tracking/Process Creation, Object Access, Account Management).

The direction matters: attackers **remove** auditing. A 4719 that turns things *off* is the one to chase.

## Pair it with the rest of the anti-forensics picture

4719 rarely travels alone:

```
4624 (+4672)   actor logs on with privilege
4719           audit subcategory "… Success removed"   (go dark)
… activity with reduced/no logging …
1102 / 104     clear what little remains                (cover tracks)
```

Seeing 4719 and [1102](/en/blog/event-id-1102-cleared-log) from the same actor is a strong anti-forensics combination. And like 1102, a 4719 on the target doesn't reach the **forwarded copy** (WEF/SIEM) or sibling hosts — so a centrally-collected 4719 survives even when the local trail is later wiped.

## Don't trust an empty log at face value

The deeper lesson: **absence of events is itself evidence.** If you expect [process](/en/blog/event-id-4688-process-creation) or [logon](/en/blog/understanding-event-id-4624) events in a window and find none, check for a preceding 4719 (auditing disabled) before concluding "nothing happened." A [missing-events gap](/en/blog/evtx-tampering-what-survives) explained by a 4719 is a finding, not a dead end.

## Hunt checklist

- Filter Security to **4719**; focus on changes that **remove** Success/Failure auditing.
- Flag changes by interactive/non-admin accounts, on single hosts, in the incident window.
- Note the `Subcategory` — Logon, Process Creation, Object Access, Account Management are high-value targets.
- Correlate the actor (`SubjectLogonId`) to their [logon](/en/blog/windows-logon-events-explained) and to any [1102](/en/blog/event-id-1102-cleared-log) clears.
- Compare against the **forwarded/SIEM** copy and sibling hosts.
- When events are missing, look for a 4719 that explains the gap.

Load the Security log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to 4719, and read the subcategory + change direction. See also the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

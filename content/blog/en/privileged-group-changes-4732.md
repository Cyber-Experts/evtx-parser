---
title: "Privileged group changes: Event IDs 4732, 4728 and 4756"
description: "Detecting privilege escalation and persistence through group membership changes in the Security log — local (4732), global (4728) and universal (4756) group additions, what the fields mean, and the create-then-add pattern."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - persistence
  - privilege-escalation
  - threat-hunting
author: "Florian Amette"
---

Adding an account to a privileged group is one of the quietest ways to escalate and persist — the attacker doesn't need a new payload, just a membership change, and afterwards the access looks entirely legitimate. The Security log records every such change, and the event ID tells you the *scope* of the group. This is part of the [persistence theme](/en/blog/scheduled-task-persistence-4698).

## The three "member added" events

The event ID depends on the group's scope:

| Event ID | Group scope | Typical high-value targets |
|---------:|-------------|----------------------------|
| **4732** | security-enabled **local** group | local `Administrators`, `Remote Desktop Users` |
| **4728** | security-enabled **global** group | `Domain Admins`, `Domain Users` |
| **4756** | security-enabled **universal** group | `Enterprise Admins`, `Schema Admins` |

The "member removed" counterparts are **4733 / 4729 / 4757**, and group creation is **4727 / 4731 / 4754**. All require **Audit Security Group Management** (enabled by default on domain controllers for the directory groups).

## Reading the event

The fields that matter:

- **`MemberSid` / `MemberName`** — *who was added*. `MemberName` is sometimes only the SID/DN, so resolve the SID.
- **`TargetUserName`** — *which group* (e.g. `Administrators`, `Domain Admins`).
- **`SubjectUserName` / `SubjectLogonId`** — *who did it*. Tie `SubjectLogonId` back to the actor's [4624 session](/en/blog/windows-logon-events-explained).

So "4728, MemberSid S-1-5-…1108, TargetUserName Domain Admins, SubjectUserName helpdesk1" reads as: *helpdesk1 added user 1108 to Domain Admins.* Whether that is normal depends entirely on whether helpdesk1 should be touching Domain Admins.

## Where the events fire

Scope decides location: **domain** group changes (4728/4756 for Domain Admins, Enterprise Admins) log on the **domain controller**; **local** group changes (4732 for a member server's local Administrators) log on **that host**. Hunting for "who got made a domain admin" means looking at DC Security logs; "who got local admin on SRV-APP01" means that server's log.

## The patterns to hunt

- **Create-then-promote.** A [4720 account creation](/en/blog/event-id-4720-account-created) followed quickly by 4732/4728 adding it to admins — an attacker minting a privileged account.
- **Add to Domain Admins / Enterprise Admins** by anyone who isn't a known tier-0 admin → escalate immediately.
- **Local Administrators additions on servers/workstations** during an incident window — local persistence/escalation.
- **`Remote Desktop Users` additions** — paired with the [RDP trail](/en/blog/detecting-rdp-lateral-movement), this is an attacker granting themselves remote access.
- **Add-then-remove** around the time of malicious activity — temporary elevation that cleans up after itself (4728 → … → 4729).
- **Off-hours** changes, or changes by a service/automation account that shouldn't manage groups.

## Confirm it's real privilege

A membership change grants rights; the next privileged logon proves they were used. Chain:

```
4720          (optional) attacker creates an account
4728 / 4732   account added to Domain Admins / local Administrators
4624 + 4672   that account logs on with special privileges
… activity …
4729 / 4733   (optional) removed afterwards to cover tracks
```

The **4672** ("special privileges assigned to new logon") alongside a 4624 for the newly-promoted account is the confirmation that the elevated rights were exercised — see [4672 special privileges](/en/blog/event-id-4672-special-privileges).

## Hunt checklist

- On DCs: filter Security to **4728 / 4756 / 4729 / 4757** and review every Domain/Enterprise Admin change.
- On servers/workstations: filter to **4732 / 4733** for local Administrators and Remote Desktop Users.
- Resolve each **`MemberSid`**; correlate **`SubjectUserName`** to the actor's logon.
- Flag create-then-promote (4720 → 4728/4732), add-then-remove, and any change by a non-admin actor.
- Confirm exercise of rights via 4624 + 4672 for the promoted account.

Group changes are small events with large consequences, which is exactly why attackers like them and why they belong on every "what changed" checklist. Load the DC and host Security logs in the [browser parser](/en/blog/how-to-open-an-evtx-file) and filter to the IDs above.

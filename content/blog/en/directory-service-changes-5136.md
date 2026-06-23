---
title: "Active Directory changes: Event ID 5136 and DCSync (4662)"
description: "Detecting AD persistence and credential-replication attacks in the directory-service logs — 5136 object modifications (ACLs, AdminSDHolder, GPO), the 5137/5141 lifecycle, and using 4662 to catch DCSync."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - active-directory
  - persistence
  - threat-hunting
author: "Florian Amette"
---

Once an attacker reaches a domain controller's level of access, the game moves into **Active Directory itself** — modifying objects for persistence, weakening ACLs, and replicating secrets. Two Security events on the DC catch this: **5136** (a directory object was modified) and **4662** (an operation was performed on an object), the latter being the key to spotting **DCSync**. These are domain-controller events and round out the [account-management coverage](/en/blog/privileged-group-changes-4732).

## The directory-change events (5136 and the lifecycle)

Logged on the DC under **Audit Directory Service Changes**:

| ID | Meaning |
|---:|---------|
| **5136** | a directory object was **modified** (attribute add/delete/replace) |
| 5137 | an object was **created** |
| 5138 / 5139 | object **undeleted / moved** |
| 5141 | an object was **deleted** |

**5136** is the workhorse. Its fields tell you the object (`DN`), the **attribute** changed, the **value**, the **operation** (Value Added / Value Deleted), and the **`SubjectUserName`** who did it.

## What to hunt in 5136

AD persistence and privilege abuse leave specific attribute changes:

- **`nTSecurityDescriptor` changes** — someone modified an object's **ACL**. On high-value objects (the domain root, `AdminSDHolder`, privileged groups), this is how attackers grant themselves durable rights. **`AdminSDHolder`** changes are especially notable: its ACL propagates to all protected (admin) accounts, making it a favourite persistence spot.
- **`scriptPath` / `msTSInitialProgram`** — logon-script or session hijacks.
- **`servicePrincipalName` added** — sets up [Kerberoasting](/en/blog/event-id-4769-kerberoasting) targets or constrained-delegation abuse.
- **`msDS-AllowedToActOnBehalfOfOtherIdentity`** — resource-based constrained delegation, an RBCD attack.
- **`userAccountControl` flips** — disabling pre-auth (AS-REP roasting), enabling delegation, or password-not-required.
- **GPO changes** — modifications to `groupPolicyContainer` objects or GPO links (`gPLink`) push malicious policy domain-wide.

A 5136 changing an ACL or a sensitive attribute on a privileged object, by an account that isn't a known AD admin, is a high-severity lead.

## DCSync: using 4662

**DCSync** abuses the directory-replication protocol to pull password hashes (including `krbtgt`) without touching a DC's disk — it just *asks* AD to replicate secrets. It doesn't generate a logon on the target the way other techniques do; the tell is **Event ID 4662** ("an operation was performed on an object") referencing the **replication extended rights**:

- `DS-Replication-Get-Changes` — `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `DS-Replication-Get-Changes-All` — `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

A **4662 referencing these GUIDs by an account that is not a domain controller** (DCs replicate constantly and legitimately — baseline and exclude them) is the DCSync signature. Hunt for those `Properties` GUIDs with a `SubjectUserName` that isn't a DC machine account.

> Note: 4662 is high-volume and requires SACL-based auditing on the domain object; many environments must enable/scope it deliberately. Where it's off, DCSync may instead be inferred from network detections — but the 4662 GUID hunt is the on-host method.

## Correlate

```
4624 (+4672)   privileged logon to / from a DC-capable context
4662           replication GUIDs requested by a NON-DC account   (DCSync)
… or …
5136           AdminSDHolder / privileged-group ACL modified     (persistence)
4728 / 4732    follow-on group additions enabled by the new ACL
```

DCSync of `krbtgt` is often the prelude to a **Golden Ticket**; an `AdminSDHolder` ACL change is durable persistence that survives group cleanups. Place both on a [timeline](/en/blog/event-log-timeline-incident-response) and pivot to [privileged group changes](/en/blog/privileged-group-changes-4732).

## Hunt checklist

- On **DCs**, filter Security to **5136 / 5137 / 5141** and review changes to ACLs (`nTSecurityDescriptor`), `AdminSDHolder`, SPNs, `userAccountControl`, and GPOs.
- Filter **4662** for the **replication GUIDs** above; exclude DC machine accounts — what remains is DCSync.
- Tie every change to its **`SubjectUserName`** and [logon](/en/blog/windows-logon-events-explained); flag non-admin actors.
- Confirm **Directory Service Changes** auditing (and the relevant SACLs) are enabled — these don't log by default everywhere.

Load the DC Security log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to 5136/4662, and read the attribute / GUID + actor. Full ID set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

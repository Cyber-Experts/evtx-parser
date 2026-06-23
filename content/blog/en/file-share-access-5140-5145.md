---
title: "File share access: Event IDs 5140 and 5145"
description: "Tracking network share and file access in the Security log — 5140 (share accessed) vs 5145 (detailed file share), spotting ADMIN$/C$ lateral movement and data staging, and managing 5145's volume."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - lateral-movement
  - data-access
  - threat-hunting
author: "Florian Amette"
---

When an attacker moves laterally or stages data, they touch **network shares** — the admin shares (`ADMIN$`, `C$`, `IPC$`) for remote execution, and file shares for collection and exfil. The Security log records this access through two events: **5140** (a share was accessed) and **5145** (detailed, per-file access). Used well they map who reached which shares from where; used carelessly, 5145 will drown you. This complements the [lateral-movement guide](/en/blog/detect-lateral-movement-evtx).

## 5140 vs 5145

| | **5140** | **5145** |
|---|----------|----------|
| Granularity | per **share** connection | per **file/object** within a share |
| Audit policy | Audit File Share | Audit **Detailed** File Share |
| Volume | moderate | **very high** |
| Best for | "who connected to which share" | "exactly which files were touched" |

5140 is the manageable overview; 5145 is the magnifying glass you enable when you need to know precisely which files were read or written.

## Reading the events

**5140** key fields:

- **`ShareName`** — `\\*\ADMIN$`, `\\*\C$`, `\\*\IPC$`, or a named file share.
- **`IpAddress`** — the **source** of the connection.
- **`SubjectUserName`** / **`SubjectLogonId`** — who connected.
- **`AccessMask`** — read/write intent.

**5145** adds, per object:

- **`RelativeTargetName`** — the **specific file** path within the share.
- **`AccessMask` / `AccessReason`** — what access was requested and why it was granted.

## The patterns to hunt

- **Admin-share access for lateral movement.** 5140 to **`ADMIN$`** or **`C$`** from another host's `IpAddress`, especially paired with a [service install (4697/7045)](/en/blog/event-id-4697-service-installed) — the PsExec footprint. **`IPC$`** access often precedes remote SCM/WMI operations.
- **Data staging and collection.** 5145 showing one account reading many files across a file share in a short window — bulk collection before exfil.
- **Sensitive shares / paths.** Access to HR, finance, backup, or `SYSVOL`/`NETLOGON` shares by accounts that don't normally touch them.
- **`SYSVOL` access** harvesting GPO files (e.g. cached credentials in legacy `Groups.xml`).
- **Off-hours / unusual source IP** for any admin-share access.

## Correlate to the actor and the host

Share access is always a **network logon**, so it ties to a [4624 type 3](/en/blog/windows-logon-events-explained):

```
4624 type 3      network logon, account + source IP
5140             ADMIN$ accessed from that IP
4697 / 7045      service installed (the payload landed via the share)
4688 / Sysmon 1  SYSTEM execution
```

For data theft instead of execution, the chain is 4624 type 3 → 5140 (file share) → many 5145 (files read) → outbound [network activity](/en/blog/sysmon-network-connection-event-id-3). The source `IpAddress` is the join key back to the originating host.

## Managing 5145's volume

5145 is one of the noisiest Security events — every file touch on an audited share generates one. Practical guidance:

- **Enable Detailed File Share auditing selectively** — on sensitive file servers, or scoped via SACLs to the directories that matter, not everywhere.
- For broad monitoring, rely on **5140** and turn on 5145 on the specific servers under investigation.
- Expect short retention where it's enabled broadly; collect early.

## Hunt checklist

- Filter Security to **5140**; flag **ADMIN$/C$/IPC$** access and **sensitive named shares** by source `IpAddress`.
- Where available, use **5145** `RelativeTargetName` to enumerate the exact files touched.
- Correlate every share access to its [network logon (4624 type 3)](/en/blog/windows-logon-events-explained) and source host.
- Tie admin-share access to [service installs](/en/blog/event-id-4697-service-installed); tie bulk file reads to [outbound network activity](/en/blog/sysmon-network-connection-event-id-3).
- Confirm which shares/servers actually have file-share auditing enabled.

Load the Security log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to 5140/5145, and pivot on `ShareName` + `IpAddress` + `SubjectUserName`. Full ID set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

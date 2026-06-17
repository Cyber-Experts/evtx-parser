---
title: "Building an event-log timeline for incident response"
description: "How to turn scattered .evtx files into one defensible timeline — which events to anchor on, normalising to UTC, correlating across hosts and logs, joining sessions by LogonId, and avoiding the common timelining mistakes."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - timeline
  - incident-response
author: "Florian Amette"
---

Individual events answer small questions. A timeline answers the big one: *what happened, in what order, across which machines.* It is also the deliverable — the artifact an investigation is judged on. This post is how to build one from event logs that holds up, pulling together the threads from across this blog.

## Start from the question, not the data

A timeline is scoped by a question: "trace this account from initial access to objective," "what touched this server between Tuesday and Thursday," "how did they persist." Decide the **subject** (an account, a host, an IP) and the **window** first — it tells you which logs to pull and keeps the timeline from drowning in noise.

## The events worth anchoring on

You rarely need every event. These carry most incident timelines:

| Phase | Anchor events |
|-------|---------------|
| Access | [4624 / 4625](/en/blog/windows-logon-events-explained) (+ logon type), [4768/4769/4771](/en/blog/event-id-4768-kerberos-tgt), 4776 |
| Remote | [RDP 1149 / 4624 type 10 / LSM 21](/en/blog/rdp-forensics-event-logs) |
| Execution | [4688](/en/blog/event-id-4688-process-creation), [Sysmon 1](/en/blog/sysmon-event-id-1-process-create), [PowerShell 4104](/en/blog/powershell-4104-scriptblock) |
| Privilege | [4672](/en/blog/event-id-4672-special-privileges), [4728/4732](/en/blog/privileged-group-changes-4732) |
| Persistence | [4698 / TaskScheduler](/en/blog/scheduled-task-persistence-4698), [7045](/en/blog/service-creation-event-id-7045), [WMI 5861](/en/blog/wmi-persistence-event-logs) |
| Anti-forensics | [1102 / 104](/en/blog/event-id-1102-cleared-log) |

A [rule scan](/en/blog/sigma-rules-evtx-chainsaw-hayabusa) is a good way to find the first anchors; then expand outward in time around each confirmed hit.

## Normalise to UTC — first, always

The most common timelining error is mixing time zones. Every EVTX record stores its time as a [UTC FILETIME](/en/blog/evtx-file-format-reference); tools may *display* local time. Before you merge anything:

- Pin every source to **UTC**.
- Note each host's clock skew if you have it (a host with a wrong clock will scatter events; record the offset and correct).
- Keep sub-second precision when ordering rapid sequences — record IDs break ties when timestamps collide.

A timeline in mixed local times is worse than no timeline; it invents a sequence that didn't happen.

## Correlate across hosts and logs

Real incidents span machines and channels. The joins that matter:

- **`TargetLogonId`** ties a session together on one host: 4624 → 4672 → activity → 4634/4647. It is the strongest within-host join.
- **Source IP / account / time** tie the **DC half** (Kerberos/NTLM validation) to the **host half** (4624) of one logon — see [logon events end to end](/en/blog/windows-logon-events-explained).
- **1024 → 1149** ties the **source** and **destination** of an [RDP hop](/en/blog/detecting-rdp-lateral-movement) across two hosts.
- **Account + time** ties a logon to the [task](/en/blog/scheduled-task-persistence-4698) or [group change](/en/blog/privileged-group-changes-4732) that logon made.

Pull logs from *every* host in scope (and the DC), not just the victim — attackers clean the target and forget the controller.

## Tools for assembly

- **Eric Zimmerman's EvtxECmd → Timeline Explorer.** EvtxECmd flattens EVTX (its maps turn EventData into named columns); Timeline Explorer sorts/filters the combined CSV. The IR workhorse.
- **Hayabusa csv-timeline** for a ranked, cross-file detection timeline ([see the tooling post](/en/blog/sigma-rules-evtx-chainsaw-hayabusa)).
- **Plaso / log2timeline** when you need a *super timeline* that fuses EVTX with filesystem, registry, and other artifacts into one stream.
- **The [browser parser](/en/blog/how-to-open-an-evtx-file)** for reading a specific file's events and its built-in timeline view when you want to eyeball one log without tooling.

## Mind the gaps

A timeline must represent absence honestly:

- **Missing expected events.** No 4624 for a session you can prove happened = suppressed logging or a cleared log, which is itself a timeline entry.
- **Record-ID gaps and a [cleared 1102](/en/blog/event-id-1102-cleared-log)** mark deleted history — annotate the gap; don't silently skip it. The [tampering guide](/en/blog/evtx-tampering-what-survives) covers reading the negative space.
- **Rolled logs.** The small Operational logs (RDP, TaskScheduler) age out fast; "nothing after date X" may mean the log rolled, not that activity stopped.

## A workable process

1. Fix the **subject and window**.
2. Collect logs from **all** in-scope hosts + DC; convert to **UTC**.
3. [Scan with Sigma](/en/blog/sigma-rules-evtx-chainsaw-hayabusa) to find anchors.
4. For each anchor, pull the surrounding events and **join** by LogonId / IP / account / 1024→1149.
5. Lay the confirmed events on one UTC line; **annotate gaps** (clears, rolls, missing events).
6. Write the narrative the timeline supports — and only what it supports.

A good event-log timeline is mostly discipline: one clock, the right anchors, honest gaps. Get those, and the [individual event posts](/en/blog/windows-logon-events-explained) on this blog supply the meaning for each row.

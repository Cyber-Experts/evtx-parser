---
title: "AppLocker event logs: 8003, 8004 and what ran"
description: "Using AppLocker's event logs for DFIR — allowed vs audited vs blocked (8002/8003/8004), the script and MSI channels, and how application-control logs double as an execution record even in audit mode."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - applocker
  - execution
  - threat-hunting
author: "Florian Amette"
---

AppLocker is an application-control feature, but for an investigator its logs are also an **execution record** — every binary, script, and installer that ran (or was stopped) on a controlled host, with the path, hash, and user. Even where AppLocker runs in *audit-only* mode and blocks nothing, it is quietly logging what executed. That makes it a high-value, often-overlooked source. It complements [process creation](/en/blog/event-id-4688-process-creation) and [Sysmon 1](/en/blog/sysmon-event-id-1-process-create).

## The channels

AppLocker splits its logging across channels under `Microsoft-Windows-AppLocker/`:

- **EXE and DLL**
- **MSI and Script**
- **Packaged app-Execution** / **Packaged app-Deployment** (Store/UWP apps)

So "what ran" is spread across logs — collect all of them.

## The event IDs

| ID | Channel | Meaning |
|---:|---------|---------|
| 8002 | EXE and DLL | **allowed** — it ran |
| **8003** | EXE and DLL | **would have been blocked** (audit mode) |
| **8004** | EXE and DLL | **blocked** (enforce mode) |
| 8005 | MSI and Script | allowed |
| **8006** | MSI and Script | would have been blocked (audit) |
| **8007** | MSI and Script | blocked (enforce) |

The fields that matter: the **full file path**, the **file hash**, the **user (SID)**, and the **rule** that matched (or the lack of one). Path + hash + user on every execution is exactly what you want for timelining and IOC matching.

## Audit mode is still gold

A crucial point teams miss: many environments run AppLocker in **audit mode** so it doesn't break anything. In that mode it **blocks nothing** but still logs **8003 / 8006** for everything that *would* have been blocked. That means:

- Every execution outside policy (binaries from `%TEMP%`, `%APPDATA%`, user folders; unsigned tools; LOLBins from odd paths) generates an 8003/8006 — a ready-made "abnormal execution" feed, even though enforcement is off.
- You can reconstruct attacker tooling that ran on the host purely from 8003 events, with paths and hashes.

So don't dismiss an "audit-only" AppLocker config — it's one of the better execution logs you'll find.

## What to hunt

- **8003 / 8006 from user-writable paths** — `%TEMP%`, `%APPDATA%`, `Downloads`, `C:\Users\Public` — execution that policy didn't sanction.
- **8004 / 8007 (enforced blocks)** — something was actively stopped; read what and by whom. A burst of blocks can mark an attacker probing what they can run.
- **Script-host activity** in the MSI and Script channel — `powershell`/`cscript`/`wscript`/`mshta` outside policy.
- **Hash pivots** — take the hash from an 8003 and sweep other hosts' AppLocker/Sysmon logs for the same binary.
- **Renamed LOLBins** — a known-good name from an unusual path; cross-check the hash.

## Caveats

- **Coverage depends on policy.** AppLocker only logs for rule collections that are configured/enabled. If the Script collection isn't enabled, script execution won't appear — know the policy before trusting an empty channel.
- **Volume.** On a busy host the allowed events (8002/8005) are noisy; the would-block/block events (8003/8004/8006/8007) are the high-signal subset.
- **Not a substitute for Sysmon.** AppLocker logs *what executed*, not parent/child lineage or command line — pair it with [Sysmon 1](/en/blog/sysmon-event-id-1-process-create) / [4688](/en/blog/event-id-4688-process-creation) for the full execution story.

## Correlate

```
8003 / 8006   unsanctioned binary/script runs from %APPDATA%  (path + hash + user)
4688 / Sysmon 1   same execution, with parent + command line
Sysmon 3 / 22     it reaches the network
```

AppLocker gives you the clean "this ran and shouldn't have" signal; the process and network events give you the context. Build it on a [timeline](/en/blog/event-log-timeline-incident-response).

## Hunt checklist

- Collect all `Microsoft-Windows-AppLocker/*` channels.
- Filter to **8003 / 8004 / 8006 / 8007**.
- Flag user-writable paths, script hosts, and enforced blocks.
- Pivot on **hash** across hosts; cross-check **renamed LOLBins**.
- Confirm which rule collections are enabled before trusting an empty result.

Load the AppLocker logs in the [browser parser](/en/blog/how-to-open-an-evtx-file) and pivot on path + hash + user. Full ID set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

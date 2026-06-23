---
title: "Event ID 4697: a service was installed (and why it beats 7045)"
description: "The Security-log record of service installation — how 4697 differs from System 7045, the fields that expose malicious services and PsExec-style lateral movement, and why it's the more reliable of the two."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - persistence
  - lateral-movement
  - threat-hunting
author: "Florian Amette"
---

Service creation is a workhorse technique for both **persistence** and **lateral movement** (PsExec and its many clones install a temporary service to run a payload as `SYSTEM`). Most analysts reach for [System log 7045](/en/blog/service-creation-event-id-7045) to catch it — but there is a second, often better record: **Security Event ID 4697**. Knowing both, and when each fires, closes a common blind spot.

## 4697 vs 7045

They record the same act from different subsystems:

| | **7045** | **4697** |
|---|----------|----------|
| Log | System | Security |
| Source | Service Control Manager | Security auditing |
| Always on? | Yes (default) | Needs **Audit Security System Extension** |
| Tampering | cleared with the System log | cleared with the Security log, but [forwarded](/en/blog/event-id-1102-cleared-log) separately |

The practical upshot: **check both**. 7045 is on by default so it's usually present; 4697 requires auditing but, when enabled, lives in the Security log that you're already collecting and forwarding for [logon analysis](/en/blog/windows-logon-events-explained). An attacker who clears one log may leave the other intact.

## Reading 4697

The high-value fields:

- **`ServiceName`** — the service's name. Random strings, single characters, or names mimicking legitimate services are flags (PsExec-style tools often use random or tool-specific names like `PSEXESVC`).
- **`ServiceFileName`** — **the command line / binary path.** This is the payload, and the most important field: look for `cmd.exe /c`, `powershell -enc`, paths in `%TEMP%`/`%ADMIN$%`, or a binary copied to `C:\Windows\` with an odd name.
- **`ServiceType`** — `0x10` (own process) is typical; kernel drivers (`0x1`) installed as services are a BYOVD signal.
- **`ServiceStartType`** — `auto start` means persistence across reboots; `demand start` is more typical of run-once lateral movement.
- **`ServiceAccount`** — usually `LocalSystem` for attacker services (they want `SYSTEM`).
- **`SubjectUserName` / `SubjectLogonId`** — who installed it; tie to the [logon](/en/blog/windows-logon-events-explained).

## The patterns to hunt

- **PsExec-style lateral movement.** A service installed by a [network logon (4624 type 3)](/en/blog/detect-lateral-movement-evtx), with a random `ServiceName`, `demand` start, running a command, then often removed shortly after. Frequently preceded by access to the `ADMIN$` share ([5140](/en/blog/file-share-access-5140-5145)).
- **Persistence services.** `auto` start, `ServiceFileName` pointing at a dropped binary or script — survives reboot.
- **Script-host / LOLBin payloads** in `ServiceFileName` — `powershell`, `cmd /c`, `rundll32`.
- **Driver services** (`ServiceType 0x1`) loading unsigned `.sys` — cross-check [Code Integrity 3076/3077](/en/blog/wdac-code-integrity-3076-3077).
- **Install-then-delete** around an activity window — run-and-clean lateral movement.

## Correlate the lateral-movement chain

```
4624 type 3        network logon from another host (the source)
5140               ADMIN$ / IPC$ share accessed
4697 / 7045        service installed, ServiceFileName = the payload
4688 / Sysmon 1    the SYSTEM process the service spawned
```

That sequence — remote logon → admin share → service install → SYSTEM execution — is the classic remote-exec footprint. The source IP from the 4624 tells you where the operator came from; chain it with the [lateral-movement guide](/en/blog/detect-lateral-movement-evtx).

## Hunt checklist

- Check **both** 4697 (Security) and [7045](/en/blog/service-creation-event-id-7045) (System).
- Read **`ServiceFileName`** for command lines, encoded payloads, and odd paths.
- Flag random/short `ServiceName`s, `LocalSystem` account, and driver-type services.
- Correlate to the installing [logon](/en/blog/windows-logon-events-explained) and to [ADMIN$ access (5140)](/en/blog/file-share-access-5140-5145).
- Look for install-then-delete and `auto`-start persistence.

Load the Security (and System) logs in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to 4697/7045, and read `ServiceFileName`. Full ID set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

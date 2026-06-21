---
title: "Event ID 4616: system time changes and timestomping"
description: "How a changed system clock undermines a timeline, and how Event ID 4616 exposes it — reading PreviousTime vs NewTime, separating benign NTP sync from anti-forensic manipulation, and the process that made the change."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - anti-forensics
  - timeline
  - threat-hunting
author: "Florian Amette"
---

A [timeline](/en/blog/event-log-timeline-incident-response) is only as trustworthy as the clock that stamped it. If an attacker moves the **system clock**, every event written during that window gets a misleading timestamp — and correlation across hosts falls apart. **Event ID 4616** ("The system time was changed") is what catches it. It belongs in the [anti-forensics theme](/en/blog/evtx-tampering-what-survives) right next to [log clearing](/en/blog/event-id-1102-cleared-log) and [audit tampering](/en/blog/audit-policy-tampering-4719).

## Why a clock change matters

EVTX records store time as a [UTC FILETIME](/en/blog/evtx-file-format-reference) taken from the system clock at write time. Move the clock and you can:

- **Backdate or postdate events** to hide *when* something happened.
- **Break cross-host correlation** — the manipulated host no longer lines up with the DC or its peers.
- **Confuse other artifacts** — file `$STANDARD_INFORMATION` times, scheduled tasks, and more are all clock-derived.

Unlike per-file [timestomping](/en/blog/evtx-tampering-what-survives), a system-clock change affects *everything* written in that window — louder, but more destructive to a naive timeline.

## Reading 4616

| Field | Use |
|-------|-----|
| `SubjectUserName` / `SubjectLogonId` | **who/what** changed the time |
| `PreviousTime` | the clock before |
| `NewTime` | the clock after |
| `ProcessName` | the process that made the change |

The `PreviousTime` → `NewTime` delta is the heart of it: a few seconds is routine sync; a jump of hours, days, or backwards in time is not.

## Benign vs suspicious

System time changes constantly for legitimate reasons, so triage on **magnitude and source**:

- **Benign**: small adjustments by `SYSTEM` via the Windows Time service (`ProcessName` of `svchost.exe`/`W32Time`) — NTP keeping drift in check. These are frequent and tiny.
- **Suspicious**: a **large** delta (hours/days), a **backwards** jump, a change by an **interactive user** or a non-time process (`cmd.exe`, `powershell.exe`, a random binary), or a change *immediately around* the activity you're investigating.

Rule of thumb: filter out the small `SYSTEM`/W32Time adjustments and what remains — big jumps, backward moves, user-driven changes — is the candidate set.

## The classic anti-forensic pattern

```
4624 (+4672)   actor logs on with privilege
4616           clock moved back N hours   (ProcessName: cmd.exe, by the user)
… actions performed under the false time …
4616           clock moved forward to correct   (restore, to avoid suspicion)
```

A **back-then-forward** pair around an activity window is a strong manipulation signal — the attacker did something under a false timestamp and reset the clock afterward. The two 4616 events bracket exactly the period whose timestamps you can no longer trust.

## Recovering the real timeline

When you find a 4616 manipulation:

- **Anchor to external time.** The DC, forwarded/SIEM events (stamped on arrival), firewall/proxy logs, and other hosts weren't on the manipulated clock — use them to re-establish true time.
- **Use record IDs for order.** EVTX `EventRecordIdentifier`s increase monotonically regardless of the clock, so even with bad timestamps the *sequence* within a log survives — see the [format reference](/en/blog/evtx-file-format-reference).
- **Flag the window.** Mark every event between the two 4616s as "timestamp suspect" on your timeline rather than trusting it.

## Hunt checklist

- Filter Security to **4616**; exclude small `SYSTEM`/W32Time adjustments.
- Flag **large or backward** `PreviousTime`→`NewTime` deltas.
- Flag changes by **interactive users** or **non-time processes** (`ProcessName`).
- Look for **back-then-forward pairs** bracketing suspicious activity.
- Re-anchor the timeline to **external time sources** and use **record-ID order** within logs.

Load the Security log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to 4616, and read the time delta + `ProcessName`. For the broader picture, see [tampered logs and what survives](/en/blog/evtx-tampering-what-survives) and the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

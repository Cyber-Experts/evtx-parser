---
title: "Sysmon Event ID 3: Network connection detected (C2 hunting)"
description: "Sysmon Event ID 3 logs each TCP/UDP connection with the process that made it. Fields explained, how to spot beaconing and LOLBin traffic, and how to tame the noise."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - sysmon
  - network
  - threat-hunting
author: "Florian Amette"
---

The built-in Security log barely sees the network. [Sysmon](/en/blog/sysmon-configuration-real-adversaries) does — **Event ID 3** records process-to-network connections, tying a TCP/UDP flow to the exact `Image` that made it. That process attribution is what turns "something talked to 185.x.x.x" into "`rundll32.exe` beaconed to 185.x.x.x," which is the difference between a netflow and a lead. This continues the Sysmon series that starts with [Event ID 1](/en/blog/sysmon-event-id-1-process-create).

## The fields that matter

| Field | Use |
|-------|-----|
| `Image` | **the process** that made the connection — the whole point |
| `User` | account context |
| `Protocol` / `Initiated` | TCP/UDP; `Initiated=true` = outbound |
| `SourceIp` / `SourcePort` | local side |
| `DestinationIp` / `DestinationPort` | remote side |
| `DestinationHostname` / `DestinationPortName` | resolved name / service |

`Initiated=true` plus a `DestinationIp` outside your network is the outbound-connection signal most hunts start from.

## What to hunt

- **LOLBins making network connections.** `powershell.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `cscript.exe`, `certutil.exe` connecting outbound is abnormal for most of them — a strong indicator of download/C2. Cross-reference the spawning [4688](/en/blog/event-id-4688-process-creation) / [Sysmon 1](/en/blog/sysmon-event-id-1-process-create).
- **Beaconing.** A process connecting to the same destination on a regular interval (jittered or not) is classic C2. EID 3 timestamps give you the cadence; pair with [DNS queries (EID 22)](/en/blog/sysmon-dns-query-event-id-22) to catch the resolution step.
- **Connections from odd paths.** A binary in `%TEMP%`, `%APPDATA%`, or a user-writable directory making outbound connections.
- **Unexpected listeners / lateral movement.** `Initiated=false` inbound to admin ports, or office hosts talking to each other on RDP/SMB/WinRM ([lateral movement](/en/blog/detect-lateral-movement-evtx)).
- **Service binaries phoning home** that shouldn't.

## Why it's off by default — and noisy

Sysmon network logging is **disabled unless explicitly turned on**, and once on it is one of the highest-volume events Sysmon produces — a busy host generates thousands per minute. Practical consequences:

- **Tune hard.** Good configs (e.g. SwiftOnSecurity / Olaf Hartong modular) filter to the processes that matter and exclude known-good chatter (browsers, update agents). An untuned EID 3 buries the signal.
- **Coverage gaps.** If a config excludes `chrome.exe`/`msedge.exe`, malware living inside a browser process won't show in EID 3 — know your config before trusting an empty result.
- **It rolls fast.** High volume means short retention; collect early.

See [Sysmon configuration for real adversaries](/en/blog/sysmon-configuration-real-adversaries) for getting the signal-to-noise right.

## Correlate, don't isolate

EID 3 is strongest as one link in a chain:

```
Sysmon 1 / 4688   suspicious process starts (e.g. rundll32 from %TEMP%)
Sysmon 22         it resolves a C2 domain
Sysmon 3          it connects outbound to the resolved IP, on a cadence
Sysmon 11         it drops a follow-on payload
```

That sequence is far more convincing than any single event. Build it on a [UTC timeline](/en/blog/event-log-timeline-incident-response).

## Hunt checklist

- Filter Sysmon/Operational to **EID 3**, `Initiated=true`.
- Flag **LOLBins** and **user-writable-path binaries** with outbound connections.
- Look for **periodic** same-destination connections (beaconing).
- Correlate to the spawning process and to [DNS (22)](/en/blog/sysmon-dns-query-event-id-22).
- Confirm your config actually logs the processes you care about.

Load the Sysmon log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to EID 3, and pivot on `Image` + `DestinationIp`. For the full Sysmon set, see the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

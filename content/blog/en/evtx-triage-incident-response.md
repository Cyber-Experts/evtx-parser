---
title: "EVTX triage: what to read first when you have an hour and a host"
description: "A practitioner's order of operations for triaging Windows Event Logs during incident response — which channels matter, which event IDs lie to you, and where Sysmon does the heavy lifting."
date: "2026-05-27"
tags:
  - evtx
  - incident-response
  - windows-event-logs
  - sysmon
  - dfir
author: "Florian Amette"
---

If somebody hands you an EVTX bundle from a host they think is compromised and gives you an hour, you do not have time for elegance. You have time for an order of operations that has worked enough times that you trust it before you have read a single record.

This is mine. It is not the complete reference and it is not the right thing for every case — slow-burn insider investigations need a completely different posture — but for the standard "is this thing popped, and how" question, this is what I run.

## Which channels actually pay back the time

A default Windows install ships with somewhere north of three hundred EVTX channels. You will look at maybe seven of them. The ones that consistently matter:

- `Security.evtx` — logons, privilege use, account changes. The first stop for every interactive incident.
- `Microsoft-Windows-Sysmon%4Operational.evtx` — if Sysmon is deployed (and you should beg, plead, threaten until it is), this is where the real signal lives. Process creates with command lines, file creates, network connections, DNS, image loads. Everything `Security.evtx` gestures at without saying.
- `System.evtx` — service installs, drivers loaded, boot events, time changes. Often the only place lateral movement leaves a service install behind.
- `Application.evtx` — usually noise, but Office macro errors, .NET exceptions and some EDR side-channels surface here.
- `Microsoft-Windows-PowerShell%4Operational.evtx` — module logging and pipeline events, if enabled. The `4104` script block log is where you find every line of malicious PowerShell, assuming the logging was on. It is the second most important channel after Sysmon when both are active.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — scheduled task creation, deletion and execution. Reads short, pays back fast.
- `Microsoft-Windows-WMI-Activity%4Operational.evtx` — WMI subscriptions and consumer registrations. Cheap to read; catches a specific persistence pattern.

If the host has Defender, also grab `Microsoft-Windows-Windows Defender%4Operational.evtx`. The `1116` / `1117` family is sometimes the only contemporaneous mention of the file that mattered.

Everything else you can leave for the second pass.

## The first thing I open is not the Security log

The default reflex is to grep `Security.evtx` for `4624`. I have stopped doing that on the first pass and you probably should too. The Security log on a busy server logs thousands of legitimate logons per hour. You will drown in noise before you have framed the question.

What I open first, when it exists, is `Sysmon%4Operational.evtx` filtered to `EventID=1` (process create) within the suspected window. Sysmon gives you the parent process, the command line as actually invoked, the user, the integrity level, and the hashes of both the parent and the child. That is enough to read a story off the screen.

If Sysmon is not present (and on a depressing number of corporate Windows estates it is still not), my next move is `Security.evtx` filtered to `4688` *with command-line audit enabled*. If command lines are not audited you get the bare program name, which is barely useful — at that point I jump to AmCache, Prefetch and the [USN journal](https://www.usnparser.com) to reconstruct what ran.

The corollary worth saying out loud: an EVTX investigation without Sysmon and without `4688` command lines is mostly a guessing game. If you are reading this in advance of an incident, fix that first.

## The event IDs you stop having to look up

You learn these by rote eventually. The short version, with the way I think about each in IR:

- `4624` — successful logon. Read `LogonType` first: `3` is network (file share, remote tool), `10` is RDP / Terminal Services, `2` is interactive, `9` is `runas` with explicit credentials. `5` is service. The `LogonType` carries more meaning than the event itself.
- `4625` — failed logon. Bursts are spray attacks; isolated ones across many accounts are credential stuffing.
- `4634` / `4647` — logoff and user-initiated logoff. Useful for closing the bracket on a session.
- `4648` — logon with explicit credentials. The one you actually want for lateral movement attribution: when account A uses account B's creds to start a process or connect somewhere, this is the record. Most defenders underuse it.
- `4672` — special privileges assigned at logon. The "this account just became admin" line. Pair with the `4624` it follows.
- `4688` — process create. Useful only when command-line auditing is enabled (Group Policy: *Audit Process Creation* and *Include command line in process creation events*). Without it, you get program names.
- `4697` — service installed. Lateral movement via PsExec, Impacket-`smbexec`, and similar tooling lives here.
- `4720` / `4732` / `4738` — account created, group membership change, account changed. Persistence loves these.
- `1102` — Security log was cleared. If you see this, the rest of the security log up to that point is suspect or absent. The fact that the event exists at all is the smoking gun.
- `5140` / `5145` — network share accessed. The latter logs the file name; if it is on, lateral movement via SMB is auditable in detail.
- `7045` — service installed (System log). Mirrors `4697` but from the System channel.
- `Sysmon 1` — process create with full context. The single most useful event ID in DFIR if Sysmon is on.
- `Sysmon 3` — network connection. Catches outbound C2 even when Defender did not.
- `Sysmon 10` — process access. The one that catches credential dumping from `lsass.exe`.
- `Sysmon 11` — file create. Catches dropper activity that did not get a chance to execute.
- `PowerShell 4104` — script block logging. Records the full text of every PowerShell command, including obfuscated ones (deobfuscated post-decode in many cases).

I keep a printed cheat sheet next to my desk and so should you. It is not glamorous and it saves real minutes.

## The events that lie to you, or are easy to misread

`4624 Type 3` from `\\NT AUTHORITY\ANONYMOUS LOGON` is not "the attacker is in". It is usually a misconfigured share enumeration, a vulnerability scanner, or one of half a dozen Windows internal mechanisms. Validate before you escalate.

`4625` against a single service account at the rate of one per minute is almost always a stale credential cached somewhere. Look at the source workstation field before you call it a brute force.

Timestamps in Security.evtx are local-time on the host that generated them by default in some tooling, UTC in others. When you load a bundle in a new tool, sanity-check by finding a logon you can correlate with a known external event (a ticket update, a VPN session) and confirm offsets. I have seen entire reports skewed by 4 hours because someone forgot to check.

Event log clearing (`1102`) is usually loud, but selective record deletion is a different beast. `wevtutil cl` clears the whole channel, which is detectable. Tools like `phant0m` and `Invoke-Phant0m` instead suspend the event service threads, which leaves no clearing event but creates a visible gap. Look for the gap, not just the `1102`.

Forwarded events (`Microsoft-Windows-EventLog%4ForwardedEvents`) preserve the originating host's RecordID and original timestamps. If you have a WEC subscriber that survived the incident, those copies are sometimes the only intact record left.

If the Security log shows `1100` (event service shutdown) followed by an unexplained gap, you are looking at one of the cleaner attempts to clear evidence. Cross-validate against [registry hives](https://www.registryparser.com), the [Master File Table](https://www.mftparser.com), and Prefetch.

## Carving and recovery, when records are missing

EVTX records can be carved out of unallocated disk and from [pagefile.sys](https://www.pagefilesysparser.com) when the live file has been cleared or rolled over. The record header (`2a 2a 00 00` magic) is distinctive enough that signature carving works reasonably well. Yamato Security's `hayabusa` and `evtx_dump` both handle malformed files with patched-up record streams.

If you are dealing with a host where you suspect the log has been tampered with, also try recovering EVTX records from a [RAM dump](https://www.ramparser.com). The event log service caches recent records in memory; a snapshot taken close to the incident sometimes contains records that never made it to disk.

## Where to go from a hit

A single event rarely closes a case. The pivot points I reach for, in order:

- A suspicious `4624` → look for the matching `4672`, the preceding `4625` failures, and what process created with that token afterwards (Sysmon 1 with matching `LogonId`).
- A `7045` or `4697` service install → check `Microsoft-Windows-TaskScheduler%4Operational.evtx` for follow-on tasks, and the [registry](https://www.registryparser.com) `HKLM\SYSTEM\CurrentControlSet\Services\` for the binary path.
- A Sysmon 10 against `lsass.exe` → process tree of the requesting process, file drops in the working directory, network connections to non-corporate destinations.
- A PowerShell 4104 with obfuscated content → decode in a sandbox, then look for the same payload landing on other hosts (most enterprise actors reuse).

## Reading EVTX in the browser

The [parser on this site](https://www.evtxparser.com) reads EVTX entirely client-side: drop a file in and you get a sortable, filterable table with channel, RecordID, EventID, time, computer and the rendered XML. No upload, which matters because EVTX from regulated environments almost always contains PII you do not want crossing a vendor boundary.

## Further reading

- [JPCERT/CC's "Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/) — the most useful single document on lateral-movement event correlation. Worth a slow read.
- Eric Zimmerman's [EvtxECmd](https://github.com/EricZimmerman/evtx) — offline parser with the canonical field-mapping outputs.
- The Sysmon configuration that Microsoft Threat Intelligence (formerly SwiftOnSecurity) maintains as a baseline: [sysmon-modular](https://github.com/olafhartong/sysmon-modular). Start from this, do not write your own from scratch.

The cynical version of all of the above: with Sysmon and command-line auditing, EVTX gives you 80% of what you need to reconstruct an intrusion. Without them, you are doing forensics on the silhouette of the event rather than the event itself.

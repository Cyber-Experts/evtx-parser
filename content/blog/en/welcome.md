---
title: "Start here: a DFIR analyst's guide to .evtx"
description: "What .evtx is, which channels matter, the Event IDs to know, and where to find each one on disk. A navigational starting point for everything else on this blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` is the binary Windows Event Log format Microsoft shipped with Vista to replace the older `.evt`. It is the spine of every Windows incident response: logons, service installs, scheduled tasks, PowerShell command lines, Sysmon process trees. All of it serialises into this format. This post is the index. A one-screen orientation, then links to the deeper posts on the channels and Event IDs that actually matter on a case.

New to `.evtx`? Start with [what an .evtx file is](/en/blog/what-is-an-evtx-file) and [how to open one](/en/blog/how-to-open-an-evtx-file). The rest of this post assumes you are already comfortable with the format and want to know what to read first when a host is on fire.

## Where the files live

Live logs sit under `C:\Windows\System32\winevt\Logs\`. One channel, one `.evtx` file. The defaults you will always have:

- `Security.evtx`. Logons, privilege use, audit policy changes. Highest forensic value on most cases.
- `System.evtx`. Drivers, services, OS-level errors.
- `Application.evtx`. Application-level errors.
- `Setup.evtx` and `ForwardedEvents.evtx`. Install records and forwarded WEF traffic.

Plus per-application channels under `Microsoft-Windows-*`. The ones that earn their keep on a case:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Only present if Sysmon is installed. Worth gold when it is.
- `Microsoft-Windows-PowerShell%4Operational.evtx`. Scriptblock and module logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Scheduled task creates and runs.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. RDP session lifecycle.

For deep details on how a file is laid out (the 64 KB chunks, the XML template tables, BinXML), see [the chunk-level deep dive](/en/blog/evtx-file-format-chunks).

## The Event IDs to know

The shortlist that covers most of what an analyst pivots on:

- [**4624** successful logon](/en/blog/understanding-event-id-4624). Read it through `LogonType`. The field decides whether you are looking at console (2), network (3), RDP (10), or `runas /netonly` (9).
- [**4625** failed logon](/en/blog/detecting-4625-brute-force). Bursts are reconnaissance, brute force, or password spray depending on which fields cluster.
- [**1102** Security log cleared](/en/blog/event-id-1102-cleared-log). If you see this, the log you are holding has a known gap. Note it loudly.
- [**4104** PowerShell scriptblock](/en/blog/powershell-4104-scriptblock). The script body *after* decoding and reflection. The single most useful free defensive control on the platform.
- [**7045** service installed](/en/blog/service-creation-event-id-7045). One of MITRE ATT&CK's most-cited persistence techniques (T1543.003). Also the PsExec signature.
- [**Sysmon 1** process create](/en/blog/sysmon-event-id-1-process-create). Richest process-creation record Windows can produce when Sysmon is present.

For the workflow that ties them together, read [EVTX triage when you have an hour and a host](/en/blog/evtx-triage-incident-response).

## How this site fits

The parser on the home page is the Rust crate [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compiled to WebAssembly and run inside a Web Worker. You drop an `.evtx`, the worker walks the chunks, and you get a filterable event timeline plus per-record XML. All in the browser, nothing uploaded. Use it for ad-hoc triage when you do not want to spin up an EDR or move a file off a system you do not own.

If you are [collecting `.evtx` from a live host](/en/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), that post covers the four standard methods with the chain-of-custody trade-offs each makes.

EVTX is rarely the only artifact you need. Pair it with [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), [Shimcache](https://www.shimcacheparser.com), [prefetch](https://www.prefetchparser.com), and [LNK](https://www.lnkparser.com) parsers. When you need to dig deeper, [pagefile](https://www.pagefilesysparser.com) and [RAM dump](https://www.ramparser.com) parsing recover what disk-resident logs lost. For user-activity timelines, [SRUM](https://www.srumparser.com), [jump lists](https://www.jumplistparser.com), [recycle bin](https://www.recyclebinparser.com), [recent file cache](https://www.recentfilecacheparser.com), and [browser history](https://www.browserforensics.app) fill the gaps EVTX cannot fill.

---
title: "Start here: a DFIR analyst's guide to .evtx"
description: "What .evtx is, which channels matter, the Event IDs to know, and where to find each one on disk — a navigational starting point for everything else on this blog."
date: "2026-05-16"
updated: "2026-05-24"
---

`.evtx` is the binary Windows Event Log format Microsoft shipped with Windows Vista to replace the older `.evt`. It's the spine of every Windows incident response: logons, service installs, scheduled tasks, PowerShell command lines, and Sysmon process trees all serialise into it. This post is the index — a one-screen orientation, then links to the deeper posts on the channels and Event IDs that actually matter on a case.

New to `.evtx`? Start with [what an .evtx file is](/en/blog/what-is-an-evtx-file) and [how to open one](/en/blog/how-to-open-an-evtx-file). The rest of this post is the channel-and-Event-ID orientation for analysts already comfortable with the format.

## Where the files live

Live logs sit under `C:\Windows\System32\winevt\Logs\`. Each channel is one `.evtx` file. The defaults you'll always have:

- `Security.evtx` — logons, privilege use, audit policy changes. Highest forensic value on most cases.
- `System.evtx` — drivers, services, OS-level errors.
- `Application.evtx` — application-level errors.
- `Setup.evtx` / `ForwardedEvents.evtx` — install records and forwarded WEF traffic.

Plus per-application channels under `Microsoft-Windows-*` — the ones that earn their keep on a case:

- `Microsoft-Windows-Sysmon%4Operational.evtx` — only present if Sysmon is installed, but worth gold when it is.
- `Microsoft-Windows-PowerShell%4Operational.evtx` — scriptblock + module logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — scheduled task creates/runs.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` — RDP session lifecycle.

For deep details on how a file is laid out — the 64 KB chunks, the XML template tables, BinXML — see [Inside the EVTX file format](/en/blog/evtx-file-format-chunks).

## The Event IDs to know

The shortlist that covers most of what an analyst pivots on:

- [**4624** — successful logon](/en/blog/understanding-event-id-4624). Read it through `LogonType`; the field decides whether you're looking at console (2), network (3), RDP (10), or `runas /netonly` (9).
- [**4625** — failed logon](/en/blog/detecting-4625-brute-force). Bursts are reconnaissance, brute force, or password spray depending on which fields cluster.
- [**1102** — Security log cleared](/en/blog/event-id-1102-cleared-log). If you see this, the log you're holding has a known gap; note it loudly.
- [**4104** — PowerShell scriptblock](/en/blog/powershell-4104-scriptblock). The script body *after* decoding/reflection. The single most useful free defensive control on the platform.
- [**7045** — service installed](/en/blog/service-creation-event-id-7045). One of MITRE ATT&CK's most-cited persistence techniques (T1543.003). Also the PsExec signature.
- [**Sysmon 1** — process create](/en/blog/sysmon-event-id-1-process-create). Richest process-creation record Windows can produce — when Sysmon is present.

## How this site fits

[The parser on the home page](/en) is the Rust crate [omerbenamram/evtx](https://github.com/omerbenamram/evtx) compiled to WebAssembly and run inside a Web Worker. You drop an `.evtx`, the worker walks the chunks, and you get a filterable event timeline plus per-record XML — all in the browser, nothing uploaded. Use it for ad-hoc triage when you don't want to spin up an EDR or move a file off a system you don't own.

If you're [collecting `.evtx` from a live host](/en/blog/collecting-evtx-from-live-system) (KAPE, FTK Imager, `wevtutil`), that post covers the four standard methods with the chain-of-custody trade-offs each one makes.

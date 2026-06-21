---
title: "Sysmon Event IDs 8 and 10: process injection and LSASS access"
description: "Detecting code injection and credential theft with Sysmon — CreateRemoteThread (8) and ProcessAccess (10), reading GrantedAccess masks against lsass.exe, and using the call trace to find unsigned modules."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - sysmon
  - credential-theft
  - threat-hunting
author: "Florian Amette"
---

Two Sysmon events catch some of the most important attacker behaviour there is: **process injection** and **credential theft from LSASS**. Event ID **8 (CreateRemoteThread)** and Event ID **10 (ProcessAccess)** both watch one process reaching into another — the building blocks of injection and of dumping `lsass.exe`. Neither shows up in process-creation logging, which is exactly why attackers rely on them and why these events earn their volume. Part of the Sysmon series ([starts here](/en/blog/sysmon-event-id-1-process-create)).

## Event ID 8 — CreateRemoteThread

Fires when a process creates a thread in **another** process — the textbook injection primitive.

| Field | Use |
|-------|-----|
| `SourceImage` | the injector |
| `TargetImage` | the victim process |
| `StartAddress` / `StartModule` / `StartFunction` | where the new thread begins |

Hunt for:

- A user-land or odd-path `SourceImage` creating threads in `explorer.exe`, `svchost.exe`, `lsass.exe`, or browsers.
- A `StartModule` that is **blank/unbacked** (memory not backed by a file on disk) — shellcode injection often shows no module.
- Office apps or script hosts (`winword.exe`, `wscript.exe`, `powershell.exe`) as the `SourceImage`.

Legitimate software does inject (some AV/EDR, debuggers), so baseline your environment — but `SourceImage` → `TargetImage` pairs that don't match known tooling are leads.

## Event ID 10 — ProcessAccess (and LSASS)

Fires when a process **opens a handle** to another process. Its headline use is catching **credential dumping**: something opening `lsass.exe` with rights to read its memory.

| Field | Use |
|-------|-----|
| `SourceImage` | who opened the handle |
| `TargetImage` | the target — **watch for `lsass.exe`** |
| `GrantedAccess` | **the access mask** — the key signal |
| `CallTrace` | the stack of modules that led to the access |

### Reading GrantedAccess against lsass.exe

The access mask tells you *what* the caller could do. Masks associated with reading LSASS memory (credential theft) include values such as **`0x1010`**, **`0x1410`**, and **`0x143a`** (combinations of `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`, etc.). The exact value varies by tool and Windows version, so treat them as strong indicators rather than a fixed allow/deny list — *any* non-EDR process opening `lsass.exe` with read/VM-read rights deserves investigation.

### The call trace is gold

`CallTrace` lists the modules on the stack at the moment of access. The tell: an entry marked **`UNKNOWN`** (memory not backed by a DLL on disk) in a call trace that touches `lsass.exe` — that's code running from injected/allocated memory reaching for credentials. A trace that is entirely signed system DLLs from a known security product is the benign case.

## What makes these noisy (and how to cope)

- Both are **off by default**; EID 10 in particular is high-volume because legitimate software opens handles constantly. Real configs scope EID 10 tightly — most usefully to **`TargetImage` = `lsass.exe`** — which turns a firehose into a high-signal feed. See [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries).
- EDR products legitimately access LSASS; build an allowlist of your security tooling's `SourceImage`s so their access doesn't drown real hits.

## Correlate to the kill chain

```
Sysmon 1 / 4688   suspicious process (e.g. from %TEMP%, or a script host)
Sysmon 8          it injects a thread into a trusted process
Sysmon 10         that process opens lsass.exe with VM_READ  (CallTrace: UNKNOWN)
Sysmon 11         a dump file is written to disk
Sysmon 3          credentials/data exfiltrated
```

Injection (8) into a trusted process followed by LSASS access (10) with an unbacked call trace is one of the highest-confidence sequences in the whole event log. Lay it on a [timeline](/en/blog/event-log-timeline-incident-response) and pivot to the [logon events](/en/blog/windows-logon-events-explained) the stolen creds get used in.

## Hunt checklist

- Filter Sysmon/Operational to **EID 10** with `TargetImage` ending `lsass.exe`; review every non-EDR `SourceImage`.
- Inspect `GrantedAccess` for VM-read-class masks (`0x1010`/`0x1410`/`0x143a`-style) and `CallTrace` for `UNKNOWN` frames.
- Filter **EID 8** for injections into `explorer/svchost/lsass`/browsers, especially unbacked `StartModule`.
- Allowlist your EDR/AV `SourceImage`s; everything else is a lead.

Open the Sysmon log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to EID 10 + `lsass.exe`, and read `GrantedAccess`/`CallTrace`. Full Sysmon map in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

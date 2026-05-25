---
title: "What is an .evtx file? Windows Event Log format explained"
description: "An .evtx file is a binary Windows Event Log. Where they live, what's inside one, how they differ from .evt, and how to open them — without installing anything."
date: "2026-05-24"
faq:
  - question: "What is an .evtx file?"
    answer: "An .evtx file is the binary Windows Event Log format introduced with Windows Vista. It stores system, security and application events written by the EventLog service. Each Windows machine has dozens of .evtx files under C:\\Windows\\System32\\winevt\\Logs\\, one per channel."
  - question: "Where are .evtx files stored on Windows?"
    answer: "The default location is C:\\Windows\\System32\\winevt\\Logs\\. The three high-traffic files are Security.evtx, System.evtx and Application.evtx. Per-application channels live in the same folder under names like Microsoft-Windows-Sysmon%4Operational.evtx."
  - question: "What's the difference between .evtx and .evt?"
    answer: ".evt is the legacy binary format Windows used through XP and Server 2003. .evtx replaced it in Windows Vista (2007) with a chunked, BinXML-based layout that supports richer event metadata, larger logs, and structured queries via wevtutil and Get-WinEvent. The two formats are not interchangeable."
  - question: "How do I open an .evtx file?"
    answer: "Built-in Windows tools: Event Viewer (eventvwr.msc), wevtutil from the command line, or Get-WinEvent from PowerShell. Cross-platform: open it in the browser-based parser on this site (no install, no upload), or use evtxecmd on the command line. See our how-to-open-an-evtx-file post for all the options."
  - question: "Can I open an .evtx file on macOS or Linux?"
    answer: "Yes. The native Windows tools won't work, but several cross-platform parsers do: the browser-based parser on this site (any OS with a modern browser), python-evtx, the Rust evtx crate, and evtxecmd via mono. None of them require a Windows host."
---

An `.evtx` file is the binary Windows Event Log format that Microsoft shipped with Windows Vista in 2007 to replace the older `.evt` format. Every event the operating system, a driver, a service, or an application writes to the Windows Event Log lands in an `.evtx` file on disk. They are the backbone of every Windows investigation.

## Quick answer

`.evtx` files are written by the Windows EventLog service to `C:\Windows\System32\winevt\Logs\`. There is one file per **channel** (`Security.evtx`, `System.evtx`, `Application.evtx`, plus per-application channels). Internally each file is a chunked binary container of `BinXML`-encoded records — not plain text. You read them with Event Viewer, `wevtutil`, `Get-WinEvent`, or a third-party parser.

## Where .evtx files live

The standard location on every supported Windows version (Vista through Windows 11 / Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Each `.evtx` file maps to one event channel. The defaults you will always find:

- `Security.evtx` — logons, privilege use, audit policy changes. Highest forensic value on most cases.
- `System.evtx` — drivers, services, kernel-level errors.
- `Application.evtx` — application-level errors and informational events.
- `Setup.evtx` — install records.
- `ForwardedEvents.evtx` — events collected from other hosts via Windows Event Forwarding (WEF).

Per-application channels are stored in the same folder with `%4` standing in for the path separator:

- `Microsoft-Windows-Sysmon%4Operational.evtx` — Sysmon process, network and file events (when installed).
- `Microsoft-Windows-PowerShell%4Operational.evtx` — PowerShell scriptblock + module logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx` — scheduled task creates and runs.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` — RDP session lifecycle.

Rotated channels produce timestamped archive files in the same folder (`Security.evtx`, `Archive-Security-2026-05-23-…evtx`). The active file is held open by the EventLog service while Windows is running.

## What's inside an .evtx file

The file is a binary container, not plain text. A 4 KB header (magic `ElfFile\0`) is followed by a sequence of 64 KB **chunks**. Each chunk has its own header (`ElfChnk`), a table of the XML **templates** that appear inside it, and a stream of records that reference those templates by ID. A parser reconstructs each event by substituting record-level values into the template's placeholders — this is what makes `.evtx` more compact than literal XML on disk.

Once decoded, every record is an XML document with two halves:

- `<System>` — provider name, channel, Event ID, level (1 Critical → 5 Verbose), computer name, security context, and UTC write timestamp.
- `<EventData>` — provider-specific parameters: the target account on a logon, the image path on a process create, the registry key on an audited write, and so on.

The Event ID alone is rarely enough for triage. The forensic signal lives in `<EventData>`. For the deep-format mechanics — chunks, BinXML, templates, dirty-chunk recovery — see [Inside the EVTX file format](/en/blog/evtx-file-format-chunks).

## .evtx vs .evt: why the format changed

The legacy `.evt` format Windows used through XP and Server 2003 had three hard limits the new format was designed to fix:

- **Fixed-size strings.** `.evt` records carried message-table references rather than the full message; render-time joins broke when source DLLs were missing or upgraded.
- **No structured querying.** Filtering required reading and parsing every record linearly.
- **Single channel per file.** Custom application logs needed their own non-standard formats.

`.evtx` (Vista, 2007) introduced BinXML records, per-channel files with arbitrary nesting, XPath-style filtering via `wevtutil qe` and `Get-WinEvent -FilterHashtable`, and a chunked layout that survives partial writes. The trade-off was a complete break in compatibility — `.evt` and `.evtx` are not interchangeable, and the only built-in tool that reads `.evt` on a modern Windows is `wevtutil` with the legacy flag (and only for export to `.evtx`).

## How to open an .evtx file

Five common paths, in rough order of friction:

1. **In your browser, no install** — drop the file into the parser on the home page of this site. It runs the Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate compiled to WebAssembly inside a Web Worker. Nothing leaves your machine. Right for ad-hoc triage when you do not want to spin up a forensic VM.
2. **Event Viewer (`eventvwr.msc`)** — the built-in Windows GUI. Open Event Viewer → Action → Open Saved Log… → select the `.evtx`. Good for browsing, weak for filtering at scale.
3. **`wevtutil` / `Get-WinEvent`** — command-line and PowerShell, both ship with Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` dumps every record; `Get-WinEvent -Path` returns objects you can pipe into `Where-Object`.
4. **EvtxECmd** — Eric Zimmerman's parser. Cross-platform via .NET, fast, produces CSV with one row per record and the full `<EventData>` flattened.
5. **`python-evtx`** — pure-Python, easy to script. Slower than the Rust crate but useful when you already have a Python tooling chain.

For a full walkthrough of each method with the commands you would actually run, see [How to open an .evtx file](/en/blog/how-to-open-an-evtx-file).

## When you encounter .evtx in the wild

- **Incident response.** Pulled from a compromised host as part of triage. Channels of interest depend on the lead — `Security` for logons and privilege abuse, `Sysmon` for process trees, `PowerShell` for scriptblock content.
- **Compliance audits.** Auditors request `Security.evtx` over a defined window to verify logon and policy-change history.
- **Application debugging.** `Application.evtx` plus per-vendor channels often hold crash and error context the application's own logs don't.
- **Threat hunting.** Long-tail rules against archived `.evtx` (or a SIEM forwarding the live channel) catch slow-burn patterns like off-hours RDP or service-account `LogonType` drift.

The single most useful pivot is the Event ID. For the shortlist that earns its keep in a real SOC — [4624 successful logon](/en/blog/understanding-event-id-4624), [4625 failed logon](/en/blog/detecting-4625-brute-force), [1102 log cleared](/en/blog/event-id-1102-cleared-log), [4104 PowerShell scriptblock](/en/blog/powershell-4104-scriptblock), [7045 service installed](/en/blog/service-creation-event-id-7045), [Sysmon 1 process create](/en/blog/sysmon-event-id-1-process-create) — see [the start-here orientation](/en/blog/welcome).

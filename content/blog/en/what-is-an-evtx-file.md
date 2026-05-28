---
title: "What is an .evtx file? Windows Event Log format explained"
description: "An .evtx file is a binary Windows Event Log. Where they live, what is inside one, how they differ from .evt, and how to open them. No install required."
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
    answer: "Yes. The native Windows tools won't work, but several cross-platform parsers do: the browser-based parser on this site (any OS with a modern browser), python-evtx, the Rust evtx crate, and evtxecmd via .NET. None of them require a Windows host."
---

An `.evtx` file is the binary Windows Event Log format Microsoft shipped with Vista in 2007 to replace the older `.evt`. Every event the operating system, a driver, a service, or an application writes to the Windows Event Log lands in an `.evtx` file on disk. They are the backbone of every Windows investigation. If you do DFIR on Windows, you will spend more time inside these files than any other artifact class.

## Quick answer

`.evtx` files are written by the Windows EventLog service to `C:\Windows\System32\winevt\Logs\`. One file per **channel** (`Security.evtx`, `System.evtx`, `Application.evtx`, plus per-application channels). Internally each file is a chunked binary container of `BinXML`-encoded records. Not plain text. You read them with Event Viewer, `wevtutil`, `Get-WinEvent`, or a third-party parser.

## Where .evtx files live

Standard location on every supported Windows version (Vista through Windows 11 and Server 2025):

```text
C:\Windows\System32\winevt\Logs\
```

Each `.evtx` file maps to one event channel. The defaults:

- `Security.evtx`. Logons, privilege use, audit policy changes. Highest forensic value on most cases.
- `System.evtx`. Drivers, services, kernel-level errors.
- `Application.evtx`. Application-level errors and informational events.
- `Setup.evtx`. Install records.
- `ForwardedEvents.evtx`. Events collected from other hosts via Windows Event Forwarding (WEF).

Per-application channels are stored in the same folder with `%4` standing in for the path separator:

- `Microsoft-Windows-Sysmon%4Operational.evtx`. Sysmon process, network, and file events (when installed).
- `Microsoft-Windows-PowerShell%4Operational.evtx`. PowerShell scriptblock and module logging.
- `Microsoft-Windows-TaskScheduler%4Operational.evtx`. Scheduled task creates and runs.
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`. RDP session lifecycle.

Rotated channels produce timestamped archive files in the same folder (`Security.evtx`, `Archive-Security-2026-05-23-...evtx`). The active file is held open by the EventLog service while Windows is running, which is the entire reason there is a [collection post about getting these files off a live host](/en/blog/collecting-evtx-from-live-system).

## What is inside an .evtx file

The file is a binary container, not plain text. A 4 KB header (magic `ElfFile\0`) is followed by a sequence of 64 KB **chunks**. Each chunk has its own header (`ElfChnk`), a table of the XML **templates** that appear inside it, and a stream of records that reference those templates by ID. A parser reconstructs each event by substituting record-level values into the template's placeholders. This is what makes `.evtx` more compact than literal XML on disk.

Once decoded, every record is an XML document with two halves:

- `<System>`. Provider name, channel, Event ID, level (1 Critical through 5 Verbose), computer name, security context, and UTC write timestamp.
- `<EventData>`. Provider-specific parameters: the target account on a logon, the image path on a process create, the registry key on an audited write, and so on.

The Event ID alone is rarely enough for triage. The forensic signal lives in `<EventData>`. For the deep format mechanics (chunks, BinXML, templates, dirty-chunk recovery) see [the chunk-level deep dive](/en/blog/evtx-file-format-chunks).

## .evtx vs .evt: why the format changed

The legacy `.evt` format Windows used through XP and Server 2003 had three hard limits the new format was designed to fix:

- **Fixed-size strings.** `.evt` records carried message-table references rather than the full message. Render-time joins broke when source DLLs were missing or upgraded.
- **No structured querying.** Filtering required reading and parsing every record linearly.
- **Single channel per file.** Custom application logs needed their own non-standard formats.

`.evtx` (Vista, 2007) introduced BinXML records, per-channel files with arbitrary nesting, XPath-style filtering via `wevtutil qe` and `Get-WinEvent -FilterHashtable`, and a chunked layout that survives partial writes. The trade-off was a complete break in compatibility. `.evt` and `.evtx` are not interchangeable, and the only built-in tool that reads `.evt` on a modern Windows is `wevtutil` with the legacy flag (and only for export to `.evtx`).

## How to open an .evtx file

Five common paths, in rough order of friction:

1. **In your browser, no install.** Drop the file onto the parser on the home page of this site. It runs the Rust [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate compiled to WebAssembly inside a Web Worker. Nothing leaves your machine. Right for ad-hoc triage when you do not want to spin up a forensic VM.
2. **Event Viewer (`eventvwr.msc`).** Built-in Windows GUI. Action / Open Saved Log / select the `.evtx`. Good for browsing, weak for filtering at scale.
3. **`wevtutil` / `Get-WinEvent`.** Command line and PowerShell, both ship with Windows. `wevtutil qe path\to\file.evtx /f:text /lf:true` dumps every record. `Get-WinEvent -Path` returns objects you can pipe into `Where-Object`.
4. **EvtxECmd.** Eric Zimmerman's parser. Cross-platform via .NET, fast, produces CSV with one row per record and `<EventData>` flattened.
5. **`python-evtx`.** Pure Python, easy to script. Slower than the Rust crate but useful when you already have a Python tooling chain.

For a full walkthrough of each with the commands you would actually run, see [How to open an .evtx file](/en/blog/how-to-open-an-evtx-file).

## When you encounter .evtx in the wild

- **Incident response.** Pulled from a compromised host as part of triage. Channels of interest depend on the lead: `Security` for logons and privilege abuse, `Sysmon` for process trees, `PowerShell` for scriptblock content. Pair with [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com), [AmCache](https://www.amcacheparser.com), and [prefetch](https://www.prefetchparser.com) for execution corroboration.
- **Compliance audits.** Auditors request `Security.evtx` over a defined window to verify logon and policy-change history.
- **Application debugging.** `Application.evtx` plus per-vendor channels often hold crash and error context the application's own logs do not.
- **Threat hunting.** Long-tail rules against archived `.evtx` (or a SIEM forwarding the live channel) catch slow-burn patterns like off-hours RDP or service-account `LogonType` drift.

The single most useful pivot is the Event ID. For the shortlist that earns its keep in a real SOC ([4624](/en/blog/understanding-event-id-4624), [4625](/en/blog/detecting-4625-brute-force), [1102](/en/blog/event-id-1102-cleared-log), [4104](/en/blog/powershell-4104-scriptblock), [7045](/en/blog/service-creation-event-id-7045), [Sysmon 1](/en/blog/sysmon-event-id-1-process-create)) see [the start-here orientation](/en/blog/welcome).

## Further reading

- [Microsoft documentation: Windows Event Log](https://learn.microsoft.com/en-us/windows/win32/wes/windows-event-log)
- [libevtx EVTX format specification](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc)
- [omerbenamram/evtx (Rust parser)](https://github.com/omerbenamram/evtx)

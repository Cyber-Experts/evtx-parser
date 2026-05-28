---
title: "How to open an .evtx file (5 methods, no install required)"
description: "Five ways to open a Windows .evtx file: in your browser, in Event Viewer, with wevtutil, with EvtxECmd, or with python-evtx. Pick by host OS and how much friction you can stomach."
date: "2026-05-24"
howto:
  name: "How to open an .evtx file"
  steps:
    - name: "Open it in your browser (no install)"
      text: "Go to the EVTX parser home page, drop your .evtx file onto the upload zone. The file is parsed locally in a Web Worker using a Rust EVTX parser compiled to WebAssembly. Nothing is uploaded. Works on Windows, macOS and Linux."
    - name: "Open it in Event Viewer (Windows only)"
      text: "Launch eventvwr.msc, choose Action then Open Saved Log, browse to the .evtx file, name the view, and click OK. Good for browsing one channel; weak for filtering across thousands of records."
    - name: "Dump it with wevtutil or Get-WinEvent (Windows command line)"
      text: "Run wevtutil qe \"C:\\path\\Security.evtx\" /lf:true /f:text > out.txt to export every record as text. From PowerShell, Get-WinEvent -Path .\\Security.evtx | Where-Object Id -eq 4624 returns parsed objects you can pipe further."
    - name: "Parse it with EvtxECmd (cross-platform CLI)"
      text: "Download EvtxECmd from Eric Zimmerman's tools, then run EvtxECmd.exe -f Security.evtx --csv out\\ --csvf parsed.csv to flatten every record (including all EventData fields) into one CSV row per event."
    - name: "Script it with python-evtx (cross-platform Python)"
      text: "pip install python-evtx, then run python -m Evtx.evtx_dump path\\to\\file.evtx > out.xml to get every record as XML on stdout. Slower than the Rust parser but easy to embed in pipelines and Jupyter notebooks."
---

An `.evtx` file is the binary Windows Event Log format ([what is inside one](/en/blog/what-is-an-evtx-file)). You cannot read it with a text editor. It is BinXML inside chunked binary containers. There are five methods that cover every realistic case, in rough order from "drop the file and you are done" to "wire it into a Python pipeline".

## Method 1: open it in your browser, no install

The fastest path on any operating system. Drop the `.evtx` onto the parser on the [home page of this site](/en). The file is read into your browser's memory and parsed locally by a Web Worker running the [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate compiled to WebAssembly. Nothing leaves your machine. Confirm by disconnecting from the network before you drop the file.

You get the same record-level view a desktop tool produces: filterable timeline, full `<EventData>` flattened into the table, full XML one click away, CSV/JSON export of the filtered set. Right for ad-hoc triage when you do not want to install anything, do not want to upload anything, or you are on a machine that is not yours.

Constraint. Browser memory caps mean files larger than around 500 MB get slow. For multi-gigabyte archived logs, drop down to a native tool.

## Method 2: Event Viewer, Windows only, built in

Every Windows install ships with Event Viewer. Launch `eventvwr.msc`, then **Action / Open Saved Log** and pick the `.evtx`. Event Viewer offers to import the file into your current view. Accept and you can browse it like any live channel.

```text
Action -> Open Saved Log -> Browse -> select .evtx -> OK
```

Good for browsing a single file, looking at one record's friendly-formatted message, copy-pasting an XML view. Weak for filtering thousands of records (the UI gets slow), bulk export, or running queries you want to script. Also strictest about dirty trailing chunks: it will refuse files other tools accept.

## Method 3: wevtutil and Get-WinEvent, Windows command line

`wevtutil` is the Windows built-in for log management. `Get-WinEvent` is its PowerShell counterpart. Both work on saved `.evtx` files, not just live channels.

Dump every record from a saved `.evtx` to text:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /f:text > security.txt
```

Filter with XPath. Every 4624 in the last 24 hours:

```cmd
wevtutil qe "C:\triage\Security.evtx" /lf:true /q:"*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]]]" /f:text
```

PowerShell with the same intent, but returning typed objects:

```powershell
Get-WinEvent -Path C:\triage\Security.evtx |
  Where-Object { $_.Id -eq 4624 } |
  Select-Object TimeCreated, Id, @{n='User';e={$_.Properties[5].Value}}
```

Good for scripted extraction, scheduled jobs, surgical filtering. The trade-off is verbosity. XPath against XML is precise but not friendly.

## Method 4: EvtxECmd, the DFIR standard

[Eric Zimmerman's `EvtxECmd`](https://ericzimmerman.github.io/) is the parser most IR practitioners default to. It runs natively on Windows and on macOS / Linux under .NET. It parses faster than `wevtutil` and flattens every `<EventData>` field into a CSV column. One row per record.

```cmd
EvtxECmd.exe -f Security.evtx --csv out --csvf parsed.csv
```

For a whole `winevt\Logs\` folder in one pass, with maps that decode well-known event fields into friendly columns:

```cmd
EvtxECmd.exe -d "C:\triage\winevt\Logs" --csv out --csvf all.csv --maps "C:\Tools\EvtxECmd\Maps"
```

Right for bulk parse of multi-file collections, importing to a SIEM or notebook, cross-platform analyst workflow. EvtxECmd is the right answer for almost every "parse this offline" task. Pair it with KAPE's `EventLogs` target and you have a one-command engagement.

## Method 5: python-evtx, script it into a pipeline

When the file needs to feed a Python pipeline, [`python-evtx`](https://github.com/williballenthin/python-evtx) is the pure-Python parser.

```bash
pip install python-evtx
python -m Evtx.evtx_dump path/to/file.evtx > out.xml
```

In a notebook or script:

```python
from Evtx.Evtx import Evtx
with Evtx("Security.evtx") as log:
    for record in log.records():
        xml = record.xml()
        ...
```

Slower than the Rust crate (interpreted Python on binary chunks) but the right call when you are already inside a Python toolchain: Jupyter forensic notebooks, threat-hunting jobs, custom enrichment, joining EVTX data to [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN](https://www.usnparser.com), or [prefetch](https://www.prefetchparser.com) artifacts from the same case.

## Which method to use when

- You just want to look at the file: drop it on the [home page parser](/en). Fastest, zero install.
- Windows endpoint with admin and the file is small: Event Viewer.
- Scripted one-off extraction: `wevtutil` or `Get-WinEvent`.
- Real DFIR on multi-channel collections: EvtxECmd.
- Building a pipeline in Python: `python-evtx`.

## Common errors and how to read them

- "The file does not appear to be valid" in Event Viewer almost always means the trailing chunk is dirty (the file was copied while the EventLog service was still writing). Most parsers handle this. Try [the browser parser](/en) or `EvtxECmd`, which both report dirty chunks as a warning and continue.
- "Access is denied" from `wevtutil` against a file in `winevt\Logs\` is the EventLog service holding an exclusive lock. See [collecting .evtx from a live system](/en/blog/collecting-evtx-from-live-system) for the four standard ways around it.
- Empty output from `Get-WinEvent` on a saved log. Pass the file with `-Path`, not `-LogName`. `-LogName` only reads live channels.
- PowerShell `Get-WinEvent` says "No events were found that match the specified selection criteria". Your `-FilterHashtable` keys are case-sensitive on some properties. Try without the filter first to confirm the file parses.

For background on what is actually inside an `.evtx` and why the format looks the way it does, see [the chunk-level deep dive](/en/blog/evtx-file-format-chunks).

## Further reading

- [Eric Zimmerman's tools](https://ericzimmerman.github.io/)
- [omerbenamram/evtx (Rust)](https://github.com/omerbenamram/evtx)
- [williballenthin/python-evtx](https://github.com/williballenthin/python-evtx)

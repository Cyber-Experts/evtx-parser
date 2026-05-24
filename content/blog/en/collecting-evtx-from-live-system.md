---
title: "How to collect .evtx logs from a live Windows system (4 methods)"
description: "Four ways to pull .evtx off a live Windows host — wevtutil, FTK Imager, KAPE, raw NTFS — with chain-of-custody trade-offs for each and the commands you'll actually run."
date: "2026-05-17"
howto:
  name: "How to collect .evtx logs from a live Windows system"
  steps:
    - name: "Export with wevtutil"
      text: "Run wevtutil epl Security C:\\triage\\Security.evtx as administrator to seal a portable copy of the active Security channel without taking the live file."
    - name: "Acquire with FTK Imager"
      text: "Open FTK Imager, Add Evidence Item → Physical or Logical Drive, navigate to \\Windows\\System32\\winevt\\Logs\\, select the channel files (including archived *.evtx) and Export Files. FTK reads NTFS directly, bypassing the EventLog service's file locks."
    - name: "Bulk collect with KAPE"
      text: "Run kape.exe --tsource C: --target EventLogs --tdest C:\\triage to pull every .evtx under winevt\\Logs\\ in one pass, with chain-of-custody metadata. Pair with the WindowsEventLogs module to parse on collection."
    - name: "Raw NTFS read"
      text: "When tampering is suspected, use RawCopy or tsk_recover to open the volume below the filesystem layer (\\\\.\\PhysicalDriveN or \\\\.\\C:) and read each .evtx byte-for-byte from the MFT. The EventLog service cannot block this path."
---

The first hard problem in an event-log investigation isn't parsing, it's *getting the files*. On a running Windows host, the EventLog service holds open handles to the active `.evtx` files in `C:\Windows\System32\winevt\Logs\`, which means a naive `copy` fails. Four approaches cover almost every case.

## Built-in: wevtutil / Get-WinEvent

The simplest method exports records (not the file) via the documented API:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

This produces a sealed `.evtx` containing every record currently in the log. Quick, doesn't require third-party tools, and runs as administrator. The downside: it doesn't capture archived (rotated) `.evtx` files, only the active one.

PowerShell equivalent:

```powershell
Get-WinEvent -LogName Security |
  Export-Csv triage.csv
```

`Get-WinEvent` returns parsed records, not the file. Useful for a quick triage CSV but loses the binary fidelity needed for deeper forensics — chunk-level recovery, dirty-chunk inspection, carving.

## FTK Imager

For full disk or filesystem-level acquisition, FTK Imager is the standard. Add the live drive as evidence (Physical Drive or Logical Drive), navigate to `\Windows\System32\winevt\Logs\`, right-click the channel files, and Export Files. FTK reads the underlying NTFS structures directly, bypassing the file-system lock the EventLog service holds. It also exports archived `*.evtx` files (those with timestamps in the name) that `wevtutil` won't touch.

The trade-off is that FTK reads files that may be mid-write — the resulting `.evtx` can have a dirty trailing chunk. Most parsers (including this one) handle that gracefully but it's worth verifying.

## KAPE

For incident response at scale, the Kroll Artifact Parser and Extractor (KAPE) automates the collection of every forensically-relevant file in one pass:

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

The `EventLogs` target pulls every `.evtx` under `winevt\Logs\` plus the related event tracing files. Pair it with the `WindowsEventLogs` module to also run an immediate parse and produce a CSV alongside the raw files. Recommended for any IR engagement that touches more than one host.

## Raw NTFS read

For maximum fidelity — useful when you suspect the live filesystem APIs are being intercepted or you want bit-for-bit acquisition — read the volume below the filesystem layer. Tools like [The Sleuth Kit](https://www.sleuthkit.org/) (`tsk_recover`, `icat`) or Eric Zimmerman's `RawCopy.exe` open the volume via `\\.\PhysicalDriveN` or `\\.\C:`, walk the MFT, and emit the file content byte-for-byte. The EventLog service can't block this because the read bypasses the file-system layer entirely.

## Which to use when

- **Quick triage on one host, you have admin**: `wevtutil`.
- **Full forensic acquisition, you have a disk image already**: FTK Imager or `tsk_recover` against the image.
- **IR engagement, multiple hosts**: KAPE.
- **Suspected rootkit or live tampering**: raw NTFS via RawCopy or TSK on the live volume, with the host network-isolated.

Whichever you choose, document it. The provenance chain matters in incident reports — a parsed CSV says nothing about whether it came from a live host with the EventLog service running or a sealed image.

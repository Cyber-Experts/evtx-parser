---
title: "How to collect .evtx logs from a live Windows system (4 methods)"
description: "Four ways to pull .evtx off a live Windows host: wevtutil, FTK Imager, KAPE, raw NTFS. With the chain-of-custody trade-offs for each and the commands you'll actually run."
date: "2026-05-17"
howto:
  name: "How to collect .evtx logs from a live Windows system"
  steps:
    - name: "Export with wevtutil"
      text: "Run wevtutil epl Security C:\\triage\\Security.evtx as administrator to seal a portable copy of the active Security channel without taking the live file."
    - name: "Acquire with FTK Imager"
      text: "Open FTK Imager, Add Evidence Item, navigate to \\Windows\\System32\\winevt\\Logs\\, select the channel files (including archived *.evtx) and Export Files. FTK reads NTFS directly, bypassing the EventLog service's file locks."
    - name: "Bulk collect with KAPE"
      text: "Run kape.exe --tsource C: --target EventLogs --tdest C:\\triage to pull every .evtx under winevt\\Logs\\ in one pass, with chain-of-custody metadata. Pair with the WindowsEventLogs module to parse on collection."
    - name: "Raw NTFS read"
      text: "When tampering is suspected, use RawCopy or tsk_recover to open the volume below the filesystem layer (\\\\.\\PhysicalDriveN or \\\\.\\C:) and read each .evtx byte-for-byte from the MFT. The EventLog service cannot block this path."
---

The first hard problem on an event log job is not parsing. It is getting the files off the host without the EventLog service slapping your hand. On a running Windows box the service holds open handles to the active [`.evtx` files](/en/blog/what-is-an-evtx-file) in `C:\Windows\System32\winevt\Logs\`, so a naive `copy` returns sharing-violation errors. Four methods cover almost every case I have run into.

## wevtutil and Get-WinEvent: built-in, fastest

The cheapest path uses the Microsoft-documented API:

```cmd
wevtutil epl Security C:\triage\Security.evtx
```

That produces a sealed `.evtx` containing every record currently in the channel. No third-party tooling, admin shell required. The catch worth saying out loud: `epl` only captures the active log. Rotated `Archive-Security-*.evtx` files in the same directory are left behind. If the rotation happened recently and the records you want are in an archive, this method misses them.

PowerShell does parsed records instead:

```powershell
Get-WinEvent -Path C:\Windows\System32\winevt\Logs\Security.evtx |
  Export-Csv triage.csv -NoTypeInformation
```

That gives you a CSV, not a `.evtx`. Convenient for ad-hoc triage on the box. Useless for [chunk-level recovery, dirty-chunk inspection, or carving from unallocated space](/en/blog/evtx-file-format-chunks), because you have thrown away the binary fidelity.

## FTK Imager: NTFS-level acquisition

When you want the file, not the records, FTK Imager is the workhorse. Add the live drive as evidence (Physical Drive or Logical Drive), navigate to `\Windows\System32\winevt\Logs\`, right-click the channel files and Export Files. FTK reads the underlying NTFS structures directly, which sidesteps the file-system lock the EventLog service is holding. It also captures the archived `Archive-*.evtx` files that `wevtutil epl` skips.

Trade-off: FTK reads files that may be mid-write. The trailing chunk on the active channel can be dirty. Most parsers handle that gracefully (including the [browser parser on this site](/en/blog/how-to-open-an-evtx-file)) but verify on the bench before you write it into a report. The corresponding [USN journal](https://www.usnparser.com) entries are useful corroboration when you suspect the EventLog service did something nonstandard during acquisition.

## KAPE: bulk collection at IR speed

When the engagement has more than one host, the Kroll Artifact Parser and Extractor pays for itself within an hour.

```cmd
kape.exe --tsource C: --target EventLogs --tdest C:\triage
```

The `EventLogs` target sweeps every `.evtx` under `winevt\Logs\` plus the related ETW files. Pair it with the `!EZParser` or `WindowsEventLogs` module and KAPE will also run EvtxECmd against the collection on the way out, giving you parsed CSVs alongside the raw evidence. While you are at it, the `RegistryHives` and `FileSystem` targets pick up the [registry](https://www.registryparser.com), [MFT](https://www.mftparser.com), [USN journal](https://www.usnparser.com), and [prefetch](https://www.prefetchparser.com) data you will want anyway.

KAPE's output ships with copy log metadata. That matters for chain of custody more than people give it credit for.

## Raw NTFS read: when you suspect tampering

For maximum fidelity, drop below the filesystem layer. The Sleuth Kit's `tsk_recover` and `icat`, or Eric Zimmerman's `RawCopy.exe`, open the volume via `\\.\PhysicalDriveN` or `\\.\C:`, walk the MFT, and emit the file content byte for byte. The EventLog service cannot block this because the read does not go through the Win32 file API.

Use this when a rootkit is in scope, when you have reason to think a kernel filter driver is intercepting `\winevt\Logs\` reads, or when you simply do not trust the running OS. Pair the result with a [RAM dump](https://www.ramparser.com) taken at the same moment. The event log service caches recent records in memory, and a snapshot taken minutes before tampering sometimes contains records that never made it to disk.

## Which one when

- One host, you have admin, you have an hour: `wevtutil epl` for every channel that matters, zip the directory, done.
- [Disk image already in hand](https://www.diskimageparser.com): FTK Imager or `tsk_recover` against the image. Faster than the live host, and you do not have to coordinate with the SOC.
- Multiple hosts, real IR engagement: KAPE. Nothing else comes close on throughput.
- Suspected live tampering or rootkit: RawCopy or TSK against the volume, with the host network isolated.

Whichever you choose, document it. Parsed CSVs say nothing about provenance. A line in the case notes that reads `KAPE 1.3.0.2 EventLogs target, hash file attached` is the difference between an exhibit and an opinion.

## Further reading

- [KAPE documentation](https://ericzimmerman.github.io/KapeDocs/)
- [The Sleuth Kit](https://www.sleuthkit.org/)
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager)

---
title: "Carving deleted EVTX records and recovering rolled-over logs"
description: "Signature carving EVTX records from unallocated space, pagefile, and memory — and the tools that handle malformed chunks gracefully when the live log is missing what you need."
date: "2026-05-27"
tags:
  - evtx
  - carving
  - dfir
  - data-recovery
  - anti-forensics
author: "Florian Amette"
---

The Security log on a busy domain controller wraps in hours, not days. The default channel size is 20 MB, which is a few thousand records on a noisy host. By the time you image the disk in response to an incident that started three weeks ago, the events you actually wanted have rolled off the live file and are sitting in unallocated space, pagefile, and possibly hibernation. Carving them back is a routine part of any EVTX-driven investigation, and most defenders skip it because they treat the live file as the source of truth.

It is not. The live file is the last 20 MB. The disk has the rest.

## The signature: `2a 2a 00 00`

Every EVTX record begins with the four-byte magic `2a 2a 00 00`. That is `**` followed by two null bytes. This signature is distinctive enough that scanning a raw disk image with `bulk_extractor`, `scalpel`, or even a custom four-byte grep will return a useful set of candidates. The signature density on a Windows volume is low; most hits are real records.

The structure that follows the magic is well-enough defined that you can validate hits cheaply:

- Bytes 4-7: `Size` (uint32). Should be plausible (32 bytes minimum, typically under 4 KB).
- Bytes 8-15: `EventRecordIdentifier` (uint64). Should be a reasonable RecordID for the time window.
- Bytes 16-23: `WriteTime` as FILETIME. Should land between Vista (the first version with EVTX) and now.
- Bytes `Size-4` to `Size`: the same `Size` value, repeated as a tail marker.

A candidate where the head `Size` matches the tail `Size`, the FILETIME parses to a plausible date, and the RecordID is in range is overwhelmingly likely to be a real record. False positives drop to near zero with these four checks.

The challenge is what to do with the bytes between the head and tail.

## The chunk problem

EVTX records reference templates and strings stored once per chunk. A record carved in isolation has substitution arrays with no template to apply them to. You can read the typed values from the substitution array directly, which is enough to recover field-level data ("user X logged on at time T from IP Y"), but the rendered XML you would get from a live parser is not reconstructible without the chunk.

This is the difference between two carving outcomes:

- **Record-only carving**: you recover RecordID, timestamp, EventID, and the substitution values. You can build a field-by-field view of the event, but not the human-readable rendered XML.
- **Chunk carving**: you find a chunk (`ElfChnk\0` magic, 64 KB aligned) and recover its template table along with the records. Now you have everything.

`ElfChnk\0` is also signature-carvable. The 64 KB alignment helps because chunks land on sector boundaries on disk; an offset-aligned signature scan is fast. Most carving tools support both modes, and you should run both. Chunks give you readable events; orphan records give you the rest when no enclosing chunk survived.

## Where the bytes live

The places worth scanning, in order of yield:

- **Unallocated clusters on the volume hosting `%SystemRoot%\System32\winevt\Logs\`**. When an EVTX file rolls or is cleared, the old contents are unallocated. NTFS does not zero unallocated clusters, so the bytes are recoverable until they are reused. On a server with low write churn, this can be weeks.
- **Slack space in the live EVTX file**. EVTX files are written in 64 KB chunks. The last chunk in the file is often partially filled, with the slack containing the previous generation of data that was written to those bytes before the current chunk was sized down. Worth a scan.
- **[pagefile.sys](https://www.pagefilesysparser.com)**. The event log service caches recent records and templates in memory. Pages backing those structures get swapped out under memory pressure. The pagefile is a goldmine for records that were never flushed to disk because the host crashed or was killed before they made it.
- **`hiberfil.sys`**. Compressed snapshot of physical memory at hibernation time. Decompress with `Volatility 3` or Hibr2Bin and search the resulting raw memory for the record signatures.
- **[RAM dump](https://www.ramparser.com)** captured during live response. The event log service's working set will contain recent records and the templates needed to render them.
- **Shadow copies (VSS)**. Old snapshots of the volume contain old versions of the live EVTX files. `vshadow` or `vssadmin list shadows` followed by `mklink /d` to mount the shadow gives you a previous-generation copy of the file with whatever records were live at the shadow time.

VSS is the highest-leverage source on hosts that have it enabled and have not been tampered with at the VSS layer. A modern Windows server typically has 7-30 days of shadow copies. If the incident happened three weeks ago, the shadow from the time of the incident may have the live log as it existed then, untampered.

## Tools that handle malformed input

A clean EVTX file is rare in carving scenarios. You will get partial chunks, records with missing tails, templates that reference offsets outside the chunk, and CRC failures throughout. The parsers that handle this are not the same as the ones that handle clean files.

- **`EvtxECmd`** (Eric Zimmerman). Best-in-class for IR fieldwork. Pass `--inc` to include records that failed normal parsing and it will emit what it could read of partial records. The CSV output is what you want for timeline work.
- **`hayabusa`** (Yamato Security). Built for hunting across large EVTX corpora, with sigma-style rules. It handles partial chunks reasonably and is fast. The `--exclude-status` filter lets you reduce noise from corrupt records.
- **`evtx_dump`** (Omer Ben-Amram's Rust crate). Robust against malformed structures, JSONL output. Good for pipelining into `jq` or a SIEM.
- **`evtxtools`** (Joachim Metz, part of libevtx). The format-canonical reference implementation. Slower than the others but it tells you exactly which field failed which validation when a record is partially recovered, which is what you want when debugging carving output.
- **`bulk_extractor`** with the EVTX scanner. The carving step itself. Outputs candidate records with their offsets in the source image for later validation.

A practical pipeline:

1. `bulk_extractor -E evtx -o out/ image.dd` to carve candidate records and chunks from the disk image.
2. Reassemble the chunks into synthetic EVTX files by concatenating the carved chunks with a forged file header. The `libevtx` examples include a `evtxexport`-compatible chunk reassembler.
3. Run `EvtxECmd` over the reassembled file with `--inc` to dump everything readable to CSV.
4. Diff the carved RecordIDs against the live file's RecordIDs to find the records that were not in the live log.

The output of step 4 is what carving gives you: the events that the attacker or time has removed from the live file.

## When the live log shows nothing because it rolled

The common case for carving is not anti-forensic clearing; it is rollover. An incident from 30 days ago on a host with a 20 MB Security log and 50 events per second has rolled the entire file dozens of times. The live log shows the last few hours. Everything in between is in unallocated.

The carve here is straightforward because there has been no tampering. You scan unallocated, you find chunks, you reassemble. The yield depends on how much write churn the volume has had since the rollover. A server volume with mostly-static system files and the EVTX directory as the dominant write source will keep old chunks intact for a long time. A volume with heavy application writes will overwrite the unallocated regions faster.

A trick that helps: the EVTX directory is at `%SystemRoot%\System32\winevt\Logs\`, which is one of the colder spots on the volume in terms of competing writes. Cluster runs that were freed when the EVTX file rolled often stay unallocated for weeks. The same is not true of volumes hosting application data.

## What to do with what you recover

Carved records go into the same timeline as live records. The RecordID and WriteTime survive carving and are the join keys. A carved `4624 Type 3` at the time of suspected initial access is as useful as a live one, modulo the caveat that you cannot necessarily render its full XML.

Cross-reference against:

- The [Master File Table](https://www.mftparser.com) entries for `Security.evtx` to see when the file was rewritten by clearing or rollover.
- The [USN journal](https://www.usnparser.com) for `DATA_OVERWRITE` events on the EVTX file, which gives high-resolution timestamps for each rollover.
- [Prefetch](https://www.prefetchparser.com) for the binaries that ran during the gap, since `Prefetch` is independent of `Security.evtx` and survives log clearing.
- [AmCache](https://www.amcacheparser.com) and [Shimcache](https://www.shimcacheparser.com) for first-execution evidence.
- The [registry](https://www.registryparser.com) hives in shadow copies for state at the time of the incident.

A carved record that lines up with a Prefetch entry and an MFT timestamp on a suspicious binary is a finding. A carved record sitting alone is a clue worth chasing.

## Further reading

- Andreas Schuster's original carving work in the [DFRWS 2007 paper](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf). The carving heuristics in every modern tool trace back here.
- Eric Zimmerman's [EvtxECmd](https://github.com/EricZimmerman/evtx) documentation and the `--inc` flag for partial-record handling.
- Yamato Security's [hayabusa](https://github.com/Yamato-Security/hayabusa) and its bundled sample corpus, useful for testing carving pipelines.
- Simson Garfinkel's [bulk_extractor](https://github.com/simsong/bulk_extractor) and its EVTX scanner module.

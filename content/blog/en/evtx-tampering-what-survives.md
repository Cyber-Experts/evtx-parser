---
title: "Tampered event logs and what survives"
description: "How attackers clear, truncate and timestomp Windows event logs — and the byte-level tells that survive: 1102/104 clearing events, record-ID gaps, chunk CRC mismatches, dirty chunks, and records carvable from slack and unallocated space."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - anti-forensics
  - file-format
  - threat-hunting
author: "Florian Amette"
---

"The logs were cleared" is rarely the end of an investigation. The EVTX format's chunked, append-only, checksummed design means tampering tends to leave its own evidence — and a surprising amount of the supposedly-deleted data is still on disk. This post is about reading the negative space: what an attacker did to the logs, and what survived anyway. It builds on the [byte-level format reference](/en/blog/evtx-file-format-reference); the structures named here (chunks, record IDs, CRCs) are defined there.

## The hierarchy of log tampering

From loudest to quietest:

1. **[Clear the log](https://www.reverseengineering.app/en/techniques/event-log-clearing)** — `wevtutil cl`, `Clear-EventLog`, or the Event Viewer GUI. Easy, complete, and **noisy**: it generates an event.
2. **Stop or starve logging** — stop the EventLog service, shrink the max size so events roll instantly, or disable an audit subcategory. Quieter; leaves gaps rather than a clearing event.
3. **Surgically remove records** — edit the `.evtx` offline to drop specific events. Rare, hard, and it breaks the file's internal consistency in detectable ways.
4. **Suppress at the source** — tooling like Phant0m suspends the EventLog service's threads so events are simply never written. Leaves the existing file untouched; the tell is the *absence* of expected events plus the process artifacts.

Each leaves a different signature.

## Clearing is loud: 1102, 104, 1100

Clearing the **Security** log writes **Event ID 1102** ("The audit log was cleared") — into the very log being cleared, as the first record of the new sequence, with the `SubjectUserName` of whoever did it. Clearing any other log writes **104** ("log was cleared") in the System log. Service shutdown writes **1100**. See [Event ID 1102 in depth](/en/blog/event-id-1102-cleared-log) and [log clearing as evidence](/en/blog/event-log-clearing-evidence).

So the paradox: clearing the log to hide activity creates a high-fidelity event saying exactly when, and by whom, it was cleared. Forwarded logs (WEF/SIEM) make this worse for the attacker — the cleared records are already off-box.

## Record-ID gaps: the math that exposes deletion

Every record carries a monotonic `EventRecordIdentifier`, and the file header stores `NextRecordIdentifier`. These don't reset on clear — they keep climbing for the life of the channel. That gives two checks:

- **Within a file**: record IDs should be contiguous. A jump from `…4012` to `…4090` with nothing between means ~78 records are gone — truncation, rollover, or selective deletion.
- **Header vs last record**: if `NextRecordIdentifier` is far ahead of the highest record actually present, records were written and are now missing.

A *clean* clear resets the file to a fresh low range, which is itself anomalous next to forwarded copies or the high IDs on sibling hosts. Selective deletion is what leaves mid-file gaps.

## CRC mismatches: editing without recomputing

The format checksums itself in three places (all in the [reference](/en/blog/evtx-file-format-reference)): a CRC-32 over the file header, a CRC-32 over each chunk header, and a CRC-32 over each chunk's **records area**. Anyone editing a record's bytes must recompute the records-area CRC for that chunk *and* keep the chunk header's record-ID range consistent. In practice, hand-edited `.evtx` files usually show:

- a **records-area CRC that no longer matches** the chunk contents, and/or
- a **chunk header whose first/last record IDs disagree** with the records actually present.

Strict parsers reject such a file outright; forensic parsers should report the mismatch and carry on. Either way, the mismatch *is* the finding.

## Timestamps are harder to forge than people think

The record `WriteTime` is a `FILETIME` written by the EventLog service at write time; the embedded `TimeCreated` in the event's `System` block comes from the same source. An attacker can't casually "timestomp" an event the way they touch an NTFS `$STANDARD_INFORMATION` timestamp — doing so means an offline edit, which lands you back in CRC-mismatch and record-ID-gap territory. Inconsistencies to look for: an event's `TimeCreated` out of order with its neighbours' record IDs (IDs increase monotonically with write time), or write times that disagree with the chunk's first/last record metadata.

## Dirty chunks and the live tail

A chunk whose data was being written when acquisition happened is **dirty** (the file header's dirty flag, plus a last-write inconsistency). On a [live-collected](/en/blog/collecting-evtx-from-live-system) host the active channel always has a dirty trailing chunk. That is normal — but it also means the most recent events may sit in a half-written chunk that strict tools refuse. Don't mistake a tool's refusal to read the dirty tail for "no recent events"; a recovering parser will pull the records before the break.

## What survives: carving the deleted

Because chunks are independent and 64 KB aligned with the `ElfChnk\0` magic, and records carry the `2A 2A 00 00` magic, deleted or overwritten log data is frequently recoverable from places the attacker didn't think to clean:

- **Slack and unallocated space** on the volume — old chunks freed when a log rolled.
- **`pagefile.sys`** and hibernation files.
- **RAM images** — the EventLog service's buffers and recently written chunks.
- **VSS / shadow copies and backups** — a previous version of the `.evtx` from before the clear.

Carve on the chunk magic, wrap a recovered chunk in a synthetic 4 KB file header, and parse it. This is the core technique in [carving deleted EVTX records](/en/blog/carve-deleted-evtx-records); a single recovered chunk can hold hundreds of "deleted" events.

## A triage checklist for suspected tampering

- Search every channel for **1102 / 104 / 1100** and note the actor and time.
- Check **record-ID continuity** within the file and against `NextRecordIdentifier`.
- Validate **chunk header and records CRCs**; flag mismatches.
- Compare on-box logs against **forwarded/SIEM** copies and **sibling hosts** — gaps show up as divergence.
- Pull **shadow copies / backups** for a pre-clear version.
- **Carve** slack, pagefile, and RAM for orphaned chunks.
- Treat a **missing expected event** (no 4624 for a session you can prove happened) as a finding in its own right — the quiet-suppression case.

The throughline: EVTX was built for write throughput and machine consumption, not for being edited after the fact. That makes clean tampering hard and messy tampering obvious. Load the suspect file in the [browser parser](/en/blog/how-to-open-an-evtx-file), and for the structures behind every check above, keep the [format reference](/en/blog/evtx-file-format-reference) open.

---
title: "The EVTX file format, decoded"
description: "A working tour of the EVTX binary format: file header, ELFCHNK chunks, BinXML templates, substitution arrays, and why parsing this thing is harder than it looks."
date: "2026-05-27"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

The old EVT format was almost readable with a hex editor and patience. EVTX is not. Microsoft replaced it in Vista with something designed for write throughput and machine consumption, and the side effect is that everyone who wants to read an EVTX file ends up reimplementing the same few hundred pages of Andreas Schuster's reverse-engineering notes. The format is documented in `[MS-EVEN6]` only at the protocol layer. The on-disk structure you have to figure out yourself or borrow from `libevtx`.

This post is the version of that I wish I had when I started.

## The file header, briefly

Every EVTX file opens with a 4096-byte file header. The magic is `ElfFile\0` at offset 0. After that the fields you actually care about during triage:

- `FirstChunkNumber` and `LastChunkNumber` — chunk indices, not byte offsets.
- `NextRecordIdentifier` — the next RecordID that would be written. Useful for spotting truncation.
- `HeaderSize` — almost always 128, with the rest of the 4096 bytes zero-padded.
- `MinorVersion` / `MajorVersion` — `3.1` is the version every modern Windows writes.
- `FileFlags` — bit 0 set means the file is dirty (not cleanly closed), bit 1 means it has been "full" and is rolling. Both matter for forensic interpretation.
- A CRC32 over the first 120 bytes of the header. Tools that ignore the CRC will happily parse corrupt headers; tools that enforce it will reject files you can still recover records from. Know which yours does.

After the header, you get a sequence of 65,536-byte chunks. Always 64 KB, always aligned. This is the unit Windows writes atomically, and it is the unit you carve.

## ELFCHNK: the chunk header

Each chunk starts with `ElfChnk\0` at the chunk boundary. The header is 512 bytes and carries the fields that make parsing possible:

- `FirstEventRecordNumber` and `LastEventRecordNumber` — the RecordID range covered by this chunk.
- `FirstEventRecordIdentifier` and `LastEventRecordIdentifier` — same thing, kept for legacy.
- `FirstEventRecordOffset` — where the first record's bytes begin inside this chunk.
- `LastEventRecordOffset` — where the last record begins. If this is past the end of the populated chunk, the chunk has been partially written; the writer crashed.
- A `StringTable` and a `TemplateTable`, both hash tables keyed by FNV-style hashes, pointing into the chunk's BinXML payload.
- Two CRCs: one over the header, one over the records area.

The string and template tables are the part that throws people. Templates and strings are stored *once per chunk* and referenced by offset within the chunk. This means you cannot meaningfully parse a record in isolation. You need its enclosing chunk, with its tables resolved, to render the record's XML. Carve a record without its chunk and you will get a substitution array with no template to substitute into.

`NumLogRecords` lives implicitly as `LastEventRecordNumber - FirstEventRecordNumber + 1`. Some early documentation called this field out by name; modern parsers compute it.

## EventRecord encoding

Past the chunk header you get records, back to back, until the chunk is full or the rest is zeroed. Each record begins with the magic `2a 2a 00 00` (which makes signature carving from raw disk feasible — more on that in a separate post) followed by:

- `Size` — total record length including the trailing size repeat.
- `EventRecordIdentifier` — the monotonically increasing RecordID.
- `WriteTime` — a Windows FILETIME, 100-ns ticks since 1601-01-01 UTC.
- The BinXML payload.
- `Size` again, repeated at the tail so a reader can walk records backwards.

The BinXML payload is where the real work begins.

## BinXML and the template/substitution model

BinXML is a token stream that encodes XML as binary opcodes. The opcodes that matter:

- `0x00` end-of-stream.
- `0x01` open start tag (with attributes).
- `0x02` close start tag.
- `0x03` close empty tag.
- `0x04` end element.
- `0x05` value, followed by a `ValueType` and the value bytes.
- `0x06` attribute.
- `0x0c` template instance.
- `0x0d` normal substitution.
- `0x0e` conditional substitution.
- `0x0f` start of stream (with a 3-byte preamble).

The Windows event log writer almost never emits raw XML for an event. It emits a *template instance* (`0x0c`), which references a template definition (stored once per chunk by ID) and supplies a *substitution array* containing the variable values for that template. To render a single human-readable XML record you need to:

1. Locate the template in the chunk's template table by its template ID and offset.
2. Walk the template's BinXML, treating it as a skeleton with numbered substitution placeholders.
3. For each placeholder, look up the corresponding entry in the substitution array, type-check it against the placeholder's declared type, and inline it.

The substitution array has typed entries: UInt32, UInt64, Boolean, GUID, FILETIME, SID, HexInt32, HexInt64, BinXML, EvtHandle, EvtXml, plus strings in either UTF-16LE inline or by offset reference, plus arrays of any of the above. Type 0x21 is "BinXML" which means the substitution is itself a nested BinXML stream, which means parsers need to recurse. This is where naive implementations fall over.

Two pitfalls worth flagging:

- Templates can be referenced from *other* records in the same chunk by offset. If you build a parser that resolves templates only when it sees their declaration inline, you will miss records that reference an earlier template by ID alone.
- The "conditional substitution" type (`0x0e`) means: substitute if the value is non-null, otherwise omit the parent element. Skipping this distinction produces XML that looks fine but has empty elements where the real log would have nothing.

## Why this is harder than parsing EVT

EVT was a flat file of fixed-shape records. Strings were stored inline. You could write a parser in an afternoon.

EVTX is a paginated, write-optimized, self-deduplicating format. The same string ("Microsoft-Windows-Security-Auditing") is stored once per chunk and referenced from every record that uses it. The same XML skeleton ("a 4624 event") is stored once per chunk as a template, and every 4624 record in that chunk is a substitution array against it. Cross-record state matters. Cross-chunk state does not, which is the saving grace: lose a chunk and you lose its records, but the rest of the file is recoverable.

This deduplication is what makes EVTX small enough to keep on busy hosts and what makes naive parsers wrong. If you have ever seen a "parsed" EVTX where every record's `Provider` field says "Unknown", you have seen a parser that did not resolve the string table.

## The tools that actually work

- `python-evtx` (Willi Ballenthin) — slow, pure Python, but the cleanest reference implementation. Read its source before you write your own.
- `evtx_dump` from Omer Ben-Amram's `evtx` Rust crate — fast, robust, the default for command-line dumping. JSONL output that pipes into anything.
- `libevtx` and `evtxtools` (Joachim Metz) — C library, the canonical reference for the format. The Python bindings (`pyevtx`) are slower than `python-evtx` in some workloads but handle edge cases better.
- Eric Zimmerman's `EvtxECmd` — .NET, hands-down the best for IR fieldwork because of its map system. Maps are YAML files that flatten the EventData substitutions into named columns, which is what you want for grep and timeline work. Pair it with `Timeline Explorer`.
- The [parser on this site](https://www.evtxparser.com) — browser-based, useful when you do not want to upload regulated data to a vendor and do not have your kit on the box you are working from.

If you are writing a parser from scratch (do not, but if you must), the test corpus to validate against is the public EVTX samples from the [SANS DFIR poster](https://github.com/forensicmatt/EVTX-ETW-Resources) repo and the Yamato Security `hayabusa` sample logs. They cover the malformed-chunk and partial-record cases your code will get wrong on the first pass.

The other thing worth saying: the format is shared with other Windows artifacts. The same FILETIME encoding shows up in the [registry](https://www.registryparser.com), in [MFT](https://www.mftparser.com) `$STANDARD_INFORMATION` timestamps, in [Prefetch](https://www.prefetchparser.com) headers. Get good at reading FILETIME in your head and a lot of Windows forensics gets quieter.

## Further reading

- Andreas Schuster's original ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) (DFRWS 2007). The reverse-engineering paper everything since cites.
- Joachim Metz's [libevtx format specification](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc). The closest thing to a complete reference.
- Willi Ballenthin's [python-evtx source](https://github.com/williballenthin/python-evtx). Read `Evtx/Nodes.py` for the BinXML node hierarchy.
- Omer Ben-Amram's [evtx Rust crate](https://github.com/omerbenamram/evtx). The fast path most modern tooling sits on.

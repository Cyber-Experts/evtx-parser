---
title: "EVTX file format explained: chunks, templates and BinXML internals"
description: "How a .evtx file is laid out at the byte level: file header, 64 KB chunks, the template table, and the BinXML record stream that references it."
date: "2026-05-17"
---

The [Windows Event Log format `.evtx`](/en/blog/what-is-an-evtx-file) shipped with Vista to replace the line-oriented `.evt`. It is a binary, append-only, chunked container written by a single process (the EventLog service) and rotated when full. Most analysts never need to know how it is laid out at the byte level. The ones who carve records from unallocated space, hand-parse damaged chunks, or argue with a parser that refuses to read a truncated file very much do.

This post is the practical version. Enough internals to debug a broken parse, not so much that you end up writing your own parser from scratch.

## File header

Every `.evtx` starts with a 4 KB header. The magic is `ElfFile\0\0`. The fields that matter to an investigator are version, chunk count, oldest and current chunk indices, and a CRC32 over the header itself. The header is rewritten in place each time the file rotates or a chunk is sealed, so its `Dirty` and `Full` flags are useful tells. A file with `Dirty` set was open when the host crashed or when the disk image was acquired live.

After the header comes a sequence of fixed-size chunks.

## Chunks: 64 KB each

Each chunk is exactly 65,536 bytes and has its own 512-byte header. The chunk magic is `ElfChnk\0`. The header carries the log record IDs of the first and last record in the chunk, the file offsets, and two CRC32s: one over the header, one over the record data.

Chunks are independent. You can carve a chunk out of unallocated space and parse it without the rest of the file. This is what makes EVTX [recoverable from disk fragments](/en/blog/carve-deleted-evtx-records), and it is also what makes the format friendlier to forensic tooling than something that compressed across the whole file.

Inside a chunk:

- **String table.** Strings interned within this chunk, referenced by offset.
- **Template table.** XML templates used by records in this chunk, also offset-indexed.
- **Records.** A stream of BinXML records, each referencing one template plus per-record substitution values.

## BinXML and templates

EVTX records are not stored as XML text. They are stored as **BinXML**, a tokenized binary representation of an XML document. To save space, the structural skeleton (element names, attribute names, tree shape) is factored out into a **template** stored once in the chunk's template table. Each record then says "use template ID 5, with values [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

To reconstruct the XML for a record, a parser:

1. Reads the record's token stream.
2. Looks up the template by ID in the chunk's template table.
3. Substitutes the per-record values into the template's placeholder positions.
4. Emits the resulting XML.

This is why parsers (the [browser parser on this site](/en/blog/how-to-open-an-evtx-file), the [Rust `omerbenamram/evtx`](https://github.com/omerbenamram/evtx) crate it wraps, and python-evtx all share this requirement) need to track chunk-local context. Template IDs are not global across the file. Two chunks can have entirely different template tables; the same template ID number means different things in each.

This is also the single most common reason analysts see "garbage XML" when they try to hand-decode a record they pulled out with `xxd`. Without the template table, the substitution values are just a bag of typed values with no schema.

## Sealed versus dirty chunks

When the EventLog service finishes writing a chunk and moves to the next one, it computes and writes the chunk's CRC32 and marks the chunk's header `Full`. A clean file has every chunk in this state except the last.

A `Dirty` chunk (last-modified time after the file header was last updated) is the live tail. It is often parseable, but tools sometimes refuse to read it because the record stream may terminate mid-token. For forensics this matters: a bundle [collected from a live host](/en/blog/collecting-evtx-from-live-system) will have a dirty trailing chunk on the active channel, and your parser's behaviour on that chunk needs to be known. Does it skip the chunk, error on the file, or recover what it can?

EvtxECmd, hayabusa, and python-evtx all recover dirty chunks with varying tolerance. Native Event Viewer is the strictest and will refuse the file outright more often than the others.

## Practical implications

- A truncated `.evtx`, common when you [collect from a live host](/en/blog/collecting-evtx-from-live-system), is often mostly recoverable. Every complete chunk is independent.
- Carved-from-unallocated chunks can be wrapped with a synthetic file header and parsed. This is how libevtx and python-evtx recover from `pagefile.sys` (see [pagefile parser](https://www.pagefilesysparser.com)) and [RAM dump](https://www.ramparser.com) carving sweeps.
- A failed parse of one chunk does not mean failure of the file. Robust parsers move on to the next chunk and report the bad one separately.
- The chunk CRC32 is what flags tampering. A modified record that does not recompute the CRC is detectable. Most attackers do not bother because clearing the log (firing [1102](/en/blog/event-id-1102-cleared-log)) is the easier path. The careful ones use Phant0m, which leaves the file alone entirely.

## Further reading

- [Andreas Schuster: Introducing the Microsoft Vista Event Log File Format](https://digital-forensics.sans.org/blog/2008/05/01/the-windows-vista-event-log-file-format) (original reverse-engineering work)
- [libevtx documentation](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) (the most thorough format spec in the wild)
- [omerbenamram/evtx](https://github.com/omerbenamram/evtx) (Rust parser, the WASM build powers the browser parser on this site)

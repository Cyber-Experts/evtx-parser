---
title: "EVTX file format explained: chunks, templates & BinXML internals"
description: "How a .evtx file is laid out at the byte level — file header, 64 KB chunks, the template table, and the BinXML record stream that references it."
date: "2026-05-17"
---

The Windows Event Log format — `.evtx` — was introduced with Windows Vista to replace the line-oriented `.evt`. It is a binary, append-only, chunked container designed to be written by a single process (the EventLog service) and rotated or sealed when full. Understanding how it's laid out makes the forensic recovery cases — partial files, dirty chunks, carving — much easier.

## File header

Every `.evtx` starts with a 4 KB header (`ElfFile\0\0` magic, version, chunk count, oldest/current chunk indices, and a CRC32). The header is rewritten in place each time the file is rotated or a chunk is sealed, which makes its `Dirty` and `Full` flags useful tells: a file with `Dirty` set was open when the host crashed or the disk image was acquired live.

After the header come a sequence of fixed-size chunks.

## Chunks (64 KB)

Each chunk is exactly 64 KB and has its own 512-byte header (`ElfChnk\0` magic, log record IDs of first and last record in the chunk, file offsets, two CRC32s — one for the header, one for the record data). Chunks are independent: you can carve a chunk out of unallocated space and parse it without the rest of the file. This is what makes EVTX recoverable from disk fragments.

Inside a chunk:

- **String table** — strings interned within this chunk, referenced by offset.
- **Template table** — XML templates used by records in this chunk, also offset-indexed.
- **Records** — a stream of BinXML records, each referencing one template plus per-record substitution values.

## BinXML and templates

EVTX records are not stored as XML text. They're stored as **BinXML**, a tokenized binary representation of an XML document. To save space, the structural skeleton (element names, attribute names, the tree shape) is factored out into a **template** stored once in the chunk's template table. Each record then says "use template ID 5, with values [`alice`, `S-1-5-21-...`, `3`, `0xc000006a`]".

To reconstruct the XML for a record, a parser:

1. Reads the record's token stream.
2. Looks up the template by ID in the chunk's template table.
3. Substitutes the per-record values into the template's placeholder positions.
4. Emits the resulting XML.

This is why parsers (including the one powering this page, [`omerbenamram/evtx`](https://github.com/omerbenamram/evtx)) need to track chunk-local context — template IDs are not global across the file.

## Sealed vs dirty chunks

When the EventLog service finishes writing a chunk and moves to the next one, it computes and writes the chunk's CRC32 and marks the chunk's header `Full`. A clean file has every chunk in this state except the last.

A `Dirty` chunk — last-modified time after the file header was last updated — is the live tail. It's often parseable, but tools sometimes refuse to read it because the record stream may terminate mid-token. For forensics this matters: an attacker who acquired a host mid-write will see a dirty trailing chunk, and your parser's behaviour on that chunk needs to be known (does it skip, error, or recover what it can?).

## Practical implications for parsing

- A truncated `.evtx` is often still mostly recoverable — every complete chunk is independent.
- Carved-from-unallocated chunks can be wrapped with a synthetic file header and parsed.
- A failed parse of one chunk does not mean failure of the file — robust parsers move on to the next chunk.
- The chunk's CRC32 is what flags tampering: a modified record that doesn't recompute the CRC is detectable.

---
title: "The EVTX file format: a complete byte-level reference"
description: "A field-by-field reference for the Windows .evtx format — file header, ELFCHNK chunk header, event record, the full BinXML token and value-type tables, and a worked decode from raw bytes to rendered XML."
date: "2026-06-17"
tags:
  - evtx
  - file-format
  - binxml
  - dfir
  - reverse-engineering
  - reference
author: "Florian Amette"
---

Most writing about the EVTX format — including [our own working tour of it](/en/blog/evtx-file-format) — explains the format in prose. This page is the other thing: a reference you can keep open in a second tab while you read a hex dump. Every structure below is given with offsets, sizes, and the values you should actually see on disk, followed by a worked decode of a single record from raw bytes to the XML an analyst reads.

The on-disk format is not covered by `[MS-EVEN6]`, which documents only the remoting protocol. The definitive public sources are Andreas Schuster's 2007 reverse-engineering paper and Joachim Metz's [`libevtx` specification](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc); the tables here follow `libevtx`. Everything is **little-endian** unless noted.

## The shape of the file

```
┌──────────────────────────────┐  offset 0
│  File header (4096 bytes)     │
├──────────────────────────────┤  offset 4096
│  Chunk 0 (65536 bytes)        │
│   ├─ Chunk header (512 B)     │
│   ├─ String table (offsets)   │
│   ├─ Template table (offsets) │
│   └─ Event records →          │
├──────────────────────────────┤  offset 4096 + 65536
│  Chunk 1 (65536 bytes)        │
├──────────────────────────────┤
│  …                            │
└──────────────────────────────┘
```

A file is a 4 KB header followed by N fixed 64 KB chunks. Chunks are self-contained: each carries the string and template tables its own records reference. That independence is the single most important property of the format — it is why a chunk [carved from unallocated space](/en/blog/carve-deleted-evtx-records) is parseable on its own, and why a record carved *without* its chunk is not.

## File header (`ElfFile`)

4096 bytes. Magic `45 6C 66 46 69 6C 65 00` (`"ElfFile\0"`). Only the first 128 bytes are used; the rest is zero padding.

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 8 | Signature | `ElfFile\0` |
| 8 | 8 | First chunk number | chunk index, not a byte offset |
| 16 | 8 | Last chunk number | |
| 24 | 8 | Next record identifier | next `RecordID` to be written — a truncation tell |
| 32 | 4 | Header size | always `0x80` (128) |
| 36 | 2 | Minor version | `1` |
| 38 | 2 | Major version | `3` → format **3.1** |
| 40 | 2 | Header block size | always `0x1000` (4096) |
| 42 | 2 | Number of chunks | |
| 120 | 4 | File flags | `0x1` = dirty, `0x2` = full |
| 124 | 4 | Checksum | CRC-32 of bytes `0–119` |

Two flags carry forensic weight. **Dirty** means the file was not cleanly closed — set on the active channel of a [live-collected](/en/blog/collecting-evtx-from-live-system) host or a crashed machine. **Full** means the file has wrapped at least once. Note also that strict parsers *enforce* the header CRC and will reject files that looser parsers happily recover records from; know which behaviour yours has.

## Chunk header (`ElfChnk`)

Each chunk is exactly 65536 bytes. The header is 512 bytes; magic `45 6C 66 43 68 6E 6B 00` (`"ElfChnk\0"`).

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 8 | Signature | `ElfChnk\0` |
| 8 | 8 | First event record number | |
| 16 | 8 | Last event record number | |
| 24 | 8 | First event record identifier | |
| 32 | 8 | Last event record identifier | |
| 40 | 4 | Header size | `0x80` (128) |
| 44 | 4 | Last record data offset | relative to chunk start |
| 48 | 4 | Free space offset | start of unused tail |
| 52 | 4 | Event records CRC-32 | over the records area |
| 120 | 4 | (unknown / flags) | |
| 124 | 4 | Header CRC-32 | over bytes `0–119` **and** `128–511` |
| 128 | 256 | String-offset table | 64 × 4-byte offsets |
| 384 | 128 | Template-pointer table | 32 × 4-byte offsets |

The two tables are why **you cannot render a record in isolation**. Element names, attribute names, and provider strings are interned once per chunk and referenced by offset; XML skeletons are stored once per chunk as *templates*. A record is a template ID plus a list of values. Resolve the tables or every `Provider` reads `Unknown`.

The records-area CRC-32 is the tamper tripwire: edit a record without recomputing it and the mismatch is detectable. (Most attackers don't bother — see [tampered logs and what survives](/en/blog/evtx-tampering-what-survives).)

## Event record

Records run back-to-back from offset 512 until the free-space offset.

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 4 | Signature | `2A 2A 00 00` (`**\0\0`) |
| 4 | 4 | Size | total length, including the trailing copy |
| 8 | 8 | Event record identifier | monotonic `RecordID` |
| 16 | 8 | Written time | Windows `FILETIME`, 100 ns ticks since 1601-01-01 UTC |
| 24 | … | BinXML | the event payload |
| end | 4 | Size (copy) | repeat of the size field, so readers can walk backwards |

That `2A 2A 00 00` signature is what makes record-level carving feasible. The `FILETIME` here is the same encoding you'll meet in the [registry](https://www.registryparser.com), [$MFT](https://www.mftparser.com), and [Prefetch](https://www.prefetchparser.com) — worth learning to read in your head.

## BinXML token table

The payload is **BinXML**: a token stream of XML opcodes. A token's high bit `0x40` is a "more data follows" flag (e.g. an element that has attributes), which is why the same logical token appears at two values.

| Token | Value(s) | Meaning |
|-------|----------|---------|
| EndOfStream | `0x00` | end of the token stream |
| OpenStartElement | `0x01` / `0x41` | `<name …` (`0x41` = has attributes) |
| CloseStartElement | `0x02` | `>` |
| CloseEmptyElement | `0x03` | `/>` |
| EndElement | `0x04` | `</name>` |
| Value | `0x05` / `0x45` | literal value, followed by a value type + bytes |
| Attribute | `0x06` / `0x46` | `name="…"` |
| CDATASection | `0x07` / `0x47` | `<![CDATA[…]]>` |
| CharRef | `0x08` / `0x48` | `&#x…;` |
| EntityRef | `0x09` / `0x49` | `&name;` |
| PITarget | `0x0a` | processing-instruction target |
| PIData | `0x0b` | processing-instruction data |
| TemplateInstance | `0x0c` | use a template + substitution array |
| NormalSubstitution | `0x0d` | insert value `[id]` |
| OptionalSubstitution | `0x0e` | insert value `[id]`, or omit the element if null |
| FragmentHeader | `0x0f` | stream prologue, always `0F 01 01 00` |

The distinction between **normal** (`0x0d`) and **optional** (`0x0e`) substitution is a classic correctness bug: optional means *omit the parent element when the value is null*. Treat them the same and you emit empty `<Data/>` elements that the real log doesn't contain.

## BinXML value types

Every literal value and every substitution slot is typed. The high bit `0x80` marks an **array** of the base type.

| Value | Type | Encoding |
|-------|------|----------|
| `0x00` | NullType | empty |
| `0x01` | StringType | UTF-16LE, no BOM, no terminator |
| `0x02` | AnsiStringType | code-page string |
| `0x03`–`0x0a` | Int8…UInt64 | 8/16/32/64-bit signed & unsigned |
| `0x0b` / `0x0c` | Real32 / Real64 | float / double |
| `0x0d` | BoolType | 32-bit `0`/`1` |
| `0x0e` | BinaryType | raw bytes |
| `0x0f` | GuidType | 16-byte GUID |
| `0x10` | SizeTType | 32- or 64-bit |
| `0x11` | FileTimeType | 64-bit `FILETIME` |
| `0x12` | SysTimeType | 128-bit `SYSTEMTIME` |
| `0x13` | SidType | NT security identifier |
| `0x14` / `0x15` | HexInt32 / HexInt64 | rendered as `0x…` |
| `0x21` | BinXmlType | **a nested BinXML fragment — parsers must recurse** |
| `0x81`–`0x95` | array variants | e.g. `0x81` = array of UTF-16LE strings |

Type `0x21` is where naive parsers fall over: a substitution value can itself be a BinXML stream (this is how `UserData`/`EventData` nest), so the decoder has to call itself.

## Templates and the substitution array

The event-log writer almost never emits raw element tokens for an event. It emits a **template instance** (`0x0c`): a reference to a template definition stored once per chunk, plus a typed **substitution array** of the per-record values.

**Template definition** (referenced by ID/offset within the chunk):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 1 | version |
| 1 | 4 | template id |
| 5 | 4 | next-template offset (`0` if none) |
| 9 | 16 | template GUID |
| 25 | 4 | data size |
| 29 | … | BinXML skeleton (fragment header + elements + `0x00`) |

**Substitution array** (carried by the instance):

| Offset | Size | Field |
|-------:|-----:|-------|
| 0 | 4 | value count `n` |
| 4 | `4·n` | descriptors: `size` (2) + `type` (1) + reserved (1) |
| … | … | the values, back-to-back, in descriptor order |

To render one record:

1. Read its token stream; on `0x0c`, resolve the template by ID in the chunk's template table.
2. Walk the template skeleton. Each `0x0d`/`0x0e` carries a substitution **id** (index into the array) and a type.
3. For each placeholder, read array entry `[id]`, type-check it against the declared type, and inline it — recursing if the type is `0x21` (BinXML) or iterating if the high `0x80` bit marks an array.

## Worked decode (schematic)

A `<System>` element with a substituted computer name decodes roughly like this. Bytes are illustrative — the *grammar* is exact:

```
0F 01 01 00              FragmentHeader (major 1, minor 1, flags 0)
0C ..(template ref).. │  TemplateInstance → resolve template T in chunk
                         template T skeleton, walked token by token:
  41 .. <Computer>       OpenStartElement "Computer" (0x41: has content)
    02                   CloseStartElement  >
    0E 00 00 01          OptionalSubstitution id=0, type=0x01 (String)
    04                   EndElement  </Computer>
  00                     EndOfStream

substitution array:
  count = 1
  [0] size=0x1A type=0x01  → "WIN-DC01" (UTF-16LE)
```

Result: `<Computer>WIN-DC01</Computer>`. Multiply that by ~20 placeholders and you have a 4624 event; the template (`<System>`, `<EventData>`, every element name) is stored once for the whole chunk and every 4624 record in it is just a fresh substitution array. That deduplication is what keeps EVTX small and what makes a half-finished parser wrong. The token-by-token mechanics — names, hashes, nested fragments — are their own subject: see [how BinXML actually works](/en/blog/binxml-format-explained).

## Validation and recovery checklist

- **Header CRC-32** (file `+124`, chunk `+124`) and **records CRC-32** (chunk `+52`) — mismatches mean corruption or tampering, not necessarily an unreadable file.
- **`NextRecordIdentifier`** vs the last record's ID — a gap means records are missing (truncation, or selective deletion).
- A **dirty trailing chunk** may end mid-token; robust parsers recover what precedes the break and report the chunk, rather than failing the whole file.
- Each complete chunk stands alone: wrap a carved chunk in a synthetic 4 KB header and it parses.

## Sources & further reading

- Andreas Schuster, ["Introducing the Microsoft Vista Event Log File Format"](https://www.dfrws.org/sites/default/files/session-files/paper-introducing_the_microsoft_vista_log_file_format.pdf) — DFRWS 2007, the original reverse-engineering work.
- Joachim Metz, [`libevtx` format specification](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) — the most complete public reference; the tables above follow it.
- Willi Ballenthin, [`python-evtx`](https://github.com/williballenthin/python-evtx) — read `Evtx/Nodes.py` for the BinXML node hierarchy.
- Omer Ben-Amram, [`evtx` (Rust)](https://github.com/omerbenamram/evtx) — the fast parser whose WASM build powers the [in-browser parser on this site](/en/blog/how-to-open-an-evtx-file).
- Companion posts: [the EVTX format, decoded](/en/blog/evtx-file-format) · [chunks, templates and BinXML internals](/en/blog/evtx-file-format-chunks) · [what is an EVTX file](/en/blog/what-is-an-evtx-file).

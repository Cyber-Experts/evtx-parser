---
title: "How BinXML actually works: decoding the EVTX token stream"
description: "A token-by-token walkthrough of BinXML — the binary XML encoding inside .evtx records. Names, hashes, templates, the substitution array, nested fragments, and the edge cases that break parsers."
date: "2026-06-17"
tags:
  - evtx
  - binxml
  - file-format
  - dfir
  - reverse-engineering
author: "Florian Amette"
---

If you have read the [byte-level format reference](/en/blog/evtx-file-format-reference), you know an EVTX record is a BinXML stream that references a template. This post is about what actually happens inside that stream: how a sequence of bytes becomes `<Event><System>…</System><EventData>…</EventData></Event>`. It is the part almost every "EVTX explained" article waves past, and it is the part you have to get exactly right to write — or trust — a parser.

BinXML is not compression and it is not "XML with the angle brackets removed." It is a small stack-based grammar of typed tokens. Everything is **little-endian**.

## The grammar in one paragraph

A BinXML fragment is a `FragmentHeader` (`0F 01 01 00`) followed by element tokens, value tokens, and substitutions, terminated by `EndOfStream` (`0x00`). Elements open with `OpenStartElement`, optionally carry `Attribute` tokens, switch to content with `CloseStartElement`, hold values or child elements, and close with `EndElement`. The whole [token table is in the reference](/en/blog/evtx-file-format-reference); the only subtlety in the opcodes is the `0x40` "has-more" flag bit (e.g. `0x41` = an element that has attributes or content, versus `0x01`).

## Names: the part that surprises people

Element and attribute names are not stored as strings inline. Each name is an entry of the form:

```
unknown   4 bytes   (a forward pointer; absent inside template definitions)
hash      2 bytes   (a checksum of the name, used as a table key)
length    2 bytes   (character count, excluding the terminator)
string    length×2  UTF-16LE
term      2 bytes   0x0000
```

Names are interned **once per chunk** in the string table (the 64-entry offset array at chunk offset 128). A record that mentions `Provider` doesn't store the word; it stores an offset to the one copy in the chunk. This is exactly why a record carved without its chunk renders as a bag of values with no element names, and why a parser that ignores the string table prints `Unknown` for every provider.

## Templates: store the skeleton once

Almost no event is emitted as raw element tokens. The writer emits a **TemplateInstance** (`0x0c`): "use template T, with these values." The template `T` is the XML skeleton — every element name, attribute, and tree position for, say, a 4624 logon — stored once per chunk and keyed by a 16-byte GUID and a template id. The full template-definition and substitution-array layouts are in the [reference tables](/en/blog/evtx-file-format-reference); here is what matters when you decode by hand.

The skeleton contains **placeholders** instead of variable values. A placeholder is one of:

- `NormalSubstitution` `0x0d` — `[id]` `[type]`: always insert value number `id`.
- `OptionalSubstitution` `0x0e` — `[id]` `[type]`: insert value `id`, **but if it is null, omit the enclosing element entirely**.

That `0x0d` vs `0x0e` distinction is the single most common BinXML bug. Render an optional substitution as if it were normal and you produce `<Data Name="SubjectUserName"></Data>` where the genuine log has nothing at all — which quietly changes what your downstream `grep`, SIEM field-extraction, or [EvtxECmd map](/en/blog/evtx-file-format) sees.

## The substitution array

The instance carries a typed array of the per-record values:

```
count        4 bytes        number of values, n
descriptors  4×n bytes      each: size(2) + type(1) + reserved(1)
values       Σ size bytes   the raw values, in order
```

Decoding a placeholder `0x0e 03 00 01` means: optional substitution, `id = 3`, declared type `0x01` (String). Walk to descriptor 3 to get its byte size, read that many bytes from the value region, decode as UTF-16LE, and inline it — unless the value is null, in which case drop the parent element.

The [value-type table](/en/blog/evtx-file-format-reference) lists every type. Two of them are where parsers earn their keep:

- **`0x21` BinXmlType** — the value is *itself a BinXML fragment*. `EventData`/`UserData` payloads nest this way, so the decoder must **recurse** into a fresh fragment using the same chunk's tables. Miss this and complex events collapse to empty bodies.
- **`0x80`+ array types** — one placeholder expands to many elements (e.g. an array of SIDs). If the array length is zero, the result is a single empty element, not an error.

## A complete record, end to end

Putting it together, decoding one record is:

1. Read the record header; the payload starts at record offset 24.
2. `0F 01 01 00` — fragment header.
3. `0x0c` — template instance. Resolve template `T` by id/GUID in the chunk's template table (it may have been defined by an *earlier* record in the chunk and only referenced here — resolve by table, never only inline).
4. Read the substitution array: count, descriptors, values.
5. Walk `T`'s skeleton token by token. Emit element/attribute names (resolved through the string table). On each `0x0d`/`0x0e`, splice in the typed value from the array, recursing on `0x21` and iterating on `0x80`+.
6. Stop at `EndOfStream` `0x00`.

The output is the same XML you see on the *Details → XML* tab in Event Viewer, or in the detail panel of the [browser parser on this site](/en/blog/how-to-open-an-evtx-file).

## Edge cases that break naive parsers

- **Template referenced before seen inline.** Resolve templates through the chunk table, not by remembering only ones you parsed inline.
- **Optional vs normal substitution.** Covered above — the difference is presence/absence of an element, not just of a value.
- **Nested BinXML (`0x21`).** Requires recursion with the *same* chunk context.
- **Empty arrays.** Length-zero array → one empty element, not a parse error.
- **Hash collisions in the name table.** The 2-byte name hash is a lookup hint, not an identity; match on offset.
- **Dirty trailing chunk.** The last record may end mid-token; recover the records before the break and flag the chunk rather than failing the file.

## Where to verify this against working code

The cleanest reference implementations to read are Willi Ballenthin's [`python-evtx`](https://github.com/williballenthin/python-evtx) (`Evtx/BinaryParser.py` and `Evtx/Nodes.py`) and Omer Ben-Amram's [`evtx` Rust crate](https://github.com/omerbenamram/evtx) (`src/binxml/`). Joachim Metz's [`libevtx` spec](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20%28EVTX%29.asciidoc) is the document those implementations are checked against, and the one this post follows.

Continue with the [complete byte-level reference](/en/blog/evtx-file-format-reference) for the field tables, or [chunks, templates and BinXML internals](/en/blog/evtx-file-format-chunks) for the chunk-level view.

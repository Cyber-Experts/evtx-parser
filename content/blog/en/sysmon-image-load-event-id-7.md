---
title: "Sysmon Event ID 7: image loads, DLL hijacking and sideloading"
description: "Using Sysmon's image-load event to catch DLL search-order hijacking, sideloading and unsigned modules — the fields, the signature checks that matter, and how to manage its very high volume."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - sysmon
  - dll-hijacking
  - threat-hunting
author: "Florian Amette"
---

**Sysmon Event ID 7** fires every time a process loads a module (a DLL). That makes it the event for catching **DLL hijacking, sideloading, and unsigned code** running inside otherwise-trusted processes — and also one of the noisiest events Sysmon can produce. Used with discipline it finds attacks that process-creation logging ([Sysmon 1](/en/blog/sysmon-event-id-1-process-create) / [4688](/en/blog/event-id-4688-process-creation)) never sees, because the malicious code is a DLL, not a new process.

## The fields that matter

| Field | Use |
|-------|-----|
| `Image` | the process doing the loading |
| `ImageLoaded` | **the DLL being loaded** — path and name |
| `Signed` / `Signature` / `SignatureStatus` | is the DLL signed, by whom, and is it valid |
| `Hashes` | hash of the DLL for reputation lookup |
| `OriginalFileName` | the name the DLL was compiled with — mismatch with the on-disk name is a tell |

The pairing of **`Image` + `ImageLoaded` + `Signed`/`SignatureStatus`** is where most detections live.

## What to hunt

- **DLL search-order hijacking / sideloading.** A signed, legitimate executable loading a DLL from an unusual directory — `%TEMP%`, `%APPDATA%`, a user folder, or alongside a planted copy of a trusted EXE. The classic pattern: a trusted vendor binary (the "host") sideloading an attacker DLL placed next to it.
- **Unsigned DLLs in suspicious paths.** `SignatureStatus` not `Valid`, loaded from a user-writable location.
- **OriginalFileName mismatch.** The `ImageLoaded` filename differs from the embedded `OriginalFileName` — a renamed/planted DLL.
- **Trusted process, untrusted module.** `lsass.exe`, `explorer.exe`, `svchost.exe`, or an Office app loading a DLL that isn't a known system/vendor module.
- **Known-bad module names** (Cobalt Strike artifacts, credential-theft DLLs) by hash or name.

## The signature fields are the leverage

EID 7's value is the signing metadata. Prioritise:

1. `SignatureStatus != Valid` (unsigned, expired, or invalid) **and** a user-writable `ImageLoaded` path → top of the queue.
2. `Signed=true` but the signer is unexpected for that module → possible signed-malware or stolen cert.
3. `OriginalFileName` ≠ on-disk name → renamed binary.

A valid Microsoft/vendor signature from a system path is the common benign case you filter out.

## Volume: the real obstacle

EID 7 is **off by default and extremely high-volume** — every process loads dozens of DLLs at startup. Practical guidance:

- **Never enable it broadly without filtering.** Good configs scope EID 7 to specific high-risk processes (Office, browsers, script hosts, `rundll32`/`regsvr32`) or to unsigned/non-standard paths only. See [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries).
- **Expect short retention.** Even filtered, it's chatty; collect promptly.
- **Empty ≠ safe.** If the config excludes a process, hijacks inside it won't appear.

## Correlate

```
Sysmon 1 / 4688   a trusted signed EXE launches from an odd path
Sysmon 7          it loads an unsigned DLL from the same odd path  (sideload)
Sysmon 3 / 22     the now-hijacked process beacons out
```

The sideload (EID 7) is the mechanism; the network events are the payoff. Read them together on a [timeline](/en/blog/event-log-timeline-incident-response).

## Hunt checklist

- Filter Sysmon/Operational to **EID 7**.
- Flag `SignatureStatus != Valid` from **user-writable paths**.
- Flag **trusted EXE + DLL from non-standard directory** (sideloading).
- Flag **OriginalFileName mismatches** and unexpected signers.
- Confirm the config logs the processes you care about.

Open the Sysmon log in the [browser parser](/en/blog/how-to-open-an-evtx-file) and pivot on `Image` + `ImageLoaded` + `SignatureStatus`. Full Sysmon set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

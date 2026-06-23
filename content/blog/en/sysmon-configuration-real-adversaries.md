---
title: "Sysmon configuration that catches real adversaries"
description: "An opinionated take on Sysmon: which event IDs actually matter in IR, why olafhartong/sysmon-modular is the right baseline, and the configuration mistakes that blind you to real attacks."
date: "2026-05-27"
tags:
  - sysmon
  - evtx
  - detection-engineering
  - dfir
  - threat-hunting
author: "Florian Amette"
---

Sysmon is the single highest-leverage thing you can deploy on a Windows endpoint. It is free, it is signed by Microsoft, and a well-configured Sysmon turns Windows from a black box into something you can actually investigate. A badly configured Sysmon, on the other hand, is the same disk-space cost with most of the visibility excluded by overly aggressive filters. I have walked into more environments with the second than the first.

This is the configuration posture I argue for in every engagement that touches endpoint visibility.

## The EIDs that earn their disk space

Sysmon defines 29 event IDs as of version 15. You do not need all of them. The ones that pay back the storage they cost, in order of return-per-byte:

- **EID 1 — Process create**. The single most useful event in DFIR. Parent process, child process, command line, integrity level, user, both process hashes, and the process GUID. If you log nothing else from Sysmon, log this.
- **EID 3 — Network connection**. Every outbound TCP/UDP connection with source process, destination IP, port, and the process image. The C2 detection event. Filter is essential here (a default install logs every browser request and your retention burns in a week), but the value-per-event is extreme. Catch outbound to unusual destinations from unusual processes (`rundll32.exe` to a residential IP, `mshta.exe` to anything).
- **EID 7 — Image loaded**. DLL and driver loads with the loaded image hash and signing status. This is how you catch DLL search-order hijacking, sideloading, and unsigned drivers. Expensive to log everything; cheap and high-yield to log unsigned modules and modules loaded from non-standard locations.
- **EID 10 — Process accessed**. Cross-process memory access events with the source process, target process, granted access mask, and the call trace. This is the credential-dumping event. `mimikatz` opens `lsass.exe` with `PROCESS_VM_READ` (`0x10`) and `PROCESS_QUERY_INFORMATION` (`0x400`). Every modern dumper does. The detection writes itself.
- **EID 11 — File created**. New file creates with the writing process. Catches dropper activity that did not get to execute, ransomware staging, and most LOLBin-mediated payload writes.

These five are the foundation. If you have only those, configured well, you have caught most of what you would call a real intrusion before it became one.

The next tier worth turning on:

- **EID 8 — CreateRemoteThread**. Thread injection across process boundaries. The classic process injection event.
- **EID 13 — Registry value set**. Persistence via registry. Tune to the run keys, services, image file execution options, and the COM hijack paths.
- **EID 17/18 — Named pipe created/connected**. Cobalt Strike beacons and many post-exploitation frameworks use named pipes for SMB and inter-process comms. The pipe names are often defaults that survive engagement-to-engagement.
- **EID 22 — DNS query**. Outbound DNS with the requesting process. Catches DNS-based C2 (DGA, DNS tunnel) when EID 3 missed the connection because it never opened a TCP/UDP socket.
- **EID 25 — Process tampering**. Image manipulation events ([process hollowing](https://www.reverseengineering.app/en/techniques/process-hollowing), [doppelganging](https://www.reverseengineering.app/en/techniques/process-doppelganging)). Sysmon 13+.

EID 12 (registry key/value create), 14 (registry key/value renamed), 15 (file stream created with FileCreateStreamHash) and 23 (file delete with archive) are useful in specific investigations but produce too much volume to log everywhere by default. Turn them on for a host you are watching closely or for specific paths.

EID 2 (process changed file creation time) is a niche anti-timestomp event. Worth it on file servers. Optional elsewhere.

EID 4, 5, 6 (Sysmon state events) are operational, not detection. Log them so you can tell when Sysmon was tampered with.

## Why `olafhartong/sysmon-modular` is the right starting point

There are a half-dozen public Sysmon configs of varying quality. The two most cited are SwiftOnSecurity's `sysmon-config` and Olaf Hartong's `sysmon-modular`. Both are good. `sysmon-modular` is the one I push toward because of its structure.

The modular layout splits filters by EID and by technique into individual XML files that are concatenated at deployment. The benefits this gives you:

- **Diffability**. Changes to a single technique's filter show up as a single-file diff in git. Compare to a 4000-line monolithic XML where a small change disappears in the noise.
- **Per-environment overlays**. You commit the upstream tree and layer your environment-specific exclusions on top in your own files. When upstream updates a filter, you `git merge` and your overlays survive.
- **Coverage-driven authoring**. Filters are organized by MITRE ATT&CK technique. You can see at a glance which techniques you have coverage for and which you do not. The gap analysis is the file tree.
- **Active maintenance**. Hartong updates the repo against new techniques and new Sysmon versions. The SwiftOnSecurity config has long stretches of stagnation between updates.

Start from `sysmon-modular`. Commit it into your config-management tree. Layer your exclusions. Do not write your own from scratch; you will miss things.

## The configuration mistakes that blind you

The patterns I see in real engagements that cost the most visibility:

**Excluding too aggressively on EID 1**. The instinct is to exclude every chatty legitimate process to keep volume manageable. The mistake is excluding by parent path or image without thinking about what an attacker can spawn from that parent. If you exclude every child of `services.exe`, you have excluded the exact place that PsExec-installed service binaries run from. Exclude by `User` (system accounts running known-good binaries), by `IntegrityLevel`, and by precise `CommandLine` match, not by parent alone.

**Excluding EID 3 by image name**. "Exclude all network connections from `chrome.exe`" is the canonical bad rule. The first thing an attacker does when they need to evade EID 3 logging is hijack a browser process. Exclude by destination IP range (RFC1918 to RFC1918, your own infra), by port (the IPC port set you have validated), or by process+destination tuple. Never by image alone.

**Not logging EID 7 at all**. Image load logging is the heaviest Sysmon EID by volume. The temptation to disable it is strong. The cost of disabling it is that DLL sideloading, the single most common technique in modern intrusions, is invisible to you. The middle path: filter `Image load` to unsigned modules, modules loaded from `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%PUBLIC%`, and `%PROGRAMDATA%`, and modules with names matching known abuse lists. This drops the volume by an order of magnitude and keeps the signal.

**Missing EID 11 entirely on user-writable paths**. EID 11 logged for `%TEMP%`, `%APPDATA%\Roaming`, `%LOCALAPPDATA%`, and `%PUBLIC%` catches almost every dropper. Some configs exclude these because of volume. The volume is the point: that is where the writes that matter happen.

**Not including the hash algorithm you want**. The `<HashAlgorithms>` element controls which hashes Sysmon computes. The default is SHA1 only. `IMPHASH` is the import-hash, used heavily in malware tracking; `SHA256` is what most threat intel platforms key on. Set `<HashAlgorithms>md5,sha256,imphash</HashAlgorithms>` so the events line up with what your intel data uses.

**Not logging command lines on parent**. Sysmon EID 1 logs both `CommandLine` (child) and `ParentCommandLine` (parent). Some configs disable `ParentCommandLine`. This kills the most useful pivot in process-tree investigation; without it you have a parent image name but no idea what arguments started that parent.

**Not enabling EID 22 (DNS) at all**. DNS logging is recent (Sysmon 10+) and many configs predate it. Turn it on. Filter chatty hosts (`*.windowsupdate.com`, your internal AD), log everything else.

## The disk-space tradeoff

A well-configured Sysmon on a typical workstation produces 100-500 MB of EVTX per day. On a busy server, 1-5 GB. The default channel size is 64 MB, which means the `Microsoft-Windows-Sysmon%4Operational.evtx` file rolls in hours and your usable retention is short.

The fix is two-step. First, raise the channel size. `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:4294967296` sets it to 4 GB, which gives you days to weeks on most hosts. Second, forward to a central collector with longer retention. WEC works; SIEM agents work; the [Sysmon-modular WEC subscription](https://github.com/olafhartong/sysmon-modular) repo has the XML for the channel subscription.

Centralized retention matters more than local retention because the local file is what the attacker can clear. A forwarded copy at a collector they cannot reach is the durable record. Configure both.

## What good Sysmon looks like in an investigation

A host with `sysmon-modular` deployed, all five core EIDs logging, EID 7 filtered to interesting modules, and forwarding to a collector, gives you:

- A process tree for every execution on the host, with command lines, hashes, and the user context.
- Every outbound network connection with the originating process.
- Every DLL load from a user-writable directory.
- Every memory access against `lsass.exe`.
- Every file creation in `%TEMP%` and `%APPDATA%`.
- Every DNS query with the requesting process.

The intrusion story reads itself off this data. You do not need to guess. You do not need to carve. You read it, top to bottom, and the gaps in the story are the questions to chase. Cross-reference with [AmCache](https://www.amcacheparser.com) and [Prefetch](https://www.prefetchparser.com) for binary execution evidence, the [registry](https://www.registryparser.com) for persistence, and the [USN journal](https://www.usnparser.com) for the file-system mutations that Sysmon's EID 11 may have missed if its filter was off. The [parser on this site](https://www.evtxparser.com) reads Sysmon channels with the same fidelity as Security.evtx.

Without Sysmon, you have `Security.evtx` and a wishlist.

## Further reading

- Olaf Hartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular). The repo. Read the README, then read three or four of the technique-specific XML files to get a feel for the filter style.
- Microsoft's [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). The official reference; thin but accurate.
- Roberto Rodriguez's [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook). Sysmon-driven hunts with the queries spelled out.
- The [TrustedSec sysmon-community-guide](https://github.com/trustedsec/SysmonCommunityGuide). The reference doc for filter semantics.

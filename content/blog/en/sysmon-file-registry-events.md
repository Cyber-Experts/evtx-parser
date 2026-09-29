---
title: "Sysmon file and registry events: 11, 12–14, 15 and 23/26"
description: "Tracking dropped files, registry persistence, alternate data streams and self-deletion with Sysmon — FileCreate (11), registry events (12/13/14), FileCreateStreamHash (15) and FileDelete (23/26)."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - sysmon
  - persistence
  - threat-hunting
author: "Florian Amette"
---

After a process runs and reaches the network, it usually touches the disk and the registry — dropping payloads, writing persistence, and sometimes cleaning up. Sysmon's file and registry events capture all of that, and together they reconstruct what an intrusion *left behind*. This rounds out the Sysmon series ([process](/en/blog/sysmon-event-id-1-process-create), [network](/en/blog/sysmon-network-connection-event-id-3), [injection](/en/blog/sysmon-process-injection-event-id-8-10)).

## Event ID 11 — FileCreate

Fires when a file is created or overwritten. Fields: `Image` (who), `TargetFilename` (what), `CreationUtcTime`.

Hunt for:

- **Payloads in user-writable paths** — `%TEMP%`, `%APPDATA%`, `%PUBLIC%`, `C:\Users\…\Downloads`, `C:\Windows\Temp`.
- **Startup-folder persistence** — files written to `…\Start Menu\Programs\Startup`.
- **Web shells** — files written under a web root (`inetpub`, `wwwroot`) by `w3wp.exe` or a service account.
- **Script-host / Office** (`wscript`, `powershell`, `winword`) creating executables or scripts.
- **Tooling drops** — `.exe`/`.dll`/`.ps1`/`.bat` from a process that has no business writing them.

`CreationUtcTime` is also a timestomping reference: if `$STANDARD_INFORMATION` on disk later disagrees with Sysmon's recorded creation time, you have evidence of timestamp manipulation.

## Event IDs 12, 13, 14 — Registry

| ID | Meaning |
|---:|---------|
| 12 | registry key/value **created or deleted** |
| 13 | registry **value set** (the data written) |
| 14 | key/value **renamed** |

Registry is where a lot of persistence lives, so target the known keys:

- **Run / RunOnce** — `…\CurrentVersion\Run`, `RunOnce` (per-user and machine).
- **Services** — `HKLM\SYSTEM\CurrentControlSet\Services\…` (pairs with [7045](/en/blog/service-creation-event-id-7045)).
- **Winlogon** — `Shell`, `Userinit`, `Notify`.
- **Image File Execution Options** (debugger hijack), **AppInit_DLLs**, **COM hijacks** (`HKCU\…\CLSID`).
- **Defender tampering** — disabling real-time protection via policy keys.

EID 13 gives you the **value data** — the actual command or path being persisted — which often is the whole finding.

## Event ID 15 — FileCreateStreamHash (alternate data streams)

Fires when an **alternate data stream** is created, and hashes the content. Two big uses:

- **Mark of the Web** — the `Zone.Identifier` ADS browsers add to downloaded files tells you a file came from the internet (and from where).
- **ADS payload hiding** — attackers stash executables/scripts in ADS to evade casual inspection. A non-`Zone.Identifier` stream containing executable content is suspicious.

## Event IDs 23 and 26 — FileDelete

- **23** — FileDelete (archived): deletion logged, and Sysmon can **preserve a copy** of the deleted file if configured.
- **26** — FileDeleteDetected: deletion logged without archiving.

Hunt for **self-deletion / anti-forensics**: malware removing its own dropper after execution, tools wiping logs or staging files. A process that [drops (11), executes, then deletes (23/26)](/en/blog/evtx-tampering-what-survives) its own artifacts is covering tracks — and with EID 23 archiving on, you may still recover the file.

## Volume and config

These vary in noise: registry (12–14) and FileCreate (11) are manageable when scoped; un-scoped they're heavy. Real configs target the persistence keys and high-risk paths above rather than logging everything — see [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries). As always, an excluded path means a blind spot.

## Correlate

```
Sysmon 1 / 4688   process executes
Sysmon 11         drops payload to %APPDATA%
Sysmon 13         writes a Run key pointing at it          (persistence)
Sysmon 23/26      deletes the original dropper             (cleanup)
```

The drop → persist → clean sequence is a complete persistence story in three file/registry events. Assemble it on a [timeline](/en/blog/event-log-timeline-incident-response).

## Hunt checklist

- **EID 11**: executables/scripts in user-writable paths, startup folders, web roots.
- **EID 13**: writes to Run/Services/Winlogon/IFEO keys — read the value data.
- **EID 15**: non-`Zone.Identifier` streams with executable content.
- **EID 23/26**: self-deletion around execution; recover archived copies if available.
- Correlate every drop/persist/delete back to its `Image` and the spawning [process event](/en/blog/event-id-4688-process-creation).

Open the Sysmon log in the [browser parser](/en/blog/how-to-open-an-evtx-file) and pivot on `Image` + `TargetFilename` / `TargetObject`. Full map in the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

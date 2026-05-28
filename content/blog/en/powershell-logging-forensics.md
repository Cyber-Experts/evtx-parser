---
title: "PowerShell logging: what you get with module and script block logging on"
description: "The practical difference between PowerShell module logging, script block logging, transcripts, and AMSI buffers — and the GPO settings that actually turn the useful ones on."
date: "2026-05-27"
tags:
  - evtx
  - powershell
  - dfir
  - logging
  - threat-hunting
author: "Florian Amette"
---

Every adversary toolkit worth worrying about runs PowerShell at some point. Cobalt Strike beacons launch it. Empire and Covenant are built on it. Living-off-the-land guides start with it. The good news is that since PowerShell 5.0, Microsoft has shipped logging that, when configured correctly, captures the literal text of everything PowerShell executes, including obfuscated payloads after deobfuscation. The bad news is that "when configured correctly" is doing a lot of work in that sentence. Most environments I walk into have one of the four relevant logs on, not all four, and not the most useful one.

This post is what you actually get, what is worth turning on, and where the gaps are.

## The four logs, in order of usefulness

PowerShell writes to `Microsoft-Windows-PowerShell%4Operational.evtx`. The event IDs that matter:

- `4104` — script block logging. The literal text of every script block PowerShell compiles and executes. If a block is flagged as suspicious by the built-in heuristics, it logs at Warning severity; otherwise at Verbose, which is off by default. This is the event you want.
- `4103` — module logging. Records pipeline execution per module, with parameter binding. Less prose than `4104`, more structured. Useful for "what cmdlets ran" without the script body.
- `4105` and `4106` — pipeline started and pipeline stopped. Useful for bracketing, not for content.
- `400` / `403` (legacy, PowerShell 2.0 era) — engine state changes. The forensic-historical events. You will still see these on hosts where someone forced a PS 2.0 downgrade attack.

If you can turn on exactly one thing, turn on `4104` at Verbose. Everything else is supplementary.

## What `4104` actually captures

A `4104` event contains the full text of a script block as PowerShell compiled it. Two things follow from "as PowerShell compiled it":

- The text in the event is the *post-deobfuscation* representation in most cases. If an operator runs `iex ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...')))`, you get both the outer `iex` call (which is itself a `4104`) and a *second* `4104` for the inner decoded script block, because PowerShell had to compile that block to run it. This is the single most valuable property of `4104` logging.
- Large scripts are split across multiple events using `MessageNumber` and `MessageTotal` in the event data. A 50 KB script becomes a chain of events that you have to reassemble before analysis. Most tools do this; some do not. If your parser is showing you fragments, check whether it handles the chain.

The `Path` field shows the source file if there was one. Empty `Path` plus a fully inlined script body equals "this came in over the wire or out of memory" and is the single best heuristic for finding interactive operator activity versus scheduled scripts.

The `ScriptBlockId` is a GUID. Re-runs of the same block on the same host typically reuse the GUID (because of the cache), which is convenient for finding "every host this code ran on" if you have a SIEM with cross-host search.

## Module logging: what `4103` adds

Module logging is older and noisier than script block logging. It hooks the pipeline execution layer, so for every cmdlet invocation in a logged module you get a `4103` with the cmdlet name, the bound parameters, and a payload string.

In modern IR, `4103` is most useful in three cases:

- The attacker used cmdlets that bind interesting parameters (`Invoke-WebRequest -Uri ...`, `New-Object Net.Sockets.TcpClient ...`, `Get-WmiObject -Class Win32_ShadowCopy`). `4104` shows the source; `4103` shows the resolved parameter values after variable expansion.
- The attacker used encoded commands. `powershell -enc <base64>` produces a `4103` with the decoded text in the payload before the corresponding `4104` is emitted.
- The attacker disabled `4104` (it is achievable by registry edit if they have local admin). `4103` lives under a separate logging path and is sometimes left on when `4104` is silenced.

The catch: module logging logs only modules that are explicitly enabled. The GPO setting wants either `*` (log everything) or a list of module names. `*` is the answer in any environment that takes logging seriously. The "performance impact" objection you will hear is real for very heavy PowerShell workloads and is wrong for ordinary fleet desktops.

## Transcripts are not script block logs

There is a separate setting called "Turn on PowerShell Transcription" that writes every session's input and output to a text file under a configured directory. This is not the same thing as `4104` and people conflate them constantly.

The differences that matter:

- Transcripts include cmdlet *output*. `4104` does not. If you want to know what `Get-ADUser` actually returned, transcripts are it.
- Transcripts are text files. They are trivially deletable and trivially modifiable on a compromised host. `4104` events go to an EVTX channel that requires log clearing or worse to disturb.
- Transcripts default to the user's documents folder unless `OutputDirectory` is set. If you do not set `OutputDirectory` to a write-only network share, transcripts are not evidence; they are a courtesy.

Turn transcripts on with `OutputDirectory` pointed at a UNC path where the writing user has write-only NTFS permissions (no read, no delete). That gives you the cmdlet-output trail that `4104` does not, without giving the attacker the option to alter or remove their own history.

## AMSI and the buffer angle

AMSI (the Antimalware Scan Interface) is the runtime hook that allows Defender and other AV products to inspect PowerShell script content before execution. Two consequences for forensics:

- Even if the attacker disables PowerShell logging, AMSI still sees the script content right before execution, and Defender will log a `1116` or `1117` in `Microsoft-Windows-Windows Defender%4Operational.evtx` if the content matches a signature. The Defender event includes the script text, partially, in the threat detection record. On hosts where script block logging was off, this is sometimes the only place the malicious code lives.
- The "AMSI bypass" techniques attackers use (patching `amsi.dll!AmsiScanBuffer` in memory, providing a forged `AmsiContext`, COM hijack of the AMSI provider) will themselves typically generate `4104` events for the bypass code, *before* the bypass takes effect. The bypass cannot turn off logging retroactively. So even on hosts where the operator successfully neutralized AMSI, the moment they did it is on the wire.

The pattern to look for in `4104`: small script blocks containing the strings `amsiInitFailed`, `AmsiScanBuffer`, `VirtualProtect`, or `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`. These are the signatures of every common bypass.

## Turning the logging on

The GPO settings live under `Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell`. The three you want enabled:

- "Turn on PowerShell Script Block Logging" — enabled. Tick "Log script block invocation start / stop events" if you want the bracketing `4105`/`4106` events; off by default and usually not worth the volume.
- "Turn on Module Logging" — enabled. Module names: `*`.
- "Turn on PowerShell Transcription" — enabled. `OutputDirectory`: a UNC path. `Include invocation headers`: checked.

The corresponding registry paths if you are setting them outside of GPO:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
    EnableScriptBlockLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging
    EnableModuleLogging = 1
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames
    * = *
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    EnableTranscripting = 1
    OutputDirectory = \\logserver\transcripts$
```

Apply to the OUs that contain machines you would have to investigate. That is "all of them" in any serious organization.

## What this looks like during an investigation

A compromise where script block logging was on tells you, in order:

1. The first `4104` with a non-trivial script block from a non-standard parent. Time of first execution.
2. The chain of `4104`s as the loader unpacks itself. Each layer of obfuscation peeled off and logged.
3. The C2 framework's runtime cmdlets (Invoke-Beacon, Invoke-Mimi, `Invoke-Kerberoast`, every common offensive cmdlet name and its renamed variants).
4. The interactive operator's hands-on-keyboard commands. These read like a recorded shell session, because that is what they are.

Cross-reference against [Prefetch](https://www.prefetchparser.com) to find when `powershell.exe` ran, [LNK files](https://www.lnkparser.com) for files the operator opened, [AmCache](https://www.amcacheparser.com) for the hash of the PowerShell binary itself (it gets renamed sometimes), and the [registry](https://www.registryparser.com) for the GPO state to confirm logging really was on at the time of the events you are reading.

A compromise where script block logging was off tells you almost nothing about PowerShell, and a lot about your detection posture. Fix that first.

## Further reading

- Microsoft's [PowerShell logging documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows). The official reference.
- FireEye / Mandiant's [Greater Visibility Through PowerShell Logging](https://www.mandiant.com/resources/blog/greater-visibility) post. Old but still the cleanest field-perspective writeup.
- Daniel Bohannon's [Revoke-Obfuscation](https://github.com/danielbohannon/Revoke-Obfuscation) project. The deobfuscation toolkit that complements `4104` analysis.

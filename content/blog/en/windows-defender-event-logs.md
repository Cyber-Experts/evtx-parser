---
title: "Windows Defender event logs: detections and tampering"
description: "Reading Microsoft Defender's Operational log in DFIR — malware detections (1116/1117), real-time protection disabled (5001), and the settings changes (5007) attackers use to add exclusions and go quiet."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - defender
  - anti-forensics
  - threat-hunting
author: "Florian Amette"
---

Windows Defender is on almost every modern Windows host, which makes its event log a quietly excellent source — it records both **what it caught** and, just as usefully, **when someone tried to blind it**. The detections tell you the malware that touched the box; the tampering events tell you the attacker knew Defender was there and dealt with it. Both belong in every triage. This fits the [endpoint-controls and anti-forensics](/en/blog/audit-policy-tampering-4719) themes.

## Where it lives

The channel is **`Microsoft-Windows-Windows Defender/Operational`**. It is on by default, so unlike most [Sysmon events](/en/blog/sysmon-event-id-1-process-create) you get this for free on any host with Defender enabled.

## Detections: 1116 and 1117

| ID | Meaning |
|---:|---------|
| **1116** | Malware (or other potentially unwanted software) **detected** |
| **1117** | **Action taken** on detected malware (quarantine, remove, block) |
| 1118 / 1119 | Action attempted / action failed |
| 1015 / 1006 | Suspicious behaviour / engine found malware |

The fields on a 1116/1117 are a free triage lead: the **threat name**, the **file path** / **process**, the **detection source** (real-time, scan, AMSI), and the **user**. A 1116 naming a path in `%TEMP%` or `%APPDATA%`, or an AMSI detection on a PowerShell script, points you straight at the artefact — pivot from there to the [process](/en/blog/event-id-4688-process-creation) and [script-block](/en/blog/powershell-4104-scriptblock) events around it.

A subtle but important reading: a **1116 with a failed or absent 1117** means Defender *saw* something but didn't (or couldn't) remove it — the threat may still be live. Don't assume "Defender detected it" equals "Defender handled it."

## Tampering: 5001 and 5007

This is where Defender's log earns its place in anti-forensics:

| ID | Meaning |
|---:|---------|
| **5001** | **Real-time protection disabled** |
| 5004 | Real-time protection configuration changed |
| **5007** | Defender **configuration/settings changed** |
| 5010 / 5012 | Scanning for malware / antivirus disabled |

The high-value hunt is **5007 adding exclusions**. Attackers routinely exclude a folder, process, or extension so their tooling can run unscanned — `Add-MpPreference -ExclusionPath C:\Temp` and friends. A 5007 that adds an exclusion path/process during an incident window is a strong evasion signal, and it names exactly where they intended to operate. **5001** (real-time protection off) is the blunter version of the same intent.

## ASR and network protection (bonus)

If Attack Surface Reduction is configured, Defender also logs:

- **1121 / 1122** — an ASR rule **blocked / audited** an action (e.g. Office spawning a child process, credential theft from LSASS).
- **1125 / 1126** — network protection blocked/audited a connection.

These are high-signal because ASR rules target specific attacker techniques — a 1121 is often a near-miss worth investigating regardless of outcome.

## The patterns to hunt

- **5007 exclusion added** (path/process/extension) — then look for activity *in* that excluded location.
- **5001 / 5010** real-time protection or AV disabled by a non-admin or during the incident window.
- **1116 without a successful 1117** — detected but not remediated.
- **Repeated 1116s** for the same threat — reinfection or a persistence mechanism re-dropping.
- **1116/1121 naming LOLBins** (`rundll32`, `mshta`, Office children) — technique-level detections.

## Correlate

```
4624 (+4672)   actor logs on with privilege
5007           Defender exclusion added for C:\ProgramData\x   (evasion)
Sysmon 11      payload dropped into the excluded path
4688           payload executes — no Defender detection (it's excluded)
```

The exclusion (5007) explains *why* later malware didn't trigger a 1116 — absence of detection becomes evidence once you see the exclusion. Lay it on a [timeline](/en/blog/event-log-timeline-incident-response) and pair with [audit-policy tampering (4719)](/en/blog/audit-policy-tampering-4719); attackers who disable Defender often disable auditing too.

## Hunt checklist

- Pull `…Windows Defender%4Operational.evtx`; load in the [browser parser](/en/blog/how-to-open-an-evtx-file).
- Detections: **1116 / 1117 / 1015** — read threat name, path, and whether action succeeded.
- Tampering: **5001 / 5007 / 5010** — flag exclusions and disabled protection, with the actor.
- ASR/NP: **1121 / 1122 / 1125** — technique-level near-misses.
- Correlate exclusions to subsequent activity in those paths; pair with [4719](/en/blog/audit-policy-tampering-4719) and [1102](/en/blog/event-id-1102-cleared-log).

For the full set of IDs across the blog, see the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

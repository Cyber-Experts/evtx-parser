---
title: "Event ID 3076 & 3077: WDAC Code Integrity blocks explained"
description: "Event ID 3076 is a WDAC / Smart App Control audit-mode block, 3077 an enforced block, both in CodeIntegrity/Operational. What they mean, the fields that matter and how to triage them."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - wdac
  - code-integrity
  - threat-hunting
author: "Florian Amette"
---

Windows Defender Application Control (WDAC) and the underlying Code Integrity subsystem decide whether a binary or driver is *allowed to load at all* based on signing and policy. Its log is narrower than [AppLocker's](/en/blog/applocker-event-logs-8003-8004) but deeper: it speaks to **kernel-level trust**, which makes it especially useful for catching unsigned drivers and BYOVD ("bring your own vulnerable driver") activity. This rounds out the [endpoint-controls](/en/blog/windows-defender-event-logs) coverage.

## Where it lives

The channel is **`Microsoft-Windows-CodeIntegrity/Operational`**. It logs regardless of whether a formal WDAC policy is deployed — base Code Integrity (and rules like the Microsoft vulnerable-driver blocklist) still record load decisions here.

## The event IDs

| ID | Meaning |
|---:|---------|
| **3076** | Code Integrity **audit** block — the file *would* have been blocked |
| **3077** | Code Integrity **enforced** block — the file was **blocked from loading** |
| 3033 | A file did not meet integrity requirements (load failed) |
| 3089 | Signing information for a blocked/audited file |

As with AppLocker, **3076 (audit)** vs **3077 (enforce)** mirrors "would block" vs "did block." The 3089 events carry the signature details for the file referenced by a 3076/3077 — so a block plus its 3089 tells you the file path, hash, and *why* trust failed (unsigned, revoked, not in policy).

## Why it matters for DFIR

- **Unsigned / untrusted drivers.** Code Integrity gates kernel drivers. A 3077 (or 3076 in audit) on a driver is high-signal — attackers load vulnerable or malicious drivers to disable EDR or gain kernel execution (BYOVD). A driver being blocked, *or* audited-but-allowed, tells you someone tried.
- **Unsigned user-mode code under WDAC.** Where WDAC enforces user-mode rules, 3077 records blocked executables/DLLs that AppLocker policy might not cover.
- **Audit-mode reconnaissance value.** Like AppLocker, WDAC is frequently deployed in audit mode first. In that mode 3076 logs everything that violates policy without stopping it — a ready list of untrusted code that ran.

## What to hunt

- **3076/3077 on drivers** (`.sys`, paths under `\Windows\System32\drivers\` or user-writable locations) — the BYOVD signal.
- **3077 enforced blocks** during the incident window — read the file path/hash via the paired 3089.
- **Repeated blocks of the same file** — an attacker retrying a load.
- **Unsigned/revoked signature status** in 3089 for files from user-writable paths.
- **A 3076 (audited, *allowed*) for a known-vulnerable driver** — it loaded because enforcement was off; treat as a hit, not a non-event.

## The interplay with AppLocker and Defender

These controls overlap but aren't redundant:

- **WDAC/Code Integrity** = signing/kernel trust (drivers + code integrity).
- **[AppLocker](/en/blog/applocker-event-logs-8003-8004)** = path/publisher/hash rules for user-mode apps and scripts.
- **[Defender](/en/blog/windows-defender-event-logs)** = malware detection + ASR.

A capable intruder may evade one and trip another — so read all three logs together. A driver that sails past AppLocker can still light up CodeIntegrity 3077.

## Correlate

```
4624 (+4672)   privileged logon
Sysmon 11      a .sys driver dropped to disk
3076 / 3077    CodeIntegrity audits/blocks the unsigned driver load  (BYOVD)
Sysmon 10      (if it loaded) a process opens lsass / EDR is blinded
```

The Code Integrity event is the moment the kernel-trust boundary was tested. Place it on a [timeline](/en/blog/event-log-timeline-incident-response) with the drop and any follow-on injection.

## Hunt checklist

- Pull `…CodeIntegrity%4Operational.evtx`.
- Filter to **3076 / 3077** (and 3033); read the paired **3089** for path/hash/signature.
- Prioritise **driver (.sys)** blocks and **unsigned/revoked** files from user-writable paths.
- Treat **audited-but-allowed** vulnerable drivers (3076 in audit mode) as hits.
- Cross-read with [AppLocker](/en/blog/applocker-event-logs-8003-8004) and [Defender](/en/blog/windows-defender-event-logs).

Open the CodeIntegrity log in the [browser parser](/en/blog/how-to-open-an-evtx-file); full ID set in the [cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

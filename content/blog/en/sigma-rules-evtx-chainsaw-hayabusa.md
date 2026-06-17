---
title: "Running Sigma rules over EVTX with Chainsaw and Hayabusa"
description: "How to scan .evtx files with detection rules at scale — what Sigma is, how Chainsaw and Hayabusa apply it to event logs, when to use each, and how to fit rule-based triage into an investigation."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - sigma
  - detection
  - threat-hunting
author: "Florian Amette"
---

Hand-querying with [PowerShell](/en/blog/query-evtx-powershell-get-winevent) is right for a question you can phrase. But "tell me everything suspicious in these 200 `.evtx` files" needs detection rules applied at scale. That is what Sigma plus a fast scanner gives you. This post is the practical map of that workflow.

## What Sigma is

**Sigma** is a generic, vendor-neutral detection-rule format written in YAML — "the regex of SIEM rules." A rule describes a detection (which log source, which fields, which values) once, and tooling converts it to whatever backend you run. A minimal rule looks like:

```yaml
title: Suspicious Scheduled Task Creation
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4698
    TaskContent|contains:
      - 'powershell -enc'
      - 'mshta'
  condition: selection
level: high
```

The public [SigmaHQ](https://github.com/SigmaHQ/sigma) repository ships thousands of community rules covering the event IDs across this blog — logon, [scheduled tasks](/en/blog/scheduled-task-persistence-4698), [RDP](/en/blog/rdp-forensics-event-logs), [WMI](/en/blog/wmi-persistence-event-logs), and more.

## Two tools that run Sigma directly on EVTX

You don't need a SIEM. Two fast, free Rust tools read `.evtx` files and apply Sigma locally:

### Chainsaw (WithSecure)

Built for fast triage of EVTX (and other Windows artifacts). It ships **detection/hunting mappings** and runs Sigma rules against logs, with output to table/CSV/JSON.

```bash
# Hunt with Sigma rules + Chainsaw's mappings over a folder of logs
chainsaw hunt ./logs/ -s ./sigma/ --mapping ./mappings/sigma-event-logs-all.yml -o results.csv

# Quick keyword/EventID search
chainsaw search -t 'Event.System.EventID: =4624' ./logs/
```

Chainsaw is excellent when you want a fast first pass that highlights the records worth reading.

### Hayabusa (Yamato Security)

A timeline-oriented scanner: it applies its own curated Sigma-based ruleset (plus upstream Sigma) and produces a single, ranked **CSV timeline** across many logs — purpose-built for "give me the story."

```bash
# Produce a ranked detection timeline from a logs directory
hayabusa csv-timeline -d ./logs/ -o timeline.csv
```

Hayabusa leans toward a prioritised, analyst-readable timeline; Chainsaw leans toward flexible hunting and search. Many teams run both.

## When to use which

| You want… | Reach for |
|-----------|-----------|
| A fast "what's suspicious here" first pass | **Hayabusa** csv-timeline |
| Flexible hunting with your own/SigmaHQ rules | **Chainsaw** hunt |
| One specific question, one box | [PowerShell Get-WinEvent](/en/blog/query-evtx-powershell-get-winevent) |
| Eyeball a single file, no install | [browser parser](/en/blog/how-to-open-an-evtx-file) |

These aren't exclusive — a common flow is Hayabusa/Chainsaw to surface hits, then open the specific `.evtx` to read the surrounding records in context.

## Fitting it into an investigation

Rule-based scanning is a **lead generator**, not a verdict:

1. **Collect** the logs ([from a live host](/en/blog/collecting-evtx-from-live-system) or an image).
2. **Scan** with Hayabusa and/or Chainsaw to get ranked detections.
3. **Triage** the hits — read each flagged record and its neighbours, not just the rule title.
4. **Pivot** on the real ones: take the account/IP/time from a hit and pull the full [logon](/en/blog/windows-logon-events-explained) or [RDP](/en/blog/did-someone-rdp-into-this-host) timeline around it.
5. **Build the timeline** (next post) from the confirmed events.

## Caveats

- **Rules ≠ truth.** Sigma rules have false positives (and false negatives). A hit means "look here," not "this is malicious." Always read the underlying event.
- **Logging coverage decides everything.** A rule for 4698 finds nothing if Object Access auditing was off; a Sysmon rule needs Sysmon installed. Know what was being logged before trusting an empty result. See [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries).
- **Field mapping matters.** Chainsaw uses a mapping file to connect Sigma's field names to EVTX fields; a wrong/old mapping silently misses detections. Keep tools and mappings current.
- **Time zones.** Normalise everything to UTC (the [native EVTX timestamp](/en/blog/evtx-file-format-reference)) before merging tool output with other evidence.

Rule scanning tells you *where* to look across a big pile of logs; the [PowerShell guide](/en/blog/query-evtx-powershell-get-winevent) tells you how to interrogate a specific file; and the [timeline guide](/en/blog/event-log-timeline-incident-response) tells you how to assemble the confirmed pieces into a narrative.

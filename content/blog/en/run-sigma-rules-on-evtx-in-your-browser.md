---
title: "Run Sigma rules on EVTX in your browser"
description: "Run 2,395 SigmaHQ rules on Windows .evtx logs without installing Hayabusa or Chainsaw: in-browser Sigma matching, ATT&CK context, pivots, and your own YAML rules."
date: "2026-09-29"
tags:
  - evtx
  - dfir
  - threat-hunting
  - sigma
  - sysmon
author: "Florian Amette"
---

Sigma is the closest thing detection engineering has to a common language. A rule describes *what* suspicious looks like — a process, a registry write, a logon with the wrong type — and a backend turns it into whatever your SIEM speaks. For event logs sitting on an analyst's laptop, the usual answer is a command-line tool such as Hayabusa or Chainsaw: download a binary, point it at a folder of `.evtx` files, read the CSV.

That works, but it assumes you are allowed to run an unsigned binary on the machine where the evidence sits, and that you have the time to set it up. This viewer now runs the SigmaHQ rule set directly in the browser tab, next to the events. Nothing is installed, and nothing is uploaded.

## What you get when you drop a log

Open one or more `.evtx` files as usual. As soon as parsing finishes, the parser's Web Worker runs every bundled rule over every record and the **Sigma** tab shows a badge with the number of rules that matched.

Inside the tab:

- Matched rules are grouped by level — critical, high, medium, low, informational — with the number of events each one hit.
- Selecting a rule shows its description, MITRE ATT&CK tactics and techniques (linked to attack.mitre.org), the false positives the author documented, the references, the log source and the rule ID.
- The matched events are listed with the fields the rule actually tested. Click a timestamp to open the event in the main table; **Around this event** sets the time range to a window around it so you see what happened just before and after.
- **Show in events table** restricts the table to that rule's hits, so the search box, the field sidebar and the exports work on them.
- The existing time range applies: narrow it to the incident window and the counts follow.
- **Export matches** writes CSV or JSON with the rule ID, title, level, record ID, time, computer, channel and the key field values.

If you are new to the event IDs involved, [Sysmon Event ID 1](/en/blog/sysmon-event-id-1-process-create) and [Security 4688](/en/blog/event-id-4688-process-creation) are the two records most rules end up looking at.

## Which rules, and how they map to EVTX

The rule set is `rules/windows/**` from a pinned SigmaHQ release (r2026-07-01 at the time of writing). It is fetched at build time and shipped with the site as a JSON file, so the browser never reaches out to GitHub — the site's Content Security Policy would not allow it anyway. Out of 2,403 Windows rules, 2,395 run. The 8 left out use the `file_access` and `file_rename` categories, which come from ETW providers that never write to an `.evtx` file. Deprecated rules are not imported.

Sigma rules name a log source, not a file. The mapping is the one Hayabusa, Chainsaw and pySigma use:

- `category: process_creation` runs on Sysmon Event ID 1 **and** on Security 4688. For 4688, fields are translated: `Image` reads `NewProcessName`, `ParentImage` reads `ParentProcessName`, `IntegrityLevel` is derived from `MandatoryLabel`, and the hexadecimal process IDs are converted.
- Other Sysmon categories map to their Event IDs: network connections to 3, image loads to 7, process access to 10, file creation to 11, registry to 12–14, DNS to 22.
- `ps_script` and `ps_module` read PowerShell Operational 4104 and 4103; the classic `ps_classic_start` rules read Windows PowerShell 400, where `HostApplication=` and friends are pulled out of the `Data` blob.
- `service: security`, `system`, `windefend`, `taskscheduler`, `bits-client` and about forty others map to their channel.

A 4688 has no `OriginalFileName`, `Hashes` or `CurrentDirectory`, so rules that only rely on those fields cannot fire on it. That is a property of the log, not of the engine: if you want those rules to work, collect Sysmon.

## Bring your own rules

The **Your rules** button accepts YAML pasted in a text box or `.yml` files dropped on it (several rules separated by `---` are fine). Each rule is parsed and compiled in the worker; errors are reported per rule, and valid ones join the next run:

```yaml
title: Service installed from a user profile
id: 3b0f0b6e-6b1d-4e36-9a44-6d2f7d8f7a11
author: Your name
level: high
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ImagePath|contains: '\Users\'
  condition: selection
```

Your rules stay in this browser's local storage so they survive a reload. They are never sent anywhere.

## What the engine supports

The engine implements the detection part of the Sigma specification: selections as maps and lists, keyword searches, wildcards with Sigma's escaping rules, and the modifiers `contains`, `startswith`, `endswith`, `all`, `exists`, `re` (with `i`, `m`, `s`), `cased`, `base64`, `base64offset`, `utf16le`, `utf16be`, `wide`, `windash`, `cidr`, `gt`, `gte`, `lt`, `lte` and `fieldref`. Conditions support `and`, `or`, `not`, parentheses, `1 of`, `all of` and `them`.

Two things are deliberately not supported, and the tool says so instead of silently skipping: aggregation conditions (`| count() by …`) and Sigma correlation rules. None of the bundled Windows rules use them; if you paste one, it is listed as not loaded with the reason.

## Is it fast enough?

Running 2,400 rules naively on every event would be slow: a single Sysmon process-creation record is a candidate for about 1,200 rules. The engine buckets rules by channel and Event ID, then gives each rule a literal pre-filter — for example, `Image` must end with `\certutil.exe`, or `CommandLine` must contain `urlcache`. Those literals are indexed per field, substring ones in an Aho–Corasick automaton, so each record only runs the handful of rules whose pre-filter fired. In the test suite, 200,000 synthetic events against the full set take about five seconds, and the worker reports progress and keeps answering while it runs.

For a very large collection — a whole domain's worth of logs — a native tool on a workstation will still be faster. For the host in front of you, it is usually done before you have finished reading the findings panel. If you need a starting point for that first hour, see [what to read first during EVTX triage](/en/blog/evtx-triage-incident-response).

## Credit where it is due

The rules are the work of the SigmaHQ community and are licensed under the Detection Rule License 1.1. Every match shows "Rule by *author*, SigmaHQ, DRL 1.1" with a link to the original rule, and every exported row carries the same attribution. If a rule helps you close a case, the references section usually points to the research behind it — worth a read.

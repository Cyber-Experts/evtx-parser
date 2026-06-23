---
title: "Sysmon Event ID 22: DNS queries, C2 domains and exfiltration"
description: "Using Sysmon's DNS-query event for hunting — process-attributed domain lookups, spotting C2 and DGA domains, DNS tunnelling, and the fields that make it useful."
date: "2026-06-21"
tags:
  - evtx
  - dfir
  - sysmon
  - dns
  - threat-hunting
author: "Florian Amette"
---

DNS is where most C2 starts (resolve the domain) and where a surprising amount of data leaves (DNS tunnelling). **Sysmon Event ID 22** logs DNS queries **attributed to the process that made them** — so instead of a DNS server log that says "this host asked for evil.com," you get "`rundll32.exe` on this host asked for evil.com." That attribution is the value. Added in Sysmon 10, it completes the network picture alongside [Event ID 3](/en/blog/sysmon-network-connection-event-id-3).

## The fields that matter

| Field | Use |
|-------|-----|
| `Image` | **the process** that issued the query |
| `QueryName` | the domain looked up |
| `QueryStatus` | result code (`0` = success; non-zero = NXDOMAIN etc.) |
| `QueryResults` | the resolved addresses/records |
| `User` | account context |

`Image` + `QueryName` is the pairing every hunt starts from.

## What to hunt

- **LOLBins resolving domains.** `powershell.exe`, `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `certutil.exe` issuing DNS queries is abnormal and a strong download/C2 indicator — the DNS counterpart to the [EID 3 network signal](/en/blog/sysmon-network-connection-event-id-3).
- **[DGA domains](https://www.reverseengineering.app/en/techniques/domain-generation-algorithm).** High-entropy, random-looking `QueryName`s, often many in a short window with lots of `QueryStatus` NXDOMAIN failures as malware cycles through generated domains.
- **[DNS tunnelling](https://www.reverseengineering.app/en/techniques/dns-tunneling) / exfil.** Long, frequent, high-entropy subdomain labels under one parent domain (`<base32-data>.tunnel.example.com`), high query volume from one process — data smuggled inside DNS.
- **Newly-seen / low-reputation domains** queried by non-browser processes.
- **Beacon cadence.** The same domain resolved on a regular interval = C2 keep-alive; pair with EID 3 connection timing.

## QueryStatus and QueryResults are diagnostic

- A burst of **NXDOMAIN** (`QueryStatus` non-zero) from one process is a DGA fingerprint — most generated domains don't exist.
- `QueryResults` lets you connect the lookup to the [EID 3 connection](/en/blog/sysmon-network-connection-event-id-3) that follows (resolved IP → outbound connect), so you can prove the resolve-then-connect sequence rather than infer it.

## Volume and config

EID 22 is high-volume (every process that touches the internet does DNS) and benefits from filtering: exclude browser/update-agent queries to known-good domains, keep DNS from script hosts and unusual processes. See [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries). If browsers are excluded, malware inside a browser process won't show — know the config.

## Correlate

```
Sysmon 1 / 4688   suspicious process starts
Sysmon 22         it resolves a C2 / DGA domain        (QueryName, QueryResults)
Sysmon 3          it connects to the resolved IP        (DestinationIp matches)
…repeat on a cadence…                                   (beaconing)
```

The resolve → connect → repeat chain, with the resolved IP in EID 22 matching the `DestinationIp` in EID 3, is high-confidence C2. Build it on a [timeline](/en/blog/event-log-timeline-incident-response).

## Hunt checklist

- Filter Sysmon/Operational to **EID 22**.
- Flag **LOLBins** and non-browser processes issuing queries.
- Look for **high-entropy / DGA** `QueryName`s and **NXDOMAIN bursts**.
- Look for **long high-entropy subdomains** under one parent (tunnelling).
- Tie `QueryResults` to the matching [EID 3](/en/blog/sysmon-network-connection-event-id-3) connection and check for **beacon cadence**.

Open the Sysmon log in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to EID 22, and pivot on `Image` + `QueryName`. Full Sysmon set in the [event ID cheat sheet](/en/blog/windows-event-id-cheat-sheet-dfir).

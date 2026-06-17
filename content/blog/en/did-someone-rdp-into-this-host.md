---
title: "Did someone RDP into this host? A step-by-step investigation"
description: "A practical workflow for answering 'was there a remote desktop session' from EVTX alone — which logs to pull, which event IDs to filter, how to confirm a real interactive session, and how to read the source and timing."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - rdp
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

"Did someone RDP into this machine, and if so when and from where?" is one of the most common questions an analyst gets handed. This is the workflow to answer it from event logs alone, building on the [complete RDP event picture](/en/blog/rdp-forensics-event-logs). The goal is not just a yes/no — it is a defensible timeline.

## 1. Pull the right logs

You need three files from the host:

- `Security.evtx`
- `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx`
- `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx`

They live in `C:\Windows\System32\winevt\Logs\`. The Terminal Services logs are small and roll quickly, so capture them first — see [collecting EVTX from a live host](/en/blog/collecting-evtx-from-live-system). Load all three together in the [browser parser](/en/blog/how-to-open-an-evtx-file) so they share one timeline.

## 2. Establish whether RDP happened at all

Filter to **1149** (RemoteConnectionManager). No 1149 events at all, and no 4624 `LogonType 10` in Security, is strong evidence no inbound RDP occurred in the retained window. The presence of 1149 means at least one network authentication reached the RDP service — note each one's `Source Network Address`.

## 3. Confirm a real interactive session (not just an auth)

1149 alone is not a desktop. Confirm with the destination's session lifecycle:

- A matching **4624 `LogonType 10`** in Security at the same time/account → a fresh interactive session.
- **LSM 21** ("Session logon succeeded") + **22** ("Shell start") → the desktop actually loaded.
- If you see **4624 `LogonType 7`** / **LSM 25** instead, that is a **reconnect** to an existing session, not a new logon.

If you have 1149 but no 4624/21, you may be looking at authentication that succeeded at NLA but failed downstream — keep it, but don't call it a session.

## 4. Read who and from where

For each confirmed session, record from the correlated events:

- **Account** — `TargetUserName` / `Domain` (4624; cross-check 1149).
- **Source IP** — `Source Network Address` (1149, LSM 21) and `IpAddress` (4624).
- **Auth** — `AuthenticationPackageName` (Kerberos vs NTLM).
- **Privilege** — a paired **4672** means the session had admin-level rights.

A source IP outside your admin/jump-host ranges, or NTLM where Kerberos is expected, is the moment to escalate.

## 5. Build the session lifecycle

Walk the events for that account/session ID in time order:

```
1149            authentication from 10.0.0.55
4624 type 10    interactive logon, user CONTOSO\svc_backup
LSM 21 / 22     session + shell up   (Session ID 3)
4672            admin privileges assigned
… activity …
4779 / LSM 24   disconnected (NOT logged off)
4778 / LSM 25   reconnected later
4634/4647 / 23  logoff
```

A **disconnect with no later logoff** (24/4779, no 23) means the session was parked, not ended — a frequent attacker pattern. A reconnect (25/4778) from a *different* source IP than the original logon is worth a hard look.

## 6. Check for failures and brute force

Filter Security to **4625 `LogonType 10`**. Cluster by `IpAddress` and read the [sub-status code](/en/blog/detecting-4625-brute-force): many `0xC000006A` against one account is brute force; many `0xC0000064` across accounts is spraying. A successful 4624 *after* a run of 4625 from the same IP is a likely compromise — flag the timestamp.

## 7. Trace the source (if you have it)

If the *source* host is in scope, its `…TerminalServices-RDPClient/Operational` log shows **1024** ("trying to connect to `<server>`"), naming where it RDP'd out to. Chaining 1024 (source) → 1149 (destination) across hosts reconstructs a [pivot path](/en/blog/detecting-rdp-lateral-movement).

## Answering the question

You can now state, with evidence: *whether* RDP occurred (1149 + confirmed 4624/21), *who* (account), *from where* (source IP, cross-checked in two logs), *when* (UTC timeline), *with what rights* (4672), and *how it ended* (logoff vs parked disconnect). That is the difference between "maybe someone remoted in" and a timeline that holds up.

If logs are suspiciously thin, remember the Terminal Services Operational logs roll fast and may simply have aged out — and that a [cleared Security log](/en/blog/event-id-1102-cleared-log) on the destination still leaves the source host's RDPClient trail and the domain controller's [Kerberos events](/en/blog/windows-logon-events-explained) intact.

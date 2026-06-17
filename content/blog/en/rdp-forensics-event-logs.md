---
title: "RDP forensics: the complete event-log picture"
description: "Every Windows event a Remote Desktop session leaves behind, across four logs — 1149, LocalSessionManager 21/22/24/25, Security 4624 type 10 and 4778/4779 — and how they fit together into one timeline."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - rdp
  - lateral-movement
  - threat-hunting
author: "Florian Amette"
---

A single RDP session scatters evidence across **four different logs**, and no one of them tells the whole story. The Security log says a session started but is vague about the network. The Terminal Services logs know the source IP and session lifecycle but not the privileges. Reading RDP correctly means stitching them together. This post is the map; the [investigation walkthrough](/en/blog/did-someone-rdp-into-this-host) and the [lateral-movement detection guide](/en/blog/detecting-rdp-lateral-movement) build on it.

## The four logs that matter

| Log | What it knows |
|-----|---------------|
| `Security` | logon success/failure, account, privileges, logon type |
| `…TerminalServices-RemoteConnectionManager/Operational` | network authentication + **source IP**, very early |
| `…TerminalServices-LocalSessionManager/Operational` | session **lifecycle**: logon, shell, disconnect, reconnect |
| `…TerminalServices-RDPClient/Operational` | **outbound** RDP — where this host connected *to* |

The first three live on the **destination** (the box someone RDP'd *into*). The last lives on the **source** (the box someone RDP'd *from*) — which is what makes it gold for tracing a pivot.

## On the destination, in order

A clean interactive RDP logon fires, roughly in this sequence:

1. **1149** — *RemoteConnectionManager/Operational*, "User authentication succeeded." The earliest useful event. It carries `User`, `Domain`, and **`Source Network Address`** (the client IP). Caveat worth knowing: 1149 means network-level authentication passed — it can appear even when the subsequent logon fails, so it is "someone reached the RDP service and authenticated at the NLA layer," not "someone got a desktop."
2. **4624** — *Security*, `LogonType 10` (RemoteInteractive). The actual session. Read `TargetUserName`, `IpAddress`, and `AuthenticationPackageName` exactly as in any [logon analysis](/en/blog/understanding-event-id-4624). `LogonType 7` here instead means a **reconnect/unlock** of an existing session, not a fresh logon.
3. **21** — *LocalSessionManager/Operational*, "Session logon succeeded." Carries `User` and `Session ID` and the source address.
4. **22** — *LocalSessionManager/Operational*, "Shell start notification received." The desktop/shell actually came up.
5. **4778 / 4779** — *Security*, session **reconnected / disconnected** to/from a window station, with client name and address.
6. **24** — *LocalSessionManager/Operational*, "Session has been disconnected." 
7. **25** — *LocalSessionManager/Operational*, "Session reconnection succeeded" (on resume).
8. **23** — *LocalSessionManager/Operational*, "Session logoff succeeded," at the end.

So a disconnect-without-logoff (24/4779 with no 23) is a session left running — common with attackers, who disconnect rather than log off to keep a session warm.

## Key fields, and where to read them

| Field | Best source |
|-------|-------------|
| Source IP | **1149** and LSM **21/24**; 4624 `IpAddress` |
| Account | all of them; cross-check `Domain` |
| Session ID | LSM 21/22/24/25 |
| Privileges | **4672** alongside the 4624 |
| Auth package | 4624 `AuthenticationPackageName` (Kerberos vs NTLM) |
| Reconnect vs new | 4624 type **10** (new) vs **7** (reconnect); LSM 25; 4778 |

NTLM on an internal RDP where you expect Kerberos, or a `Source Network Address` outside your admin ranges, are the two fastest tells.

## On the source: where did they come from

If you can also pull logs from the **client**, the *RDPClient/Operational* log records **outbound** attempts:

- **1024** — "RDP ClientActiveX is trying to connect to the server (`<name>`)." Names the *destination* this host tried to reach.
- **1102** (RDPClient log, not the Security 1102) — connection-level detail.

This is how you reconstruct a chain: host A's RDPClient log shows 1024 → server B; server B's RemoteConnectionManager shows 1149 from A; B's RDPClient shows 1024 → server C; and so on. That breadcrumb trail is the heart of [RDP lateral-movement detection](/en/blog/detecting-rdp-lateral-movement).

## Failures: 4625 type 10 and 1149 anomalies

Failed RDP logons are **4625 with `LogonType 10`**; read the [sub-status code](/en/blog/detecting-4625-brute-force) exactly as for any failed logon (`0xC000006A` bad password, `0xC0000064` no such user). RDP brute force shows as many 4625 type 10 from one `IpAddress`; RDP spraying shows many accounts. Note that with NLA, a flood of 1149 with no matching 4624 can indicate authentication succeeding at the NLA layer while the full logon is still being rejected downstream — worth a closer look.

## Caveats that bite people

- **The Terminal Services Operational logs are small and roll fast.** On a busy host they may only cover days. Collect them early; see [collecting EVTX from a live system](/en/blog/collecting-evtx-from-live-system).
- **1149's "Domain" is often blank** for local accounts and some NLA configs — don't treat blank as suspicious by itself.
- **Type 7 vs 10.** Reconnects log as type 7; counting only type 10 undercounts real access.
- **Clock/zone.** All EVTX timestamps are UTC (see the [format reference](/en/blog/evtx-file-format-reference)); align the four logs in UTC before you correlate.

## Minimum viable RDP timeline

Load the host's `Security.evtx` plus both TerminalServices Operational logs in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to `1149, 21, 22, 23, 24, 25, 4624, 4625, 4778, 4779`, sort by time, and you have the session story: who, from where, when it started, whether they disconnected or logged off, and whether they reconnected. The next post turns that into a concrete [investigation](/en/blog/did-someone-rdp-into-this-host).

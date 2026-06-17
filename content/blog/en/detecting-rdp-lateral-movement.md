---
title: "Detecting RDP lateral movement in event logs"
description: "How attackers move host-to-host over RDP and the event-log trail it leaves — chaining RDPClient 1024 to RemoteConnectionManager 1149, spotting jump-host fan-out, restricted-admin and tunnelled RDP, and the gaps to watch for."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - rdp
  - lateral-movement
  - threat-hunting
author: "Florian Amette"
---

Once an attacker has one set of credentials, RDP is one of the most common ways they move deeper — it is built in, it is encrypted, and it looks like admin work. The trail it leaves is distinctive once you know how to chain it. This builds on the [complete RDP event picture](/en/blog/rdp-forensics-event-logs) and the broader [lateral-movement guide](/en/blog/detect-lateral-movement-evtx).

## The shape of RDP lateral movement

Three patterns cover most of it:

1. **Chaining** — A → B → C, each hop a fresh RDP session, often with the same compromised account.
2. **Jump-host fan-out** — one host RDPs out to *many* destinations in a short window (an attacker sweeping, or a legitimate admin — context decides).
3. **Inbound from the wrong place** — a workstation receiving RDP (workstations rarely should), or RDP from a non-admin subnet.

Each has an event signature.

## Chaining: the 1024 → 1149 breadcrumb

The key insight from the [event picture](/en/blog/rdp-forensics-event-logs): the **source** host logs outbound RDP and the **destination** logs inbound. So a hop leaves two correlated halves:

- On the **source**: `…TerminalServices-RDPClient/Operational` **1024** — "trying to connect to `<destination>`."
- On the **destination**: `…RemoteConnectionManager/Operational` **1149** — auth succeeded from `<source IP>`, plus **4624 type 10**.

Reconstruct the chain by matching each host's 1024 destinations against the next host's 1149 source IPs:

```
WKSTN-7   RDPClient 1024 → SRV-JUMP        (source of hop 1)
SRV-JUMP  1149 from WKSTN-7 + 4624 type10  (dest of hop 1)
SRV-JUMP  RDPClient 1024 → DC01            (source of hop 2)
DC01      1149 from SRV-JUMP + 4624 type10 (dest of hop 2)
```

A workstation RDPing to a jump host RDPing to a DC, all within minutes on one account, is a textbook movement path.

## Jump-host fan-out

On a suspected pivot, count distinct destinations in the **RDPClient 1024** events over a tight window. One account producing 1024 to a dozen hosts in ten minutes is sweeping behaviour. Legitimate admins do this too — so weight it by account (is this a normal admin?), time (3 a.m.?), and target set (does this admin normally touch DCs *and* finance servers?).

## Inbound anomalies on the destination

Hunt across hosts for:

- **4624 `LogonType 10`** (or 1149) on **workstations** — most end-user machines should rarely receive RDP.
- **Source `IpAddress` outside admin/jump ranges** — RDP from a user subnet or an unexpected host.
- **NTLM** (`AuthenticationPackageName`) on internal RDP where Kerberos is the norm — possible pass-the-hash or a downgrade.
- **A 4624 type 10 success preceded by 4625 type 10 brute force** from the same IP — credential guessing that worked.

## Restricted Admin and "no creds on the box" RDP

`mstsc /restrictedadmin` (and tooling that uses it) authenticates with the *machine's* existing credentials rather than typing a password into the target — so the target sees a **network-style** authentication and the logon may look more like type 3 in places. The tell shifts toward Kerberos/NTLM patterns and the absence of an interactive credential prompt. Don't assume "no typed password event" means "no RDP" — correlate 1149/4624 type 10 with the source's 1024.

## Tunnelled RDP

Attackers tunnel RDP over SSH or other forwarders to dodge network controls, which makes the **`Source Network Address` show as `127.0.0.1` / `::1` or the local proxy host** rather than the true origin. RDP whose source IP is localhost is a strong tunnelling indicator — the network truth is hidden, but the *fact* of a local-sourced RDP session is itself the finding. Pivot to network/process evidence (the forwarder) from there.

## The gaps to remember

- **Operational logs roll fast.** RDPClient and the TerminalServices logs are small; a multi-day-old pivot may have aged out on busy hosts. Collect broadly and early.
- **A cleared destination log isn't the end.** The source host's **1024** trail and the **DC's Kerberos** events survive a [Security-log clear](/en/blog/event-id-1102-cleared-log) on the target.
- **Disconnect ≠ logoff.** Parked sessions (24/4779 without 23) keep an attacker's foothold warm and won't show a clean session end.

## Hunt checklist

- Build the **1024 → 1149** chain across all collected hosts; flag multi-hop paths on one account.
- Flag **RDP inbound to workstations** and **from non-admin subnets**.
- Flag **NTLM RDP** where Kerberos is expected.
- Flag **localhost-sourced** RDP (tunnelling).
- Correlate **4625 type 10 → 4624 type 10** from one IP (guessed-then-succeeded).

Pull the relevant hosts' logs into the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to the RDP IDs, and read the chain in UTC. For the bytes under these records, the [format reference](/en/blog/evtx-file-format-reference) is the companion.

---
title: "Reading Windows logons end to end: 4624, 4625, Kerberos and NTLM"
description: "How Windows logon auditing actually fits together — logon types, 4624/4625 fields and failure codes, the Kerberos 4768/4769/4771 chain, NTLM 4776, and how the events correlate across the domain controller and the target host."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - logon
  - kerberos
  - ntlm
  - threat-hunting
author: "Florian Amette"
---

A single logon generates events on more than one machine, in more than one log, with the interesting detail spread across several event IDs. Reading [4624](/en/blog/understanding-event-id-4624) in isolation tells you *that* someone logged on; understanding the whole system tells you *how*, *from where*, and whether it should worry you. This post is the map.

All of these live in the **Security** channel and require the relevant audit subcategories to be enabled (`Audit Logon`, `Audit Account Logon` / Kerberos and credential validation). They are documented in Microsoft's [Advanced Audit Policy Configuration](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration).

## The two halves: account logon vs logon

Windows splits authentication auditing in a way that trips people up:

- **Account logon** events fire **where the credentials are validated** — on the **domain controller** for a domain account (Kerberos/NTLM), or locally for a local account. These are 4768/4769/4771 (Kerberos) and 4776 (NTLM).
- **Logon** events fire **where the session is created** — on the **target host** the user actually reached. These are 4624 (success) and 4625 (failure).

So a single RDP into a domain-joined server produces Kerberos events **on the DC** and a 4624 **on the server**. Correlating the two — by time, account, and source IP — is the core skill.

## Logon types: the most important field in 4624

The `LogonType` field tells you *how* the session was established. It is the first thing to read:

| Type | Name | Means |
|-----:|------|-------|
| 2 | Interactive | at the console (or KVM/ILO) |
| 3 | Network | SMB, file shares, most remote auth |
| 4 | Batch | scheduled tasks |
| 5 | Service | a service starting under an account |
| 7 | Unlock | workstation unlock |
| 8 | NetworkCleartext | password sent in the clear (e.g. IIS basic auth) |
| 9 | NewCredentials | `runas /netonly` — local token kept, network identity swapped |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | logon using cached domain credentials (offline) |

Type **3** from a user account to many hosts in a short window is lateral movement; type **10** off-hours is the RDP you investigate; type **9** is what a lot of credential-theft tooling produces. See [detecting lateral movement in EVTX](/en/blog/detect-lateral-movement-evtx).

## 4624 — successful logon

The fields that matter, beyond `LogonType`:

- **Subject** (`SubjectUserName`/`SubjectLogonId`) — who *requested* the logon (often `SYSTEM` or a service for type 3/5).
- **New Logon** (`TargetUserName`, `TargetDomainName`, `TargetLogonId`) — who actually logged on. `TargetLogonId` is the key that ties this session to later 4634/4647 logoff and 4672 events.
- **`LogonProcessName`** / **`AuthenticationPackageName`** — `Negotiate`/`Kerberos`/`NTLM`/`NtLmSsp`. An NTLM package on an internal server-to-server logon is a flag.
- **`IpAddress`** / **`IpPort`** / **`WorkstationName`** — the source. `::1`/`127.0.0.1` or `-` for local.
- **`ElevatedToken`** and the companion **4672** ("special privileges assigned") — a high-privilege session.

`TargetLogonId` is the join key for the whole session lifecycle: 4624 (start) → 4672 (privileges) → activity → 4634/4647 (logoff).

## 4625 — failed logon, and reading the failure code

[4625](/en/blog/detecting-4625-brute-force) carries a `Status`/`SubStatus` code that says *why* it failed — essential for telling a typo apart from an attack:

| Sub-status | Meaning |
|------------|---------|
| `0xC0000064` | user name does not exist (user enumeration) |
| `0xC000006A` | correct user, **bad password** (classic brute force) |
| `0xC0000234` | account **locked out** |
| `0xC0000072` | account **disabled** |
| `0xC0000070` | workstation restriction |
| `0xC000006F` | outside permitted logon hours |
| `0xC0000071` | expired password |
| `0xC0000193` | account expired |

Many `0xC0000064` across accounts = enumeration/spraying; many `0xC000006A` against one account = classic brute force; a burst then `0xC0000234` = lockout reached. The same `LogonType`/`IpAddress` reading applies.

## Kerberos: 4768 → 4769 → 4771

On the KDC (domain controller):

- **4768** — a Kerberos **TGT** was requested. The first event of a domain logon; ties an account to a client IP. [Detail on 4768](/en/blog/event-id-4768-kerberos-tgt).
- **4769** — a Kerberos **service ticket** was requested. One per service the user reaches — and the event abused by [Kerberoasting](/en/blog/event-id-4769-kerberoasting) (look for `TicketEncryptionType 0x17` / RC4 against service accounts).
- **4771** — Kerberos **pre-authentication failed**. The Kerberos analogue of 4625; its failure code `0x18` is a bad password. Watch for AS-REP roasting where pre-auth is *not* required.

Ticket `0x17` (RC4) where you expect `0x12` (AES) is a downgrade worth chasing.

## NTLM: 4776

- **4776** — "the domain controller attempted to validate the credentials for an account." This is the NTLM validation event, logged on the DC (or the local SAM for local accounts). Its error codes mirror the 4625 sub-status values (e.g. `0xC000006A`). NTLM where your environment should be Kerberos-only is itself a finding, especially server-to-server.

## Putting it together: one RDP, traced

A domain user RDPs into `SRV-APP01`:

1. **DC**: `4768` — TGT requested for the user, from the client IP.
2. **DC**: `4769` — service ticket for `SRV-APP01`'s host SPN.
3. **SRV-APP01**: `4624` `LogonType 10`, `AuthenticationPackage Kerberos`, `IpAddress` = client.
4. **SRV-APP01**: `4672` if the account is privileged.
5. **SRV-APP01**: `4634`/`4647` at session end, same `TargetLogonId`.

Miss the DC half and "where did they come from" gets much harder — which is exactly why attackers who clear the [Security log](/en/blog/event-id-1102-cleared-log) on a target still leave a trail on the controller.

## Hunting starting points

- Type 3 fan-out from one account across hosts in minutes → lateral movement.
- Type 10 off-hours, or from an unexpected `IpAddress` → RDP to investigate.
- 4769 RC4 against service accounts → Kerberoasting.
- NTLM (4776 / `NtLmSsp` in 4624) where Kerberos is expected → downgrade or pass-the-hash.
- 4625 bursts read by sub-status → spray vs brute force vs lockout.

Load a `Security.evtx` in the [browser parser](/en/blog/how-to-open-an-evtx-file), filter to these IDs, and the timeline tells the story. For the bytes underneath these records, see the [EVTX format reference](/en/blog/evtx-file-format-reference).

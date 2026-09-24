---
title: "Windows Event ID Cheat Sheet (Security, Sysmon, PowerShell)"
description: "Windows Event ID cheat sheet for DFIR and threat hunting: the Security, System, Sysmon and PowerShell IDs that matter, grouped by attack phase, each with a one-line meaning."
date: "2026-06-17"
tags:
  - evtx
  - dfir
  - event-id
  - reference
  - threat-hunting
author: "Florian Amette"
---

Windows logs thousands of distinct event IDs; only a few dozen carry most investigations. This is the working subset, grouped by **attack phase**, with the channel each lives in, what it means in one line, and a link to the deep-dive where there is one. Keep it open next to the [browser parser](/en/blog/how-to-open-an-evtx-file) while you triage.

A note on prerequisites: many Security events require the relevant **audit subcategory** to be enabled, and some require **command-line process auditing** or **Sysmon**. An empty result often means "not logged," not "didn't happen" — see [Sysmon configuration](/en/blog/sysmon-configuration-real-adversaries) and the per-event posts.

## Authentication & logon

| ID | Channel | Meaning |
|---:|---------|---------|
| **4624** | Security | An account [successfully logged on](/en/blog/understanding-event-id-4624) — read the **logon type** |
| **4625** | Security | A [logon failed](/en/blog/detecting-4625-brute-force) — read the **sub-status** code |
| 4634 / 4647 | Security | Logoff / user-initiated logoff (join by `LogonId`) |
| 4648 | Security | Logon with **explicit credentials** (`runas`) |
| **4768** | Security (DC) | [Kerberos TGT requested](/en/blog/event-id-4768-kerberos-tgt) |
| **4769** | Security (DC) | [Kerberos service ticket requested](/en/blog/event-id-4769-kerberoasting) (Kerberoasting) |
| 4771 | Security (DC) | Kerberos pre-authentication failed |
| 4776 | Security (DC) | NTLM credential validation |

The whole picture, and how the DC and host halves correlate: [reading Windows logons end to end](/en/blog/windows-logon-events-explained).

## Remote access (RDP)

| ID | Channel | Meaning |
|---:|---------|---------|
| **1149** | RemoteConnectionManager/Operational | RDP network auth succeeded — carries **source IP** |
| 21 / 22 | LocalSessionManager/Operational | RDP session logon / shell start |
| 24 / 25 | LocalSessionManager/Operational | RDP session disconnected / reconnected |
| 4778 / 4779 | Security | Session reconnected / disconnected (client name + address) |
| 1024 | RDPClient/Operational | **Outbound** RDP attempt — names the destination |

Full constellation: [RDP forensics](/en/blog/rdp-forensics-event-logs) · investigation: [did someone RDP in?](/en/blog/did-someone-rdp-into-this-host) · hunting: [RDP lateral movement](/en/blog/detecting-rdp-lateral-movement).

## Execution

| ID | Channel | Meaning |
|---:|---------|---------|
| **4688** | Security | [Process created](/en/blog/event-id-4688-process-creation) (command line if auditing on) |
| **1** | Sysmon/Operational | [Process create](/en/blog/sysmon-event-id-1-process-create) (hashes, parent, command line) |
| **4104** | PowerShell/Operational | [Script-block logging](/en/blog/powershell-4104-scriptblock) — the actual code |
| 4103 | PowerShell/Operational | Module/pipeline logging |
| 400 / 600 | Windows PowerShell | Engine start / provider lifecycle (classic) |

Background: [PowerShell logging for forensics](/en/blog/powershell-logging-forensics).

## Endpoint telemetry (Sysmon)

Sysmon must be installed and configured — the IDs below are the high-value subset. See [Sysmon configuration for real adversaries](/en/blog/sysmon-configuration-real-adversaries).

| ID | Meaning |
|---:|---------|
| **1** | [Process create](/en/blog/sysmon-event-id-1-process-create) — hashes, parent, command line |
| **3** | [Network connection](/en/blog/sysmon-network-connection-event-id-3) — process-attributed (C2/beaconing) |
| **7** | [Image/DLL loaded](/en/blog/sysmon-image-load-event-id-7) — sideloading, unsigned modules |
| **8** | [CreateRemoteThread](/en/blog/sysmon-process-injection-event-id-8-10) — process injection |
| **10** | [ProcessAccess](/en/blog/sysmon-process-injection-event-id-8-10) — LSASS handle access (`GrantedAccess`) |
| **11** | [FileCreate](/en/blog/sysmon-file-registry-events) — dropped files |
| 12–14 | [Registry](/en/blog/sysmon-file-registry-events) create / set / rename — persistence keys |
| 15 | [FileCreateStreamHash](/en/blog/sysmon-file-registry-events) — alternate data streams |
| **22** | [DNS query](/en/blog/sysmon-dns-query-event-id-22) — C2 / DGA / tunnelling |
| 23 / 26 | [FileDelete](/en/blog/sysmon-file-registry-events) — self-deletion / anti-forensics |

## Privilege & account management

| ID | Channel | Meaning |
|---:|---------|---------|
| **4672** | Security | [Special privileges](/en/blog/event-id-4672-special-privileges) assigned to a logon |
| **4720** | Security | [User account created](/en/blog/event-id-4720-account-created) |
| 4722 / 4725 / 4726 | Security | Account enabled / disabled / deleted |
| 4723 / 4724 | Security | [Password change vs admin reset](/en/blog/account-lockout-password-reset-4740) |
| 4740 / 4767 | Security (DC) | [Account locked out / unlocked](/en/blog/account-lockout-password-reset-4740) |
| **4728 / 4732 / 4756** | Security | Member added to [global / local / universal](/en/blog/privileged-group-changes-4732) security group |
| 4729 / 4733 / 4757 | Security | Member removed from those groups |

## Persistence

| ID | Channel | Meaning |
|---:|---------|---------|
| **4698** | Security | [Scheduled task created](/en/blog/scheduled-task-persistence-4698) (full task XML) |
| 4699 / 4700 / 4701 / 4702 | Security | Task deleted / enabled / disabled / updated |
| 106 / 140 / 141 | TaskScheduler/Operational | Task registered / updated / deleted |
| 200 / 201 | TaskScheduler/Operational | Task **action ran** / completed |
| **7045** | System | [Service installed](/en/blog/service-creation-event-id-7045) |
| 7034 / 7036 | System | [Service crashed / changed state](/en/blog/event-id-7036-service-state) |
| **5861** | WMI-Activity/Operational | [WMI permanent event consumer](/en/blog/wmi-persistence-event-logs) registered |
| 5858 / 5860 | WMI-Activity/Operational | WMI operation error / temporary consumer |

## Lateral movement & access to resources

| ID | Channel | Meaning |
|---:|---------|---------|
| 4624 type 3 | Security | Network logon (SMB, etc.) — fan-out = [lateral movement](/en/blog/detect-lateral-movement-evtx) |
| 4648 | Security | Explicit-credential logon (often pivoting) |
| 4663 | Security | [Object access](/en/blog/event-id-4663-object-access) attempt |
| 5140 / 5145 | Security | Network share accessed / detailed file share access |

## Defense evasion & anti-forensics

| ID | Channel | Meaning |
|---:|---------|---------|
| **1102** | Security | [Security audit log cleared](/en/blog/event-id-1102-cleared-log) — who & when |
| 104 | System | A different log was cleared |
| 1100 | Security | Event Log service shut down |
| **4719** | Security | [Audit policy changed](/en/blog/audit-policy-tampering-4719) — auditing disabled (go dark) |
| **4616** | Security | [System time changed](/en/blog/system-time-change-4616) — timestomping |

Reading what survives tampering: [tampered logs and what survives](/en/blog/evtx-tampering-what-survives) · [log clearing as evidence](/en/blog/event-log-clearing-evidence) · [carving deleted records](/en/blog/carve-deleted-evtx-records).

## The format underneath

| Topic | Reference |
|-------|-----------|
| What an EVTX file is | [what is an EVTX file](/en/blog/what-is-an-evtx-file) |
| Byte-level format | [complete format reference](/en/blog/evtx-file-format-reference) · [decoded](/en/blog/evtx-file-format) · [chunks](/en/blog/evtx-file-format-chunks) |
| The binary XML encoding | [how BinXML works](/en/blog/binxml-format-explained) |
| Collecting & opening | [collect from a live host](/en/blog/collecting-evtx-from-live-system) · [open an EVTX file](/en/blog/how-to-open-an-evtx-file) |

## How to use this

1. **Scope** the question (subject + window), then pull the right channels.
2. **Filter** to the IDs for the phase you're chasing — with [PowerShell](/en/blog/query-evtx-powershell-get-winevent), [Sigma tooling](/en/blog/sigma-rules-evtx-chainsaw-hayabusa), or the [browser parser](/en/blog/how-to-open-an-evtx-file).
3. **Correlate** by `LogonId`, source IP, account, and time; bring in the DC, not just the victim.
4. **Assemble** the confirmed events into a [UTC timeline](/en/blog/event-log-timeline-incident-response), and annotate the gaps.

Every bolded ID above has a deep-dive — follow the link for the fields, the false positives, and the hunting patterns.

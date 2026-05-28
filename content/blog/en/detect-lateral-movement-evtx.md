---
title: "Detecting lateral movement in Security.evtx"
description: "How real adversary tools move host-to-host in Windows estates, and the precise event ID combinations in Security.evtx that catch PsExec, Impacket, and WMIExec."
date: "2026-05-27"
tags:
  - evtx
  - lateral-movement
  - dfir
  - incident-response
  - threat-hunting
author: "Florian Amette"
---

Lateral movement is where most intrusions go from "they have a foothold" to "they own the domain". It is also where Windows logging is at its most useful and its most misleading. The events you need are all in `Security.evtx` and `System.evtx`. Reading them in isolation will get you nowhere. Reading them in the right pairs, with the right cross-host correlation, is what separates a useful timeline from a wall of `4624`s.

This is the part of an investigation where I stop scrolling and start grepping by `LogonId`.

## The skeleton: what happens when an attacker moves

There is no universal lateral movement pattern, but there is a universal *shape*:

1. The attacker authenticates from host A to host B, either with the current user's token (pass-the-hash, pass-the-ticket, or a stolen Kerberos TGT/TGS) or with explicit credentials for a different account.
2. Something on host B executes their payload — a service, a scheduled task, a WMI process create, a remote PowerShell session, or a DCOM invocation.
3. They reach back out for tooling, secrets, or the next hop.

Every step leaves events. The question is whether you are looking at the right ones, and whether the tooling has been instrumented at all.

## 4624 LogonType 3 is the front door

A successful network logon — `EventID=4624` with `LogonType=3` — is the single most common lateral movement primitive in the log. It is also the noisiest event Windows generates. A file server in a 500-seat office produces tens of thousands of these per day, all legitimate. Filtering by `LogonType=3` alone will not get you anywhere.

What gets you somewhere:

- `IpAddress` and `WorkstationName` in the event data. Anomalies cluster here. A workstation logging on to a server from a different subnet at 02:14 UTC is not nothing.
- `AuthenticationPackageName` and `LogonProcessName`. NTLM logons (`NTLM` / `NtLmSsp`) between domain-joined hosts in a Kerberos environment are suspicious by default. A clean Kerberos environment should be Kerberos-only for intra-domain auth, with NTLM falling back only for non-DNS-name access and legacy.
- `TargetUserName` patterns. Service accounts logging on interactively are red flags. Domain admin accounts logging on to workstations are red flags.

The pivot you want: pair every interesting `4624 Type 3` with the matching `4672` (special privileges) on the same `TargetLogonId`. If the logon got admin privileges, you have a candidate for credential abuse. If it did not, the attacker is operating with a lower-privileged token and you have time.

## 4648 is the event most defenders underuse

`4648` — "a logon was attempted using explicit credentials" — is generated whenever a process running as account A invokes credentials for account B to do something. This is the event you want for attribution. When `mimikatz` or `Rubeus` injects a ticket and the operator runs `net use \\TARGET /user:CORP\admin <pass>`, you get a `4648` on the originating host showing both accounts and the target.

The fields that matter:

- `SubjectUserName` / `SubjectLogonId` — who initiated.
- `TargetUserName` / `TargetServerName` — whose credentials, against what.
- `ProcessName` — what binary did the invocation. `cmd.exe`, `powershell.exe`, `wmic.exe`, `psexec.exe`, `wmiprvse.exe` (for WMI-based execution), and increasingly `pwsh.exe` are the usual suspects.

`4648` is the link between a compromised host and the next hop. If you have a suspect host, dump `4648` from its Security log first. It will tell you which credentials the attacker has and where they tried to use them, in time order, in one place.

## 4672 and the privilege story

`4672` is dropped immediately after `4624` for any logon that ends up with at least one sensitive privilege (`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, etc). It is generated for every logon of a member of `Administrators`, `Domain Admins`, or any account with token-elevating privileges.

Treat it as a tag, not a finding. The useful query is "show me every `4672` followed within 60 seconds by a `4624 Type 3` from a non-DC source IP", which surfaces admin token usage from workstations that should not be issuing them. The non-useful query is "show me every `4672`", which will return every service start on every server.

## 4697 and 7045: services as remote execution

PsExec, Impacket's `psexec.py`, and `smbexec.py` work by writing a service binary to the target's `ADMIN$` share, registering it via the Service Control Manager, starting it, and tearing it down. This leaves:

- `5145` on the target showing access to `\\target\ADMIN$` with the file name written (if object access auditing is on).
- `7045` in `System.evtx` showing the service install. The service binary path and service name are in the event data. PsExec defaults to `PSEXESVC` in `%SystemRoot%`; Impacket randomizes both, with patterns that vary by version and are well-documented.
- `4697` in `Security.evtx` for the same service install if you have system audit policy set.
- `4624 Type 3` from the operator's source workstation.

The signature is the *combination*: `4624 Type 3` from an unusual source, immediately followed by `5145` to `ADMIN$`, immediately followed by `7045` for a service whose binary lives somewhere it should not. Each event alone is plausible. The combination, within seconds, with the same `LogonId` linking them, is not.

Service names worth watching for in `7045`: random 8-character lowercase strings (Impacket default), `PSEXESVC` (PsExec default), `WinExec` or its variants, anything with a binary path under `C:\Windows\` that is not signed and not in the system's normal service set.

## 5140 and 5145: SMB share access in detail

`5140` logs that a share was accessed; `5145` logs the file name accessed within the share, *if* object access auditing for the share is enabled. Most environments do not enable `5145` because of the noise. Most environments also wish they had it during an incident.

For lateral movement, the `5145` events that matter are accesses to `ADMIN$`, `C$`, `IPC$`, and any `SYSVOL`/`NETLOGON` paths from unusual sources. `psexec.py` writes its service binary by writing to `\\target\ADMIN$\<random>.exe`. `secretsdump.py` reads `\\target\C$\Windows\System32\config\SAM` (and SYSTEM, and SECURITY). Each of those is a `5145` with a `RelativeTargetName` that should stand out.

Pair `5145` with the [USN journal](https://www.usnparser.com) on the target. The journal will have a `FILE_CREATE` for the same file with the same timestamp, which gives you a second-source confirmation that the file actually landed, and a [MFT](https://www.mftparser.com) record reference to chase.

## WMI as a lateral movement vector

WMI-based remote execution (`wmic /node:... process call create`, Impacket's `wmiexec.py`, PowerShell `Invoke-WmiMethod`) is harder to spot in Security.evtx alone because it does not install a service. You get:

- `4624 Type 3` on the target.
- A process create on the target with `WmiPrvSE.exe` as the parent. This is in Sysmon `EventID=1` if Sysmon is on. In `4688` it is the same picture if command-line auditing is on.
- WMI events in `Microsoft-Windows-WMI-Activity%4Operational.evtx` showing the consumer.

If Sysmon is not on, WMI-based lateral movement is mostly invisible in default-config event logs. This is one of the reasons every config baseline pushes Sysmon hard.

## Correlating across hosts

Lateral movement is a graph problem. A `4648` on host A naming host B and account `corp\admin` is one edge. The matching `4624 Type 3` on host B from host A's IP, with `TargetUserName=admin`, is the other end of the same edge. The `4769` (Kerberos service ticket) on the DC showing the ticket request for `cifs/hostB` from `admin@CORP` is the third witness.

In practice you want all of:

- Logon events from the source host's `Security.evtx`.
- Logon events from the target host's `Security.evtx`.
- TGT (`4768`) and TGS (`4769`) events from the domain controller's `Security.evtx`.
- Forwarded events from any WEC collector, which sometimes have the only intact copy if a host's local log was cleared.

Tie them together by `LogonId` within a host and by timestamp + account + IP across hosts. The classic JPCERT/CC paper lays this out in detail and is the single best free document on the topic.

For the host-side artifacts that survive log clearing, lean on [Prefetch](https://www.prefetchparser.com) for evidence of attacker-tooling execution, the [registry](https://www.registryparser.com) `Services` key for the trace of an installed-and-removed service binary, and [LNK files](https://www.lnkparser.com) and [jump lists](https://www.jumplistparser.com) for evidence of files an operator opened over a hands-on session.

## Further reading

- JPCERT/CC's ["Detecting Lateral Movement through Tracking Event Logs"](https://jpcertcc.github.io/ToolAnalysisResultSheet/). The reference. Read it twice.
- The MITRE ATT&CK [Lateral Movement matrix](https://attack.mitre.org/tactics/TA0008/) and the per-technique data source mappings.
- The Impacket [examples directory](https://github.com/fortra/impacket/tree/master/examples). If you have not read what `psexec.py`, `wmiexec.py`, and `smbexec.py` actually do on the wire, your detections are guesses.

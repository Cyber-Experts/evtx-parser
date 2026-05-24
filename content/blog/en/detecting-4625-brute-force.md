---
title: "Event ID 4625 explained: detecting brute force, sprays & enumeration"
description: "4625 is the failed-logon record. Read it right and you spot password sprays, credential stuffing, and Kerberos abuse before they succeed."
date: "2026-05-17"
---

Event ID 4625 — "An account failed to log on" — fires on the `Security` channel whenever an authentication attempt is rejected. It's the single most useful record for catching credential-attack activity, but only if you read the right fields.

## The fields that actually matter

```xml
<Data Name="TargetUserName">administrator</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="Status">0xc000006d</Data>
<Data Name="SubStatus">0xc0000064</Data>
<Data Name="LogonType">3</Data>
<Data Name="WorkstationName">attacker-vm</Data>
<Data Name="IpAddress">203.0.113.7</Data>
```

The combination of `Status` and `SubStatus` tells you *why* the logon failed:

- `0xc0000064` — account does not exist (username enumeration).
- `0xc000006a` — wrong password (the classic).
- `0xc0000234` — account locked out.
- `0xc0000072` — account disabled.
- `0xc0000071` — password expired.
- `0xc0000133` — clock skew on a Kerberos ticket (common during AS-REP roasting).
- `0xc000018b` — wrong SID — the workstation isn't in the domain it thinks it is.

A burst of `0xc0000064` against valid and invalid usernames is reconnaissance. A burst of `0xc000006a` against one account is brute force. A burst of `0xc000006a` against many accounts with the *same password* is a password spray.

## The patterns

The simplest triage queries:

1. **Spray detection**: group 4625 records by `IpAddress` (or `WorkstationName` if the IP isn't recorded), count distinct `TargetUserName` over 10 minutes. >5 accounts per source in that window is suspicious almost everywhere.
2. **Brute force**: group by `TargetUserName`, count failures per minute. >10 per minute against one account is usually a bot.
3. **Lockout root cause**: pair 4740 (account locked) with the preceding 4625s — the `WorkstationName` field will show which device triggered the lockout, which is critical because it's often a domain-joined server with a stale stored credential, not an attacker.

## The "after" matters as much as the "before"

A 4625 burst followed by a [4624](/en/blog/understanding-event-id-4624) from the same `IpAddress` is the actionable case — the attacker found a working credential. The parser on this page lets you filter the table to a source IP and watch the level and event-ID transitions over time in the timeline. The burst-then-spike pattern is unmistakable.

## Sample Sigma rule — password spray

```yaml
title: Password Spray via NTLM Failed Logons
id: 6d2e1f4a-1a8b-4c7c-8a5f-2c3d4e5f6a7b
status: stable
description: One source IP failing logons against many distinct accounts within a short window — the password-spray fingerprint.
references:
  - https://attack.mitre.org/techniques/T1110/003/
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    Status: '0xC000006D'
    SubStatus: '0xC000006A'
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 10m
falsepositives:
  - Misconfigured service account on a host hitting many endpoints
  - Vulnerability scanner authentication probes (tag scanner IPs)
level: high
tags:
  - attack.credential_access
  - attack.t1110.003
```

## Sample KQL — brute force against one account

```kusto
SecurityEvent
| where EventID == 4625
| where Status == "0xC000006D" and SubStatus == "0xC000006A"
| summarize Failures=count(), Sources=dcount(IpAddress)
    by TargetUserName, bin(TimeGenerated, 5m)
| where Failures >= 10
| order by TimeGenerated desc
```

## Sample Splunk — enumeration before brute

```spl
index=wineventlog EventCode=4625
| eval kind=case(SubStatus="0xC0000064", "enumeration", SubStatus="0xC000006A", "wrong_password", 1==1, "other")
| stats values(kind) AS Sequence count BY IpAddress
| where mvcount(Sequence) >= 2 AND mvfind(Sequence, "enumeration") >= 0 AND mvfind(Sequence, "wrong_password") >= 0
```

The signal is the *progression* — enumeration to find valid usernames, then brute force against those.

## ATT&CK mapping

- **T1110.001 — Brute Force: Password Guessing**: single account, many `0xC000006A` failures.
- **T1110.003 — Brute Force: Password Spraying**: many accounts, few failures per account, one source.
- **T1110.004 — Brute Force: Credential Stuffing**: many accounts, one source, often `0xC0000064` (account doesn't exist) for leaked-list misses interspersed with `0xC000006A` hits.
- **T1078 — Valid Accounts**: 4625 followed by [4624](/en/blog/understanding-event-id-4624) success from the same source = compromise.
- **T1556 — Modify Authentication Process**: anomalous `LogonProcessName` (anything other than `User32`, `NtLmSsp`, `Kerberos`, `Advapi`, or `Schannel`) suggests authentication tampering.

## False positives that look like attacks

- **Stored credentials going stale** after a password change. The user's mapped drives, scheduled tasks, or service account configs keep retrying the old password. The pattern: one `TargetUserName`, one `IpAddress` (sometimes one `WorkstationName`), steady `0xC000006A` cadence. Hunt for the host with the stale credential and fix it.
- **Misconfigured automation**: a script with a wrong password retrying in a loop. Same shape as brute force; talk to the owner before alerting.
- **Vulnerability scanners** during authenticated scans produce dense 4625 traffic. Tag scanner IPs.
- **Lockout-policy misconfiguration**: helpdesk procedures that unlock too aggressively can produce repeating 4625 → 4740 → 4624 cycles.

## What you don't see in 4625

NTLMv2 and Kerberos failures coming from a domain controller don't always carry a useful `IpAddress` — the field can be empty or `-`. For those you need the matching DC events ([4768](/en/blog/event-id-4768-kerberos-tgt)/4771 for Kerberos pre-auth failures) or network-level data. Don't conclude "no source IP, no investigation" — pivot to the DC channel.

The `LogonProcessName` and `AuthenticationPackageName` fields tell you which auth stack handled the attempt. Most useful are `NtLmSsp` (NTLM), `Kerberos`, and `Negotiate` (which picks one of the two). `User32` is local console; `Schannel` is TLS-based.
